package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/nemirovsky/sluice/internal/vault"
)

// SSHJumpHost handles SSH connections by acting as a credential-injecting
// intermediary. It presents an SSH server to the agent (accepting any
// authentication), authenticates to the upstream server using credentials
// from the vault, and relays SSH session channels between the two.
type SSHJumpHost struct {
	provider vault.Provider
	resolver *vault.BindingResolver
	hostKey  ssh.Signer
}

// NewSSHJumpHost creates an SSH jump host handler. The hostKey is presented
// to agents connecting through the proxy. The provider and resolver are used
// to look up SSH private keys for upstream authentication.
func NewSSHJumpHost(provider vault.Provider, resolver *vault.BindingResolver, hostKey ssh.Signer) *SSHJumpHost {
	return &SSHJumpHost{
		provider: provider,
		resolver: resolver,
		hostKey:  hostKey,
	}
}

// GenerateSSHHostKey creates a new ECDSA P-256 key pair suitable for use
// as an SSH host key.
func GenerateSSHHostKey() (ssh.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate SSH host key: %w", err)
	}
	return ssh.NewSignerFromKey(key)
}

// HandleConnection manages the SSH jump host relay between an agent and
// an upstream SSH server. The agentConn is the raw TCP stream from the
// agent (after SOCKS5 handshake). The upstreamAddr is the target
// host:port. The binding specifies which credential to use and the
// SSH username (via the Template field).
//
// Flow:
//  1. Decrypt SSH private key from vault into SecureBytes
//  2. Parse the key and zero the vault copy immediately
//  3. Dial upstream SSH server and authenticate with the real key
//  4. Accept the agent's SSH connection with no authentication
//  5. Relay SSH channels between agent and upstream
func (h *SSHJumpHost) HandleConnection(agentConn net.Conn, upstreamAddr string, binding vault.Binding) error {
	// Decrypt SSH private key from vault.
	secret, err := h.provider.Get(binding.Credential)
	if err != nil {
		return fmt.Errorf("get credential %q: %w", binding.Credential, err)
	}

	signer, parseErr := ssh.ParsePrivateKey(secret.Bytes())
	secret.Release() // Zero vault copy immediately after parsing.
	if parseErr != nil {
		return fmt.Errorf("parse SSH key for %q: %w", binding.Credential, parseErr)
	}

	// Template field holds the SSH username for SSH bindings.
	username := binding.Template
	if username == "" {
		username = "root"
	}

	// Dial upstream and authenticate with the vault credential.
	upstreamTCP, err := net.DialTimeout("tcp", upstreamAddr, connectTimeout)
	if err != nil {
		return fmt.Errorf("dial upstream %s: %w", upstreamAddr, err)
	}

	upstreamSSH, upstreamChans, upstreamReqs, err := ssh.NewClientConn(upstreamTCP, upstreamAddr, &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		upstreamTCP.Close()
		return fmt.Errorf("SSH handshake with %s: %w", upstreamAddr, err)
	}
	defer upstreamSSH.Close()

	log.Printf("[SSH] authenticated to %s as %q via credential %q", upstreamAddr, username, binding.Credential)

	// Accept the agent's SSH connection with no authentication required.
	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(h.hostKey)

	agentSSH, agentChans, agentReqs, err := ssh.NewServerConn(agentConn, serverConfig)
	if err != nil {
		return fmt.Errorf("agent SSH handshake: %w", err)
	}
	defer agentSSH.Close()

	// Relay global requests bidirectionally.
	go sshForwardGlobalRequests(agentReqs, upstreamSSH)
	go sshForwardGlobalRequests(upstreamReqs, agentSSH)

	// Relay channels opened by the upstream (e.g. reverse port forwarding).
	go sshRelayNewChannels(upstreamChans, agentSSH)

	// Relay channels opened by the agent (sessions, direct-tcpip, etc.).
	// This blocks until the agent connection closes.
	sshRelayNewChannels(agentChans, upstreamSSH)

	return nil
}

// sshForwardGlobalRequests forwards SSH global requests from src to dst.
func sshForwardGlobalRequests(reqs <-chan *ssh.Request, dst ssh.Conn) {
	for req := range reqs {
		ok, payload, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}
		if req.WantReply {
			req.Reply(ok, payload)
		}
	}
}

// sshRelayNewChannels accepts new channels from src and opens corresponding
// channels on dst, relaying data and requests between them.
func sshRelayNewChannels(chans <-chan ssh.NewChannel, dst ssh.Conn) {
	for newChan := range chans {
		go sshHandleChannel(newChan, dst)
	}
}

// sshHandleChannel opens a mirror channel on dst and relays data and
// requests bidirectionally.
//
// The relay waits for the upstream (dst) to close its channel, which
// signals that all data, stderr, and requests (including exit-status)
// have been forwarded to the agent (src). Only then does it close the
// agent-facing channel. This is necessary because the Go SSH library's
// Session.Wait() blocks until it receives SSH_MSG_CHANNEL_CLOSE, not
// just EOF. Closing prematurely would either drop exit-status or
// deadlock the session.
func sshHandleChannel(newChan ssh.NewChannel, dst ssh.Conn) {
	dstChan, dstReqs, err := dst.OpenChannel(newChan.ChannelType(), newChan.ExtraData())
	if err != nil {
		if openErr, ok := err.(*ssh.OpenChannelError); ok {
			newChan.Reject(openErr.Reason, openErr.Message)
		} else {
			newChan.Reject(ssh.ConnectionFailed, err.Error())
		}
		return
	}

	srcChan, srcReqs, err := newChan.Accept()
	if err != nil {
		dstChan.Close()
		return
	}

	// Track when upstream-to-agent relay work completes. When the
	// upstream channel closes, both data copies and request forwarding
	// from upstream finish, each signaling on this channel.
	upstreamDone := make(chan struct{}, 3)

	// Forward per-channel requests bidirectionally.
	go sshForwardChannelRequests(srcReqs, dstChan)
	go func() {
		sshForwardChannelRequests(dstReqs, srcChan)
		upstreamDone <- struct{}{}
	}()

	// Relay stdout/stdin bidirectionally.
	go io.Copy(dstChan, srcChan)
	go func() {
		io.Copy(srcChan, dstChan)
		upstreamDone <- struct{}{}
	}()

	// Relay stderr bidirectionally.
	go io.Copy(dstChan.Stderr(), srcChan.Stderr())
	go func() {
		io.Copy(srcChan.Stderr(), dstChan.Stderr())
		upstreamDone <- struct{}{}
	}()

	// Wait for upstream to fully close (data, stderr, and requests
	// all forwarded to agent).
	<-upstreamDone
	<-upstreamDone
	<-upstreamDone

	// Close both channels. The agent's session receives the channel
	// close and Session.Wait() can return.
	srcChan.Close()
	dstChan.Close()
}

// sshForwardChannelRequests forwards per-channel SSH requests from src to dst.
func sshForwardChannelRequests(reqs <-chan *ssh.Request, dst ssh.Channel) {
	for req := range reqs {
		ok, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}
		if req.WantReply {
			req.Reply(ok, nil)
		}
	}
}
