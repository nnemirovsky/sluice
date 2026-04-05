package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/nemirovsky/sluice/internal/vault"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// SSHJumpHost handles SSH connections by acting as a credential-injecting
// intermediary. It presents an SSH server to the agent (accepting any
// authentication), authenticates to the upstream server using credentials
// from the vault, and relays SSH session channels between the two.
type SSHJumpHost struct {
	provider vault.Provider
	hostKey  ssh.Signer
	// HostKeyCallback verifies the upstream SSH server's host key.
	// If nil, the jump host attempts to use the system known_hosts file
	// (~/.ssh/known_hosts). If that file does not exist, connections to
	// upstream servers are rejected to prevent silent MITM attacks.
	HostKeyCallback ssh.HostKeyCallback
}

// NewSSHJumpHost creates an SSH jump host handler. The hostKey is presented
// to agents connecting through the proxy. The provider is used to look up
// SSH private keys for upstream authentication.
func NewSSHJumpHost(provider vault.Provider, hostKey ssh.Signer) *SSHJumpHost {
	return &SSHJumpHost{
		provider: provider,
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

// resolveHostKeyCallback returns the host key callback to use for upstream
// connections. It checks in order: explicit HostKeyCallback field, system
// known_hosts file, then returns an error (never falls back to insecure).
func (h *SSHJumpHost) resolveHostKeyCallback() (ssh.HostKeyCallback, error) {
	if h.HostKeyCallback != nil {
		return h.HostKeyCallback, nil
	}

	home, err := os.UserHomeDir()
	if err == nil {
		khPath := filepath.Join(home, ".ssh", "known_hosts")
		if cb, khErr := knownhosts.New(khPath); khErr == nil {
			return cb, nil
		}
	}

	return nil, fmt.Errorf("no HostKeyCallback configured and no ~/.ssh/known_hosts found; " +
		"set SSHJumpHost.HostKeyCallback or populate known_hosts to verify upstream servers")
}

// HandleConnection manages the SSH jump host relay between an agent and
// an upstream SSH server. The agentConn is the raw TCP stream from the
// agent (after SOCKS5 handshake). dialAddrs is a list of policy-approved
// IP:port addresses to try in order for the upstream TCP connection.
// hostAddr is the FQDN:port used for SSH host key verification
// (known_hosts matching). The binding specifies which credential to use
// and the SSH username (via the Template field).
//
// The ready channel signals when setup is complete. nil means the handler
// is ready to relay traffic. A non-nil error means setup failed and the
// SOCKS5 layer should report a connection failure to the client.
//
// Flow:
//  1. Decrypt SSH private key from vault into SecureBytes
//  2. Parse the key and zero the vault copy immediately
//  3. Dial upstream SSH server using policy-approved IPs and
//     authenticate with the real key
//  4. Signal ready (setup complete)
//  5. Accept the agent's SSH connection with no authentication
//  6. Relay SSH channels between agent and upstream
func (h *SSHJumpHost) HandleConnection(agentConn net.Conn, dialAddrs []string, hostAddr string, binding vault.Binding, ready chan<- error) error {
	defer func() { _ = agentConn.Close() }()

	// signalErr sends an error on ready (if non-nil) to report setup
	// failure to the SOCKS5 layer before returning.
	signalErr := func(err error) error {
		if ready != nil {
			ready <- err
			ready = nil
		}
		return err
	}

	// Decrypt SSH private key from vault.
	secret, err := h.provider.Get(binding.Credential)
	if err != nil {
		return signalErr(fmt.Errorf("get credential %q: %w", binding.Credential, err))
	}

	signer, parseErr := ssh.ParsePrivateKey(secret.Bytes())
	secret.Release() // Zero vault copy immediately after parsing.
	if parseErr != nil {
		return signalErr(fmt.Errorf("parse SSH key for %q: %w", binding.Credential, parseErr))
	}

	// Template field holds the SSH username for SSH bindings.
	username := binding.Template
	if username == "" {
		username = "root"
	}

	// Dial upstream using policy-approved IP addresses to prevent DNS
	// rebinding between policy evaluation and connection. Multiple
	// addresses provide fallback on dual-stack hosts.
	var upstreamTCP net.Conn
	var lastDialErr error
	for _, addr := range dialAddrs {
		upstreamTCP, lastDialErr = net.DialTimeout("tcp", addr, connectTimeout)
		if lastDialErr == nil {
			break
		}
	}
	if lastDialErr != nil {
		return signalErr(fmt.Errorf("dial upstream %v: %w", dialAddrs, lastDialErr))
	}

	hostKeyCallback, hkErr := h.resolveHostKeyCallback()
	if hkErr != nil {
		_ = upstreamTCP.Close()
		return signalErr(fmt.Errorf("SSH host key verification: %w", hkErr))
	}

	// Use hostAddr (FQDN:port) for the SSH client so host key
	// verification matches known_hosts entries by hostname.
	upstreamSSH, upstreamChans, upstreamReqs, err := ssh.NewClientConn(upstreamTCP, hostAddr, &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         connectTimeout,
	})
	if err != nil {
		_ = upstreamTCP.Close()
		return signalErr(fmt.Errorf("SSH handshake with %s: %w", hostAddr, err))
	}
	defer func() { _ = upstreamSSH.Close() }()

	log.Printf("[SSH] authenticated to %s as %q via credential %q", hostAddr, username, binding.Credential)

	// Setup complete. Signal the SOCKS5 layer to send CONNECT success.
	if ready != nil {
		ready <- nil
		ready = nil
	}

	// Accept the agent's SSH connection with no authentication required.
	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(h.hostKey)

	agentSSH, agentChans, agentReqs, err := ssh.NewServerConn(agentConn, serverConfig)
	if err != nil {
		return fmt.Errorf("agent SSH handshake: %w", err)
	}
	defer func() { _ = agentSSH.Close() }()

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
				_ = req.Reply(false, nil)
			}
			continue
		}
		if req.WantReply {
			_ = req.Reply(ok, payload)
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
		var openErr *ssh.OpenChannelError
		if errors.As(err, &openErr) {
			_ = newChan.Reject(openErr.Reason, openErr.Message)
		} else {
			_ = newChan.Reject(ssh.ConnectionFailed, err.Error())
		}
		return
	}

	srcChan, srcReqs, err := newChan.Accept()
	if err != nil {
		go ssh.DiscardRequests(dstReqs)
		_ = dstChan.Close()
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
	// CloseWrite signals EOF to the remote side so processes reading
	// stdin until EOF (cat, sort, piped input) terminate properly.
	go func() {
		_, _ = io.Copy(dstChan, srcChan)
		_ = dstChan.CloseWrite()
	}()
	go func() {
		_, _ = io.Copy(srcChan, dstChan)
		_ = srcChan.CloseWrite()
		upstreamDone <- struct{}{}
	}()

	// Relay stderr bidirectionally.
	go func() { _, _ = io.Copy(dstChan.Stderr(), srcChan.Stderr()) }()
	go func() {
		_, _ = io.Copy(srcChan.Stderr(), dstChan.Stderr())
		upstreamDone <- struct{}{}
	}()

	// Wait for upstream to fully close (data, stderr, and requests
	// all forwarded to agent).
	<-upstreamDone
	<-upstreamDone
	<-upstreamDone

	// Close both channels. The agent's session receives the channel
	// close and Session.Wait() can return.
	_ = srcChan.Close()
	_ = dstChan.Close()
}

// sshForwardChannelRequests forwards per-channel SSH requests from src to dst.
func sshForwardChannelRequests(reqs <-chan *ssh.Request, dst ssh.Channel) {
	for req := range reqs {
		ok, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		if req.WantReply {
			_ = req.Reply(ok, nil)
		}
	}
}
