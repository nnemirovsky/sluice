package proxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/nemirovsky/sluice/internal/vault"
)

// tcpConnPair creates a pair of connected TCP connections. Unlike net.Pipe(),
// TCP connections have kernel buffering so both sides can write concurrently
// without deadlocking (required for SSH version exchange).
func tcpConnPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		done <- c
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-done
	return client, server
}

// generateTestSSHKey creates an ECDSA key pair and returns the SSH signer,
// public key, and PEM-encoded private key suitable for vault storage.
func generateTestSSHKey(t *testing.T) (ssh.Signer, ssh.PublicKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	return signer, signer.PublicKey(), privPEM
}

// startTestSSHServer starts an in-process SSH server that only accepts
// connections authenticated with the given public key. It responds to
// "exec" requests by writing "hello from ssh" to stdout with exit code 0.
func startTestSSHServer(t *testing.T, authorizedKey ssh.PublicKey) net.Listener {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(pubKey.Marshal(), authorizedKey.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unknown public key for user %q", conn.User())
		},
	}
	config.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveTestSSHConn(conn, config)
		}
	}()

	return ln
}

func serveTestSSHConn(conn net.Conn, config *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		conn.Close()
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		ch, reqs, err := newChan.Accept()
		if err != nil {
			continue
		}
		go func(ch ssh.Channel, reqs <-chan *ssh.Request) {
			defer ch.Close()
			for req := range reqs {
				switch req.Type {
				case "exec":
					if req.WantReply {
						req.Reply(true, nil)
					}
					ch.Write([]byte("hello from ssh"))
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					return
				default:
					if req.WantReply {
						req.Reply(false, nil)
					}
				}
			}
		}(ch, reqs)
	}
}

func TestSSHJumpHostInjectsKey(t *testing.T) {
	// Generate SSH key pair for upstream authentication.
	_, pubKey, privPEM := generateTestSSHKey(t)

	// Store private key in vault.
	dir := t.TempDir()
	store, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("ssh_key", string(privPEM)); err != nil {
		t.Fatal(err)
	}

	// Start test SSH server that only accepts our public key.
	sshServer := startTestSSHServer(t, pubKey)
	defer sshServer.Close()

	// Generate host key for the proxy's SSH server side.
	proxyHostKey, err := GenerateSSHHostKey()
	if err != nil {
		t.Fatal(err)
	}

	binding := vault.Binding{
		Credential: "ssh_key",
		Template:   "testuser",
		Protocol:   "ssh",
	}

	jumpHost := NewSSHJumpHost(store, proxyHostKey)
	jumpHost.HostKeyCallback = ssh.InsecureIgnoreHostKey()

	// Use a TCP connection pair (buffered, unlike net.Pipe).
	agentConn, proxyConn := tcpConnPair(t)

	ready := make(chan error, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- jumpHost.HandleConnection(proxyConn, []string{sshServer.Addr().String()}, sshServer.Addr().String(), binding, ready)
	}()

	if setupErr := <-ready; setupErr != nil {
		t.Fatalf("handler setup: %v", setupErr)
	}

	// Agent SSH client connects with no credentials.
	agentSSH, agentChans, agentReqs, err := ssh.NewClientConn(agentConn, "proxy", &ssh.ClientConfig{
		User:            "ignored",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("agent SSH handshake: %v", err)
	}

	client := ssh.NewClient(agentSSH, agentChans, agentReqs)

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("open session: %v", err)
	}

	output, err := session.Output("echo test")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}

	if string(output) != "hello from ssh" {
		t.Errorf("expected 'hello from ssh', got %q", string(output))
	}

	client.Close()
	agentSSH.Close()
}

func TestSSHJumpHostMissingCredential(t *testing.T) {
	dir := t.TempDir()
	store, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	proxyHostKey, err := GenerateSSHHostKey()
	if err != nil {
		t.Fatal(err)
	}

	jumpHost := NewSSHJumpHost(store, proxyHostKey)
	jumpHost.HostKeyCallback = ssh.InsecureIgnoreHostKey()

	agentConn, proxyConn := tcpConnPair(t)
	defer agentConn.Close()

	binding := vault.Binding{
		Credential: "nonexistent",
		Template:   "testuser",
	}

	ready := make(chan error, 1)
	err = jumpHost.HandleConnection(proxyConn, []string{"127.0.0.1:22"}, "127.0.0.1:22", binding, ready)
	if err == nil {
		t.Fatal("expected error for missing credential")
	}
}

func TestSSHJumpHostBadKey(t *testing.T) {
	// Generate two different key pairs: one authorized, one not.
	_, pubKey, _ := generateTestSSHKey(t)
	_, _, wrongPEM := generateTestSSHKey(t)

	// Store the WRONG key in the vault.
	dir := t.TempDir()
	store, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("wrong_key", string(wrongPEM)); err != nil {
		t.Fatal(err)
	}

	// Start server that only accepts the first key.
	sshServer := startTestSSHServer(t, pubKey)
	defer sshServer.Close()

	proxyHostKey, err := GenerateSSHHostKey()
	if err != nil {
		t.Fatal(err)
	}

	binding := vault.Binding{
		Credential: "wrong_key",
		Template:   "testuser",
	}

	jumpHost := NewSSHJumpHost(store, proxyHostKey)
	jumpHost.HostKeyCallback = ssh.InsecureIgnoreHostKey()

	agentConn, proxyConn := tcpConnPair(t)
	defer agentConn.Close()

	// HandleConnection should fail because the upstream rejects our key.
	ready := make(chan error, 1)
	err = jumpHost.HandleConnection(proxyConn, []string{sshServer.Addr().String()}, sshServer.Addr().String(), binding, ready)
	if err == nil {
		t.Fatal("expected error when upstream rejects key")
	}
}

func TestSSHVaultIntegrityAfterHandshake(t *testing.T) {
	_, pubKey, privPEM := generateTestSSHKey(t)

	dir := t.TempDir()
	store, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("ssh_key_zero", string(privPEM)); err != nil {
		t.Fatal(err)
	}

	sshServer := startTestSSHServer(t, pubKey)
	defer sshServer.Close()

	proxyHostKey, err := GenerateSSHHostKey()
	if err != nil {
		t.Fatal(err)
	}

	binding := vault.Binding{
		Credential: "ssh_key_zero",
		Template:   "testuser",
	}

	jumpHost := NewSSHJumpHost(store, proxyHostKey)
	jumpHost.HostKeyCallback = ssh.InsecureIgnoreHostKey()

	agentConn, proxyConn := tcpConnPair(t)

	ready := make(chan error, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- jumpHost.HandleConnection(proxyConn, []string{sshServer.Addr().String()}, sshServer.Addr().String(), binding, ready)
	}()

	if setupErr := <-ready; setupErr != nil {
		t.Fatalf("handler setup: %v", setupErr)
	}

	// Connect, run command, disconnect.
	agentSSH, agentChans, agentReqs, err := ssh.NewClientConn(agentConn, "proxy", &ssh.ClientConfig{
		User:            "ignored",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("agent SSH handshake: %v", err)
	}

	client := ssh.NewClient(agentSSH, agentChans, agentReqs)
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	session.Output("test")
	client.Close()
	agentSSH.Close()

	// Wait for HandleConnection to return.
	<-errCh

	// The vault's encrypted credential is unaffected by zeroing the
	// in-memory SecureBytes copy. Verify the vault still works.
	after, err := store.Get("ssh_key_zero")
	if err != nil {
		t.Fatalf("credential should still be readable from vault: %v", err)
	}
	if after.IsReleased() {
		t.Error("stored credential should not appear released")
	}
	after.Release()
}
