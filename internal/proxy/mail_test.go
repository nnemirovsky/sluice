package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/nemirovsky/sluice/internal/vault"
)

// testIMAPServer is a minimal IMAP server that captures LOGIN credentials.
type testIMAPServer struct {
	mu       sync.Mutex
	loginCmd string
}

func startTestIMAPServer(t *testing.T) (*testIMAPServer, net.Listener) {
	t.Helper()
	srv := &testIMAPServer{}
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
			go srv.handle(conn)
		}
	}()
	return srv, ln
}

func (s *testIMAPServer) handle(conn net.Conn) {
	defer conn.Close()
	fmt.Fprintf(conn, "* OK IMAP4rev1 Server Ready\r\n")

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		trimmed := strings.TrimRight(line, "\r\n")
		parts := strings.SplitN(trimmed, " ", 3)
		if len(parts) < 2 {
			continue
		}
		tag := parts[0]
		upper := strings.ToUpper(trimmed)

		if strings.Contains(upper, " LOGIN ") {
			s.mu.Lock()
			s.loginCmd = trimmed
			s.mu.Unlock()
			fmt.Fprintf(conn, "%s OK LOGIN completed\r\n", tag)
		} else if strings.Contains(upper, " LOGOUT") {
			fmt.Fprintf(conn, "%s OK LOGOUT completed\r\n", tag)
			return
		} else {
			fmt.Fprintf(conn, "%s BAD Unknown command\r\n", tag)
		}
	}
}

func (s *testIMAPServer) LoginCommand() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loginCmd
}

// testSMTPServer is a minimal SMTP server that captures AUTH PLAIN credentials.
type testSMTPServer struct {
	mu       sync.Mutex
	authData []byte
}

func startTestSMTPServer(t *testing.T) (*testSMTPServer, net.Listener) {
	t.Helper()
	srv := &testSMTPServer{}
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
			go srv.handle(conn)
		}
	}()
	return srv, ln
}

func (s *testSMTPServer) handle(conn net.Conn) {
	defer conn.Close()
	fmt.Fprintf(conn, "220 smtp.test.local ESMTP\r\n")

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		trimmed := strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(trimmed)

		if strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO") {
			fmt.Fprintf(conn, "250-smtp.test.local\r\n250 AUTH PLAIN LOGIN\r\n")
		} else if strings.HasPrefix(upper, "AUTH PLAIN ") {
			parts := strings.SplitN(trimmed, " ", 3)
			if len(parts) == 3 {
				decoded, decErr := base64.StdEncoding.DecodeString(parts[2])
				if decErr == nil {
					s.mu.Lock()
					s.authData = decoded
					s.mu.Unlock()
					fmt.Fprintf(conn, "235 2.7.0 Authentication successful\r\n")
				} else {
					fmt.Fprintf(conn, "535 5.7.8 Authentication failed\r\n")
				}
			}
		} else if strings.HasPrefix(upper, "QUIT") {
			fmt.Fprintf(conn, "221 Bye\r\n")
			return
		} else {
			fmt.Fprintf(conn, "500 Unknown command\r\n")
		}
	}
}

func (s *testSMTPServer) AuthData() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authData
}

func TestIMAPAuthSwap(t *testing.T) {
	dir := t.TempDir()
	store, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add("imap_pass", "real-imap-secret"); err != nil {
		t.Fatal(err)
	}

	imapSrv, ln := startTestIMAPServer(t)
	defer ln.Close()

	binding := vault.Binding{
		Credential: "imap_pass",
		Protocol:   "imap",
	}

	mailProxy := NewMailProxy(store)

	agentConn, proxyConn := tcpConnPair(t)

	errCh := make(chan error, 1)
	go func() {
		errCh <- mailProxy.HandleConnection(proxyConn, ln.Addr().String(), binding, ProtoIMAP)
	}()

	phantom := PhantomToken("imap_pass")
	reader := bufio.NewReader(agentConn)

	// Read server greeting.
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.Contains(greeting, "OK") {
		t.Fatalf("unexpected greeting: %q", greeting)
	}

	// Send LOGIN with phantom token.
	fmt.Fprintf(agentConn, "A001 LOGIN testuser %s\r\n", phantom)

	// Read LOGIN response.
	resp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(resp, "OK") {
		t.Fatalf("LOGIN failed: %q", resp)
	}

	// Disconnect.
	fmt.Fprintf(agentConn, "A002 LOGOUT\r\n")
	reader.ReadString('\n') // read LOGOUT response
	agentConn.Close()
	<-errCh

	// Verify server received the real password, not the phantom.
	loginCmd := imapSrv.LoginCommand()
	if strings.Contains(loginCmd, phantom) {
		t.Error("phantom token was not replaced in IMAP LOGIN")
	}
	if !strings.Contains(loginCmd, "real-imap-secret") {
		t.Errorf("real credential not found in LOGIN command: %q", loginCmd)
	}
}

func TestSMTPAuthPlainSwap(t *testing.T) {
	dir := t.TempDir()
	store, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add("smtp_pass", "real-smtp-secret"); err != nil {
		t.Fatal(err)
	}

	smtpSrv, ln := startTestSMTPServer(t)
	defer ln.Close()

	binding := vault.Binding{
		Credential: "smtp_pass",
		Protocol:   "smtp",
	}

	mailProxy := NewMailProxy(store)

	agentConn, proxyConn := tcpConnPair(t)

	errCh := make(chan error, 1)
	go func() {
		errCh <- mailProxy.HandleConnection(proxyConn, ln.Addr().String(), binding, ProtoSMTP)
	}()

	phantom := PhantomToken("smtp_pass")
	reader := bufio.NewReader(agentConn)

	// Read SMTP greeting.
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "220") {
		t.Fatalf("unexpected greeting: %q", greeting)
	}

	// Send EHLO.
	fmt.Fprintf(agentConn, "EHLO test.local\r\n")
	// Read multi-line EHLO response.
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read EHLO response: %v", err)
		}
		// Last line of multi-line response starts with "250 " (space, not dash).
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// Build AUTH PLAIN with phantom. AUTH PLAIN format: \0username\0password
	plainData := "\x00testuser\x00" + phantom
	b64 := base64.StdEncoding.EncodeToString([]byte(plainData))
	fmt.Fprintf(agentConn, "AUTH PLAIN %s\r\n", b64)

	// Read auth response.
	authResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read auth response: %v", err)
	}
	if !strings.HasPrefix(authResp, "235") {
		t.Fatalf("AUTH PLAIN failed: %q", authResp)
	}

	// Disconnect.
	fmt.Fprintf(agentConn, "QUIT\r\n")
	reader.ReadString('\n') // read QUIT response
	agentConn.Close()
	<-errCh

	// Verify server received the real password, not the phantom.
	authData := smtpSrv.AuthData()
	if strings.Contains(string(authData), phantom) {
		t.Error("phantom token was not replaced in SMTP AUTH PLAIN")
	}
	// AUTH PLAIN payload: \0username\0password
	authStr := string(authData)
	parts := strings.SplitN(authStr, "\x00", 3)
	if len(parts) != 3 {
		t.Fatalf("unexpected AUTH PLAIN data format: %q", authData)
	}
	if parts[2] != "real-smtp-secret" {
		t.Errorf("expected 'real-smtp-secret', got %q", parts[2])
	}
}

// testSMTPLoginServer handles AUTH LOGIN (multi-step: username then password).
type testSMTPLoginServer struct {
	mu       sync.Mutex
	username string
	password string
}

func startTestSMTPLoginServer(t *testing.T) (*testSMTPLoginServer, net.Listener) {
	t.Helper()
	srv := &testSMTPLoginServer{}
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
			go srv.handle(conn)
		}
	}()
	return srv, ln
}

func (s *testSMTPLoginServer) handle(conn net.Conn) {
	defer conn.Close()
	fmt.Fprintf(conn, "220 smtp.test.local ESMTP\r\n")

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		trimmed := strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(trimmed)

		if strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO") {
			fmt.Fprintf(conn, "250-smtp.test.local\r\n250 AUTH PLAIN LOGIN\r\n")
		} else if upper == "AUTH LOGIN" || strings.HasPrefix(upper, "AUTH LOGIN ") {
			// Send username prompt.
			fmt.Fprintf(conn, "334 VXNlcm5hbWU6\r\n")
			userLine, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			userB64 := strings.TrimRight(userLine, "\r\n")
			userBytes, _ := base64.StdEncoding.DecodeString(userB64)

			// Send password prompt.
			fmt.Fprintf(conn, "334 UGFzc3dvcmQ6\r\n")
			passLine, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			passB64 := strings.TrimRight(passLine, "\r\n")
			passBytes, _ := base64.StdEncoding.DecodeString(passB64)

			s.mu.Lock()
			s.username = string(userBytes)
			s.password = string(passBytes)
			s.mu.Unlock()
			fmt.Fprintf(conn, "235 2.7.0 Authentication successful\r\n")
		} else if strings.HasPrefix(upper, "QUIT") {
			fmt.Fprintf(conn, "221 Bye\r\n")
			return
		} else {
			fmt.Fprintf(conn, "500 Unknown command\r\n")
		}
	}
}

func (s *testSMTPLoginServer) Credentials() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.username, s.password
}

func TestSMTPAuthLoginSwap(t *testing.T) {
	dir := t.TempDir()
	store, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add("smtp_login_pass", "real-login-secret"); err != nil {
		t.Fatal(err)
	}

	smtpSrv, ln := startTestSMTPLoginServer(t)
	defer ln.Close()

	binding := vault.Binding{
		Credential: "smtp_login_pass",
		Protocol:   "smtp",
	}

	mailProxy := NewMailProxy(store)
	agentConn, proxyConn := tcpConnPair(t)

	errCh := make(chan error, 1)
	go func() {
		errCh <- mailProxy.HandleConnection(proxyConn, ln.Addr().String(), binding, ProtoSMTP)
	}()

	phantom := PhantomToken("smtp_login_pass")
	reader := bufio.NewReader(agentConn)

	// Read SMTP greeting.
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "220") {
		t.Fatalf("unexpected greeting: %q", greeting)
	}

	// EHLO.
	fmt.Fprintf(agentConn, "EHLO test.local\r\n")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read EHLO response: %v", err)
		}
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// Send AUTH LOGIN.
	fmt.Fprintf(agentConn, "AUTH LOGIN\r\n")

	// Read 334 username prompt.
	prompt1, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read username prompt: %v", err)
	}
	if !strings.HasPrefix(prompt1, "334") {
		t.Fatalf("unexpected username prompt: %q", prompt1)
	}

	// Send base64 username (no phantom, just a plain username).
	fmt.Fprintf(agentConn, "%s\r\n", base64.StdEncoding.EncodeToString([]byte("testuser")))

	// Read 334 password prompt.
	prompt2, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read password prompt: %v", err)
	}
	if !strings.HasPrefix(prompt2, "334") {
		t.Fatalf("unexpected password prompt: %q", prompt2)
	}

	// Send base64 password WITH phantom token.
	fmt.Fprintf(agentConn, "%s\r\n", base64.StdEncoding.EncodeToString([]byte(phantom)))

	// Read auth response.
	authResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read auth response: %v", err)
	}
	if !strings.HasPrefix(authResp, "235") {
		t.Fatalf("AUTH LOGIN failed: %q", authResp)
	}

	// Disconnect.
	fmt.Fprintf(agentConn, "QUIT\r\n")
	reader.ReadString('\n')
	agentConn.Close()
	<-errCh

	// Verify server received real credentials.
	username, password := smtpSrv.Credentials()
	if username != "testuser" {
		t.Errorf("expected username 'testuser', got %q", username)
	}
	if password == phantom {
		t.Error("phantom token was not replaced in AUTH LOGIN password")
	}
	if password != "real-login-secret" {
		t.Errorf("expected password 'real-login-secret', got %q", password)
	}
}

func TestIMAPVaultIntegrityAfterAuth(t *testing.T) {
	dir := t.TempDir()
	store, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add("imap_zero", "secret-to-zero"); err != nil {
		t.Fatal(err)
	}

	_, ln := startTestIMAPServer(t)
	defer ln.Close()

	binding := vault.Binding{
		Credential: "imap_zero",
		Protocol:   "imap",
	}

	mailProxy := NewMailProxy(store)

	agentConn, proxyConn := tcpConnPair(t)

	errCh := make(chan error, 1)
	go func() {
		errCh <- mailProxy.HandleConnection(proxyConn, ln.Addr().String(), binding, ProtoIMAP)
	}()

	phantom := PhantomToken("imap_zero")
	reader := bufio.NewReader(agentConn)

	reader.ReadString('\n') // greeting
	fmt.Fprintf(agentConn, "A001 LOGIN user %s\r\n", phantom)
	reader.ReadString('\n') // LOGIN OK
	fmt.Fprintf(agentConn, "A002 LOGOUT\r\n")
	reader.ReadString('\n') // LOGOUT OK
	agentConn.Close()
	<-errCh

	// The vault's encrypted credential is unaffected by in-memory zeroing.
	after, err := store.Get("imap_zero")
	if err != nil {
		t.Fatalf("credential should still be readable from vault: %v", err)
	}
	if after.IsReleased() {
		t.Error("stored credential should not appear released")
	}
	after.Release()
}
