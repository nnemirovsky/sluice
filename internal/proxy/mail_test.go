package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
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
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintf(conn, "* OK IMAP4rev1 Server Ready\r\n")

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
			_, _ = fmt.Fprintf(conn, "%s OK LOGIN completed\r\n", tag)
		} else if strings.Contains(upper, " LOGOUT") {
			_, _ = fmt.Fprintf(conn, "%s OK LOGOUT completed\r\n", tag)
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
	defer func() { _ = conn.Close() }()
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
	if _, err := store.Add("imap_pass", "real-imap-secret"); err != nil {
		t.Fatal(err)
	}

	imapSrv, ln := startTestIMAPServer(t)
	defer func() { _ = ln.Close() }()

	binding := vault.Binding{
		Credential: "imap_pass",
		Protocols:  []string{"imap"},
	}

	mailProxy := NewMailProxy(store, nil)

	agentConn, proxyConn := tcpConnPair(t)

	errCh := make(chan error, 1)
	go func() {
		errCh <- mailProxy.HandleConnection(proxyConn, []string{ln.Addr().String()}, ln.Addr().String(), binding, ProtoIMAP, nil)
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
	_, _ = reader.ReadString('\n') // read LOGOUT response
	_ = agentConn.Close()
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
	if _, err := store.Add("smtp_pass", "real-smtp-secret"); err != nil {
		t.Fatal(err)
	}

	smtpSrv, ln := startTestSMTPServer(t)
	defer func() { _ = ln.Close() }()

	binding := vault.Binding{
		Credential: "smtp_pass",
		Protocols:  []string{"smtp"},
	}

	mailProxy := NewMailProxy(store, nil)

	agentConn, proxyConn := tcpConnPair(t)

	errCh := make(chan error, 1)
	go func() {
		errCh <- mailProxy.HandleConnection(proxyConn, []string{ln.Addr().String()}, ln.Addr().String(), binding, ProtoSMTP, nil)
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
	_, _ = reader.ReadString('\n') // read QUIT response
	_ = agentConn.Close()
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
	defer func() { _ = conn.Close() }()
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
	if _, err := store.Add("smtp_login_pass", "real-login-secret"); err != nil {
		t.Fatal(err)
	}

	smtpSrv, ln := startTestSMTPLoginServer(t)
	defer func() { _ = ln.Close() }()

	binding := vault.Binding{
		Credential: "smtp_login_pass",
		Protocols:  []string{"smtp"},
	}

	mailProxy := NewMailProxy(store, nil)
	agentConn, proxyConn := tcpConnPair(t)

	errCh := make(chan error, 1)
	go func() {
		errCh <- mailProxy.HandleConnection(proxyConn, []string{ln.Addr().String()}, ln.Addr().String(), binding, ProtoSMTP, nil)
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
	_, _ = reader.ReadString('\n')
	_ = agentConn.Close()
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

// TestPhantomNotReplacedInNonAuthCommands verifies that phantom tokens
// embedded in non-authentication commands (MAIL FROM, RCPT TO, IMAP APPEND,
// etc.) are NOT replaced with real credentials. This prevents an attacker
// from exfiltrating secrets by smuggling phantom tokens into arbitrary
// protocol commands.
func TestPhantomNotReplacedInNonAuthCommands(t *testing.T) {
	dir := t.TempDir()
	store, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("leak_test", "super-secret"); err != nil {
		t.Fatal(err)
	}

	mailProxy := NewMailProxy(store, nil)
	phantom := PhantomToken("leak_test")
	binding := vault.Binding{Credential: "leak_test"}

	// SMTP non-auth commands containing phantom should not be replaced.
	smtpCases := []string{
		fmt.Sprintf("MAIL FROM:<%s>\r\n", phantom),
		fmt.Sprintf("RCPT TO:<%s>\r\n", phantom),
		fmt.Sprintf("EHLO %s\r\n", phantom),
		fmt.Sprintf("VRFY %s\r\n", phantom),
	}
	for _, line := range smtpCases {
		sess := &mailSession{proxy: mailProxy, proto: ProtoSMTP}
		result := sess.processLine(line, phantom, binding)
		if strings.Contains(result, "super-secret") {
			t.Errorf("secret leaked in SMTP command: %q", strings.TrimRight(line, "\r\n"))
		}
		if !strings.Contains(result, phantom) {
			t.Errorf("phantom was removed from non-auth SMTP command: %q", strings.TrimRight(line, "\r\n"))
		}
	}

	// IMAP non-auth commands containing phantom should not be replaced.
	imapCases := []string{
		fmt.Sprintf("A001 SELECT %s\r\n", phantom),
		fmt.Sprintf("A002 FETCH 1 (BODY[TEXT] %s)\r\n", phantom),
		fmt.Sprintf("A003 SEARCH BODY %s\r\n", phantom),
	}
	for _, line := range imapCases {
		sess := &mailSession{proxy: mailProxy, proto: ProtoIMAP}
		result := sess.processLine(line, phantom, binding)
		if strings.Contains(result, "super-secret") {
			t.Errorf("secret leaked in IMAP command: %q", strings.TrimRight(line, "\r\n"))
		}
		if !strings.Contains(result, phantom) {
			t.Errorf("phantom was removed from non-auth IMAP command: %q", strings.TrimRight(line, "\r\n"))
		}
	}

	// IMAP LOGIN should still work (regression check).
	loginSess := &mailSession{proxy: mailProxy, proto: ProtoIMAP}
	loginLine := fmt.Sprintf("A001 LOGIN testuser %s\r\n", phantom)
	result := loginSess.processLine(loginLine, phantom, binding)
	if strings.Contains(result, phantom) {
		t.Error("phantom was NOT replaced in IMAP LOGIN (regression)")
	}
	if !strings.Contains(result, "super-secret") {
		t.Errorf("real credential not injected in IMAP LOGIN: %q", result)
	}
}

// testSMTPRejectAuthServer rejects AUTH PLAIN with 504 and captures any
// subsequent line the client sends. Used to verify that phantom tokens
// are NOT replaced when the server doesn't confirm auth continuation.
type testSMTPRejectAuthServer struct {
	mu          sync.Mutex
	capturedLine string
}

func startTestSMTPRejectAuthServer(t *testing.T) (*testSMTPRejectAuthServer, net.Listener) {
	t.Helper()
	srv := &testSMTPRejectAuthServer{}
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

func (s *testSMTPRejectAuthServer) handle(conn net.Conn) {
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
			fmt.Fprintf(conn, "250 OK\r\n")
		} else if upper == "AUTH PLAIN" {
			// Reject AUTH PLAIN (server does not support it).
			fmt.Fprintf(conn, "504 Unrecognized authentication type\r\n")
		} else if strings.HasPrefix(upper, "QUIT") {
			fmt.Fprintf(conn, "221 Bye\r\n")
			return
		} else {
			// Capture any other line (this is where the malicious
			// base64 continuation would arrive).
			s.mu.Lock()
			s.capturedLine = trimmed
			s.mu.Unlock()
			fmt.Fprintf(conn, "500 Unknown command\r\n")
		}
	}
}

func (s *testSMTPRejectAuthServer) CapturedLine() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.capturedLine
}

// TestAuthContinuationRequiresServerPrompt verifies that base64 continuation
// lines are NOT processed for phantom replacement unless the server has sent
// a proper continuation prompt (334 for SMTP). This prevents a malicious
// client from exfiltrating credentials by sending AUTH commands and
// phantom-containing base64 data without server cooperation.
func TestAuthContinuationRequiresServerPrompt(t *testing.T) {
	dir := t.TempDir()
	store, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("exfil_test", "top-secret-value"); err != nil {
		t.Fatal(err)
	}

	srv, ln := startTestSMTPRejectAuthServer(t)
	defer ln.Close()

	binding := vault.Binding{
		Credential: "exfil_test",
		Protocols:  []string{"smtp"},
	}

	mailProxy := NewMailProxy(store, nil)
	agentConn, proxyConn := tcpConnPair(t)

	errCh := make(chan error, 1)
	go func() {
		errCh <- mailProxy.HandleConnection(proxyConn, []string{ln.Addr().String()}, ln.Addr().String(), binding, ProtoSMTP, nil)
	}()

	phantom := PhantomToken("exfil_test")
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
	ehloResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read EHLO response: %v", err)
	}
	if !strings.HasPrefix(ehloResp, "250") {
		t.Fatalf("unexpected EHLO response: %q", ehloResp)
	}

	// Send AUTH PLAIN (continuation mode, no inline data).
	fmt.Fprintf(agentConn, "AUTH PLAIN\r\n")

	// Read server response: should be 504 (rejected), NOT 334.
	authResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read AUTH response: %v", err)
	}
	if strings.HasPrefix(authResp, "334") {
		t.Fatal("test server should reject AUTH PLAIN, not send 334")
	}

	// Now send base64-encoded phantom token as if it were a continuation.
	// This simulates the attack: the server rejected AUTH, but the
	// malicious client sends phantom data anyway.
	plainData := "\x00user\x00" + phantom
	b64 := base64.StdEncoding.EncodeToString([]byte(plainData))
	fmt.Fprintf(agentConn, "%s\r\n", b64)

	// Read the server's response to the base64 line.
	_, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read response to base64 line: %v", err)
	}

	// Disconnect.
	fmt.Fprintf(agentConn, "QUIT\r\n")
	reader.ReadString('\n')
	agentConn.Close()
	<-errCh

	// The server should have received the base64 line UNCHANGED.
	// If the vulnerability exists, the phantom would be replaced with
	// the real credential and forwarded to the server.
	captured := srv.CapturedLine()
	if strings.Contains(captured, "top-secret-value") {
		t.Error("SECURITY: real credential was injected despite server not confirming auth continuation")
	}
	// The line should still contain the phantom token (unreplaced)
	// or the base64-encoded version of it.
	if captured == "" {
		t.Error("server did not receive the continuation line")
	}
}

func TestIMAPVaultIntegrityAfterAuth(t *testing.T) {
	dir := t.TempDir()
	store, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("imap_zero", "secret-to-zero"); err != nil {
		t.Fatal(err)
	}

	_, ln := startTestIMAPServer(t)
	defer ln.Close()

	binding := vault.Binding{
		Credential: "imap_zero",
		Protocols:  []string{"imap"},
	}

	mailProxy := NewMailProxy(store, nil)

	agentConn, proxyConn := tcpConnPair(t)

	errCh := make(chan error, 1)
	go func() {
		errCh <- mailProxy.HandleConnection(proxyConn, []string{ln.Addr().String()}, ln.Addr().String(), binding, ProtoIMAP, nil)
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

// TestIMAPImplicitTLSAuthSwap verifies that the agent-side TLS termination
// works for implicit TLS (IMAPS) connections. The proxy presents a MITM cert
// to the agent, reads plaintext IMAP LOGIN commands through the TLS layer,
// replaces phantom tokens with real credentials, and forwards to upstream.
//
// Since binding to port 993 requires root, this test manually replicates the
// TLS wrapping that HandleConnection performs for implicit TLS ports, using
// a plain upstream IMAP server.
func TestIMAPImplicitTLSAuthSwap(t *testing.T) {
	dir := t.TempDir()
	store, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("imaps_pass", "real-imaps-secret"); err != nil {
		t.Fatal(err)
	}

	// Generate CA for the proxy's agent-side MITM.
	caCert, _, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}

	binding := vault.Binding{
		Credential: "imaps_pass",
		Protocols:  []string{"imap"},
	}

	mailProxy := NewMailProxy(store, &caCert)

	// Start a plain IMAP server (simulating the upstream after the proxy
	// has established its own TLS connection to the real server).
	imapSrv, plainLn := startTestIMAPServer(t)
	defer plainLn.Close()

	agentConn, proxyConn := tcpConnPair(t)

	// Build a CA pool that trusts our proxy CA for the agent's TLS client.
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert.Leaf)

	errCh := make(chan error, 1)
	go func() {
		// Replicate the implicit TLS wrapping from HandleConnection:
		// 1. Generate per-host cert signed by the CA
		// 2. Wrap the proxy side in TLS server (agent sees a TLS endpoint)
		// 3. Connect to the plain IMAP server upstream
		// 4. Relay with phantom replacement between the TLS and plain layers
		hostCert, err := GenerateHostCert(caCert, "localhost")
		if err != nil {
			errCh <- err
			return
		}
		agentTLS := tls.Server(proxyConn, &tls.Config{
			Certificates: []tls.Certificate{hostCert},
		})
		if err := agentTLS.Handshake(); err != nil {
			errCh <- err
			return
		}

		upstreamConn, err := net.Dial("tcp", plainLn.Addr().String())
		if err != nil {
			agentTLS.Close()
			errCh <- err
			return
		}

		phantom := PhantomToken("imaps_pass")
		sess := &mailSession{proxy: mailProxy, proto: ProtoIMAP}
		done := make(chan struct{})

		go func() {
			sr := bufio.NewReader(upstreamConn)
			for {
				line, readErr := sr.ReadString('\n')
				if len(line) > 0 {
					sess.processServerLine(line)
					if _, wErr := io.WriteString(agentTLS, line); wErr != nil {
						break
					}
				}
				if readErr != nil {
					break
				}
			}
			agentTLS.Close()
			close(done)
		}()

		cr := bufio.NewReader(agentTLS)
		for {
			line, readErr := cr.ReadString('\n')
			if len(line) > 0 {
				modified := sess.processLine(line, phantom, binding)
				if _, wErr := io.WriteString(upstreamConn, modified); wErr != nil {
					break
				}
			}
			if readErr != nil {
				break
			}
		}
		upstreamConn.Close()
		<-done
		errCh <- nil
	}()

	// Agent side: connect via TLS and speak IMAP.
	tlsClient := tls.Client(agentConn, &tls.Config{
		ServerName: "localhost",
		RootCAs:    caPool,
	})
	reader := bufio.NewReader(tlsClient)

	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.Contains(greeting, "OK") {
		t.Fatalf("unexpected greeting: %q", greeting)
	}

	phantom := PhantomToken("imaps_pass")
	fmt.Fprintf(tlsClient, "A001 LOGIN testuser %s\r\n", phantom)

	resp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(resp, "OK") {
		t.Fatalf("LOGIN failed: %q", resp)
	}

	fmt.Fprintf(tlsClient, "A002 LOGOUT\r\n")
	reader.ReadString('\n')
	tlsClient.Close()
	agentConn.Close()

	if err := <-errCh; err != nil {
		t.Fatalf("proxy error: %v", err)
	}

	loginCmd := imapSrv.LoginCommand()
	if strings.Contains(loginCmd, phantom) {
		t.Error("phantom token was not replaced in IMAP LOGIN over implicit TLS")
	}
	if !strings.Contains(loginCmd, "real-imaps-secret") {
		t.Errorf("real credential not found in LOGIN command: %q", loginCmd)
	}
}

// TestGenerateHostCert verifies that GenerateHostCert creates a valid
// certificate signed by the CA with the correct hostname.
func TestGenerateHostCert(t *testing.T) {
	caCert, _, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}

	hostCert, err := GenerateHostCert(caCert, "mail.example.com")
	if err != nil {
		t.Fatal(err)
	}

	if len(hostCert.Certificate) != 2 {
		t.Fatalf("expected 2 certs in chain (host + CA), got %d", len(hostCert.Certificate))
	}

	parsed, err := x509.ParseCertificate(hostCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Subject.CommonName != "mail.example.com" {
		t.Errorf("expected CN mail.example.com, got %q", parsed.Subject.CommonName)
	}

	if len(parsed.DNSNames) == 0 || parsed.DNSNames[0] != "mail.example.com" {
		t.Errorf("expected SAN mail.example.com, got %v", parsed.DNSNames)
	}

	// Verify the cert is signed by the CA.
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert.Leaf)
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: caPool}); err != nil {
		t.Errorf("host cert not valid under CA: %v", err)
	}
}
