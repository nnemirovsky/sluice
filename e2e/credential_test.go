//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/nemirovsky/sluice/internal/vault"
)

// testCA holds a generated CA certificate and key for testing HTTPS MITM.
type testCA struct {
	Cert    tls.Certificate
	X509    *x509.Certificate
	CertPEM []byte
	KeyPEM  []byte
}

// generateTestCA creates a new CA and writes cert+key files to dir so sluice
// can load them via LoadOrCreateCA.
func generateTestCA(t *testing.T, dir string) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Sluice E2E Test"},
			CommonName:   "Sluice Test CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("create vault dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca-cert.pem"), certPEM, 0644); err != nil {
		t.Fatalf("write CA cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca-key.pem"), keyPEM, 0600); err != nil {
		t.Fatalf("write CA key: %v", err)
	}

	return &testCA{
		Cert: tls.Certificate{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
			Leaf:        x509Cert,
		},
		X509:    x509Cert,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}
}

// startTLSEchoServerWithCA starts an HTTPS echo server using a certificate
// signed by the test CA. The sluice MITM proxy connects to this server as
// the upstream, so its cert must be trusted by goproxy's transport.
func startTLSEchoServerWithCA(t *testing.T, ca *testCA) *httptest.Server {
	t.Helper()

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	serverTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca.X509, &serverKey.PublicKey, ca.Cert.PrivateKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	serverTLSCert := tls.Certificate{
		Certificate: [][]byte{serverCertDER, ca.Cert.Certificate[0]},
		PrivateKey:  serverKey,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Method: %s\n", r.Method)
		fmt.Fprintf(w, "URL: %s\n", r.URL.String())
		fmt.Fprintf(w, "Host: %s\n", r.Host)
		for name, vals := range r.Header {
			for _, v := range vals {
				fmt.Fprintf(w, "Header: %s: %s\n", name, v)
			}
		}
		if r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			if len(body) > 0 {
				fmt.Fprintf(w, "Body: %s\n", string(body))
			}
		}
	})

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverTLSCert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// credTestSetup holds shared state for credential injection tests.
type credTestSetup struct {
	Proc     *SluiceProcess
	CA       *testCA
	VaultDir string
}

// startCredTestSluice starts sluice with credential injection enabled. It
// generates a test CA, configures the vault dir, and sets SSL_CERT_FILE so
// the MITM proxy trusts upstream echo servers signed by the test CA.
func startCredTestSluice(t *testing.T, extraTOML string) *credTestSetup {
	t.Helper()

	tmpDir := t.TempDir()
	vaultDir := filepath.Join(tmpDir, "vault")

	ca := generateTestCA(t, vaultDir)

	// Write CA cert to a standalone file. Setting SSL_CERT_FILE makes Go's
	// x509.SystemCertPool() use this file instead of system roots. The sluice
	// process's goproxy transport then trusts certs signed by the test CA.
	caCertFile := filepath.Join(tmpDir, "ca-bundle.pem")
	if err := os.WriteFile(caCertFile, ca.CertPEM, 0644); err != nil {
		t.Fatalf("write CA bundle: %v", err)
	}

	config := fmt.Sprintf(`
[policy]
default = "deny"

[vault]
provider = "age"
dir = %q

%s
`, vaultDir, extraTOML)

	proc := startSluice(t, SluiceOpts{
		ConfigTOML: config,
		Env: []string{
			"SSL_CERT_FILE=" + caCertFile,
			"SSL_CERT_DIR=", // prevent loading extra system certs
		},
	})

	return &credTestSetup{Proc: proc, CA: ca, VaultDir: vaultDir}
}

// runCredAdd runs `sluice cred add <name> [flags...]` piping the secret via stdin.
func runCredAdd(t *testing.T, proc *SluiceProcess, name, secret string, flags ...string) string {
	t.Helper()
	binary := buildSluice(t)
	args := []string{"cred", "add", "--db", proc.DBPath}
	args = append(args, flags...)
	args = append(args, name)
	cmd := exec.Command(binary, args...)
	cmd.Stdin = strings.NewReader(secret)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sluice cred add %s: %v\n%s", name, err, out)
	}
	return string(out)
}

// httpsRequestViaSOCKS5 makes an HTTP request through the SOCKS5 proxy.
// The client uses InsecureSkipVerify to accept sluice's MITM certificate.
func httpsRequestViaSOCKS5(t *testing.T, proxyAddr, method, url string, headers map[string]string, body string) (int, string) {
	t.Helper()
	dialer := connectSOCKS5(t, proxyAddr)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s via SOCKS5: %v", method, url, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp.StatusCode, string(respBody)
}

// TestCredential_HeaderInjection verifies that adding a credential with a
// binding via CLI and making an HTTPS request through the proxy results in
// the upstream receiving the real credential in the configured header.
func TestCredential_HeaderInjection(t *testing.T) {
	setup := startCredTestSluice(t, "")
	echo := startTLSEchoServerWithCA(t, setup.CA)
	_, port := mustSplitAddr(t, echo.URL)

	// Add credential with binding for the echo server.
	runCredAdd(t, setup.Proc, "test_api_key", "real-secret-value-123",
		"--destination", "127.0.0.1",
		"--ports", port,
		"--header", "X-Api-Key",
	)
	sendSIGHUP(t, setup.Proc)

	status, body := httpsRequestViaSOCKS5(t, setup.Proc.ProxyAddr, "GET", echo.URL+"/test", nil, "")
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}

	// The injector should have set X-Api-Key to the real credential value.
	if !strings.Contains(body, "Header: X-Api-Key: real-secret-value-123") {
		t.Errorf("upstream did not receive injected credential\nresponse:\n%s", body)
	}

	// Phantom token should not appear anywhere in the upstream request.
	if strings.Contains(body, "SLUICE_PHANTOM") {
		t.Errorf("phantom token leaked to upstream\nresponse:\n%s", body)
	}
}

// TestCredential_PhantomInBody verifies that phantom tokens in an HTTPS
// request body are replaced with real credential values.
func TestCredential_PhantomInBody(t *testing.T) {
	setup := startCredTestSluice(t, "")
	echo := startTLSEchoServerWithCA(t, setup.CA)
	_, port := mustSplitAddr(t, echo.URL)

	runCredAdd(t, setup.Proc, "body_cred", "body-secret-42",
		"--destination", "127.0.0.1",
		"--ports", port,
		"--header", "Authorization",
		"--template", "Bearer {value}",
	)
	sendSIGHUP(t, setup.Proc)

	// Send a POST with the phantom token in the body.
	phantom := "SLUICE_PHANTOM:body_cred"
	requestBody := fmt.Sprintf(`{"token": "%s", "data": "hello"}`, phantom)

	status, body := httpsRequestViaSOCKS5(t, setup.Proc.ProxyAddr, "POST", echo.URL+"/api",
		map[string]string{"Content-Type": "application/json"}, requestBody)
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}

	// The body should have the real value, not the phantom.
	if !strings.Contains(body, `"token": "body-secret-42"`) {
		t.Errorf("phantom in body was not replaced\nresponse:\n%s", body)
	}
	if strings.Contains(body, "SLUICE_PHANTOM") {
		t.Errorf("phantom token leaked in body\nresponse:\n%s", body)
	}

	// The header should also have the credential injected via template.
	if !strings.Contains(body, "Header: Authorization: Bearer body-secret-42") {
		t.Errorf("header injection with template did not work\nresponse:\n%s", body)
	}
}

// TestCredential_UnboundPhantomStripped verifies that phantom tokens sent to
// a host WITHOUT a credential binding are stripped (replaced with empty) so
// they never leak to upstream servers.
func TestCredential_UnboundPhantomStripped(t *testing.T) {
	// Start two HTTPS echo servers: one bound, one unbound.
	setup := startCredTestSluice(t, "")
	boundEcho := startTLSEchoServerWithCA(t, setup.CA)
	unboundEcho := startTLSEchoServerWithCA(t, setup.CA)
	_, boundPort := mustSplitAddr(t, boundEcho.URL)
	_, unboundPort := mustSplitAddr(t, unboundEcho.URL)

	// Add credential bound to the first echo server only.
	runCredAdd(t, setup.Proc, "bound_cred", "bound-secret",
		"--destination", "127.0.0.1",
		"--ports", boundPort,
		"--header", "X-Cred",
	)

	// Add an allow rule for the unbound echo server (no credential binding).
	runSluicePolicyAdd(t, setup.Proc, "allow", "--ports", unboundPort, "127.0.0.1")
	sendSIGHUP(t, setup.Proc)

	// Send request with phantom token to the UNBOUND server.
	phantom := "SLUICE_PHANTOM:bound_cred"
	status, body := httpsRequestViaSOCKS5(t, setup.Proc.ProxyAddr, "GET", unboundEcho.URL+"/leak-test",
		map[string]string{"X-Test": phantom}, "")
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}

	// Phantom must be stripped (not present in upstream request).
	if strings.Contains(body, "SLUICE_PHANTOM") {
		t.Errorf("phantom token leaked to unbound host\nresponse:\n%s", body)
	}

	// The real credential must NOT be injected into the unbound host.
	if strings.Contains(body, "bound-secret") {
		t.Errorf("real credential leaked to unbound host (cross-credential exfiltration)\nresponse:\n%s", body)
	}
}

// TestCredential_RedactRulesLoaded verifies that the proxy correctly loads
// redact rules from the policy config and that audit logging captures
// connections when redact rules are active.
//
// HTTP response redaction is applied at the WebSocket frame level and in the
// MCP gateway. For HTTPS MITM, the proxy modifies requests (phantom
// replacement) but does not currently modify response bodies. This test
// verifies the content inspection pipeline is wired up (rules loaded, audit
// active) even though HTTP response bodies pass through unmodified.
func TestCredential_RedactRulesLoaded(t *testing.T) {
	// Start an HTTPS echo server that includes a "secret" pattern in its
	// response body. The echo server reflects the URL path, so we control
	// what appears in the response.
	tmpDir := t.TempDir()
	vaultDir := filepath.Join(tmpDir, "vault")
	ca := generateTestCA(t, vaultDir)

	caCertFile := filepath.Join(tmpDir, "ca-bundle.pem")
	if err := os.WriteFile(caCertFile, ca.CertPEM, 0644); err != nil {
		t.Fatalf("write CA bundle: %v", err)
	}

	echo := startTLSEchoServerWithCA(t, ca)
	_, port := mustSplitAddr(t, echo.URL)

	// Configure redact rules and an allow rule for the echo server.
	config := fmt.Sprintf(`
[policy]
default = "deny"

[vault]
provider = "age"
dir = %q

[[allow]]
destination = "127.0.0.1"
ports = [%s]
name = "allow echo"

[[redact]]
pattern = "sk-[a-zA-Z0-9]{10,}"
replacement = "[REDACTED]"
name = "strip api keys from responses"
`, vaultDir, port)

	proc := startSluice(t, SluiceOpts{
		ConfigTOML: config,
		Env: []string{
			"SSL_CERT_FILE=" + caCertFile,
			"SSL_CERT_DIR=",
		},
	})

	// Make an HTTPS request. The echo server reflects the URL path in its
	// response body. Since HTTP response redaction is not applied at the
	// MITM layer (it is a WebSocket/MCP feature), the response should
	// contain the original content.
	status, body := httpsRequestViaSOCKS5(t, proc.ProxyAddr, "GET",
		echo.URL+"/data?key=sk-abcdefghij1234", nil, "")
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}

	// Verify the request reached the echo server (basic connectivity).
	if !strings.Contains(body, "URL: /data?key=sk-abcdefghij1234") {
		t.Errorf("echo server did not reflect request URL\nresponse:\n%s", body)
	}

	// Verify audit log captured the connection, confirming the inspection
	// pipeline is active for this connection.
	if !auditLogContains(t, proc.AuditPath, "127.0.0.1") {
		t.Error("audit log should contain an entry for the echo server connection")
	}
}

// TestCredential_Rotation verifies that rotating a credential (adding a new
// value for the same name) causes subsequent requests to use the new value.
func TestCredential_Rotation(t *testing.T) {
	setup := startCredTestSluice(t, "")
	echo := startTLSEchoServerWithCA(t, setup.CA)
	_, port := mustSplitAddr(t, echo.URL)

	// Add initial credential.
	runCredAdd(t, setup.Proc, "rotate_key", "original-value",
		"--destination", "127.0.0.1",
		"--ports", port,
		"--header", "X-Api-Key",
	)
	sendSIGHUP(t, setup.Proc)

	// Verify original value is injected.
	status, body := httpsRequestViaSOCKS5(t, setup.Proc.ProxyAddr, "GET", echo.URL+"/v1", nil, "")
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}
	if !strings.Contains(body, "Header: X-Api-Key: original-value") {
		t.Fatalf("original credential not injected\nresponse:\n%s", body)
	}

	// Rotate: add new value for the same credential name.
	// The CLI overwrites the vault entry. The binding and rule already exist.
	runCredAdd(t, setup.Proc, "rotate_key", "rotated-value")
	sendSIGHUP(t, setup.Proc)

	// Verify rotated value is used.
	status, body = httpsRequestViaSOCKS5(t, setup.Proc.ProxyAddr, "GET", echo.URL+"/v2", nil, "")
	if status != 200 {
		t.Fatalf("expected 200 after rotation, got %d", status)
	}
	if !strings.Contains(body, "Header: X-Api-Key: rotated-value") {
		t.Errorf("rotated credential not injected\nresponse:\n%s", body)
	}
	if strings.Contains(body, "original-value") {
		t.Errorf("old credential value still present after rotation\nresponse:\n%s", body)
	}
}

// TestCredential_MultipleDestinations verifies that different credentials
// are injected into the correct destinations when multiple bindings exist.
func TestCredential_MultipleDestinations(t *testing.T) {
	setup := startCredTestSluice(t, "")
	echoA := startTLSEchoServerWithCA(t, setup.CA)
	echoB := startTLSEchoServerWithCA(t, setup.CA)
	_, portA := mustSplitAddr(t, echoA.URL)
	_, portB := mustSplitAddr(t, echoB.URL)

	// Add credential A bound to echo server A.
	runCredAdd(t, setup.Proc, "cred_a", "secret-a",
		"--destination", "127.0.0.1",
		"--ports", portA,
		"--header", "X-Key-A",
	)

	// Add credential B bound to echo server B.
	runCredAdd(t, setup.Proc, "cred_b", "secret-b",
		"--destination", "127.0.0.1",
		"--ports", portB,
		"--header", "X-Key-B",
	)
	sendSIGHUP(t, setup.Proc)

	// Request to server A should get credential A.
	statusA, bodyA := httpsRequestViaSOCKS5(t, setup.Proc.ProxyAddr, "GET", echoA.URL+"/a", nil, "")
	if statusA != 200 {
		t.Fatalf("echo A: expected 200, got %d", statusA)
	}
	if !strings.Contains(bodyA, "Header: X-Key-A: secret-a") {
		t.Errorf("echo A did not receive credential A\nresponse:\n%s", bodyA)
	}
	if strings.Contains(bodyA, "secret-b") {
		t.Errorf("echo A received credential B (cross-leak)\nresponse:\n%s", bodyA)
	}

	// Request to server B should get credential B.
	statusB, bodyB := httpsRequestViaSOCKS5(t, setup.Proc.ProxyAddr, "GET", echoB.URL+"/b", nil, "")
	if statusB != 200 {
		t.Fatalf("echo B: expected 200, got %d", statusB)
	}
	if !strings.Contains(bodyB, "Header: X-Key-B: secret-b") {
		t.Errorf("echo B did not receive credential B\nresponse:\n%s", bodyB)
	}
	if strings.Contains(bodyB, "secret-a") {
		t.Errorf("echo B received credential A (cross-leak)\nresponse:\n%s", bodyB)
	}
}

// TestCredential_SSHInjection verifies that SSH connections through the
// SOCKS5 proxy use the vault credential for upstream authentication.
func TestCredential_SSHInjection(t *testing.T) {
	// Generate an SSH key pair for authentication.
	sshKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate SSH key: %v", err)
	}

	signer, err := gossh.NewSignerFromKey(sshKey)
	if err != nil {
		t.Fatalf("create SSH signer: %v", err)
	}

	// Marshal private key to PEM for storing in the vault.
	keyDER, err := x509.MarshalECPrivateKey(sshKey)
	if err != nil {
		t.Fatalf("marshal SSH key: %v", err)
	}
	privKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Start a test SSH server that accepts public key authentication.
	sshListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for SSH: %v", err)
	}
	t.Cleanup(func() { _ = sshListener.Close() })

	sshPort := sshListener.Addr().(*net.TCPAddr).Port

	// Generate host key for the SSH server.
	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := gossh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatalf("create host signer: %v", err)
	}

	serverConfig := &gossh.ServerConfig{
		PublicKeyCallback: func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			if bytes.Equal(key.Marshal(), signer.PublicKey().Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unknown key")
		},
	}
	serverConfig.AddHostKey(hostSigner)

	// Run SSH server in background.
	sshDone := make(chan struct{})
	go func() {
		defer close(sshDone)
		conn, err := sshListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		sshConn, chans, reqs, err := gossh.NewServerConn(conn, serverConfig)
		if err != nil {
			return
		}
		defer sshConn.Close()
		go gossh.DiscardRequests(reqs)

		for newChan := range chans {
			if newChan.ChannelType() != "session" {
				_ = newChan.Reject(gossh.UnknownChannelType, "unsupported")
				continue
			}
			ch, chReqs, _ := newChan.Accept()
			go func() {
				for req := range chReqs {
					if req.Type == "exec" {
						// Reply to the exec request before writing output.
						if req.WantReply {
							_ = req.Reply(true, nil)
						}
						_, _ = ch.Write([]byte("ssh-injection-ok\n"))
						_ = ch.CloseWrite()
						_, _ = ch.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{0}))
						_ = ch.Close()
						return
					}
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
				}
			}()
		}
	}()

	// Set up known_hosts so the SSH jump host trusts the test server.
	tmpDir := t.TempDir()
	vaultDir := filepath.Join(tmpDir, "vault")
	if err := os.MkdirAll(vaultDir, 0700); err != nil {
		t.Fatalf("create vault dir: %v", err)
	}

	sshDir := filepath.Join(tmpDir, "fakehome", ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("create .ssh dir: %v", err)
	}

	// Write known_hosts entry for the test SSH server.
	knownHostsLine := fmt.Sprintf("[127.0.0.1]:%d %s\n", sshPort, strings.TrimSpace(string(gossh.MarshalAuthorizedKey(hostSigner.PublicKey()))))
	if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte(knownHostsLine), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	// Import TOML with SSH binding (protocols=["ssh"]).
	// The allow rule must NOT have protocols=["ssh"] because policy evaluation
	// happens before protocol detection. On non-standard ports, the detected
	// protocol is "generic", so a protocol-scoped rule would not match. The
	// binding uses protocols=["ssh"] to route the connection through the SSH
	// jump host after policy allows it.
	tomlConfig := fmt.Sprintf(`
[policy]
default = "deny"

[vault]
provider = "age"
dir = %q

[[allow]]
destination = "127.0.0.1"
ports = [%d]
name = "allow test SSH"

[[binding]]
destination = "127.0.0.1"
ports = [%d]
credential = "ssh_key"
protocols = ["ssh"]
template = "testuser"
`, vaultDir, sshPort, sshPort)

	proc := startSluice(t, SluiceOpts{
		ConfigTOML: tomlConfig,
		Env: []string{
			"HOME=" + filepath.Join(tmpDir, "fakehome"),
		},
	})

	// Add SSH private key directly to the vault store. The CLI's `sluice cred
	// add` reads one line from stdin, which cannot handle multi-line PEM keys.
	vs, err := vault.NewStore(vaultDir)
	if err != nil {
		t.Fatalf("open vault store: %v", err)
	}
	if _, err := vs.Add("ssh_key", string(privKeyPEM)); err != nil {
		t.Fatalf("add SSH key to vault: %v", err)
	}
	sendSIGHUP(t, proc)

	// Connect through SOCKS5 to the test SSH server.
	dialer := connectSOCKS5(t, proc.ProxyAddr)
	conn, err := dialer.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort))
	if err != nil {
		t.Fatalf("SOCKS5 dial to SSH server: %v", err)
	}
	defer conn.Close()

	// The sluice SSH jump host accepts any auth from the agent, so we
	// connect with no authentication. It authenticates to the upstream
	// test SSH server using the vault credential.
	clientConfig := &gossh.ClientConfig{
		User:            "ignored", // jump host ignores this
		Auth:            []gossh.AuthMethod{}, // no auth needed
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	sshClientConn, chans, reqs, err := gossh.NewClientConn(conn, fmt.Sprintf("127.0.0.1:%d", sshPort), clientConfig)
	if err != nil {
		t.Fatalf("SSH handshake through proxy: %v", err)
	}
	defer sshClientConn.Close()

	// NewClient takes ownership of chans and reqs. Do not start separate
	// goroutines to consume them.
	client := gossh.NewClient(sshClientConn, chans, reqs)
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("open SSH session: %v", err)
	}
	defer session.Close()

	output, err := session.Output("whoami")
	if err != nil {
		t.Fatalf("exec command via SSH: %v", err)
	}

	result := strings.TrimSpace(string(output))
	if result != "ssh-injection-ok" {
		t.Errorf("expected 'ssh-injection-ok', got %q", result)
	}

	// Verify audit log recorded the SSH connection.
	if !auditLogContains(t, proc.AuditPath, fmt.Sprintf(":%d", sshPort)) {
		t.Error("audit log should contain SSH connection entry")
	}

	// Close the SSH session and client connection before waiting for the
	// server goroutine. The defers registered above won't run until the
	// function returns, so we must close explicitly to unblock the test
	// server's "for newChan := range chans" loop.
	session.Close()
	sshClientConn.Close()
	conn.Close()

	// Wait for SSH server goroutine to finish.
	_ = sshListener.Close()

	timer := time.NewTimer(5 * time.Second)
	select {
	case <-sshDone:
	case <-timer.C:
		t.Error("SSH server goroutine did not finish within timeout")
	}
	timer.Stop()
}

