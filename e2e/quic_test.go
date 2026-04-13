//go:build e2e

package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// startHTTP3EchoServer starts an HTTP/3 echo server on a free UDP port using
// the test CA. It returns the address (host:port). The server echoes request
// details back as plain text, the same as the HTTP/HTTPS echo servers.
func startHTTP3EchoServer(t *testing.T, ca *testCA) (addr string) {
	t.Helper()

	serverCert, certErr := generateServerTLSCert(t, ca, "127.0.0.1")
	if certErr != nil {
		t.Fatal(certErr)
	}

	udpPort := freeUDPPort(t)
	udpAddr := fmt.Sprintf("127.0.0.1:%d", udpPort)

	handler := httpEchoHandler()

	srv := &http3.Server{
		Addr:    udpAddr,
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
		},
	}

	// Listen on UDP first, then serve.
	udpConn, err := net.ListenPacket("udp4", udpAddr)
	if err != nil {
		t.Fatalf("listen udp for HTTP/3: %v", err)
	}

	go func() {
		if serveErr := srv.Serve(udpConn); serveErr != nil && !strings.Contains(serveErr.Error(), "closed") {
			t.Logf("HTTP/3 server stopped: %v", serveErr)
		}
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = udpConn.Close()
	})

	return udpAddr
}

// TestQUIC_HTTP3ServerStarts verifies that the HTTP/3 echo server starts and
// accepts direct connections (without going through sluice). This validates
// the test infrastructure before testing the proxy path.
func TestQUIC_HTTP3ServerStarts(t *testing.T) {
	tmpDir := t.TempDir()
	vaultDir := tmpDir + "/vault"
	ca := generateTestCA(t, vaultDir)

	h3Addr := startHTTP3EchoServer(t, ca)

	// Create a pool with the test CA cert.
	pool := certPoolFromCA(t, ca)

	roundTripper := &http3.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: pool,
		},
	}
	defer roundTripper.Close()

	client := &http.Client{Transport: roundTripper, Timeout: 5 * time.Second}

	resp, err := client.Get("https://" + h3Addr + "/test")
	if err != nil {
		t.Fatalf("direct HTTP/3 request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d\nbody: %s", resp.StatusCode, bodyStr)
	}
	if !strings.Contains(bodyStr, "Proto: HTTP/3") {
		t.Errorf("expected HTTP/3 protocol, got:\n%s", bodyStr)
	}
}

// TestQUIC_SluiceStartsWithQUICProxy verifies that sluice starts successfully
// with QUIC proxy support enabled (it has a CA cert for QUIC MITM). This is
// a basic wiring test. Full QUIC e2e through the SOCKS5 UDP ASSOCIATE path
// requires tun2proxy which is not available in the e2e sandbox.
func TestQUIC_SluiceStartsWithQUICProxy(t *testing.T) {
	tmpDir := t.TempDir()
	vaultDir := tmpDir + "/vault"
	_ = generateTestCA(t, vaultDir)

	config := fmt.Sprintf(`
[policy]
default = "deny"

[vault]
provider = "age"
dir = %q

[[allow]]
destination = "127.0.0.1"
ports = [443]
name = "allow test"
`, vaultDir)

	proc := startSluice(t, SluiceOpts{ConfigTOML: config})

	// Sluice should be healthy with QUIC proxy initialized.
	resp, err := http.Get(proc.HealthURL)
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 from healthz, got %d", resp.StatusCode)
	}

	// Verify the audit log path exists (sluice started cleanly).
	if !fileExists(proc.AuditPath) {
		t.Error("audit log file was not created")
	}
}

// TestQUIC_DenyRuleBlocksTCPFallback verifies that when a QUIC destination
// has a deny rule, TCP connections (HTTPS fallback) to the same destination
// are also blocked. This tests the policy engine's handling of the destination
// regardless of transport.
func TestQUIC_DenyRuleBlocksTCPFallback(t *testing.T) {
	setup := startCredTestSluice(t, "")
	h2Addr := startH2EchoServer(t, setup.CA)
	_, port := splitHostPort(t, h2Addr)

	// Deny the server destination.
	runSluicePolicyAdd(t, setup.Proc, "deny", "--ports", port, "127.0.0.1")
	sendSIGHUP(t, setup.Proc)

	// Try to connect via HTTPS (TCP). Should be denied by the same rule
	// that would deny QUIC to the same destination.
	_, _, err := tryHTTPGetViaSOCKS5(t, setup.Proc.ProxyAddr, "https://127.0.0.1:"+port+"/test")
	if err == nil {
		t.Fatal("expected connection to be denied, but it succeeded")
	}

	time.Sleep(500 * time.Millisecond)
	if !auditLogContains(t, setup.Proc.AuditPath, `"verdict":"deny"`) {
		t.Error("audit log should contain deny verdict")
	}
}

// certPoolFromCA creates a cert pool containing only the test CA certificate.
func certPoolFromCA(t *testing.T, ca *testCA) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM) {
		t.Fatal("failed to add test CA to cert pool")
	}
	return pool
}

// fileExists checks if a file exists at the given path.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
