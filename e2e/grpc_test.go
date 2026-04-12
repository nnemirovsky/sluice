//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// startH2EchoServer starts an HTTP/2 echo server on a free port using the
// test CA. It responds to all requests with the method, URL, host, and
// headers echoed back in plain text. This mimics a gRPC server at the
// transport level (gRPC uses HTTP/2 with application/grpc content type).
func startH2EchoServer(t *testing.T, ca *testCA) (addr string) {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	serverCert, certErr := generateServerTLSCert(t, ca, "127.0.0.1")
	if certErr != nil {
		t.Fatal(certErr)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Proto: %s\n", r.Proto)
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

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	srv := &http.Server{
		Handler:   handler,
		TLSConfig: tlsConfig,
	}
	// Configure HTTP/2 support.
	if err := http2.ConfigureServer(srv, nil); err != nil {
		t.Fatal(err)
	}

	tlsLn := tls.NewListener(ln, tlsConfig)
	go func() { _ = srv.Serve(tlsLn) }()
	t.Cleanup(func() { _ = srv.Close() })

	return ln.Addr().String()
}

// h2ClientViaSOCKS5 returns an HTTP client configured for HTTP/2 that routes
// through the given SOCKS5 proxy and skips TLS verification.
func h2ClientViaSOCKS5(t *testing.T, proxyAddr string) *http.Client {
	t.Helper()
	dialer := connectSOCKS5(t, proxyAddr)
	transport := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			rawConn, err := dialer.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			// Wrap in TLS for HTTP/2.
			tlsConn := tls.Client(rawConn, &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h2"},
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second}
}

// TestGRPC_AllowRulePermitsHTTP2Request verifies that HTTP/2 requests (the
// transport layer for gRPC) are allowed through the SOCKS5 proxy when an
// allow rule is configured. The test starts an HTTP/2 server and makes a
// request with gRPC-style headers through sluice.
func TestGRPC_AllowRulePermitsHTTP2Request(t *testing.T) {
	setup := startCredTestSluice(t, "")
	h2Addr := startH2EchoServer(t, setup.CA)
	_, port := splitHostPort(t, h2Addr)

	// Add allow rule for the H2 server.
	runSluicePolicyAdd(t, setup.Proc, "allow", "--ports", port, "127.0.0.1")
	sendSIGHUP(t, setup.Proc)

	client := h2ClientViaSOCKS5(t, setup.Proc.ProxyAddr)

	// Make a gRPC-style HTTP/2 POST request.
	req, err := http.NewRequest("POST", "https://127.0.0.1:"+port+"/grpc.EchoService/Echo", strings.NewReader("test-body"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTP/2 request via SOCKS5: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d\nbody: %s", resp.StatusCode, bodyStr)
	}

	// Verify HTTP/2 was used.
	if !strings.Contains(bodyStr, "Proto: HTTP/2") {
		t.Errorf("expected HTTP/2 protocol, got:\n%s", bodyStr)
	}

	// Verify gRPC headers were forwarded.
	if !strings.Contains(bodyStr, "Header: Content-Type: application/grpc") {
		t.Errorf("gRPC content-type header not forwarded:\n%s", bodyStr)
	}

	time.Sleep(500 * time.Millisecond)
	if !auditLogContains(t, setup.Proc.AuditPath, "127.0.0.1") {
		t.Error("audit log should contain entry for HTTP/2 connection")
	}
}

// TestGRPC_DenyRuleBlocksHTTP2Connection verifies that a deny rule blocks
// HTTP/2 connections through the SOCKS5 proxy.
func TestGRPC_DenyRuleBlocksHTTP2Connection(t *testing.T) {
	setup := startCredTestSluice(t, "")
	h2Addr := startH2EchoServer(t, setup.CA)
	_, port := splitHostPort(t, h2Addr)

	// Add deny rule for the H2 server.
	runSluicePolicyAdd(t, setup.Proc, "deny", "--ports", port, "127.0.0.1")
	sendSIGHUP(t, setup.Proc)

	client := h2ClientViaSOCKS5(t, setup.Proc.ProxyAddr)

	req, err := http.NewRequest("POST", "https://127.0.0.1:"+port+"/grpc.EchoService/Echo", strings.NewReader("test-body"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")

	_, doErr := client.Do(req)
	if doErr == nil {
		t.Fatal("expected HTTP/2 connection to be denied, but it succeeded")
	}

	time.Sleep(500 * time.Millisecond)
	if !auditLogContains(t, setup.Proc.AuditPath, `"verdict":"deny"`) {
		t.Error("audit log should contain deny verdict for blocked HTTP/2 connection")
	}
}

// TestGRPC_CredentialInjectionInMetadata verifies that credentials bound to
// the HTTP/2 server destination are injected into gRPC metadata headers
// by the MITM proxy.
func TestGRPC_CredentialInjectionInMetadata(t *testing.T) {
	setup := startCredTestSluice(t, "")
	h2Addr := startH2EchoServer(t, setup.CA)
	_, port := splitHostPort(t, h2Addr)

	// Add credential with binding for the H2 server.
	runCredAdd(t, setup.Proc, "grpc_token", "grpc-real-secret-456",
		"--destination", "127.0.0.1",
		"--ports", port,
		"--header", "Authorization",
		"--template", "Bearer {value}",
	)
	sendSIGHUP(t, setup.Proc)

	client := h2ClientViaSOCKS5(t, setup.Proc.ProxyAddr)

	req, err := http.NewRequest("POST", "https://127.0.0.1:"+port+"/grpc.EchoService/Echo", strings.NewReader("test"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTP/2 request via SOCKS5: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// The echo server should show the injected Authorization header.
	if !strings.Contains(bodyStr, "Header: Authorization: Bearer grpc-real-secret-456") {
		t.Errorf("credential not injected into gRPC metadata\nresponse:\n%s", bodyStr)
	}

	if strings.Contains(bodyStr, "SLUICE_PHANTOM") {
		t.Errorf("phantom token leaked to upstream in gRPC request\nresponse:\n%s", bodyStr)
	}
}

// TestGRPC_MultipleHTTP2StreamsOnSameConnection verifies that multiple
// HTTP/2 requests on the same connection each pass through the proxy
// correctly, testing per-stream handling.
func TestGRPC_MultipleHTTP2StreamsOnSameConnection(t *testing.T) {
	setup := startCredTestSluice(t, "")
	h2Addr := startH2EchoServer(t, setup.CA)
	_, port := splitHostPort(t, h2Addr)

	runSluicePolicyAdd(t, setup.Proc, "allow", "--ports", port, "127.0.0.1")
	sendSIGHUP(t, setup.Proc)

	client := h2ClientViaSOCKS5(t, setup.Proc.ProxyAddr)

	// Make multiple requests. HTTP/2 multiplexes them on the same connection.
	for i := 0; i < 3; i++ {
		path := fmt.Sprintf("/grpc.EchoService/Echo%d", i)
		req, err := http.NewRequest("POST", "https://127.0.0.1:"+port+path, strings.NewReader(fmt.Sprintf("msg-%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/grpc")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("request %d: expected 200, got %d", i, resp.StatusCode)
		}
		if !strings.Contains(string(body), path) {
			t.Errorf("request %d: expected URL %s in response, got:\n%s", i, path, string(body))
		}
	}
}
