package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/vault"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// stubQUICProvider is a minimal vault.Provider for QUIC proxy tests.
type stubQUICProvider struct{}

func (s *stubQUICProvider) Get(_ string) (vault.SecureBytes, error) {
	return vault.SecureBytes{}, nil
}
func (s *stubQUICProvider) List() ([]string, error) { return nil, nil }
func (s *stubQUICProvider) Name() string            { return "stub" }

// mapQUICProvider returns credentials from a map, for tests that need
// phantom token replacement.
type mapQUICProvider struct {
	creds map[string]string
}

func (m *mapQUICProvider) Get(name string) (vault.SecureBytes, error) {
	v, ok := m.creds[name]
	if !ok {
		return vault.SecureBytes{}, fmt.Errorf("credential %q not found", name)
	}
	return vault.NewSecureBytes(v), nil
}

func (m *mapQUICProvider) List() ([]string, error) {
	var names []string
	for k := range m.creds {
		names = append(names, k)
	}
	return names, nil
}
func (m *mapQUICProvider) Name() string { return "map" }

// startH3Upstream starts a real HTTP/3 server that echoes back the request
// headers and body. Returns the address and a cleanup function. The server
// generates a per-host certificate signed by the given CA for any SNI.
func startH3Upstream(t *testing.T, caCert tls.Certificate) (string, func()) {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		apiKey := r.Header.Get("X-Api-Key")
		body, _ := io.ReadAll(r.Body)

		w.Header().Set("X-Echo-Auth", authHeader)
		w.Header().Set("X-Echo-Api-Key", apiKey)
		respBody := fmt.Sprintf("auth=%s body=%s secret=sk-real-secret-12345", authHeader, string(body))
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(respBody))
	})

	tlsCfg := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			host := hello.ServerName
			if host == "" {
				host = "localhost"
			}
			cert, err := GenerateHostCert(caCert, host)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{"h3"},
			}, nil
		},
		NextProtos: []string{"h3"},
	}

	srv := &http3.Server{
		TLSConfig: tlsCfg,
		Handler:   handler,
	}

	ln, err := quic.ListenAddrEarly("127.0.0.1:0", http3.ConfigureTLSConfig(tlsCfg), &quic.Config{})
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}

	go func() {
		_ = srv.ServeListener(ln)
	}()

	return ln.Addr().String(), func() {
		_ = srv.Close()
		_ = ln.Close()
	}
}

// waitForQUICAddr polls until the QUICProxy has a non-nil address.
func waitForQUICAddr(t *testing.T, qp *QUICProxy) string {
	t.Helper()
	for i := 0; i < 50; i++ {
		if a := qp.Addr(); a != nil {
			return a.String()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("QUIC proxy did not start listening")
	return ""
}

func TestQUICProxy_HandshakeSucceeds(t *testing.T) {
	// Generate a CA for the proxy.
	caCert, caX509, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	var resolver atomic.Pointer[vault.BindingResolver]
	qp, err := NewQUICProxy(caCert, &stubQUICProvider{}, &resolver, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewQUICProxy: %v", err)
	}

	// Start the QUIC proxy in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		errCh <- qp.ListenAndServe("127.0.0.1:0")
	}()

	// Wait for the listener to be ready.
	var addr string
	for i := 0; i < 50; i++ {
		if a := qp.Addr(); a != nil {
			addr = a.String()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("QUIC proxy did not start listening")
	}

	// Create a QUIC client that trusts the proxy's CA.
	pool := x509.NewCertPool()
	pool.AddCert(caX509)

	tlsCfg := &tls.Config{
		RootCAs:    pool,
		NextProtos: []string{"h3"},
		ServerName: "example.com",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, dialErr := quic.DialAddr(ctx, addr, tlsCfg, &quic.Config{})
	if dialErr != nil {
		t.Fatalf("QUIC dial: %v", dialErr)
	}
	defer func() { _ = conn.CloseWithError(0, "") }()

	// Verify the TLS handshake completed with the correct SNI.
	state := conn.ConnectionState().TLS
	if state.ServerName != "example.com" {
		t.Errorf("SNI = %q, want %q", state.ServerName, "example.com")
	}

	// Verify the server certificate was signed by our CA.
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certificates")
	}
	serverCert := state.PeerCertificates[0]
	if serverCert.Subject.CommonName != "example.com" {
		t.Errorf("cert CN = %q, want %q", serverCert.Subject.CommonName, "example.com")
	}

	_ = qp.Close()
}

func TestQUICProxy_SNIExtraction(t *testing.T) {
	// Verify that different SNI values produce matching server certificates.
	// The proxy uses GetConfigForClient to extract the SNI from each
	// ClientHello and generates a per-host certificate with that hostname.
	caCert, caX509, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	var resolver atomic.Pointer[vault.BindingResolver]
	qp, err := NewQUICProxy(caCert, &stubQUICProvider{}, &resolver, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewQUICProxy: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- qp.ListenAndServe("127.0.0.1:0")
	}()

	var addr string
	for i := 0; i < 50; i++ {
		if a := qp.Addr(); a != nil {
			addr = a.String()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("QUIC proxy did not start listening")
	}

	pool := x509.NewCertPool()
	pool.AddCert(caX509)

	tests := []struct {
		name string
		sni  string
	}{
		{"simple_hostname", "api.example.com"},
		{"subdomain", "deep.nested.example.org"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsCfg := &tls.Config{
				RootCAs:    pool,
				NextProtos: []string{"h3"},
				ServerName: tt.sni,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			conn, dialErr := quic.DialAddr(ctx, addr, tlsCfg, &quic.Config{})
			if dialErr != nil {
				t.Fatalf("QUIC dial with SNI %q: %v", tt.sni, dialErr)
			}

			state := conn.ConnectionState().TLS
			if len(state.PeerCertificates) == 0 {
				t.Fatal("no peer certificates")
			}
			certCN := state.PeerCertificates[0].Subject.CommonName
			if certCN != tt.sni {
				t.Errorf("cert CN = %q, want %q (SNI not extracted correctly)", certCN, tt.sni)
			}

			_ = conn.CloseWithError(0, "")
		})
	}

	_ = qp.Close()
}

// setupQUICProxyForH3 creates a QUICProxy wired to forward HTTP/3 requests to
// a local upstream. It configures the upstream dial and TLS to work in tests.
func setupQUICProxyForH3(
	t *testing.T,
	provider vault.Provider,
	bindings []vault.Binding,
	upstreamAddr string,
	upstreamCAX509 *x509.Certificate,
	blockRules []QUICBlockRuleConfig,
	redactRules []QUICRedactRuleConfig,
) (*QUICProxy, *x509.Certificate) {
	t.Helper()
	caCert, caX509, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	var resolverPtr atomic.Pointer[vault.BindingResolver]
	if len(bindings) > 0 {
		resolver, resolverErr := vault.NewBindingResolver(bindings)
		if resolverErr != nil {
			t.Fatalf("NewBindingResolver: %v", resolverErr)
		}
		resolverPtr.Store(resolver)
	}

	qp, err := NewQUICProxy(caCert, provider, &resolverPtr, nil, blockRules, redactRules)
	if err != nil {
		t.Fatalf("NewQUICProxy: %v", err)
	}

	// Configure outbound transport to trust the upstream CA and dial the
	// local test upstream instead of the host from the request URL.
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstreamCAX509)
	qp.upstreamTLSConfig = &tls.Config{
		RootCAs: upstreamPool,
	}
	qp.upstreamDial = func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		return quic.DialAddr(ctx, upstreamAddr, tlsCfg, cfg)
	}

	return qp, caX509
}

// doH3Request sends an HTTP/3 request through the QUICProxy MITM and returns
// the response status, headers, and body. It creates a known local UDP socket,
// registers it as an expected destination with the QUIC proxy, and uses
// quic.Dial (not DialAddr) so the proxy can verify the source.
func doH3Request(t *testing.T, qp *QUICProxy, proxyAddr string, caX509 *x509.Certificate, sni, method, path string, body []byte, extraHeaders map[string]string) (int, http.Header, string) { //nolint:unparam // sni is parameterized for test readability
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(caX509)

	// Create a local UDP socket so we know the source address for
	// expected host registration.
	localConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen local UDP: %v", err)
	}
	defer func() { _ = localConn.Close() }()
	qp.RegisterExpectedHost(localConn.LocalAddr().String(), sni, 443)
	defer qp.UnregisterExpectedHost(localConn.LocalAddr().String())

	proxyUDPAddr, err := net.ResolveUDPAddr("udp", proxyAddr)
	if err != nil {
		t.Fatalf("resolve proxy addr: %v", err)
	}

	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: sni,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.Dial(ctx, localConn, proxyUDPAddr, tlsCfg, cfg)
		},
	}
	defer func() { _ = transport.Close() }()

	reqURL := fmt.Sprintf("https://%s%s", sni, path)
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, reqErr := http.NewRequest(method, reqURL, bodyReader)
	if reqErr != nil {
		t.Fatalf("create request: %v", reqErr)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, roundTripErr := transport.RoundTrip(req)
	if roundTripErr != nil {
		t.Fatalf("HTTP/3 request: %v", roundTripErr)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(respBody)
}

func TestQUICProxy_HTTP3PhantomTokenReplacement(t *testing.T) {
	// End-to-end test: HTTP/3 request through QUIC MITM, phantom token in
	// header replaced with real credential before reaching upstream.

	// Use the same CA for both upstream and proxy (in production they differ,
	// but for test simplicity this works).
	upstreamCACert, upstreamCAX509, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA for upstream: %v", err)
	}

	upstreamAddr, cleanup := startH3Upstream(t, upstreamCACert)
	defer cleanup()

	provider := &mapQUICProvider{
		creds: map[string]string{
			"test_api_key": "real-secret-key-value",
		},
	}

	bindings := []vault.Binding{
		{
			Destination: "api.example.com",
			Ports:       []int{443},
			Credential:  "test_api_key",
			Header:      "X-Api-Key",
			Protocols:   []string{"quic"},
		},
	}

	qp, proxyCAX509 := setupQUICProxyForH3(t, provider, bindings, upstreamAddr, upstreamCAX509, nil, nil)
	go func() {
		_ = qp.ListenAndServe("127.0.0.1:0")
	}()
	proxyAddr := waitForQUICAddr(t, qp)
	defer func() { _ = qp.Close() }()

	// Send request with phantom token in Authorization header.
	phantomToken := PhantomToken("test_api_key")
	status, headers, body := doH3Request(t, qp, proxyAddr, proxyCAX509,
		"api.example.com", "POST", "/v1/test",
		[]byte("payload with "+phantomToken+" inside"),
		map[string]string{
			"Authorization": "Bearer " + phantomToken,
		},
	)

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	// Verify binding-specific header injection: the upstream should see the
	// real credential in X-Api-Key (injected by the proxy via the binding).
	echoAPIKey := headers.Get("X-Echo-Api-Key")
	if echoAPIKey != "real-secret-key-value" {
		t.Errorf("X-Echo-Api-Key = %q, want %q", echoAPIKey, "real-secret-key-value")
	}

	// Verify phantom tokens replaced in headers.
	echoAuth := headers.Get("X-Echo-Auth")
	if echoAuth != "Bearer real-secret-key-value" {
		t.Errorf("X-Echo-Auth = %q, want %q", echoAuth, "Bearer real-secret-key-value")
	}

	// Verify phantom tokens replaced in body.
	if bytes.Contains([]byte(body), []byte(phantomToken)) {
		t.Errorf("response body still contains phantom token: %s", body)
	}
	if !bytes.Contains([]byte(body), []byte("real-secret-key-value")) {
		t.Errorf("response body missing real credential: %s", body)
	}
}

func TestQUICProxy_HTTP3ContentDenyBlocks(t *testing.T) {
	// Test: request body matching a deny pattern returns 403.
	upstreamCACert, upstreamCAX509, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	upstreamAddr, cleanup := startH3Upstream(t, upstreamCACert)
	defer cleanup()

	provider := &mapQUICProvider{creds: map[string]string{}}

	blockRules := []QUICBlockRuleConfig{
		{Pattern: `(?i)password\s*=\s*\S+`, Name: "password_leak"},
	}

	qp, proxyCAX509 := setupQUICProxyForH3(t, provider, nil, upstreamAddr, upstreamCAX509, blockRules, nil)
	go func() {
		_ = qp.ListenAndServe("127.0.0.1:0")
	}()
	proxyAddr := waitForQUICAddr(t, qp)
	defer func() { _ = qp.Close() }()

	// Request with banned content should be blocked.
	status, _, _ := doH3Request(t, qp, proxyAddr, proxyCAX509,
		"api.example.com", "POST", "/v1/data",
		[]byte(`{"password = hunter2"}`),
		nil,
	)
	if status != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for blocked content", status)
	}

	// Request without banned content should pass.
	status2, _, _ := doH3Request(t, qp, proxyAddr, proxyCAX509,
		"api.example.com", "POST", "/v1/data",
		[]byte(`{"message": "hello world"}`),
		nil,
	)
	if status2 != http.StatusOK {
		t.Errorf("status = %d, want 200 for clean content", status2)
	}
}

func TestQUICProxy_HTTP3ContentRedact(t *testing.T) {
	// Test: response body matching a redact pattern is sanitized.
	upstreamCACert, upstreamCAX509, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	upstreamAddr, cleanup := startH3Upstream(t, upstreamCACert)
	defer cleanup()

	provider := &mapQUICProvider{creds: map[string]string{}}

	redactRules := []QUICRedactRuleConfig{
		{Pattern: `sk-real-secret-\w+`, Replacement: "[REDACTED]", Name: "api_key_redact"},
	}

	qp, proxyCAX509 := setupQUICProxyForH3(t, provider, nil, upstreamAddr, upstreamCAX509, nil, redactRules)
	go func() {
		_ = qp.ListenAndServe("127.0.0.1:0")
	}()
	proxyAddr := waitForQUICAddr(t, qp)
	defer func() { _ = qp.Close() }()

	status, _, body := doH3Request(t, qp, proxyAddr, proxyCAX509,
		"api.example.com", "GET", "/v1/data",
		nil, nil,
	)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	// The upstream response contains "secret=sk-real-secret-12345" which
	// should be redacted to "secret=[REDACTED]".
	if bytes.Contains([]byte(body), []byte("sk-real-secret-12345")) {
		t.Errorf("response body still contains unredacted secret: %s", body)
	}
	if !bytes.Contains([]byte(body), []byte("[REDACTED]")) {
		t.Errorf("response body missing redaction marker: %s", body)
	}
}

// quicTransportFixture wires a single local UDP socket to a QUICProxy via
// http3.Transport. Multiple requests made through the returned transport
// reuse the same underlying QUIC connection, which is what we need to
// verify per-request policy consumes "Allow Once" on a keep-alive session.
type quicTransportFixture struct {
	localConn net.PacketConn
	transport *http3.Transport
	sni       string
}

func newQUICTransportFixture(t *testing.T, proxyAddr string, caX509 *x509.Certificate) *quicTransportFixture {
	t.Helper()

	const sni = "api.example.com"

	pool := x509.NewCertPool()
	pool.AddCert(caX509)
	localConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen local UDP: %v", err)
	}
	proxyUDPAddr, err := net.ResolveUDPAddr("udp", proxyAddr)
	if err != nil {
		_ = localConn.Close()
		t.Fatalf("resolve proxy addr: %v", err)
	}
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: sni,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.Dial(ctx, localConn, proxyUDPAddr, tlsCfg, cfg)
		},
	}
	return &quicTransportFixture{
		localConn: localConn,
		transport: transport,
		sni:       sni,
	}
}

func (f *quicTransportFixture) Close() {
	_ = f.transport.Close()
	_ = f.localConn.Close()
}

func (f *quicTransportFixture) sourceAddr() string {
	return f.localConn.LocalAddr().String()
}

func (f *quicTransportFixture) do(t *testing.T, path string) int {
	t.Helper()
	reqURL := fmt.Sprintf("https://%s%s", f.sni, path)
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	resp, err := f.transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("HTTP/3 request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)
	return resp.StatusCode
}

// TestQUICProxy_FastPathStillServesRequests verifies that nil checker
// (explicit allow fast path) serves HTTP/3 requests without per-request
// policy evaluation.
func TestQUICProxy_FastPathStillServesRequests(t *testing.T) {
	upstreamCACert, upstreamCAX509, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	upstreamAddr, cleanup := startH3Upstream(t, upstreamCACert)
	defer cleanup()

	provider := &mapQUICProvider{creds: map[string]string{}}
	qp, proxyCAX509 := setupQUICProxyForH3(t, provider, nil, upstreamAddr, upstreamCAX509, nil, nil)
	go func() { _ = qp.ListenAndServe("127.0.0.1:0") }()
	proxyAddr := waitForQUICAddr(t, qp)
	defer func() { _ = qp.Close() }()

	fx := newQUICTransportFixture(t, proxyAddr, proxyCAX509)
	defer fx.Close()
	qp.RegisterExpectedHost(fx.sourceAddr(), "api.example.com", 443)
	defer qp.UnregisterExpectedHost(fx.sourceAddr())

	status := fx.do(t, "/v1/a")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (QUIC fast path should serve requests)", status)
	}
}

// newQUICTestChecker builds a RequestPolicyChecker wired to a fakeChannel
// and broker for QUIC per-request policy tests. The TOML must define an
// ask rule for the destination under test.
func newQUICTestChecker(t *testing.T, toml string, resp channel.Response) (*RequestPolicyChecker, *fakeChannel) {
	t.Helper()
	eng, err := policy.LoadFromBytes([]byte(toml))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	eng.TimeoutSec = 2
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)
	fc := newFakeChannel(resp)
	broker := channel.NewBroker([]channel.Channel{fc})
	fc.broker = broker
	return NewRequestPolicyChecker(ptr, broker, WithSeedCredits(1)), fc
}

func TestQUICProxy_PerRequestAllowOnceConsumed(t *testing.T) {
	// An ask-rule session with AllowOnce: the first request uses the seeded
	// credit. The second request re-enters the broker. When the broker
	// denies, the second request returns 403.
	upstreamCACert, upstreamCAX509, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	upstreamAddr, cleanup := startH3Upstream(t, upstreamCACert)
	defer cleanup()

	provider := &mapQUICProvider{creds: map[string]string{}}
	qp, proxyCAX509 := setupQUICProxyForH3(t, provider, nil, upstreamAddr, upstreamCAX509, nil, nil)
	go func() { _ = qp.ListenAndServe("127.0.0.1:0") }()
	proxyAddr := waitForQUICAddr(t, qp)
	defer func() { _ = qp.Close() }()

	toml := `
[policy]
default = "deny"

[[ask]]
destination = "api.example.com"
ports = [443]
protocols = ["quic"]
`
	// Broker returns AllowOnce on the first ask. After the seed credit is
	// consumed, the second ask will also get AllowOnce, letting the second
	// request through as well. To test consumption of the seed, we set the
	// broker to Deny so the second request is blocked.
	checker, fc := newQUICTestChecker(t, toml, channel.ResponseDeny)

	fx := newQUICTransportFixture(t, proxyAddr, proxyCAX509)
	defer fx.Close()
	qp.RegisterExpectedHostWithChecker(fx.sourceAddr(), "api.example.com", 443, checker)
	defer qp.UnregisterExpectedHost(fx.sourceAddr())

	// First request: uses seeded allow credit, no broker call.
	status1 := fx.do(t, "/v1/first")
	if status1 != http.StatusOK {
		t.Fatalf("first request status = %d, want 200 (seeded credit)", status1)
	}
	if fc.requestCount() != 0 {
		t.Fatalf("broker called %d times after first request, want 0 (seed consumed)", fc.requestCount())
	}

	// Second request: seed exhausted, broker returns Deny.
	status2 := fx.do(t, "/v1/second")
	if status2 != http.StatusForbidden {
		t.Fatalf("second request status = %d, want 403 (broker denied)", status2)
	}
	if fc.requestCount() != 1 {
		t.Fatalf("broker called %d times after second request, want 1", fc.requestCount())
	}
}

func TestQUICProxy_PerRequestDenyReturns403(t *testing.T) {
	// When the checker immediately denies (explicit deny rule), the HTTP/3
	// request returns 403.
	upstreamCACert, upstreamCAX509, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	upstreamAddr, cleanup := startH3Upstream(t, upstreamCACert)
	defer cleanup()

	provider := &mapQUICProvider{creds: map[string]string{}}
	qp, proxyCAX509 := setupQUICProxyForH3(t, provider, nil, upstreamAddr, upstreamCAX509, nil, nil)
	go func() { _ = qp.ListenAndServe("127.0.0.1:0") }()
	proxyAddr := waitForQUICAddr(t, qp)
	defer func() { _ = qp.Close() }()

	// Use an explicit deny rule. The checker evaluates deny before checking
	// seeds, so the request is blocked even with a seed credit.
	toml := `
[policy]
default = "deny"

[[deny]]
destination = "api.example.com"
ports = [443]
`
	eng, loadErr := policy.LoadFromBytes([]byte(toml))
	if loadErr != nil {
		t.Fatalf("LoadFromBytes: %v", loadErr)
	}
	eng.TimeoutSec = 2
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)
	checker := NewRequestPolicyChecker(ptr, nil, WithSeedCredits(1))

	fx := newQUICTransportFixture(t, proxyAddr, proxyCAX509)
	defer fx.Close()
	qp.RegisterExpectedHostWithChecker(fx.sourceAddr(), "api.example.com", 443, checker)
	defer qp.UnregisterExpectedHost(fx.sourceAddr())

	status := fx.do(t, "/v1/data")
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (explicit deny beats seed credit)", status)
	}
}

func TestQUICProxy_ExplicitAllowSkipsChecker(t *testing.T) {
	// When RegisterExpectedHost is used (nil checker), requests flow through
	// without per-request policy checks, regardless of how many requests
	// are made on the same QUIC session.
	upstreamCACert, upstreamCAX509, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	upstreamAddr, cleanup := startH3Upstream(t, upstreamCACert)
	defer cleanup()

	provider := &mapQUICProvider{creds: map[string]string{}}
	qp, proxyCAX509 := setupQUICProxyForH3(t, provider, nil, upstreamAddr, upstreamCAX509, nil, nil)
	go func() { _ = qp.ListenAndServe("127.0.0.1:0") }()
	proxyAddr := waitForQUICAddr(t, qp)
	defer func() { _ = qp.Close() }()

	fx := newQUICTransportFixture(t, proxyAddr, proxyCAX509)
	defer fx.Close()
	qp.RegisterExpectedHost(fx.sourceAddr(), "api.example.com", 443)
	defer qp.UnregisterExpectedHost(fx.sourceAddr())

	// Multiple requests on the same session all succeed.
	for i := 0; i < 3; i++ {
		status := fx.do(t, fmt.Sprintf("/v1/req%d", i))
		if status != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200 (explicit allow, no checker)", i, status)
		}
	}
}
