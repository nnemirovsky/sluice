package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/vault"
	"golang.org/x/net/proxy"
)

// countingChannel is a mock channel that counts approval requests and
// auto-resolves each one with AllowOnce. Tests read approvalCount to
// verify that the per-request policy check fired the expected number
// of times.
type countingChannel struct {
	broker        *channel.Broker
	approvalCount atomic.Int64
	mu            sync.Mutex
	requests      []channel.ApprovalRequest
}

func (c *countingChannel) RequestApproval(_ context.Context, req channel.ApprovalRequest) error {
	c.approvalCount.Add(1)
	c.mu.Lock()
	c.requests = append(c.requests, req)
	c.mu.Unlock()
	go c.broker.Resolve(req.ID, channel.ResponseAllowOnce)
	return nil
}

func (c *countingChannel) CancelApproval(_ string) error            { return nil }
func (c *countingChannel) Commands() <-chan channel.Command         { return nil }
func (c *countingChannel) Notify(_ context.Context, _ string) error { return nil }
func (c *countingChannel) Start() error                             { return nil }
func (c *countingChannel) Stop()                                    {}
func (c *countingChannel) Type() channel.ChannelType                { return channel.ChannelTelegram }

// newCountingBroker creates a Broker with a countingChannel. Returns both
// so the test can inspect approvalCount after requests complete.
func newCountingBroker() (*channel.Broker, *countingChannel) {
	ch := &countingChannel{}
	broker := channel.NewBroker([]channel.Channel{ch})
	ch.broker = broker
	return broker, ch
}

// sequencingChannel responds to approval requests with a preconfigured
// sequence of responses. The first approval gets responses[0], the second
// gets responses[1], etc. After the sequence is exhausted, all further
// approvals are denied.
type sequencingChannel struct {
	broker    *channel.Broker
	responses []channel.Response
	callCount atomic.Int64
	mu        sync.Mutex
	requests  []channel.ApprovalRequest
}

func (c *sequencingChannel) RequestApproval(_ context.Context, req channel.ApprovalRequest) error {
	idx := int(c.callCount.Add(1)) - 1
	c.mu.Lock()
	c.requests = append(c.requests, req)
	c.mu.Unlock()

	resp := channel.ResponseDeny
	if idx < len(c.responses) {
		resp = c.responses[idx]
	}
	go c.broker.Resolve(req.ID, resp)
	return nil
}

func (c *sequencingChannel) CancelApproval(_ string) error            { return nil }
func (c *sequencingChannel) Commands() <-chan channel.Command         { return nil }
func (c *sequencingChannel) Notify(_ context.Context, _ string) error { return nil }
func (c *sequencingChannel) Start() error                             { return nil }
func (c *sequencingChannel) Stop()                                    {}
func (c *sequencingChannel) Type() channel.ChannelType                { return channel.ChannelTelegram }

func newSequencingBroker(responses []channel.Response) (*channel.Broker, *sequencingChannel) {
	ch := &sequencingChannel{responses: responses}
	broker := channel.NewBroker([]channel.Channel{ch})
	ch.broker = broker
	return broker, ch
}

// startH2Backend creates and starts a TLS HTTP/2 test server. The handler
// records each request's Authorization header in receivedAuths and
// increments requestCount. The caller must defer h2Server.Close().
func startH2Backend(t *testing.T) (
	server *httptest.Server,
	host string,
	port int,
	receivedAuths *[]string,
	requestCount *int,
	mu *sync.Mutex,
) {
	t.Helper()
	mu = &sync.Mutex{}
	receivedAuths = &[]string{}
	requestCount = new(int)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		mu.Lock()
		*receivedAuths = append(*receivedAuths, auth)
		*requestCount++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "proto=%s auth=%s", r.Proto, auth)
	})

	ln, listenErr := net.Listen("tcp4", "127.0.0.1:0")
	if listenErr != nil {
		t.Fatal(listenErr)
	}
	server = &httptest.Server{
		Listener:    ln,
		EnableHTTP2: true,
		Config:      &http.Server{Handler: handler},
	}
	server.StartTLS()

	h, portStr, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return server, h, p, receivedAuths, requestCount, mu
}

// buildH2Client creates an HTTP client that routes through the given
// SOCKS5 proxy address with TLS verification disabled. HTTP/2 is forced
// via ForceAttemptHTTP2. TLS verification is skipped because
// go-mitmproxy generates MITM certs using the TLS ClientHello SNI
// field, which is empty for IP-literal destinations per the TLS spec.
func buildH2Client(t *testing.T, socksAddr string) *http.Client {
	t.Helper()
	socksDialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	contextDialer, ok := socksDialer.(proxy.ContextDialer)
	if !ok {
		t.Fatal("SOCKS5 dialer does not implement ContextDialer")
	}

	transport := &http.Transport{
		DialContext:       contextDialer.DialContext,
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	return &http.Client{Transport: transport}
}

// TestHTTP2PerRequestPolicyAndInjection verifies that go-mitmproxy fires
// per-request addon hooks for each HTTP/2 stream multiplexed on a single
// TCP connection. This is the key integration test proving that
// go-mitmproxy per-stream interception works for the gRPC use case:
//
//  1. Two HTTP/2 requests on the same connection each trigger a separate
//     per-request policy check (broker called twice with AllowOnce).
//  2. Credential injection (header injection via binding) works on both
//     HTTP/2 streams independently.
//
// The test goes through the full SOCKS5 -> go-mitmproxy MITM -> TLS
// HTTP/2 backend pipeline.
func TestHTTP2PerRequestPolicyAndInjection(t *testing.T) {
	// -- 1. HTTP/2 TLS backend --
	h2Backend, backendHost, backendPort, receivedAuths, _, mu := startH2Backend(t)
	defer h2Backend.Close()

	// -- 2. Credential setup --
	dir := t.TempDir()
	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	credName := "h2_api_key"
	realSecret := "real-h2-secret"
	if _, err := vs.Add(credName, realSecret); err != nil {
		t.Fatal(err)
	}

	bindings := []vault.Binding{{
		Destination: backendHost,
		Ports:       []int{backendPort},
		Credential:  credName,
		Header:      "Authorization",
		Template:    "Bearer {value}",
	}}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}

	// -- 3. Policy: ask-all so per-request checker fires --
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[ask]]
destination = "*"
`))
	if err != nil {
		t.Fatal(err)
	}

	broker, counting := newCountingBroker()

	// -- 4. Start sluice proxy --
	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
		Provider:   vs,
		Resolver:   resolver,
		VaultDir:   dir,
		Broker:     broker,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	// Wait for the proxy to be ready.
	time.Sleep(100 * time.Millisecond)

	// -- 5. Build HTTP/2-capable client through SOCKS5 --
	client := buildH2Client(t, srv.Addr())

	reqURL := fmt.Sprintf("https://%s:%d/test", backendHost, backendPort)

	// -- 6. Send two requests (HTTP/2 multiplexed on same connection) --
	resp1, err := client.Get(reqURL)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()

	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first request: status=%d body=%s, want 200", resp1.StatusCode, body1)
	}

	resp2, err := client.Get(reqURL + "?q=2")
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("second request: status=%d body=%s, want 200", resp2.StatusCode, body2)
	}

	// -- 7. Verify per-request policy fired for both requests --
	// The countingChannel records every approval request from the
	// broker. The flow is:
	//   - Connection-level ask -> broker call #1 (AllowOnce) -> seed=1
	//   - First HTTP/2 stream: seed credit consumed (no broker call)
	//   - Second HTTP/2 stream: seed exhausted -> broker call #2
	// Total: at least 2 broker calls.
	got := counting.approvalCount.Load()
	if got < 2 {
		t.Fatalf("broker approval count = %d, want >= 2 (connection-level + per-request)", got)
	}

	// -- 8. Verify credential injection on both streams --
	wantAuth := "Bearer " + realSecret
	mu.Lock()
	defer mu.Unlock()

	if len(*receivedAuths) < 2 {
		t.Fatalf("backend received %d requests, want >= 2", len(*receivedAuths))
	}
	for i, auth := range *receivedAuths {
		if auth != wantAuth {
			t.Errorf("request %d: backend received Authorization=%q, want %q", i+1, auth, wantAuth)
		}
	}

	t.Logf("HTTP/2 per-request test passed: %d broker calls, %d backend requests with correct injection",
		got, len(*receivedAuths))
}

// TestHTTP2PerRequestDenySecondStream verifies that when the broker
// allows the connection and the first HTTP/2 stream but denies the
// second, the first request succeeds and the second gets 403. This
// proves per-stream granularity: go-mitmproxy treats each HTTP/2
// stream as an independent request through the addon hooks.
//
// Approval sequence:
//
//	#1 AllowOnce (connection-level ask) -> connection allowed, seed=1
//	#2 Deny      (second HTTP/2 stream) -> 403
//
// The first HTTP/2 stream uses the seed credit without a broker call.
func TestHTTP2PerRequestDenySecondStream(t *testing.T) {
	// -- 1. HTTP/2 TLS backend --
	h2Backend, backendHost, backendPort, _, requestCount, mu := startH2Backend(t)
	defer h2Backend.Close()

	// -- 2. Policy: ask-all with sequencing broker --
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[ask]]
destination = "*"
`))
	if err != nil {
		t.Fatal(err)
	}

	// Responses: #1 AllowOnce (connection), #2 Deny (second stream).
	// The first stream uses the seed credit from AllowOnce.
	broker, seq := newSequencingBroker([]channel.Response{
		channel.ResponseAllowOnce,
		channel.ResponseDeny,
	})

	dir := t.TempDir()
	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     eng,
		Provider:   vs,
		VaultDir:   dir,
		Broker:     broker,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	time.Sleep(100 * time.Millisecond)

	client := buildH2Client(t, srv.Addr())

	reqURL := fmt.Sprintf("https://%s:%d/test", backendHost, backendPort)

	// First request: seed credit consumed, should succeed.
	resp1, err := client.Get(reqURL)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()

	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first request: status=%d body=%s, want 200", resp1.StatusCode, body1)
	}

	// Second request: seed exhausted, broker denies -> 403.
	resp2, err := client.Get(reqURL + "?q=2")
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()

	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("second request: status=%d body=%s, want 403", resp2.StatusCode, body2)
	}

	// Backend should have received exactly one request.
	mu.Lock()
	rc := *requestCount
	mu.Unlock()
	if rc != 1 {
		t.Fatalf("backend received %d requests, want 1 (second should be blocked)", rc)
	}

	// Broker should have been called exactly twice (connection + second stream).
	calls := seq.callCount.Load()
	if calls != 2 {
		t.Fatalf("broker call count = %d, want 2", calls)
	}

	t.Logf("HTTP/2 deny-second-stream test passed: first request OK, second 403, backend saw %d request(s)", rc)
}
