//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"testing"
	"time"
)

// keepAliveClient builds an HTTP client that routes through the SOCKS5 proxy
// at proxyAddr, trusts any TLS certificate (since go-mitmproxy presents its
// own CA), and keeps connections alive between requests.
func keepAliveClient(t *testing.T, proxyAddr string) *http.Client {
	t.Helper()
	dialer := connectSOCKS5(t, proxyAddr)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     30 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}
}

// doGetWithTrace performs an HTTP GET with connection tracing. It returns the
// status code, body, whether the connection was reused, and any error.
func doGetWithTrace(client *http.Client, url string) (int, string, bool, error) {
	var reused atomic.Bool
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			reused.Store(info.Reused)
		},
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, url, nil)
	if err != nil {
		return 0, "", false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", reused.Load(), err
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return resp.StatusCode, "", reused.Load(), readErr
	}
	return resp.StatusCode, string(body), reused.Load(), nil
}

// TestPerRequestAllowOnceBlocksSecondRequest verifies that an allow_once
// verdict permits the first HTTP request on a keep-alive connection but
// the second request (on the same TCP connection) triggers a new approval
// and is denied.
//
// Webhook call sequence:
//
//	#1 allow_once (connection-level ask) -> CONNECT allowed, seed=1
//	#2 allow_once (first HTTP request uses seed credit, no webhook call)
//	#3 deny       (second HTTP request, seed exhausted) -> 403
//
// The connection-level allow_once consumes the first verdict. The first
// HTTP request uses the seed credit. The second HTTP request re-enters
// the approval flow and gets the "deny" verdict.
func TestPerRequestAllowOnceBlocksSecondRequest(t *testing.T) {
	// Start a TLS echo backend so go-mitmproxy intercepts the CONNECT tunnel.
	backend := startTLSEchoServer(t)
	host, port := mustSplitAddr(t, backend.URL)

	// Verdict sequence: allow_once for connection, deny for second request.
	// The first HTTP request uses the seed credit from allow_once.
	srv, vs := startVerdictServer(t, "allow_once", "deny")

	config := fmt.Sprintf(`
[policy]
default = "deny"

[[ask]]
destination = "%s"
ports = [%s]
name = "ask backend"
`, host, port)

	proc := sluiceWithWebhook(t, config, srv.URL)

	client := keepAliveClient(t, proc.ProxyAddr)

	// First request: seed credit consumed, should succeed.
	status1, _, reused1, err := doGetWithTrace(client, backend.URL+"/first")
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	if reused1 {
		t.Fatal("first request should not reuse a connection")
	}
	if status1 != http.StatusOK {
		t.Fatalf("first request: status=%d, want 200", status1)
	}

	// Second request: seed exhausted, webhook returns deny -> 403.
	status2, _, reused2, err := doGetWithTrace(client, backend.URL+"/second")
	if err != nil {
		t.Fatalf("second request failed unexpectedly: %v", err)
	}
	if !reused2 {
		t.Log("second request did not reuse the connection (may happen if MITM closed it)")
	}
	if status2 != http.StatusForbidden {
		t.Fatalf("second request: status=%d, want 403", status2)
	}

	// Webhook should have received at least two approval requests: once for
	// the connection-level ask, and once for the second HTTP request.
	calls := vs.ApprovalCalls()
	if calls < 2 {
		t.Fatalf("webhook approval calls=%d, want >= 2", calls)
	}
}

// TestPerRequestAlwaysAllowPermitsBoth verifies that an always_allow
// verdict persists an allow rule so subsequent requests on the same
// keep-alive connection succeed without additional webhook calls.
//
// Webhook call sequence:
//
//	#1 always_allow (connection-level ask) -> allow rule persisted
//
// Both requests succeed. The webhook is called only once.
func TestPerRequestAlwaysAllowPermitsBoth(t *testing.T) {
	backend := startTLSEchoServer(t)
	host, port := mustSplitAddr(t, backend.URL)

	srv, vs := startVerdictServer(t, "always_allow")

	config := fmt.Sprintf(`
[policy]
default = "deny"

[[ask]]
destination = "%s"
ports = [%s]
name = "ask backend"
`, host, port)

	proc := sluiceWithWebhook(t, config, srv.URL)

	client := keepAliveClient(t, proc.ProxyAddr)

	// First request: always_allow persists a rule.
	status1, _, _, err := doGetWithTrace(client, backend.URL+"/first")
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	if status1 != http.StatusOK {
		t.Fatalf("first request: status=%d, want 200", status1)
	}

	// Second request: persisted allow rule, no webhook call.
	status2, _, _, err := doGetWithTrace(client, backend.URL+"/second")
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	if status2 != http.StatusOK {
		t.Fatalf("second request: status=%d, want 200", status2)
	}

	// Webhook should receive exactly one approval request (connection-level
	// ask only). The always_allow verdict persists the rule so no further
	// approvals are needed.
	calls := vs.ApprovalCalls()
	if calls != 1 {
		t.Fatalf("webhook approval calls=%d, want 1 (always_allow persists rule)", calls)
	}
}

// TestPerRequestDenyBlocksFirst verifies that a deny verdict at the
// connection level blocks the SOCKS5 CONNECT, preventing any HTTP
// request from reaching the backend.
func TestPerRequestDenyBlocksFirst(t *testing.T) {
	backend := startTLSEchoServer(t)
	host, port := mustSplitAddr(t, backend.URL)

	srv, vs := startVerdictServer(t, "deny")

	config := fmt.Sprintf(`
[policy]
default = "deny"

[[ask]]
destination = "%s"
ports = [%s]
name = "ask backend"
`, host, port)

	proc := sluiceWithWebhook(t, config, srv.URL)

	// The deny verdict is consumed at connection level, so the SOCKS5
	// CONNECT is refused and the HTTP client gets a transport error.
	dialer := connectSOCKS5(t, proc.ProxyAddr)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	resp, err := client.Get(backend.URL + "/should-fail")
	if err == nil {
		// If the connection somehow succeeded, check for 403.
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden {
			t.Log("deny returned 403 via MITM (connection was established)")
		} else {
			t.Fatalf("expected connection error or 403, got status %d", resp.StatusCode)
		}
	}
	// Connection error is the expected outcome when SOCKS5 CONNECT is denied.

	// Webhook should have received at least one approval request for the
	// connection-level ask.
	calls := vs.ApprovalCalls()
	if calls < 1 {
		t.Fatalf("webhook approval calls=%d, want >= 1", calls)
	}
}

// TestPerRequestAllowOnceReAsks verifies that two consecutive allow_once
// verdicts each permit exactly one HTTP request, with the webhook called
// for each re-ask after the seed credit is consumed.
//
// Webhook call sequence:
//
//	#1 allow_once (connection-level ask) -> CONNECT allowed, seed=1
//	#2 allow_once (second HTTP request, seed exhausted) -> allowed
//
// Both requests succeed. The webhook is called at least twice.
func TestPerRequestAllowOnceReAsks(t *testing.T) {
	backend := startTLSEchoServer(t)
	host, port := mustSplitAddr(t, backend.URL)

	srv, vs := startVerdictServer(t, "allow_once", "allow_once")

	config := fmt.Sprintf(`
[policy]
default = "deny"

[[ask]]
destination = "%s"
ports = [%s]
name = "ask backend"
`, host, port)

	proc := sluiceWithWebhook(t, config, srv.URL)

	client := keepAliveClient(t, proc.ProxyAddr)

	// First request: seed credit consumed, should succeed.
	status1, _, _, err := doGetWithTrace(client, backend.URL+"/first")
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	if status1 != http.StatusOK {
		t.Fatalf("first request: status=%d, want 200", status1)
	}

	// Second request: seed exhausted, webhook returns allow_once -> 200.
	status2, _, _, err := doGetWithTrace(client, backend.URL+"/second")
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	if status2 != http.StatusOK {
		t.Fatalf("second request: status=%d, want 200", status2)
	}

	// Webhook should have received at least two approval requests.
	calls := vs.ApprovalCalls()
	if calls < 2 {
		t.Fatalf("webhook approval calls=%d, want >= 2", calls)
	}
}
