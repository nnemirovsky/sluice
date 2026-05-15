package proxy

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mitmproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/nemirovsky/sluice/internal/audit"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
	uuid "github.com/satori/go.uuid"
)

// newPoolRespFlow builds a response flow for the pooled destination with an
// arbitrary status code and body. The request URL is the OAuth token URL so
// the token-endpoint body classification path is exercised.
func newPoolRespFlow(client *mitmproxy.ClientConn, status int, respBody []byte) *mitmproxy.Flow {
	u, _ := url.Parse(testOAuthTokenURL)
	reqHdr := make(http.Header)
	respHdr := make(http.Header)
	respHdr.Set("Content-Type", "application/json")
	return &mitmproxy.Flow{
		Id:          uuid.NewV4(),
		ConnContext: &mitmproxy.ConnContext{ClientConn: client},
		Request: &mitmproxy.Request{
			Method: "POST",
			URL:    u,
			Header: reqHdr,
			Body:   []byte("grant_type=refresh_token&refresh_token=x"),
		},
		Response: &mitmproxy.Response{
			StatusCode: status,
			Header:     respHdr,
			Body:       respBody,
		},
	}
}

// TestClassifyFailover is the classification truth table from the plan.
func TestClassifyFailover(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		body        string
		tokenEP     bool
		wantClass   failoverClass
		wantTagPart string
	}{
		{"429 rate limited", 429, "", false, failoverRateLimited, "429"},
		{"403 insufficient_quota", 403, `{"error":"insufficient_quota"}`, false, failoverRateLimited, "403"},
		{"403 quota_exceeded", 403, `{"error":{"code":"quota_exceeded"}}`, false, failoverRateLimited, "403"},
		{"403 unrelated -> noop", 403, `{"error":"forbidden: bad scope"}`, false, failoverNone, ""},
		{"401 auth failure", 401, "", false, failoverAuthFailure, "401"},
		{"token-endpoint invalid_grant", 400, `{"error":"invalid_grant"}`, true, failoverAuthFailure, "invalid_grant"},
		{"token-endpoint invalid_token", 400, `{"error":"invalid_token"}`, true, failoverAuthFailure, "invalid_token"},
		{"invalid_grant but NOT token endpoint -> noop", 400, `{"error":"invalid_grant"}`, false, failoverNone, ""},
		{"200 success -> noop", 200, `{"access_token":"x"}`, true, failoverNone, ""},
		{"500 server error -> noop", 500, `oops`, false, failoverNone, ""},
		{"502 -> noop", 502, ``, false, failoverNone, ""},
		{"404 -> noop", 404, ``, false, failoverNone, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			class, bodyTag := classifyFailover(c.status, []byte(c.body), c.tokenEP)
			if class != c.wantClass {
				t.Fatalf("class = %v, want %v", class, c.wantClass)
			}
			if c.wantClass == failoverNone {
				return
			}
			tag := failoverReasonTag(class, c.status, bodyTag)
			if tag != c.wantTagPart {
				t.Fatalf("reason tag = %q, want %q", tag, c.wantTagPart)
			}
		})
	}
}

// TestFailoverSynchronousHealthSwap asserts that after a 429 response on a
// pooled destination, the very NEXT ResolveActive call returns the next
// member — without any reliance on the 2s store-reconcile watcher (Risk I1).
func TestFailoverSynchronousHealthSwap(t *testing.T) {
	addon, _, prPtr := setupPoolAddon(t, "codex_pool", "memA", "memB")
	client := setupAddonConn(addon, "auth.example.com:443")

	pr := prPtr.Load()
	if got, _ := pr.ResolveActive("codex_pool"); got != "memA" {
		t.Fatalf("pre-failover active = %q, want memA", got)
	}

	var got FailoverEvent
	gotCalled := make(chan struct{}, 1)
	addon.SetOnFailover(func(ev FailoverEvent) {
		got = ev
		gotCalled <- struct{}{}
	})

	addon.Response(newPoolRespFlow(client, 429, []byte(`{"error":"rate_limited"}`)))

	// Synchronous: by the time Response returns the swap is already done.
	if active, _ := pr.ResolveActive("codex_pool"); active != "memB" {
		t.Fatalf("post-failover active = %q, want memB (synchronous swap, no watcher)", active)
	}

	select {
	case <-gotCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("onFailover callback not invoked")
	}
	if got.Pool != "codex_pool" || got.From != "memA" || got.To != "memB" || got.Reason != "429" {
		t.Fatalf("FailoverEvent = %+v, want pool=codex_pool from=memA to=memB reason=429", got)
	}
	if got.Class != failoverRateLimited {
		t.Fatalf("class = %v, want rate-limited", got.Class)
	}
}

// TestFailoverCooldownTTLAndLazyRecovery asserts the documented cooldown
// durations and that an expired cooldown makes the member eligible again
// with no scheduler (lazy recovery in ResolveActive).
func TestFailoverCooldownTTLAndLazyRecovery(t *testing.T) {
	// Rate-limit TTL = 60s, auth-fail TTL = 300s (named consts).
	if vault.RateLimitCooldown != 60*time.Second {
		t.Fatalf("RateLimitCooldown = %v, want 60s", vault.RateLimitCooldown)
	}
	if vault.AuthFailCooldown != 300*time.Second {
		t.Fatalf("AuthFailCooldown = %v, want 300s", vault.AuthFailCooldown)
	}

	addon, _, prPtr := setupPoolAddon(t, "codex_pool", "memA", "memB")
	client := setupAddonConn(addon, "auth.example.com:443")
	pr := prPtr.Load()

	// Auth failure (401) -> memA cools down for AuthFailCooldown.
	before := time.Now()
	addon.Response(newPoolRespFlow(client, 401, nil))
	until, cooling := pr.CooldownUntil("memA")
	if !cooling {
		t.Fatal("memA should be cooling down after 401")
	}
	gotTTL := until.Sub(before)
	// Allow generous slack for scheduling jitter.
	if gotTTL < vault.AuthFailCooldown-5*time.Second || gotTTL > vault.AuthFailCooldown+5*time.Second {
		t.Fatalf("auth-fail cooldown TTL = %v, want ~%v", gotTTL, vault.AuthFailCooldown)
	}

	// Lazy recovery: force the cooldown to the past; ResolveActive must
	// treat memA as eligible again with no background scheduler involved.
	pr.MarkCooldown("memA", time.Now().Add(-time.Second), "expired")
	if active, _ := pr.ResolveActive("codex_pool"); active != "memA" {
		t.Fatalf("after expiry active = %q, want memA (lazy recovery)", active)
	}
}

// TestFailoverNoopForNonPooledAndSuccess asserts the failover path is a
// no-op for a successful response and never invokes the callback.
func TestFailoverNoopForSuccessfulResponse(t *testing.T) {
	addon, _, prPtr := setupPoolAddon(t, "codex_pool", "memA", "memB")
	client := setupAddonConn(addon, "auth.example.com:443")

	called := false
	addon.SetOnFailover(func(FailoverEvent) { called = true })

	addon.Response(newPoolRespFlow(client, 200, []byte(`{"access_token":"ok"}`)))
	if called {
		t.Fatal("onFailover invoked for a 200 response")
	}
	if active, _ := prPtr.Load().ResolveActive("codex_pool"); active != "memA" {
		t.Fatalf("active = %q, want memA unchanged on success", active)
	}

	// 5xx is also a documented no-op.
	addon.Response(newPoolRespFlow(client, 503, []byte(`upstream down`)))
	if called {
		t.Fatal("onFailover invoked for a 5xx response (must be no-op)")
	}
}

// TestFailoverNoticeNonBlocking asserts the response path is not blocked by
// a slow onFailover callback. The callback in production dispatches its own
// goroutine; this test models a callback whose own work is slow and verifies
// Response returns promptly regardless (the addon does not goroutine for the
// callback, so the callback contract is "be non-blocking yourself" — here we
// assert Response itself never waits on callback-internal work by having the
// callback spawn the slow part and return immediately, mirroring main.go).
func TestFailoverNoticeNonBlocking(t *testing.T) {
	addon, _, _ := setupPoolAddon(t, "codex_pool", "memA", "memB")
	client := setupAddonConn(addon, "auth.example.com:443")

	done := make(chan struct{})
	addon.SetOnFailover(func(FailoverEvent) {
		// Production wiring (main.go) detaches the slow store/Telegram
		// work into a goroutine and returns immediately. Model that.
		go func() {
			time.Sleep(500 * time.Millisecond)
			close(done)
		}()
	})

	start := time.Now()
	addon.Response(newPoolRespFlow(client, 429, nil))
	elapsed := time.Since(start)
	if elapsed > 200*time.Millisecond {
		t.Fatalf("Response blocked %v on failover callback; must be non-blocking", elapsed)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("detached failover work never completed")
	}
}

// TestFailoverNonPooledDestinationIgnored asserts a response whose
// destination is NOT bound to a pool never triggers failover.
func TestFailoverNonPooledDestinationIgnored(t *testing.T) {
	addon, _, _ := setupPoolAddon(t, "codex_pool", "memA", "memB")
	// Connect to a destination with no pooled binding.
	client := setupAddonConn(addon, "unrelated.example.com:443")

	called := false
	addon.SetOnFailover(func(FailoverEvent) { called = true })

	// Request URL is a plain API endpoint on an unrelated host: it neither
	// has a pooled CONNECT binding NOR matches any pooled member's OAuth
	// token URL, so poolForResponse must return ok=false and no failover
	// fires. (newPoolRespFlow points the request at the token URL, which
	// WOULD legitimately match a pooled member via the CRITICAL-2 token-URL
	// path, so it must not be used here.)
	u, _ := url.Parse("https://unrelated.example.com/v1/data")
	f := &mitmproxy.Flow{
		Id:          uuid.NewV4(),
		ConnContext: &mitmproxy.ConnContext{ClientConn: client},
		Request:     &mitmproxy.Request{Method: "GET", URL: u, Header: make(http.Header)},
		Response:    &mitmproxy.Response{StatusCode: 429, Header: make(http.Header)},
	}
	addon.Response(f)
	if called {
		t.Fatal("onFailover invoked for a non-pooled destination")
	}
}

// TestFailoverAuditEvent asserts a cred_failover audit event is emitted with
// the documented Reason shape "<pool>:<from>-><to>:<tag>".
func TestFailoverAuditEvent(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	logger, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	addon, _, _ := setupPoolAddon(t, "codex_pool", "memA", "memB")
	addon.auditLog = logger
	client := setupAddonConn(addon, "auth.example.com:443")

	addon.Response(newPoolRespFlow(client, 429, []byte(`{"error":"rate_limited"}`)))

	if err := logger.Close(); err != nil {
		t.Fatalf("logger close: %v", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}

	var found bool
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var evt audit.Event
		if uerr := json.Unmarshal([]byte(line), &evt); uerr != nil {
			t.Fatalf("unmarshal audit line %q: %v", line, uerr)
		}
		if evt.Action != "cred_failover" {
			continue
		}
		found = true
		if evt.Reason != "codex_pool:memA->memB:429" {
			t.Fatalf("audit Reason = %q, want %q", evt.Reason, "codex_pool:memA->memB:429")
		}
		if evt.Verdict != "failover" {
			t.Fatalf("audit Verdict = %q, want failover", evt.Verdict)
		}
		if evt.Credential != "memA" {
			t.Fatalf("audit Credential = %q, want memA", evt.Credential)
		}
	}
	if !found {
		t.Fatalf("no cred_failover audit event found in:\n%s", data)
	}
}

// TestPoolForResponseResolvesActiveMember sanity-checks the destination ->
// pool reverse mapping used by handlePoolFailover.
func TestPoolForResponseResolvesActiveMember(t *testing.T) {
	addon, _, prPtr := setupPoolAddon(t, "codex_pool", "memA", "memB")
	client := setupAddonConn(addon, "auth.example.com:443")
	f := newPoolRespFlow(client, 429, nil)

	pool, member, pr, ok := addon.poolForResponse(f)
	if !ok {
		t.Fatal("poolForResponse: expected a pooled destination match")
	}
	if pool != "codex_pool" || member != "memA" {
		t.Fatalf("got pool=%q member=%q, want codex_pool/memA", pool, member)
	}
	if pr != prPtr.Load() {
		t.Fatal("poolForResponse returned a different resolver than the live one")
	}
}

// setupPoolAddonSplitHost is like setupPoolAddon but the pool binding lives on
// the API host (api.example.com) while the OAuth token URL is on a DIFFERENT
// host (auth.example.com). This mirrors the real Codex deployment: the pool
// binding is on api.openai.com, the OAuth refresh hits auth.openai.com. The
// CONNECT-host reverse mapping in poolForResponse therefore CANNOT match a
// token-endpoint response — only the token-URL-index path can.
func setupPoolAddonSplitHost(t *testing.T, poolName, memberA, memberB string) (*SluiceAddon, *atomic.Pointer[vault.PoolResolver]) {
	t.Helper()

	provider := &addonWritableProvider{
		creds: map[string]string{
			memberA: poolMemberCred(t, "A-access-old", "A-refresh-old"),
			memberB: poolMemberCred(t, "B-access-old", "B-refresh-old"),
		},
	}

	// Pool binding is on the API host, NOT the token-URL host.
	bindings := []vault.Binding{{
		Destination: "api.example.com",
		Ports:       []int{443},
		Credential:  poolName,
	}}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatalf("NewBindingResolver: %v", err)
	}
	var resolverPtr atomic.Pointer[vault.BindingResolver]
	resolverPtr.Store(resolver)

	addon := NewSluiceAddon(WithResolver(&resolverPtr), WithProvider(provider))
	addon.persistDone = make(chan struct{}, 10)

	// testOAuthTokenURL is https://auth.example.com/oauth/token — a different
	// host from the api.example.com pool binding above.
	metas := []store.CredentialMeta{
		{Name: memberA, CredType: "oauth", TokenURL: testOAuthTokenURL},
		{Name: memberB, CredType: "oauth", TokenURL: testOAuthTokenURL},
	}
	addon.UpdateOAuthIndex(metas)

	pool := store.Pool{Name: poolName, Strategy: store.PoolStrategyFailover}
	pool.Members = []store.PoolMember{
		{Credential: memberA, Position: 0},
		{Credential: memberB, Position: 1},
	}
	var prPtr atomic.Pointer[vault.PoolResolver]
	prPtr.Store(vault.NewPoolResolver([]store.Pool{pool}, nil))
	addon.SetPoolResolver(&prPtr)

	return addon, &prPtr
}

// TestTokenEndpointHostFailoverOnPooledMember is the CRITICAL-2 regression.
// The OAuth refresh hits the token-URL host (auth.example.com), which has NO
// pool binding (the binding is on api.example.com). Without the token-URL
// index path in poolForResponse, the token-endpoint 401/invalid_grant
// classification is dead code: poolForResponse returns ok=false and the
// member is never cooled down. The fix recognizes the pooled member via
// idx.Match(f.Request.URL) -> PoolForMember.
func TestTokenEndpointHostFailoverOnPooledMember(t *testing.T) {
	addon, prPtr := setupPoolAddonSplitHost(t, "codex_pool", "memA", "memB")
	// CONNECT target is the TOKEN-URL host, which has no pool binding.
	client := setupAddonConn(addon, "auth.example.com:443")

	pr := prPtr.Load()
	if got, _ := pr.ResolveActive("codex_pool"); got != "memA" {
		t.Fatalf("pre-failover active = %q, want memA", got)
	}

	// Sanity: the CONNECT-host reverse mapping alone must NOT match here
	// (this is exactly the gap CRITICAL-2 describes). poolForResponse must
	// still succeed via the token-URL index path.
	f := newPoolRespFlow(client, 400, []byte(`{"error":"invalid_grant"}`))
	pool, member, _, ok := addon.poolForResponse(f)
	if !ok {
		t.Fatal("poolForResponse: token-endpoint response on a pooled member must be attributed (CRITICAL-2 fix); got ok=false")
	}
	if pool != "codex_pool" || member != "memA" {
		t.Fatalf("got pool=%q member=%q, want codex_pool/memA", pool, member)
	}

	var got FailoverEvent
	gotCalled := make(chan struct{}, 1)
	addon.SetOnFailover(func(ev FailoverEvent) {
		got = ev
		gotCalled <- struct{}{}
	})

	// A token-endpoint invalid_grant must cool memA and switch to memB.
	addon.Response(newPoolRespFlow(client, 400, []byte(`{"error":"invalid_grant"}`)))

	if active, _ := pr.ResolveActive("codex_pool"); active != "memB" {
		t.Fatalf("post-failover active = %q, want memB (token-endpoint auth failure must fail over)", active)
	}

	select {
	case <-gotCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("onFailover callback not invoked for token-endpoint failover")
	}
	if got.Pool != "codex_pool" || got.From != "memA" || got.To != "memB" || got.Reason != "invalid_grant" {
		t.Fatalf("FailoverEvent = %+v, want pool=codex_pool from=memA to=memB reason=invalid_grant", got)
	}
	if got.Class != failoverAuthFailure {
		t.Fatalf("class = %v, want auth-failure", got.Class)
	}
}
