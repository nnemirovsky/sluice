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
		// Finding 1: a token-endpoint 403 carrying invalid_grant/invalid_token
		// is an auth failure (consistent with the 400/401 token-endpoint path).
		// The old code early-returned failoverNone in the 403 branch before the
		// token-endpoint body check ever ran.
		{"403 token-endpoint invalid_grant -> auth", 403, `{"error":"invalid_grant"}`, true, failoverAuthFailure, "invalid_grant"},
		{"403 token-endpoint invalid_token -> auth", 403, `{"error":"invalid_token"}`, true, failoverAuthFailure, "invalid_token"},
		// 403 + quota signal stays rate-limited (unchanged).
		{"403 insufficient_quota (tokenEP) stays rate-limited", 403, `{"error":"insufficient_quota"}`, true, failoverRateLimited, "403"},
		// 403 + invalid_grant but NOT a real token endpoint -> still noop
		// (the body is only trusted on a real token URL).
		{"403 invalid_grant but NOT token endpoint -> noop", 403, `{"error":"invalid_grant"}`, false, failoverNone, ""},
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
	addon, _, prPtr := setupPoolAddon(t, "memA", "memB")
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

	f := newPoolRespFlow(client, 429, []byte(`{"error":"rate_limited"}`))
	// A genuine pooled request always carries the injection-time flow tag
	// (addon.go buildPhantomPairs / Finding-4 token-host expansion call
	// flowInjected.Tag). Post-round-12 the API-host failover path requires
	// that pool-usage evidence and no longer blind-falls-back to
	// ResolveActive, so a realistic regression must tag like production.
	addon.flowInjected.Tag(f.Id, "memA")
	addon.Response(f)

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

	addon, _, prPtr := setupPoolAddon(t, "memA", "memB")
	client := setupAddonConn(addon, "auth.example.com:443")
	pr := prPtr.Load()

	// Auth failure (401) -> memA cools down for AuthFailCooldown.
	before := time.Now()
	f401 := newPoolRespFlow(client, 401, nil)
	addon.flowInjected.Tag(f401.Id, "memA") // production injection-time tag
	addon.Response(f401)
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
	addon, _, prPtr := setupPoolAddon(t, "memA", "memB")
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
	addon, _, _ := setupPoolAddon(t, "memA", "memB")
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

	fnb := newPoolRespFlow(client, 429, nil)
	addon.flowInjected.Tag(fnb.Id, "memA") // production injection-time tag
	start := time.Now()
	addon.Response(fnb)
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
	addon, _, _ := setupPoolAddon(t, "memA", "memB")
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

	addon, _, _ := setupPoolAddon(t, "memA", "memB")
	addon.auditLog = logger
	client := setupAddonConn(addon, "auth.example.com:443")

	fae := newPoolRespFlow(client, 429, []byte(`{"error":"rate_limited"}`))
	addon.flowInjected.Tag(fae.Id, "memA") // production injection-time tag
	addon.Response(fae)

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
	addon, _, prPtr := setupPoolAddon(t, "memA", "memB")
	client := setupAddonConn(addon, "auth.example.com:443")
	f := newPoolRespFlow(client, 429, nil)
	addon.flowInjected.Tag(f.Id, "memA") // production injection-time tag

	pool, member, _, pr, ok := addon.poolForResponse(f)
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
//
// poolName/memberA/memberB are parameterized on purpose: this is a general
// split-host pool fixture and a multi-pool test may legitimately pass other
// names. unparam only sees the current callers all using codex_pool/memA/memB.
//
//nolint:unparam
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

	// A genuine pooled refresh ALWAYS goes through pass-2, which records
	// the real-refresh -> member attribution tag (buildPooledMemberPairs).
	// Model that so the response carries recoverable pool-usage evidence —
	// post-Finding-3 a token-endpoint failure with NO pool-usage evidence
	// is intentionally NOT failed over (it could be a plain credential
	// merely sharing the token URL), so a realistic pooled-refresh
	// regression must tag like production does.
	addon.refreshAttr.Tag("A-refresh-old", "memA")

	// Sanity: the CONNECT-host reverse mapping alone must NOT match here
	// (this is exactly the gap CRITICAL-2 describes). poolForResponse must
	// still succeed via the token-URL index path.
	f := newPoolRespFlowBody(client, 400, "A-refresh-old", []byte(`{"error":"invalid_grant"}`))
	pool, member, _, _, ok := addon.poolForResponse(f)
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
	// Peek (failover path) does not consume the tag, so it is still live.
	addon.Response(newPoolRespFlowBody(client, 400, "A-refresh-old", []byte(`{"error":"invalid_grant"}`)))

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

// newPoolRespFlowBody builds a token-endpoint response flow whose REQUEST
// body carries the given (already pass-2-swapped) real refresh token, so
// poolForResponse can recover the true owning member via the refresh
// attribution map (the CRITICAL-2 join key).
func newPoolRespFlowBody(client *mitmproxy.ClientConn, status int, realRefresh string, respBody []byte) *mitmproxy.Flow {
	u, _ := url.Parse(testOAuthTokenURL)
	reqHdr := make(http.Header)
	reqHdr.Set("Content-Type", "application/x-www-form-urlencoded")
	respHdr := make(http.Header)
	respHdr.Set("Content-Type", "application/json")
	return &mitmproxy.Flow{
		Id:          uuid.NewV4(),
		ConnContext: &mitmproxy.ConnContext{ClientConn: client},
		Request: &mitmproxy.Request{
			Method: "POST",
			URL:    u,
			Header: reqHdr,
			Body:   []byte("grant_type=refresh_token&refresh_token=" + realRefresh),
		},
		Response: &mitmproxy.Response{
			StatusCode: status,
			Header:     respHdr,
			Body:       respBody,
		},
	}
}

// TestTokenEndpointFailoverAttributesInjectedMemberNotFirstIndex is the
// CRITICAL-2 regression. Both members share one token URL, so
// OAuthIndex.Match deterministically returns the FIRST index entry (memA)
// regardless of which member's refresh token is in the request body. The
// failing/active member here is memB (not the first index entry). The bug:
// the failover path attributed by idx.Match and cooled the WRONG member
// (memA), leaving the dead memB active so the pool thrashed the broken
// account forever. The fix recovers the true owner from the injected real
// refresh token (refreshAttribution.Peek), the SAME join key the 2xx
// persist path uses.
//
// This test MUST fail before the fix: idx.Match -> memA, so memA would be
// (re-)cooled and memB left untouched/active.
func TestTokenEndpointFailoverAttributesInjectedMemberNotFirstIndex(t *testing.T) {
	addon, prPtr := setupPoolAddonSplitHost(t, "codex_pool", "memA", "memB")
	client := setupAddonConn(addon, "auth.example.com:443")
	pr := prPtr.Load()

	// memA is first index AND would be first active. Cool memA via an API
	// 429 path so memB becomes the active member (the realistic precursor:
	// memA rate-limited on api host, traffic rolled to memB).
	memACooldown := time.Now().Add(90 * time.Second)
	pr.MarkCooldown("memA", memACooldown, "429")
	if got, _ := pr.ResolveActive("codex_pool"); got != "memB" {
		t.Fatalf("after cooling memA, active = %q, want memB", got)
	}

	// pass-2 injected memB's real refresh token into this refresh request;
	// mirror that by tagging the attribution map (what the real Request()
	// pass-2 swap does) and putting memB's real refresh in the body.
	addon.refreshAttr.Tag("B-refresh-old", "memB")

	// Sanity: idx.Match alone returns memA (the collision the bug rode on).
	if idx := addon.oauthIndex.Load(); idx != nil {
		u, _ := url.Parse(testOAuthTokenURL)
		if matched, _ := idx.Match(u); matched != "memA" {
			t.Fatalf("precondition: idx.Match must return first entry memA, got %q", matched)
		}
	}

	// poolForResponse must now attribute the failure to memB (the injected
	// member), NOT memA (the first index entry).
	f := newPoolRespFlowBody(client, 400, "B-refresh-old", []byte(`{"error":"invalid_grant"}`))
	pool, member, _, _, ok := addon.poolForResponse(f)
	if !ok {
		t.Fatal("poolForResponse: token-endpoint failure on a pooled member must be attributed")
	}
	if pool != "codex_pool" || member != "memB" {
		t.Fatalf("got pool=%q member=%q, want codex_pool/memB (CRITICAL-2: must attribute the INJECTED member, not idx.Match's first entry)", pool, member)
	}

	var got FailoverEvent
	gotCalled := make(chan struct{}, 1)
	addon.SetOnFailover(func(ev FailoverEvent) {
		got = ev
		gotCalled <- struct{}{}
	})

	addon.Response(newPoolRespFlowBody(client, 400, "B-refresh-old", []byte(`{"error":"invalid_grant"}`)))

	// memB must now be cooled with the long auth-failure TTL.
	bUntil, bCooling := pr.CooldownUntil("memB")
	if !bCooling {
		t.Fatal("memB must be in cooldown after its own invalid_grant (CRITICAL-2)")
	}
	if time.Until(bUntil) < vault.AuthFailCooldown-30*time.Second {
		t.Fatalf("memB cooldown TTL = %s, want ~%s (auth-failure)", time.Until(bUntil), vault.AuthFailCooldown)
	}

	// memA must be UNTOUCHED: still cooling on its ORIGINAL 90s 429 window,
	// NOT re-cooled with memB's 300s auth-failure TTL. The bug re-cooled
	// memA here; the fix must leave memA's cooldown exactly as it was.
	aUntil, aCooling := pr.CooldownUntil("memA")
	if !aCooling {
		t.Fatal("memA should still be cooling on its original 429 window")
	}
	if aUntil.Sub(memACooldown).Abs() > time.Second {
		t.Fatalf("memA cooldown was modified: got %s, want original %s (innocent member must not be re-cooled — CRITICAL-2)",
			aUntil.Format(time.RFC3339Nano), memACooldown.Format(time.RFC3339Nano))
	}

	select {
	case <-gotCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("onFailover callback not invoked")
	}
	if got.From != "memB" {
		t.Fatalf("FailoverEvent.From = %q, want memB (the correctly-attributed failing member)", got.From)
	}
	if got.Pool != "codex_pool" || got.Reason != "invalid_grant" || got.Class != failoverAuthFailure {
		t.Fatalf("FailoverEvent = %+v, want pool=codex_pool reason=invalid_grant class=auth-failure", got)
	}
}

// setupPoolAddonSplitHost3 is setupPoolAddonSplitHost with three members,
// all sharing one token URL on a host distinct from the pool binding host.
func setupPoolAddonSplitHost3(t *testing.T, poolName, a, b, c string) (*SluiceAddon, *atomic.Pointer[vault.PoolResolver]) {
	t.Helper()
	provider := &addonWritableProvider{
		creds: map[string]string{
			a: poolMemberCred(t, a+"-access", a+"-refresh"),
			b: poolMemberCred(t, b+"-access", b+"-refresh"),
			c: poolMemberCred(t, c+"-access", c+"-refresh"),
		},
	}
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

	metas := []store.CredentialMeta{
		{Name: a, CredType: "oauth", TokenURL: testOAuthTokenURL},
		{Name: b, CredType: "oauth", TokenURL: testOAuthTokenURL},
		{Name: c, CredType: "oauth", TokenURL: testOAuthTokenURL},
	}
	addon.UpdateOAuthIndex(metas)

	pool := store.Pool{Name: poolName, Strategy: store.PoolStrategyFailover}
	pool.Members = []store.PoolMember{
		{Credential: a, Position: 0},
		{Credential: b, Position: 1},
		{Credential: c, Position: 2},
	}
	var prPtr atomic.Pointer[vault.PoolResolver]
	prPtr.Store(vault.NewPoolResolver([]store.Pool{pool}, nil))
	addon.SetPoolResolver(&prPtr)
	return addon, &prPtr
}

// TestTokenEndpointFailover3MemberAttributesMiddleMember is the 3-member
// CRITICAL-2 variant: memA (first index) and memC are cooled, memB is
// active and refreshing. idx.Match still returns memA (first entry). The
// fix must cool memB (the injected member) and leave memA/memC's distinct
// cooldown windows untouched.
func TestTokenEndpointFailover3MemberAttributesMiddleMember(t *testing.T) {
	addon, prPtr := setupPoolAddonSplitHost3(t, "codex_pool", "memA", "memB", "memC")
	client := setupAddonConn(addon, "auth.example.com:443")
	pr := prPtr.Load()

	aUntil0 := time.Now().Add(45 * time.Second)
	cUntil0 := time.Now().Add(75 * time.Second)
	pr.MarkCooldown("memA", aUntil0, "429")
	pr.MarkCooldown("memC", cUntil0, "403")
	if got, _ := pr.ResolveActive("codex_pool"); got != "memB" {
		t.Fatalf("active = %q, want memB", got)
	}

	addon.refreshAttr.Tag("memB-refresh", "memB")

	f := newPoolRespFlowBody(client, 401, "memB-refresh", []byte(`{"error":"invalid_token"}`))
	pool, member, _, _, ok := addon.poolForResponse(f)
	if !ok || pool != "codex_pool" || member != "memB" {
		t.Fatalf("poolForResponse got ok=%v pool=%q member=%q, want codex_pool/memB", ok, pool, member)
	}

	addon.Response(newPoolRespFlowBody(client, 401, "memB-refresh", []byte(`{"error":"invalid_token"}`)))

	if _, cooling := pr.CooldownUntil("memB"); !cooling {
		t.Fatal("memB must be cooled after its own 401")
	}
	if aU, c := pr.CooldownUntil("memA"); !c || aU.Sub(aUntil0).Abs() > time.Second {
		t.Fatalf("memA cooldown changed: got %v (cooling=%v), want original %v", aU, c, aUntil0)
	}
	if cU, c := pr.CooldownUntil("memC"); !c || cU.Sub(cUntil0).Abs() > time.Second {
		t.Fatalf("memC cooldown changed: got %v (cooling=%v), want original %v", cU, c, cUntil0)
	}
}

// TestTokenEndpointFailoverFailClosedWithoutPoolUsageEvidence is the
// Finding 3 regression. A token-endpoint 401 / invalid_grant on a token URL
// that a pool shares must NOT cool a pool member when there is no evidence
// the failing request actually used the pool. The pre-Finding-3 code
// blindly fell back to the pool's ACTIVE member on a missing tag, so a
// PLAIN (non-pool) OAuth credential that merely shares the token URL would,
// on its own invalid_grant, cool an unrelated active pool member and park
// it. The fix returns ok=false unless a refreshAttr OR flowInjected tag
// proves the request went through the pooled injection path.
//
// This test MUST fail before the fix: the old active-member fallback cools
// memB even though nothing tied the failing request to the pool.
func TestTokenEndpointFailoverFailClosedWithoutPoolUsageEvidence(t *testing.T) {
	addon, prPtr := setupPoolAddonSplitHost(t, "codex_pool", "memA", "memB")
	client := setupAddonConn(addon, "auth.example.com:443")
	pr := prPtr.Load()

	// memA cooled -> memB active. NO refreshAttr tag, NO flowInjected tag:
	// the failing request carries zero evidence it used the pool (this is
	// exactly the shape of a plain non-pool OAuth credential that merely
	// shares the token URL hitting its own invalid_grant).
	memBPre, _ := pr.CooldownUntil("memB")
	pr.MarkCooldown("memA", time.Now().Add(90*time.Second), "429")
	if got, _ := pr.ResolveActive("codex_pool"); got != "memB" {
		t.Fatalf("active = %q, want memB", got)
	}

	f := newPoolRespFlowBody(client, 400, "unrelated-plain-refresh", []byte(`{"error":"invalid_grant"}`))
	pool, member, _, _, ok := addon.poolForResponse(f)
	if ok {
		t.Fatalf("poolForResponse must fail closed (ok=false) with no pool-usage "+
			"evidence; got ok=true pool=%q member=%q — Finding 3: a plain credential "+
			"sharing the token URL would cool an unrelated active pool member", pool, member)
	}

	// Drive the full Response path and assert NO pool member was cooled.
	addon.Response(f)
	if _, cooling := pr.CooldownUntil("memB"); cooling {
		t.Fatal("memB (active member) was cooled by an unattributed shared-token-URL " +
			"failure — Finding 3 over-application of the fallback")
	}
	if bU, _ := pr.CooldownUntil("memB"); !bU.Equal(memBPre) {
		t.Fatalf("memB cooldown changed (%v -> %v) despite no pool-usage evidence", memBPre, bU)
	}
	// memA's original 429 window must be untouched too.
	if aU, c := pr.CooldownUntil("memA"); !c {
		t.Fatal("memA should still be on its original 429 window")
	} else if time.Until(aU) < 60*time.Second {
		t.Fatalf("memA 429 window was shortened/cleared: %s left", time.Until(aU))
	}
}

// TestTokenEndpointFailoverFlowInjectedTagFailsOver is the companion to the
// fail-closed test: when the refreshAttr tag is absent but the
// injection-time flowInjected tag IS present (genuine pooled usage proven
// by the flow ID), the failover MUST still cool the injected member. This
// guards against over-restricting the Finding 3 fix.
func TestTokenEndpointFailoverFlowInjectedTagFailsOver(t *testing.T) {
	addon, prPtr := setupPoolAddonSplitHost(t, "codex_pool", "memA", "memB")
	client := setupAddonConn(addon, "auth.example.com:443")
	pr := prPtr.Load()

	pr.MarkCooldown("memA", time.Now().Add(90*time.Second), "429")
	if got, _ := pr.ResolveActive("codex_pool"); got != "memB" {
		t.Fatalf("active = %q, want memB", got)
	}

	// No refreshAttr tag (e.g. it expired), but the request DID go through
	// the pooled injection path, so flowInjected carries memB for this flow.
	f := newPoolRespFlowBody(client, 400, "expired-refresh", []byte(`{"error":"invalid_grant"}`))
	addon.flowInjected.Tag(f.Id, "memB")

	pool, member, _, _, ok := addon.poolForResponse(f)
	if !ok {
		t.Fatal("poolForResponse: a flow-injection-tagged pooled refresh must still fail over")
	}
	if pool != "codex_pool" || member != "memB" {
		t.Fatalf("got pool=%q member=%q, want codex_pool/memB (flowInjected tag is "+
			"valid pool-usage evidence — Finding 3 must not over-restrict)", pool, member)
	}
}

// TestAPIHostFailoverConcurrentAttributesInjectedMemberNotActive is the
// Finding 1 regression. Two concurrent in-flight API-host requests are both
// backed by member A (the active member at send time). request1's 429
// arrives first: it cools A and the pool switches active to B. request2's
// 429 then arrives. The bug attributed request2's 429 via response-time
// pr.ResolveActive, which now returns B (already active after request1's
// failover) — so B would be wrongly cooled too, parking BOTH accounts.
//
// The fix pins attribution to the member that was injected for THAT request
// (recovered by flow ID from the injection-time tag). Both requests were
// backed by A, so both 429s must be attributed to A; B must remain healthy
// and active-eligible.
//
// This test MUST fail before the fix: with response-time ResolveActive,
// request2's 429 cools B (active after request1's failover), so B ends up
// in cooldown.
func TestAPIHostFailoverConcurrentAttributesInjectedMemberNotActive(t *testing.T) {
	addon, _, prPtr := setupPoolAddon(t, "memA", "memB")
	client := setupAddonConn(addon, "auth.example.com:443")
	pr := prPtr.Load()

	if got, _ := pr.ResolveActive("codex_pool"); got != "memA" {
		t.Fatalf("pre-failover active = %q, want memA", got)
	}

	// Two concurrent requests, both sent while memA was the active member,
	// so pass-1/pass-2 injected memA's credential into both. Mirror that by
	// tagging each flow's injected member as memA (what injectHeaders /
	// buildPhantomPairs now record at injection time).
	req1 := newPoolRespFlow(client, 429, []byte(`{"error":"rate_limited"}`))
	req2 := newPoolRespFlow(client, 429, []byte(`{"error":"rate_limited"}`))
	addon.flowInjected.Tag(req1.Id, "memA")
	addon.flowInjected.Tag(req2.Id, "memA")

	// request1's 429 arrives: cools memA, pool switches active to memB.
	addon.Response(req1)
	if _, cooling := pr.CooldownUntil("memA"); !cooling {
		t.Fatal("memA must be cooling after request1's 429")
	}
	if got, _ := pr.ResolveActive("codex_pool"); got != "memB" {
		t.Fatalf("after request1 failover, active = %q, want memB", got)
	}

	// request2's 429 arrives. memB is now the active member. The bug would
	// attribute this to memB (response-time ResolveActive) and cool it. The
	// fix attributes it to memA (request2's injected member, by flow ID).
	addon.Response(req2)

	if _, cooling := pr.CooldownUntil("memB"); cooling {
		t.Fatal("memB was cooled by request2's 429 — attribution used " +
			"response-time active member instead of the request's injected " +
			"member (Finding 1). Both accounts are now parked.")
	}
	if got, _ := pr.ResolveActive("codex_pool"); got != "memB" {
		t.Fatalf("active = %q, want memB (memB must stay healthy and active)", got)
	}
}

// TestServerStorePoolConcurrentMarkCooldown is the CRITICAL-1 integration
// regression at the real production code path: Server.StorePool's atomic
// pointer swap (the SIGHUP / data_version reload) racing handlePoolFailover's
// lock-free MarkCooldown. With the shared-PoolHealth fix the cooldown can
// never be lost across the swap. Run with -race.
func TestServerStorePoolConcurrentMarkCooldown(t *testing.T) {
	srv := &Server{} // addon nil: StorePool's `if s.addon != nil` guards it.
	shared := vault.NewPoolHealth()
	pool := store.Pool{Name: "p", Strategy: store.PoolStrategyFailover}
	pool.Members = []store.PoolMember{
		{Credential: "m0", Position: 0},
		{Credential: "m1", Position: 1},
		{Credential: "m2", Position: 2},
	}
	srv.StorePool(vault.NewPoolResolverShared([]store.Pool{pool}, nil, shared))

	const iters = 400
	far := 10 * time.Minute
	done := make(chan struct{})

	// Reload loop: rebuild + StorePool (the real atomic swap), bound to the
	// SAME shared health, exactly like loadPoolResolver -> StorePool.
	go func() {
		for i := 0; i < iters; i++ {
			srv.StorePool(vault.NewPoolResolverShared([]store.Pool{pool}, nil, shared))
		}
		close(done)
	}()

	// Failover loop: MarkCooldown on whatever resolver is live now (often
	// one about to be replaced), with NO ReloadMu held — exactly the
	// handlePoolFailover discipline.
	for i := 0; i < iters; i++ {
		pr := srv.poolResolver.Load()
		pr.MarkCooldown(pool.Members[i%3].Credential, time.Now().Add(far), "429")
	}
	<-done

	latest := srv.poolResolver.Load()
	for _, m := range pool.Members {
		if _, cooling := latest.CooldownUntil(m.Credential); !cooling {
			t.Fatalf("cooldown for %q lost across Server.StorePool swaps (CRITICAL-1)", m.Credential)
		}
	}
}

// TestServerStorePoolStaleGenerationCooldownNotLost is the deterministic
// CRITICAL-1 regression that MergeLiveCooldowns' one-generation-back
// chaining provably cannot rescue. A reference to a generation is captured,
// TWO StorePool swaps happen (so the captured pointer is two generations
// stale and was already merged forward BEFORE the cooldown), THEN
// MarkCooldown is applied to that stale generation. Pre-fix, the cooldown
// was applied to a private health map that no live generation points at and
// that was merged forward before the mark — permanently invisible. The
// shared-PoolHealth fix makes it visible because every generation mutates
// the SAME map. A credential ("z") cooled by nothing else makes the
// assertion unambiguous.
func TestServerStorePoolStaleGenerationCooldownNotLost(t *testing.T) {
	srv := &Server{}
	shared := vault.NewPoolHealth()
	pool := store.Pool{Name: "p", Strategy: store.PoolStrategyFailover}
	pool.Members = []store.PoolMember{
		{Credential: "y", Position: 0},
		{Credential: "z", Position: 1},
	}
	srv.StorePool(vault.NewPoolResolverShared([]store.Pool{pool}, nil, shared))

	stale := srv.poolResolver.Load() // generation N
	srv.StorePool(vault.NewPoolResolverShared([]store.Pool{pool}, nil, shared))
	srv.StorePool(vault.NewPoolResolverShared([]store.Pool{pool}, nil, shared))
	// "z" has never been cooled; mark it on the two-generations-stale ref.
	stale.MarkCooldown("z", time.Now().Add(10*time.Minute), "401")

	cur := srv.poolResolver.Load()
	if _, cooling := cur.CooldownUntil("z"); !cooling {
		t.Fatal("cooldown applied to a two-generations-stale resolver was lost " +
			"(CRITICAL-1: MergeLiveCooldowns chains only one generation back and " +
			"runs before the late mark; only shared-PoolHealth survives this)")
	}
	// And it must steer ResolveActive on the live generation.
	if got, _ := cur.ResolveActive("p"); got != "y" {
		t.Fatalf("ResolveActive = %q, want y (z cooled via stale-gen mark)", got)
	}
}
