package proxy

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
)

// setupPoolSplitHostWithPlainCred wires the EXACT topology Copilot round-3
// flagged: a credential pool bound ONLY to the API host (api.example.com),
// whose members refresh against a DIFFERENT token-URL host
// (auth.example.com, testOAuthTokenURL) that has NO pool binding — AND a
// plain (non-pool) OAuth credential that
//
//	(1) shares the same token URL as the pool members, and
//	(2) sorts BEFORE the pool members in credential_meta order.
//
// (2) is the trigger for Findings 1 & 2: OAuthIndex.Match is
// deterministic-first, so it returns the plain credential even when a pool
// member's refresh token is actually in the request body. The metas slice
// below puts the plain credential first so idx.Match(tokenURL) == plain.
func setupPoolSplitHostWithPlainCred(t *testing.T) (*SluiceAddon, *addonWritableProvider, *atomic.Pointer[vault.PoolResolver]) {
	t.Helper()
	const (
		poolName = "codex_pool"
		plain    = "aaa_plain" // sorts before memA/memB
		memA     = "memA"
		memB     = "memB"
	)

	provider := &addonWritableProvider{
		creds: map[string]string{
			plain: poolMemberCred(t, "plain-access-old", "plain-refresh-old"),
			memA:  poolMemberCred(t, "A-access-old", "A-refresh-old"),
			memB:  poolMemberCred(t, "B-access-old", "B-refresh-old"),
		},
	}

	// Pool binding is on the API host only. The plain credential is bound to
	// its own (different) API host so the split-host token-refresh path is
	// the ONLY way its / the pool's refresh can be swapped.
	bindings := []vault.Binding{
		{Destination: "api.example.com", Ports: []int{443}, Credential: poolName},
		{Destination: "plain-api.example.com", Ports: []int{443}, Credential: plain},
	}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatalf("NewBindingResolver: %v", err)
	}
	var resolverPtr atomic.Pointer[vault.BindingResolver]
	resolverPtr.Store(resolver)

	addon := NewSluiceAddon(WithResolver(&resolverPtr), WithProvider(provider))
	addon.persistDone = make(chan struct{}, 10)

	// Plain credential FIRST so idx.Match(testOAuthTokenURL) returns it.
	metas := []store.CredentialMeta{
		{Name: plain, CredType: "oauth", TokenURL: testOAuthTokenURL},
		{Name: memA, CredType: "oauth", TokenURL: testOAuthTokenURL},
		{Name: memB, CredType: "oauth", TokenURL: testOAuthTokenURL},
	}
	addon.UpdateOAuthIndex(metas)

	pool := store.Pool{Name: poolName, Strategy: store.PoolStrategyFailover}
	pool.Members = []store.PoolMember{
		{Credential: memA, Position: 0},
		{Credential: memB, Position: 1},
	}
	var prPtr atomic.Pointer[vault.PoolResolver]
	prPtr.Store(vault.NewPoolResolver([]store.Pool{pool}, nil))
	addon.SetPoolResolver(&prPtr)

	return addon, provider, &prPtr
}

// TestSplitHost_RequestSidePhantomSwapOnTokenHost is the Finding 4
// regression (the crux). The agent POSTs a refresh-grant to the token-URL
// host (auth.example.com), which has NO pool binding — the pool binding
// lives on api.example.com. Before the fix, buildPhantomPairs only iterated
// credentials bound to the CONNECT host, so SLUICE_PHANTOM:codex_pool.refresh
// was NEVER swapped on the token host: the phantom would travel upstream
// verbatim and the refresh would fail. The fix expands pooled OAuth
// credentials whose token_url matches the request even with no CONNECT-host
// binding.
//
// Asserts: (a) the pool refresh phantom is swapped to the ACTIVE member's
// real refresh token, and (b) the realRefreshToken -> member attribution tag
// is recorded (so Findings 1/2 persist + failover can trigger).
func TestSplitHost_RequestSidePhantomSwapOnTokenHost(t *testing.T) {
	addon, _, prPtr := setupPoolSplitHostWithPlainCred(t)
	// CONNECT target is the TOKEN host, which has NO pool binding.
	client := setupAddonConn(addon, "auth.example.com:443")

	pr := prPtr.Load()
	if got, _ := pr.ResolveActive("codex_pool"); got != "memA" {
		t.Fatalf("pre-condition active = %q, want memA", got)
	}

	// Agent holds the pool-keyed refresh phantom. POST it to the token host.
	reqFlow := newTestFlow(client, "POST", testOAuthTokenURL)
	reqFlow.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqFlow.Request.Body = refreshGrantBody("codex_pool")

	addon.Requestheaders(reqFlow)
	addon.Request(reqFlow)

	// (a) The pool refresh phantom must be gone and replaced by memA's REAL
	// refresh token (memA is active).
	body := string(reqFlow.Request.Body)
	if strings.Contains(body, "SLUICE_PHANTOM:codex_pool.refresh") {
		t.Fatalf("Finding 4: pool refresh phantom NOT swapped on the token host; body=%q", body)
	}
	if !strings.Contains(body, "A-refresh-old") {
		t.Fatalf("Finding 4: active member memA's real refresh token not injected; body=%q", body)
	}

	// (b) The R1 attribution tag must be recorded for memA's real refresh
	// token (Peek does not consume it, so this is a non-destructive check).
	if owner, ok := addon.refreshAttr.Peek("A-refresh-old"); !ok || owner != "memA" {
		t.Fatalf("Finding 4: refresh-attribution tag not recorded for memA; got owner=%q ok=%v", owner, ok)
	}
}

// TestSplitHost_2xxPersistAttributedToPoolMemberNotPlainFirstMatch is the
// Finding 1 regression. A successful refresh on the token host where
// idx.Match returns the PLAIN credential (it sorts first and shares the
// token URL). Before the fix, resolveOAuthResponseAttribution saw
// pr.PoolForMember(plain) == "" and took the plain-credential identity
// branch: the pooled member's rotated tokens were persisted under the PLAIN
// credential's vault entry (and the agent got the plain credential's phantom
// instead of the pool-stable one). The fix consults MatchAll, detects the
// pool sharing the token URL, and recovers the true owner from the injected
// refresh token.
func TestSplitHost_2xxPersistAttributedToPoolMemberNotPlainFirstMatch(t *testing.T) {
	addon, provider, _ := setupPoolSplitHostWithPlainCred(t)
	client := setupAddonConn(addon, "auth.example.com:443")

	// Real pass-2 swap on the token host: pool phantom -> memA real refresh,
	// and tags A-refresh-old -> memA.
	reqFlow := newTestFlow(client, "POST", testOAuthTokenURL)
	reqFlow.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqFlow.Request.Body = refreshGrantBody("codex_pool")
	addon.Request(reqFlow)
	if !strings.Contains(string(reqFlow.Request.Body), "A-refresh-old") {
		t.Fatalf("pass-2 did not inject memA real refresh; body=%q", reqFlow.Request.Body)
	}

	// Sanity: idx.Match deterministically returns the PLAIN credential (the
	// collision the Finding-1 bug rode on).
	if idx := addon.oauthIndex.Load(); idx != nil {
		if matched, _ := idx.Match(reqFlow.Request.URL); matched != "aaa_plain" {
			t.Fatalf("precondition: idx.Match must return the first entry aaa_plain, got %q", matched)
		}
	}

	respFlow := newPoolReqRespFlow(client, reqFlow.Request.Body, mustJSON(t, map[string]interface{}{
		"access_token":  "A-access-rotated-1",
		"refresh_token": "A-refresh-rotated-1",
		"expires_in":    3600,
	}))
	addon.Response(respFlow)
	waitAddonPersist(t, addon)

	// memA's vault entry must have the rotated tokens.
	credA, err := vault.ParseOAuth([]byte(provider.creds["memA"]))
	if err != nil {
		t.Fatalf("parse memA: %v", err)
	}
	if credA.RefreshToken != "A-refresh-rotated-1" {
		t.Fatalf("Finding 1: pooled member memA refresh not persisted; got %q want A-refresh-rotated-1",
			credA.RefreshToken)
	}

	// The PLAIN credential must be UNTOUCHED — the bug persisted memA's
	// rotated tokens here because idx.Match returned the plain credential.
	credPlain, err := vault.ParseOAuth([]byte(provider.creds["aaa_plain"]))
	if err != nil {
		t.Fatalf("parse aaa_plain: %v", err)
	}
	if credPlain.RefreshToken != "plain-refresh-old" || credPlain.AccessToken != "plain-access-old" {
		t.Fatalf("Finding 1 VIOLATION: pooled member's rotated tokens landed in the plain credential's vault entry; got access=%q refresh=%q",
			credPlain.AccessToken, credPlain.RefreshToken)
	}

	// The agent must receive the POOL-STABLE phantom, NOT the plain
	// credential's phantom. The pool-stable access phantom is a 3-part
	// synthetic JWT keyed on the pool name.
	agentBody := string(respFlow.Response.Body)
	if strings.Contains(agentBody, "A-access-rotated-1") {
		t.Fatalf("Finding 1: real rotated access token leaked to agent; body=%q", agentBody)
	}
	wantAccessPhantom := poolStablePhantomAccess("codex_pool")
	if !strings.Contains(agentBody, wantAccessPhantom) {
		t.Fatalf("Finding 1: agent did not receive the pool-stable access phantom; body=%q", agentBody)
	}
	if !strings.Contains(agentBody, "SLUICE_PHANTOM:codex_pool.refresh") {
		t.Fatalf("Finding 1: agent did not receive the pool-stable refresh phantom; body=%q", agentBody)
	}
}

// TestSplitHost_TokenEndpointFailoverWithPlainCredSortingFirst is the
// Finding 2 regression. A token-endpoint invalid_grant on the token host
// where idx.Match returns the PLAIN credential (sorts first, shares token
// URL). Before the fix, poolForResponse gated the token-endpoint branch on
// pr.PoolForMember(idx.Match(...)) != "" — which is "" for the plain
// credential — so the whole branch was skipped, poolForResponse returned
// ok=false, NO cooldown was applied, and the broken pool member stayed
// active forever. The fix uses MatchAll to find the pool sharing the token
// URL independent of which credential sorts first, then recovers the true
// owner from the injected refresh token.
func TestSplitHost_TokenEndpointFailoverWithPlainCredSortingFirst(t *testing.T) {
	addon, _, prPtr := setupPoolSplitHostWithPlainCred(t)
	client := setupAddonConn(addon, "auth.example.com:443")
	pr := prPtr.Load()

	// memA is first member AND first active. The realistic precursor: memA
	// got API-429-cooled, traffic rolled to memB, and now memB's refresh
	// invalid_grants on the token host.
	memACooldown := time.Now().Add(90 * time.Second)
	pr.MarkCooldown("memA", memACooldown, "429")
	if got, _ := pr.ResolveActive("codex_pool"); got != "memB" {
		t.Fatalf("after cooling memA, active = %q, want memB", got)
	}

	// pass-2 injected memB's real refresh token; mirror the tag the real
	// pass-2 swap records.
	addon.refreshAttr.Tag("B-refresh-old", "memB")

	// Precondition: idx.Match returns the PLAIN credential (the collision).
	if idx := addon.oauthIndex.Load(); idx != nil {
		u := newPoolRespFlowBody(client, 400, "B-refresh-old", nil).Request.URL
		if matched, _ := idx.Match(u); matched != "aaa_plain" {
			t.Fatalf("precondition: idx.Match must return aaa_plain, got %q", matched)
		}
	}

	// poolForResponse MUST attribute the failure to memB (the injected
	// member), not return ok=false because the plain credential sorted first.
	f := newPoolRespFlowBody(client, 400, "B-refresh-old", []byte(`{"error":"invalid_grant"}`))
	pool, member, _, ok := addon.poolForResponse(f)
	if !ok {
		t.Fatal("Finding 2: token-endpoint failure on a pooled member must be attributed even when a plain cred sorts first; got ok=false")
	}
	if pool != "codex_pool" || member != "memB" {
		t.Fatalf("Finding 2: got pool=%q member=%q, want codex_pool/memB", pool, member)
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
		t.Fatal("Finding 2: memB must be in cooldown after its own invalid_grant")
	}
	if time.Until(bUntil) < vault.AuthFailCooldown-30*time.Second {
		t.Fatalf("memB cooldown TTL = %s, want ~%s (auth-failure)", time.Until(bUntil), vault.AuthFailCooldown)
	}

	// memA must be UNTOUCHED: still cooling on its ORIGINAL 90s 429 window.
	aUntil, aCooling := pr.CooldownUntil("memA")
	if !aCooling {
		t.Fatal("memA should still be cooling on its original 429 window")
	}
	if aUntil.Sub(memACooldown).Abs() > time.Second {
		t.Fatalf("Finding 2: innocent member memA was re-cooled: got %s, want original %s",
			aUntil.Format(time.RFC3339Nano), memACooldown.Format(time.RFC3339Nano))
	}

	select {
	case <-gotCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("onFailover callback not invoked")
	}
	if got.From != "memB" || got.Pool != "codex_pool" || got.Reason != "invalid_grant" {
		t.Fatalf("FailoverEvent = %+v, want from=memB pool=codex_pool reason=invalid_grant", got)
	}
}

// TestFinding3_ProtocolScopedPooledBindingFailoverLookup is the Finding 3
// regression. A pooled binding scoped to a non-https protocol (grpc) on the
// API host. The request-side injection resolves the protocol via
// detectRequestProtocol, so the credential IS injected for a gRPC request.
// Before the fix, poolForResponse hardcoded "https" in its
// CredentialsForDestination lookup, so the protocol-scoped grpc binding was
// invisible on the response path: a 429 on that binding would NOT fail over.
// The fix uses the same detectRequestProtocol result for the lookup.
func TestFinding3_ProtocolScopedPooledBindingFailoverLookup(t *testing.T) {
	const poolName = "grpc_pool"
	provider := &addonWritableProvider{
		creds: map[string]string{
			"gA": poolMemberCred(t, "gA-access", "gA-refresh"),
			"gB": poolMemberCred(t, "gB-access", "gB-refresh"),
		},
	}
	// Pool binding scoped to grpc ONLY on the API host.
	bindings := []vault.Binding{{
		Destination: "grpc.example.com",
		Ports:       []int{443},
		Credential:  poolName,
		Protocols:   []string{"grpc"},
	}}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatalf("NewBindingResolver: %v", err)
	}
	var resolverPtr atomic.Pointer[vault.BindingResolver]
	resolverPtr.Store(resolver)

	addon := NewSluiceAddon(WithResolver(&resolverPtr), WithProvider(provider))
	addon.persistDone = make(chan struct{}, 10)
	addon.UpdateOAuthIndex([]store.CredentialMeta{
		{Name: "gA", CredType: "oauth", TokenURL: testOAuthTokenURL},
		{Name: "gB", CredType: "oauth", TokenURL: testOAuthTokenURL},
	})
	pool := store.Pool{Name: poolName, Strategy: store.PoolStrategyFailover}
	pool.Members = []store.PoolMember{
		{Credential: "gA", Position: 0},
		{Credential: "gB", Position: 1},
	}
	var prPtr atomic.Pointer[vault.PoolResolver]
	prPtr.Store(vault.NewPoolResolver([]store.Pool{pool}, nil))
	addon.SetPoolResolver(&prPtr)

	client := setupAddonConn(addon, "grpc.example.com:443")
	pr := prPtr.Load()
	if got, _ := pr.ResolveActive(poolName); got != "gA" {
		t.Fatalf("pre-failover active = %q, want gA", got)
	}

	// Build a gRPC response flow. detectRequestProtocol refines to gRPC when
	// the request carries the gRPC content type over TLS (https scheme).
	f := newPoolRespFlow(client, 429, []byte(`{"error":"rate_limited"}`))
	f.Request.URL.Scheme = "https"
	f.Request.URL.Host = "grpc.example.com"
	f.Request.Header.Set("Content-Type", "application/grpc")
	f.Response.Header.Set("Content-Type", "application/grpc")

	// Sanity: detectRequestProtocol must classify this as gRPC, and the
	// hardcoded-"https" lookup would have missed the grpc-scoped binding.
	if got := addon.detectRequestProtocol(f, 443); got != ProtoGRPC {
		t.Fatalf("precondition: detectRequestProtocol = %v, want ProtoGRPC", got)
	}
	if res := resolverPtr.Load(); len(res.CredentialsForDestination("grpc.example.com", 443, "https")) != 0 {
		t.Fatal("precondition: a 'https' lookup must NOT match the grpc-scoped binding (this is the Finding 3 bug)")
	}

	pool2, member, _, ok := addon.poolForResponse(f)
	if !ok {
		t.Fatal("Finding 3: protocol-scoped (grpc) pooled binding must be recognized on the failover path; got ok=false")
	}
	if pool2 != poolName || member != "gA" {
		t.Fatalf("Finding 3: got pool=%q member=%q, want %s/gA", pool2, member, poolName)
	}

	var got FailoverEvent
	gotCalled := make(chan struct{}, 1)
	addon.SetOnFailover(func(ev FailoverEvent) {
		got = ev
		gotCalled <- struct{}{}
	})
	addon.Response(f)

	if active, _ := pr.ResolveActive(poolName); active != "gB" {
		t.Fatalf("Finding 3: post-429 active = %q, want gB (grpc-scoped binding must fail over)", active)
	}
	select {
	case <-gotCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("onFailover callback not invoked for grpc-scoped failover")
	}
	if got.From != "gA" || got.Pool != poolName || got.Reason != "429" {
		t.Fatalf("FailoverEvent = %+v, want from=gA pool=%s reason=429", got, poolName)
	}
}
