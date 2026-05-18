package proxy

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/audit"
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
	pool, member, _, _, ok := addon.poolForResponse(f)
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
	// A genuine pooled gRPC request carries the injection-time flow tag
	// (addon.go buildPhantomPairs flowInjected.Tag). Post-round-12 the
	// API-host failover path requires that pool-usage evidence instead of
	// blind-falling-back to ResolveActive, so model production.
	addon.flowInjected.Tag(f.Id, "gA")

	// Sanity: detectRequestProtocol must classify this as gRPC, and the
	// hardcoded-"https" lookup would have missed the grpc-scoped binding.
	if got := addon.detectRequestProtocol(f, 443); got != ProtoGRPC {
		t.Fatalf("precondition: detectRequestProtocol = %v, want ProtoGRPC", got)
	}
	if res := resolverPtr.Load(); len(res.CredentialsForDestination("grpc.example.com", 443, "https")) != 0 {
		t.Fatal("precondition: a 'https' lookup must NOT match the grpc-scoped binding (this is the Finding 3 bug)")
	}

	pool2, member, detProto, _, ok := addon.poolForResponse(f)
	if !ok {
		t.Fatal("Finding 3: protocol-scoped (grpc) pooled binding must be recognized on the failover path; got ok=false")
	}
	if pool2 != poolName || member != "gA" {
		t.Fatalf("Finding 3: got pool=%q member=%q, want %s/gA", pool2, member, poolName)
	}
	if detProto != ProtoGRPC.String() {
		t.Fatalf("Finding 2: poolForResponse detected protocol = %q, want %q", detProto, ProtoGRPC.String())
	}

	// Finding 2: the cred_failover audit event must record the SAME
	// protocol that drove the binding lookup (grpc here), not a hardcoded
	// "https". Wire a real audit logger and assert the persisted Protocol.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	logger, lerr := audit.NewFileLogger(logPath)
	if lerr != nil {
		t.Fatalf("NewFileLogger: %v", lerr)
	}
	addon.auditLog = logger

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

	if cerr := logger.Close(); cerr != nil {
		t.Fatalf("logger close: %v", cerr)
	}
	data, rerr := os.ReadFile(logPath)
	if rerr != nil {
		t.Fatalf("read audit log: %v", rerr)
	}
	var foundFailover bool
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
		foundFailover = true
		if evt.Protocol != ProtoGRPC.String() {
			t.Fatalf("Finding 2: cred_failover audit Protocol = %q, want %q (must match the detected request protocol, not hardcoded https)", evt.Protocol, ProtoGRPC.String())
		}
	}
	if !foundFailover {
		t.Fatalf("no cred_failover audit event found in:\n%s", data)
	}
}

// TestFinding1Round9_PoolNamespaceNotSuppressedByMemberPlainBinding is the
// Copilot round-9 Finding 1 regression. Topology: a pool bound to the API
// host (api.example.com), AND the active pool member (memA) ALSO has its OWN
// plain direct binding on the TOKEN host (auth.example.com, == the pool's
// token URL host). The agent POSTs the pool-keyed refresh grant
// (SLUICE_PHANTOM:codex_pool.refresh) to the token host.
//
// Before the fix, the CONNECT-host binding loop processed memA's plain
// binding on the token host, emitted only memA-scoped phantoms, and set
// covered[memA]=true. The token-host expansion pass then saw
// covered[member]==true (member==memA) and skipped the pool entirely, so
// SLUICE_PHANTOM:codex_pool.refresh AND .access were NEVER swapped: the
// pool-keyed phantoms the agent actually holds would travel upstream
// verbatim and the refresh would fail. The fix gates the token-host pass on
// the POOL namespace (poolEmitted[poolName]) rather than covered[member], so
// a plain member binding no longer suppresses the pool expansion. The pool
// namespace must be emitted exactly once (not double-emitted, not skipped).
func TestFinding1Round9_PoolNamespaceNotSuppressedByMemberPlainBinding(t *testing.T) {
	const (
		poolName = "codex_pool"
		memA     = "memA"
		memB     = "memB"
	)

	provider := &addonWritableProvider{
		creds: map[string]string{
			memA: poolMemberCred(t, "A-access-old", "A-refresh-old"),
			memB: poolMemberCred(t, "B-access-old", "B-refresh-old"),
		},
	}

	// Pool bound to the API host. AND memA (the active member) ALSO has a
	// plain direct binding on the TOKEN host -- this is the configuration
	// that, pre-fix, set covered[memA] in the CONNECT-host loop and
	// suppressed the pool expansion on the token host.
	bindings := []vault.Binding{
		{Destination: "api.example.com", Ports: []int{443}, Credential: poolName},
		{Destination: "auth.example.com", Ports: []int{443}, Credential: memA},
	}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatalf("NewBindingResolver: %v", err)
	}
	var resolverPtr atomic.Pointer[vault.BindingResolver]
	resolverPtr.Store(resolver)

	addon := NewSluiceAddon(WithResolver(&resolverPtr), WithProvider(provider))
	addon.persistDone = make(chan struct{}, 10)

	metas := []store.CredentialMeta{
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

	if got, _ := prPtr.Load().ResolveActive(poolName); got != memA {
		t.Fatalf("pre-condition active = %q, want %s", got, memA)
	}

	// CONNECT target is the token host (where memA ALSO has a plain
	// binding). The agent body carries the pool-keyed refresh phantom.
	client := setupAddonConn(addon, "auth.example.com:443")
	reqFlow := newTestFlow(client, "POST", testOAuthTokenURL)
	reqFlow.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqFlow.Request.Body = refreshGrantBody(poolName)

	addon.Requestheaders(reqFlow)
	addon.Request(reqFlow)

	body := string(reqFlow.Request.Body)

	// The pool refresh phantom must be swapped to the active member's REAL
	// refresh token, NOT left verbatim.
	if strings.Contains(body, "SLUICE_PHANTOM:"+poolName+".refresh") {
		t.Fatalf("Finding 1 r9: pool refresh phantom NOT swapped (suppressed by member plain binding); body=%q", body)
	}
	if !strings.Contains(body, "A-refresh-old") {
		t.Fatalf("Finding 1 r9: active member memA real refresh token not injected; body=%q", body)
	}
	// The pool ACCESS phantom must also be swappable: build the pairs
	// directly and assert the pool access phantom maps to memA's real
	// access token exactly once (no double-emit, not suppressed).
	pairs := addon.buildPhantomPairs("auth.example.com", 443, "https", reqFlow.Request.URL, requestFlowGrantType(reqFlow))
	defer releasePhantomPairs(pairs)
	accessPhantom := poolStablePhantomAccess(poolName)
	refreshPhantom := "SLUICE_PHANTOM:" + poolName + ".refresh"
	var accessCount, refreshCount int
	for _, p := range pairs {
		switch string(p.phantom) {
		case accessPhantom:
			accessCount++
			if got := string(p.secret.Bytes()); got != "A-access-old" {
				t.Fatalf("pool access phantom -> %q, want A-access-old", got)
			}
		case refreshPhantom:
			refreshCount++
			if got := string(p.secret.Bytes()); got != "A-refresh-old" {
				t.Fatalf("pool refresh phantom -> %q, want A-refresh-old", got)
			}
		}
	}
	if accessCount != 1 {
		t.Fatalf("Finding 1 r9: pool access phantom emitted %d times, want exactly 1 (not suppressed, not double-emitted)", accessCount)
	}
	if refreshCount != 1 {
		t.Fatalf("Finding 1 r9: pool refresh phantom emitted %d times, want exactly 1 (not suppressed, not double-emitted)", refreshCount)
	}
}

// TestFinding2_PlainOAuthOnSharedTokenURLDoesNotTagOrCoolPool is the
// Finding 2 (round-16) regression.
//
// The token-host expansion in buildPhantomPairs tagged the flow
// (flowInjected.Tag) the moment it BUILT candidate pool phantom pairs for a
// matching token URL — BEFORE verifying any pool phantom was actually
// present in (and swapped out of) the outbound request. A plain OAuth
// credential whose token URL is SHARED with a pool therefore acquired a
// per-flow pool-usage tag on its OWN refresh. poolForResponse treats that
// flowInjected tag as proof the request used the pool, so the plain
// credential's 401 / invalid_grant cooled an UNRELATED active pool member
// and parked it.
//
// The fix moves tagging to tagPooledFlowAfterSwap, which records the tag
// only when the pool phantom is genuinely present in the request (i.e. an
// actual pool-phantom replacement happens for this flow). A plain refresh
// (no pool phantom in the body) is no longer tagged, so its failure cannot
// be mis-attributed to the pool.
//
// Two halves, both must hold:
//
//	(a) plain OAuth refresh on the shared token URL, NO pool phantom in the
//	    body, 401/invalid_grant -> NO pool member cooled (no flowInjected
//	    tag was set). FAILS before the fix (the build-time tag is set, so
//	    poolForResponse cools the active member).
//	(b) a genuine pooled refresh (pool phantom present, actually swapped)
//	    with 401/invalid_grant -> the correct member is still cooled. Guards
//	    against the fix over-restricting the legit split-host pooled-refresh
//	    path / regressing the round-9/12 fixes.
func TestFinding2_PlainOAuthOnSharedTokenURLDoesNotTagOrCoolPool(t *testing.T) {
	// --- (a) plain refresh, no pool phantom: must NOT tag, must NOT cool ---
	addon, _, prPtr := setupPoolSplitHostWithPlainCred(t)
	// CONNECT target is the shared TOKEN host (no pool binding lives here;
	// the only pooled injection path is the token-host expansion).
	client := setupAddonConn(addon, "auth.example.com:443")
	pr := prPtr.Load()

	// Realistic precursor: memA API-429-cooled, traffic on memB.
	memACooldown := time.Now().Add(90 * time.Second)
	pr.MarkCooldown("memA", memACooldown, "429")
	if got, _ := pr.ResolveActive("codex_pool"); got != "memB" {
		t.Fatalf("after cooling memA, active = %q, want memB", got)
	}
	memBPre, memBPreCooling := pr.CooldownUntil("memB")

	// The agent refreshes a PLAIN OAuth credential against the shared token
	// URL. Its body carries NO SLUICE_PHANTOM:codex_pool.* pool phantom —
	// it is an ordinary refresh-grant. The token-host expansion still
	// builds the pool's candidate phantom pairs (the pool shares this token
	// URL), but no pool phantom is present to swap.
	reqFlow := newTestFlow(client, "POST", testOAuthTokenURL)
	reqFlow.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqFlow.Request.Body = []byte("grant_type=refresh_token&refresh_token=plain-refresh-old")

	addon.Requestheaders(reqFlow)
	addon.Request(reqFlow)

	// The pool phantom never appeared in the request, so NO flowInjected
	// pool-usage tag may have been recorded for this flow.
	if m, ok := addon.flowInjected.Peek(reqFlow.Id); ok {
		t.Fatalf("Finding 2: a plain OAuth refresh on a shared token URL acquired "+
			"a flowInjected pool-usage tag (member=%q) even though NO pool phantom "+
			"was present/swapped — its 401 would cool an unrelated pool member", m)
	}

	// The plain credential's refresh now 401s / invalid_grants on the
	// shared token host. With no pool-usage evidence, poolForResponse must
	// fail closed and NO pool member may be cooled.
	respFlow := newPoolRespFlowBody(client, 401, "plain-refresh-old",
		[]byte(`{"error":"invalid_grant"}`))
	if pool, member, _, _, ok := addon.poolForResponse(respFlow); ok {
		t.Fatalf("Finding 2: poolForResponse attributed a plain-credential failure "+
			"to the pool (pool=%q member=%q) — the build-time flowInjected tag "+
			"mis-flagged a plain refresh as pooled usage", pool, member)
	}
	addon.Response(respFlow)

	if u, cooling := pr.CooldownUntil("memB"); cooling != memBPreCooling || !u.Equal(memBPre) {
		t.Fatalf("Finding 2: active pool member memB cooldown changed (%v/%v -> %v/%v) "+
			"on a PLAIN credential's invalid_grant — an innocent member was parked",
			memBPre, memBPreCooling, u, cooling)
	}
	if aU, c := pr.CooldownUntil("memA"); !c || aU.Sub(memACooldown).Abs() > time.Second {
		t.Fatalf("Finding 2: memA's original 429 window disturbed: got %v (cooling=%v), want %v",
			aU, c, memACooldown)
	}

	// --- (b) genuine pooled refresh: pool phantom present -> still cools ---
	addon2, _, prPtr2 := setupPoolSplitHostWithPlainCred(t)
	client2 := setupAddonConn(addon2, "auth.example.com:443")
	pr2 := prPtr2.Load()
	if got, _ := pr2.ResolveActive("codex_pool"); got != "memA" {
		t.Fatalf("pre-condition active = %q, want memA", got)
	}

	// The agent holds the POOL refresh phantom and POSTs it. The token-host
	// expansion swaps it to memA's real refresh token AND (post-swap)
	// records the per-flow pool-usage tag because the pool phantom WAS
	// genuinely present.
	poolReq := newTestFlow(client2, "POST", testOAuthTokenURL)
	poolReq.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	poolReq.Request.Body = refreshGrantBody("codex_pool")

	addon2.Requestheaders(poolReq)
	addon2.Request(poolReq)

	if strings.Contains(string(poolReq.Request.Body), "SLUICE_PHANTOM:codex_pool.refresh") {
		t.Fatalf("genuine pooled refresh: pool phantom not swapped; body=%q",
			string(poolReq.Request.Body))
	}
	if m, ok := addon2.flowInjected.Peek(poolReq.Id); !ok || m != "memA" {
		t.Fatalf("Finding 2 over-restriction: a genuine pooled refresh (pool "+
			"phantom actually swapped) was NOT tagged; got member=%q ok=%v "+
			"(the legit split-host pooled-refresh path must still tag)", m, ok)
	}

	// memA's pooled refresh invalid_grants -> memA must still be cooled and
	// the pool must fail over to memB.
	poolResp := newPoolRespFlowBody(client2, 401, "A-refresh-old",
		[]byte(`{"error":"invalid_grant"}`))
	pool, member, _, _, ok := addon2.poolForResponse(poolResp)
	if !ok || pool != "codex_pool" || member != "memA" {
		t.Fatalf("Finding 2 over-restriction: genuine pooled refresh not attributed; "+
			"got ok=%v pool=%q member=%q, want codex_pool/memA", ok, pool, member)
	}
	addon2.Response(poolResp)
	if _, cooling := pr2.CooldownUntil("memA"); !cooling {
		t.Fatal("Finding 2 over-restriction: genuine pooled member memA not cooled " +
			"after its own invalid_grant")
	}
	if active, _ := pr2.ResolveActive("codex_pool"); active != "memB" {
		t.Fatalf("Finding 2 over-restriction: pool did not fail over; active = %q, want memB", active)
	}
}

// TestFinding1Round19_PlainCredRefreshOnSharedTokenURLPersistsNormally is the
// round-19 Finding 1 regression. A PLAIN (non-pool) OAuth credential whose
// token URL is shared with a pool refreshes normally: its own phantom is in
// the request body, NO pool phantom. Before this fix,
// resolveOAuthResponseAttribution saw "a pool shares this token URL" +
// refreshAttr.Recover failing (no pooled tag, because the plain injection
// path never recorded one) and took the pooled fail-closed branch — it
// SKIPPED the plain credential's vault write AND rewrote the response with
// the POOL phantom instead of the plain credential's own phantom. That
// breaks a legitimate standalone credential that merely shares an OAuth
// issuer with a pool.
//
// The fix tags the plain credential's real refresh token under the PLAIN
// name (PoolForMember == "" distinguishes it from a pooled member) on the
// request side, so the response side recovers it and attributes 1:1.
func TestFinding1Round19_PlainCredRefreshOnSharedTokenURLPersistsNormally(t *testing.T) {
	addon, provider, prPtr := setupPoolSplitHostWithPlainCred(t)
	client := setupAddonConn(addon, "auth.example.com:443")
	pr := prPtr.Load()

	// Sanity: the pool's active member is memA and idx.Match returns the
	// plain credential first (the collision the round-9/16 bug rode on).
	if got, _ := pr.ResolveActive("codex_pool"); got != "memA" {
		t.Fatalf("pre-condition active = %q, want memA", got)
	}

	// The agent refreshes the PLAIN credential. Its body carries the plain
	// credential's OWN refresh phantom (SLUICE_PHANTOM:aaa_plain.refresh),
	// NOT any pool phantom. The token-host expansion swaps it to the plain
	// credential's real refresh token and tags plain-refresh-old -> aaa_plain.
	reqFlow := newTestFlow(client, "POST", testOAuthTokenURL)
	reqFlow.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqFlow.Request.Body = []byte(
		"grant_type=refresh_token&refresh_token=SLUICE_PHANTOM:aaa_plain.refresh",
	)

	addon.Requestheaders(reqFlow)
	addon.Request(reqFlow)

	// (req) The plain phantom must be swapped to the plain credential's REAL
	// refresh token (proves the token-host plain expansion fired) and the
	// pool's real refresh token must NOT appear (no pool involvement).
	reqBody := string(reqFlow.Request.Body)
	if strings.Contains(reqBody, "SLUICE_PHANTOM:aaa_plain.refresh") {
		t.Fatalf("plain refresh phantom not swapped on the token host; body=%q", reqBody)
	}
	if !strings.Contains(reqBody, "plain-refresh-old") {
		t.Fatalf("plain credential's real refresh token not injected; body=%q", reqBody)
	}
	if strings.Contains(reqBody, "A-refresh-old") || strings.Contains(reqBody, "B-refresh-old") {
		t.Fatalf("a pool member's real refresh token leaked into a PLAIN refresh; body=%q", reqBody)
	}

	// No pool-usage tag may have been recorded (no pool phantom present).
	if m, ok := addon.flowInjected.Peek(reqFlow.Id); ok {
		t.Fatalf("plain refresh acquired a flowInjected pool-usage tag (member=%q)", m)
	}

	// The upstream returns rotated tokens for the PLAIN credential.
	respFlow := newPoolReqRespFlow(client, reqFlow.Request.Body, mustJSON(t, map[string]interface{}{
		"access_token":  "plain-access-rotated-1",
		"refresh_token": "plain-refresh-rotated-1",
		"expires_in":    3600,
	}))
	addon.Response(respFlow)
	waitAddonPersist(t, addon)

	// (persist) The PLAIN credential's vault entry MUST hold the rotated
	// tokens — NOT skipped (the round-9/16 fail-closed bug skipped it).
	credPlain, err := vault.ParseOAuth([]byte(provider.creds["aaa_plain"]))
	if err != nil {
		t.Fatalf("parse aaa_plain: %v", err)
	}
	if credPlain.RefreshToken != "plain-refresh-rotated-1" ||
		credPlain.AccessToken != "plain-access-rotated-1" {
		t.Fatalf("Finding 1 round-19: plain credential refresh NOT persisted "+
			"(fail-closed mis-applied); got access=%q refresh=%q want "+
			"plain-access-rotated-1/plain-refresh-rotated-1",
			credPlain.AccessToken, credPlain.RefreshToken)
	}

	// The pool members' vault entries MUST be untouched.
	credA, _ := vault.ParseOAuth([]byte(provider.creds["memA"]))
	if credA.RefreshToken != "A-refresh-old" {
		t.Fatalf("Finding 1 round-19: plain refresh misfiled into pool member memA; got %q",
			credA.RefreshToken)
	}

	// (phantom) The agent must receive the PLAIN credential's OWN phantom,
	// NOT the pool-stable phantom (the round-9/16 bug rewrote with the pool
	// phantom).
	agentBody := string(respFlow.Response.Body)
	if strings.Contains(agentBody, "plain-access-rotated-1") ||
		strings.Contains(agentBody, "plain-refresh-rotated-1") {
		t.Fatalf("Finding 1 round-19: real rotated plain tokens leaked to agent; body=%q", agentBody)
	}
	if !strings.Contains(agentBody, "SLUICE_PHANTOM:aaa_plain.refresh") {
		t.Fatalf("Finding 1 round-19: agent did not receive the plain credential's "+
			"own refresh phantom; body=%q", agentBody)
	}
	if !strings.Contains(agentBody, "SLUICE_PHANTOM:aaa_plain.access") {
		t.Fatalf("Finding 1 round-19: agent did not receive the plain credential's "+
			"own access phantom; body=%q", agentBody)
	}
	if strings.Contains(agentBody, poolStablePhantomAccess("codex_pool")) ||
		strings.Contains(agentBody, "SLUICE_PHANTOM:codex_pool.refresh") {
		t.Fatalf("Finding 1 round-19: response rewritten with the POOL phantom for a "+
			"PLAIN refresh; body=%q", agentBody)
	}
}

// TestFinding2Round19_QUICPoolBindingExpandsToActiveMember is the round-19
// Finding 2 regression. A binding that NAMES A POOL must work over QUIC.
// Before this fix the QUIC injection path was constructed with only the
// binding resolver and called provider.Get(<bound name>) directly — for a
// pool-named binding that is provider.Get(<pool>), but no vault secret is
// stored under a pool name, so injection failed for that destination over
// QUIC. The fix wires the pool resolver into QUICProxy and expands a pool
// binding to its ACTIVE member (ResolveActive) before provider.Get,
// mirroring the HTTP-MITM chokepoint.
//
// QUIC-LIMITED scope (documented in CLAUDE.md): only active-member
// expansion is implemented on QUIC. The asserts below also pin the
// documented boundary — the phantom stays keyed on the POOL name (stable
// across member switches) and switching the active member changes only the
// injected SECRET, never the phantom; per-request refresh attribution and
// 429/401 auto-failover are HTTP-path only and are NOT exercised here.
func TestFinding2Round19_QUICPoolBindingExpandsToActiveMember(t *testing.T) {
	caCert, _, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	const poolName = "codex_pool"
	provider := &addonWritableProvider{
		creds: map[string]string{
			"memA": poolMemberCred(t, "A-access-old", "A-refresh-old"),
			"memB": poolMemberCred(t, "B-access-old", "B-refresh-old"),
		},
	}

	// The binding NAMES THE POOL, not a member.
	bindings := []vault.Binding{{
		Destination: "api.example.com",
		Ports:       []int{443},
		Credential:  poolName,
	}}
	br, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatalf("NewBindingResolver: %v", err)
	}
	var brPtr atomic.Pointer[vault.BindingResolver]
	brPtr.Store(br)

	pool := store.Pool{Name: poolName, Strategy: store.PoolStrategyFailover}
	pool.Members = []store.PoolMember{
		{Credential: "memA", Position: 0},
		{Credential: "memB", Position: 1},
	}
	var prPtr atomic.Pointer[vault.PoolResolver]
	prPtr.Store(vault.NewPoolResolver([]store.Pool{pool}, nil))

	qp, err := NewQUICProxy(caCert, provider, &brPtr, &prPtr, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewQUICProxy: %v", err)
	}

	// resolvePoolMember must expand the pool name to the active member.
	if got := qp.resolvePoolMember(poolName); got != "memA" {
		t.Fatalf("Finding 2: resolvePoolMember(%q) = %q, want active member memA", poolName, got)
	}
	if got := qp.resolvePoolMember("memA"); got != "memA" {
		t.Fatalf("resolvePoolMember must pass a plain/member name through; got %q", got)
	}

	// buildPhantomPairs must NOT fail with provider.Get(<pool>) "not found";
	// it must inject the ACTIVE member's (memA) real OAuth tokens while
	// keying the phantom on the POOL name (stable across member switches).
	pairs := qp.buildPhantomPairs("api.example.com", 443)
	if len(pairs) == 0 {
		t.Fatal("Finding 2: buildPhantomPairs returned no pairs for a pool-named " +
			"binding over QUIC (pool->member expansion missing — provider.Get(<pool>) failed)")
	}
	// Finding 1 (round 20): the pooled OAuth access phantom is the
	// pool-stable SYNTHETIC JWT keyed on the pool name (poolStablePhantomAccess),
	// NOT the literal "SLUICE_PHANTOM:<pool>.access" string. The earlier
	// assertion only held because these access tokens are non-JWT and the
	// old code fell back to the static string — a coincidence that masked
	// the R3 violation. Assert the real pool-stable phantom here.
	wantPoolAccess := poolStablePhantomAccess(poolName)
	var sawPoolAccessPhantom, sawPoolRefreshPhantom, sawMemAAccess, sawMemARefresh bool
	for _, p := range pairs {
		ps := string(p.phantom)
		switch ps {
		case wantPoolAccess:
			sawPoolAccessPhantom = true
		case "SLUICE_PHANTOM:" + poolName + ".refresh":
			sawPoolRefreshPhantom = true
		}
		switch p.secret.String() {
		case "A-access-old":
			sawMemAAccess = true
		case "A-refresh-old":
			sawMemARefresh = true
		}
		if strings.HasPrefix(ps, "SLUICE_PHANTOM:memA") || strings.HasPrefix(ps, "SLUICE_PHANTOM:memB") {
			t.Fatalf("Finding 2 QUIC-limit: phantom keyed on a MEMBER name (%q) — must "+
				"be keyed on the POOL name so it is stable across member switches", ps)
		}
	}
	releasePhantomPairs(pairs)
	if !sawPoolAccessPhantom || !sawPoolRefreshPhantom {
		t.Fatalf("Finding 2: pool-keyed phantoms missing (access=%v refresh=%v)",
			sawPoolAccessPhantom, sawPoolRefreshPhantom)
	}
	if !sawMemAAccess || !sawMemARefresh {
		t.Fatalf("Finding 2: active member memA's real OAuth tokens not injected "+
			"(access=%v refresh=%v)", sawMemAAccess, sawMemARefresh)
	}

	// Documented QUIC boundary: flipping the active member changes ONLY the
	// injected secret; the phantom the agent holds stays pool-keyed and
	// byte-identical (no per-request attribution / failover on QUIC, but
	// the active member IS honored).
	prPtr.Load().MarkCooldown("memA", time.Now().Add(time.Minute), "429")
	if got := qp.resolvePoolMember(poolName); got != "memB" {
		t.Fatalf("Finding 2: after cooling memA, resolvePoolMember = %q, want memB", got)
	}
	pairs2 := qp.buildPhantomPairs("api.example.com", 443)
	var sawMemBRefresh, stillPoolKeyed bool
	for _, p := range pairs2 {
		if p.secret.String() == "B-refresh-old" {
			sawMemBRefresh = true
		}
		if string(p.phantom) == "SLUICE_PHANTOM:"+poolName+".refresh" {
			stillPoolKeyed = true
		}
	}
	releasePhantomPairs(pairs2)
	if !sawMemBRefresh {
		t.Fatal("Finding 2: after failover the new active member memB's real refresh " +
			"token was not injected over QUIC")
	}
	if !stillPoolKeyed {
		t.Fatal("Finding 2 QUIC-limit: phantom changed across member switch — it must " +
			"stay keyed on the pool name (R3-style stability) even on QUIC")
	}
}

// makeTestJWT builds a structurally valid (header.payload.sig) JWT whose
// payload varies by sub. resignJWT re-signs header+payload of the *real*
// token, so two members with DIFFERENT JWT payloads produce DIFFERENT
// re-signed phantoms under the buggy buildOAuthPhantomPairs(boundName,...)
// path — which is exactly the R3 violation Finding 1 targets. The earlier
// QUIC test used non-JWT access strings, so resignJWT returned "" and the
// static SLUICE_PHANTOM:<pool>.access fallback masked the bug.
func makeTestJWT(t *testing.T, sub string) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	pl := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + sub + `","iss":"real-idp"}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("real-signature-for-" + sub))
	return hdr + "." + pl + "." + sig
}

// TestFinding1Round20_QUICPoolAccessPhantomStableAcrossMemberSwitch asserts
// the R3 pool-stable access-token guarantee on the QUIC path: the
// agent-facing access phantom must be byte-identical across a member switch
// (it is keyed on the POOL name via poolStablePhantomAccess), while the
// injected real token must be the *active* member's. Before the fix the
// QUIC path used buildOAuthPhantomPairs(boundName,...) which re-signed the
// active member's REAL JWT, so the phantom changed on every member switch.
func TestFinding1Round20_QUICPoolAccessPhantomStableAcrossMemberSwitch(t *testing.T) {
	caCert, _, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	const poolName = "codex_pool"
	jwtA := makeTestJWT(t, "member-A")
	jwtB := makeTestJWT(t, "member-B")
	provider := &addonWritableProvider{
		creds: map[string]string{
			"memA": poolMemberCred(t, jwtA, "A-refresh"),
			"memB": poolMemberCred(t, jwtB, "B-refresh"),
		},
	}

	bindings := []vault.Binding{{
		Destination: "api.example.com",
		Ports:       []int{443},
		Credential:  poolName,
	}}
	br, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatalf("NewBindingResolver: %v", err)
	}
	var brPtr atomic.Pointer[vault.BindingResolver]
	brPtr.Store(br)

	pool := store.Pool{Name: poolName, Strategy: store.PoolStrategyFailover}
	pool.Members = []store.PoolMember{
		{Credential: "memA", Position: 0},
		{Credential: "memB", Position: 1},
	}
	var prPtr atomic.Pointer[vault.PoolResolver]
	prPtr.Store(vault.NewPoolResolver([]store.Pool{pool}, nil))

	qp, err := NewQUICProxy(caCert, provider, &brPtr, &prPtr, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewQUICProxy: %v", err)
	}

	accessPhantomFor := func(t *testing.T, wantSecret string) string {
		t.Helper()
		pairs := qp.buildPhantomPairs("api.example.com", 443)
		defer releasePhantomPairs(pairs)
		var accessPhantom string
		var sawWantSecret bool
		for _, p := range pairs {
			ps := string(p.phantom)
			// The access phantom is the one whose real secret is a JWT
			// (the refresh phantom carries the *-refresh secret).
			if strings.Count(ps, ".") == 2 && !strings.HasPrefix(ps, "SLUICE_PHANTOM:") {
				accessPhantom = ps
			}
			if p.secret.String() == wantSecret {
				sawWantSecret = true
			}
			if strings.HasPrefix(ps, "SLUICE_PHANTOM:memA") ||
				strings.HasPrefix(ps, "SLUICE_PHANTOM:memB") {
				t.Fatalf("phantom keyed on a MEMBER name (%q)", ps)
			}
		}
		if accessPhantom == "" {
			t.Fatal("no JWT-shaped access phantom found in pairs")
		}
		if !sawWantSecret {
			t.Fatalf("active member's real access token %q not injected", wantSecret)
		}
		return accessPhantom
	}

	// Active member memA: phantom must be the pool-stable synthetic JWT,
	// real injected secret must be memA's JWT.
	phantom1 := accessPhantomFor(t, jwtA)

	// Independently confirm it is exactly the pool-stable synthetic JWT
	// (not a re-sign of memA's real JWT).
	wantStable := poolStablePhantomAccess(poolName)
	if phantom1 != wantStable {
		t.Fatalf("access phantom is not the pool-stable synthetic JWT\n got: %q\nwant: %q",
			phantom1, wantStable)
	}

	// Flip the active member to memB.
	prPtr.Load().MarkCooldown("memA", time.Now().Add(time.Minute), "429")
	if got := qp.resolvePoolMember(poolName); got != "memB" {
		t.Fatalf("after cooling memA, active member = %q, want memB", got)
	}

	// After the switch the agent-facing access phantom MUST be
	// byte-identical (R3), while the injected real token is now memB's JWT.
	phantom2 := accessPhantomFor(t, jwtB)
	if phantom2 != phantom1 {
		t.Fatalf("Finding 1 (R3 on QUIC): agent-facing access phantom CHANGED across "+
			"a member switch — must be byte-identical\nbefore: %q\n after: %q",
			phantom1, phantom2)
	}
}
