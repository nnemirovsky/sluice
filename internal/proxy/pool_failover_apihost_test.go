package proxy

import (
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"

	mitmproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
	uuid "github.com/satori/go.uuid"
)

// Round-12 regression: poolForResponse's API-host path iterates
// CredentialsForDestination(dest:port), which can return MULTIPLE matching
// pools (or a plain binding) for one destination. The old code called the
// single-use flowInjected.Recover INSIDE that loop and blind-fell-back to
// ResolveActive for any matching pool, so:
//
//   - a request that used a PLAIN binding (no flow tag) but whose dest:port
//     also matched a pool would wrongly cool that pool's active member; and
//   - when two pools matched the same dest:port and the flow tag belonged to
//     the SECOND pool, the FIRST pool consumed the tag, mis-cooled itself via
//     blind ResolveActive, and starved the true (second) pool of its tag.
//
// The fix Peeks the per-flow injected member ONCE (non-consuming) before the
// loop and attributes a pool ONLY when the injected member proves it belongs
// to THAT pool. No blind ResolveActive fallback.

// setupTwoPoolAddonSameAPIHost wires a SluiceAddon with TWO failover pools
// (poolX, poolY) BOTH bound to the same API host api.example.com:443. The
// agent's bindings point at the pool names; CredentialsForDestination for
// api.example.com:443 therefore returns [poolX, poolY] in binding order.
func setupTwoPoolAddonSameAPIHost(t *testing.T) (*SluiceAddon, *atomic.Pointer[vault.PoolResolver]) {
	t.Helper()

	provider := &addonWritableProvider{
		creds: map[string]string{
			"x1": poolMemberCred(t, "x1-access", "x1-refresh"),
			"x2": poolMemberCred(t, "x2-access", "x2-refresh"),
			"y1": poolMemberCred(t, "y1-access", "y1-refresh"),
			"y2": poolMemberCred(t, "y2-access", "y2-refresh"),
		},
	}

	// Two distinct pool bindings on the SAME api host:port. Binding order
	// (poolX first) drives CredentialsForDestination ordering.
	bindings := []vault.Binding{
		{Destination: "api.example.com", Ports: []int{443}, Credential: "poolX"},
		{Destination: "api.example.com", Ports: []int{443}, Credential: "poolY"},
	}
	resolver, err := vault.NewBindingResolver(bindings)
	if err != nil {
		t.Fatalf("NewBindingResolver: %v", err)
	}
	var resolverPtr atomic.Pointer[vault.BindingResolver]
	resolverPtr.Store(resolver)

	addon := NewSluiceAddon(WithResolver(&resolverPtr), WithProvider(provider))
	addon.persistDone = make(chan struct{}, 10)

	poolX := store.Pool{Name: "poolX", Strategy: store.PoolStrategyFailover}
	poolX.Members = []store.PoolMember{
		{Credential: "x1", Position: 0},
		{Credential: "x2", Position: 1},
	}
	poolY := store.Pool{Name: "poolY", Strategy: store.PoolStrategyFailover}
	poolY.Members = []store.PoolMember{
		{Credential: "y1", Position: 0},
		{Credential: "y2", Position: 1},
	}
	var prPtr atomic.Pointer[vault.PoolResolver]
	prPtr.Store(vault.NewPoolResolver([]store.Pool{poolX, poolY}, nil))
	addon.SetPoolResolver(&prPtr)

	return addon, &prPtr
}

// newAPIHostRespFlow builds a plain API-host response flow (not a token
// endpoint). The request URL is a regular API path on api.example.com so the
// token-URL index path is NOT exercised — only the CONNECT-host API path.
//
// status is parameterized on purpose: this is a general API-host response
// builder for the round-12 suite (429 is the only failover-trigger the
// current cases need, but 403/401/2xx are equally valid inputs). unparam
// only sees the current callers all using 429.
//
//nolint:unparam
func newAPIHostRespFlow(client *mitmproxy.ClientConn, status int) *mitmproxy.Flow {
	u, _ := url.Parse("https://api.example.com/v1/responses")
	return &mitmproxy.Flow{
		Id:          uuid.NewV4(),
		ConnContext: &mitmproxy.ConnContext{ClientConn: client},
		Request:     &mitmproxy.Request{Method: "POST", URL: u, Header: make(http.Header)},
		Response:    &mitmproxy.Response{StatusCode: status, Header: make(http.Header)},
	}
}

// TestAPIHostFailover_PlainBindingNoTag_NoPoolCooled is round-12 case (a).
//
// A request used a PLAIN (non-pool) binding so there is NO per-flow injected
// tag, but dest:port (api.example.com:443) also matches pooled bindings. The
// old code blind-fell-back to ResolveActive and cooled a pool the request
// never used. After the fix, with no proof of pool usage, NO pool member is
// cooled and poolForResponse returns ok=false.
//
// Fails before the fix: the old loop, finding poolX matched and no recoverable
// tag, returned (poolX, x1, true) via the blind ResolveActive fallback.
func TestAPIHostFailover_PlainBindingNoTag_NoPoolCooled(t *testing.T) {
	addon, prPtr := setupTwoPoolAddonSameAPIHost(t)
	client := setupAddonConn(addon, "api.example.com:443")

	pr := prPtr.Load()
	if got, _ := pr.ResolveActive("poolX"); got != "x1" {
		t.Fatalf("pre active poolX = %q, want x1", got)
	}
	if got, _ := pr.ResolveActive("poolY"); got != "y1" {
		t.Fatalf("pre active poolY = %q, want y1", got)
	}

	// No flowInjected.Tag for this flow id: models a request that went out
	// on a plain binding (or never through pooled injection).
	f := newAPIHostRespFlow(client, 429)

	pool, member, _, _, ok := addon.poolForResponse(f)
	if ok {
		t.Fatalf("poolForResponse: with no pool-usage evidence it must NOT "+
			"attribute any pool; got ok=true pool=%q member=%q", pool, member)
	}

	called := false
	addon.SetOnFailover(func(FailoverEvent) { called = true })
	addon.Response(newAPIHostRespFlow(client, 429))
	if called {
		t.Fatal("onFailover invoked though no pool was used by the request")
	}

	// Neither pool's active member changed (nothing was cooled).
	if got, _ := pr.ResolveActive("poolX"); got != "x1" {
		t.Fatalf("post active poolX = %q, want x1 (must not be cooled)", got)
	}
	if got, _ := pr.ResolveActive("poolY"); got != "y1" {
		t.Fatalf("post active poolY = %q, want y1 (must not be cooled)", got)
	}
}

// TestAPIHostFailover_TagBelongsToSecondPool is round-12 case (b).
//
// Both poolX and poolY bind api.example.com:443, so
// CredentialsForDestination returns [poolX, poolY]. The per-flow injected
// member belongs to the SECOND pool (poolY's y1). The old single-use
// Recover, called inside the loop, was consumed by the FIRST pool (poolX):
// poolX's PoolForMember(y1) != "poolX" so poolX blind-fell-back to
// ResolveActive and was wrongly cooled, AND poolY could no longer see the
// (already consumed) tag so poolY — the true owner — was never attributed.
//
// After the fix the single non-consuming Peek serves the whole iteration:
// poolX is skipped (y1 is not its member, no blind fallback) and poolY is
// correctly attributed to y1.
//
// Fails before the fix: poolForResponse returned (poolX, x1) — wrong pool,
// wrong member.
func TestAPIHostFailover_TagBelongsToSecondPool(t *testing.T) {
	addon, prPtr := setupTwoPoolAddonSameAPIHost(t)
	client := setupAddonConn(addon, "api.example.com:443")
	pr := prPtr.Load()

	f := newAPIHostRespFlow(client, 429)
	// The request was backed by poolY's member y1 (the SECOND matching
	// pool). buildPooledMemberPairs would have Tag'd this at injection time.
	addon.flowInjected.Tag(f.Id, "y1")

	pool, member, _, _, ok := addon.poolForResponse(f)
	if !ok {
		t.Fatal("poolForResponse: a genuinely pooled API request must be attributed; got ok=false")
	}
	if pool != "poolY" || member != "y1" {
		t.Fatalf("got pool=%q member=%q, want poolY/y1 "+
			"(first pool must not consume the tag / mis-cool itself)", pool, member)
	}

	var got FailoverEvent
	gotCalled := make(chan struct{}, 1)
	addon.SetOnFailover(func(ev FailoverEvent) {
		got = ev
		gotCalled <- struct{}{}
	})

	f2 := newAPIHostRespFlow(client, 429)
	addon.flowInjected.Tag(f2.Id, "y1")
	addon.Response(f2)

	// poolY's y1 cooled -> poolY rolls to y2. poolX must be UNTOUCHED.
	if active, _ := pr.ResolveActive("poolY"); active != "y2" {
		t.Fatalf("post active poolY = %q, want y2 (y1 must have been cooled)", active)
	}
	if active, _ := pr.ResolveActive("poolX"); active != "x1" {
		t.Fatalf("post active poolX = %q, want x1 (poolX must NOT be cooled — "+
			"it was not used by this request)", active)
	}
	if got.Pool != "poolY" || got.From != "y1" {
		t.Fatalf("FailoverEvent = %+v, want pool=poolY from=y1", got)
	}
}

// TestAPIHostFailover_SinglePoolValidTag_NoRegression is round-12 case (c):
// the legit happy path must still work. A genuine single-pool API 429 whose
// flow tag proves it used poolX still fails over the correct member of poolX.
func TestAPIHostFailover_SinglePoolValidTag_NoRegression(t *testing.T) {
	addon, prPtr := setupTwoPoolAddonSameAPIHost(t)
	client := setupAddonConn(addon, "api.example.com:443")
	pr := prPtr.Load()

	if got, _ := pr.ResolveActive("poolX"); got != "x1" {
		t.Fatalf("pre active poolX = %q, want x1", got)
	}

	f := newAPIHostRespFlow(client, 429)
	addon.flowInjected.Tag(f.Id, "x1")

	pool, member, _, _, ok := addon.poolForResponse(f)
	if !ok {
		t.Fatal("poolForResponse: genuine pooled API 429 must be attributed; got ok=false")
	}
	if pool != "poolX" || member != "x1" {
		t.Fatalf("got pool=%q member=%q, want poolX/x1", pool, member)
	}

	var got FailoverEvent
	gotCalled := make(chan struct{}, 1)
	addon.SetOnFailover(func(ev FailoverEvent) {
		got = ev
		gotCalled <- struct{}{}
	})

	f2 := newAPIHostRespFlow(client, 429)
	addon.flowInjected.Tag(f2.Id, "x1")
	addon.Response(f2)

	if active, _ := pr.ResolveActive("poolX"); active != "x2" {
		t.Fatalf("post active poolX = %q, want x2 (x1 must be cooled by the 429)", active)
	}
	if active, _ := pr.ResolveActive("poolY"); active != "y1" {
		t.Fatalf("post active poolY = %q, want y1 (poolY must not be cooled)", active)
	}
	if got.Pool != "poolX" || got.From != "x1" || got.To != "x2" || got.Reason != "429" {
		t.Fatalf("FailoverEvent = %+v, want pool=poolX from=x1 to=x2 reason=429", got)
	}
	if got.Class != failoverRateLimited {
		t.Fatalf("class = %v, want rate-limited", got.Class)
	}
}
