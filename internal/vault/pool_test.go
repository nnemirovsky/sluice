package vault

import (
	"sync"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/store"
)

func mkPool(name string, members ...string) store.Pool {
	p := store.Pool{Name: name, Strategy: store.PoolStrategyFailover}
	for i, m := range members {
		p.Members = append(p.Members, store.PoolMember{Credential: m, Position: i})
	}
	return p
}

func TestResolveActivePassthroughForNonPool(t *testing.T) {
	pr := NewPoolResolver(nil, nil)
	got, ok := pr.ResolveActive("plain_cred")
	if !ok || got != "plain_cred" {
		t.Errorf("ResolveActive(plain) = %q,%v; want plain_cred,true", got, ok)
	}
	if pr.IsPool("plain_cred") {
		t.Error("IsPool(plain_cred) = true, want false")
	}
}

func TestResolveActivePicksFirstHealthy(t *testing.T) {
	pr := NewPoolResolver([]store.Pool{mkPool("pool", "a", "b")}, nil)
	if !pr.IsPool("pool") {
		t.Fatal("IsPool(pool) = false")
	}
	got, ok := pr.ResolveActive("pool")
	if !ok || got != "a" {
		t.Errorf("ResolveActive = %q,%v; want a,true", got, ok)
	}
}

func TestResolveActiveSkipsCooledDownMember(t *testing.T) {
	future := time.Now().Add(60 * time.Second)
	health := []store.CredentialHealth{
		{Credential: "a", Status: "cooldown", CooldownUntil: future, LastFailureReason: "429"},
	}
	pr := NewPoolResolver([]store.Pool{mkPool("pool", "a", "b")}, health)
	got, ok := pr.ResolveActive("pool")
	if !ok || got != "b" {
		t.Errorf("ResolveActive = %q,%v; want b,true (a is cooling down)", got, ok)
	}
}

func TestResolveActiveExpiredCooldownIsEligible(t *testing.T) {
	past := time.Now().Add(-1 * time.Second)
	health := []store.CredentialHealth{
		{Credential: "a", Status: "cooldown", CooldownUntil: past},
	}
	pr := NewPoolResolver([]store.Pool{mkPool("pool", "a", "b")}, health)
	got, _ := pr.ResolveActive("pool")
	if got != "a" {
		t.Errorf("ResolveActive = %q; want a (cooldown expired -> eligible)", got)
	}
}

func TestResolveActiveAllDownDegradesToSoonest(t *testing.T) {
	now := time.Now()
	health := []store.CredentialHealth{
		{Credential: "a", Status: "cooldown", CooldownUntil: now.Add(300 * time.Second)},
		{Credential: "b", Status: "cooldown", CooldownUntil: now.Add(30 * time.Second)},
	}
	pr := NewPoolResolver([]store.Pool{mkPool("pool", "a", "b")}, health)
	got, ok := pr.ResolveActive("pool")
	if !ok || got != "b" {
		t.Errorf("ResolveActive (all down) = %q,%v; want b,true (soonest recovery)", got, ok)
	}
}

func TestResolveActiveEmptyPool(t *testing.T) {
	pr := NewPoolResolver([]store.Pool{mkPool("empty")}, nil)
	if _, ok := pr.ResolveActive("empty"); ok {
		t.Error("ResolveActive(empty pool) ok=true, want false")
	}
}

func TestMarkCooldownSynchronousFlip(t *testing.T) {
	pr := NewPoolResolver([]store.Pool{mkPool("pool", "a", "b")}, nil)
	if got, _ := pr.ResolveActive("pool"); got != "a" {
		t.Fatalf("initial active = %q, want a", got)
	}
	// Synchronous in-memory failover (Phase 2 path): the very next
	// resolution must already see b.
	pr.MarkCooldown("a", time.Now().Add(60*time.Second), "429")
	if got, _ := pr.ResolveActive("pool"); got != "b" {
		t.Errorf("after MarkCooldown(a) active = %q, want b", got)
	}
	if _, cooling := pr.CooldownUntil("a"); !cooling {
		t.Error("CooldownUntil(a) cooling=false, want true")
	}
	// Clearing (zero/past) recovers the member.
	pr.MarkCooldown("a", time.Time{}, "")
	if got, _ := pr.ResolveActive("pool"); got != "a" {
		t.Errorf("after clear active = %q, want a", got)
	}
}

func TestMarkCooldownMonotonicExtend(t *testing.T) {
	pr := NewPoolResolver([]store.Pool{mkPool("pool", "a", "b")}, nil)

	// Park "a" for an auth failure (300s).
	authUntil := time.Now().Add(AuthFailCooldown)
	pr.MarkCooldown("a", authUntil, "401")
	got, ok := pr.CooldownUntil("a")
	if !ok || !got.Equal(authUntil) {
		t.Fatalf("after auth-fail cooldown = %v,%v; want %v,true", got, ok, authUntil)
	}

	// A subsequent shorter rate-limit cooldown (60s) must NOT shorten it:
	// the credential is known-bad for 300s and must not be eligible early.
	rlUntil := time.Now().Add(RateLimitCooldown)
	pr.MarkCooldown("a", rlUntil, "429")
	got, ok = pr.CooldownUntil("a")
	if !ok || !got.Equal(authUntil) {
		t.Errorf("after shorter rate-limit cooldown = %v,%v; want %v,true (NOT shortened to %v)",
			got, ok, authUntil, rlUntil)
	}

	// A strictly LATER cooldown does extend.
	laterUntil := authUntil.Add(120 * time.Second)
	pr.MarkCooldown("a", laterUntil, "429-again")
	got, ok = pr.CooldownUntil("a")
	if !ok || !got.Equal(laterUntil) {
		t.Errorf("after later cooldown = %v,%v; want %v,true (extended)", got, ok, laterUntil)
	}

	// Explicit clear (zero) still recovers despite an active longer cooldown.
	pr.MarkCooldown("a", time.Time{}, "")
	if _, cooling := pr.CooldownUntil("a"); cooling {
		t.Error("after explicit clear CooldownUntil(a) cooling=true, want false (recovery path must not be blocked by monotonicity)")
	}
	if active, _ := pr.ResolveActive("pool"); active != "a" {
		t.Errorf("after clear active = %q, want a", active)
	}

	// Expired existing cooldown must lose to a fresh future one (lazy
	// expiry preserved): set a past cooldown, then a normal future one.
	pr.MarkCooldown("b", time.Now().Add(-time.Hour), "stale") // zero/past => clear, b stays healthy
	freshUntil := time.Now().Add(RateLimitCooldown)
	pr.MarkCooldown("b", freshUntil, "429")
	got, ok = pr.CooldownUntil("b")
	if !ok || !got.Equal(freshUntil) {
		t.Errorf("fresh cooldown after stale = %v,%v; want %v,true", got, ok, freshUntil)
	}
}

func TestPoolForMemberAndMembers(t *testing.T) {
	pr := NewPoolResolver([]store.Pool{mkPool("pool", "a", "b")}, nil)
	if p := pr.PoolForMember("b"); p != "pool" {
		t.Errorf("PoolForMember(b) = %q, want pool", p)
	}
	if p := pr.PoolForMember("nope"); p != "" {
		t.Errorf("PoolForMember(nope) = %q, want empty", p)
	}
	m := pr.Members("pool")
	if len(m) != 2 || m[0] != "a" || m[1] != "b" {
		t.Errorf("Members(pool) = %v, want [a b]", m)
	}
}

// TestMergeLiveCooldownsSurvivesUnrelatedReload is the CRITICAL-1 regression:
// an unrelated reload rebuilds the resolver from store rows alone (no cooldown
// row, because the durable SetCredentialHealth write is detached/best-effort
// and may not have landed). Without MergeLiveCooldowns the freshly built
// resolver would resurrect member "a" — defeating the I1 synchronous-failover
// guarantee. With the merge, "a" stays cooled and ResolveActive picks "b".
func TestMergeLiveCooldownsSurvivesUnrelatedReload(t *testing.T) {
	// Live resolver: member "a" failed over and was cooled down in memory.
	prev := NewPoolResolver([]store.Pool{mkPool("pool", "a", "b")}, nil)
	prev.MarkCooldown("a", time.Now().Add(60*time.Second), "429")
	if got, _ := prev.ResolveActive("pool"); got != "b" {
		t.Fatalf("precondition: live resolver active = %q; want b", got)
	}

	// Unrelated reload: store has NO credential_health row (async write not
	// yet persisted), so NewPoolResolver seeds an empty health map.
	fresh := NewPoolResolver([]store.Pool{mkPool("pool", "a", "b")}, nil)
	if got, _ := fresh.ResolveActive("pool"); got != "a" {
		t.Fatalf("sanity: fresh resolver without merge resurrects to %q; want a (proves the bug exists without the fix)", got)
	}

	// The fix: StorePool calls MergeLiveCooldowns before the atomic swap.
	fresh.MergeLiveCooldowns(prev)

	if got, ok := fresh.ResolveActive("pool"); !ok || got != "b" {
		t.Errorf("after merge ResolveActive(pool) = %q,%v; want b,true (cooled member must NOT be resurrected by an unrelated reload)", got, ok)
	}
	if until, cooling := fresh.CooldownUntil("a"); !cooling || until.IsZero() {
		t.Errorf("after merge member a should still be cooling down; got until=%v cooling=%v", until, cooling)
	}
}

// TestMergeLiveCooldownsIsMonotonic: a store-seeded cooldown that is later
// than the in-memory one is kept (never shortened), and an expired in-memory
// cooldown is not carried.
func TestMergeLiveCooldownsIsMonotonic(t *testing.T) {
	storeLater := time.Now().Add(300 * time.Second)
	fresh := NewPoolResolver([]store.Pool{mkPool("pool", "a", "b")},
		[]store.CredentialHealth{{Credential: "a", Status: "cooldown", CooldownUntil: storeLater, LastFailureReason: "401"}})

	prev := NewPoolResolver([]store.Pool{mkPool("pool", "a", "b")}, nil)
	prev.MarkCooldown("a", time.Now().Add(10*time.Second), "429")   // earlier than store
	prev.MarkCooldown("b", time.Now().Add(-1*time.Second), "stale") // already expired

	fresh.MergeLiveCooldowns(prev)

	until, cooling := fresh.CooldownUntil("a")
	if !cooling || until.Before(storeLater.Add(-time.Second)) {
		t.Errorf("merge must not shorten a longer store cooldown: got %v, want ~%v", until, storeLater)
	}
	if _, cooling := fresh.CooldownUntil("b"); cooling {
		t.Error("expired in-memory cooldown for b must not be carried forward")
	}
}

// TestMergeLiveCooldownsDropsRemovedMember: a cooldown for a credential no
// longer in any pool (membership change) is not carried.
func TestMergeLiveCooldownsDropsRemovedMember(t *testing.T) {
	prev := NewPoolResolver([]store.Pool{mkPool("pool", "a", "b")}, nil)
	prev.MarkCooldown("b", time.Now().Add(60*time.Second), "429")

	// New membership: "b" was removed from the pool.
	fresh := NewPoolResolver([]store.Pool{mkPool("pool", "a")}, nil)
	fresh.MergeLiveCooldowns(prev)

	if _, cooling := fresh.CooldownUntil("b"); cooling {
		t.Error("cooldown for a removed member must be dropped, not carried")
	}
}

func TestNilPoolResolverSafe(t *testing.T) {
	var pr *PoolResolver
	if got, ok := pr.ResolveActive("x"); !ok || got != "x" {
		t.Errorf("nil ResolveActive = %q,%v; want x,true", got, ok)
	}
	if pr.IsPool("x") {
		t.Error("nil IsPool = true")
	}
	pr.MarkCooldown("x", time.Now(), "") // must not panic
}

// TestSharedHealthSurvivesResolverRebuild is the CRITICAL-1 regression:
// when the long-lived path rebuilds the resolver against the SAME shared
// PoolHealth (every SIGHUP / data_version reload), a cooldown recorded on
// the OLD generation must be visible to ResolveActive on the NEW
// generation — with zero dependency on the detached durable store write.
func TestSharedHealthSurvivesResolverRebuild(t *testing.T) {
	shared := NewPoolHealth()
	gen1 := NewPoolResolverShared([]store.Pool{mkPool("pool", "a", "b")}, nil, shared)

	// Failover cools "a" on gen1. The store write has NOT landed (best
	// effort/detached), so a rebuild sees no health rows.
	gen1.MarkCooldown("a", time.Now().Add(120*time.Second), "429")

	// Reload rebuilds a fresh generation from store rows alone (empty),
	// against the SAME shared health.
	gen2 := NewPoolResolverShared([]store.Pool{mkPool("pool", "a", "b")}, nil, shared)

	if got, _ := gen2.ResolveActive("pool"); got != "b" {
		t.Fatalf("gen2 active = %q, want b (cooldown on gen1 must survive the rebuild — CRITICAL-1)", got)
	}
	// And a MarkCooldown that lands on the OLD generation AFTER gen2 exists
	// must still be observed by gen2 (no lost update across the swap).
	gen1.MarkCooldown("b", time.Now().Add(120*time.Second), "401")
	if _, cooling := gen2.CooldownUntil("b"); !cooling {
		t.Fatal("MarkCooldown on old generation not visible on new generation — CRITICAL-1 lost-update race")
	}
}

// TestFinding2Round9_SharedHealthPrunesNonMembers is the Copilot round-9
// Finding 2 regression. On the shared-PoolHealth path (the normal server
// path, prev.health == pr.health) MergeLiveCooldowns early-returned BEFORE
// pruning cooldowns for credentials no longer a member of ANY pool. A cooled
// member removed from a pool stayed in the process-wide shared health map
// and, if re-added before its old TTL expired, was skipped again by
// ResolveActive even though the store snapshot no longer recorded the
// cooldown. The fix prunes non-member entries on the shared path too, while
// never shortening a still-valid cooldown for a current member.
func TestFinding2Round9_SharedHealthPrunesNonMembers(t *testing.T) {
	shared := NewPoolHealth()

	// gen1: a single resolver generation holds ALL pools (this is how the
	// server builds it — one PoolResolver per process, every pool inside
	// it). "pool" has members "a" and "b"; "other" has "c". "a" (still a
	// member next gen) and "b" (about to be removed) both get cooled.
	gen1 := NewPoolResolverShared([]store.Pool{
		mkPool("pool", "a", "b"),
		mkPool("other", "c"),
	}, nil, shared)
	aUntil := time.Now().Add(300 * time.Second)
	bUntil := time.Now().Add(300 * time.Second)
	gen1.MarkCooldown("a", aUntil, "429")
	gen1.MarkCooldown("b", bUntil, "401")

	// gen2: "b" removed from "pool" (membership change). gen2's memberOf is
	// the COMPLETE member set across all pools for the new generation, so a
	// credential absent from it is no longer in ANY pool. Same shared
	// health instance — this is the normal server path
	// (prev.health == pr.health).
	gen2 := NewPoolResolverShared([]store.Pool{
		mkPool("pool", "a"),
		mkPool("other", "c"),
	}, nil, shared)

	// Without the fix MergeLiveCooldowns early-returns on the shared path
	// and "b"'s stale cooldown lingers in the process-wide shared map.
	gen2.MergeLiveCooldowns(gen1)

	// "b" is no longer a member of any pool: its stale cooldown MUST be
	// pruned so a re-add before the old TTL does not inherit it.
	if until, cooling := gen2.CooldownUntil("b"); cooling {
		t.Errorf("Finding 2 r9: stale cooldown for removed non-member b must be pruned; got until=%v cooling=%v", until, cooling)
	}

	// "a" is still a member of "pool": its cooldown must survive the merge
	// and must NOT be shortened (monotonic-cooldown / CRITICAL-1 durability
	// for live members).
	if until, cooling := gen2.CooldownUntil("a"); !cooling {
		t.Fatalf("Finding 2 r9: still-member a lost its cooldown across the shared-path merge")
	} else if until.Before(aUntil.Add(-time.Second)) {
		t.Errorf("Finding 2 r9: still-member a's cooldown was shortened: got %v want ~%v", until, aUntil)
	}

	// Re-add "b" to a pool (next generation) BEFORE its old TTL would have
	// expired. Because the stale cooldown was pruned, "b" must now be
	// healthy and ResolveActive must pick it, not skip it as still-cooling.
	gen3 := NewPoolResolverShared([]store.Pool{
		mkPool("pool", "a"),
		mkPool("other", "c"),
		mkPool("p2", "b", "d"),
	}, nil, shared)
	gen3.MergeLiveCooldowns(gen2)
	if _, cooling := gen3.CooldownUntil("b"); cooling {
		t.Errorf("Finding 2 r9: re-added b inherited a stale cooldown that should have been pruned")
	}
	if got, ok := gen3.ResolveActive("p2"); !ok || got != "b" {
		t.Errorf("Finding 2 r9: re-added b should be the active member of p2; got %q,%v want b,true", got, ok)
	}
	// "a" is still in gen3's "pool"; its (unshortened) cooldown must still
	// be intact after the second merge as well.
	if until, cooling := gen3.CooldownUntil("a"); !cooling {
		t.Errorf("Finding 2 r9: still-member a lost its cooldown across the second shared-path merge")
	} else if until.Before(aUntil.Add(-time.Second)) {
		t.Errorf("Finding 2 r9: still-member a's cooldown was shortened by the second merge: got %v want ~%v", until, aUntil)
	}
}

// TestSharedHealthConcurrentMarkCooldownVsRebuild stresses the CRITICAL-1
// race: MarkCooldown on rotating "old" generations racing continuous
// resolver rebuilds (the StorePool/reload swap) against one shared health.
// Run with -race. The invariant: a cooldown that was set is NEVER lost —
// every credential we cooled is still cooling when observed through the
// latest generation.
func TestSharedHealthConcurrentMarkCooldownVsRebuild(t *testing.T) {
	shared := NewPoolHealth()
	pool := mkPool("pool", "m0", "m1", "m2", "m3")

	var cur struct {
		sync.RWMutex
		pr *PoolResolver
	}
	cur.pr = NewPoolResolverShared([]store.Pool{pool}, nil, shared)

	const iters = 400
	far := 10 * time.Minute
	done := make(chan struct{})

	// Rebuilder: continuously swaps in a fresh generation bound to the
	// SAME shared health (models StorePool's reload swap).
	go func() {
		for i := 0; i < iters; i++ {
			fresh := NewPoolResolverShared([]store.Pool{pool}, nil, shared)
			cur.Lock()
			cur.pr = fresh
			cur.Unlock()
		}
		close(done)
	}()

	// Marker: cools members on whatever generation is current at the time
	// (often an about-to-be-replaced one). Every cooldown uses a far-future
	// expiry so it must still be live at the assertion.
	members := pool.Members
	for i := 0; i < iters; i++ {
		cur.RLock()
		g := cur.pr
		cur.RUnlock()
		m := members[i%len(members)].Credential
		g.MarkCooldown(m, time.Now().Add(far), "429")
	}
	<-done

	// Observe through the latest generation: every member we cooled must
	// still be cooling. None lost across any swap.
	cur.RLock()
	latest := cur.pr
	cur.RUnlock()
	for _, m := range members {
		if _, cooling := latest.CooldownUntil(m.Credential); !cooling {
			t.Fatalf("cooldown for %q was lost across resolver swaps (CRITICAL-1 race)", m.Credential)
		}
	}
}
