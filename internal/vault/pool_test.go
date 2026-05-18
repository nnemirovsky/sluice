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

// mkPoolEpoch builds a pool whose members all carry the given membership
// epoch, mirroring what the store stamps on credential_pool_members rows.
func mkPoolEpoch(name string, epoch int64, members ...string) store.Pool {
	p := store.Pool{Name: name, Strategy: store.PoolStrategyFailover}
	for i, m := range members {
		p.Members = append(p.Members, store.PoolMember{Credential: m, Position: i, Epoch: epoch})
	}
	return p
}

// TestMarkCooldownScopedRejectsReAddedSuccessor is the Cluster A #1
// regression. The round-15 gate only checked the credential NAME was in the
// current generation's member set. Sequence: pool P with member c (epoch e1)
// takes a 429 on an in-flight request; c/P are removed and c is re-created
// into a NEW pool Q (epoch e2 > e1); the OLD in-flight response's
// MarkCooldown for c now lands. The name-only gate sees c present (it is a
// member of Q now) and WRONGLY parks the re-created successor with the OLD
// response's cooldown.
//
// Deterministic interleave (no sleeps): operations are explicitly ordered so
// the stale gen1 MarkCooldownScoped(c, P, e1) runs AFTER gen2 published Q's
// member set (c at epoch e2). Fail-before: c cooling in gen2. Pass-after:
// the (pool, epoch) identity no longer matches so the write no-ops, and the
// genuinely-live (c, Q, e2) cooldown still applies.
func TestMarkCooldownScopedRejectsReAddedSuccessor(t *testing.T) {
	shared := NewPoolHealth()

	const e1 = int64(1)
	const e2 = int64(2)

	// gen1 (OLD): pool P with member c at epoch e1. An in-flight response
	// resolved through gen1 and holds the gen1 resolver.
	gen1 := NewPoolResolverShared([]store.Pool{mkPoolEpoch("P", e1, "c")}, nil, shared)

	// gen2 (NEW): P removed; c re-created into pool Q at a strictly greater
	// epoch e2. The rebuild publishes gen2's identity map.
	gen2 := NewPoolResolverShared([]store.Pool{mkPoolEpoch("Q", e2, "c")}, nil, shared)
	gen2.MergeLiveCooldowns(gen1)

	// INTERLEAVE: the stale gen1 response records a failover cooldown for c
	// using the identity it captured (P, e1) — AFTER gen2 published (c -> Q,
	// e2). The identity no longer matches, so the write must be gated out.
	gen1.MarkCooldownScoped("c", "P", e1, time.Now().Add(300*time.Second), "failover:429")

	if until, cooling := gen2.CooldownUntil("c"); cooling {
		t.Fatalf("Cluster A #1: stale (P,e1) MarkCooldownScoped parked the re-added successor c (Q,e2): until=%v", until)
	}
	if got, ok := gen2.ResolveActive("Q"); !ok || got != "c" {
		t.Fatalf("Cluster A #1: re-added c must be active in Q; got %q,%v want c,true", got, ok)
	}

	// CRITICAL-1 preserved: the genuinely-live member failing over against
	// its CURRENT identity (Q, e2) still records the cooldown.
	gen2.MarkCooldownScoped("c", "Q", e2, time.Now().Add(300*time.Second), "failover:429 live")
	if _, cooling := gen2.CooldownUntil("c"); !cooling {
		t.Fatal("Cluster A #1 regressed CRITICAL-1: live (Q,e2) failover cooldown was dropped")
	}
}

// TestMarkCooldownLegacyUnscopedStillGated pins that the legacy
// identity-UNSCOPED MarkCooldown keeps the round-15 name-only
// write-after-prune behavior (single-generation CLI/test callers are not
// regressed): a non-member write is still gated, a member write still
// applies.
func TestMarkCooldownLegacyUnscopedStillGated(t *testing.T) {
	shared := NewPoolHealth()
	gen1 := NewPoolResolverShared([]store.Pool{mkPool("pool", "a", "x")}, nil, shared)
	gen2 := NewPoolResolverShared([]store.Pool{mkPool("pool", "a")}, nil, shared)
	gen2.MergeLiveCooldowns(gen1)

	// Non-member "x": still gated by the name-only set (round-15 preserved).
	gen1.MarkCooldown("x", time.Now().Add(300*time.Second), "failover:401")
	if _, cooling := gen2.CooldownUntil("x"); cooling {
		t.Fatal("legacy MarkCooldown lost the round-15 write-after-prune gate")
	}
	// Member "a": still applies.
	gen2.MarkCooldown("a", time.Now().Add(300*time.Second), "429")
	if _, cooling := gen2.CooldownUntil("a"); !cooling {
		t.Fatal("legacy MarkCooldown wrongly gated a live member")
	}
}

// TestResolveActiveStickyHold: once a member is selected it keeps being
// returned across many ResolveActive calls while it is healthy, even though a
// lower-position member is also healthy. (Fail-before: old position-priority
// always returned position-0 "a".)
func TestResolveActiveStickyHold(t *testing.T) {
	pr := NewPoolResolver([]store.Pool{mkPool("pool", "a", "b")}, nil)
	// First resolution settles on "a" (position 0, both healthy).
	if got, _ := pr.ResolveActive("pool"); got != "a" {
		t.Fatalf("initial = %q, want a", got)
	}
	// "a" cools -> switch to "b".
	pr.MarkCooldown("a", time.Now().Add(60*time.Second), "429")
	if got, _ := pr.ResolveActive("pool"); got != "b" {
		t.Fatalf("after cooling a = %q, want b", got)
	}
	// "a" recovers, but "b" is healthy: sticky hold across many calls.
	pr.MarkCooldown("a", time.Time{}, "")
	for i := 0; i < 25; i++ {
		if got, _ := pr.ResolveActive("pool"); got != "b" {
			t.Fatalf("call %d: sticky hold broke, got %q want b (lower-position a recovered must NOT snap back)", i, got)
		}
	}
}

// TestResolveActiveFlapRegression is the core flap fix. Sequence mirrors the
// live knuth bug: A (position 0) is upstream-exhausted. Fail A (cooldown) ->
// ResolveActive returns B. A's cooldown EXPIRES -> ResolveActive STILL returns
// B (no snap-back, so A is not re-probed every 60s and no spurious failover).
// Then B itself cools -> advance to the next member WITH WRAP (back to A,
// which has recovered). Fail-before (position-priority): step 3 would return
// A, the flap.
func TestResolveActiveFlapRegression(t *testing.T) {
	pr := NewPoolResolver([]store.Pool{mkPool("pool", "A", "B", "C")}, nil)
	if got, _ := pr.ResolveActive("pool"); got != "A" {
		t.Fatalf("initial = %q, want A", got)
	}
	// 1. A exhausts -> failover to B.
	pr.MarkCooldown("A", time.Now().Add(60*time.Second), "429")
	if got, _ := pr.ResolveActive("pool"); got != "B" {
		t.Fatalf("after cooling A = %q, want B", got)
	}
	// 2. A's short cooldown lapses (still upstream-exhausted in reality).
	pr.MarkCooldown("A", time.Time{}, "")
	if got, _ := pr.ResolveActive("pool"); got != "B" {
		t.Fatalf("FLAP: after A cooldown lapse = %q, want B (must NOT snap back to A)", got)
	}
	// 3. B itself now exhausts -> advance forward with wrap. C is next.
	pr.MarkCooldown("B", time.Now().Add(60*time.Second), "429")
	if got, _ := pr.ResolveActive("pool"); got != "C" {
		t.Fatalf("after cooling B = %q, want C (advance forward from B)", got)
	}
	// 4. C exhausts too -> wrap forward past end -> A (recovered at step 2).
	pr.MarkCooldown("C", time.Now().Add(60*time.Second), "429")
	if got, _ := pr.ResolveActive("pool"); got != "A" {
		t.Fatalf("after cooling C = %q, want A (wrap forward, A is healthy again)", got)
	}
}

// TestResolveActiveStickyRotateAdvancesAndStays: `sluice pool rotate` parks
// the active member with ManualRotateReason; the next ResolveActive must
// advance to the next member and STAY there (no snap-back) even after the
// parked member's park lapses.
func TestResolveActiveStickyRotateAdvancesAndStays(t *testing.T) {
	pr := NewPoolResolver([]store.Pool{mkPool("pool", "a", "b")}, nil)
	if got, _ := pr.ResolveActive("pool"); got != "a" {
		t.Fatalf("initial = %q, want a", got)
	}
	// Operator rotate: park the active "a".
	pr.MarkCooldown("a", time.Now().Add(ManualRotateCooldownForTest()), ManualRotateReason)
	if got, _ := pr.ResolveActive("pool"); got != "b" {
		t.Fatalf("after rotate = %q, want b (advance)", got)
	}
	// "a"'s park lapses: must NOT snap back, "b" stays active.
	pr.MarkCooldown("a", time.Time{}, "")
	for i := 0; i < 10; i++ {
		if got, _ := pr.ResolveActive("pool"); got != "b" {
			t.Fatalf("call %d after park lapse = %q, want b (rotate advances AND stays)", i, got)
		}
	}
}

// ManualRotateCooldownForTest is a small helper duration for the rotate test.
func ManualRotateCooldownForTest() time.Duration { return 300 * time.Second }

// TestResolveActiveStickyPointerSurvivesRebuildAndSwap extends the CRITICAL-1
// shared-health regression to the sticky pointer: a member switched-to on an
// OLD generation must remain the active member on a NEW generation built
// against the SAME shared PoolHealth, and a stale generation must not clobber
// it back to position 0.
func TestResolveActiveStickyPointerSurvivesRebuildAndSwap(t *testing.T) {
	shared := NewPoolHealth()
	gen1 := NewPoolResolverShared([]store.Pool{mkPool("pool", "a", "b")}, nil, shared)
	if got, _ := gen1.ResolveActive("pool"); got != "a" {
		t.Fatalf("gen1 initial = %q, want a", got)
	}
	// Failover on gen1 switches the sticky pointer to "b".
	gen1.MarkCooldown("a", time.Now().Add(120*time.Second), "429")
	if got, _ := gen1.ResolveActive("pool"); got != "b" {
		t.Fatalf("gen1 after cooling a = %q, want b", got)
	}
	// "a" recovers (durable write may not have landed).
	gen1.MarkCooldown("a", time.Time{}, "")

	// Reload: fresh generation, SAME shared health, store has no rows.
	gen2 := NewPoolResolverShared([]store.Pool{mkPool("pool", "a", "b")}, nil, shared)
	gen2.MergeLiveCooldowns(gen1)
	// Sticky pointer survived the swap: gen2 keeps serving "b", not "a".
	if got, _ := gen2.ResolveActive("pool"); got != "b" {
		t.Fatalf("gen2 active = %q, want b (sticky pointer must survive resolver swap, no snap-back)", got)
	}

	// A stale OLD generation's ResolveActive must not clobber the pointer to
	// a member of the wrong/old member list. gen1 still has {a,b}; calling
	// it again only ever writes a member of THIS gen's list. Even so, the
	// authoritative current generation (gen2) must keep "b".
	gen1.ResolveActive("pool")
	if got, _ := gen2.ResolveActive("pool"); got != "b" {
		t.Fatalf("after stale gen1 ResolveActive, gen2 = %q, want b (stale generation must not clobber sticky pointer)", got)
	}

	// A pool dropped entirely prunes its sticky pointer (mirrors cooldown
	// prune) so a re-add does not inherit a stale active member.
	gen3 := NewPoolResolverShared([]store.Pool{mkPool("other", "x")}, nil, shared)
	gen3.MergeLiveCooldowns(gen2)
	gen4 := NewPoolResolverShared([]store.Pool{mkPool("pool", "a", "b"), mkPool("other", "x")}, nil, shared)
	gen4.MergeLiveCooldowns(gen3)
	if got, _ := gen4.ResolveActive("pool"); got != "a" {
		t.Fatalf("re-added pool active = %q, want a (dropped pool's sticky pointer must be pruned)", got)
	}
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

// TestResolveActiveAllDownPrefersManualRotateOverFailure is the
// pool-stranding regression. `sluice pool rotate` parks the previously
// active member with reason ManualRotateReason — that member is healthy,
// just operator-deprioritized. If the rotated-to member then fails (rate
// limit / auth), EVERY member is cooling. The old degrade picked the member
// with the soonest cooldownUntil, which is the genuinely-FAILED one (a 429
// cooldown is 60s; a manual rotate park is 300s), so a rotate onto an
// exhausted account self-looped on the exhausted account and the agent hard
// errored. Fail-before: soonest-by-time -> "a" (the failed member).
// Pass-after: a manual-rotate-parked-but-healthy member is preferred -> "b".
func TestResolveActiveAllDownPrefersManualRotateOverFailure(t *testing.T) {
	now := time.Now()
	health := []store.CredentialHealth{
		// Genuinely failed, recovers SOON (would win the old soonest rule).
		{Credential: "a", Status: "cooldown", CooldownUntil: now.Add(30 * time.Second), LastFailureReason: "429"},
		// Operator-parked by `pool rotate`, recovers LATER, but healthy.
		{Credential: "b", Status: "cooldown", CooldownUntil: now.Add(300 * time.Second), LastFailureReason: ManualRotateReason},
	}
	pr := NewPoolResolver([]store.Pool{mkPool("pool", "a", "b")}, health)
	got, ok := pr.ResolveActive("pool")
	if !ok || got != "b" {
		t.Errorf("ResolveActive (all down) = %q,%v; want b,true (operator-parked-but-healthy preferred over genuinely-failed soonest)", got, ok)
	}
}

// TestResolveActiveAllDownNoManualRotateStillSoonest guards that the
// preference is ONLY for manual-rotate parks: when every member is cooling
// for a genuine failure, behavior is unchanged (soonest recovery wins).
func TestResolveActiveAllDownNoManualRotateStillSoonest(t *testing.T) {
	now := time.Now()
	health := []store.CredentialHealth{
		{Credential: "a", Status: "cooldown", CooldownUntil: now.Add(300 * time.Second), LastFailureReason: "401"},
		{Credential: "b", Status: "cooldown", CooldownUntil: now.Add(30 * time.Second), LastFailureReason: "429"},
	}
	pr := NewPoolResolver([]store.Pool{mkPool("pool", "a", "b")}, health)
	got, ok := pr.ResolveActive("pool")
	if !ok || got != "b" {
		t.Errorf("ResolveActive (all down, no manual rotate) = %q,%v; want b,true (soonest unchanged)", got, ok)
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
	// Clearing (zero/past) recovers the member, but selection is STICKY:
	// "a" recovering does NOT snap the active member back to it. "b" was
	// switched to and is healthy, so it keeps being served (flap fix).
	pr.MarkCooldown("a", time.Time{}, "")
	if got, _ := pr.ResolveActive("pool"); got != "b" {
		t.Errorf("after clear active = %q, want b (sticky: recovered a must NOT snap back)", got)
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

// TestFinding3Round15_WriteAfterPruneGatedByMemberSet is the round-15
// Finding 3 regression. A response handled by an OLD resolver generation can
// call MarkCooldown AFTER a NEW generation already pruned non-members and
// published its member set (StorePool -> MergeLiveCooldowns shared path /
// NewPoolResolverShared). If that credential was removed from EVERY pool in
// the new generation, the OLD unguarded MarkCooldown re-inserted a stale
// in-memory cooldown that a later same-named re-add inherited before its TTL.
//
// The fix gates cooldown WRITES on the CURRENT generation's authoritative
// member set, stored on the shared PoolHealth and checked under the SAME
// mutex as the write, so the prune (member-set replace) and a concurrent
// stale MarkCooldown cannot interleave to leave a non-member entry.
//
// Deterministic interleave (no sleeps): we explicitly order the operations
// so the old-generation MarkCooldown(credX) executes AFTER the new
// generation pruned credX. Fail-before: credX would be cooling. Pass-after:
// credX has no cooldown, and a re-add before its TTL is healthy/active.
func TestFinding3Round15_WriteAfterPruneGatedByMemberSet(t *testing.T) {
	shared := NewPoolHealth()

	// gen1 (OLD): pool {a, x}. A response that resolved through gen1 is
	// still in flight and holds the gen1 *PoolResolver.
	gen1 := NewPoolResolverShared([]store.Pool{mkPool("pool", "a", "x")}, nil, shared)

	// gen2 (NEW): "x" was removed from the pool entirely (membership change
	// -> resolver rebuild). StorePool's MergeLiveCooldowns shared-path prune
	// runs and publishes gen2's member set (which no longer contains "x").
	gen2 := NewPoolResolverShared([]store.Pool{mkPool("pool", "a")}, nil, shared)
	gen2.MergeLiveCooldowns(gen1) // prune + publish current member set {a}

	// INTERLEAVE: the stale, still-in-flight gen1 response NOW records a
	// failover cooldown for "x" — AFTER gen2 already pruned it. The write
	// must be gated out by the current member set.
	gen1.MarkCooldown("x", time.Now().Add(300*time.Second), "failover:401")

	if until, cooling := gen2.CooldownUntil("x"); cooling {
		t.Fatalf("Finding 3 r15: write-after-prune resurrected a cooldown for non-member x: until=%v (must be gated by current member set)", until)
	}
	// Also assert through gen1's own view (same shared map): still no entry.
	if _, cooling := gen1.CooldownUntil("x"); cooling {
		t.Errorf("Finding 3 r15: stale gen1 MarkCooldown(x) leaked into the shared map despite x not being a current member")
	}

	// Re-add "x" to a fresh pool BEFORE its (would-be) TTL: it must be
	// healthy and selectable, not skipped as still-cooling.
	gen3 := NewPoolResolverShared([]store.Pool{mkPool("pool", "a"), mkPool("p2", "x", "d")}, nil, shared)
	gen3.MergeLiveCooldowns(gen2)
	if _, cooling := gen3.CooldownUntil("x"); cooling {
		t.Errorf("Finding 3 r15: re-added x inherited a stale cooldown")
	}
	if got, ok := gen3.ResolveActive("p2"); !ok || got != "x" {
		t.Errorf("Finding 3 r15: re-added x should be active in p2; got %q,%v want x,true", got, ok)
	}

	// MUST NOT regress CRITICAL-1: a LIVE member's synchronous cooldown
	// recorded on an old generation across a benign StorePool still
	// persists. "a" is a member in every generation here.
	gen3.MarkCooldown("a", time.Now().Add(300*time.Second), "429")
	gen4 := NewPoolResolverShared([]store.Pool{mkPool("pool", "a"), mkPool("p2", "x", "d")}, nil, shared)
	gen4.MergeLiveCooldowns(gen3)
	if _, cooling := gen4.CooldownUntil("a"); !cooling {
		t.Fatalf("Finding 3 r15 regressed CRITICAL-1: a live member's cooldown was dropped across a benign StorePool")
	}
}

// TestFinding3Round15_ConcurrentStaleMarkVsPruneUnderRace forces the prune
// and the stale-generation MarkCooldown to run concurrently so `go test
// -race` exercises the shared-mutex discipline (member-set replace and
// cooldown write are one critical section). The deterministic post-condition
// holds regardless of who wins the lock: a credential removed from every
// pool in the new generation must never end up with a resurrected cooldown.
func TestFinding3Round15_ConcurrentStaleMarkVsPruneUnderRace(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		shared := NewPoolHealth()
		gen1 := NewPoolResolverShared([]store.Pool{mkPool("pool", "a", "x")}, nil, shared)

		var wg sync.WaitGroup
		wg.Add(2)
		// New generation rebuild + prune (drops "x").
		go func() {
			defer wg.Done()
			gen2 := NewPoolResolverShared([]store.Pool{mkPool("pool", "a")}, nil, shared)
			gen2.MergeLiveCooldowns(gen1)
		}()
		// Stale old-generation failover cooldown for the dropped member.
		go func() {
			defer wg.Done()
			gen1.MarkCooldown("x", time.Now().Add(300*time.Second), "failover:401")
		}()
		wg.Wait()

		// Observe the SHARED health map directly (CooldownUntil is read-only
		// and does NOT prune). Build the observer WITH "x" as a member so a
		// resurrected entry could NOT be hidden by an observer-side prune:
		// if the write-after-prune gate worked, "x" was never written; if it
		// failed, the stale cooldown is still here. No MergeLiveCooldowns is
		// called, so this asserts the gate's effect, not the prune's.
		observer := NewPoolResolverShared([]store.Pool{mkPool("p2", "x")}, nil, shared)
		if _, cooling := observer.CooldownUntil("x"); cooling {
			t.Fatalf("iter %d: non-member x ended up with a resurrected cooldown after the concurrent prune/mark race", iter)
		}
	}
}

// TestResolveActiveStickyEpochClobberRegression is the Finding 3 regression.
// A pool name is removed and re-created with an OVERLAPPING member name but a
// strictly greater membership epoch (the store stamps every membership
// generation with a monotonic epoch). Before the fix the sticky pointer
// stored only the member NAME, so the new generation accepted the old
// generation's stored name as a valid sticky hold even though it belongs to
// the OLD epoch/order. Fail-before: gen2 honors the stale name and skips
// fresh position-0 selection. Pass-after: the epoch mismatch makes gen2
// treat it as "no current active" and select by fresh position order.
func TestResolveActiveStickyEpochClobberRegression(t *testing.T) {
	shared := NewPoolHealth()
	const e1 = int64(1)
	const e2 = int64(2)

	// gen1: pool P = [a, b] at epoch e1. Fail a over so the sticky pointer
	// settles on "b".
	gen1 := NewPoolResolverShared([]store.Pool{mkPoolEpoch("P", e1, "a", "b")}, nil, shared)
	if got, _ := gen1.ResolveActive("P"); got != "a" {
		t.Fatalf("gen1 initial = %q, want a", got)
	}
	gen1.MarkCooldownScoped("a", "P", e1, time.Now().Add(300*time.Second), "failover:429")
	if got, _ := gen1.ResolveActive("P"); got != "b" {
		t.Fatalf("gen1 after cooling a = %q, want b", got)
	}

	// P is removed and RE-CREATED with the SAME name but a DIFFERENT member
	// order [b, a] at a strictly greater epoch e2. "b" still exists by name
	// but at epoch e2 / position 0; the stored sticky entry (member "b",
	// epoch e1) must NOT be honored — the new generation must pick by fresh
	// position order, which is "b" at position 0. To make the test prove the
	// epoch check (not just coincide), the new order is [c, b]: position 0 is
	// "c". A name-only sticky pointer would wrongly return "b"; the
	// epoch-scoped pointer rejects the stale entry and returns fresh
	// position-0 "c".
	gen2 := NewPoolResolverShared([]store.Pool{mkPoolEpoch("P", e2, "c", "b")}, nil, shared)
	gen2.MergeLiveCooldowns(gen1)
	if got, ok := gen2.ResolveActive("P"); !ok || got != "c" {
		t.Fatalf("Finding 3: stale-epoch sticky entry honored; got %q,%v want c,true "+
			"(epoch-bumped re-create must NOT inherit the old generation's sticky member)", got, ok)
	}
}

// TestResolveActiveFastPathAndAdvancePath exercises both Finding 2 lock
// paths for correctness: the RLock sticky-hold fast path (no mutation) and
// the write-lock advance path. It is a correctness test, not a benchmark.
func TestResolveActiveFastPathAndAdvancePath(t *testing.T) {
	shared := NewPoolHealth()
	pr := NewPoolResolverShared([]store.Pool{mkPool("pool", "a", "b")}, nil, shared)

	// First call: no sticky entry -> advance/init path (write lock), settles a.
	if got, _ := pr.ResolveActive("pool"); got != "a" {
		t.Fatalf("init = %q, want a", got)
	}
	// Subsequent calls: sticky hold -> RLock fast path, must keep returning a.
	for i := 0; i < 100; i++ {
		if got, _ := pr.ResolveActive("pool"); got != "a" {
			t.Fatalf("fast-path call %d = %q, want a (sticky hold)", i, got)
		}
	}
	// Cool a -> next call takes the advance (write-lock) path and moves to b.
	pr.MarkCooldown("a", time.Now().Add(120*time.Second), "429")
	if got, _ := pr.ResolveActive("pool"); got != "b" {
		t.Fatalf("after cooling a = %q, want b (advance path)", got)
	}
	// Now b is the sticky hold: fast path again.
	for i := 0; i < 100; i++ {
		if got, _ := pr.ResolveActive("pool"); got != "b" {
			t.Fatalf("fast-path call %d after advance = %q, want b", i, got)
		}
	}
	// Concurrent resolves under the read-mostly pattern must all agree and be
	// race-clean (run under -race).
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if got, _ := pr.ResolveActive("pool"); got != "b" {
					t.Errorf("concurrent resolve = %q, want b", got)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestSetCurrentMembersPrunesStaleActive pins Finding 1: SetCurrentMembers is
// a live reload path (NewPoolResolverShared calls it before StorePool reaches
// MergeLiveCooldowns), so it must itself prune a stale sticky entry. This
// drives SetCurrentMembers directly with a member set that drops the pool's
// recorded member and asserts the sticky pointer is gone.
func TestSetCurrentMembersPrunesStaleActive(t *testing.T) {
	shared := NewPoolHealth()
	pr := NewPoolResolverShared([]store.Pool{mkPoolEpoch("pool", 1, "a", "b")}, nil, shared)
	if got, _ := pr.ResolveActive("pool"); got != "a" {
		t.Fatalf("init = %q, want a", got)
	}
	// New generation: pool no longer contains "a" (membership changed). Drive
	// SetCurrentMembers directly with the new member set (b only, epoch 2).
	shared.SetCurrentMembers(map[string]memberIdentity{
		"b": {pool: "pool", epoch: 2},
	})
	shared.mu.RLock()
	_, stillActive := shared.active["pool"]
	shared.mu.RUnlock()
	if stillActive {
		t.Fatal("Finding 1: SetCurrentMembers did not prune the stale sticky pointer for a dropped/epoch-bumped member")
	}
}
