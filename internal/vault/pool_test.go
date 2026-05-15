package vault

import (
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
