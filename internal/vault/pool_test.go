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
