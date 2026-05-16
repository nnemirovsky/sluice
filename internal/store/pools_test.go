package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migsqlite "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// seedOAuthCred registers a credential_meta row so a pool member passes the
// oauth+token_url validation.
func seedOAuthCred(t *testing.T, s *Store, name string) {
	t.Helper()
	if err := s.AddCredentialMeta(name, "oauth", "https://auth.example.com/token"); err != nil {
		t.Fatalf("seed oauth cred %q: %v", name, err)
	}
}

func TestCreatePoolWithMembersAndGet(t *testing.T) {
	s := newTestStore(t)
	seedOAuthCred(t, s, "acct_a")
	seedOAuthCred(t, s, "acct_b")

	if err := s.CreatePoolWithMembers("codex", "", []string{"acct_a", "acct_b"}); err != nil {
		t.Fatalf("CreatePoolWithMembers: %v", err)
	}

	p, err := s.GetPool("codex")
	if err != nil {
		t.Fatalf("GetPool: %v", err)
	}
	if p == nil {
		t.Fatal("GetPool returned nil for existing pool")
	}
	if p.Strategy != PoolStrategyFailover {
		t.Errorf("strategy = %q, want %q", p.Strategy, PoolStrategyFailover)
	}
	if len(p.Members) != 2 {
		t.Fatalf("members = %d, want 2", len(p.Members))
	}
	// Ordering must follow the slice order via position.
	if p.Members[0].Credential != "acct_a" || p.Members[0].Position != 0 {
		t.Errorf("member[0] = %+v, want acct_a@0", p.Members[0])
	}
	if p.Members[1].Credential != "acct_b" || p.Members[1].Position != 1 {
		t.Errorf("member[1] = %+v, want acct_b@1", p.Members[1])
	}

	exists, err := s.PoolExists("codex")
	if err != nil || !exists {
		t.Errorf("PoolExists(codex) = %v, %v; want true, nil", exists, err)
	}
	if got, _ := s.GetPool("missing"); got != nil {
		t.Errorf("GetPool(missing) = %+v, want nil", got)
	}
}

func TestCreatePoolRejectsStaticMember(t *testing.T) {
	s := newTestStore(t)
	if err := s.AddCredentialMeta("static_key", "static", ""); err != nil {
		t.Fatalf("AddCredentialMeta: %v", err)
	}
	err := s.CreatePoolWithMembers("p", "failover", []string{"static_key"})
	if err == nil {
		t.Fatal("expected error creating pool with static member")
	}
	// The pool row must not survive a failed member insert (tx rollback).
	if exists, _ := s.PoolExists("p"); exists {
		t.Error("pool row leaked after failed member validation")
	}
}

func TestCreatePoolRejectsMissingMember(t *testing.T) {
	s := newTestStore(t)
	if err := s.CreatePoolWithMembers("p", "failover", []string{"nope"}); err == nil {
		t.Fatal("expected error for non-existent member credential")
	}
}

func TestCreatePoolRejectsBadStrategyAndDupes(t *testing.T) {
	s := newTestStore(t)
	seedOAuthCred(t, s, "a")
	if err := s.CreatePoolWithMembers("p", "roundrobin", []string{"a"}); err == nil {
		t.Error("expected error for unsupported strategy")
	}
	if err := s.CreatePoolWithMembers("p", "failover", []string{"a", "a"}); err == nil {
		t.Error("expected error for duplicate member")
	}
	if err := s.CreatePoolWithMembers("p", "failover", nil); err == nil {
		t.Error("expected error for empty member list")
	}
}

func TestPoolCredentialNamespaceMutualExclusion(t *testing.T) {
	s := newTestStore(t)
	seedOAuthCred(t, s, "acct_a")
	// "acct_a" is a credential; a pool may not shadow it.
	if err := s.CreatePoolWithMembers("acct_a", "failover", []string{"acct_a"}); err == nil {
		t.Fatal("expected namespace collision error (pool name == credential name)")
	}
}

// TestCreatePoolRejectsMemberAlreadyInAnotherPool is the Finding 5
// regression. A credential may belong to at most one pool: proxy
// attribution (PoolResolver.PoolForMember) maps a member back to a SINGLE
// pool, so a token response for a second pool would be persisted/audited
// against the first pool's phantom, leaving the agent with an
// unreplaceable phantom. Adding a credential that already belongs to
// another pool must fail, and the second pool must not be left behind.
func TestCreatePoolRejectsMemberAlreadyInAnotherPool(t *testing.T) {
	s := newTestStore(t)
	seedOAuthCred(t, s, "shared")
	seedOAuthCred(t, s, "solo")

	if err := s.CreatePoolWithMembers("pool_one", "failover", []string{"shared"}); err != nil {
		t.Fatalf("CreatePoolWithMembers(pool_one): %v", err)
	}

	// "shared" already belongs to pool_one; adding it to pool_two must fail.
	err := s.CreatePoolWithMembers("pool_two", "failover", []string{"solo", "shared"})
	if err == nil {
		t.Fatal("expected error: credential already a member of another pool (Finding 5)")
	}

	// The second pool must not survive the rejected insert (tx rollback).
	if exists, _ := s.PoolExists("pool_two"); exists {
		t.Error("pool_two leaked after a member belonging to another pool was rejected")
	}

	// pool_one is untouched and "shared" is still only in pool_one.
	pools, err := s.PoolsForMember("shared")
	if err != nil {
		t.Fatalf("PoolsForMember: %v", err)
	}
	if len(pools) != 1 || pools[0] != "pool_one" {
		t.Fatalf("PoolsForMember(shared) = %v, want [pool_one] (one credential = at most one pool)", pools)
	}

	// Re-adding the same member to its OWN pool is rejected too (the pool
	// already exists; this would be a duplicate pool name), but the
	// single-pool invariant itself must not block recreating a fresh pool
	// after the old one is removed.
	if _, err := s.RemovePool("pool_one"); err != nil {
		t.Fatalf("RemovePool: %v", err)
	}
	if err := s.CreatePoolWithMembers("pool_three", "failover", []string{"shared"}); err != nil {
		t.Fatalf("after removing pool_one, re-adding shared to a new pool must succeed: %v", err)
	}
}

func TestListPoolsOrdersMembers(t *testing.T) {
	s := newTestStore(t)
	for _, n := range []string{"a", "b", "c"} {
		seedOAuthCred(t, s, n)
	}
	if err := s.CreatePoolWithMembers("p1", "failover", []string{"c", "a"}); err != nil {
		t.Fatalf("create p1: %v", err)
	}
	if err := s.CreatePoolWithMembers("p2", "failover", []string{"b"}); err != nil {
		t.Fatalf("create p2: %v", err)
	}
	pools, err := s.ListPools()
	if err != nil {
		t.Fatalf("ListPools: %v", err)
	}
	if len(pools) != 2 {
		t.Fatalf("pools = %d, want 2", len(pools))
	}
	// Pools ordered by name; p1 members in insertion order (c, a).
	if pools[0].Name != "p1" || len(pools[0].Members) != 2 ||
		pools[0].Members[0].Credential != "c" || pools[0].Members[1].Credential != "a" {
		t.Errorf("p1 members wrong: %+v", pools[0])
	}
	if pools[1].Name != "p2" || len(pools[1].Members) != 1 {
		t.Errorf("p2 wrong: %+v", pools[1])
	}
}

func TestRemovePoolCascadesMembers(t *testing.T) {
	s := newTestStore(t)
	seedOAuthCred(t, s, "a")
	if err := s.CreatePoolWithMembers("p", "failover", []string{"a"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	removed, err := s.RemovePool("p")
	if err != nil || !removed {
		t.Fatalf("RemovePool = %v, %v; want true, nil", removed, err)
	}
	// Members cascade-deleted via FK ON DELETE CASCADE.
	mp, _ := s.PoolsForMember("a")
	if len(mp) != 0 {
		t.Errorf("PoolsForMember after remove = %v, want empty", mp)
	}
	if removed, _ := s.RemovePool("p"); removed {
		t.Error("RemovePool of missing pool returned true")
	}
}

func TestPoolsForMember(t *testing.T) {
	s := newTestStore(t)
	seedOAuthCred(t, s, "shared")
	seedOAuthCred(t, s, "x")
	if err := s.CreatePoolWithMembers("p1", "failover", []string{"shared", "x"}); err != nil {
		t.Fatalf("create p1: %v", err)
	}
	// A credential belongs to at most one pool (Finding 5): adding "shared"
	// to a second pool must be rejected.
	if err := s.CreatePoolWithMembers("p2", "failover", []string{"shared"}); err == nil {
		t.Fatal("expected p2 creation to fail: shared already belongs to p1")
	}

	// PoolsForMember still reports the (single) owning pool. It returns a
	// slice because it also guards `cred remove` and must tolerate any
	// pre-invariant rows; the live invariant keeps it to one entry.
	pools, err := s.PoolsForMember("shared")
	if err != nil {
		t.Fatalf("PoolsForMember: %v", err)
	}
	if len(pools) != 1 || pools[0] != "p1" {
		t.Errorf("PoolsForMember(shared) = %v, want [p1] (one credential = at most one pool)", pools)
	}
	// "x" is also only in p1.
	xpools, err := s.PoolsForMember("x")
	if err != nil {
		t.Fatalf("PoolsForMember(x): %v", err)
	}
	if len(xpools) != 1 || xpools[0] != "p1" {
		t.Errorf("PoolsForMember(x) = %v, want [p1]", xpools)
	}
}

func TestCredentialHealthCRUD(t *testing.T) {
	s := newTestStore(t)

	// No row -> nil (callers treat as healthy).
	h, err := s.GetCredentialHealth("a")
	if err != nil || h != nil {
		t.Fatalf("GetCredentialHealth(absent) = %+v, %v; want nil, nil", h, err)
	}

	until := time.Now().Add(60 * time.Second).UTC().Truncate(time.Second)
	if err := s.SetCredentialHealth("a", "cooldown", until, "429 rate limited"); err != nil {
		t.Fatalf("SetCredentialHealth: %v", err)
	}
	h, err = s.GetCredentialHealth("a")
	if err != nil || h == nil {
		t.Fatalf("GetCredentialHealth = %+v, %v", h, err)
	}
	if h.Status != "cooldown" || h.LastFailureReason != "429 rate limited" {
		t.Errorf("health = %+v, want cooldown/429", h)
	}
	if !h.CooldownUntil.Equal(until) {
		t.Errorf("CooldownUntil = %v, want %v", h.CooldownUntil, until)
	}

	// Upsert back to healthy clears the cooldown.
	if err := s.SetCredentialHealth("a", "healthy", time.Time{}, ""); err != nil {
		t.Fatalf("SetCredentialHealth healthy: %v", err)
	}
	h, _ = s.GetCredentialHealth("a")
	if h.Status != "healthy" || !h.CooldownUntil.IsZero() {
		t.Errorf("after healthy upsert = %+v, want healthy/zero", h)
	}

	if err := s.SetCredentialHealth("b", "bogus", time.Time{}, ""); err == nil {
		t.Error("expected error for invalid health status")
	}

	all, err := s.ListCredentialHealth()
	if err != nil {
		t.Fatalf("ListCredentialHealth: %v", err)
	}
	if len(all) != 1 || all[0].Credential != "a" {
		t.Errorf("ListCredentialHealth = %+v, want [a]", all)
	}
}

func TestSetCredentialHealthMonotonicCooldown(t *testing.T) {
	s := newTestStore(t)

	// Seed a long auth-failure cooldown (now+300s).
	authUntil := time.Now().Add(300 * time.Second).UTC().Truncate(time.Second)
	if err := s.SetCredentialHealth("a", "cooldown", authUntil, "401 auth fail"); err != nil {
		t.Fatalf("seed cooldown: %v", err)
	}

	// A subsequent shorter rate-limit cooldown (now+60s) must NOT shorten
	// the durable row — restart durability must match the resolver.
	rlUntil := time.Now().Add(60 * time.Second).UTC().Truncate(time.Second)
	if err := s.SetCredentialHealth("a", "cooldown", rlUntil, "429 rate limited"); err != nil {
		t.Fatalf("shorter cooldown write: %v", err)
	}
	h, _ := s.GetCredentialHealth("a")
	if h == nil || !h.CooldownUntil.Equal(authUntil) {
		t.Fatalf("after shorter write CooldownUntil = %v, want %v (NOT shortened)",
			cooldownOf(h), authUntil)
	}
	if h.LastFailureReason != "401 auth fail" {
		t.Errorf("reason = %q, want %q (longer cooldown's metadata kept)", h.LastFailureReason, "401 auth fail")
	}

	// A strictly LATER cooldown does extend.
	laterUntil := authUntil.Add(120 * time.Second)
	if err := s.SetCredentialHealth("a", "cooldown", laterUntil, "429 again"); err != nil {
		t.Fatalf("later cooldown write: %v", err)
	}
	h, _ = s.GetCredentialHealth("a")
	if h == nil || !h.CooldownUntil.Equal(laterUntil) {
		t.Fatalf("after later write CooldownUntil = %v, want %v (extended)",
			cooldownOf(h), laterUntil)
	}

	// Transition to healthy clears, even though a longer cooldown is active
	// (recovery/heal path must remain intact).
	if err := s.SetCredentialHealth("a", "healthy", time.Time{}, ""); err != nil {
		t.Fatalf("heal write: %v", err)
	}
	h, _ = s.GetCredentialHealth("a")
	if h == nil || h.Status != "healthy" || !h.CooldownUntil.IsZero() {
		t.Errorf("after heal = %+v, want healthy/zero (recovery must not be blocked by monotonicity)", h)
	}

	// An already-expired stored cooldown loses to a fresh future one
	// (lazy expiry preserved at the durable layer too).
	pastUntil := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	if err := s.SetCredentialHealth("b", "cooldown", pastUntil, "stale"); err != nil {
		t.Fatalf("seed stale cooldown: %v", err)
	}
	freshUntil := time.Now().Add(60 * time.Second).UTC().Truncate(time.Second)
	if err := s.SetCredentialHealth("b", "cooldown", freshUntil, "429"); err != nil {
		t.Fatalf("fresh cooldown write: %v", err)
	}
	h, _ = s.GetCredentialHealth("b")
	if h == nil || !h.CooldownUntil.Equal(freshUntil) {
		t.Errorf("fresh cooldown after stale = %v, want %v", cooldownOf(h), freshUntil)
	}
}

func cooldownOf(h *CredentialHealth) interface{} {
	if h == nil {
		return nil
	}
	return h.CooldownUntil
}

// TestMigration000006DownUp verifies the pool migration is reversible.
func TestMigration000006DownUp(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "m.db")
	s, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = s.Close() }()

	tableExists := func(name string) bool {
		var n string
		err := s.db.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", name,
		).Scan(&n)
		return err == nil && n == name
	}

	for _, tbl := range []string{"credential_pools", "credential_pool_members", "credential_health"} {
		if !tableExists(tbl) {
			t.Fatalf("table %q missing after up migration", tbl)
		}
	}

	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("iofs: %v", err)
	}
	drv, err := migsqlite.WithInstance(s.db, &migsqlite.Config{})
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "sqlite", drv)
	if err != nil {
		t.Fatalf("migrator: %v", err)
	}

	// Step down one migration (000006 -> 000005).
	if err := m.Steps(-1); err != nil {
		t.Fatalf("down 1: %v", err)
	}
	for _, tbl := range []string{"credential_pools", "credential_pool_members", "credential_health"} {
		if tableExists(tbl) {
			t.Errorf("table %q still present after down migration", tbl)
		}
	}

	// Step back up; tables return.
	if err := m.Steps(1); err != nil {
		t.Fatalf("up 1: %v", err)
	}
	for _, tbl := range []string{"credential_pools", "credential_pool_members", "credential_health"} {
		if !tableExists(tbl) {
			t.Errorf("table %q missing after re-up migration", tbl)
		}
	}
}

// TestRemoveCredentialMetaBlocksLivePoolMember is the Finding 3 regression.
// The pool-member integrity guard must live in the store layer so the REST
// API and Telegram removal paths (which call RemoveCredentialMeta directly,
// bypassing the CLI guard) cannot orphan a credential_pool_members row.
func TestRemoveCredentialMetaBlocksLivePoolMember(t *testing.T) {
	s := newTestStore(t)
	seedOAuthCred(t, s, "member")
	seedOAuthCred(t, s, "other")
	if err := s.CreatePoolWithMembers("p", "failover", []string{"member", "other"}); err != nil {
		t.Fatalf("CreatePoolWithMembers: %v", err)
	}

	// Store-level removal of a live pool member must be refused.
	removed, err := s.RemoveCredentialMeta("member")
	if err == nil {
		t.Fatal("expected RemoveCredentialMeta to refuse a live pool member (Finding 3)")
	}
	if removed {
		t.Fatal("RemoveCredentialMeta reported removed=true for a refused removal")
	}
	// The meta row must still be present (refusal must not delete anything).
	m, gerr := s.GetCredentialMeta("member")
	if gerr != nil || m == nil {
		t.Fatalf("credential meta deleted despite refusal: %+v, %v", m, gerr)
	}
	// And the member row must still point at a real credential.
	pools, perr := s.PoolsForMember("member")
	if perr != nil || len(pools) != 1 || pools[0] != "p" {
		t.Fatalf("PoolsForMember(member) = %v, %v; want [p] (no dangling change)", pools, perr)
	}

	// Removing a NON-member credential still works.
	seedOAuthCred(t, s, "free")
	removed, err = s.RemoveCredentialMeta("free")
	if err != nil || !removed {
		t.Fatalf("RemoveCredentialMeta(free) = %v, %v; want true, nil", removed, err)
	}
}

// TestRemoveCredentialMetaCleansHealthRow is the Finding 2 regression.
// credential_health is keyed by name and not FK-tied to credential_meta, so a
// bare meta delete would leave a stale cooldown that a recreated same-named
// credential inherits on the next resolver seed.
func TestRemoveCredentialMetaCleansHealthRow(t *testing.T) {
	s := newTestStore(t)
	seedOAuthCred(t, s, "x")

	// Seed a cooldown for x.
	until := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	if err := s.SetCredentialHealth("x", "cooldown", until, "429 rate limited"); err != nil {
		t.Fatalf("SetCredentialHealth: %v", err)
	}
	if h, _ := s.GetCredentialHealth("x"); h == nil || h.Status != "cooldown" {
		t.Fatalf("precondition: expected x in cooldown, got %+v", h)
	}

	// Remove the credential. The health row must go with it.
	removed, err := s.RemoveCredentialMeta("x")
	if err != nil || !removed {
		t.Fatalf("RemoveCredentialMeta(x) = %v, %v; want true, nil", removed, err)
	}
	if h, herr := s.GetCredentialHealth("x"); herr != nil || h != nil {
		t.Fatalf("stale health row survived removal: %+v, %v", h, herr)
	}

	// Recreate the same-named credential and add it to a fresh pool. It must
	// NOT inherit the old cooldown — GetCredentialHealth is nil (= healthy).
	seedOAuthCred(t, s, "x")
	seedOAuthCred(t, s, "y")
	if err := s.CreatePoolWithMembers("fresh", "failover", []string{"x", "y"}); err != nil {
		t.Fatalf("CreatePoolWithMembers(fresh): %v", err)
	}
	if h, herr := s.GetCredentialHealth("x"); herr != nil || h != nil {
		t.Fatalf("recreated credential inherited a stale cooldown: %+v, %v", h, herr)
	}
}

// TestAddCredentialMetaRejectsPoolNameCollision is the Finding 4 regression.
// The pool-vs-credential namespace mutual-exclusion must be enforced in the
// store so the REST API and any other AddCredentialMeta caller cannot create
// a credential whose name collides with an existing pool.
func TestAddCredentialMetaRejectsPoolNameCollision(t *testing.T) {
	s := newTestStore(t)
	seedOAuthCred(t, s, "acct_a")
	seedOAuthCred(t, s, "acct_b")
	if err := s.CreatePoolWithMembers("codex", "failover", []string{"acct_a", "acct_b"}); err != nil {
		t.Fatalf("CreatePoolWithMembers: %v", err)
	}

	// A credential named "codex" collides with the existing pool.
	if err := s.AddCredentialMeta("codex", "oauth", "https://auth.example.com/token"); err == nil {
		t.Fatal("expected AddCredentialMeta to reject a name that collides with an existing pool (Finding 4)")
	}
	// No credential_meta row may have been written.
	if m, _ := s.GetCredentialMeta("codex"); m != nil {
		t.Fatalf("credential_meta row leaked for colliding name: %+v", m)
	}

	// A non-colliding name still succeeds.
	if err := s.AddCredentialMeta("not_a_pool", "static", ""); err != nil {
		t.Fatalf("AddCredentialMeta(not_a_pool) = %v, want nil", err)
	}

	// The reverse direction still holds: CreatePoolWithMembers rejects a
	// name that already exists as a credential.
	if err := s.CreatePoolWithMembers("not_a_pool", "failover", []string{"acct_a"}); err == nil {
		t.Fatal("expected CreatePoolWithMembers to reject a name that is already a credential")
	}
}
