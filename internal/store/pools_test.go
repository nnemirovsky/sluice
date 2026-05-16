package store

import (
	"path/filepath"
	"strings"
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

// TestRemoveCredentialMetaCASGuardsLivePoolMember is the round-10 Finding 1
// regression. The cred-add rollback path (RemoveCredentialMetaCAS) must apply
// the SAME fail-closed pool-member guard and the SAME credential_health
// cleanup as RemoveCredentialMeta. Interleave being defended:
//
//	cred add inserts credential_meta("c")  ->  a concurrent caller creates a
//	pool that claims "c"  ->  a later step in the original add flow fails  ->
//	the CAS rollback runs. A blind CAS delete here would orphan the
//	credential_pool_members row (pool -> missing credential). The shared
//	guarded helper must refuse the delete and surface an informative error.
func TestRemoveCredentialMetaCASGuardsLivePoolMember(t *testing.T) {
	s := newTestStore(t)

	// cred add inserted the meta row (oauth, with the seed token URL).
	seedOAuthCred(t, s, "c")
	seedOAuthCred(t, s, "sibling")

	// Concurrent pool-create claims "c" between the insert and the rollback.
	if err := s.CreatePoolWithMembers("p", "failover", []string{"c", "sibling"}); err != nil {
		t.Fatalf("CreatePoolWithMembers: %v", err)
	}

	// The original add flow failed; its rollback fires RemoveCredentialMetaCAS
	// with the values it inserted. The pool-member guard must REFUSE.
	removed, noConcurrent, err := s.RemoveCredentialMetaCAS("c", "oauth", "https://auth.example.com/token")
	if err == nil {
		t.Fatal("expected CAS rollback to refuse a live pool member (Finding 1)")
	}
	if removed || noConcurrent {
		t.Fatalf("CAS rollback reported removed=%v noConcurrent=%v on a refused delete; want false,false", removed, noConcurrent)
	}
	if !strings.Contains(err.Error(), "member of pool") {
		t.Fatalf("CAS refusal error is not informative about pool membership: %v", err)
	}
	// The meta row must survive (it IS a live pool member — correct state),
	// so the pool does not resolve to a missing credential.
	if m, gerr := s.GetCredentialMeta("c"); gerr != nil || m == nil {
		t.Fatalf("CAS rollback deleted a live pool member's meta row: %+v, %v", m, gerr)
	}
	pools, perr := s.PoolsForMember("c")
	if perr != nil || len(pools) != 1 || pools[0] != "p" {
		t.Fatalf("PoolsForMember(c) = %v, %v; want [p] (no orphan)", pools, perr)
	}

	// A normal rollback (no pool claim) must still delete meta + health row
	// and leave no stale cooldown for a same-named recreation.
	seedOAuthCred(t, s, "lone")
	until := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	if err := s.SetCredentialHealth("lone", "cooldown", until, "429 from a prior add attempt"); err != nil {
		t.Fatalf("SetCredentialHealth(lone): %v", err)
	}
	removed, noConcurrent, err = s.RemoveCredentialMetaCAS("lone", "oauth", "https://auth.example.com/token")
	if err != nil || !removed || !noConcurrent {
		t.Fatalf("RemoveCredentialMetaCAS(lone) = %v,%v,%v; want true,true,nil", removed, noConcurrent, err)
	}
	if m, _ := s.GetCredentialMeta("lone"); m != nil {
		t.Fatalf("CAS rollback left a meta row for a non-member: %+v", m)
	}
	if h, herr := s.GetCredentialHealth("lone"); herr != nil || h != nil {
		t.Fatalf("CAS rollback left a stale cooldown row: %+v, %v", h, herr)
	}

	// CAS predicate is still honoured: a concurrent overwrite (different
	// cred_type) must not be deleted by a stale-expectation rollback, even
	// when the credential is free of any pool.
	seedOAuthCred(t, s, "raced")
	// A concurrent writer overwrote "raced" as a static credential.
	if _, err := s.db.Exec("UPDATE credential_meta SET cred_type = 'static', token_url = NULL WHERE name = ?", "raced"); err != nil {
		t.Fatalf("simulate concurrent overwrite: %v", err)
	}
	removed, noConcurrent, err = s.RemoveCredentialMetaCAS("raced", "oauth", "https://auth.example.com/token")
	if err != nil {
		t.Fatalf("CAS with stale expectation errored: %v", err)
	}
	if removed || noConcurrent {
		t.Fatalf("CAS deleted a concurrently-overwritten row: removed=%v noConcurrent=%v; want false,false", removed, noConcurrent)
	}
	if m, _ := s.GetCredentialMeta("raced"); m == nil {
		t.Fatal("CAS wiped a concurrent writer's row despite the predicate mismatch")
	}
}

// TestRemovePoolDeletesMemberHealth pins Finding 1: RemovePool must delete the
// credential_health rows of the pool's members in the same transaction so a
// cooled member taken out with its pool does not leave a stale durable
// cooldown that loadPoolResolver (which seeds the shared PoolHealth from ALL
// credential_health rows) would inherit when the credential is re-added to a
// NEW pool before the old TTL expires.
//
// Fail-before: RemovePool only DELETEd credential_pools (members cascaded),
// leaving the health row -> GetCredentialHealth still returns the cooldown.
// Pass-after: the member's health row is gone.
func TestRemovePoolDeletesMemberHealth(t *testing.T) {
	s := newTestStore(t)
	seedOAuthCred(t, s, "m")
	if err := s.CreatePoolWithMembers("p", "failover", []string{"m"}); err != nil {
		t.Fatalf("create pool: %v", err)
	}
	until := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	if err := s.SetCredentialHealth("m", "cooldown", until, "429 rate limited"); err != nil {
		t.Fatalf("cool member: %v", err)
	}

	removed, err := s.RemovePool("p")
	if err != nil || !removed {
		t.Fatalf("RemovePool = %v, %v; want true, nil", removed, err)
	}

	// The former member's durable cooldown must be gone so re-adding it to a
	// new pool before the old TTL expires yields a healthy member.
	h, err := s.GetCredentialHealth("m")
	if err != nil {
		t.Fatalf("GetCredentialHealth: %v", err)
	}
	if h != nil {
		t.Fatalf("member health row survived RemovePool (stale cooldown inherited): %+v", h)
	}
}

// TestRemovePoolSparesStillPooledMemberHealth is the negative case for
// Finding 1: a member that is STILL a live member of another pool after the
// removal must keep its health row (its cooldown is still meaningful for that
// pool). The one-credential-one-pool invariant is enforced at the
// application layer, so a second membership is injected via raw SQL to
// exercise the residual-membership defensive branch (the same reason
// PoolsForMember returns a slice).
func TestRemovePoolSparesStillPooledMemberHealth(t *testing.T) {
	s := newTestStore(t)
	seedOAuthCred(t, s, "m")
	if err := s.CreatePoolWithMembers("p", "failover", []string{"m"}); err != nil {
		t.Fatalf("create pool p: %v", err)
	}
	// "m" also belongs to pool q (legacy/pre-invariant row injected directly).
	if _, err := s.db.Exec("INSERT INTO credential_pools (name, strategy) VALUES ('q', 'failover')"); err != nil {
		t.Fatalf("insert pool q: %v", err)
	}
	if _, err := s.db.Exec("INSERT INTO credential_pool_members (pool, credential, position) VALUES ('q', 'm', 0)"); err != nil {
		t.Fatalf("insert q membership: %v", err)
	}
	until := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	if err := s.SetCredentialHealth("m", "cooldown", until, "401 auth fail"); err != nil {
		t.Fatalf("cool member: %v", err)
	}

	removed, err := s.RemovePool("p")
	if err != nil || !removed {
		t.Fatalf("RemovePool(p) = %v, %v; want true, nil", removed, err)
	}

	// "m" is still in pool q, so its cooldown must be preserved.
	h, err := s.GetCredentialHealth("m")
	if err != nil {
		t.Fatalf("GetCredentialHealth: %v", err)
	}
	if h == nil {
		t.Fatal("RemovePool(p) wiped the health row of a member still in pool q")
	}
	if h.Status != "cooldown" {
		t.Errorf("health status = %q, want cooldown (cooldown for still-pooled member destroyed)", h.Status)
	}
}

// TestAddCredentialMetaRejectsLivePoolMemberDowngrade pins Finding 2:
// AddCredentialMeta is an upsert, and a re-add/update path could flip an
// existing credential that is a LIVE pool member to static / non-oauth /
// missing token_url, leaving the pool pointing at a member the pooled OAuth
// injection+failover code cannot use. The downgrade must be rejected; benign
// updates (still oauth with a token_url) and non-member upserts must still
// work.
func TestAddCredentialMetaRejectsLivePoolMemberDowngrade(t *testing.T) {
	s := newTestStore(t)
	seedOAuthCred(t, s, "poolcred")
	if err := s.CreatePoolWithMembers("p", "failover", []string{"poolcred"}); err != nil {
		t.Fatalf("create pool: %v", err)
	}

	// Downgrade a live pool member to static -> rejected, row unchanged.
	if err := s.AddCredentialMeta("poolcred", "static", ""); err == nil {
		t.Fatal("expected AddCredentialMeta to reject downgrading a live pool member to static")
	}
	meta, err := s.GetCredentialMeta("poolcred")
	if err != nil {
		t.Fatalf("get meta: %v", err)
	}
	if meta == nil || meta.CredType != "oauth" || meta.TokenURL == "" {
		t.Fatalf("live pool member meta was mutated by a rejected downgrade: %+v", meta)
	}

	// Dropping the token_url while still "oauth" is also a downgrade
	// (pooled failover needs a token endpoint). AddCredentialMeta's own
	// oauth-needs-token_url validation rejects this before the guard, which
	// still leaves the row unchanged — the property under test.
	if err := s.AddCredentialMeta("poolcred", "oauth", ""); err == nil {
		t.Fatal("expected AddCredentialMeta to reject a live pool member losing its token_url")
	}
	if m, _ := s.GetCredentialMeta("poolcred"); m == nil || m.TokenURL == "" {
		t.Fatalf("token_url drop mutated the live pool member row: %+v", m)
	}

	// Benign update: still oauth, new token_url -> allowed.
	if err := s.AddCredentialMeta("poolcred", "oauth", "https://new.example.com/token"); err != nil {
		t.Fatalf("benign oauth token_url change on a pool member rejected: %v", err)
	}
	m2, _ := s.GetCredentialMeta("poolcred")
	if m2 == nil || m2.TokenURL != "https://new.example.com/token" {
		t.Fatalf("benign token_url change not applied: %+v", m2)
	}

	// Non-member credential: static upsert still allowed (no regression).
	if err := s.AddCredentialMeta("freecred", "oauth", "https://auth.example.com/token"); err != nil {
		t.Fatalf("seed freecred: %v", err)
	}
	if err := s.AddCredentialMeta("freecred", "static", ""); err != nil {
		t.Fatalf("static upsert of a non-pool-member credential was wrongly rejected: %v", err)
	}
	fm, _ := s.GetCredentialMeta("freecred")
	if fm == nil || fm.CredType != "static" {
		t.Fatalf("non-member static upsert did not apply: %+v", fm)
	}
}

// TestSetCredentialHealthIfPoolMemberLiveMemberPersists is case (a): a
// credential that IS a live pool member must get its durable cooldown written
// by the guarded failover path, preserving the CRITICAL-1 restart-durability
// guarantee. Fail-before would exist if the guard skipped a live member;
// pass-after asserts wrote=true and the row is readable with the cooldown.
func TestSetCredentialHealthIfPoolMemberLiveMemberPersists(t *testing.T) {
	s := newTestStore(t)
	seedOAuthCred(t, s, "live")
	if err := s.CreatePoolWithMembers("p", "failover", []string{"live"}); err != nil {
		t.Fatalf("create pool: %v", err)
	}
	until := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)

	wrote, err := s.SetCredentialHealthIfPoolMember("live", "cooldown", until, "failover:401 auth fail")
	if err != nil {
		t.Fatalf("SetCredentialHealthIfPoolMember: %v", err)
	}
	if !wrote {
		t.Fatal("guarded write skipped a LIVE pool member (CRITICAL-1 durability regressed)")
	}
	h, err := s.GetCredentialHealth("live")
	if err != nil || h == nil {
		t.Fatalf("GetCredentialHealth(live) = %+v, %v; want a persisted cooldown row", h, err)
	}
	if h.Status != "cooldown" {
		t.Errorf("health status = %q, want cooldown", h.Status)
	}
	if !h.CooldownUntil.Equal(until) {
		t.Errorf("cooldown_until = %v, want %v (durable cooldown not persisted)", h.CooldownUntil, until)
	}
}

// TestSetCredentialHealthIfPoolMemberSkipsRemoved is case (b): once the
// credential is no longer a live pool member (its pool — and health row — was
// removed), a LATE-running failover goroutine's guarded write must be a no-op:
// NO credential_health row may be (re)created, and a later same-named
// credential added to a NEW pool must inherit NO stale cooldown.
//
// Fail-before: the old unconditional db.SetCredentialHealth upsert would
// resurrect a credential_health row for the removed credential, which
// loadPoolResolver later seeds into PoolHealth, so a same-named re-add starts
// in cooldown. Pass-after: the guarded write returns wrote=false and writes
// nothing.
func TestSetCredentialHealthIfPoolMemberSkipsRemoved(t *testing.T) {
	s := newTestStore(t)
	seedOAuthCred(t, s, "gone")
	if err := s.CreatePoolWithMembers("p", "failover", []string{"gone"}); err != nil {
		t.Fatalf("create pool: %v", err)
	}

	// Pool removal deletes the member's credential_health row (round-8/9/11
	// cleanup) AND drops it from credential_pool_members.
	removed, err := s.RemovePool("p")
	if err != nil || !removed {
		t.Fatalf("RemovePool = %v, %v; want true, nil", removed, err)
	}

	// A failover goroutine for the just-removed credential lands LATE.
	until := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	wrote, err := s.SetCredentialHealthIfPoolMember("gone", "cooldown", until, "failover:401 auth fail")
	if err != nil {
		t.Fatalf("SetCredentialHealthIfPoolMember (late failover): %v", err)
	}
	if wrote {
		t.Fatal("late failover write resurrected a removed credential's health row (Finding)")
	}
	if h, herr := s.GetCredentialHealth("gone"); herr != nil || h != nil {
		t.Fatalf("health row resurrected for a removed credential: %+v, %v", h, herr)
	}

	// A later same-named credential added to a NEW pool must inherit NO stale
	// cooldown: ListCredentialHealth (what loadPoolResolver seeds from) must
	// carry no row for "gone".
	seedOAuthCred(t, s, "gone")
	if err := s.CreatePoolWithMembers("p2", "failover", []string{"gone"}); err != nil {
		t.Fatalf("recreate pool: %v", err)
	}
	rows, err := s.ListCredentialHealth()
	if err != nil {
		t.Fatalf("ListCredentialHealth: %v", err)
	}
	for _, r := range rows {
		if r.Credential == "gone" {
			t.Fatalf("same-named credential inherited a stale cooldown from a resurrected row: %+v", r)
		}
	}
}

// TestSetCredentialHealthIfPoolMemberValidates pins that the guarded variant
// applies the same input validation as the unconditional path before touching
// the DB (no transaction opened for invalid input).
func TestSetCredentialHealthIfPoolMemberValidates(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.SetCredentialHealthIfPoolMember("", "cooldown", time.Now(), "x"); err == nil {
		t.Error("empty credential name accepted")
	}
	if _, err := s.SetCredentialHealthIfPoolMember("c", "bogus", time.Time{}, ""); err == nil {
		t.Error("invalid status accepted")
	}
}

// TestRemoveCredentialFullyAtomicHappyPath is the round-15 Finding 2
// happy-path regression. RemoveCredentialFully must, in ONE transaction,
// delete credential_meta, credential_health, every binding on the
// credential, and every auto-created allow rule (cred-add:/binding-add:).
func TestRemoveCredentialFullyAtomicHappyPath(t *testing.T) {
	s := newTestStore(t)
	seedOAuthCred(t, s, "c")

	until := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	if err := s.SetCredentialHealth("c", "cooldown", until, "429"); err != nil {
		t.Fatalf("SetCredentialHealth: %v", err)
	}
	if _, _, err := s.AddRuleAndBinding(
		"allow",
		RuleOpts{Destination: "api.example.com", Ports: []int{443}, Source: CredAddSourcePrefix + "c"},
		"c",
		BindingOpts{Ports: []int{443}, Header: "Authorization", Template: "Bearer {value}"},
	); err != nil {
		t.Fatalf("AddRuleAndBinding: %v", err)
	}

	metaDeleted, bn, rn, err := s.RemoveCredentialFully("c")
	if err != nil {
		t.Fatalf("RemoveCredentialFully: %v", err)
	}
	if !metaDeleted {
		t.Error("metaDeleted = false, want true")
	}
	if bn != 1 {
		t.Errorf("bindings removed = %d, want 1", bn)
	}
	if rn != 1 {
		t.Errorf("rules removed = %d, want 1", rn)
	}
	if m, _ := s.GetCredentialMeta("c"); m != nil {
		t.Errorf("credential_meta survived: %+v", m)
	}
	if h, _ := s.GetCredentialHealth("c"); h != nil {
		t.Errorf("credential_health survived: %+v", h)
	}
	if b, _ := s.ListBindingsByCredential("c"); len(b) != 0 {
		t.Errorf("bindings survived: %+v", b)
	}
	rules, _ := s.ListRules(RuleFilter{Type: "network"})
	for _, r := range rules {
		if r.Source == CredAddSourcePrefix+"c" {
			t.Errorf("auto-created rule survived: %+v", r)
		}
	}
}

// TestRemoveCredentialFullyRollsBackOnRuleFailure is the round-15 Finding 2
// fail-before/pass-after regression. The OLD removal path committed the
// credential_meta (+health) delete in its OWN transaction, then removed
// bindings/rules in SEPARATE statements: a binding/rule failure left
// meta+health gone while the vault secret + partial store state survived (a
// partially-deleted credential). RemoveCredentialFully folds all four
// deletes into ONE transaction, so a rule-delete failure must roll the
// WHOLE unit back: credential_meta, credential_health, and bindings must
// ALL still be present, and a clear error returned.
//
// The failure is forced deterministically by dropping the `rules` table
// before the call, so the in-tx rules DELETE errors AFTER the meta+health
// +bindings deletes have run inside the same (uncommitted) transaction.
func TestRemoveCredentialFullyRollsBackOnRuleFailure(t *testing.T) {
	s := newTestStore(t)
	seedOAuthCred(t, s, "c")

	until := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	if err := s.SetCredentialHealth("c", "cooldown", until, "429"); err != nil {
		t.Fatalf("SetCredentialHealth: %v", err)
	}
	if _, err := s.AddBinding("api.example.com", "c", BindingOpts{
		Ports: []int{443}, Header: "Authorization", Template: "Bearer {value}",
	}); err != nil {
		t.Fatalf("AddBinding: %v", err)
	}

	// Force the in-tx rules DELETE to fail.
	if _, err := s.db.Exec("DROP TABLE rules"); err != nil {
		t.Fatalf("drop rules table: %v", err)
	}

	metaDeleted, _, _, err := s.RemoveCredentialFully("c")
	if err == nil {
		t.Fatal("RemoveCredentialFully succeeded despite a forced rule-delete failure")
	}
	if metaDeleted {
		t.Error("metaDeleted = true on a rolled-back removal")
	}

	// The WHOLE store unit must have rolled back: meta, health, and the
	// binding must all still be present.
	if m, _ := s.GetCredentialMeta("c"); m == nil {
		t.Error("credential_meta was deleted despite the tx rolling back (partial-delete bug)")
	}
	if h, _ := s.GetCredentialHealth("c"); h == nil {
		t.Error("credential_health was deleted despite the tx rolling back (partial-delete bug)")
	}
	if b, _ := s.ListBindingsByCredential("c"); len(b) != 1 {
		t.Errorf("binding count = %d, want 1 (binding deleted despite rollback)", len(b))
	}
}

// TestRemoveCredentialFullyRefusesLivePoolMember pins that the fail-closed
// pool-member guard still fires inside the atomic unit: a live pool member
// removal is refused with NOTHING deleted (so callers leave the vault
// secret intact).
func TestRemoveCredentialFullyRefusesLivePoolMember(t *testing.T) {
	s := newTestStore(t)
	seedOAuthCred(t, s, "m")
	seedOAuthCred(t, s, "n")
	if err := s.CreatePoolWithMembers("p", "failover", []string{"m", "n"}); err != nil {
		t.Fatalf("CreatePoolWithMembers: %v", err)
	}

	metaDeleted, _, _, err := s.RemoveCredentialFully("m")
	if err == nil {
		t.Fatal("expected RemoveCredentialFully to refuse a live pool member")
	}
	if metaDeleted {
		t.Error("metaDeleted = true for a refused removal")
	}
	if m, _ := s.GetCredentialMeta("m"); m == nil {
		t.Error("credential_meta deleted for a refused live pool member")
	}

	// A free (non-member) credential still removes cleanly.
	seedOAuthCred(t, s, "free")
	if md, _, _, ferr := s.RemoveCredentialFully("free"); ferr != nil || !md {
		t.Fatalf("RemoveCredentialFully(free) = %v, %v; want true, nil", md, ferr)
	}
}

// TestRemoveCredentialFullyCleansHealthOnPartialCleanupFinish is the round-17
// Finding 1 fail-before/pass-after regression. Pre-state simulates a prior
// PARTIAL cleanup: credential_meta for "x" is ALREADY absent, but a stale
// credential_health cooldown row plus a binding and an auto-created allow
// rule survived. deleteCredentialMetaGuardedTx only drops the health row when
// the meta DELETE affected a row (n>0, CAS no-op semantics), so the OLD
// RemoveCredentialFully left the stale health row behind (n==0 here) and a
// later same-named credential would inherit the dead cooldown. The fix adds
// an UNCONDITIONAL health delete for the named credential in the full-removal
// tx. Pass-after: health, binding, and rule for "x" are all gone, so a later
// same-named pool member inherits NO stale cooldown.
func TestRemoveCredentialFullyCleansHealthOnPartialCleanupFinish(t *testing.T) {
	s := newTestStore(t)

	// Bindings + rules require a credential_meta row to be created via the
	// normal path; seed it, wire the binding/rule/health, THEN delete ONLY
	// the meta row directly to reproduce the "prior partial cleanup" state
	// (meta gone, health + binding + rule still present).
	seedOAuthCred(t, s, "x")
	until := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	if err := s.SetCredentialHealth("x", "cooldown", until, "429"); err != nil {
		t.Fatalf("SetCredentialHealth: %v", err)
	}
	if _, _, err := s.AddRuleAndBinding(
		"allow",
		RuleOpts{Destination: "api.example.com", Ports: []int{443}, Source: CredAddSourcePrefix + "x"},
		"x",
		BindingOpts{Ports: []int{443}, Header: "Authorization", Template: "Bearer {value}"},
	); err != nil {
		t.Fatalf("AddRuleAndBinding: %v", err)
	}
	// Simulate the prior partial cleanup: meta row gone, everything else left.
	if _, err := s.db.Exec("DELETE FROM credential_meta WHERE name = ?", "x"); err != nil {
		t.Fatalf("simulate partial cleanup (delete meta): %v", err)
	}
	if m, _ := s.GetCredentialMeta("x"); m != nil {
		t.Fatalf("precondition: credential_meta should be absent, got %+v", m)
	}
	if h, _ := s.GetCredentialHealth("x"); h == nil {
		t.Fatal("precondition: stale credential_health row must still be present")
	}

	// Finishing the partial cleanup. metaDeleted is false (meta already
	// gone), but bindings/rules AND the stale health row must be swept.
	metaDeleted, bn, rn, err := s.RemoveCredentialFully("x")
	if err != nil {
		t.Fatalf("RemoveCredentialFully: %v", err)
	}
	if metaDeleted {
		t.Error("metaDeleted = true, want false (meta was already gone)")
	}
	if bn != 1 {
		t.Errorf("bindings removed = %d, want 1", bn)
	}
	if rn != 1 {
		t.Errorf("rules removed = %d, want 1", rn)
	}
	if h, _ := s.GetCredentialHealth("x"); h != nil {
		t.Errorf("stale credential_health survived partial-cleanup finish: %+v", h)
	}
	if b, _ := s.ListBindingsByCredential("x"); len(b) != 0 {
		t.Errorf("bindings survived: %+v", b)
	}
	rules, _ := s.ListRules(RuleFilter{Type: "network"})
	for _, r := range rules {
		if r.Source == CredAddSourcePrefix+"x" {
			t.Errorf("auto-created rule survived: %+v", r)
		}
	}

	// A later same-named credential added to a pool must inherit NO stale
	// cooldown: ListCredentialHealth (what loadPoolResolver seeds from)
	// carries no row for "x".
	seedOAuthCred(t, s, "x")
	seedOAuthCred(t, s, "y")
	if err := s.CreatePoolWithMembers("p", "failover", []string{"x", "y"}); err != nil {
		t.Fatalf("CreatePoolWithMembers: %v", err)
	}
	hrows, err := s.ListCredentialHealth()
	if err != nil {
		t.Fatalf("ListCredentialHealth: %v", err)
	}
	for _, r := range hrows {
		if r.Credential == "x" {
			t.Fatalf("same-named credential inherited a stale cooldown: %+v", r)
		}
	}
}

// TestRemoveCredentialMetaCASNoOpLeavesHealthIntact pins the round-11
// invariant the Finding 1 fix MUST NOT regress: a CAS no-op (a concurrent
// writer changed cred_type/token_url so the guarded meta DELETE matches 0
// rows) must leave the credential_health row UNTOUCHED. The fix added the
// unconditional health delete ONLY in RemoveCredentialFully, not in the
// shared deleteCredentialMetaGuardedTx helper, so RemoveCredentialMetaCAS's
// no-op semantics are unchanged.
func TestRemoveCredentialMetaCASNoOpLeavesHealthIntact(t *testing.T) {
	s := newTestStore(t)
	seedOAuthCred(t, s, "c")
	until := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	if err := s.SetCredentialHealth("c", "cooldown", until, "429"); err != nil {
		t.Fatalf("SetCredentialHealth: %v", err)
	}

	// CAS with MISMATCHED expected values: a "concurrent writer" effectively
	// owns the row, so the delete is a no-op and the health row it owns must
	// be left intact.
	removed, noConcurrent, err := s.RemoveCredentialMetaCAS("c", "static", "https://wrong.example/token")
	if err != nil {
		t.Fatalf("RemoveCredentialMetaCAS: %v", err)
	}
	if removed {
		t.Error("removed = true on a mismatched CAS (should be a no-op)")
	}
	if noConcurrent {
		t.Error("noConcurrent = true; expected the concurrent-writer signal")
	}
	if m, _ := s.GetCredentialMeta("c"); m == nil {
		t.Error("credential_meta wrongly deleted by a mismatched CAS")
	}
	if h, _ := s.GetCredentialHealth("c"); h == nil {
		t.Error("credential_health wrongly deleted by a CAS no-op (round-11 invariant regressed)")
	}
}
