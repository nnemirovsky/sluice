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
	if err := s.CreatePoolWithMembers("p2", "failover", []string{"shared"}); err != nil {
		t.Fatalf("create p2: %v", err)
	}
	pools, err := s.PoolsForMember("shared")
	if err != nil {
		t.Fatalf("PoolsForMember: %v", err)
	}
	if len(pools) != 2 || pools[0] != "p1" || pools[1] != "p2" {
		t.Errorf("PoolsForMember(shared) = %v, want [p1 p2]", pools)
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
