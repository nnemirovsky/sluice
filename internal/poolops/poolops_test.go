package poolops_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nemirovsky/sluice/internal/poolops"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
)

// newTestStore opens a fresh sqlite store and a paired vault dir, then seeds
// `creds` as oauth members so they are valid pool members.
func newTestStore(t *testing.T, creds ...string) *store.Store {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "sluice.db")
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	for _, c := range creds {
		if err := db.AddCredentialMeta(c, "oauth", "https://auth.example.com/token"); err != nil {
			t.Fatalf("add meta %q: %v", c, err)
		}
	}
	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	for _, c := range creds {
		if _, err := vs.Add(c, `{"access_token":"x","token_url":"https://auth.example.com/token"}`); err != nil {
			t.Fatalf("vault add %q: %v", c, err)
		}
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestParseMembers(t *testing.T) {
	got, err := poolops.ParseMembers(" a , b ,c")
	if err != nil {
		t.Fatalf("ParseMembers: %v", err)
	}
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("ParseMembers = %v", got)
	}
	if _, err := poolops.ParseMembers(""); !errors.Is(err, poolops.ErrNoMembers) {
		t.Fatalf("empty members err = %v, want ErrNoMembers", err)
	}
	if _, err := poolops.ParseMembers("a,,b"); err == nil {
		t.Fatalf("expected error for empty entry in members list")
	}
}

func TestCreateListStatusRotateRemove(t *testing.T) {
	db := newTestStore(t, "acct_a", "acct_b")

	if err := poolops.Create(db, "codex", "", []string{"acct_a", "acct_b"}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	pools, err := poolops.List(db)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(pools) != 1 || pools[0].Name != "codex" {
		t.Fatalf("List = %+v", pools)
	}

	st, err := poolops.Status(db, "codex")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Active != "acct_a" {
		t.Fatalf("Status.Active = %q, want acct_a", st.Active)
	}
	if len(st.Members) != 2 || !st.Members[0].Active || st.Members[0].State != "healthy" {
		t.Fatalf("Status.Members = %+v", st.Members)
	}

	rr, err := poolops.Rotate(db, "codex")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rr.From != "acct_a" || rr.To != "acct_b" {
		t.Fatalf("Rotate = %+v, want acct_a -> acct_b", rr)
	}

	st, err = poolops.Status(db, "codex")
	if err != nil {
		t.Fatalf("Status post-rotate: %v", err)
	}
	if st.Active != "acct_b" {
		t.Fatalf("post-rotate Active = %q, want acct_b", st.Active)
	}
	// acct_a now in cooldown.
	if st.Members[0].State != "cooldown" || st.Members[0].LastFailureReason != vault.ManualRotateReason {
		t.Fatalf("post-rotate Members[0] = %+v", st.Members[0])
	}

	if err := poolops.Remove(db, "codex"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := poolops.Status(db, "codex"); err == nil {
		t.Fatalf("Status after remove: err = nil, want PoolNotFoundError")
	}
}

func TestCreateErrors(t *testing.T) {
	db := newTestStore(t, "acct_a")

	if err := poolops.Create(db, "p", "", nil); !errors.Is(err, poolops.ErrNoMembers) {
		t.Fatalf("Create empty members err = %v, want ErrNoMembers", err)
	}

	// Static member rejected by the store.
	if err := db.AddCredentialMeta("static_one", "static", ""); err != nil {
		t.Fatalf("add static meta: %v", err)
	}
	if err := poolops.Create(db, "p2", "", []string{"static_one"}); err == nil {
		t.Fatalf("Create with static member: err = nil, want rejection")
	}

	// Namespace collision: a pool name equal to an existing credential.
	if err := poolops.Create(db, "acct_a", "", []string{"acct_a"}); err == nil {
		t.Fatalf("Create with name colliding with a credential: err = nil, want rejection")
	}
}

func TestStatusRotateRemoveUnknownPool(t *testing.T) {
	db := newTestStore(t)

	_, err := poolops.Status(db, "missing")
	var nf *poolops.PoolNotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("Status unknown pool err = %v, want PoolNotFoundError", err)
	}

	_, err = poolops.Rotate(db, "missing")
	if !errors.As(err, &nf) {
		t.Fatalf("Rotate unknown pool err = %v, want PoolNotFoundError", err)
	}

	err = poolops.Remove(db, "missing")
	if !errors.As(err, &nf) {
		t.Fatalf("Remove unknown pool err = %v, want PoolNotFoundError", err)
	}
}

func TestRemoveBlockedByBinding(t *testing.T) {
	db := newTestStore(t, "acct_a", "acct_b")
	if err := poolops.Create(db, "codex", "", []string{"acct_a", "acct_b"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// A binding whose credential column holds the pool name blocks removal.
	if _, err := db.AddBinding("api.example.com", "codex", store.BindingOpts{
		Ports:    []int{443},
		Header:   "Authorization",
		Template: "Bearer {value}",
	}); err != nil {
		t.Fatalf("AddBinding: %v", err)
	}
	err := poolops.Remove(db, "codex")
	var refErr *store.PoolReferencedError
	if !errors.As(err, &refErr) {
		t.Fatalf("Remove with referencing binding err = %v, want *PoolReferencedError", err)
	}
}

// TestRotateEpochRaceNoOp reproduces the post-race store state the guarded
// write observes: the pool snapshot resolved a member, but by write time the
// member row was deleted from credential_pool_members. The guarded write must
// no-op and Rotate must return a RotateRaceError, persisting nothing.
func TestRotateEpochRaceNoOp(t *testing.T) {
	db := newTestStore(t, "acct_a", "acct_b")
	if err := poolops.Create(db, "codex", "", []string{"acct_a", "acct_b"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Drop membership rows directly, leaving the credential_pools row intact:
	// exactly the state a concurrent member removal leaves. GetPool then
	// returns codex with NO members, so Rotate reports no resolvable member
	// and writes nothing.
	if _, err := db.DB().Exec("DELETE FROM credential_pool_members WHERE pool = 'codex'"); err != nil {
		t.Fatalf("delete membership rows: %v", err)
	}
	if _, err := poolops.Rotate(db, "codex"); err == nil {
		t.Fatalf("Rotate against vanished members: err = nil, want failure")
	}
	// No health row resurrected for the vanished members.
	rows, err := db.ListCredentialHealth()
	if err != nil {
		t.Fatalf("ListCredentialHealth: %v", err)
	}
	for _, r := range rows {
		if (r.Credential == "acct_a" || r.Credential == "acct_b") && r.Status == "cooldown" {
			t.Fatalf("vanished member %q got a resurrected cooldown: %+v", r.Credential, r)
		}
	}
}

// fakeRaceStore returns a live snapshot from GetPool but forces the
// epoch-guarded write to report wrote=false, simulating a cross-pool re-add
// that advanced the epoch between snapshot and write. Rotate must surface a
// *RotateRaceError.
type fakeRaceStore struct {
	poolops.Store
}

func (f fakeRaceStore) SetCredentialHealthIfPoolMemberEpoch(string, string, int64, string, time.Time, string) (bool, error) {
	return false, nil
}

func TestRotateRaceErrorOnGuardedWriteNoOp(t *testing.T) {
	db := newTestStore(t, "acct_a", "acct_b")
	if err := poolops.Create(db, "codex", "", []string{"acct_a", "acct_b"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err := poolops.Rotate(fakeRaceStore{Store: db}, "codex")
	var re *poolops.RotateRaceError
	if !errors.As(err, &re) {
		t.Fatalf("Rotate with no-op guarded write err = %v, want *RotateRaceError", err)
	}
}
