package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
)

// seedPoolCred registers an oauth credential_meta row plus a vault secret so
// it is a valid pool member and a removable credential.
func seedPoolCred(t *testing.T, dbPath, dir, name string) {
	t.Helper()
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AddCredentialMeta(name, "oauth", "https://auth.example.com/token"); err != nil {
		t.Fatalf("add meta %q: %v", name, err)
	}
	_ = db.Close()
	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if _, err := vs.Add(name, `{"access_token":"x","token_url":"https://auth.example.com/token"}`); err != nil {
		t.Fatalf("vault add %q: %v", name, err)
	}
}

func TestHandlePoolCreateListStatusRemove(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)
	seedPoolCred(t, dbPath, dir, "acct_a")
	seedPoolCred(t, dbPath, dir, "acct_b")

	out := captureStdout(t, func() {
		if err := handleCredCommand([]string{}); err == nil {
			t.Error("expected usage error for empty cred args")
		}
		if err := handlePoolCommand([]string{"create", "--db", dbPath, "--members", "acct_a,acct_b", "codex"}); err != nil {
			t.Fatalf("pool create: %v", err)
		}
	})
	if !strings.Contains(out, `pool "codex" created`) {
		t.Errorf("create output = %q", out)
	}

	out = captureStdout(t, func() {
		if err := handlePoolCommand([]string{"list", "--db", dbPath}); err != nil {
			t.Fatalf("pool list: %v", err)
		}
	})
	if !strings.Contains(out, "codex") || !strings.Contains(out, "acct_a, acct_b") {
		t.Errorf("list output = %q", out)
	}

	out = captureStdout(t, func() {
		if err := handlePoolCommand([]string{"status", "--db", dbPath, "codex"}); err != nil {
			t.Fatalf("pool status: %v", err)
		}
	})
	// First member is active.
	if !strings.Contains(out, "* [0] acct_a") || !strings.Contains(out, "active: acct_a") {
		t.Errorf("status output = %q", out)
	}

	// Rotate parks acct_a so acct_b becomes active.
	out = captureStdout(t, func() {
		if err := handlePoolCommand([]string{"rotate", "--db", dbPath, "codex"}); err != nil {
			t.Fatalf("pool rotate: %v", err)
		}
	})
	if !strings.Contains(out, "acct_a -> acct_b") {
		t.Errorf("rotate output = %q", out)
	}
	out = captureStdout(t, func() {
		_ = handlePoolCommand([]string{"status", "--db", dbPath, "codex"})
	})
	if !strings.Contains(out, "active: acct_b") {
		t.Errorf("post-rotate status = %q", out)
	}

	out = captureStdout(t, func() {
		if err := handlePoolCommand([]string{"remove", "--db", dbPath, "codex"}); err != nil {
			t.Fatalf("pool remove: %v", err)
		}
	})
	if !strings.Contains(out, `pool "codex" removed`) {
		t.Errorf("remove output = %q", out)
	}
}

func TestHandlePoolErrorPaths(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)
	seedPoolCred(t, dbPath, dir, "acct_a")

	if err := handlePoolCommand(nil); err == nil {
		t.Error("expected usage error for no args")
	}
	if err := handlePoolCommand([]string{"bogus"}); err == nil {
		t.Error("expected error for unknown subcommand")
	}
	if err := handlePoolCommand([]string{"create", "--db", dbPath, "p"}); err == nil {
		t.Error("expected error for missing --members")
	}
	if err := handlePoolCommand([]string{"status", "--db", dbPath, "missing"}); err == nil {
		t.Error("expected error for status of missing pool")
	}
	if err := handlePoolCommand([]string{"remove", "--db", dbPath, "missing"}); err == nil {
		t.Error("expected error for remove of missing pool")
	}
	// Pool name colliding with an existing credential is rejected.
	if err := handlePoolCommand([]string{"create", "--db", dbPath, "--members", "acct_a", "acct_a"}); err == nil {
		t.Error("expected namespace collision error (pool == credential)")
	}
}

func TestCredAddRejectsPoolNameCollision(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)
	seedPoolCred(t, dbPath, dir, "acct_a")
	if err := handlePoolCommand([]string{"create", "--db", dbPath, "--members", "acct_a", "mypool"}); err != nil {
		t.Fatalf("pool create: %v", err)
	}

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	_, _ = w.Write([]byte("secret\n"))
	_ = w.Close()
	defer func() { os.Stdin = oldStdin }()

	err := handleCredCommand([]string{"add", "--db", dbPath, "mypool"})
	if err == nil || !strings.Contains(err.Error(), "already a credential pool") {
		t.Fatalf("cred add colliding with pool: err = %v, want namespace error", err)
	}
}

func TestCredRemoveBlockedForLivePoolMember(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)
	seedPoolCred(t, dbPath, dir, "acct_a")
	seedPoolCred(t, dbPath, dir, "acct_b")
	if err := handlePoolCommand([]string{"create", "--db", dbPath, "--members", "acct_a,acct_b", "codex"}); err != nil {
		t.Fatalf("pool create: %v", err)
	}

	err := handleCredCommand([]string{"remove", "--db", dbPath, "acct_a"})
	if err == nil || !strings.Contains(err.Error(), "member of pool") {
		t.Fatalf("cred remove of live member: err = %v, want block error", err)
	}
	// Secret must still be present (removal was blocked before vault delete).
	vs, verr := vault.NewStore(dir)
	if verr != nil {
		t.Fatalf("open vault: %v", verr)
	}
	sb, gerr := vs.Get("acct_a")
	if gerr != nil {
		t.Fatalf("credential acct_a was destroyed despite blocked removal: %v", gerr)
	}
	sb.Release()
}

// TestPoolRemoveBlockedWhileBindingReferencesIt asserts that "sluice pool
// remove" refuses while a binding still references the pool by name, then
// succeeds once the binding is gone. Without the guard the pool would be
// deleted out from under the binding, leaving it pointing at a non-existent
// credential (and silently re-applying to any later credential created with
// the same name). Regression for Copilot round-7 finding.
func TestPoolRemoveBlockedWhileBindingReferencesIt(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)
	seedPoolCred(t, dbPath, dir, "acct_a")
	seedPoolCred(t, dbPath, dir, "acct_b")
	if err := handlePoolCommand([]string{"create", "--db", dbPath, "--members", "acct_a,acct_b", "codex"}); err != nil {
		t.Fatalf("pool create: %v", err)
	}

	// binding add <pool> creates a binding whose credential == "codex" plus
	// a paired auto-created allow rule tagged binding-add:codex.
	if err := handleBindingCommand([]string{"add", "--db", dbPath, "--destination", "api.example.com", "codex"}); err != nil {
		t.Fatalf("binding add: %v", err)
	}

	// pool remove must be refused while the binding references the pool.
	err := handlePoolCommand([]string{"remove", "--db", dbPath, "codex"})
	if err == nil {
		t.Fatalf("pool remove with referencing binding: err = nil, want block error")
	}
	if !strings.Contains(err.Error(), "still referenced by") || !strings.Contains(err.Error(), "api.example.com") {
		t.Fatalf("pool remove error = %v, want message naming the blocking binding", err)
	}

	// The pool must still exist (removal was refused before RemovePool).
	db, derr := store.New(dbPath)
	if derr != nil {
		t.Fatalf("open db: %v", derr)
	}
	p, perr := db.GetPool("codex")
	if perr != nil {
		t.Fatalf("get pool after blocked remove: %v", perr)
	}
	if p == nil {
		t.Fatalf("pool %q was deleted despite blocked removal", "codex")
	}
	_ = db.Close()

	// Resolve the blocking binding id and remove it (clears the paired rule
	// too via RemoveBindingWithRuleCleanup).
	db2, derr2 := store.New(dbPath)
	if derr2 != nil {
		t.Fatalf("reopen db: %v", derr2)
	}
	refs, lerr := db2.ListBindingsByCredential("codex")
	if lerr != nil || len(refs) != 1 {
		t.Fatalf("list bindings: refs=%v err=%v", refs, lerr)
	}
	bindingID := refs[0].ID
	_ = db2.Close()

	if err := handleBindingCommand([]string{"remove", "--db", dbPath, strconv.FormatInt(bindingID, 10)}); err != nil {
		t.Fatalf("binding remove: %v", err)
	}

	// With no binding referencing it, pool remove now succeeds.
	out := captureStdout(t, func() {
		if err := handlePoolCommand([]string{"remove", "--db", dbPath, "codex"}); err != nil {
			t.Fatalf("pool remove after binding removed: %v", err)
		}
	})
	if !strings.Contains(out, `pool "codex" removed`) {
		t.Errorf("remove output = %q", out)
	}

	db3, derr3 := store.New(dbPath)
	if derr3 != nil {
		t.Fatalf("reopen db: %v", derr3)
	}
	gone, gerr := db3.GetPool("codex")
	if gerr != nil {
		t.Fatalf("get pool after successful remove: %v", gerr)
	}
	if gone != nil {
		t.Fatalf("pool %q still exists after successful remove", "codex")
	}
	_ = db3.Close()
}

// TestPoolRemoveCleanWithoutReferencingBindings is the no-regression case:
// a pool with no binding referencing it removes cleanly as before.
func TestPoolRemoveCleanWithoutReferencingBindings(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)
	seedPoolCred(t, dbPath, dir, "acct_a")
	seedPoolCred(t, dbPath, dir, "acct_b")
	if err := handlePoolCommand([]string{"create", "--db", dbPath, "--members", "acct_a,acct_b", "codex"}); err != nil {
		t.Fatalf("pool create: %v", err)
	}
	out := captureStdout(t, func() {
		if err := handlePoolCommand([]string{"remove", "--db", dbPath, "codex"}); err != nil {
			t.Fatalf("pool remove (no bindings): %v", err)
		}
	})
	if !strings.Contains(out, `pool "codex" removed`) {
		t.Errorf("remove output = %q", out)
	}
}

// TestCredRemoveFailsClosedWhenDBUnopenable asserts that when the policy DB
// path exists but cannot be opened, cred remove refuses (fails closed)
// instead of logging a warning and deleting the vault secret anyway. A
// continue-on-error here would orphan a credential_pool_members row pointing
// at a now-missing credential -- exactly what the membership guard prevents.
// Regression for Copilot re-review finding 2.
func TestCredRemoveFailsClosedWhenDBUnopenable(t *testing.T) {
	dir := t.TempDir()

	// Put a vault secret in place so we can prove it survives the refused
	// removal. The vault dir is independent of the DB path.
	vs, verr := vault.NewStore(dir)
	if verr != nil {
		t.Fatalf("open vault: %v", verr)
	}
	if _, err := vs.Add("acct_a", `{"access_token":"x"}`); err != nil {
		t.Fatalf("vault add: %v", err)
	}

	// dbPath exists (os.Stat succeeds, so the membership guard is entered)
	// but is a directory, so store.New cannot open it as a SQLite file.
	dbPath := filepath.Join(dir, "broken.db")
	if err := os.Mkdir(dbPath, 0o755); err != nil {
		t.Fatalf("mkdir broken db: %v", err)
	}

	err := handleCredCommand([]string{"remove", "--db", dbPath, "acct_a"})
	if err == nil {
		t.Fatalf("cred remove with unopenable DB: err = nil, want fail-closed error")
	}
	// Fail-closed message. Since Finding 1 (round-13) the vault store is
	// opened/validated FIRST, before the pool-membership gate, so an
	// unopenable DB is caught by openVaultStore ("open store ...") rather
	// than by the membership-guard branch ("refusing to remove ..."). Either
	// wording is an acceptable fail-closed refusal: the invariant the test
	// guards is that the removal aborts BEFORE the vault delete (asserted
	// below by the surviving secret), not the exact message. Accept both.
	msg := err.Error()
	if !strings.Contains(msg, "refusing to remove") && !strings.Contains(msg, "open store") {
		t.Fatalf("cred remove error = %v, want a fail-closed message (containing %q or %q)", err, "refusing to remove", "open store")
	}

	// The secret must still be present: the removal was refused before the
	// vault delete.
	vs2, verr2 := vault.NewStore(dir)
	if verr2 != nil {
		t.Fatalf("reopen vault: %v", verr2)
	}
	sb2, gerr2 := vs2.Get("acct_a")
	if gerr2 != nil {
		t.Fatalf("credential acct_a was destroyed despite refused removal: %v", gerr2)
	}
	sb2.Release()
}
