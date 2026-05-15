package main

import (
	"os"
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
