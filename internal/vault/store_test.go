package vault

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestAddAndGetCredential(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.Add("github_token", "ghp_abc123secrettoken456")
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	val, err := store.Get("github_token")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer val.Release()
	if val.String() != "ghp_abc123secrettoken456" {
		t.Errorf("expected token, got %q", val.String())
	}

	// Verify the file on disk is encrypted (not plaintext)
	data, _ := os.ReadFile(filepath.Join(dir, "credentials", "github_token.age"))
	if string(data) == "ghp_abc123secrettoken456" {
		t.Error("credential stored in plaintext")
	}
}

func TestGetNonexistentCredential(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.Get("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent credential")
	}
}

func TestListCredentials(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("key_a", "val_a"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("key_b", "val_b"); err != nil {
		t.Fatal(err)
	}

	names, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Errorf("expected 2, got %d", len(names))
	}
}

func TestRemoveCredential(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("key_a", "val_a"); err != nil {
		t.Fatal(err)
	}

	if err := store.Remove("key_a"); err != nil {
		t.Fatal(err)
	}
	_, err = store.Get("key_a")
	if err == nil {
		t.Error("expected error after remove")
	}
}

func TestReadRawCredential(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Write a credential normally.
	ciphertext, err := store.Add("raw_test", "raw_secret_value")
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	// ReadRawCredential should return the encrypted bytes.
	raw, err := store.ReadRawCredential("raw_test")
	if err != nil {
		t.Fatalf("ReadRawCredential: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("expected non-empty raw credential")
	}
	// Raw bytes should match what Add returned.
	if len(ciphertext) != len(raw) {
		t.Errorf("ciphertext length mismatch: Add=%d, ReadRaw=%d", len(ciphertext), len(raw))
	}

	// Nonexistent credential returns nil, nil.
	raw, err = store.ReadRawCredential("nonexistent")
	if err != nil {
		t.Fatalf("ReadRawCredential nonexistent: %v", err)
	}
	if raw != nil {
		t.Errorf("expected nil for nonexistent, got %d bytes", len(raw))
	}
}

func TestWriteRawCredential(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Add a credential, read raw, then write raw to a new name.
	if _, err := store.Add("original", "original_value"); err != nil {
		t.Fatal(err)
	}
	raw, err := store.ReadRawCredential("original")
	if err != nil {
		t.Fatal(err)
	}

	// Write the encrypted bytes to a new name.
	if err := store.WriteRawCredential("copy", raw); err != nil {
		t.Fatalf("WriteRawCredential: %v", err)
	}

	// The copy should decrypt to the same value.
	val, err := store.Get("copy")
	if err != nil {
		t.Fatalf("Get copy: %v", err)
	}
	defer val.Release()
	if val.String() != "original_value" {
		t.Errorf("expected 'original_value', got %q", val.String())
	}
}

func TestWriteRawCredentialPathTraversal(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	err = store.WriteRawCredential("../escape", []byte("data"))
	if err == nil {
		t.Error("expected error for path traversal in WriteRawCredential")
	}
}

// TestRollbackAddRestoresPrevious covers the happy path when nothing else has
// touched the credential: a prior ciphertext is restored.
func TestRollbackAddRestoresPrevious(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Seed the credential so there is a "previous" ciphertext to restore.
	prev, err := store.Add("cas_restore", "first")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Overwrite as if we were the add path that now needs to roll back.
	ours, err := store.Add("cas_restore", "second")
	if err != nil {
		t.Fatalf("overwrite: %v", err)
	}

	owned, rbErr := store.RollbackAdd("cas_restore", prev, ours)
	if rbErr != nil {
		t.Fatalf("RollbackAdd: %v", rbErr)
	}
	if !owned {
		t.Fatalf("expected owned=true when no concurrent writer")
	}

	val, err := store.Get("cas_restore")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer val.Release()
	if val.String() != "first" {
		t.Errorf("expected restored value 'first', got %q", val.String())
	}
}

// TestRollbackAddDeletesNew covers the fresh-create case: prev is nil so the
// rollback should delete the entry we just added.
func TestRollbackAddDeletesNew(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ours, err := store.Add("cas_delete", "fresh")
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	owned, rbErr := store.RollbackAdd("cas_delete", nil, ours)
	if rbErr != nil {
		t.Fatalf("RollbackAdd: %v", rbErr)
	}
	if !owned {
		t.Fatalf("expected owned=true when no concurrent writer")
	}

	if _, err := store.Get("cas_delete"); err == nil {
		t.Error("expected credential to be deleted after rollback")
	}
}

// TestRollbackAddCASMismatchSkipsRestore verifies that a concurrent writer
// that overwrote our ciphertext wins: RollbackAdd leaves their state alone
// and returns owned=false.
func TestRollbackAddCASMismatchSkipsRestore(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	prev, err := store.Add("cas_mismatch", "original")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	ours, err := store.Add("cas_mismatch", "ours")
	if err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	// Simulate a concurrent writer overwriting our ciphertext after we
	// added it but before rollback.
	if _, err := store.Add("cas_mismatch", "winner"); err != nil {
		t.Fatalf("concurrent overwrite: %v", err)
	}

	owned, rbErr := store.RollbackAdd("cas_mismatch", prev, ours)
	if rbErr != nil {
		t.Fatalf("RollbackAdd: %v", rbErr)
	}
	if owned {
		t.Fatalf("expected owned=false when ciphertext was overwritten")
	}

	// Winner's value must still be there.
	val, err := store.Get("cas_mismatch")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer val.Release()
	if val.String() != "winner" {
		t.Errorf("expected winner's value preserved, got %q", val.String())
	}
}

// TestRollbackAddCASMismatchWhenDeleted verifies the case where a concurrent
// writer deleted the credential entirely: RollbackAdd should not recreate it.
func TestRollbackAddCASMismatchWhenDeleted(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ours, err := store.Add("cas_deleted", "ours")
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	// Simulate a concurrent delete.
	if err := store.Remove("cas_deleted"); err != nil {
		t.Fatalf("concurrent remove: %v", err)
	}

	// With prev=nil (fresh create), the CAS mismatch path should leave
	// the vault empty (not re-delete, not restore).
	owned, rbErr := store.RollbackAdd("cas_deleted", nil, ours)
	if rbErr != nil {
		t.Fatalf("RollbackAdd: %v", rbErr)
	}
	if owned {
		t.Fatalf("expected owned=false after concurrent delete")
	}

	if _, err := store.Get("cas_deleted"); err == nil {
		t.Error("expected credential to remain deleted")
	}
}

// TestRollbackAddIdempotent verifies RollbackAdd can be safely called twice
// in a row (e.g. defensive retries). After the first call the CAS will no
// longer match, so the second call must be a no-op instead of clobbering.
func TestRollbackAddIdempotent(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	prev, err := store.Add("cas_idem", "first")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	ours, err := store.Add("cas_idem", "second")
	if err != nil {
		t.Fatalf("overwrite: %v", err)
	}

	// First rollback restores "first".
	owned, rbErr := store.RollbackAdd("cas_idem", prev, ours)
	if rbErr != nil || !owned {
		t.Fatalf("first RollbackAdd: owned=%v err=%v", owned, rbErr)
	}

	// Second rollback should notice the CAS mismatch (ciphertext is now
	// prev, not ours) and skip.
	owned, rbErr = store.RollbackAdd("cas_idem", prev, ours)
	if rbErr != nil {
		t.Fatalf("second RollbackAdd: %v", rbErr)
	}
	if owned {
		t.Fatalf("expected second rollback to be no-op")
	}

	val, err := store.Get("cas_idem")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer val.Release()
	if val.String() != "first" {
		t.Errorf("expected preserved value 'first', got %q", val.String())
	}
}

func TestPathTraversalPrevented(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	cases := []string{
		"../escape",
		"../../etc/passwd",
		"sub/dir",
		"back\\slash",
		"..",
		".",
		"",
	}
	for _, name := range cases {
		if _, err := store.Add(name, "val"); err == nil {
			t.Errorf("expected error for name %q, got nil", name)
		}
		if _, err := store.Get(name); err == nil {
			t.Errorf("expected error for Get(%q), got nil", name)
		}
		if err := store.Remove(name); err == nil {
			t.Errorf("expected error for Remove(%q), got nil", name)
		}
	}
}

// TestLoadOrCreateIdentityCreatesNew verifies that a new identity is generated
// when no key file exists.
func TestLoadOrCreateIdentityCreatesNew(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "vault-key.txt")

	id, err := loadOrCreateIdentity(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateIdentity: %v", err)
	}
	if id == nil {
		t.Fatal("expected non-nil identity")
	}

	// Verify the file was created.
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if !strings.HasPrefix(string(data), "AGE-SECRET-KEY-") {
		t.Errorf("expected AGE-SECRET-KEY prefix, got: %q", string(data[:30]))
	}

	// Verify file permissions are restrictive.
	info, _ := os.Stat(keyPath)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key file perms = %o, want 0600", info.Mode().Perm())
	}
}

// TestLoadOrCreateIdentityLoadsExisting verifies that an existing key file
// is loaded correctly.
func TestLoadOrCreateIdentityLoadsExisting(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "vault-key.txt")

	// Create the identity first.
	id1, err := loadOrCreateIdentity(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Load again. Should get the same identity.
	id2, err := loadOrCreateIdentity(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	if id1.String() != id2.String() {
		t.Errorf("identities should match on reload: %q vs %q", id1.String(), id2.String())
	}
}

// TestLoadOrCreateIdentityCorruptedFile verifies error on a corrupted key file.
func TestLoadOrCreateIdentityCorruptedFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "vault-key.txt")

	// Write garbage.
	_ = os.WriteFile(keyPath, []byte("not a valid age key"), 0o600)

	_, err := loadOrCreateIdentity(keyPath)
	if err == nil {
		t.Fatal("expected error for corrupted key file")
	}
}

// TestLoadOrCreateIdentityUnreadableFile verifies error on permission denied.
func TestLoadOrCreateIdentityUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "vault-key.txt")

	// Create a directory where the file should be. This makes ReadFile fail
	// with a non-IsNotExist error.
	_ = os.MkdirAll(keyPath, 0o700)

	_, err := loadOrCreateIdentity(keyPath)
	if err == nil {
		t.Fatal("expected error for unreadable file")
	}
}

// TestLoadOrCreateIdentityConcurrent verifies that concurrent calls don't
// corrupt the key file. Both should end up with the same identity.
func TestLoadOrCreateIdentityConcurrent(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "vault-key.txt")

	var ids [10]string
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id, err := loadOrCreateIdentity(keyPath)
			if err != nil {
				t.Errorf("goroutine %d: %v", idx, err)
				return
			}
			ids[idx] = id.String()
		}(i)
	}
	wg.Wait()

	// All goroutines should have gotten the same identity.
	first := ""
	for _, s := range ids {
		if s == "" {
			continue // errored goroutine
		}
		if first == "" {
			first = s
		} else if s != first {
			t.Errorf("concurrent identities differ: %q vs %q", first, s)
		}
	}
}

// TestNewStoreCreatesDir verifies that NewStore creates the vault directory.
func TestNewStoreCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "vault")
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s == nil {
		t.Fatal("expected non-nil store")
	}

	// Verify the credentials subdirectory exists.
	info, err := os.Stat(filepath.Join(dir, "credentials"))
	if err != nil {
		t.Fatalf("credentials dir should exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("credentials should be a directory")
	}
}
