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
	if info.Mode().Perm() != 0600 {
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
	os.WriteFile(keyPath, []byte("not a valid age key"), 0600)

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
	os.MkdirAll(keyPath, 0700)

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
