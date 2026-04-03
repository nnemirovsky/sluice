package vault

import (
	"os"
	"path/filepath"
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
