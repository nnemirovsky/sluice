package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
)

// setupVaultDB creates a temporary SQLite DB with vault_dir set to the given
// directory so openVaultStore reads from the DB (matching runtime behavior).
func setupVaultDB(t *testing.T, dir string) string {
	t.Helper()
	dbPath := filepath.Join(dir, "test.db")
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("create test DB: %v", err)
	}
	if err := db.UpdateConfig(store.ConfigUpdate{VaultDir: &dir}); err != nil {
		t.Fatalf("set vault_dir: %v", err)
	}
	_ = db.Close()
	return dbPath
}

// captureStdout runs fn with stdout redirected to a pipe and returns the output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	defer func() { os.Stdout = oldStdout }()

	fn()

	_ = outW.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, outR)
	os.Stdout = oldStdout
	return buf.String()
}

// TestOpenVaultStoreNoDB tests openVaultStore with empty dbPath (uses default home dir).
func TestOpenVaultStoreNoDB(t *testing.T) {
	// Set HOME to a writable temp dir so the default vault path is writable.
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	vs, err := openVaultStore("")
	if err != nil {
		t.Fatalf("openVaultStore with empty path: %v", err)
	}
	if vs == nil {
		t.Fatal("expected non-nil vault store")
	}
}

// TestOpenVaultStoreWithVaultDir tests openVaultStore reads vault_dir from DB.
func TestOpenVaultStoreWithVaultDir(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	vs, err := openVaultStore(dbPath)
	if err != nil {
		t.Fatalf("openVaultStore: %v", err)
	}
	if vs == nil {
		t.Fatal("expected non-nil vault store")
	}
}

// TestOpenVaultStoreNonAgeProvider tests that non-age provider returns error.
func TestOpenVaultStoreNonAgeProvider(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	provider := "hashicorp"
	if err := db.UpdateConfig(store.ConfigUpdate{VaultProvider: &provider}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	_, err = openVaultStore(dbPath)
	if err == nil {
		t.Fatal("expected error for non-age provider")
	}
	if !strings.Contains(err.Error(), "hashicorp") {
		t.Errorf("error should mention the configured provider, got: %v", err)
	}
}

// TestOpenVaultStoreChainWithoutAge tests that chain provider without age errors.
func TestOpenVaultStoreChainWithoutAge(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	providers := []string{"hashicorp", "env"}
	if err := db.UpdateConfig(store.ConfigUpdate{VaultProviders: &providers}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	_, err = openVaultStore(dbPath)
	if err == nil {
		t.Fatal("expected error for chain without age")
	}
	if !strings.Contains(err.Error(), "without the age backend") {
		t.Errorf("expected 'without the age backend' in error, got: %v", err)
	}
}

// TestOpenVaultStoreChainAgeNotFirst tests warning when age is not first in chain.
func TestOpenVaultStoreChainAgeNotFirst(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	vaultDir := dir
	providers := []string{"env", "age"}
	if err := db.UpdateConfig(store.ConfigUpdate{VaultDir: &vaultDir, VaultProviders: &providers}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	// Should succeed (warning is logged, not returned as error).
	vs, err := openVaultStore(dbPath)
	if err != nil {
		t.Fatalf("openVaultStore with age not first: %v", err)
	}
	if vs == nil {
		t.Fatal("expected non-nil vault store")
	}
}

// TestOpenVaultStoreNonexistentDB tests that a non-existent DB path
// falls through to default (the file simply doesn't exist yet).
func TestOpenVaultStoreNonexistentDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "doesnotexist.db")

	// Set HOME to a writable temp dir for the default vault path.
	t.Setenv("HOME", dir)

	vs, err := openVaultStore(dbPath)
	if err != nil {
		t.Fatalf("openVaultStore with nonexistent DB: %v", err)
	}
	if vs == nil {
		t.Fatal("expected non-nil vault store")
	}
}

// TestHandleCredAdd tests adding a credential via piped stdin.
func TestHandleCredAdd(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	// Pipe the secret via stdin (non-terminal path).
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	if _, err := w.Write([]byte("my-secret-value\n")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	defer func() { os.Stdin = oldStdin }()

	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{"add", "--db", dbPath, "test_key"}); err != nil {
			t.Fatalf("handleCredCommand add: %v", err)
		}
	})

	if !strings.Contains(output, `credential "test_key" added`) {
		t.Errorf("unexpected output: %s", output)
	}

	// Verify credential was stored and can be retrieved.
	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	sb, err := vs.Get("test_key")
	if err != nil {
		t.Fatalf("get credential: %v", err)
	}
	defer sb.Release()
	if sb.String() != "my-secret-value" {
		t.Errorf("got %q, want %q", sb.String(), "my-secret-value")
	}
}

// TestHandleCredList tests listing credentials.
func TestHandleCredList(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	// Pre-populate some credentials.
	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alpha", "beta", "gamma"} {
		if _, err := vs.Add(name, "secret-"+name); err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
	}

	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{"list", "--db", dbPath}); err != nil {
			t.Fatalf("handleCredCommand list: %v", err)
		}
	})

	for _, name := range []string{"alpha", "beta", "gamma"} {
		if !strings.Contains(output, name) {
			t.Errorf("expected %q in output, got: %s", name, output)
		}
	}
}

// TestHandleCredRemove tests removing a credential.
func TestHandleCredRemove(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	// Pre-populate a credential.
	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Add("to_remove", "secret"); err != nil {
		t.Fatal(err)
	}

	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{"remove", "--db", dbPath, "to_remove"}); err != nil {
			t.Fatalf("handleCredCommand remove: %v", err)
		}
	})

	if !strings.Contains(output, `credential "to_remove" removed`) {
		t.Errorf("unexpected output: %s", output)
	}

	// Verify credential was removed.
	names, err := vs.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if n == "to_remove" {
			t.Error("credential should have been removed")
		}
	}
}

// TestHandleCredListEmpty tests listing when no credentials exist.
func TestHandleCredListEmpty(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	// Initialize the vault so the credentials dir exists.
	_, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{"list", "--db", dbPath}); err != nil {
			t.Fatalf("handleCredCommand list: %v", err)
		}
	})

	output = strings.TrimSpace(output)
	if output != "" {
		t.Errorf("expected empty output for empty vault, got: %q", output)
	}
}

// TestHandleCredNoArgs verifies error when no subcommand is given.
func TestHandleCredNoArgs(t *testing.T) {
	err := handleCredCommand([]string{})
	if err == nil {
		t.Fatal("expected error for no args")
	}
}

// TestHandleCredAddNoName verifies error when add is called without a name.
func TestHandleCredAddNoName(t *testing.T) {
	err := handleCredCommand([]string{"add"})
	if err == nil {
		t.Fatal("expected error for add without name")
	}
}

// TestHandleCredRemoveNoName verifies error when remove is called without a name.
func TestHandleCredRemoveNoName(t *testing.T) {
	err := handleCredCommand([]string{"remove"})
	if err == nil {
		t.Fatal("expected error for remove without name")
	}
}

// TestHandleCredUnknownSubcommand verifies error for unknown subcommand.
func TestHandleCredUnknownSubcommand(t *testing.T) {
	err := handleCredCommand([]string{"bogus"})
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}

// TestHandleCredRemoveNonexistent verifies idempotent behavior when removing
// a credential that does not exist. This allows retrying after partial failures
// where the vault entry was deleted but DB cleanup failed.
func TestHandleCredRemoveNonexistent(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	// Initialize vault so credentials dir exists.
	if _, err := vault.NewStore(dir); err != nil {
		t.Fatal(err)
	}

	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{"remove", "--db", dbPath, "does_not_exist"}); err != nil {
			t.Fatalf("handleCredCommand remove nonexistent: %v", err)
		}
	})

	if !strings.Contains(output, "already removed from vault") {
		t.Errorf("expected 'already removed from vault' message, got: %s", output)
	}
}

// TestHandleCredAddWithDestination tests adding a credential with --destination
// which should auto-create an allow rule and a binding in the store.
func TestHandleCredAddWithDestination(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	// Pipe the secret via stdin.
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	if _, err := w.Write([]byte("sk-ant-abc123\n")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	defer func() { os.Stdin = oldStdin }()

	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{
			"add",
			"--db", dbPath,
			"--destination", "api.anthropic.com",
			"--ports", "443",
			"--header", "x-api-key",
			"anthropic_key",
		}); err != nil {
			t.Fatalf("handleCredCommand add with destination: %v", err)
		}
	})

	if !strings.Contains(output, `credential "anthropic_key" added`) {
		t.Errorf("expected credential added message, got: %s", output)
	}
	if !strings.Contains(output, "added allow rule") {
		t.Errorf("expected allow rule message, got: %s", output)
	}
	if !strings.Contains(output, "added binding") {
		t.Errorf("expected binding message, got: %s", output)
	}

	// Verify the credential is in the vault.
	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	sb, err := vs.Get("anthropic_key")
	if err != nil {
		t.Fatalf("get credential: %v", err)
	}
	defer sb.Release()
	if sb.String() != "sk-ant-abc123" {
		t.Errorf("got %q, want %q", sb.String(), "sk-ant-abc123")
	}

	// Verify the allow rule was created in the store.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()

	rules, err := db.ListRules(store.RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 allow rule, got %d", len(rules))
	}
	if rules[0].Destination != "api.anthropic.com" {
		t.Errorf("rule destination = %q, want %q", rules[0].Destination, "api.anthropic.com")
	}
	if rules[0].Source != credAddSourcePrefix+"anthropic_key" {
		t.Errorf("rule source = %q, want %q", rules[0].Source, credAddSourcePrefix+"anthropic_key")
	}
	if len(rules[0].Ports) != 1 || rules[0].Ports[0] != 443 {
		t.Errorf("rule ports = %v, want [443]", rules[0].Ports)
	}

	// Verify the binding was created.
	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if bindings[0].Destination != "api.anthropic.com" {
		t.Errorf("binding destination = %q, want %q", bindings[0].Destination, "api.anthropic.com")
	}
	if bindings[0].Credential != "anthropic_key" {
		t.Errorf("binding credential = %q, want %q", bindings[0].Credential, "anthropic_key")
	}
	if bindings[0].Header != "x-api-key" {
		t.Errorf("binding header = %q, want %q", bindings[0].Header, "x-api-key")
	}
}

// TestHandleCredAddWithTemplate tests adding a credential with --template.
func TestHandleCredAddWithTemplate(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	if _, err := w.Write([]byte("ghp_abc123\n")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	defer func() { os.Stdin = oldStdin }()

	_ = captureStdout(t, func() {
		if err := handleCredCommand([]string{
			"add",
			"--db", dbPath,
			"--destination", "api.github.com",
			"--ports", "443",
			"--header", "Authorization",
			"--template", "Bearer {value}",
			"github_token",
		}); err != nil {
			t.Fatalf("handleCredCommand add with template: %v", err)
		}
	})

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()

	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if bindings[0].Template != "Bearer {value}" {
		t.Errorf("binding template = %q, want %q", bindings[0].Template, "Bearer {value}")
	}
}

// TestHandleCredListWithBindings tests that cred list shows binding info.
func TestHandleCredListWithBindings(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	// Create a credential in the vault.
	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Add("mykey", "secret"); err != nil {
		t.Fatal(err)
	}

	// Create a binding in the store.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.AddBinding("api.example.com", "mykey", store.BindingOpts{
		Ports:    []int{443},
		Header:   "Authorization",
		Template: "Bearer {value}",
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{"list", "--db", dbPath}); err != nil {
			t.Fatalf("handleCredCommand list: %v", err)
		}
	})

	if !strings.Contains(output, "mykey") {
		t.Errorf("expected credential name in output, got: %s", output)
	}
	if !strings.Contains(output, "api.example.com") {
		t.Errorf("expected destination in output, got: %s", output)
	}
	if !strings.Contains(output, "header=Authorization") {
		t.Errorf("expected header in output, got: %s", output)
	}
}

// TestHandleCredRemoveWithBindings tests that removing a credential also
// removes associated bindings and auto-created rules.
func TestHandleCredRemoveWithBindings(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	// Create a credential in the vault.
	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Add("cleanup_key", "secret"); err != nil {
		t.Fatal(err)
	}

	// Create an auto-generated rule and binding in the store.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.AddRule("allow", store.RuleOpts{
		Destination: "api.cleanup.com",
		Ports:       []int{443},
		Source:      credAddSourcePrefix + "cleanup_key",
		Name:        "auto-created for credential \"cleanup_key\"",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.AddBinding("api.cleanup.com", "cleanup_key", store.BindingOpts{
		Ports:  []int{443},
		Header: "Authorization",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Also add a manually created rule for the same destination (should NOT be removed).
	_, err = db.AddRule("allow", store.RuleOpts{
		Destination: "api.cleanup.com",
		Ports:       []int{80},
		Source:      "manual",
		Name:        "manually added",
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{"remove", "--db", dbPath, "cleanup_key"}); err != nil {
			t.Fatalf("handleCredCommand remove: %v", err)
		}
	})

	if !strings.Contains(output, `credential "cleanup_key" removed`) {
		t.Errorf("expected removal message, got: %s", output)
	}
	if !strings.Contains(output, "removed 1 auto-created rule") {
		t.Errorf("expected rule cleanup message, got: %s", output)
	}
	if !strings.Contains(output, "removed 1 binding") {
		t.Errorf("expected binding cleanup message, got: %s", output)
	}

	// Verify the credential was removed from vault.
	names, err := vs.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if n == "cleanup_key" {
			t.Error("credential should have been removed from vault")
		}
	}

	// Verify the auto-created rule was removed but the manual one remains.
	db, err = store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	rules, err := db.ListRules(store.RuleFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 remaining rule, got %d", len(rules))
	}
	if rules[0].Source != "manual" {
		t.Errorf("remaining rule source = %q, want %q", rules[0].Source, "manual")
	}

	// Verify bindings were removed.
	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 0 {
		t.Errorf("expected 0 bindings, got %d", len(bindings))
	}
}

// TestHandleCredAddThenRemoveIntegrated tests the full add-with-destination
// then remove workflow to verify everything is created and cleaned up correctly.
func TestHandleCredAddThenRemoveIntegrated(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	// Step 1: Add credential with destination.
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	if _, err := w.Write([]byte("real-secret\n")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()

	_ = captureStdout(t, func() {
		if err := handleCredCommand([]string{
			"add",
			"--db", dbPath,
			"--destination", "api.test.com",
			"--ports", "443,8443",
			"--header", "X-Custom",
			"--template", "Token {value}",
			"integrated_key",
		}); err != nil {
			t.Fatalf("handleCredCommand add: %v", err)
		}
	})
	os.Stdin = oldStdin

	// Verify store state after add.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	rules, err := db.ListRules(store.RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule after add, got %d", len(rules))
	}

	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding after add, got %d", len(bindings))
	}
	if len(bindings[0].Ports) != 2 || bindings[0].Ports[0] != 443 || bindings[0].Ports[1] != 8443 {
		t.Errorf("binding ports = %v, want [443, 8443]", bindings[0].Ports)
	}
	_ = db.Close()

	// Step 2: Remove credential.
	_ = captureStdout(t, func() {
		if err := handleCredCommand([]string{"remove", "--db", dbPath, "integrated_key"}); err != nil {
			t.Fatalf("handleCredCommand remove: %v", err)
		}
	})

	// Verify everything was cleaned up.
	db, err = store.New(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer func() { _ = db.Close() }()

	rules, err = db.ListRules(store.RuleFilter{})
	if err != nil {
		t.Fatalf("list rules after remove: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after remove, got %d", len(rules))
	}

	bindings, err = db.ListBindings()
	if err != nil {
		t.Fatalf("list bindings after remove: %v", err)
	}
	if len(bindings) != 0 {
		t.Errorf("expected 0 bindings after remove, got %d", len(bindings))
	}
}

// --- OAuth credential CLI tests ---

// pipeStdin replaces os.Stdin with a pipe containing the given data and returns
// a cleanup function that restores the original stdin.
func pipeStdin(t *testing.T, data string) func() {
	t.Helper()
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	if _, err := w.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	return func() { os.Stdin = oldStdin }
}

// TestHandleCredAddOAuthTypeFlag tests that --type oauth requires --token-url.
func TestHandleCredAddOAuthTypeFlag(t *testing.T) {
	err := handleCredCommand([]string{"add", "--type", "oauth", "test_oauth"})
	if err == nil {
		t.Fatal("expected error when --type=oauth without --token-url")
	}
	if !strings.Contains(err.Error(), "--token-url is required") {
		t.Errorf("expected token-url required error, got: %v", err)
	}
}

// TestHandleCredAddTokenURLWithoutOAuth tests that --token-url is rejected
// for static credentials.
func TestHandleCredAddTokenURLWithoutOAuth(t *testing.T) {
	err := handleCredCommand([]string{
		"add", "--type", "static",
		"--token-url", "https://example.com/token",
		"test_static",
	})
	if err == nil {
		t.Fatal("expected error when --token-url used with --type=static")
	}
	if !strings.Contains(err.Error(), "--token-url is only valid with --type=oauth") {
		t.Errorf("expected token-url-only-oauth error, got: %v", err)
	}
}

// TestHandleCredAddInvalidType tests that an invalid --type is rejected.
func TestHandleCredAddInvalidType(t *testing.T) {
	err := handleCredCommand([]string{"add", "--type", "bogus", "test_cred"})
	if err == nil {
		t.Fatal("expected error for invalid type")
	}
	if !strings.Contains(err.Error(), "invalid credential type") {
		t.Errorf("expected invalid-type error, got: %v", err)
	}
}

// TestHandleCredAddOAuth tests adding an OAuth credential via piped stdin.
func TestHandleCredAddOAuth(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	// Pipe access token and refresh token via stdin (two lines).
	cleanup := pipeStdin(t, "my-access-token\nmy-refresh-token\n")
	defer cleanup()

	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{
			"add",
			"--db", dbPath,
			"--type", "oauth",
			"--token-url", "https://auth.example.com/oauth/token",
			"--destination", "api.example.com",
			"--ports", "443",
			"openai_oauth",
		}); err != nil {
			t.Fatalf("handleCredCommand add oauth: %v", err)
		}
	})

	if !strings.Contains(output, `credential "openai_oauth" added (type: oauth)`) {
		t.Errorf("expected oauth added message, got: %s", output)
	}
	if !strings.Contains(output, "added allow rule") {
		t.Errorf("expected allow rule message, got: %s", output)
	}
	if !strings.Contains(output, "added binding") {
		t.Errorf("expected binding message, got: %s", output)
	}
	// Phantom env var auto-naming was removed. OAuth credentials no longer
	// print auto-generated env var names (explicit --env-var is used instead).
	if strings.Contains(output, "phantom env vars") {
		t.Errorf("unexpected phantom env vars message in output: %s", output)
	}

	// Verify the credential is in the vault as OAuth JSON.
	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	sb, err := vs.Get("openai_oauth")
	if err != nil {
		t.Fatalf("get credential: %v", err)
	}
	defer sb.Release()

	if !vault.IsOAuth(sb.Bytes()) {
		t.Fatal("expected vault content to be OAuth JSON")
	}
	oauthCred, err := vault.ParseOAuth(sb.Bytes())
	if err != nil {
		t.Fatalf("parse oauth: %v", err)
	}
	if oauthCred.AccessToken != "my-access-token" {
		t.Errorf("access token = %q, want %q", oauthCred.AccessToken, "my-access-token")
	}
	if oauthCred.RefreshToken != "my-refresh-token" {
		t.Errorf("refresh token = %q, want %q", oauthCred.RefreshToken, "my-refresh-token")
	}
	if oauthCred.TokenURL != "https://auth.example.com/oauth/token" {
		t.Errorf("token url = %q, want %q", oauthCred.TokenURL, "https://auth.example.com/oauth/token")
	}

	// Verify credential_meta was created.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()

	meta, err := db.GetCredentialMeta("openai_oauth")
	if err != nil {
		t.Fatalf("get credential meta: %v", err)
	}
	if meta == nil {
		t.Fatal("expected credential_meta row")
	}
	if meta.CredType != "oauth" {
		t.Errorf("meta cred_type = %q, want %q", meta.CredType, "oauth")
	}
	if meta.TokenURL != "https://auth.example.com/oauth/token" {
		t.Errorf("meta token_url = %q, want %q", meta.TokenURL, "https://auth.example.com/oauth/token")
	}
}

// TestHandleCredAddOAuthAccessOnly tests adding an OAuth credential with
// only an access token (no refresh token).
func TestHandleCredAddOAuthAccessOnly(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	// Only one line: access token.
	cleanup := pipeStdin(t, "only-access\n")
	defer cleanup()

	_ = captureStdout(t, func() {
		if err := handleCredCommand([]string{
			"add",
			"--db", dbPath,
			"--type", "oauth",
			"--token-url", "https://auth.example.com/token",
			"access_only_oauth",
		}); err != nil {
			t.Fatalf("handleCredCommand add oauth access-only: %v", err)
		}
	})

	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	sb, err := vs.Get("access_only_oauth")
	if err != nil {
		t.Fatalf("get credential: %v", err)
	}
	defer sb.Release()

	oauthCred, err := vault.ParseOAuth(sb.Bytes())
	if err != nil {
		t.Fatalf("parse oauth: %v", err)
	}
	if oauthCred.AccessToken != "only-access" {
		t.Errorf("access token = %q, want %q", oauthCred.AccessToken, "only-access")
	}
	if oauthCred.RefreshToken != "" {
		t.Errorf("refresh token = %q, want empty", oauthCred.RefreshToken)
	}
}

// TestHandleCredAddOAuthEmptyAccess tests that an empty access token is rejected.
func TestHandleCredAddOAuthEmptyAccess(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	// Empty access token line.
	cleanup := pipeStdin(t, "\n")
	defer cleanup()

	err := handleCredCommand([]string{
		"add",
		"--db", dbPath,
		"--type", "oauth",
		"--token-url", "https://auth.example.com/token",
		"empty_access",
	})
	if err == nil {
		t.Fatal("expected error for empty access token")
	}
	if !strings.Contains(err.Error(), "access token is required") {
		t.Errorf("expected access-token-required error, got: %v", err)
	}
}

// TestHandleCredAddOAuthWithoutDestination tests adding an OAuth credential
// without --destination (only credential_meta is stored, no rule/binding).
func TestHandleCredAddOAuthWithoutDestination(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	cleanup := pipeStdin(t, "access-tok\nrefresh-tok\n")
	defer cleanup()

	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{
			"add",
			"--db", dbPath,
			"--type", "oauth",
			"--token-url", "https://auth.example.com/token",
			"nodest_oauth",
		}); err != nil {
			t.Fatalf("handleCredCommand add oauth without destination: %v", err)
		}
	})

	if !strings.Contains(output, `credential "nodest_oauth" added (type: oauth)`) {
		t.Errorf("expected added message, got: %s", output)
	}
	// Should not mention rule or binding.
	if strings.Contains(output, "allow rule") {
		t.Errorf("unexpected allow rule message for no-destination add: %s", output)
	}

	// Verify credential_meta was still created.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()

	meta, err := db.GetCredentialMeta("nodest_oauth")
	if err != nil {
		t.Fatalf("get credential meta: %v", err)
	}
	if meta == nil {
		t.Fatal("expected credential_meta even without --destination")
	}
	if meta.CredType != "oauth" {
		t.Errorf("cred_type = %q, want oauth", meta.CredType)
	}
}

// TestHandleCredListShowsType tests that cred list includes the credential type.
func TestHandleCredListShowsType(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Add a static credential.
	if _, err := vs.Add("github_pat", "ghp_secret"); err != nil {
		t.Fatal(err)
	}

	// Add an OAuth credential (store the JSON blob in vault).
	oauthCred := &vault.OAuthCredential{
		AccessToken:  "real-access",
		RefreshToken: "real-refresh",
		TokenURL:     "https://auth.example.com/token",
	}
	oauthJSON, _ := oauthCred.Marshal()
	if _, err := vs.Add("openai_oauth", string(oauthJSON)); err != nil {
		t.Fatal(err)
	}

	// Create credential_meta for the OAuth credential.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddCredentialMeta("openai_oauth", "oauth", "https://auth.example.com/token"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{"list", "--db", dbPath}); err != nil {
			t.Fatalf("handleCredCommand list: %v", err)
		}
	})

	// Static credential should show [static].
	if !strings.Contains(output, "github_pat [static]") {
		t.Errorf("expected 'github_pat [static]' in output, got: %s", output)
	}
	// OAuth credential should show [oauth].
	if !strings.Contains(output, "openai_oauth [oauth]") {
		t.Errorf("expected 'openai_oauth [oauth]' in output, got: %s", output)
	}
}

// TestHandleCredRemoveOAuth tests that removing an OAuth credential also
// removes the credential_meta row.
func TestHandleCredRemoveOAuth(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	// Create an OAuth credential in vault.
	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	oauthJSON, _ := json.Marshal(map[string]string{
		"access_token": "real-access",
		"token_url":    "https://auth.example.com/token",
	})
	if _, err := vs.Add("oauth_to_remove", string(oauthJSON)); err != nil {
		t.Fatal(err)
	}

	// Create credential_meta row.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddCredentialMeta("oauth_to_remove", "oauth", "https://auth.example.com/token"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{"remove", "--db", dbPath, "oauth_to_remove"}); err != nil {
			t.Fatalf("handleCredCommand remove oauth: %v", err)
		}
	})

	if !strings.Contains(output, `credential "oauth_to_remove" removed`) {
		t.Errorf("expected removal message, got: %s", output)
	}
	if !strings.Contains(output, "removed credential metadata") {
		t.Errorf("expected credential metadata removed message, got: %s", output)
	}

	// Verify credential_meta was deleted.
	db, err = store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	meta, err := db.GetCredentialMeta("oauth_to_remove")
	if err != nil {
		t.Fatal(err)
	}
	if meta != nil {
		t.Error("expected credential_meta to be deleted")
	}
}

// TestHandleCredAddOAuthCreationFlow tests the full OAuth credential creation
// flow: vault storage, credential_meta, rule, and binding.
func TestHandleCredAddOAuthCreationFlow(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	cleanup := pipeStdin(t, "access-123\nrefresh-456\n")
	defer cleanup()

	_ = captureStdout(t, func() {
		if err := handleCredCommand([]string{
			"add",
			"--db", dbPath,
			"--type", "oauth",
			"--token-url", "https://auth0.openai.com/oauth/token",
			"--destination", "api.openai.com",
			"--ports", "443",
			"openai_cred",
		}); err != nil {
			t.Fatalf("handleCredCommand add oauth full: %v", err)
		}
	})

	// Open the DB and verify all artifacts.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// 1. Credential_meta exists with correct type and token_url.
	meta, err := db.GetCredentialMeta("openai_cred")
	if err != nil {
		t.Fatal(err)
	}
	if meta == nil {
		t.Fatal("expected credential_meta row")
	}
	if meta.CredType != "oauth" {
		t.Errorf("meta cred_type = %q, want oauth", meta.CredType)
	}
	if meta.TokenURL != "https://auth0.openai.com/oauth/token" {
		t.Errorf("meta token_url = %q, want https://auth0.openai.com/oauth/token", meta.TokenURL)
	}

	// 2. Allow rule exists for the destination.
	rules, err := db.ListRules(store.RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 allow rule, got %d", len(rules))
	}
	if rules[0].Destination != "api.openai.com" {
		t.Errorf("rule destination = %q, want api.openai.com", rules[0].Destination)
	}

	// 3. Binding exists.
	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if bindings[0].Credential != "openai_cred" {
		t.Errorf("binding credential = %q, want openai_cred", bindings[0].Credential)
	}

	// 4. Vault content is valid OAuth JSON.
	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := vs.Get("openai_cred")
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Release()

	oauthCred, err := vault.ParseOAuth(sb.Bytes())
	if err != nil {
		t.Fatalf("parse oauth: %v", err)
	}
	if oauthCred.AccessToken != "access-123" {
		t.Errorf("access_token = %q, want access-123", oauthCred.AccessToken)
	}
	if oauthCred.RefreshToken != "refresh-456" {
		t.Errorf("refresh_token = %q, want refresh-456", oauthCred.RefreshToken)
	}
}

// TestHandleCredAddOAuthThenRemoveIntegrated tests the full add-then-remove
// lifecycle for OAuth credentials including credential_meta cleanup.
func TestHandleCredAddOAuthThenRemoveIntegrated(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	// Step 1: Add OAuth credential.
	cleanup := pipeStdin(t, "acc-tok\nref-tok\n")
	defer cleanup()

	_ = captureStdout(t, func() {
		if err := handleCredCommand([]string{
			"add",
			"--db", dbPath,
			"--type", "oauth",
			"--token-url", "https://example.com/token",
			"--destination", "api.test.com",
			"--ports", "443",
			"lifecycle_oauth",
		}); err != nil {
			t.Fatalf("add: %v", err)
		}
	})

	// Verify credential_meta exists after add.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	meta, _ := db.GetCredentialMeta("lifecycle_oauth")
	if meta == nil {
		t.Fatal("expected credential_meta after add")
	}
	_ = db.Close()

	// Step 2: Remove.
	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{"remove", "--db", dbPath, "lifecycle_oauth"}); err != nil {
			t.Fatalf("remove: %v", err)
		}
	})

	if !strings.Contains(output, "removed credential metadata") {
		t.Errorf("expected credential metadata removal message, got: %s", output)
	}

	// Verify everything cleaned up.
	db, err = store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	meta, _ = db.GetCredentialMeta("lifecycle_oauth")
	if meta != nil {
		t.Error("credential_meta should be removed")
	}

	rules, _ := db.ListRules(store.RuleFilter{})
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after remove, got %d", len(rules))
	}

	bindings, _ := db.ListBindings()
	if len(bindings) != 0 {
		t.Errorf("expected 0 bindings after remove, got %d", len(bindings))
	}
}

// TestHandleCredAddStaticDefaultType verifies that omitting --type defaults
// to static and output shows (type: static).
func TestHandleCredAddStaticDefaultType(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	cleanup := pipeStdin(t, "plain-secret\n")
	defer cleanup()

	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{"add", "--db", dbPath, "plain_cred"}); err != nil {
			t.Fatalf("add: %v", err)
		}
	})

	if !strings.Contains(output, "(type: static)") {
		t.Errorf("expected '(type: static)' in output, got: %s", output)
	}
}

// TestHandleCredAddWithEnvVar tests adding a credential with --env-var flag.
func TestHandleCredAddWithEnvVar(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	cleanup := pipeStdin(t, "sk-test-secret\n")
	defer cleanup()

	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{
			"add",
			"--db", dbPath,
			"--destination", "api.openai.com",
			"--ports", "443",
			"--header", "Authorization",
			"--template", "Bearer {value}",
			"--env-var", "OPENAI_API_KEY",
			"openai_key",
		}); err != nil {
			t.Fatalf("handleCredCommand add with env-var: %v", err)
		}
	})

	if !strings.Contains(output, `credential "openai_key" added`) {
		t.Errorf("expected credential added message, got: %s", output)
	}
	if !strings.Contains(output, "env var: OPENAI_API_KEY") {
		t.Errorf("expected env var message, got: %s", output)
	}

	// Verify the binding has the env_var set.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()

	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if bindings[0].EnvVar != "OPENAI_API_KEY" {
		t.Errorf("binding env_var = %q, want %q", bindings[0].EnvVar, "OPENAI_API_KEY")
	}
}

// TestHandleCredAddWithoutEnvVar tests that env_var is empty when --env-var is omitted.
func TestHandleCredAddWithoutEnvVar(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	cleanup := pipeStdin(t, "my-secret\n")
	defer cleanup()

	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{
			"add",
			"--db", dbPath,
			"--destination", "api.example.com",
			"--ports", "443",
			"no_env_key",
		}); err != nil {
			t.Fatalf("handleCredCommand add without env-var: %v", err)
		}
	})

	// Should not print env var line when --env-var is not provided.
	if strings.Contains(output, "env var:") {
		t.Errorf("unexpected env var message when --env-var not provided: %s", output)
	}

	// Verify the binding has empty env_var.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()

	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if bindings[0].EnvVar != "" {
		t.Errorf("binding env_var = %q, want empty", bindings[0].EnvVar)
	}
}

// TestHandleCredAddEnvVarRequiresDestination verifies that --env-var without
// --destination returns an error since the env var is stored on the binding.
func TestHandleCredAddEnvVarRequiresDestination(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	cleanup := pipeStdin(t, "my-secret\n")
	defer cleanup()

	err := handleCredCommand([]string{
		"add",
		"--db", dbPath,
		"--env-var", "MY_KEY",
		"test_cred",
	})
	if err == nil {
		t.Fatal("expected error when --env-var is used without --destination")
	}
	if !strings.Contains(err.Error(), "--env-var requires --destination") {
		t.Errorf("error should mention --env-var requires --destination, got: %v", err)
	}
}

// TestHandleCredAddEnvVarFlagParsing tests that --env-var works in different
// argument positions (before name, after name, with =).
func TestHandleCredAddEnvVarFlagParsing(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "env-var before name",
			args: []string{"add", "--env-var", "MY_KEY", "--destination", "api.test.com"},
		},
		{
			name: "env-var after name",
			args: []string{"add", "test_cred", "--env-var", "MY_KEY", "--destination", "api.test.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			dbPath := setupVaultDB(t, dir)

			cleanup := pipeStdin(t, "secret-val\n")
			defer cleanup()

			fullArgs := append([]string{}, tt.args...)
			// Ensure --db is added and a credential name is present.
			fullArgs = append(fullArgs, "--db", dbPath)
			// If args don't end with a non-flag, the positional is already in
			// the args via reorderPositionalLast.
			hasName := false
			for _, a := range tt.args {
				if a == "test_cred" {
					hasName = true
					break
				}
			}
			if !hasName {
				fullArgs = append(fullArgs, "test_cred")
			}

			_ = captureStdout(t, func() {
				if err := handleCredCommand(fullArgs); err != nil {
					t.Fatalf("handleCredCommand: %v", err)
				}
			})

			db, err := store.New(dbPath)
			if err != nil {
				t.Fatalf("open store: %v", err)
			}
			defer func() { _ = db.Close() }()

			bindings, err := db.ListBindings()
			if err != nil {
				t.Fatalf("list bindings: %v", err)
			}
			if len(bindings) != 1 {
				t.Fatalf("expected 1 binding, got %d", len(bindings))
			}
			if bindings[0].EnvVar != "MY_KEY" {
				t.Errorf("binding env_var = %q, want %q", bindings[0].EnvVar, "MY_KEY")
			}
		})
	}
}

// TestHandleCredListShowsEnvVar tests that cred list displays env_var when set.
func TestHandleCredListShowsEnvVar(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	// Create a credential in the vault.
	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Add("my_api_key", "secret"); err != nil {
		t.Fatal(err)
	}

	// Create a binding with env_var set.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.AddBinding("api.example.com", "my_api_key", store.BindingOpts{
		Ports:  []int{443},
		Header: "Authorization",
		EnvVar: "OPENAI_API_KEY",
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{"list", "--db", dbPath}); err != nil {
			t.Fatalf("handleCredCommand list: %v", err)
		}
	})

	if !strings.Contains(output, "env=OPENAI_API_KEY") {
		t.Errorf("expected 'env=OPENAI_API_KEY' in list output, got: %s", output)
	}
}

// TestHandleCredListHidesEnvVarWhenEmpty tests that cred list does not show
// env= when env_var is not set.
func TestHandleCredListHidesEnvVarWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Add("no_env_cred", "secret"); err != nil {
		t.Fatal(err)
	}

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.AddBinding("api.example.com", "no_env_cred", store.BindingOpts{
		Ports: []int{443},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{"list", "--db", dbPath}); err != nil {
			t.Fatalf("handleCredCommand list: %v", err)
		}
	})

	if strings.Contains(output, "env=") {
		t.Errorf("unexpected 'env=' in list output when env_var is empty: %s", output)
	}
}

// TestHandleCredAddMultipleDestinations tests that passing --destination
// multiple times creates one credential in the vault and one allow rule plus
// one binding per destination. All bindings share the same ports/header/
// template supplied via the shared flags.
func TestHandleCredAddMultipleDestinations(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	if _, err := w.Write([]byte("ghp_multi\n")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	defer func() { os.Stdin = oldStdin }()

	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{
			"add",
			"--db", dbPath,
			"--destination", "api.github.com",
			"--destination", "uploads.github.com",
			"--ports", "443",
			"--header", "Authorization",
			"--template", "Bearer {value}",
			"github_pat",
		}); err != nil {
			t.Fatalf("handleCredCommand add with multiple destinations: %v", err)
		}
	})

	if !strings.Contains(output, `credential "github_pat" added`) {
		t.Errorf("expected credential added message, got: %s", output)
	}
	if !strings.Contains(output, "api.github.com") {
		t.Errorf("expected api.github.com in output, got: %s", output)
	}
	if !strings.Contains(output, "uploads.github.com") {
		t.Errorf("expected uploads.github.com in output, got: %s", output)
	}

	// Verify only one credential was stored in the vault.
	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	names, err := vs.List()
	if err != nil {
		t.Fatalf("list vault: %v", err)
	}
	if len(names) != 1 {
		t.Fatalf("expected 1 credential in vault, got %d: %v", len(names), names)
	}
	if names[0] != "github_pat" {
		t.Errorf("vault credential name = %q, want %q", names[0], "github_pat")
	}

	sb, err := vs.Get("github_pat")
	if err != nil {
		t.Fatalf("get credential: %v", err)
	}
	defer sb.Release()
	if sb.String() != "ghp_multi" {
		t.Errorf("vault value = %q, want %q", sb.String(), "ghp_multi")
	}

	// Verify two allow rules were created, one per destination.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()

	rules, err := db.ListRules(store.RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 allow rules, got %d", len(rules))
	}
	ruleDests := map[string]bool{}
	for _, r := range rules {
		ruleDests[r.Destination] = true
		if r.Source != credAddSourcePrefix+"github_pat" {
			t.Errorf("rule source = %q, want %q", r.Source, credAddSourcePrefix+"github_pat")
		}
	}
	if !ruleDests["api.github.com"] || !ruleDests["uploads.github.com"] {
		t.Errorf("missing expected destinations in rules, got: %v", ruleDests)
	}

	// Verify two bindings, one per destination, both pointing at github_pat
	// and sharing the same header/template/ports.
	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 2 {
		t.Fatalf("expected 2 bindings, got %d", len(bindings))
	}
	bindDests := map[string]bool{}
	for _, b := range bindings {
		bindDests[b.Destination] = true
		if b.Credential != "github_pat" {
			t.Errorf("binding credential = %q, want %q", b.Credential, "github_pat")
		}
		if b.Header != "Authorization" {
			t.Errorf("binding header = %q, want %q", b.Header, "Authorization")
		}
		if b.Template != "Bearer {value}" {
			t.Errorf("binding template = %q, want %q", b.Template, "Bearer {value}")
		}
		if len(b.Ports) != 1 || b.Ports[0] != 443 {
			t.Errorf("binding ports = %v, want [443]", b.Ports)
		}
	}
	if !bindDests["api.github.com"] || !bindDests["uploads.github.com"] {
		t.Errorf("missing expected destinations in bindings, got: %v", bindDests)
	}
}

// TestHandleCredAddSingleDestinationBackwardCompat ensures that the single
// --destination form still works identically after the flag was made
// repeatable.
func TestHandleCredAddSingleDestinationBackwardCompat(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	if _, err := w.Write([]byte("single-secret\n")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	defer func() { os.Stdin = oldStdin }()

	_ = captureStdout(t, func() {
		if err := handleCredCommand([]string{
			"add",
			"--db", dbPath,
			"--destination", "api.single.com",
			"--ports", "443",
			"--header", "Authorization",
			"single_key",
		}); err != nil {
			t.Fatalf("handleCredCommand add single destination: %v", err)
		}
	})

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()

	rules, err := db.ListRules(store.RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Destination != "api.single.com" {
		t.Errorf("rule destination = %q, want %q", rules[0].Destination, "api.single.com")
	}

	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if bindings[0].Destination != "api.single.com" {
		t.Errorf("binding destination = %q, want %q", bindings[0].Destination, "api.single.com")
	}
}

// TestHandleCredAddNoDestinationStillWorks verifies that omitting --destination
// still allows creating a credential in the vault without any rules or bindings.
func TestHandleCredAddNoDestinationStillWorks(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	if _, err := w.Write([]byte("bare-secret\n")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	defer func() { os.Stdin = oldStdin }()

	output := captureStdout(t, func() {
		if err := handleCredCommand([]string{
			"add",
			"--db", dbPath,
			"bare_key",
		}); err != nil {
			t.Fatalf("handleCredCommand add without destination: %v", err)
		}
	})

	if !strings.Contains(output, `credential "bare_key" added`) {
		t.Errorf("expected credential added message, got: %s", output)
	}
	if strings.Contains(output, "added allow rule") {
		t.Errorf("did not expect rule creation message, got: %s", output)
	}
	if strings.Contains(output, "added binding") {
		t.Errorf("did not expect binding creation message, got: %s", output)
	}

	// Verify no rules or bindings were created.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()

	rules, err := db.ListRules(store.RuleFilter{})
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}

	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 0 {
		t.Errorf("expected 0 bindings, got %d", len(bindings))
	}

	// Verify the credential is in the vault.
	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	sb, err := vs.Get("bare_key")
	if err != nil {
		t.Fatalf("get credential: %v", err)
	}
	defer sb.Release()
	if sb.String() != "bare-secret" {
		t.Errorf("vault value = %q, want %q", sb.String(), "bare-secret")
	}
}

// TestHandleCredAddMultipleDestinationsBadPortRollback verifies that when
// a port is invalid, nothing is written to the vault or the DB. This tests
// the upfront-validation path: failures before any DB or vault writes should
// leave the system in a clean state when multiple destinations are supplied.
func TestHandleCredAddMultipleDestinationsBadPortRollback(t *testing.T) {
	dir := t.TempDir()
	dbPath := setupVaultDB(t, dir)

	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	if _, err := w.Write([]byte("rollback-secret\n")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	defer func() { os.Stdin = oldStdin }()

	// Invalid port triggers a validation error after destination validation
	// but before any vault or DB writes.
	err = handleCredCommand([]string{
		"add",
		"--db", dbPath,
		"--destination", "api.first.com",
		"--destination", "api.second.com",
		"--ports", "70000",
		"rollback_key",
	})
	if err == nil {
		t.Fatal("expected error for out-of-range port")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Errorf("expected out-of-range error, got: %v", err)
	}

	// Verify no rules or bindings were created (validation fails before DB writes).
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()

	rules, err := db.ListRules(store.RuleFilter{})
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after rollback, got %d", len(rules))
	}

	bindings, err := db.ListBindings()
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 0 {
		t.Errorf("expected 0 bindings after rollback, got %d", len(bindings))
	}

	// Verify no credential was stored in the vault (validation ran before vault write).
	vs, err := vault.NewStore(dir)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	names, err := vs.List()
	if err != nil {
		t.Fatalf("list vault: %v", err)
	}
	for _, n := range names {
		if n == "rollback_key" {
			t.Error("credential should not have been added to vault after validation failure")
		}
	}
}
