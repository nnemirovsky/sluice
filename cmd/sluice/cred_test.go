package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
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

	// Capture stdout.
	oldStdout := os.Stdout
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	defer func() { os.Stdout = oldStdout }()

	handleCredCommand([]string{"add", "--db", dbPath, "test_key"})

	_ = outW.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, outR)
	os.Stdout = oldStdout

	output := buf.String()
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

	// Capture stdout.
	oldStdout := os.Stdout
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	defer func() { os.Stdout = oldStdout }()

	handleCredCommand([]string{"list", "--db", dbPath})

	_ = outW.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, outR)
	os.Stdout = oldStdout

	output := buf.String()
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

	// Capture stdout.
	oldStdout := os.Stdout
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	defer func() { os.Stdout = oldStdout }()

	handleCredCommand([]string{"remove", "--db", dbPath, "to_remove"})

	_ = outW.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, outR)
	os.Stdout = oldStdout

	output := buf.String()
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

	// Capture stdout.
	oldStdout := os.Stdout
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	defer func() { os.Stdout = oldStdout }()

	handleCredCommand([]string{"list", "--db", dbPath})

	_ = outW.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, outR)
	os.Stdout = oldStdout

	output := strings.TrimSpace(buf.String())
	if output != "" {
		t.Errorf("expected empty output for empty vault, got: %q", output)
	}
}

// TestHandleCredNoArgs verifies exit 1 when no subcommand is given.
func TestHandleCredNoArgs(t *testing.T) {
	if os.Getenv("TEST_CRED_SUBPROCESS") == "no_args" {
		handleCredCommand([]string{})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHandleCredNoArgs")
	cmd.Env = append(os.Environ(), "TEST_CRED_SUBPROCESS=no_args")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return // expected non-zero exit
	}
	t.Fatal("expected non-zero exit code")
}

// TestHandleCredAddNoName verifies exit 1 when add is called without a name.
func TestHandleCredAddNoName(t *testing.T) {
	if os.Getenv("TEST_CRED_SUBPROCESS") == "add_no_name" {
		handleCredCommand([]string{"add"})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHandleCredAddNoName")
	cmd.Env = append(os.Environ(), "TEST_CRED_SUBPROCESS=add_no_name")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Fatal("expected non-zero exit code")
}

// TestHandleCredRemoveNoName verifies exit 1 when remove is called without a name.
func TestHandleCredRemoveNoName(t *testing.T) {
	if os.Getenv("TEST_CRED_SUBPROCESS") == "remove_no_name" {
		handleCredCommand([]string{"remove"})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHandleCredRemoveNoName")
	cmd.Env = append(os.Environ(), "TEST_CRED_SUBPROCESS=remove_no_name")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Fatal("expected non-zero exit code")
}

// TestHandleCredUnknownSubcommand verifies exit 1 for unknown subcommand.
func TestHandleCredUnknownSubcommand(t *testing.T) {
	if os.Getenv("TEST_CRED_SUBPROCESS") == "unknown" {
		handleCredCommand([]string{"bogus"})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHandleCredUnknownSubcommand")
	cmd.Env = append(os.Environ(), "TEST_CRED_SUBPROCESS=unknown")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Fatal("expected non-zero exit code")
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

	// Capture stdout.
	oldStdout := os.Stdout
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	defer func() { os.Stdout = oldStdout }()

	handleCredCommand([]string{"remove", "--db", dbPath, "does_not_exist"})

	_ = outW.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, outR)
	os.Stdout = oldStdout

	output := buf.String()
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

	// Capture stdout.
	oldStdout := os.Stdout
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	defer func() { os.Stdout = oldStdout }()

	handleCredCommand([]string{
		"add",
		"--db", dbPath,
		"--destination", "api.anthropic.com",
		"--ports", "443",
		"--header", "x-api-key",
		"anthropic_key",
	})

	_ = outW.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, outR)
	os.Stdout = oldStdout

	output := buf.String()
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

	oldStdout := os.Stdout
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	defer func() { os.Stdout = oldStdout }()

	handleCredCommand([]string{
		"add",
		"--db", dbPath,
		"--destination", "api.github.com",
		"--ports", "443",
		"--header", "Authorization",
		"--template", "Bearer {value}",
		"github_token",
	})

	_ = outW.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, outR)
	os.Stdout = oldStdout

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

	// Capture stdout.
	oldStdout := os.Stdout
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	defer func() { os.Stdout = oldStdout }()

	handleCredCommand([]string{"list", "--db", dbPath})

	_ = outW.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, outR)
	os.Stdout = oldStdout

	output := buf.String()
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

	// Capture stdout.
	oldStdout := os.Stdout
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	defer func() { os.Stdout = oldStdout }()

	handleCredCommand([]string{"remove", "--db", dbPath, "cleanup_key"})

	_ = outW.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, outR)
	os.Stdout = oldStdout

	output := buf.String()
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

	oldStdout := os.Stdout
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW

	handleCredCommand([]string{
		"add",
		"--db", dbPath,
		"--destination", "api.test.com",
		"--ports", "443,8443",
		"--header", "X-Custom",
		"--template", "Token {value}",
		"integrated_key",
	})

	_ = outW.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, outR)
	os.Stdout = oldStdout
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
	outR, outW, err = os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW

	handleCredCommand([]string{"remove", "--db", dbPath, "integrated_key"})

	_ = outW.Close()
	buf.Reset()
	_, _ = io.Copy(&buf, outR)
	os.Stdout = oldStdout

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
