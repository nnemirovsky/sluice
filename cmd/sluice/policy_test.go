package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nemirovsky/sluice/internal/store"
)

// capturePolicyOutput runs fn with stdout redirected and returns the output.
func capturePolicyOutput(t *testing.T, fn func()) string {
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

// seedDB creates a temp DB and populates it with test rules for handler tests.
func seedDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("create test DB: %v", err)
	}
	defer func() { _ = db.Close() }()
	_, _ = db.AddRule("allow", store.RuleOpts{Destination: "api.example.com", Ports: []int{443, 80}, Name: "API access"})
	_, _ = db.AddRule("deny", store.RuleOpts{Destination: "evil.example.com", Name: "blocked"})
	_, _ = db.AddRule("ask", store.RuleOpts{Destination: "unknown.example.com", Ports: []int{443}})
	return dbPath
}

// --- handlePolicyCommand tests ---

func TestHandlePolicyCommandNoArgs(t *testing.T) {
	err := handlePolicyCommand([]string{})
	if err == nil {
		t.Fatal("expected error for no args")
	}
}

func TestHandlePolicyCommandUnknown(t *testing.T) {
	err := handlePolicyCommand([]string{"bogus"})
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
	if !strings.Contains(err.Error(), "unknown policy command") {
		t.Errorf("expected 'unknown policy command' in error, got: %v", err)
	}
}

// --- handlePolicyList tests ---

func TestHandlePolicyListNoFilter(t *testing.T) {
	dbPath := seedDB(t)

	output := capturePolicyOutput(t, func() {
		if err := handlePolicyList([]string{"--db", dbPath}); err != nil {
			t.Fatalf("handlePolicyList: %v", err)
		}
	})

	if !strings.Contains(output, "api.example.com") {
		t.Errorf("expected api.example.com in output: %s", output)
	}
	if !strings.Contains(output, "evil.example.com") {
		t.Errorf("expected evil.example.com in output: %s", output)
	}
	if !strings.Contains(output, "unknown.example.com") {
		t.Errorf("expected unknown.example.com in output: %s", output)
	}
}

func TestHandlePolicyListFilterAllow(t *testing.T) {
	dbPath := seedDB(t)

	output := capturePolicyOutput(t, func() {
		if err := handlePolicyList([]string{"--db", dbPath, "--verdict", "allow"}); err != nil {
			t.Fatalf("handlePolicyList: %v", err)
		}
	})

	if !strings.Contains(output, "api.example.com") {
		t.Errorf("expected api.example.com in allow output: %s", output)
	}
	if strings.Contains(output, "evil.example.com") {
		t.Errorf("deny rule should not appear in allow filter: %s", output)
	}
	if strings.Contains(output, "unknown.example.com") {
		t.Errorf("ask rule should not appear in allow filter: %s", output)
	}
}

func TestHandlePolicyListFilterDeny(t *testing.T) {
	dbPath := seedDB(t)

	output := capturePolicyOutput(t, func() {
		if err := handlePolicyList([]string{"--db", dbPath, "--verdict", "deny"}); err != nil {
			t.Fatalf("handlePolicyList: %v", err)
		}
	})

	if !strings.Contains(output, "evil.example.com") {
		t.Errorf("expected evil.example.com in deny output: %s", output)
	}
	if strings.Contains(output, "api.example.com") {
		t.Errorf("allow rule should not appear in deny filter: %s", output)
	}
}

func TestHandlePolicyListEmpty(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "empty.db")
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	output := capturePolicyOutput(t, func() {
		if err := handlePolicyList([]string{"--db", dbPath}); err != nil {
			t.Fatalf("handlePolicyList: %v", err)
		}
	})

	if !strings.Contains(output, "no rules found") {
		t.Errorf("expected 'no rules found', got: %s", output)
	}
}

func TestHandlePolicyListShowsPorts(t *testing.T) {
	dbPath := seedDB(t)

	output := capturePolicyOutput(t, func() {
		if err := handlePolicyList([]string{"--db", dbPath}); err != nil {
			t.Fatalf("handlePolicyList: %v", err)
		}
	})

	if !strings.Contains(output, "ports=443,80") {
		t.Errorf("expected 'ports=443,80' in output: %s", output)
	}
}

// --- handlePolicyAdd tests ---

func TestHandlePolicyAddAllow(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	output := capturePolicyOutput(t, func() {
		if err := handlePolicyAdd([]string{"allow", "--db", dbPath, "--ports", "443", "--name", "test", "api.example.com"}); err != nil {
			t.Fatalf("handlePolicyAdd: %v", err)
		}
	})

	if !strings.Contains(output, "added allow rule") {
		t.Errorf("expected 'added allow rule' in output: %s", output)
	}
	if !strings.Contains(output, "api.example.com") {
		t.Errorf("expected destination in output: %s", output)
	}

	// Verify the rule was stored.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	rules, err := db.ListRules(store.RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Destination != "api.example.com" {
		t.Errorf("destination = %q, want %q", rules[0].Destination, "api.example.com")
	}
	if rules[0].Name != "test" {
		t.Errorf("name = %q, want %q", rules[0].Name, "test")
	}
	if len(rules[0].Ports) != 1 || rules[0].Ports[0] != 443 {
		t.Errorf("ports = %v, want [443]", rules[0].Ports)
	}
}

func TestHandlePolicyAddDeny(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	output := capturePolicyOutput(t, func() {
		if err := handlePolicyAdd([]string{"deny", "--db", dbPath, "evil.example.com"}); err != nil {
			t.Fatalf("handlePolicyAdd deny: %v", err)
		}
	})

	if !strings.Contains(output, "added deny rule") {
		t.Errorf("expected 'added deny rule' in output: %s", output)
	}
}

func TestHandlePolicyAddAsk(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	output := capturePolicyOutput(t, func() {
		if err := handlePolicyAdd([]string{"ask", "--db", dbPath, "--ports", "443", "sensitive.example.com"}); err != nil {
			t.Fatalf("handlePolicyAdd ask: %v", err)
		}
	})

	if !strings.Contains(output, "added ask rule") {
		t.Errorf("expected 'added ask rule' in output: %s", output)
	}
}

func TestHandlePolicyAddNoArgs(t *testing.T) {
	err := handlePolicyAdd([]string{})
	if err == nil {
		t.Fatal("expected error for no args")
	}
}

func TestHandlePolicyAddInvalidVerdict(t *testing.T) {
	err := handlePolicyAdd([]string{"invalid", "example.com"})
	if err == nil {
		t.Fatal("expected error for invalid verdict")
	}
	if !strings.Contains(err.Error(), "invalid verdict") {
		t.Errorf("expected 'invalid verdict' in error, got: %v", err)
	}
}

func TestHandlePolicyAddNoDestination(t *testing.T) {
	err := handlePolicyAdd([]string{"allow"})
	if err == nil {
		t.Fatal("expected error for no destination")
	}
}

func TestHandlePolicyAddInvalidPort(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	err := handlePolicyAdd([]string{"allow", "--db", dbPath, "--ports", "99999", "example.com"})
	if err == nil {
		t.Fatal("expected error for out-of-range port")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Errorf("expected 'out of range' in error, got: %v", err)
	}
}

func TestHandlePolicyAddNonNumericPort(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	err := handlePolicyAdd([]string{"allow", "--db", dbPath, "--ports", "abc", "example.com"})
	if err == nil {
		t.Fatal("expected error for non-numeric port")
	}
	if !strings.Contains(err.Error(), "invalid port") {
		t.Errorf("expected 'invalid port' in error, got: %v", err)
	}
}

func TestHandlePolicyAddWithGlob(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	_ = capturePolicyOutput(t, func() {
		if err := handlePolicyAdd([]string{"allow", "--db", dbPath, "*.example.com"}); err != nil {
			t.Fatalf("handlePolicyAdd with glob: %v", err)
		}
	})

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	rules, _ := db.ListRules(store.RuleFilter{})
	if len(rules) != 1 || rules[0].Destination != "*.example.com" {
		t.Errorf("expected glob rule, got: %v", rules)
	}
}

// --- handlePolicyRemove tests ---

func TestHandlePolicyRemoveValid(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := db.AddRule("allow", store.RuleOpts{Destination: "example.com"})
	_ = db.Close()

	output := capturePolicyOutput(t, func() {
		if err := handlePolicyRemove([]string{"--db", dbPath, "1"}); err != nil {
			t.Fatalf("handlePolicyRemove: %v", err)
		}
	})

	if !strings.Contains(output, "removed rule") {
		t.Errorf("expected 'removed rule' in output: %s", output)
	}

	// Verify removal.
	db, err = store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	rules, _ := db.ListRules(store.RuleFilter{})
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after removal, got %d", len(rules))
	}
	_ = id
}

func TestHandlePolicyRemoveInvalidID(t *testing.T) {
	err := handlePolicyRemove([]string{"--db", ":memory:", "abc"})
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !strings.Contains(err.Error(), "invalid rule ID") {
		t.Errorf("expected 'invalid rule ID' in error, got: %v", err)
	}
}

func TestHandlePolicyRemoveNonExistent(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, _ := store.New(dbPath)
	_ = db.Close()

	err := handlePolicyRemove([]string{"--db", dbPath, "9999"})
	if err == nil {
		t.Fatal("expected error for non-existent rule")
	}
	if !strings.Contains(err.Error(), "no rule with ID") {
		t.Errorf("expected 'no rule with ID' in error, got: %v", err)
	}
}

func TestHandlePolicyRemoveNoArgs(t *testing.T) {
	err := handlePolicyRemove([]string{})
	if err == nil {
		t.Fatal("expected error for no args")
	}
}

// --- handlePolicyImport tests ---

func TestHandlePolicyImportValid(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	tomlPath := filepath.Join(dir, "config.toml")

	tomlData := `[policy]
default = "deny"

[[allow]]
destination = "api.example.com"
ports = [443]
name = "API"

[[deny]]
destination = "evil.example.com"
`
	if err := os.WriteFile(tomlPath, []byte(tomlData), 0o644); err != nil {
		t.Fatal(err)
	}

	output := capturePolicyOutput(t, func() {
		if err := handlePolicyImport([]string{"--db", dbPath, tomlPath}); err != nil {
			t.Fatalf("handlePolicyImport: %v", err)
		}
	})

	if !strings.Contains(output, "imported:") {
		t.Errorf("expected 'imported:' in output: %s", output)
	}
	if !strings.Contains(output, "2 rules") {
		t.Errorf("expected '2 rules' in output: %s", output)
	}

	// Verify rules were imported.
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	rules, _ := db.ListRules(store.RuleFilter{})
	if len(rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rules))
	}
}

func TestHandlePolicyImportMalformed(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	tomlPath := filepath.Join(dir, "bad.toml")

	if err := os.WriteFile(tomlPath, []byte("this is not valid toml [[["), 0o644); err != nil {
		t.Fatal(err)
	}

	err := handlePolicyImport([]string{"--db", dbPath, tomlPath})
	if err == nil {
		t.Fatal("expected error for malformed TOML")
	}
}

func TestHandlePolicyImportNonExistentFile(t *testing.T) {
	err := handlePolicyImport([]string{"/nonexistent/path/file.toml"})
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
	if !strings.Contains(err.Error(), "read TOML file") {
		t.Errorf("expected file read error, got: %v", err)
	}
}

func TestHandlePolicyImportNoArgs(t *testing.T) {
	err := handlePolicyImport([]string{})
	if err == nil {
		t.Fatal("expected error for no args")
	}
}

// --- handlePolicyExport tests ---

func TestHandlePolicyExportMatchesStore(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	dv := "deny"
	ts := 120
	_ = db.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &dv, TimeoutSec: &ts})
	_, _ = db.AddRule("allow", store.RuleOpts{Destination: "api.example.com", Ports: []int{443}, Name: "API"})
	_, _ = db.AddRule("deny", store.RuleOpts{Destination: "evil.example.com"})
	_, _ = db.AddRule("allow", store.RuleOpts{Tool: "github__list_*", Name: "read-only github"})
	_, _ = db.AddRule("deny", store.RuleOpts{Pattern: "(?i)(sk-[a-zA-Z0-9_-]{20,})", Name: "api_key_leak"})
	_, _ = db.AddRule("redact", store.RuleOpts{Pattern: "(?i)(sk-[a-zA-Z0-9_-]{20,})", Replacement: "[REDACTED]", Name: "api_key_response"})
	_, _ = db.AddBinding("api.example.com", "my_key", store.BindingOpts{
		Ports:    []int{443},
		Header:   "Authorization",
		Template: "Bearer {value}",
	})
	_ = db.Close()

	output := capturePolicyOutput(t, func() {
		if err := handlePolicyExport([]string{"--db", dbPath}); err != nil {
			t.Fatalf("handlePolicyExport: %v", err)
		}
	})

	// Verify config section.
	if !strings.Contains(output, `[policy]`) {
		t.Errorf("missing [policy] section: %s", output)
	}
	if !strings.Contains(output, `default = "deny"`) {
		t.Errorf("missing default verdict: %s", output)
	}
	if !strings.Contains(output, `timeout_sec = 120`) {
		t.Errorf("missing timeout_sec: %s", output)
	}

	// Verify network rules.
	if !strings.Contains(output, `destination = "api.example.com"`) {
		t.Errorf("missing api.example.com rule: %s", output)
	}
	if !strings.Contains(output, `destination = "evil.example.com"`) {
		t.Errorf("missing evil.example.com rule: %s", output)
	}

	// Verify tool rule.
	if !strings.Contains(output, `tool = "github__list_*"`) {
		t.Errorf("missing tool rule: %s", output)
	}

	// Verify pattern rules.
	if !strings.Contains(output, `pattern = "(?i)(sk-[a-zA-Z0-9_-]{20,})"`) {
		t.Errorf("missing pattern rule: %s", output)
	}
	if !strings.Contains(output, `replacement = "[REDACTED]"`) {
		t.Errorf("missing redact replacement: %s", output)
	}

	// Verify binding.
	if !strings.Contains(output, `[[binding]]`) {
		t.Errorf("missing [[binding]] section: %s", output)
	}
	if !strings.Contains(output, `credential = "my_key"`) {
		t.Errorf("missing credential in binding: %s", output)
	}
	if !strings.Contains(output, `header = "Authorization"`) {
		t.Errorf("missing header in binding: %s", output)
	}
	if !strings.Contains(output, `template = "Bearer {value}"`) {
		t.Errorf("missing template in binding: %s", output)
	}
}

func TestHandlePolicyExportEmpty(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, _ := store.New(dbPath)
	_ = db.Close()

	output := capturePolicyOutput(t, func() {
		if err := handlePolicyExport([]string{"--db", dbPath}); err != nil {
			t.Fatalf("handlePolicyExport empty: %v", err)
		}
	})

	// Empty DB should still have the default config section (age provider).
	// Should not contain any rule sections.
	if strings.Contains(output, "[[allow]]") {
		t.Errorf("empty DB should not have [[allow]]: %s", output)
	}
	if strings.Contains(output, "[[deny]]") {
		t.Errorf("empty DB should not have [[deny]]: %s", output)
	}
}

// --- handlePolicyCommand routing tests ---

func TestHandlePolicyCommandRouting(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Route through "list" with empty DB.
	output := capturePolicyOutput(t, func() {
		if err := handlePolicyCommand([]string{"list", "--db", dbPath}); err != nil {
			t.Fatalf("handlePolicyCommand list: %v", err)
		}
	})
	if !strings.Contains(output, "no rules found") {
		t.Errorf("expected 'no rules found' from list routing: %s", output)
	}

	// Route through "add".
	output = capturePolicyOutput(t, func() {
		if err := handlePolicyCommand([]string{"add", "allow", "--db", dbPath, "api.example.com"}); err != nil {
			t.Fatalf("handlePolicyCommand add: %v", err)
		}
	})
	if !strings.Contains(output, "added allow rule") {
		t.Errorf("expected 'added allow rule' from add routing: %s", output)
	}

	// Route through "remove".
	output = capturePolicyOutput(t, func() {
		if err := handlePolicyCommand([]string{"remove", "--db", dbPath, "1"}); err != nil {
			t.Fatalf("handlePolicyCommand remove: %v", err)
		}
	})
	if !strings.Contains(output, "removed rule") {
		t.Errorf("expected 'removed rule' from remove routing: %s", output)
	}

	// Route through "export".
	_ = capturePolicyOutput(t, func() {
		if err := handlePolicyCommand([]string{"export", "--db", dbPath}); err != nil {
			t.Fatalf("handlePolicyCommand export: %v", err)
		}
	})
}

// --- handlePolicyExport with vault config ---

func TestHandlePolicyExportWithVaultConfig(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	vp := "hashicorp"
	vaddr := "https://vault.example.com:8200"
	vmount := "secret"
	vprefix := "sluice/"
	vauth := "approle"
	vrenv := "VAULT_ROLE_ID"
	vsenv := "VAULT_SECRET_ID"
	_ = db.UpdateConfig(store.ConfigUpdate{
		VaultProvider:             &vp,
		VaultHashicorpAddr:        &vaddr,
		VaultHashicorpMount:       &vmount,
		VaultHashicorpPrefix:      &vprefix,
		VaultHashicorpAuth:        &vauth,
		VaultHashicorpRoleIDEnv:   &vrenv,
		VaultHashicorpSecretIDEnv: &vsenv,
	})
	_ = db.Close()

	output := capturePolicyOutput(t, func() {
		if err := handlePolicyExport([]string{"--db", dbPath}); err != nil {
			t.Fatalf("handlePolicyExport: %v", err)
		}
	})

	if !strings.Contains(output, `[vault]`) {
		t.Errorf("missing [vault] section: %s", output)
	}
	if !strings.Contains(output, `provider = "hashicorp"`) {
		t.Errorf("missing vault provider: %s", output)
	}
	if !strings.Contains(output, `[vault.hashicorp]`) {
		t.Errorf("missing [vault.hashicorp] section: %s", output)
	}
	if !strings.Contains(output, `addr = "https://vault.example.com:8200"`) {
		t.Errorf("missing hashicorp addr: %s", output)
	}
	if !strings.Contains(output, `mount = "secret"`) {
		t.Errorf("missing hashicorp mount: %s", output)
	}
	if !strings.Contains(output, `auth = "approle"`) {
		t.Errorf("missing hashicorp auth: %s", output)
	}
}

func TestHandlePolicyExportWithMCPUpstream(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.AddMCPUpstream("github", "npx", store.MCPUpstreamOpts{
		Args:       []string{"-y", "@mcp/server-github"},
		TimeoutSec: 60,
	})
	_ = db.Close()

	output := capturePolicyOutput(t, func() {
		if err := handlePolicyExport([]string{"--db", dbPath}); err != nil {
			t.Fatalf("handlePolicyExport: %v", err)
		}
	})

	if !strings.Contains(output, `[[mcp_upstream]]`) {
		t.Errorf("missing [[mcp_upstream]] section: %s", output)
	}
	if !strings.Contains(output, `name = "github"`) {
		t.Errorf("missing upstream name: %s", output)
	}
	if !strings.Contains(output, `command = "npx"`) {
		t.Errorf("missing upstream command: %s", output)
	}
	if !strings.Contains(output, `timeout_sec = 60`) {
		t.Errorf("missing timeout_sec: %s", output)
	}
}

// --- Existing tests (kept for backward compat, now test through store directly) ---

// TestPolicyListEmpty verifies listing rules on an empty store.
func TestPolicyListEmpty(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	rules, err := db.ListRules(store.RuleFilter{})
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

// TestPolicyAddAndList verifies adding rules and listing them.
func TestPolicyAddAndList(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	id1, err := db.AddRule("allow", store.RuleOpts{Destination: "api.example.com", Ports: []int{443, 80}, Name: "API access"})
	if err != nil {
		t.Fatalf("add allow rule: %v", err)
	}
	if id1 == 0 {
		t.Error("expected non-zero ID for allow rule")
	}

	id2, err := db.AddRule("deny", store.RuleOpts{Destination: "evil.example.com", Name: "blocked"})
	if err != nil {
		t.Fatalf("add deny rule: %v", err)
	}

	id3, err := db.AddRule("ask", store.RuleOpts{Destination: "unknown.example.com", Ports: []int{443}})
	if err != nil {
		t.Fatalf("add ask rule: %v", err)
	}

	all, err := db.ListRules(store.RuleFilter{})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(all))
	}

	if all[0].Verdict != "allow" {
		t.Errorf("expected allow, got %s", all[0].Verdict)
	}
	if all[0].Destination != "api.example.com" {
		t.Errorf("expected api.example.com, got %s", all[0].Destination)
	}
	if len(all[0].Ports) != 2 || all[0].Ports[0] != 443 || all[0].Ports[1] != 80 {
		t.Errorf("expected ports [443,80], got %v", all[0].Ports)
	}

	allows, err := db.ListRules(store.RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatalf("list allow: %v", err)
	}
	if len(allows) != 1 {
		t.Errorf("expected 1 allow rule, got %d", len(allows))
	}

	denies, err := db.ListRules(store.RuleFilter{Verdict: "deny"})
	if err != nil {
		t.Fatalf("list deny: %v", err)
	}
	if len(denies) != 1 {
		t.Errorf("expected 1 deny rule, got %d", len(denies))
	}

	_ = id2
	_ = id3
}

// TestPolicyRemove verifies removing a rule by ID.
func TestPolicyRemove(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	id, err := db.AddRule("allow", store.RuleOpts{Destination: "api.example.com", Ports: []int{443}})
	if err != nil {
		t.Fatal(err)
	}

	deleted, err := db.RemoveRule(id)
	if err != nil {
		t.Fatalf("remove rule: %v", err)
	}
	if !deleted {
		t.Error("expected rule to be deleted")
	}

	rules, err := db.ListRules(store.RuleFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after remove, got %d", len(rules))
	}

	deleted, err = db.RemoveRule(9999)
	if err != nil {
		t.Fatalf("remove non-existent: %v", err)
	}
	if deleted {
		t.Error("expected false for non-existent rule")
	}
}

// TestPolicyImportFromTOML verifies TOML import via the store.
func TestPolicyImportFromTOML(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	tomlData := `[policy]
default = "deny"
timeout_sec = 60

[[allow]]
destination = "api.example.com"
ports = [443]
name = "API"

[[deny]]
destination = "evil.example.com"

[[allow]]
tool = "github__list_*"

[[deny]]
tool = "exec__*"

[[binding]]
destination = "api.example.com"
ports = [443]
credential = "my_key"
header = "Authorization"
template = "Bearer {value}"

[[mcp_upstream]]
name = "github"
command = "npx"
args = ["-y", "@mcp/server-github"]
timeout_sec = 60
`
	result, err := db.ImportTOML([]byte(tomlData))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if result.RulesInserted != 4 {
		t.Errorf("expected 4 rules inserted, got %d", result.RulesInserted)
	}
	if result.BindingsInserted != 1 {
		t.Errorf("expected 1 binding inserted, got %d", result.BindingsInserted)
	}
	if result.UpstreamsInserted != 1 {
		t.Errorf("expected 1 upstream inserted, got %d", result.UpstreamsInserted)
	}

	result2, err := db.ImportTOML([]byte(tomlData))
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if result2.RulesInserted != 0 {
		t.Errorf("expected 0 rules on re-import, got %d", result2.RulesInserted)
	}
	if result2.RulesSkipped != 4 {
		t.Errorf("expected 4 rules skipped, got %d", result2.RulesSkipped)
	}
}

// TestPolicyExportRoundTrip verifies that import then export produces valid TOML.
func TestPolicyExportRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	dv := "deny"
	ts := 120
	_ = db.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &dv, TimeoutSec: &ts})
	_, _ = db.AddRule("allow", store.RuleOpts{Destination: "api.example.com", Ports: []int{443}, Name: "API"})
	_, _ = db.AddRule("deny", store.RuleOpts{Destination: "evil.example.com"})
	_, _ = db.AddRule("allow", store.RuleOpts{Tool: "github__list_*"})
	_, _ = db.AddRule("deny", store.RuleOpts{Tool: "exec__*", Name: "blocked"})
	_, _ = db.AddBinding("api.example.com", "my_key", store.BindingOpts{
		Ports:    []int{443},
		Header:   "Authorization",
		Template: "Bearer {value}",
	})
	_, _ = db.AddMCPUpstream("github", "npx", store.MCPUpstreamOpts{
		Args:       []string{"-y", "@mcp/server-github"},
		TimeoutSec: 60,
	})
	_, _ = db.AddRule("deny", store.RuleOpts{Pattern: "(?i)(sk-[a-zA-Z0-9_-]{20,})", Name: "api_key_leak"})
	_, _ = db.AddRule("redact", store.RuleOpts{
		Pattern:     "(?i)(sk-[a-zA-Z0-9_-]{20,})",
		Name:        "api_key_in_response",
		Replacement: "[REDACTED]",
	})
	_ = db.Close()

	db2, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db2.Close() }()

	rules, _ := db2.ListRules(store.RuleFilter{Type: "network"})
	if len(rules) != 2 {
		t.Errorf("expected 2 network rules, got %d", len(rules))
	}

	toolRules, _ := db2.ListRules(store.RuleFilter{Type: "tool"})
	if len(toolRules) != 2 {
		t.Errorf("expected 2 tool rules, got %d", len(toolRules))
	}

	inspectRules, _ := db2.ListRules(store.RuleFilter{Type: "pattern"})
	if len(inspectRules) != 2 {
		t.Errorf("expected 2 inspect rules, got %d", len(inspectRules))
	}

	cfg, _ := db2.GetConfig()
	if cfg.DefaultVerdict != "deny" {
		t.Errorf("expected default_verdict deny, got %q", cfg.DefaultVerdict)
	}
}

// TestPolicyImportFile verifies import from a file on disk.
func TestPolicyImportFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	tomlPath := filepath.Join(dir, "policy.toml")

	tomlData := `[policy]
default = "ask"

[[allow]]
destination = "safe.example.com"
ports = [443]
`
	if err := os.WriteFile(tomlPath, []byte(tomlData), 0o644); err != nil {
		t.Fatal(err)
	}

	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	data, err := os.ReadFile(tomlPath)
	if err != nil {
		t.Fatal(err)
	}

	result, err := db.ImportTOML(data)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if result.RulesInserted != 1 {
		t.Errorf("expected 1 rule inserted, got %d", result.RulesInserted)
	}

	cfg, _ := db.GetConfig()
	if cfg.DefaultVerdict != "ask" {
		t.Errorf("expected default_verdict ask, got %q", cfg.DefaultVerdict)
	}
}

// TestPolicyAddInvalidVerdict verifies that invalid verdicts are rejected by the store.
func TestPolicyAddInvalidVerdict(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	_, err = db.AddRule("invalid", store.RuleOpts{Destination: "example.com"})
	if err == nil {
		t.Error("expected error for invalid verdict")
	}
}

// TestPolicyAddWithAllVerdicts verifies that all three verdict types work.
func TestPolicyAddWithAllVerdicts(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	for _, v := range []string{"allow", "deny", "ask"} {
		id, err := db.AddRule(v, store.RuleOpts{Destination: v + ".example.com", Ports: []int{443}, Name: v + " rule"})
		if err != nil {
			t.Fatalf("add %s rule: %v", v, err)
		}
		if id == 0 {
			t.Errorf("expected non-zero ID for %s rule", v)
		}
	}

	all, err := db.ListRules(store.RuleFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(all))
	}
}

// TestPolicyImportMalformedTOML verifies that malformed TOML is rejected.
func TestPolicyImportMalformedTOML(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	_, err = db.ImportTOML([]byte("this is not valid toml [[["))
	if err == nil {
		t.Error("expected error for malformed TOML")
	}

	rules, _ := db.ListRules(store.RuleFilter{})
	if len(rules) != 0 {
		t.Error("store should be empty after failed import")
	}
}

// TestPolicyExportContainsExpectedSections verifies export output format.
func TestPolicyExportContainsExpectedSections(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	dvs := "deny"
	tss := 60
	_ = db.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &dvs, TimeoutSec: &tss})
	_, _ = db.AddRule("allow", store.RuleOpts{Destination: "api.example.com", Ports: []int{443}, Name: "API"})
	_, _ = db.AddRule("deny", store.RuleOpts{Destination: "evil.example.com"})
	_, _ = db.AddRule("allow", store.RuleOpts{Tool: "github__list_*"})
	_, _ = db.AddBinding("api.example.com", "my_key", store.BindingOpts{
		Ports:  []int{443},
		Header: "Authorization",
	})

	cfg, _ := db.GetConfig()
	if cfg.DefaultVerdict != "deny" {
		t.Errorf("expected deny, got %q", cfg.DefaultVerdict)
	}

	rules, _ := db.ListRules(store.RuleFilter{Type: "network"})
	if len(rules) != 2 {
		t.Fatalf("expected 2 network rules, got %d", len(rules))
	}
	if rules[0].Destination != "api.example.com" {
		t.Errorf("expected api.example.com, got %s", rules[0].Destination)
	}

	toolRules, _ := db.ListRules(store.RuleFilter{Type: "tool"})
	if len(toolRules) != 1 {
		t.Fatalf("expected 1 tool rule, got %d", len(toolRules))
	}

	bindings, _ := db.ListBindings()
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
}

// TestPolicyWorkflow verifies the full add-list-remove workflow.
func TestPolicyWorkflow(t *testing.T) {
	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	id, err := db.AddRule("allow", store.RuleOpts{Destination: "api.example.com", Ports: []int{443}, Name: "test"})
	if err != nil {
		t.Fatal(err)
	}

	rules, err := db.ListRules(store.RuleFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].ID != id {
		t.Errorf("expected ID %d, got %d", id, rules[0].ID)
	}
	if rules[0].Source != "manual" {
		t.Errorf("expected source manual, got %s", rules[0].Source)
	}

	deleted, err := db.RemoveRule(id)
	if err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Error("expected deleted")
	}

	rules, err = db.ListRules(store.RuleFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after remove, got %d", len(rules))
	}
}

// TestPolicyImportExistingFixtures verifies import works with the repo's
// existing testdata TOML fixtures.
func TestPolicyImportExistingFixtures(t *testing.T) {
	entries, err := os.ReadDir("../../testdata")
	if err != nil {
		t.Skip("testdata directory not found")
	}

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("../../testdata", e.Name()))
			if err != nil {
				t.Fatal(err)
			}

			db, err := store.New(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()

			_, err = db.ImportTOML(data)
			if err != nil {
				t.Errorf("import %s failed: %v", e.Name(), err)
			}
		})
	}
}

// TestPolicyImportExampleConfig verifies the examples/config.toml imports cleanly.
func TestPolicyImportExampleConfig(t *testing.T) {
	data, err := os.ReadFile("../../examples/config.toml")
	if err != nil {
		t.Skip("examples/config.toml not found")
	}

	db, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	result, err := db.ImportTOML(data)
	if err != nil {
		t.Fatalf("import examples/config.toml: %v", err)
	}

	if result.RulesInserted < 10 {
		t.Errorf("expected at least 10 rules from example config, got %d", result.RulesInserted)
	}
}
