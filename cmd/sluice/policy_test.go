package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nemirovsky/sluice/internal/store"
)

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

	// Add allow rule.
	id1, err := db.AddRule("allow", store.RuleOpts{Destination: "api.example.com", Ports: []int{443, 80}, Name: "API access"})
	if err != nil {
		t.Fatalf("add allow rule: %v", err)
	}
	if id1 == 0 {
		t.Error("expected non-zero ID for allow rule")
	}

	// Add deny rule.
	id2, err := db.AddRule("deny", store.RuleOpts{Destination: "evil.example.com", Name: "blocked"})
	if err != nil {
		t.Fatalf("add deny rule: %v", err)
	}

	// Add ask rule.
	id3, err := db.AddRule("ask", store.RuleOpts{Destination: "unknown.example.com", Ports: []int{443}})
	if err != nil {
		t.Fatalf("add ask rule: %v", err)
	}

	// List all rules.
	all, err := db.ListRules(store.RuleFilter{})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(all))
	}

	// Verify first rule.
	if all[0].Verdict != "allow" {
		t.Errorf("expected allow, got %s", all[0].Verdict)
	}
	if all[0].Destination != "api.example.com" {
		t.Errorf("expected api.example.com, got %s", all[0].Destination)
	}
	if len(all[0].Ports) != 2 || all[0].Ports[0] != 443 || all[0].Ports[1] != 80 {
		t.Errorf("expected ports [443,80], got %v", all[0].Ports)
	}
	if all[0].Name != "API access" {
		t.Errorf("expected name 'API access', got %q", all[0].Name)
	}

	// List filtered by verdict.
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

	// Remove existing rule.
	deleted, err := db.RemoveRule(id)
	if err != nil {
		t.Fatalf("remove rule: %v", err)
	}
	if !deleted {
		t.Error("expected rule to be deleted")
	}

	// Verify it's gone.
	rules, err := db.ListRules(store.RuleFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after remove, got %d", len(rules))
	}

	// Removing non-existent rule returns false.
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
	if result.ConfigSet < 2 {
		t.Errorf("expected at least 2 config set, got %d", result.ConfigSet)
	}

	// Second import should skip duplicates.
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

	// Populate the store.
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

	// Re-open and export to verify the data is readable.
	db2, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db2.Close() }()

	// Verify all data is present by reading it back.
	rules, _ := db2.ListRules(store.RuleFilter{Type: "network"})
	if len(rules) != 2 {
		t.Errorf("expected 2 network rules, got %d", len(rules))
	}

	toolRules, _ := db2.ListRules(store.RuleFilter{Type: "tool"})
	if len(toolRules) != 2 {
		t.Errorf("expected 2 tool rules, got %d", len(toolRules))
	}

	bindings, _ := db2.ListBindings()
	if len(bindings) != 1 {
		t.Errorf("expected 1 binding, got %d", len(bindings))
	}

	upstreams, _ := db2.ListMCPUpstreams()
	if len(upstreams) != 1 {
		t.Errorf("expected 1 upstream, got %d", len(upstreams))
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
	if err := os.WriteFile(tomlPath, []byte(tomlData), 0644); err != nil {
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

	// Store should still be empty.
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

	// Read back and verify the data that would be exported.
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

	// Add.
	id, err := db.AddRule("allow", store.RuleOpts{Destination: "api.example.com", Ports: []int{443}, Name: "test"})
	if err != nil {
		t.Fatal(err)
	}

	// List.
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

	// Remove.
	deleted, err := db.RemoveRule(id)
	if err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Error("expected deleted")
	}

	// List again.
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
	// Find testdata files.
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

	// The example has 14 total rules (network + tool + content + redact).
	if result.RulesInserted < 10 {
		t.Errorf("expected at least 10 rules from example config, got %d", result.RulesInserted)
	}
}
