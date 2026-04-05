package store

import (
	"fmt"
	"os"
	"sync"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// --- Schema migration tests ---

func TestNewCreatesSchema(t *testing.T) {
	s := newTestStore(t)
	// Verify all 5 tables exist by querying them.
	tables := []string{"rules", "config", "bindings", "mcp_upstreams", "channels"}
	for _, table := range tables {
		var count int
		err := s.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count)
		if err != nil {
			t.Fatalf("table %q should exist: %v", table, err)
		}
	}

	// Verify rules table is empty.
	var ruleCount int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM rules").Scan(&ruleCount)
	if ruleCount != 0 {
		t.Errorf("rules table should be empty, got %d", ruleCount)
	}

	// Verify config singleton row exists with defaults.
	var defaultVerdict string
	var timeoutSec int
	err := s.db.QueryRow("SELECT default_verdict, timeout_sec FROM config WHERE id = 1").Scan(&defaultVerdict, &timeoutSec)
	if err != nil {
		t.Fatalf("config singleton should exist: %v", err)
	}
	if defaultVerdict != "deny" {
		t.Errorf("default verdict = %q, want deny", defaultVerdict)
	}
	if timeoutSec != 120 {
		t.Errorf("timeout_sec = %d, want 120", timeoutSec)
	}

	// Verify channels default row exists.
	var channelType, enabled int
	err = s.db.QueryRow("SELECT type, enabled FROM channels WHERE id = 1").Scan(&channelType, &enabled)
	if err != nil {
		t.Fatalf("channels default row should exist: %v", err)
	}
	if channelType != 0 {
		t.Errorf("channel type = %d, want 0 (Telegram)", channelType)
	}
	if enabled != 1 {
		t.Errorf("channel enabled = %d, want 1", enabled)
	}
}

func TestNewCreatesSchemaCorrectColumns(t *testing.T) {
	s := newTestStore(t)

	// Verify rules table columns by inserting a row with all fields.
	_, err := s.db.Exec(
		`INSERT INTO rules (verdict, destination, ports, protocols, name, source)
		 VALUES ('allow', 'test.com', '[443]', '["https"]', 'test', 'manual')`,
	)
	if err != nil {
		t.Fatalf("insert into rules with destination: %v", err)
	}

	_, err = s.db.Exec(
		`INSERT INTO rules (verdict, tool, name, source)
		 VALUES ('allow', 'github__list_*', 'read-only', 'manual')`,
	)
	if err != nil {
		t.Fatalf("insert into rules with tool: %v", err)
	}

	_, err = s.db.Exec(
		`INSERT INTO rules (verdict, pattern, replacement, name, source)
		 VALUES ('redact', 'sk-[a-z]+', '[REDACTED]', 'api keys', 'manual')`,
	)
	if err != nil {
		t.Fatalf("insert into rules with pattern: %v", err)
	}

	// Verify bindings table has renamed columns.
	_, err = s.db.Exec(
		`INSERT INTO bindings (destination, credential, header, template, protocols)
		 VALUES ('api.test.com', 'my_key', 'Authorization', 'Bearer {value}', '["https"]')`,
	)
	if err != nil {
		t.Fatalf("insert into bindings with new columns: %v", err)
	}
}

func TestNewIdempotentMigration(t *testing.T) {
	s := newTestStore(t)
	// Run migrations again. Should not fail (no change).
	if err := runMigrations(s.db); err != nil {
		t.Fatalf("second migration should be idempotent: %v", err)
	}
}

func TestRulesCheckConstraint(t *testing.T) {
	s := newTestStore(t)

	// Setting both destination and tool should violate the CHECK constraint.
	_, err := s.db.Exec(
		`INSERT INTO rules (verdict, destination, tool, source) VALUES ('allow', 'test.com', 'github__*', 'manual')`,
	)
	if err == nil {
		t.Error("setting both destination and tool should violate CHECK constraint")
	}

	// Setting both destination and pattern should violate the CHECK constraint.
	_, err = s.db.Exec(
		`INSERT INTO rules (verdict, destination, pattern, source) VALUES ('deny', 'test.com', 'sk-.*', 'manual')`,
	)
	if err == nil {
		t.Error("setting both destination and pattern should violate CHECK constraint")
	}

	// Setting none of destination/tool/pattern should violate the CHECK constraint.
	_, err = s.db.Exec(
		`INSERT INTO rules (verdict, source) VALUES ('allow', 'manual')`,
	)
	if err == nil {
		t.Error("setting none of destination/tool/pattern should violate CHECK constraint")
	}
}

// --- Unified Rule CRUD ---

func TestAddRuleNetwork(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddRule("allow", RuleOpts{
		Destination: "api.example.com",
		Ports:       []int{443, 80},
		Protocols:   []string{"https"},
		Name:        "test rule",
		Source:      "seed",
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}
	if id < 1 {
		t.Fatalf("expected positive id, got %d", id)
	}

	rules, err := s.ListRules(RuleFilter{Type: "network"})
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.ID != id {
		t.Errorf("id mismatch: %d != %d", r.ID, id)
	}
	if r.Verdict != "allow" {
		t.Errorf("verdict = %q, want allow", r.Verdict)
	}
	if r.Destination != "api.example.com" {
		t.Errorf("destination = %q", r.Destination)
	}
	if len(r.Ports) != 2 || r.Ports[0] != 443 || r.Ports[1] != 80 {
		t.Errorf("ports = %v, want [443 80]", r.Ports)
	}
	if len(r.Protocols) != 1 || r.Protocols[0] != "https" {
		t.Errorf("protocols = %v, want [https]", r.Protocols)
	}
	if r.Name != "test rule" {
		t.Errorf("name = %q", r.Name)
	}
	if r.Source != "seed" {
		t.Errorf("source = %q", r.Source)
	}
}

func TestAddRuleTool(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddRule("allow", RuleOpts{
		Tool:   "github__list_*",
		Name:   "read-only GitHub",
		Source: "seed",
	})
	if err != nil {
		t.Fatalf("add tool rule: %v", err)
	}
	if id < 1 {
		t.Fatal("expected positive id")
	}

	rules, err := s.ListRules(RuleFilter{Type: "tool"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1, got %d", len(rules))
	}
	r := rules[0]
	if r.Verdict != "allow" || r.Tool != "github__list_*" || r.Name != "read-only GitHub" || r.Source != "seed" {
		t.Errorf("unexpected values: %+v", r)
	}
}

func TestAddRulePattern(t *testing.T) {
	s := newTestStore(t)

	// Content deny (block) rule.
	id1, err := s.AddRule("deny", RuleOpts{
		Pattern: `sk-[a-zA-Z0-9]+`,
		Name:    "API keys",
	})
	if err != nil {
		t.Fatalf("add deny pattern rule: %v", err)
	}

	// Content redact rule.
	id2, err := s.AddRule("redact", RuleOpts{
		Pattern:     `\d{3}-\d{2}-\d{4}`,
		Replacement: "[REDACTED]",
		Name:        "SSNs",
	})
	if err != nil {
		t.Fatalf("add redact rule: %v", err)
	}

	rules, err := s.ListRules(RuleFilter{Type: "pattern"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2, got %d", len(rules))
	}
	if rules[0].ID != id1 || rules[0].Pattern != `sk-[a-zA-Z0-9]+` || rules[0].Verdict != "deny" {
		t.Errorf("unexpected rule[0]: %+v", rules[0])
	}
	if rules[1].ID != id2 || rules[1].Replacement != "[REDACTED]" || rules[1].Verdict != "redact" {
		t.Errorf("unexpected rule[1]: %+v", rules[1])
	}
}

func TestAddRuleDefaultSource(t *testing.T) {
	s := newTestStore(t)
	_, err := s.AddRule("deny", RuleOpts{Destination: "evil.com"})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}
	rules, err := s.ListRules(RuleFilter{Type: "network"})
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if rules[0].Source != "manual" {
		t.Errorf("default source = %q, want manual", rules[0].Source)
	}
	if rules[0].Ports != nil {
		t.Errorf("ports should be nil, got %v", rules[0].Ports)
	}
}

func TestAddRuleValidation(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.AddRule("", RuleOpts{Destination: "example.com"}); err == nil {
		t.Error("empty verdict should fail")
	}
	if _, err := s.AddRule("allow", RuleOpts{}); err == nil {
		t.Error("no destination/tool/pattern should fail")
	}
}

func TestAddRuleInvalidVerdict(t *testing.T) {
	s := newTestStore(t)
	_, err := s.AddRule("block", RuleOpts{Destination: "example.com"})
	if err == nil {
		t.Error("invalid verdict should fail")
	}
}

func TestAddRuleMutualExclusivity(t *testing.T) {
	s := newTestStore(t)

	// Destination + tool.
	_, err := s.AddRule("allow", RuleOpts{Destination: "example.com", Tool: "github__*"})
	if err == nil {
		t.Error("destination + tool should fail mutual exclusivity check")
	}

	// Destination + pattern.
	_, err = s.AddRule("deny", RuleOpts{Destination: "example.com", Pattern: "sk-.*"})
	if err == nil {
		t.Error("destination + pattern should fail mutual exclusivity check")
	}

	// Tool + pattern.
	_, err = s.AddRule("deny", RuleOpts{Tool: "exec__*", Pattern: "sk-.*"})
	if err == nil {
		t.Error("tool + pattern should fail mutual exclusivity check")
	}

	// All three.
	_, err = s.AddRule("deny", RuleOpts{Destination: "example.com", Tool: "exec__*", Pattern: "sk-.*"})
	if err == nil {
		t.Error("all three should fail mutual exclusivity check")
	}
}

func TestAddRuleRedactRequiresPattern(t *testing.T) {
	s := newTestStore(t)
	// Redact with destination but no pattern should fail.
	_, err := s.AddRule("redact", RuleOpts{Destination: "example.com"})
	if err == nil {
		t.Error("redact rule with destination (no pattern) should fail")
	}
	// Redact with tool but no pattern should fail.
	_, err = s.AddRule("redact", RuleOpts{Tool: "exec__*"})
	if err == nil {
		t.Error("redact rule with tool (no pattern) should fail")
	}
	// Redact with pattern should succeed.
	_, err = s.AddRule("redact", RuleOpts{Pattern: "sk-.*", Replacement: "[REDACTED]"})
	if err != nil {
		t.Errorf("redact rule with pattern should succeed: %v", err)
	}
}

func TestAddRuleInvalidPort(t *testing.T) {
	s := newTestStore(t)
	_, err := s.AddRule("allow", RuleOpts{Destination: "example.com", Ports: []int{0}})
	if err == nil {
		t.Error("port 0 should fail validation")
	}
	_, err = s.AddRule("allow", RuleOpts{Destination: "example.com", Ports: []int{70000}})
	if err == nil {
		t.Error("port 70000 should fail validation")
	}
	_, err = s.AddRule("allow", RuleOpts{Destination: "example.com", Ports: []int{443}})
	if err != nil {
		t.Errorf("port 443 should succeed: %v", err)
	}
}

func TestRemoveRule(t *testing.T) {
	s := newTestStore(t)
	id, _ := s.AddRule("allow", RuleOpts{Destination: "example.com"})
	ok, err := s.RemoveRule(id)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !ok {
		t.Error("expected true for existing rule")
	}
	ok, err = s.RemoveRule(id)
	if err != nil {
		t.Fatalf("remove again: %v", err)
	}
	if ok {
		t.Error("expected false for already-deleted rule")
	}
}

func TestRemoveRuleUnified(t *testing.T) {
	s := newTestStore(t)

	// RemoveRule works on any rule type (network, tool, pattern).
	id1, _ := s.AddRule("allow", RuleOpts{Destination: "example.com"})
	id2, _ := s.AddRule("allow", RuleOpts{Tool: "github__list_*"})
	id3, _ := s.AddRule("deny", RuleOpts{Pattern: `sk-[a-z]+`})

	ok, _ := s.RemoveRule(id2)
	if !ok {
		t.Error("remove tool rule should return true")
	}
	ok, _ = s.RemoveRule(id3)
	if !ok {
		t.Error("remove pattern rule should return true")
	}
	ok, _ = s.RemoveRule(id1)
	if !ok {
		t.Error("remove network rule should return true")
	}

	all, _ := s.ListRules(RuleFilter{})
	if len(all) != 0 {
		t.Errorf("expected 0 rules after removing all, got %d", len(all))
	}
}

func TestListRulesFilterByVerdict(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddRule("allow", RuleOpts{Destination: "a.com"})
	_, _ = s.AddRule("deny", RuleOpts{Destination: "b.com"})
	_, _ = s.AddRule("ask", RuleOpts{Destination: "c.com"})
	_, _ = s.AddRule("allow", RuleOpts{Destination: "d.com"})

	allows, _ := s.ListRules(RuleFilter{Verdict: "allow", Type: "network"})
	if len(allows) != 2 {
		t.Errorf("expected 2 allow rules, got %d", len(allows))
	}
	denies, _ := s.ListRules(RuleFilter{Verdict: "deny", Type: "network"})
	if len(denies) != 1 {
		t.Errorf("expected 1 deny rule, got %d", len(denies))
	}
	all, _ := s.ListRules(RuleFilter{Type: "network"})
	if len(all) != 4 {
		t.Errorf("expected 4 total network rules, got %d", len(all))
	}
}

func TestListRulesFilterByType(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddRule("allow", RuleOpts{Destination: "a.com"})
	_, _ = s.AddRule("allow", RuleOpts{Tool: "github__list_*"})
	_, _ = s.AddRule("deny", RuleOpts{Pattern: `sk-[a-zA-Z0-9]+`})

	network, _ := s.ListRules(RuleFilter{Type: "network"})
	if len(network) != 1 {
		t.Errorf("expected 1 network rule, got %d", len(network))
	}
	if network[0].Destination != "a.com" {
		t.Errorf("expected a.com, got %q", network[0].Destination)
	}

	tool, _ := s.ListRules(RuleFilter{Type: "tool"})
	if len(tool) != 1 {
		t.Errorf("expected 1 tool rule, got %d", len(tool))
	}
	if tool[0].Tool != "github__list_*" {
		t.Errorf("expected github__list_*, got %q", tool[0].Tool)
	}

	pattern, _ := s.ListRules(RuleFilter{Type: "pattern"})
	if len(pattern) != 1 {
		t.Errorf("expected 1 pattern rule, got %d", len(pattern))
	}

	all, _ := s.ListRules(RuleFilter{})
	if len(all) != 3 {
		t.Errorf("expected 3 total rules, got %d", len(all))
	}
}

func TestListRulesFilterVerdictAndType(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddRule("allow", RuleOpts{Tool: "tool_a"})
	_, _ = s.AddRule("deny", RuleOpts{Tool: "tool_b"})
	_, _ = s.AddRule("ask", RuleOpts{Tool: "tool_c"})

	allows, _ := s.ListRules(RuleFilter{Verdict: "allow", Type: "tool"})
	if len(allows) != 1 {
		t.Errorf("expected 1 allow tool rule, got %d", len(allows))
	}
	all, _ := s.ListRules(RuleFilter{Type: "tool"})
	if len(all) != 3 {
		t.Errorf("expected 3 total tool rules, got %d", len(all))
	}
}

// --- Config ---

func TestConfigGetDefaults(t *testing.T) {
	s := newTestStore(t)
	cfg, err := s.GetConfig()
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	if cfg.DefaultVerdict != "deny" {
		t.Errorf("default verdict = %q, want deny", cfg.DefaultVerdict)
	}
	if cfg.TimeoutSec != 120 {
		t.Errorf("timeout_sec = %d, want 120", cfg.TimeoutSec)
	}
	if cfg.VaultProvider != "age" {
		t.Errorf("vault_provider = %q, want age", cfg.VaultProvider)
	}
	if cfg.VaultDir != "" {
		t.Errorf("vault_dir = %q, want empty", cfg.VaultDir)
	}
	if cfg.VaultProviders != nil {
		t.Errorf("vault_providers = %v, want nil", cfg.VaultProviders)
	}
}

func TestConfigUpdatePartial(t *testing.T) {
	s := newTestStore(t)

	// Update only default_verdict.
	verdict := "ask"
	if err := s.UpdateConfig(ConfigUpdate{DefaultVerdict: &verdict}); err != nil {
		t.Fatalf("update: %v", err)
	}
	cfg, _ := s.GetConfig()
	if cfg.DefaultVerdict != "ask" {
		t.Errorf("default verdict = %q, want ask", cfg.DefaultVerdict)
	}
	// Other fields should remain at defaults.
	if cfg.TimeoutSec != 120 {
		t.Errorf("timeout_sec = %d, want 120", cfg.TimeoutSec)
	}
}

func TestConfigUpdateFull(t *testing.T) {
	s := newTestStore(t)

	verdict := "allow"
	timeout := 60
	provider := "hashicorp"
	dir := "/tmp/vault"
	providers := []string{"age", "hashicorp"}
	addr := "https://vault.example.com:8200"
	mount := "kv"
	prefix := "sluice/"
	auth := "approle"
	roleID := "my-role"
	secretID := "my-secret"
	roleIDEnv := "ROLE_ID"
	secretIDEnv := "SECRET_ID"

	err := s.UpdateConfig(ConfigUpdate{
		DefaultVerdict:            &verdict,
		TimeoutSec:                &timeout,
		VaultProvider:             &provider,
		VaultDir:                  &dir,
		VaultProviders:            &providers,
		VaultHashicorpAddr:        &addr,
		VaultHashicorpMount:       &mount,
		VaultHashicorpPrefix:      &prefix,
		VaultHashicorpAuth:        &auth,
		VaultHashicorpRoleID:      &roleID,
		VaultHashicorpSecretID:    &secretID,
		VaultHashicorpRoleIDEnv:   &roleIDEnv,
		VaultHashicorpSecretIDEnv: &secretIDEnv,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	cfg, _ := s.GetConfig()
	if cfg.DefaultVerdict != "allow" {
		t.Errorf("default verdict = %q", cfg.DefaultVerdict)
	}
	if cfg.TimeoutSec != 60 {
		t.Errorf("timeout = %d", cfg.TimeoutSec)
	}
	if cfg.VaultProvider != "hashicorp" {
		t.Errorf("vault provider = %q", cfg.VaultProvider)
	}
	if cfg.VaultDir != "/tmp/vault" {
		t.Errorf("vault dir = %q", cfg.VaultDir)
	}
	if len(cfg.VaultProviders) != 2 || cfg.VaultProviders[0] != "age" {
		t.Errorf("vault providers = %v", cfg.VaultProviders)
	}
	if cfg.VaultHashicorpAddr != addr {
		t.Errorf("hc addr = %q", cfg.VaultHashicorpAddr)
	}
	if cfg.VaultHashicorpMount != mount {
		t.Errorf("hc mount = %q", cfg.VaultHashicorpMount)
	}
	if cfg.VaultHashicorpPrefix != prefix {
		t.Errorf("hc prefix = %q", cfg.VaultHashicorpPrefix)
	}
	if cfg.VaultHashicorpAuth != auth {
		t.Errorf("hc auth = %q", cfg.VaultHashicorpAuth)
	}
	if cfg.VaultHashicorpRoleID != roleID {
		t.Errorf("hc role_id = %q", cfg.VaultHashicorpRoleID)
	}
	if cfg.VaultHashicorpSecretID != secretID {
		t.Errorf("hc secret_id = %q", cfg.VaultHashicorpSecretID)
	}
	if cfg.VaultHashicorpRoleIDEnv != roleIDEnv {
		t.Errorf("hc role_id_env = %q", cfg.VaultHashicorpRoleIDEnv)
	}
	if cfg.VaultHashicorpSecretIDEnv != secretIDEnv {
		t.Errorf("hc secret_id_env = %q", cfg.VaultHashicorpSecretIDEnv)
	}
}

func TestConfigUpdateNoOp(t *testing.T) {
	s := newTestStore(t)
	// Empty update should be a no-op.
	if err := s.UpdateConfig(ConfigUpdate{}); err != nil {
		t.Fatalf("empty update: %v", err)
	}
	cfg, _ := s.GetConfig()
	if cfg.DefaultVerdict != "deny" {
		t.Errorf("default verdict changed unexpectedly: %q", cfg.DefaultVerdict)
	}
}

func TestConfigVaultProviderDefaults(t *testing.T) {
	s := newTestStore(t)
	cfg, err := s.GetConfig()
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	// New provider columns should all default to empty.
	if cfg.Vault1PasswordToken != "" {
		t.Errorf("vault_1password_token = %q, want empty", cfg.Vault1PasswordToken)
	}
	if cfg.Vault1PasswordVault != "" {
		t.Errorf("vault_1password_vault = %q, want empty", cfg.Vault1PasswordVault)
	}
	if cfg.VaultBitwardenToken != "" {
		t.Errorf("vault_bitwarden_token = %q, want empty", cfg.VaultBitwardenToken)
	}
	if cfg.VaultBitwardenOrgID != "" {
		t.Errorf("vault_bitwarden_org_id = %q, want empty", cfg.VaultBitwardenOrgID)
	}
	if cfg.VaultKeePassPath != "" {
		t.Errorf("vault_keepass_path = %q, want empty", cfg.VaultKeePassPath)
	}
	if cfg.VaultKeePassKeyFile != "" {
		t.Errorf("vault_keepass_key_file = %q, want empty", cfg.VaultKeePassKeyFile)
	}
	if cfg.VaultGopassStore != "" {
		t.Errorf("vault_gopass_store = %q, want empty", cfg.VaultGopassStore)
	}
}

func TestConfigUpdateVaultProviderFields(t *testing.T) {
	s := newTestStore(t)

	opToken := "ops_test_token_12345"
	opVault := "sluice-credentials"
	bwToken := "bws_test_token_67890"
	bwOrgID := "org-uuid-abcdef"
	kpPath := "/data/credentials.kdbx"
	kpKeyFile := "/data/keyfile.key"
	gpStore := "/home/user/.local/share/gopass/stores/root"

	err := s.UpdateConfig(ConfigUpdate{
		Vault1PasswordToken: &opToken,
		Vault1PasswordVault: &opVault,
		VaultBitwardenToken: &bwToken,
		VaultBitwardenOrgID: &bwOrgID,
		VaultKeePassPath:    &kpPath,
		VaultKeePassKeyFile: &kpKeyFile,
		VaultGopassStore:    &gpStore,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	cfg, err := s.GetConfig()
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	if cfg.Vault1PasswordToken != opToken {
		t.Errorf("1password token = %q, want %q", cfg.Vault1PasswordToken, opToken)
	}
	if cfg.Vault1PasswordVault != opVault {
		t.Errorf("1password vault = %q, want %q", cfg.Vault1PasswordVault, opVault)
	}
	if cfg.VaultBitwardenToken != bwToken {
		t.Errorf("bitwarden token = %q, want %q", cfg.VaultBitwardenToken, bwToken)
	}
	if cfg.VaultBitwardenOrgID != bwOrgID {
		t.Errorf("bitwarden org_id = %q, want %q", cfg.VaultBitwardenOrgID, bwOrgID)
	}
	if cfg.VaultKeePassPath != kpPath {
		t.Errorf("keepass path = %q, want %q", cfg.VaultKeePassPath, kpPath)
	}
	if cfg.VaultKeePassKeyFile != kpKeyFile {
		t.Errorf("keepass key_file = %q, want %q", cfg.VaultKeePassKeyFile, kpKeyFile)
	}
	if cfg.VaultGopassStore != gpStore {
		t.Errorf("gopass store = %q, want %q", cfg.VaultGopassStore, gpStore)
	}

	// Existing fields should be untouched.
	if cfg.DefaultVerdict != "deny" {
		t.Errorf("default verdict changed: %q", cfg.DefaultVerdict)
	}
	if cfg.VaultProvider != "age" {
		t.Errorf("vault provider changed: %q", cfg.VaultProvider)
	}
}

func TestConfigUpdateVaultProviderPartial(t *testing.T) {
	s := newTestStore(t)

	// Update only 1Password fields.
	opToken := "ops_token"
	opVault := "my-vault"
	if err := s.UpdateConfig(ConfigUpdate{
		Vault1PasswordToken: &opToken,
		Vault1PasswordVault: &opVault,
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	cfg, _ := s.GetConfig()
	if cfg.Vault1PasswordToken != opToken {
		t.Errorf("1password token = %q", cfg.Vault1PasswordToken)
	}
	if cfg.Vault1PasswordVault != opVault {
		t.Errorf("1password vault = %q", cfg.Vault1PasswordVault)
	}
	// Other new fields should remain empty.
	if cfg.VaultBitwardenToken != "" {
		t.Errorf("bitwarden token should be empty: %q", cfg.VaultBitwardenToken)
	}
	if cfg.VaultKeePassPath != "" {
		t.Errorf("keepass path should be empty: %q", cfg.VaultKeePassPath)
	}
	if cfg.VaultGopassStore != "" {
		t.Errorf("gopass store should be empty: %q", cfg.VaultGopassStore)
	}
}

func TestConfigUpdateVaultProviderClearFields(t *testing.T) {
	s := newTestStore(t)

	// Set a value, then clear it by setting to empty string.
	opToken := "ops_token"
	if err := s.UpdateConfig(ConfigUpdate{Vault1PasswordToken: &opToken}); err != nil {
		t.Fatalf("set: %v", err)
	}
	cfg, _ := s.GetConfig()
	if cfg.Vault1PasswordToken != opToken {
		t.Fatalf("expected token set")
	}

	empty := ""
	if err := s.UpdateConfig(ConfigUpdate{Vault1PasswordToken: &empty}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	cfg, _ = s.GetConfig()
	if cfg.Vault1PasswordToken != "" {
		t.Errorf("expected token cleared, got %q", cfg.Vault1PasswordToken)
	}
}

// --- Binding CRUD ---

func TestBindingCRUD(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddBinding("api.example.com", "my_api_key", BindingOpts{
		Ports:     []int{443},
		Header:    "Authorization",
		Template:  "Bearer {value}",
		Protocols: []string{"https"},
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if id < 1 {
		t.Fatal("expected positive id")
	}

	bindings, _ := s.ListBindings()
	if len(bindings) != 1 {
		t.Fatalf("expected 1, got %d", len(bindings))
	}
	b := bindings[0]
	if b.Destination != "api.example.com" {
		t.Errorf("dest = %q", b.Destination)
	}
	if b.Credential != "my_api_key" {
		t.Errorf("cred = %q", b.Credential)
	}
	if len(b.Ports) != 1 || b.Ports[0] != 443 {
		t.Errorf("ports = %v", b.Ports)
	}
	if b.Header != "Authorization" {
		t.Errorf("header = %q", b.Header)
	}
	if b.Template != "Bearer {value}" {
		t.Errorf("template = %q", b.Template)
	}
	if len(b.Protocols) != 1 || b.Protocols[0] != "https" {
		t.Errorf("protocols = %v", b.Protocols)
	}

	ok, _ := s.RemoveBinding(id)
	if !ok {
		t.Error("expected true")
	}
	bindings, _ = s.ListBindings()
	if len(bindings) != 0 {
		t.Error("expected empty after remove")
	}
}

func TestBindingMultipleProtocols(t *testing.T) {
	s := newTestStore(t)
	_, err := s.AddBinding("mail.example.com", "mail_cred", BindingOpts{
		Ports:     []int{993, 587},
		Protocols: []string{"imap", "smtp"},
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	bindings, _ := s.ListBindings()
	if len(bindings[0].Protocols) != 2 || bindings[0].Protocols[0] != "imap" || bindings[0].Protocols[1] != "smtp" {
		t.Errorf("protocols = %v, want [imap smtp]", bindings[0].Protocols)
	}
}

func TestBindingNoProtocols(t *testing.T) {
	s := newTestStore(t)
	_, err := s.AddBinding("api.example.com", "key", BindingOpts{
		Ports:  []int{443},
		Header: "Authorization",
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	bindings, _ := s.ListBindings()
	if bindings[0].Protocols != nil {
		t.Errorf("protocols should be nil, got %v", bindings[0].Protocols)
	}
}

func TestBindingValidation(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.AddBinding("", "cred", BindingOpts{}); err == nil {
		t.Error("empty destination should fail")
	}
	if _, err := s.AddBinding("dest", "", BindingOpts{}); err == nil {
		t.Error("empty credential should fail")
	}
}

// --- MCP Upstream CRUD ---

func TestMCPUpstreamCRUD(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddMCPUpstream("github", "npx", MCPUpstreamOpts{
		Args:       []string{"-y", "@mcp/server-github"},
		Env:        map[string]string{"GITHUB_TOKEN": "phantom"},
		TimeoutSec: 60,
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if id < 1 {
		t.Fatal("expected positive id")
	}

	upstreams, _ := s.ListMCPUpstreams()
	if len(upstreams) != 1 {
		t.Fatalf("expected 1, got %d", len(upstreams))
	}
	u := upstreams[0]
	if u.Name != "github" || u.Command != "npx" {
		t.Errorf("name/cmd = %q/%q", u.Name, u.Command)
	}
	if len(u.Args) != 2 || u.Args[0] != "-y" {
		t.Errorf("args = %v", u.Args)
	}
	if u.Env["GITHUB_TOKEN"] != "phantom" {
		t.Errorf("env = %v", u.Env)
	}
	if u.TimeoutSec != 60 {
		t.Errorf("timeout = %d", u.TimeoutSec)
	}

	ok, _ := s.RemoveMCPUpstream("github")
	if !ok {
		t.Error("expected true")
	}
	upstreams, _ = s.ListMCPUpstreams()
	if len(upstreams) != 0 {
		t.Error("expected empty after remove")
	}
}

func TestMCPUpstreamValidation(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.AddMCPUpstream("", "cmd", MCPUpstreamOpts{}); err == nil {
		t.Error("empty name should fail")
	}
	if _, err := s.AddMCPUpstream("name", "", MCPUpstreamOpts{}); err == nil {
		t.Error("empty command should fail")
	}
}

func TestMCPUpstreamDuplicateName(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddMCPUpstream("github", "npx", MCPUpstreamOpts{})
	_, err := s.AddMCPUpstream("github", "node", MCPUpstreamOpts{})
	if err == nil {
		t.Error("duplicate name should fail")
	}
}

func TestMCPUpstreamDefaultTimeout(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddMCPUpstream("test", "cmd", MCPUpstreamOpts{})
	upstreams, _ := s.ListMCPUpstreams()
	if upstreams[0].TimeoutSec != 120 {
		t.Errorf("default timeout = %d, want 120", upstreams[0].TimeoutSec)
	}
}

func TestMCPUpstreamRemoveNonExistent(t *testing.T) {
	s := newTestStore(t)
	ok, err := s.RemoveMCPUpstream("nonexistent")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if ok {
		t.Error("expected false for non-existent upstream")
	}
}

// --- RuleExists ---

func TestRuleExistsNetwork(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddRule("allow", RuleOpts{Destination: "example.com", Ports: []int{443}})

	exists, _ := s.RuleExists("allow", RuleExistsOpts{Destination: "example.com", Ports: []int{443}})
	if !exists {
		t.Error("should exist")
	}
	exists, _ = s.RuleExists("allow", RuleExistsOpts{Destination: "example.com"})
	if exists {
		t.Error("different ports should not match")
	}
	exists, _ = s.RuleExists("deny", RuleExistsOpts{Destination: "example.com", Ports: []int{443}})
	if exists {
		t.Error("different verdict should not match")
	}
}

func TestRuleExistsNilPorts(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddRule("deny", RuleOpts{Destination: "evil.com"})

	exists, _ := s.RuleExists("deny", RuleExistsOpts{Destination: "evil.com"})
	if !exists {
		t.Error("nil ports rule should exist")
	}
	exists, _ = s.RuleExists("deny", RuleExistsOpts{Destination: "evil.com", Ports: []int{80}})
	if exists {
		t.Error("should not match when stored ports is nil")
	}
}

func TestRuleExistsTool(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddRule("allow", RuleOpts{Tool: "github__list_*"})

	exists, _ := s.RuleExists("allow", RuleExistsOpts{Tool: "github__list_*"})
	if !exists {
		t.Error("should exist")
	}
	exists, _ = s.RuleExists("deny", RuleExistsOpts{Tool: "github__list_*"})
	if exists {
		t.Error("different verdict should not match")
	}
}

func TestRuleExistsPattern(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddRule("deny", RuleOpts{Pattern: `sk-[a-zA-Z0-9]+`})

	exists, _ := s.RuleExists("deny", RuleExistsOpts{Pattern: `sk-[a-zA-Z0-9]+`})
	if !exists {
		t.Error("should exist")
	}
	exists, _ = s.RuleExists("deny", RuleExistsOpts{Pattern: `different-pattern`})
	if exists {
		t.Error("different pattern should not match")
	}
}

func TestRuleExistsRequiresField(t *testing.T) {
	s := newTestStore(t)
	_, err := s.RuleExists("allow", RuleExistsOpts{})
	if err == nil {
		t.Error("empty opts should fail")
	}
}

func TestRuleExistsProtocolScoped(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddRule("allow", RuleOpts{
		Destination: "api.example.com",
		Ports:       []int{443},
		Protocols:   []string{"https"},
	})

	// Same destination+ports but different protocols should not match.
	exists, _ := s.RuleExists("allow", RuleExistsOpts{
		Destination: "api.example.com",
		Ports:       []int{443},
		Protocols:   []string{"http"},
	})
	if exists {
		t.Error("different protocols should not match")
	}

	// Same destination+ports+protocols should match.
	exists, _ = s.RuleExists("allow", RuleExistsOpts{
		Destination: "api.example.com",
		Ports:       []int{443},
		Protocols:   []string{"https"},
	})
	if !exists {
		t.Error("same protocols should match")
	}

	// Nil protocols should not match non-nil.
	exists, _ = s.RuleExists("allow", RuleExistsOpts{
		Destination: "api.example.com",
		Ports:       []int{443},
	})
	if exists {
		t.Error("nil protocols should not match non-nil")
	}
}

func TestBindingExists(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddBinding("api.example.com", "my_key", BindingOpts{})

	exists, _ := s.BindingExists("api.example.com", "my_key")
	if !exists {
		t.Error("should exist")
	}
	exists, _ = s.BindingExists("api.example.com", "other_key")
	if exists {
		t.Error("different credential should not match")
	}
}

func TestMCPUpstreamExists(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddMCPUpstream("github", "npx", MCPUpstreamOpts{})

	exists, _ := s.MCPUpstreamExists("github")
	if !exists {
		t.Error("should exist")
	}
	exists, _ = s.MCPUpstreamExists("gitlab")
	if exists {
		t.Error("should not exist")
	}
}

// --- Concurrent access ---

func TestConcurrentAccess(t *testing.T) {
	s := newTestStore(t)
	var wg sync.WaitGroup
	errs := make(chan error, 100)

	// Concurrent writers.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			dest := fmt.Sprintf("host-%d.example.com", i)
			_, err := s.AddRule("allow", RuleOpts{Destination: dest, Ports: []int{443}, Source: "test"})
			if err != nil {
				errs <- fmt.Errorf("add rule %d: %w", i, err)
			}
		}(i)
	}

	// Concurrent readers.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.ListRules(RuleFilter{Type: "network"})
			if err != nil {
				errs <- fmt.Errorf("list rules: %w", err)
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	// Verify all 20 rules were inserted.
	rules, _ := s.ListRules(RuleFilter{Type: "network"})
	if len(rules) != 20 {
		t.Errorf("expected 20 rules, got %d", len(rules))
	}
}

func TestConcurrentConfigAccess(t *testing.T) {
	s := newTestStore(t)
	var wg sync.WaitGroup
	errs := make(chan error, 50)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			value := fmt.Sprintf("value_%d", i)
			if err := s.UpdateConfig(ConfigUpdate{VaultDir: &value}); err != nil {
				errs <- err
			}
			if _, err := s.GetConfig(); err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// --- Edge cases ---

func TestRuleWithNullOptionalFields(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddRule("ask", RuleOpts{Destination: "example.com"})

	rules, _ := s.ListRules(RuleFilter{Type: "network"})
	r := rules[0]
	if r.Protocols != nil {
		t.Errorf("protocols should be nil, got %v", r.Protocols)
	}
	if r.Name != "" {
		t.Errorf("name should be empty, got %q", r.Name)
	}
}

func TestMCPUpstreamNilArgsEnv(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddMCPUpstream("simple", "cmd", MCPUpstreamOpts{})

	upstreams, _ := s.ListMCPUpstreams()
	u := upstreams[0]
	if u.Args != nil {
		t.Errorf("args should be nil, got %v", u.Args)
	}
	if u.Env != nil {
		t.Errorf("env should be nil, got %v", u.Env)
	}
}

// --- MCP Upstream Transport ---

func TestMCPUpstreamTransportDefault(t *testing.T) {
	s := newTestStore(t)
	_, err := s.AddMCPUpstream("test", "npx", MCPUpstreamOpts{})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	upstreams, _ := s.ListMCPUpstreams()
	if upstreams[0].Transport != "stdio" {
		t.Errorf("default transport = %q, want stdio", upstreams[0].Transport)
	}
}

func TestMCPUpstreamTransportHTTP(t *testing.T) {
	s := newTestStore(t)
	_, err := s.AddMCPUpstream("github", "https://mcp.github.com/v1", MCPUpstreamOpts{
		Transport:  "http",
		TimeoutSec: 60,
	})
	if err != nil {
		t.Fatalf("add http upstream: %v", err)
	}
	upstreams, _ := s.ListMCPUpstreams()
	if upstreams[0].Transport != "http" {
		t.Errorf("transport = %q, want http", upstreams[0].Transport)
	}
	if upstreams[0].Command != "https://mcp.github.com/v1" {
		t.Errorf("command = %q", upstreams[0].Command)
	}
}

func TestMCPUpstreamTransportWebSocket(t *testing.T) {
	s := newTestStore(t)
	_, err := s.AddMCPUpstream("realtime", "wss://mcp.example.com/ws", MCPUpstreamOpts{
		Transport: "websocket",
	})
	if err != nil {
		t.Fatalf("add ws upstream: %v", err)
	}
	upstreams, _ := s.ListMCPUpstreams()
	if upstreams[0].Transport != "websocket" {
		t.Errorf("transport = %q, want websocket", upstreams[0].Transport)
	}
}

func TestMCPUpstreamTransportInvalid(t *testing.T) {
	s := newTestStore(t)
	_, err := s.AddMCPUpstream("bad", "cmd", MCPUpstreamOpts{
		Transport: "grpc",
	})
	if err == nil {
		t.Error("invalid transport should fail")
	}
}

func TestMCPUpstreamTransportExplicitStdio(t *testing.T) {
	s := newTestStore(t)
	_, err := s.AddMCPUpstream("local", "npx", MCPUpstreamOpts{
		Transport: "stdio",
		Args:      []string{"-y", "@mcp/server-filesystem"},
	})
	if err != nil {
		t.Fatalf("add stdio upstream: %v", err)
	}
	upstreams, _ := s.ListMCPUpstreams()
	if upstreams[0].Transport != "stdio" {
		t.Errorf("transport = %q, want stdio", upstreams[0].Transport)
	}
}

func TestMCPUpstreamTransportMixedTypes(t *testing.T) {
	s := newTestStore(t)

	_, err := s.AddMCPUpstream("local-fs", "npx", MCPUpstreamOpts{
		Transport: "stdio",
		Args:      []string{"-y", "@mcp/server-filesystem"},
	})
	if err != nil {
		t.Fatalf("add stdio: %v", err)
	}
	_, err = s.AddMCPUpstream("remote-github", "https://mcp.github.com/v1", MCPUpstreamOpts{
		Transport: "http",
	})
	if err != nil {
		t.Fatalf("add http: %v", err)
	}
	_, err = s.AddMCPUpstream("realtime-data", "wss://mcp.example.com/ws", MCPUpstreamOpts{
		Transport: "websocket",
	})
	if err != nil {
		t.Fatalf("add ws: %v", err)
	}

	upstreams, _ := s.ListMCPUpstreams()
	if len(upstreams) != 3 {
		t.Fatalf("expected 3 upstreams, got %d", len(upstreams))
	}
	if upstreams[0].Transport != "stdio" {
		t.Errorf("upstream[0] transport = %q, want stdio", upstreams[0].Transport)
	}
	if upstreams[1].Transport != "http" {
		t.Errorf("upstream[1] transport = %q, want http", upstreams[1].Transport)
	}
	if upstreams[2].Transport != "websocket" {
		t.Errorf("upstream[2] transport = %q, want websocket", upstreams[2].Transport)
	}
}

// --- RemoveRulesBySource ---

func TestRemoveRulesBySource(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddRule("allow", RuleOpts{Destination: "a.com", Source: "seed"})
	_, _ = s.AddRule("deny", RuleOpts{Destination: "b.com", Source: "seed"})
	_, _ = s.AddRule("allow", RuleOpts{Tool: "github__list_*", Source: "seed"})
	_, _ = s.AddRule("allow", RuleOpts{Destination: "c.com", Source: "manual"})

	n, err := s.RemoveRulesBySource("seed")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 removed, got %d", n)
	}

	all, _ := s.ListRules(RuleFilter{})
	if len(all) != 1 {
		t.Errorf("expected 1 remaining, got %d", len(all))
	}
	if all[0].Destination != "c.com" {
		t.Errorf("expected c.com remaining, got %q", all[0].Destination)
	}
}

// --- Redact verdict ---

func TestRedactVerdict(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddRule("redact", RuleOpts{
		Pattern:     `(?i)(sk-[a-zA-Z0-9]{20,})`,
		Replacement: "[REDACTED_API_KEY]",
		Name:        "api key in responses",
	})
	if err != nil {
		t.Fatalf("add redact rule: %v", err)
	}
	if id < 1 {
		t.Fatal("expected positive id")
	}

	rules, _ := s.ListRules(RuleFilter{Verdict: "redact"})
	if len(rules) != 1 {
		t.Fatalf("expected 1, got %d", len(rules))
	}
	if rules[0].Verdict != "redact" {
		t.Errorf("verdict = %q, want redact", rules[0].Verdict)
	}
	if rules[0].Replacement != "[REDACTED_API_KEY]" {
		t.Errorf("replacement = %q", rules[0].Replacement)
	}
}

// --- Channels CRUD ---

func TestChannelGetDefault(t *testing.T) {
	s := newTestStore(t)
	ch, err := s.GetChannel(1)
	if err != nil {
		t.Fatalf("get channel: %v", err)
	}
	if ch == nil {
		t.Fatal("default channel should exist")
	}
	if ch.Type != 0 {
		t.Errorf("type = %d, want 0 (Telegram)", ch.Type)
	}
	if !ch.Enabled {
		t.Error("default channel should be enabled")
	}
}

func TestChannelGetNonExistent(t *testing.T) {
	s := newTestStore(t)
	ch, err := s.GetChannel(999)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if ch != nil {
		t.Error("non-existent channel should return nil")
	}
}

func TestChannelUpdate(t *testing.T) {
	s := newTestStore(t)
	disabled := false
	if err := s.UpdateChannel(1, ChannelUpdate{Enabled: &disabled}); err != nil {
		t.Fatalf("update: %v", err)
	}
	ch, _ := s.GetChannel(1)
	if ch.Enabled {
		t.Error("channel should be disabled")
	}

	enabled := true
	if err := s.UpdateChannel(1, ChannelUpdate{Enabled: &enabled}); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	ch, _ = s.GetChannel(1)
	if !ch.Enabled {
		t.Error("channel should be enabled")
	}
}

func TestChannelUpdateNoOp(t *testing.T) {
	s := newTestStore(t)
	if err := s.UpdateChannel(1, ChannelUpdate{}); err != nil {
		t.Fatalf("empty update: %v", err)
	}
	ch, _ := s.GetChannel(1)
	if !ch.Enabled {
		t.Error("channel should still be enabled after no-op update")
	}
}

func TestListChannels(t *testing.T) {
	s := newTestStore(t)
	channels, err := s.ListChannels()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(channels) != 1 {
		t.Fatalf("expected 1 default channel, got %d", len(channels))
	}
	if channels[0].ID != 1 || channels[0].Type != 0 || !channels[0].Enabled {
		t.Errorf("unexpected default channel: %+v", channels[0])
	}
}

// --- Migration 000002: webhook channel columns ---

func TestWebhookColumnsExist(t *testing.T) {
	s := newTestStore(t)
	// The migration should have added webhook_url and webhook_secret columns.
	// Verify by inserting a channel with webhook fields.
	id, err := s.AddChannel(1, true, AddChannelOpts{
		WebhookURL:    "https://example.com/webhook",
		WebhookSecret: "secret123",
	})
	if err != nil {
		t.Fatalf("add channel with webhook: %v", err)
	}
	ch, err := s.GetChannel(id)
	if err != nil {
		t.Fatalf("get channel: %v", err)
	}
	if ch.WebhookURL != "https://example.com/webhook" {
		t.Errorf("webhook_url = %q, want %q", ch.WebhookURL, "https://example.com/webhook")
	}
	if ch.WebhookSecret != "secret123" {
		t.Errorf("webhook_secret = %q, want %q", ch.WebhookSecret, "secret123")
	}
}

func TestDefaultChannelHasEmptyWebhookFields(t *testing.T) {
	s := newTestStore(t)
	ch, err := s.GetChannel(1)
	if err != nil {
		t.Fatalf("get channel: %v", err)
	}
	if ch.WebhookURL != "" {
		t.Errorf("default channel webhook_url = %q, want empty", ch.WebhookURL)
	}
	if ch.WebhookSecret != "" {
		t.Errorf("default channel webhook_secret = %q, want empty", ch.WebhookSecret)
	}
}

func TestChannelUpdateWebhookFields(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddChannel(1, true, AddChannelOpts{
		WebhookURL: "https://old.example.com/hook",
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	newURL := "https://new.example.com/hook"
	newSecret := "newsecret"
	if err := s.UpdateChannel(id, ChannelUpdate{
		WebhookURL:    &newURL,
		WebhookSecret: &newSecret,
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	ch, _ := s.GetChannel(id)
	if ch.WebhookURL != newURL {
		t.Errorf("webhook_url = %q, want %q", ch.WebhookURL, newURL)
	}
	if ch.WebhookSecret != newSecret {
		t.Errorf("webhook_secret = %q, want %q", ch.WebhookSecret, newSecret)
	}
}

func TestRemoveChannel(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddChannel(1, true)
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	deleted, err := s.RemoveChannel(id)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !deleted {
		t.Error("expected deletion")
	}

	ch, _ := s.GetChannel(id)
	if ch != nil {
		t.Error("channel should be gone after removal")
	}
}

func TestRemoveChannelNonExistent(t *testing.T) {
	s := newTestStore(t)
	deleted, err := s.RemoveChannel(999)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if deleted {
		t.Error("should not have deleted non-existent channel")
	}
}

func TestCountEnabledChannels(t *testing.T) {
	s := newTestStore(t)
	// Default has 1 enabled (Telegram).
	count, err := s.CountEnabledChannels()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}

	// Add another enabled channel.
	_, _ = s.AddChannel(1, true, AddChannelOpts{WebhookURL: "https://example.com/hook"})
	count, _ = s.CountEnabledChannels()
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}

	// Add a disabled channel.
	_, _ = s.AddChannel(1, false)
	count, _ = s.CountEnabledChannels()
	if count != 2 {
		t.Errorf("count = %d, want 2 (disabled channel should not count)", count)
	}
}

func TestListChannelsWithWebhookFields(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddChannel(1, true, AddChannelOpts{
		WebhookURL:    "https://example.com/hook",
		WebhookSecret: "s3cret",
	})

	channels, err := s.ListChannels()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(channels) != 2 {
		t.Fatalf("expected 2 channels, got %d", len(channels))
	}

	httpCh := channels[1]
	if httpCh.WebhookURL != "https://example.com/hook" {
		t.Errorf("webhook_url = %q", httpCh.WebhookURL)
	}
	if httpCh.WebhookSecret != "s3cret" {
		t.Errorf("webhook_secret = %q", httpCh.WebhookSecret)
	}
}

func TestNewStoreFilePath(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"
	s, err := New(path)
	if err != nil {
		t.Fatalf("New with file path: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Verify the file was created with restricted permissions.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("file permissions = %o, want 0600", info.Mode().Perm())
	}

	// Verify the store is functional.
	_, err = s.AddRule("allow", RuleOpts{Destination: "test.com"})
	if err != nil {
		t.Fatalf("add rule to file store: %v", err)
	}
}

func TestNewStoreFilePathExisting(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/existing.db"

	// Create the file with wider permissions.
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}

	s, err := New(path)
	if err != nil {
		t.Fatalf("New with existing file: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Verify permissions were tightened.
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Errorf("file permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestMigrationCorruptedDB(t *testing.T) {
	// Write garbage to a file and try to open as a SQLite DB.
	dir := t.TempDir()
	path := dir + "/corrupted.db"
	if err := os.WriteFile(path, []byte("this is not a sqlite database"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := New(path)
	if err == nil {
		t.Fatal("expected error for corrupted DB file")
	}
}

func TestConcurrentImport(t *testing.T) {
	s := newTestStore(t)

	toml1 := []byte(`
[[allow]]
destination = "api.one.com"
ports = [443]
`)
	toml2 := []byte(`
[[allow]]
destination = "api.two.com"
ports = [443]
`)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, errs[0] = s.ImportTOML(toml1)
	}()
	go func() {
		defer wg.Done()
		_, errs[1] = s.ImportTOML(toml2)
	}()
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("import %d: %v", i, err)
		}
	}

	rules, err := s.ListRules(RuleFilter{Type: "network"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Errorf("expected 2 rules after concurrent import, got %d", len(rules))
	}
}

func TestConfigAllFields(t *testing.T) {
	s := newTestStore(t)

	// Set every field.
	verdict := "allow"
	timeout := 30
	provider := "1password"
	dir := "/opt/vault"
	providers := []string{"1password", "env"}
	hcAddr := "https://vault.prod.com:8200"
	hcMount := "kv-v2"
	hcPrefix := "prod/"
	hcAuth := "approle"
	hcToken := "hvs.prod-token"
	hcRoleID := "role-prod"
	hcSecretID := "secret-prod"
	hcRoleIDEnv := "MY_ROLE"
	hcSecretIDEnv := "MY_SECRET"
	opToken := "ops-token-xyz"
	opVault := "production"
	opField := "password"
	bwToken := "bws-access-token"
	bwOrgID := "org-uuid-123"
	kpPath := "/secure/db.kdbx"
	kpKeyFile := "/secure/key.keyx"
	gpStore := "/data/gopass"

	err := s.UpdateConfig(ConfigUpdate{
		DefaultVerdict:            &verdict,
		TimeoutSec:                &timeout,
		VaultProvider:             &provider,
		VaultDir:                  &dir,
		VaultProviders:            &providers,
		VaultHashicorpAddr:        &hcAddr,
		VaultHashicorpMount:       &hcMount,
		VaultHashicorpPrefix:      &hcPrefix,
		VaultHashicorpAuth:        &hcAuth,
		VaultHashicorpToken:       &hcToken,
		VaultHashicorpRoleID:      &hcRoleID,
		VaultHashicorpSecretID:    &hcSecretID,
		VaultHashicorpRoleIDEnv:   &hcRoleIDEnv,
		VaultHashicorpSecretIDEnv: &hcSecretIDEnv,
		Vault1PasswordToken:       &opToken,
		Vault1PasswordVault:       &opVault,
		Vault1PasswordField:       &opField,
		VaultBitwardenToken:       &bwToken,
		VaultBitwardenOrgID:       &bwOrgID,
		VaultKeePassPath:          &kpPath,
		VaultKeePassKeyFile:       &kpKeyFile,
		VaultGopassStore:          &gpStore,
	})
	if err != nil {
		t.Fatalf("update all: %v", err)
	}

	cfg, err := s.GetConfig()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if cfg.DefaultVerdict != verdict {
		t.Errorf("DefaultVerdict = %q", cfg.DefaultVerdict)
	}
	if cfg.TimeoutSec != timeout {
		t.Errorf("TimeoutSec = %d", cfg.TimeoutSec)
	}
	if cfg.VaultProvider != provider {
		t.Errorf("VaultProvider = %q", cfg.VaultProvider)
	}
	if cfg.VaultDir != dir {
		t.Errorf("VaultDir = %q", cfg.VaultDir)
	}
	if len(cfg.VaultProviders) != 2 || cfg.VaultProviders[0] != "1password" || cfg.VaultProviders[1] != "env" {
		t.Errorf("VaultProviders = %v", cfg.VaultProviders)
	}
	if cfg.VaultHashicorpAddr != hcAddr {
		t.Errorf("VaultHashicorpAddr = %q", cfg.VaultHashicorpAddr)
	}
	if cfg.VaultHashicorpMount != hcMount {
		t.Errorf("VaultHashicorpMount = %q", cfg.VaultHashicorpMount)
	}
	if cfg.VaultHashicorpPrefix != hcPrefix {
		t.Errorf("VaultHashicorpPrefix = %q", cfg.VaultHashicorpPrefix)
	}
	if cfg.VaultHashicorpAuth != hcAuth {
		t.Errorf("VaultHashicorpAuth = %q", cfg.VaultHashicorpAuth)
	}
	if cfg.VaultHashicorpToken != hcToken {
		t.Errorf("VaultHashicorpToken = %q", cfg.VaultHashicorpToken)
	}
	if cfg.VaultHashicorpRoleID != hcRoleID {
		t.Errorf("VaultHashicorpRoleID = %q", cfg.VaultHashicorpRoleID)
	}
	if cfg.VaultHashicorpSecretID != hcSecretID {
		t.Errorf("VaultHashicorpSecretID = %q", cfg.VaultHashicorpSecretID)
	}
	if cfg.VaultHashicorpRoleIDEnv != hcRoleIDEnv {
		t.Errorf("VaultHashicorpRoleIDEnv = %q", cfg.VaultHashicorpRoleIDEnv)
	}
	if cfg.VaultHashicorpSecretIDEnv != hcSecretIDEnv {
		t.Errorf("VaultHashicorpSecretIDEnv = %q", cfg.VaultHashicorpSecretIDEnv)
	}
	if cfg.Vault1PasswordToken != opToken {
		t.Errorf("Vault1PasswordToken = %q", cfg.Vault1PasswordToken)
	}
	if cfg.Vault1PasswordVault != opVault {
		t.Errorf("Vault1PasswordVault = %q", cfg.Vault1PasswordVault)
	}
	if cfg.Vault1PasswordField != opField {
		t.Errorf("Vault1PasswordField = %q", cfg.Vault1PasswordField)
	}
	if cfg.VaultBitwardenToken != bwToken {
		t.Errorf("VaultBitwardenToken = %q", cfg.VaultBitwardenToken)
	}
	if cfg.VaultBitwardenOrgID != bwOrgID {
		t.Errorf("VaultBitwardenOrgID = %q", cfg.VaultBitwardenOrgID)
	}
	if cfg.VaultKeePassPath != kpPath {
		t.Errorf("VaultKeePassPath = %q", cfg.VaultKeePassPath)
	}
	if cfg.VaultKeePassKeyFile != kpKeyFile {
		t.Errorf("VaultKeePassKeyFile = %q", cfg.VaultKeePassKeyFile)
	}
	if cfg.VaultGopassStore != gpStore {
		t.Errorf("VaultGopassStore = %q", cfg.VaultGopassStore)
	}
}

func TestAddChannelWithoutOpts(t *testing.T) {
	s := newTestStore(t)
	// Verify that the variadic opts parameter works when omitted.
	id, err := s.AddChannel(0, true)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	ch, _ := s.GetChannel(id)
	if ch.WebhookURL != "" || ch.WebhookSecret != "" {
		t.Error("channel without opts should have empty webhook fields")
	}
}

func TestListBindingsByCredential(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddBinding("api.one.com", "cred_a", BindingOpts{Ports: []int{443}})
	_, _ = s.AddBinding("api.two.com", "cred_a", BindingOpts{Ports: []int{443}})
	_, _ = s.AddBinding("api.three.com", "cred_b", BindingOpts{Ports: []int{443}})

	bindings, err := s.ListBindingsByCredential("cred_a")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(bindings) != 2 {
		t.Errorf("expected 2 bindings for cred_a, got %d", len(bindings))
	}

	bindings, err = s.ListBindingsByCredential("nonexistent")
	if err != nil {
		t.Fatalf("list nonexistent: %v", err)
	}
	if len(bindings) != 0 {
		t.Errorf("expected 0 bindings for nonexistent, got %d", len(bindings))
	}
}

func TestRemoveBindingsByCredential(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddBinding("api.one.com", "cred_a", BindingOpts{})
	_, _ = s.AddBinding("api.two.com", "cred_a", BindingOpts{})
	_, _ = s.AddBinding("api.three.com", "cred_b", BindingOpts{})

	n, err := s.RemoveBindingsByCredential("cred_a")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 removed, got %d", n)
	}

	all, _ := s.ListBindings()
	if len(all) != 1 {
		t.Errorf("expected 1 remaining binding, got %d", len(all))
	}
	if all[0].Credential != "cred_b" {
		t.Errorf("remaining binding should be cred_b, got %q", all[0].Credential)
	}
}

func TestRemoveRulesByName(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddRule("allow", RuleOpts{Destination: "a.com", Name: "test-rule"})
	_, _ = s.AddRule("deny", RuleOpts{Destination: "b.com", Name: "test-rule"})
	_, _ = s.AddRule("allow", RuleOpts{Destination: "c.com", Name: "other-rule"})

	n, err := s.RemoveRulesByName("test-rule")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 removed, got %d", n)
	}

	rules, _ := s.ListRules(RuleFilter{})
	if len(rules) != 1 {
		t.Errorf("expected 1 remaining rule, got %d", len(rules))
	}
}

func TestIsEmpty(t *testing.T) {
	s := newTestStore(t)

	empty, err := s.IsEmpty()
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !empty {
		t.Error("new store should be empty")
	}

	_, _ = s.AddRule("allow", RuleOpts{Destination: "test.com"})
	empty, err = s.IsEmpty()
	if err != nil {
		t.Fatalf("check after add: %v", err)
	}
	if empty {
		t.Error("store with rule should not be empty")
	}
}

func TestIsEmptyWithBinding(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddBinding("test.com", "cred", BindingOpts{})

	empty, err := s.IsEmpty()
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if empty {
		t.Error("store with binding should not be empty")
	}
}

func TestIsEmptyWithUpstream(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddMCPUpstream("test", "echo", MCPUpstreamOpts{})

	empty, err := s.IsEmpty()
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if empty {
		t.Error("store with upstream should not be empty")
	}
}

func TestAddRuleAndBinding(t *testing.T) {
	s := newTestStore(t)
	ruleID, bindingID, err := s.AddRuleAndBinding(
		"allow",
		RuleOpts{Destination: "api.example.com", Ports: []int{443}, Name: "api access"},
		"api_key",
		BindingOpts{Ports: []int{443}, Header: "Authorization", Template: "Bearer {value}"},
	)
	if err != nil {
		t.Fatalf("AddRuleAndBinding: %v", err)
	}
	if ruleID < 1 {
		t.Errorf("expected positive rule ID, got %d", ruleID)
	}
	if bindingID < 1 {
		t.Errorf("expected positive binding ID, got %d", bindingID)
	}

	// Verify rule was created.
	rules, _ := s.ListRules(RuleFilter{Type: "network"})
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Destination != "api.example.com" {
		t.Errorf("rule destination = %q", rules[0].Destination)
	}

	// Verify binding was created.
	bindings, _ := s.ListBindings()
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if bindings[0].Credential != "api_key" {
		t.Errorf("binding credential = %q", bindings[0].Credential)
	}
}

func TestAddRuleAndBindingValidation(t *testing.T) {
	s := newTestStore(t)

	// Missing verdict.
	_, _, err := s.AddRuleAndBinding("", RuleOpts{Destination: "test.com"}, "cred", BindingOpts{})
	if err == nil {
		t.Error("expected error for empty verdict")
	}

	// Invalid verdict.
	_, _, err = s.AddRuleAndBinding("bogus", RuleOpts{Destination: "test.com"}, "cred", BindingOpts{})
	if err == nil {
		t.Error("expected error for invalid verdict")
	}

	// Missing destination.
	_, _, err = s.AddRuleAndBinding("allow", RuleOpts{}, "cred", BindingOpts{})
	if err == nil {
		t.Error("expected error for empty destination")
	}

	// Missing credential.
	_, _, err = s.AddRuleAndBinding("allow", RuleOpts{Destination: "test.com"}, "", BindingOpts{})
	if err == nil {
		t.Error("expected error for empty credential")
	}
}
