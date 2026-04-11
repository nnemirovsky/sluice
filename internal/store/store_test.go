package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	migsqlite "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
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
	// Verify all 6 tables exist by querying them.
	tables := []string{"rules", "config", "bindings", "mcp_upstreams", "channels", "credential_meta"}
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

func TestUpdateBindingSingleField(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddBinding("api.example.com", "my_key", BindingOpts{
		Ports:    []int{443},
		Header:   "Authorization",
		Template: "Bearer {value}",
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	newHeader := "X-Api-Key"
	if _, _, _, err := s.UpdateBindingWithRuleSync(id, BindingUpdateOpts{Header: &newHeader}); err != nil {
		t.Fatalf("update: %v", err)
	}

	bindings, _ := s.ListBindings()
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	b := bindings[0]
	if b.Header != "X-Api-Key" {
		t.Errorf("header = %q, want %q", b.Header, "X-Api-Key")
	}
	// Other fields unchanged.
	if b.Destination != "api.example.com" {
		t.Errorf("destination changed unexpectedly: %q", b.Destination)
	}
	if b.Template != "Bearer {value}" {
		t.Errorf("template changed unexpectedly: %q", b.Template)
	}
	if len(b.Ports) != 1 || b.Ports[0] != 443 {
		t.Errorf("ports changed unexpectedly: %v", b.Ports)
	}
}

func TestUpdateBindingMultipleFields(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddBinding("api.example.com", "my_key", BindingOpts{
		Ports:     []int{443},
		Header:    "Authorization",
		Template:  "Bearer {value}",
		Protocols: []string{"https"},
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	newDest := "api.other.com"
	newPorts := []int{8080, 8443}
	newHeader := "X-Token"
	newTemplate := "Token {value}"
	newProtocols := []string{"http", "https"}
	if _, _, _, err := s.UpdateBindingWithRuleSync(id, BindingUpdateOpts{
		Destination: &newDest,
		Ports:       &newPorts,
		Header:      &newHeader,
		Template:    &newTemplate,
		Protocols:   &newProtocols,
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	bindings, _ := s.ListBindings()
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	b := bindings[0]
	if b.Destination != newDest {
		t.Errorf("destination = %q, want %q", b.Destination, newDest)
	}
	if len(b.Ports) != 2 || b.Ports[0] != 8080 || b.Ports[1] != 8443 {
		t.Errorf("ports = %v, want %v", b.Ports, newPorts)
	}
	if b.Header != newHeader {
		t.Errorf("header = %q, want %q", b.Header, newHeader)
	}
	if b.Template != newTemplate {
		t.Errorf("template = %q, want %q", b.Template, newTemplate)
	}
	if len(b.Protocols) != 2 || b.Protocols[0] != "http" || b.Protocols[1] != "https" {
		t.Errorf("protocols = %v, want %v", b.Protocols, newProtocols)
	}
	// Credential unchanged.
	if b.Credential != "my_key" {
		t.Errorf("credential changed unexpectedly: %q", b.Credential)
	}
}

func TestUpdateBindingClearFields(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddBinding("api.example.com", "my_key", BindingOpts{
		Ports:    []int{443},
		Header:   "Authorization",
		Template: "Bearer {value}",
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	// Clearing string fields with empty string should set them to NULL.
	empty := ""
	if _, _, _, err := s.UpdateBindingWithRuleSync(id, BindingUpdateOpts{
		Header:   &empty,
		Template: &empty,
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	bindings, _ := s.ListBindings()
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding")
	}
	if bindings[0].Header != "" {
		t.Errorf("header should be empty, got %q", bindings[0].Header)
	}
	if bindings[0].Template != "" {
		t.Errorf("template should be empty, got %q", bindings[0].Template)
	}
}

func TestUpdateBindingNotFound(t *testing.T) {
	s := newTestStore(t)
	newDest := "api.example.com"
	_, _, _, err := s.UpdateBindingWithRuleSync(9999, BindingUpdateOpts{Destination: &newDest})
	if err == nil {
		t.Fatal("expected error for nonexistent binding")
	}
	if !errors.Is(err, ErrBindingNotFound) {
		t.Errorf("expected ErrBindingNotFound, got %v", err)
	}
}

func TestUpdateBindingEmptyOpts(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddBinding("api.example.com", "my_key", BindingOpts{Ports: []int{443}})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	// Empty update should succeed (no-op) when the row exists.
	if _, _, _, err := s.UpdateBindingWithRuleSync(id, BindingUpdateOpts{}); err != nil {
		t.Errorf("empty update on existing row should succeed, got %v", err)
	}
	// Empty update on nonexistent row should still fail.
	if _, _, _, err := s.UpdateBindingWithRuleSync(9999, BindingUpdateOpts{}); err == nil {
		t.Error("empty update on nonexistent row should fail")
	}
}

func TestUpdateBindingEmptyDestination(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddBinding("api.example.com", "my_key", BindingOpts{})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	empty := ""
	if _, _, _, err := s.UpdateBindingWithRuleSync(id, BindingUpdateOpts{Destination: &empty}); err == nil {
		t.Error("empty destination should be rejected")
	}
}

// TestUpdateBindingClearPortsAndProtocols verifies that passing a non-nil
// empty slice pointer clears the stored ports and protocols respectively.
// This is distinct from passing nil (which means "no change").
func TestUpdateBindingClearPortsAndProtocols(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddBinding("api.example.com", "my_key", BindingOpts{
		Ports:     []int{443, 8080},
		Protocols: []string{"http", "grpc"},
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	emptyPorts := []int{}
	emptyProtocols := []string{}
	if _, _, _, err := s.UpdateBindingWithRuleSync(id, BindingUpdateOpts{
		Ports:     &emptyPorts,
		Protocols: &emptyProtocols,
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	bindings, _ := s.ListBindings()
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if len(bindings[0].Ports) != 0 {
		t.Errorf("ports should be cleared, got %v", bindings[0].Ports)
	}
	if len(bindings[0].Protocols) != 0 {
		t.Errorf("protocols should be cleared, got %v", bindings[0].Protocols)
	}
}

// TestUpdateBindingEnvVar verifies that the EnvVar field of
// BindingUpdateOpts can set, change, and clear env_var on a binding.
// Also covers the uniqueness check: updating a binding to an env_var
// that is already in use by a binding on a different credential should
// fail, keeping the same env_var on the same binding should succeed,
// and sharing an env_var across bindings of the same credential is
// allowed because they resolve to the same phantom value.
func TestUpdateBindingEnvVar(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddBinding("api.example.com", "my_key", BindingOpts{})
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	// Set env_var.
	set := "MY_KEY"
	if _, _, _, err := s.UpdateBindingWithRuleSync(id, BindingUpdateOpts{EnvVar: &set}); err != nil {
		t.Fatalf("set env_var: %v", err)
	}
	bindings, _ := s.ListBindings()
	if bindings[0].EnvVar != "MY_KEY" {
		t.Errorf("env_var = %q, want MY_KEY", bindings[0].EnvVar)
	}

	// Update the same binding keeping the same env_var; should succeed
	// because the uniqueness check excludes the binding being updated.
	if _, _, _, err := s.UpdateBindingWithRuleSync(id, BindingUpdateOpts{EnvVar: &set}); err != nil {
		t.Errorf("keeping same env_var should succeed, got %v", err)
	}

	// Add a second binding for the SAME credential using a different
	// env_var, then try to make it match MY_KEY; must succeed because
	// both bindings resolve to the same phantom.
	sharedID, err := s.AddBinding("api.shared.com", "my_key", BindingOpts{})
	if err != nil {
		t.Fatalf("add shared binding: %v", err)
	}
	if _, _, _, err := s.UpdateBindingWithRuleSync(sharedID, BindingUpdateOpts{EnvVar: &set}); err != nil {
		t.Errorf("sharing env_var across bindings of the same credential should succeed, got %v", err)
	}

	// Add a binding for a DIFFERENT credential with a different env_var.
	id2, err := s.AddBinding("api.other.com", "other_cred", BindingOpts{
		EnvVar: "OTHER_KEY",
	})
	if err != nil {
		t.Fatalf("add other-credential binding: %v", err)
	}

	// Attempt to reuse the other credential's env_var on the first binding;
	// must fail because the env_var belongs to a different credential.
	other := "OTHER_KEY"
	if _, _, _, err := s.UpdateBindingWithRuleSync(id, BindingUpdateOpts{EnvVar: &other}); err == nil {
		t.Error("reusing another credential's env_var should fail")
	}

	// Clear env_var on the other credential's binding.
	cleared := ""
	if _, _, _, err := s.UpdateBindingWithRuleSync(id2, BindingUpdateOpts{EnvVar: &cleared}); err != nil {
		t.Fatalf("clear env_var: %v", err)
	}
	bindings, _ = s.ListBindings()
	for _, b := range bindings {
		if b.ID == id2 && b.EnvVar != "" {
			t.Errorf("env_var should be cleared, got %q", b.EnvVar)
		}
	}

	// With the other credential's env_var cleared, reusing OTHER_KEY on
	// the first binding should now succeed.
	if _, _, _, err := s.UpdateBindingWithRuleSync(id, BindingUpdateOpts{EnvVar: &other}); err != nil {
		t.Errorf("reusing freed env_var should succeed, got %v", err)
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
	if info.Mode().Perm() != 0o600 {
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
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := New(path)
	if err != nil {
		t.Fatalf("New with existing file: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Verify permissions were tightened.
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file permissions = %o, want 0600", info.Mode().Perm())
	}
}

// TestMigrationBindingUniqueDedup verifies that migration 5 (the
// (credential, destination) UNIQUE index) collapses pre-existing
// duplicate rows into the oldest entry instead of failing the upgrade.
// The test manually applies migrations 1-4, seeds two duplicate
// bindings via raw SQL, then applies migration 5 and asserts only one
// row remains.
// openMigrationTestDB opens a fresh SQLite file under a temp directory with
// the same PRAGMAs the Store uses, plus a golang-migrate migrator wired to
// the embedded migrations FS. It returns the db handle and the migrator so
// each test can step migrations up to an arbitrary version before seeding.
func openMigrationTestDB(t *testing.T, name string) (*sql.DB, *migrate.Migrate) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		t.Fatalf("set WAL: %v", err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		t.Fatalf("set busy timeout: %v", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatalf("enable foreign keys: %v", err)
	}

	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("new iofs source: %v", err)
	}
	driver, err := migsqlite.WithInstance(db, &migsqlite.Config{NoTxWrap: false})
	if err != nil {
		t.Fatalf("new migrate driver: %v", err)
	}
	m, err := migrate.NewWithInstance("iofs", source, "sqlite", driver)
	if err != nil {
		t.Fatalf("new migrator: %v", err)
	}
	return db, m
}

// TestMigrationBindingUniqueDedupIdentical verifies that migration 5 collapses
// byte-identical duplicate bindings to the lowest-id row. Rows that compare
// equal on every behavioral column are safe to drop because the surviving
// row produces identical resolver behavior.
func TestMigrationBindingUniqueDedupIdentical(t *testing.T) {
	db, m := openMigrationTestDB(t, "dedup_identical.db")

	if err := m.Steps(4); err != nil {
		t.Fatalf("apply migrations 1-4: %v", err)
	}
	v, dirty, err := m.Version()
	if err != nil {
		t.Fatalf("version after step 4: %v", err)
	}
	if v != 4 || dirty {
		t.Fatalf("expected version 4, got version=%d dirty=%v", v, dirty)
	}

	// Seed two byte-identical rows. Only the auto-increment id differs.
	// These mirror the "retried AddBinding" case where a writer repeated
	// the same call before the UNIQUE index existed.
	for i := 0; i < 2; i++ {
		if _, err := db.Exec(
			`INSERT INTO bindings (destination, ports, credential, header, template, protocols, env_var)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			"api.example.com", nil, "my_key", "Authorization", "Bearer {value}", nil, nil,
		); err != nil {
			t.Fatalf("seed binding %d: %v", i, err)
		}
	}
	var before int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM bindings WHERE credential = ? AND destination = ?",
		"my_key", "api.example.com",
	).Scan(&before); err != nil {
		t.Fatalf("count before: %v", err)
	}
	if before != 2 {
		t.Fatalf("expected 2 identical rows before migration, got %d", before)
	}

	if err := m.Steps(1); err != nil {
		t.Fatalf("apply migration 5: %v", err)
	}
	v, dirty, err = m.Version()
	if err != nil {
		t.Fatalf("version after step 5: %v", err)
	}
	if v != 5 || dirty {
		t.Fatalf("expected version 5 clean, got version=%d dirty=%v", v, dirty)
	}

	var after int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM bindings WHERE credential = ? AND destination = ?",
		"my_key", "api.example.com",
	).Scan(&after); err != nil {
		t.Fatalf("count after: %v", err)
	}
	if after != 1 {
		t.Errorf("expected 1 row after dedup, got %d", after)
	}

	// The surviving row must be the oldest (lowest id). Since both inputs
	// were identical, the surviving row must still have the seeded values.
	var header sql.NullString
	if err := db.QueryRow(
		"SELECT header FROM bindings WHERE credential = ? AND destination = ? ORDER BY id LIMIT 1",
		"my_key", "api.example.com",
	).Scan(&header); err != nil {
		t.Fatalf("scan survivor: %v", err)
	}
	if header.String != "Authorization" {
		t.Errorf("surviving header = %q, want Authorization", header.String)
	}

	// A further insert of the same pair must now fail due to the
	// UNIQUE index established by migration 5.
	if _, err := db.Exec(
		`INSERT INTO bindings (destination, credential) VALUES (?, ?)`,
		"api.example.com", "my_key",
	); err == nil {
		t.Error("expected UNIQUE violation on duplicate insert after migration 5")
	}
}

// TestMigrationBindingUniqueDedupNoDuplicates verifies migration 5 succeeds
// on a database with no duplicates at all. This is the common upgrade path
// where the operator never hit a race and every (credential, destination)
// group already has exactly one row.
func TestMigrationBindingUniqueDedupNoDuplicates(t *testing.T) {
	db, m := openMigrationTestDB(t, "dedup_none.db")

	if err := m.Steps(4); err != nil {
		t.Fatalf("apply migrations 1-4: %v", err)
	}

	// Seed three distinct bindings. No duplicates. Migration must succeed
	// and every row must survive.
	seeds := []struct {
		destination string
		credential  string
	}{
		{"api.example.com", "key_a"},
		{"api.example.com", "key_b"},
		{"other.example.com", "key_a"},
	}
	for _, s := range seeds {
		if _, err := db.Exec(
			`INSERT INTO bindings (destination, credential) VALUES (?, ?)`,
			s.destination, s.credential,
		); err != nil {
			t.Fatalf("seed %+v: %v", s, err)
		}
	}

	if err := m.Steps(1); err != nil {
		t.Fatalf("apply migration 5: %v", err)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM bindings").Scan(&count); err != nil {
		t.Fatalf("count bindings: %v", err)
	}
	if count != len(seeds) {
		t.Errorf("expected %d bindings to survive, got %d", len(seeds), count)
	}
}

// TestMigrationBindingUniqueDedupRejectsConflicts verifies that migration 5
// refuses to silently drop bindings that share (credential, destination) but
// differ on behavioral columns. Each sub-test seeds two rows that share the
// primary key but differ on exactly one column and confirms the migration
// aborts with an operator-facing error that mentions manual resolution.
func TestMigrationBindingUniqueDedupRejectsConflicts(t *testing.T) {
	type conflictCase struct {
		name        string
		destination string
		firstValues []any
		secondCols  string
		secondArgs  []any
	}
	cases := []conflictCase{
		{
			name:        "different ports",
			destination: "api.example.com",
			firstValues: []any{"api.example.com", `[443]`, "my_key", nil, nil, nil, nil},
			secondCols:  "destination, ports, credential, header, template, protocols, env_var",
			secondArgs:  []any{"api.example.com", `[8080]`, "my_key", nil, nil, nil, nil},
		},
		{
			name:        "different protocols",
			destination: "api.example.com",
			firstValues: []any{"api.example.com", nil, "my_key", nil, nil, `["tcp"]`, nil},
			secondCols:  "destination, ports, credential, header, template, protocols, env_var",
			secondArgs:  []any{"api.example.com", nil, "my_key", nil, nil, `["udp"]`, nil},
		},
		{
			name:        "different header",
			destination: "api.example.com",
			firstValues: []any{"api.example.com", nil, "my_key", "Authorization", "Bearer {value}", nil, nil},
			secondCols:  "destination, ports, credential, header, template, protocols, env_var",
			secondArgs:  []any{"api.example.com", nil, "my_key", "X-Api-Key", "Bearer {value}", nil, nil},
		},
		{
			name:        "different template",
			destination: "api.example.com",
			firstValues: []any{"api.example.com", nil, "my_key", "Authorization", "Bearer {value}", nil, nil},
			secondCols:  "destination, ports, credential, header, template, protocols, env_var",
			secondArgs:  []any{"api.example.com", nil, "my_key", "Authorization", "Token {value}", nil, nil},
		},
		{
			name:        "different env_var",
			destination: "api.example.com",
			firstValues: []any{"api.example.com", nil, "my_key", nil, nil, nil, "KEY_A"},
			secondCols:  "destination, ports, credential, header, template, protocols, env_var",
			secondArgs:  []any{"api.example.com", nil, "my_key", nil, nil, nil, "KEY_B"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, m := openMigrationTestDB(t, "dedup_conflict_"+strings.ReplaceAll(tc.name, " ", "_")+".db")
			if err := m.Steps(4); err != nil {
				t.Fatalf("apply migrations 1-4: %v", err)
			}
			if _, err := db.Exec(
				`INSERT INTO bindings (destination, ports, credential, header, template, protocols, env_var)
				 VALUES (?, ?, ?, ?, ?, ?, ?)`,
				tc.firstValues...,
			); err != nil {
				t.Fatalf("seed first row: %v", err)
			}
			if _, err := db.Exec(
				`INSERT INTO bindings (`+tc.secondCols+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				tc.secondArgs...,
			); err != nil {
				t.Fatalf("seed second row: %v", err)
			}

			err := m.Steps(1)
			if err == nil {
				t.Fatalf("expected migration 5 to fail on %s conflict, got nil", tc.name)
			}
			msg := err.Error()
			if !strings.Contains(msg, "sluice binding list") {
				t.Errorf("migration error missing operator guidance: %q", msg)
			}
			if !strings.Contains(msg, "upgrade blocked") {
				t.Errorf("migration error missing upgrade-blocked marker: %q", msg)
			}
			// Both rows must still exist after the aborted migration so
			// the operator can resolve them on the old binary.
			var count int
			if err := db.QueryRow(
				"SELECT COUNT(*) FROM bindings WHERE credential = ? AND destination = ?",
				"my_key", tc.destination,
			).Scan(&count); err != nil {
				t.Fatalf("count bindings after failed migration: %v", err)
			}
			if count != 2 {
				t.Errorf("expected both bindings to survive aborted migration, got %d", count)
			}
		})
	}
}

// TestMigrationBindingUniqueDedupCleansPairedRules verifies that migration
// 5 also removes duplicate auto-created allow rules that were paired with
// the bindings being collapsed. AddRuleAndBinding inserts the rule and the
// binding in one transaction, so concurrent pre-migration writers racing
// on the same (credential, destination) pair each produce their own paired
// rule. Dedup keeps the lowest-id binding but leaves the extra rules
// orphaned. The fix deduplicates rules by (source, destination) the same
// way: keep the lowest-id row per group and drop the rest. This test
// seeds three bindings and three paired rules on the same destination,
// plus an unrelated manual rule and an unrelated destination, and asserts
// the end state.
func TestMigrationBindingUniqueDedupCleansPairedRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dedup_rules.db")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		t.Fatalf("set WAL: %v", err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		t.Fatalf("set busy timeout: %v", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatalf("enable foreign keys: %v", err)
	}

	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("new iofs source: %v", err)
	}
	driver, err := migsqlite.WithInstance(db, &migsqlite.Config{NoTxWrap: false})
	if err != nil {
		t.Fatalf("new migrate driver: %v", err)
	}
	m, err := migrate.NewWithInstance("iofs", source, "sqlite", driver)
	if err != nil {
		t.Fatalf("new migrator: %v", err)
	}

	// Stop at version 4 (pre-unique index) so we can seed duplicates.
	if err := m.Steps(4); err != nil {
		t.Fatalf("apply migrations 1-4: %v", err)
	}

	// Seed three bindings that share (credential, destination). The
	// lowest-id row survives dedup, the other two get dropped.
	for i := 0; i < 3; i++ {
		if _, err := db.Exec(
			`INSERT INTO bindings (destination, credential) VALUES (?, ?)`,
			"api.example.com", "my_key",
		); err != nil {
			t.Fatalf("seed binding: %v", err)
		}
	}

	// Seed three paired rules at the same destination. Each simulates a
	// pre-migration AddRuleAndBinding insert from a racing writer. One
	// must survive (lowest id), the others must be cleaned up.
	for i := 0; i < 3; i++ {
		if _, err := db.Exec(
			`INSERT INTO rules (verdict, destination, source, name) VALUES (?, ?, ?, ?)`,
			"allow", "api.example.com", "binding-add:my_key", "auto",
		); err != nil {
			t.Fatalf("seed paired rule: %v", err)
		}
	}

	// Seed a rule tagged with the cred-add prefix at the same destination.
	// It has a distinct (source, destination) group, so it must survive.
	if _, err := db.Exec(
		`INSERT INTO rules (verdict, destination, source, name) VALUES (?, ?, ?, ?)`,
		"allow", "api.example.com", "cred-add:my_key", "auto",
	); err != nil {
		t.Fatalf("seed cred-add rule: %v", err)
	}

	// Seed a second binding on a different destination plus its paired
	// rule. Both must survive because they are unique.
	if _, err := db.Exec(
		`INSERT INTO bindings (destination, credential) VALUES (?, ?)`,
		"other.example.com", "my_key",
	); err != nil {
		t.Fatalf("seed other binding: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO rules (verdict, destination, source, name) VALUES (?, ?, ?, ?)`,
		"allow", "other.example.com", "binding-add:my_key", "auto",
	); err != nil {
		t.Fatalf("seed other rule: %v", err)
	}

	// Seed an unrelated manual rule to confirm the migration ignores
	// rules with other source tags.
	if _, err := db.Exec(
		`INSERT INTO rules (verdict, destination, source, name) VALUES (?, ?, ?, ?)`,
		"allow", "api.example.com", "manual", "hand-written",
	); err != nil {
		t.Fatalf("seed manual rule: %v", err)
	}

	// Apply migration 5.
	if err := m.Steps(1); err != nil {
		t.Fatalf("apply migration 5: %v", err)
	}

	// Bindings: one row per (credential, destination). Three at api +
	// one at other collapse to two.
	var bcount int
	if err := db.QueryRow("SELECT COUNT(*) FROM bindings").Scan(&bcount); err != nil {
		t.Fatalf("count bindings: %v", err)
	}
	if bcount != 2 {
		t.Errorf("expected 2 bindings after dedup, got %d", bcount)
	}

	// Paired "binding-add:my_key" rules at api.example.com must collapse
	// to one (lowest id). The cred-add:my_key rule at api is a different
	// (source, destination) group and must survive.
	var bindingAddAtAPI int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM rules WHERE destination = ? AND source = ?`,
		"api.example.com", "binding-add:my_key",
	).Scan(&bindingAddAtAPI); err != nil {
		t.Fatalf("count binding-add rules at api: %v", err)
	}
	if bindingAddAtAPI != 1 {
		t.Errorf("expected 1 binding-add:my_key rule at api.example.com after dedup, got %d", bindingAddAtAPI)
	}

	var credAddAtAPI int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM rules WHERE destination = ? AND source = ?`,
		"api.example.com", "cred-add:my_key",
	).Scan(&credAddAtAPI); err != nil {
		t.Fatalf("count cred-add rules at api: %v", err)
	}
	if credAddAtAPI != 1 {
		t.Errorf("expected 1 cred-add:my_key rule at api.example.com to survive, got %d", credAddAtAPI)
	}

	// The unique rule at other.example.com must still exist.
	var otherCount int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM rules WHERE destination = ? AND source = ?`,
		"other.example.com", "binding-add:my_key",
	).Scan(&otherCount); err != nil {
		t.Fatalf("count other rule: %v", err)
	}
	if otherCount != 1 {
		t.Errorf("expected binding-add:my_key rule at other.example.com to remain, got %d", otherCount)
	}

	// The unrelated manual rule must survive.
	var manualCount int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM rules WHERE source = 'manual'`,
	).Scan(&manualCount); err != nil {
		t.Fatalf("count manual rules: %v", err)
	}
	if manualCount != 1 {
		t.Errorf("expected 1 manual rule to survive, got %d", manualCount)
	}
}

// TestMigrationBindingUniqueDedupPreservesSingletonRules verifies that
// migration 5 does not delete paired rules that have no duplicates. In
// particular, a rule that was deliberately kept after a "binding remove"
// (source like binding-add:X but no matching binding) must still be
// present after the upgrade. The rule is the only row in its
// (source, destination) group, so MIN(id) is the identity and the DELETE
// statement leaves it alone.
func TestMigrationBindingUniqueDedupPreservesSingletonRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dedup_keep.db")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		t.Fatalf("set WAL: %v", err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		t.Fatalf("set busy timeout: %v", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatalf("enable foreign keys: %v", err)
	}

	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("new iofs source: %v", err)
	}
	driver, err := migsqlite.WithInstance(db, &migsqlite.Config{NoTxWrap: false})
	if err != nil {
		t.Fatalf("new migrate driver: %v", err)
	}
	m, err := migrate.NewWithInstance("iofs", source, "sqlite", driver)
	if err != nil {
		t.Fatalf("new migrator: %v", err)
	}

	if err := m.Steps(4); err != nil {
		t.Fatalf("apply migrations 1-4: %v", err)
	}

	// Seed a standalone rule with no matching binding. This mirrors the
	// "binding remove but kept the rule" case.
	if _, err := db.Exec(
		`INSERT INTO rules (verdict, destination, source) VALUES (?, ?, ?)`,
		"allow", "keep.example.com", "binding-add:k",
	); err != nil {
		t.Fatalf("seed standalone rule: %v", err)
	}

	if err := m.Steps(1); err != nil {
		t.Fatalf("apply migration 5: %v", err)
	}

	var kept int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM rules WHERE destination = ? AND source = ?`,
		"keep.example.com", "binding-add:k",
	).Scan(&kept); err != nil {
		t.Fatalf("count kept rule: %v", err)
	}
	if kept != 1 {
		t.Errorf("expected singleton rule to survive migration, got %d", kept)
	}
}

// TestMigrationBindingUniqueDedupCaseInsensitive verifies that migration 5
// collapses pre-existing rows that differ only in destination case and
// then installs a case-insensitive unique index. Policy matching is
// case-insensitive, so "api.example.com" and "API.EXAMPLE.COM" target the
// exact same set of connections and must be treated as duplicates.
// Regression for codex iteration 6 finding 1.
func TestMigrationBindingUniqueDedupCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dedup_nocase.db")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		t.Fatalf("set WAL: %v", err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		t.Fatalf("set busy timeout: %v", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatalf("enable foreign keys: %v", err)
	}

	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("new iofs source: %v", err)
	}
	driver, err := migsqlite.WithInstance(db, &migsqlite.Config{NoTxWrap: false})
	if err != nil {
		t.Fatalf("new migrate driver: %v", err)
	}
	m, err := migrate.NewWithInstance("iofs", source, "sqlite", driver)
	if err != nil {
		t.Fatalf("new migrator: %v", err)
	}

	// Apply migrations 1-4 to reach the schema right before migration 5.
	// No unique index exists on bindings(credential, destination) yet, so
	// case-variant duplicates can be seeded directly.
	if err := m.Steps(4); err != nil {
		t.Fatalf("apply migrations 1-4: %v", err)
	}

	// Seed two bindings that share (credential, LOWER(destination)) but
	// differ in the stored case.
	if _, err := db.Exec(
		`INSERT INTO bindings (destination, credential) VALUES (?, ?)`,
		"api.example.com", "my_key",
	); err != nil {
		t.Fatalf("seed first binding: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO bindings (destination, credential) VALUES (?, ?)`,
		"API.EXAMPLE.COM", "my_key",
	); err != nil {
		t.Fatalf("seed second binding: %v", err)
	}

	// Pair them with matching auto-created allow rules so the rule dedup
	// path is exercised too.
	if _, err := db.Exec(
		`INSERT INTO rules (verdict, destination, source, name) VALUES (?, ?, ?, ?)`,
		"allow", "api.example.com", "binding-add:my_key", "auto",
	); err != nil {
		t.Fatalf("seed first rule: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO rules (verdict, destination, source, name) VALUES (?, ?, ?, ?)`,
		"allow", "API.EXAMPLE.COM", "binding-add:my_key", "auto",
	); err != nil {
		t.Fatalf("seed second rule: %v", err)
	}

	// Apply migration 5. The seeded duplicates must be collapsed and the
	// unique index must be created as case-insensitive.
	if err := m.Steps(1); err != nil {
		t.Fatalf("apply migration 5: %v", err)
	}
	v, dirty, err := m.Version()
	if err != nil {
		t.Fatalf("version after step 5: %v", err)
	}
	if v != 5 || dirty {
		t.Fatalf("expected version 5 clean, got version=%d dirty=%v", v, dirty)
	}

	var after int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM bindings WHERE credential = ?`,
		"my_key",
	).Scan(&after); err != nil {
		t.Fatalf("count after: %v", err)
	}
	if after != 1 {
		t.Errorf("expected 1 binding after case-insensitive dedup, got %d", after)
	}

	var rulesAfter int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM rules WHERE source = ?`,
		"binding-add:my_key",
	).Scan(&rulesAfter); err != nil {
		t.Fatalf("count rules after: %v", err)
	}
	if rulesAfter != 1 {
		t.Errorf("expected 1 paired rule after case-insensitive dedup, got %d", rulesAfter)
	}

	// A further insert of a case variant must now fail due to the new
	// case-insensitive unique index.
	if _, err := db.Exec(
		`INSERT INTO bindings (destination, credential) VALUES (?, ?)`,
		"Api.Example.Com", "my_key",
	); err == nil {
		t.Error("expected UNIQUE violation on case-variant insert after migration 5")
	}
}

// TestMigrationBindingUniqueDedupCaseInsensitiveRejectsConflicts verifies
// that migration 5 refuses to silently drop case-variant duplicates that
// also differ on behavioral columns. The operator must resolve the conflict
// on the old binary before upgrading.
func TestMigrationBindingUniqueDedupCaseInsensitiveRejectsConflicts(t *testing.T) {
	db, m := openMigrationTestDB(t, "dedup_nocase_conflict.db")

	// Apply migrations 1-4 to reach the schema right before migration 5.
	// No unique index exists on bindings(credential, destination) yet, so
	// case-variant rows can be seeded directly.
	if err := m.Steps(4); err != nil {
		t.Fatalf("apply migrations 1-4: %v", err)
	}

	// Two rows that share (credential, LOWER(destination)) but differ in
	// both case and the behavioral column env_var.
	if _, err := db.Exec(
		`INSERT INTO bindings (destination, credential, env_var) VALUES (?, ?, ?)`,
		"api.example.com", "my_key", "KEY_A",
	); err != nil {
		t.Fatalf("seed first: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO bindings (destination, credential, env_var) VALUES (?, ?, ?)`,
		"API.EXAMPLE.COM", "my_key", "KEY_B",
	); err != nil {
		t.Fatalf("seed second: %v", err)
	}

	err := m.Steps(1)
	if err == nil {
		t.Fatalf("expected migration 5 to fail on case-insensitive conflict")
	}
	msg := err.Error()
	if !strings.Contains(msg, "sluice binding list") {
		t.Errorf("migration error missing operator guidance: %q", msg)
	}
	if !strings.Contains(msg, "upgrade blocked") {
		t.Errorf("migration error missing upgrade-blocked marker: %q", msg)
	}

	// Both rows must still exist so the operator can resolve them.
	var count int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM bindings WHERE credential = ?`,
		"my_key",
	).Scan(&count); err != nil {
		t.Fatalf("count bindings after failed migration: %v", err)
	}
	if count != 2 {
		t.Errorf("expected both bindings to survive aborted migration, got %d", count)
	}
}

func TestMigrationCorruptedDB(t *testing.T) {
	// Write garbage to a file and try to open as a SQLite DB.
	dir := t.TempDir()
	path := dir + "/corrupted.db"
	if err := os.WriteFile(path, []byte("this is not a sqlite database"), 0o600); err != nil {
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

// --- Credential Meta tests ---

func TestCredentialMetaMigration(t *testing.T) {
	s := newTestStore(t)

	// Verify credential_meta table exists by querying it.
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM credential_meta").Scan(&count)
	if err != nil {
		t.Fatalf("credential_meta table should exist: %v", err)
	}
	if count != 0 {
		t.Errorf("credential_meta should be empty, got %d", count)
	}
}

func TestCredentialMetaMigrationDown(t *testing.T) {
	// Verify the down migration SQL is valid by checking the embedded file exists
	// and the table can be dropped. We test this indirectly: create a store,
	// verify the table exists, then manually run the down migration.
	s := newTestStore(t)

	// Table should exist after migration.
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM credential_meta").Scan(&count)
	if err != nil {
		t.Fatalf("credential_meta should exist: %v", err)
	}

	// Run the down migration manually.
	_, err = s.db.Exec("DROP TABLE IF EXISTS credential_meta")
	if err != nil {
		t.Fatalf("drop credential_meta: %v", err)
	}

	// Table should no longer exist.
	err = s.db.QueryRow("SELECT COUNT(*) FROM credential_meta").Scan(&count)
	if err == nil {
		t.Error("credential_meta should not exist after drop")
	}
}

func TestAddCredentialMetaStatic(t *testing.T) {
	s := newTestStore(t)

	err := s.AddCredentialMeta("github_pat", "static", "")
	if err != nil {
		t.Fatalf("add static credential meta: %v", err)
	}

	meta, err := s.GetCredentialMeta("github_pat")
	if err != nil {
		t.Fatalf("get credential meta: %v", err)
	}
	if meta == nil {
		t.Fatal("expected non-nil meta")
	}
	if meta.Name != "github_pat" {
		t.Errorf("name = %q, want github_pat", meta.Name)
	}
	if meta.CredType != "static" {
		t.Errorf("cred_type = %q, want static", meta.CredType)
	}
	if meta.TokenURL != "" {
		t.Errorf("token_url = %q, want empty", meta.TokenURL)
	}
	if meta.CreatedAt == "" {
		t.Error("created_at should not be empty")
	}
}

func TestAddCredentialMetaOAuth(t *testing.T) {
	s := newTestStore(t)

	err := s.AddCredentialMeta("openai_oauth", "oauth", "https://auth0.openai.com/oauth/token")
	if err != nil {
		t.Fatalf("add oauth credential meta: %v", err)
	}

	meta, err := s.GetCredentialMeta("openai_oauth")
	if err != nil {
		t.Fatalf("get credential meta: %v", err)
	}
	if meta == nil {
		t.Fatal("expected non-nil meta")
	}
	if meta.Name != "openai_oauth" {
		t.Errorf("name = %q, want openai_oauth", meta.Name)
	}
	if meta.CredType != "oauth" {
		t.Errorf("cred_type = %q, want oauth", meta.CredType)
	}
	if meta.TokenURL != "https://auth0.openai.com/oauth/token" {
		t.Errorf("token_url = %q, want https://auth0.openai.com/oauth/token", meta.TokenURL)
	}
}

func TestAddCredentialMetaDefaultType(t *testing.T) {
	s := newTestStore(t)

	// Empty cred type should default to "static".
	err := s.AddCredentialMeta("test_cred", "", "")
	if err != nil {
		t.Fatalf("add credential meta with empty type: %v", err)
	}

	meta, err := s.GetCredentialMeta("test_cred")
	if err != nil {
		t.Fatalf("get credential meta: %v", err)
	}
	if meta.CredType != "static" {
		t.Errorf("cred_type = %q, want static (default)", meta.CredType)
	}
}

func TestAddCredentialMetaValidation(t *testing.T) {
	s := newTestStore(t)

	// Empty name.
	err := s.AddCredentialMeta("", "static", "")
	if err == nil {
		t.Error("expected error for empty name")
	}

	// Invalid type.
	err = s.AddCredentialMeta("test", "bogus", "")
	if err == nil {
		t.Error("expected error for invalid credential type")
	}

	// OAuth without token URL.
	err = s.AddCredentialMeta("test", "oauth", "")
	if err == nil {
		t.Error("expected error for oauth without token_url")
	}
}

func TestAddCredentialMetaDuplicate(t *testing.T) {
	s := newTestStore(t)

	err := s.AddCredentialMeta("test_cred", "static", "")
	if err != nil {
		t.Fatalf("first add: %v", err)
	}

	// Re-adding the same name should succeed (upsert) so credential
	// rotation works without requiring a remove-then-add sequence.
	err = s.AddCredentialMeta("test_cred", "static", "")
	if err != nil {
		t.Errorf("upsert should succeed: %v", err)
	}
}

func TestAddCredentialMetaUpsertChangesType(t *testing.T) {
	s := newTestStore(t)

	// Start as static.
	if err := s.AddCredentialMeta("rotating", "static", ""); err != nil {
		t.Fatalf("first add: %v", err)
	}
	meta, err := s.GetCredentialMeta("rotating")
	if err != nil {
		t.Fatalf("get after first add: %v", err)
	}
	if meta.CredType != "static" {
		t.Fatalf("expected static, got %q", meta.CredType)
	}

	// Upsert to oauth.
	if err := s.AddCredentialMeta("rotating", "oauth", "https://auth.example.com/token"); err != nil {
		t.Fatalf("upsert to oauth: %v", err)
	}
	meta, err = s.GetCredentialMeta("rotating")
	if err != nil {
		t.Fatalf("get after upsert: %v", err)
	}
	if meta.CredType != "oauth" {
		t.Errorf("expected oauth after upsert, got %q", meta.CredType)
	}
	if meta.TokenURL != "https://auth.example.com/token" {
		t.Errorf("expected token URL after upsert, got %q", meta.TokenURL)
	}
}

func TestGetCredentialMetaNotFound(t *testing.T) {
	s := newTestStore(t)

	meta, err := s.GetCredentialMeta("nonexistent")
	if err != nil {
		t.Fatalf("get nonexistent: %v", err)
	}
	if meta != nil {
		t.Errorf("expected nil for nonexistent, got %+v", meta)
	}
}

func TestListCredentialMeta(t *testing.T) {
	s := newTestStore(t)

	// Empty list.
	metas, err := s.ListCredentialMeta()
	if err != nil {
		t.Fatalf("list empty: %v", err)
	}
	if len(metas) != 0 {
		t.Errorf("expected 0 metas, got %d", len(metas))
	}

	// Add multiple credentials.
	_ = s.AddCredentialMeta("beta_oauth", "oauth", "https://example.com/token")
	_ = s.AddCredentialMeta("alpha_static", "static", "")
	_ = s.AddCredentialMeta("gamma_oauth", "oauth", "https://other.com/oauth/token")

	metas, err = s.ListCredentialMeta()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(metas) != 3 {
		t.Fatalf("expected 3 metas, got %d", len(metas))
	}

	// Should be ordered by name.
	if metas[0].Name != "alpha_static" {
		t.Errorf("metas[0].Name = %q, want alpha_static", metas[0].Name)
	}
	if metas[1].Name != "beta_oauth" {
		t.Errorf("metas[1].Name = %q, want beta_oauth", metas[1].Name)
	}
	if metas[2].Name != "gamma_oauth" {
		t.Errorf("metas[2].Name = %q, want gamma_oauth", metas[2].Name)
	}

	// Verify types.
	if metas[0].CredType != "static" {
		t.Errorf("metas[0].CredType = %q, want static", metas[0].CredType)
	}
	if metas[1].CredType != "oauth" {
		t.Errorf("metas[1].CredType = %q, want oauth", metas[1].CredType)
	}
	if metas[1].TokenURL != "https://example.com/token" {
		t.Errorf("metas[1].TokenURL = %q, want https://example.com/token", metas[1].TokenURL)
	}
}

func TestRemoveCredentialMeta(t *testing.T) {
	s := newTestStore(t)

	_ = s.AddCredentialMeta("test_cred", "static", "")

	deleted, err := s.RemoveCredentialMeta("test_cred")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !deleted {
		t.Error("expected deletion to succeed")
	}

	// Verify it is gone.
	meta, err := s.GetCredentialMeta("test_cred")
	if err != nil {
		t.Fatalf("get after remove: %v", err)
	}
	if meta != nil {
		t.Errorf("expected nil after removal, got %+v", meta)
	}
}

func TestRemoveCredentialMetaNonExistent(t *testing.T) {
	s := newTestStore(t)

	deleted, err := s.RemoveCredentialMeta("nonexistent")
	if err != nil {
		t.Fatalf("remove nonexistent: %v", err)
	}
	if deleted {
		t.Error("expected no deletion for nonexistent name")
	}
}

// TestRemoveCredentialMetaCASHappyPath verifies that a matching row is
// deleted when no concurrent writer has touched it.
func TestRemoveCredentialMetaCASHappyPath(t *testing.T) {
	s := newTestStore(t)
	if err := s.AddCredentialMeta("cas_happy", "static", ""); err != nil {
		t.Fatalf("seed: %v", err)
	}

	removed, noConcurrent, err := s.RemoveCredentialMetaCAS("cas_happy", "static", "")
	if err != nil {
		t.Fatalf("RemoveCredentialMetaCAS: %v", err)
	}
	if !removed {
		t.Error("expected removed=true")
	}
	if !noConcurrent {
		t.Error("expected noConcurrent=true")
	}

	meta, err := s.GetCredentialMeta("cas_happy")
	if err != nil {
		t.Fatal(err)
	}
	if meta != nil {
		t.Errorf("expected row deleted, got %+v", meta)
	}
}

// TestRemoveCredentialMetaCASTypeMismatch verifies that a row whose cred_type
// has been overwritten by a concurrent writer is left alone.
func TestRemoveCredentialMetaCASTypeMismatch(t *testing.T) {
	s := newTestStore(t)

	// We "inserted" static but a concurrent writer upserted the row as
	// oauth. Our rollback must not delete their state.
	if err := s.AddCredentialMeta("cas_type", "oauth", "https://auth.example.com/token"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	removed, noConcurrent, err := s.RemoveCredentialMetaCAS("cas_type", "static", "")
	if err != nil {
		t.Fatalf("RemoveCredentialMetaCAS: %v", err)
	}
	if removed {
		t.Error("expected removed=false on type mismatch")
	}
	if noConcurrent {
		t.Error("expected noConcurrent=false on type mismatch")
	}

	// Row must still be there with the winner's values.
	meta, err := s.GetCredentialMeta("cas_type")
	if err != nil {
		t.Fatal(err)
	}
	if meta == nil {
		t.Fatal("expected winner's meta row to be preserved")
	}
	if meta.CredType != "oauth" || meta.TokenURL != "https://auth.example.com/token" {
		t.Errorf("preserved row has wrong values: %+v", meta)
	}
}

// TestRemoveCredentialMetaCASTokenURLMismatch verifies that a row whose
// token_url has been overwritten is left alone.
func TestRemoveCredentialMetaCASTokenURLMismatch(t *testing.T) {
	s := newTestStore(t)

	// We "inserted" with one token URL but a concurrent writer upserted a
	// different one.
	if err := s.AddCredentialMeta("cas_url", "oauth", "https://winner.example.com/token"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	removed, noConcurrent, err := s.RemoveCredentialMetaCAS("cas_url", "oauth", "https://ours.example.com/token")
	if err != nil {
		t.Fatalf("RemoveCredentialMetaCAS: %v", err)
	}
	if removed {
		t.Error("expected removed=false on token_url mismatch")
	}
	if noConcurrent {
		t.Error("expected noConcurrent=false on token_url mismatch")
	}

	meta, err := s.GetCredentialMeta("cas_url")
	if err != nil {
		t.Fatal(err)
	}
	if meta == nil || meta.TokenURL != "https://winner.example.com/token" {
		t.Errorf("expected winner's token URL preserved, got %+v", meta)
	}
}

// TestRemoveCredentialMetaCASMissingRow verifies that a missing row is a
// benign no-op: removed=false, noConcurrent=true, no error.
func TestRemoveCredentialMetaCASMissingRow(t *testing.T) {
	s := newTestStore(t)

	removed, noConcurrent, err := s.RemoveCredentialMetaCAS("never_existed", "static", "")
	if err != nil {
		t.Fatalf("RemoveCredentialMetaCAS missing row: %v", err)
	}
	if removed {
		t.Error("expected removed=false on missing row")
	}
	if !noConcurrent {
		t.Error("expected noConcurrent=true on missing row")
	}
}

func TestCredentialMetaCRUDRoundTrip(t *testing.T) {
	s := newTestStore(t)

	// Add several entries of different types.
	_ = s.AddCredentialMeta("static_cred", "static", "")
	_ = s.AddCredentialMeta("oauth_cred", "oauth", "https://auth.example.com/token")

	// List and verify count.
	metas, err := s.ListCredentialMeta()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(metas) != 2 {
		t.Fatalf("expected 2, got %d", len(metas))
	}

	// Remove one.
	deleted, err := s.RemoveCredentialMeta("static_cred")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !deleted {
		t.Error("expected deletion")
	}

	// List should now have 1.
	metas, err = s.ListCredentialMeta()
	if err != nil {
		t.Fatalf("list after remove: %v", err)
	}
	if len(metas) != 1 {
		t.Fatalf("expected 1, got %d", len(metas))
	}
	if metas[0].Name != "oauth_cred" {
		t.Errorf("remaining name = %q, want oauth_cred", metas[0].Name)
	}
}

// --- Binding env_var tests ---

func TestBindingEnvVarMigration(t *testing.T) {
	s := newTestStore(t)

	// Verify the env_var column exists by inserting and reading back.
	_, err := s.AddBinding("api.example.com", "key", BindingOpts{
		Ports:  []int{443},
		EnvVar: "OPENAI_API_KEY",
	})
	if err != nil {
		t.Fatalf("add binding with env_var: %v", err)
	}

	bindings, err := s.ListBindings()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if bindings[0].EnvVar != "OPENAI_API_KEY" {
		t.Errorf("env_var = %q, want OPENAI_API_KEY", bindings[0].EnvVar)
	}
}

func TestBindingEnvVarEmpty(t *testing.T) {
	s := newTestStore(t)

	// Binding without env_var should have empty string.
	_, err := s.AddBinding("api.example.com", "key", BindingOpts{
		Ports: []int{443},
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	bindings, _ := s.ListBindings()
	if bindings[0].EnvVar != "" {
		t.Errorf("env_var should be empty, got %q", bindings[0].EnvVar)
	}
}

func TestAddBindingWithEnvVar(t *testing.T) {
	s := newTestStore(t)

	id, err := s.AddBinding("api.openai.com", "openai_key", BindingOpts{
		Ports:  []int{443},
		Header: "Authorization",
		EnvVar: "OPENAI_API_KEY",
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
	if b.EnvVar != "OPENAI_API_KEY" {
		t.Errorf("env_var = %q, want OPENAI_API_KEY", b.EnvVar)
	}
	if b.Credential != "openai_key" {
		t.Errorf("credential = %q", b.Credential)
	}
	if b.Header != "Authorization" {
		t.Errorf("header = %q", b.Header)
	}
}

func TestAddBindingEnvVarUniqueness(t *testing.T) {
	s := newTestStore(t)

	// First binding with env_var should succeed.
	_, err := s.AddBinding("api.openai.com", "openai_key", BindingOpts{
		Ports:  []int{443},
		EnvVar: "OPENAI_API_KEY",
	})
	if err != nil {
		t.Fatalf("first add: %v", err)
	}

	// Second binding with same env_var should fail.
	_, err = s.AddBinding("api.other.com", "other_key", BindingOpts{
		Ports:  []int{443},
		EnvVar: "OPENAI_API_KEY",
	})
	if err == nil {
		t.Fatal("expected error for duplicate env_var")
	}
	if !strings.Contains(err.Error(), "already used") {
		t.Errorf("error should mention 'already used', got: %v", err)
	}

	// Binding without env_var should still succeed.
	_, err = s.AddBinding("api.other.com", "other_key", BindingOpts{
		Ports: []int{443},
	})
	if err != nil {
		t.Fatalf("add without env_var should succeed: %v", err)
	}

	// Another binding with a different env_var should succeed.
	_, err = s.AddBinding("api.telegram.org", "telegram_bot", BindingOpts{
		Ports:  []int{443},
		EnvVar: "TELEGRAM_BOT_TOKEN",
	})
	if err != nil {
		t.Fatalf("add with different env_var should succeed: %v", err)
	}
}

// TestAddBindingEnvVarUniquenessConcurrent is a regression test for the
// check-then-insert race that existed before AddBinding wrapped the
// env_var uniqueness check and INSERT in a single transaction. Migration
// 000005 dropped the DB-level env_var unique index, so this invariant is
// now enforced purely in Go. Concurrent callers trying to register the
// same env_var against different credentials must have exactly one
// succeed; the rest must fail with the "already used" error.
func TestAddBindingEnvVarUniquenessConcurrent(t *testing.T) {
	s := newTestStore(t)

	const workers = 20
	var (
		wg       sync.WaitGroup
		successM sync.Mutex
		success  int
		failures int
	)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			dest := fmt.Sprintf("api.svc%d.example.com", i)
			cred := fmt.Sprintf("cred-%d", i)
			_, err := s.AddBinding(dest, cred, BindingOpts{
				Ports:  []int{443},
				EnvVar: "SHARED_KEY",
			})
			successM.Lock()
			defer successM.Unlock()
			if err == nil {
				success++
				return
			}
			if !strings.Contains(err.Error(), "already used") {
				t.Errorf("worker %d: unexpected error: %v", i, err)
				return
			}
			failures++
		}(i)
	}
	close(start)
	wg.Wait()

	if success != 1 {
		t.Errorf("expected exactly 1 successful AddBinding, got %d", success)
	}
	if failures != workers-1 {
		t.Errorf("expected %d rejected AddBinding calls, got %d", workers-1, failures)
	}

	// Only one row should have env_var SHARED_KEY after the dust settles.
	bindings, err := s.ListBindingsWithEnvVar()
	if err != nil {
		t.Fatalf("ListBindingsWithEnvVar: %v", err)
	}
	count := 0
	for _, b := range bindings {
		if b.EnvVar == "SHARED_KEY" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 binding with SHARED_KEY env_var, got %d", count)
	}
}

func TestListBindingsWithEnvVar(t *testing.T) {
	s := newTestStore(t)

	// Add bindings with and without env_var.
	_, _ = s.AddBinding("api.openai.com", "openai_key", BindingOpts{
		Ports:  []int{443},
		EnvVar: "OPENAI_API_KEY",
	})
	_, _ = s.AddBinding("api.github.com", "github_key", BindingOpts{
		Ports: []int{443},
		// No env_var.
	})
	_, _ = s.AddBinding("api.telegram.org", "telegram_bot", BindingOpts{
		Ports:  []int{443},
		EnvVar: "TELEGRAM_BOT_TOKEN",
	})

	// ListBindingsWithEnvVar should return only the two with env_var set.
	bindings, err := s.ListBindingsWithEnvVar()
	if err != nil {
		t.Fatalf("ListBindingsWithEnvVar: %v", err)
	}
	if len(bindings) != 2 {
		t.Fatalf("expected 2 bindings with env_var, got %d", len(bindings))
	}
	if bindings[0].EnvVar != "OPENAI_API_KEY" {
		t.Errorf("bindings[0].EnvVar = %q, want OPENAI_API_KEY", bindings[0].EnvVar)
	}
	if bindings[1].EnvVar != "TELEGRAM_BOT_TOKEN" {
		t.Errorf("bindings[1].EnvVar = %q, want TELEGRAM_BOT_TOKEN", bindings[1].EnvVar)
	}
}

func TestListBindingsWithEnvVarEmpty(t *testing.T) {
	s := newTestStore(t)

	// No bindings at all.
	bindings, err := s.ListBindingsWithEnvVar()
	if err != nil {
		t.Fatalf("ListBindingsWithEnvVar on empty: %v", err)
	}
	if len(bindings) != 0 {
		t.Errorf("expected 0, got %d", len(bindings))
	}

	// Add binding without env_var.
	_, _ = s.AddBinding("api.example.com", "key", BindingOpts{Ports: []int{443}})

	bindings, err = s.ListBindingsWithEnvVar()
	if err != nil {
		t.Fatalf("ListBindingsWithEnvVar: %v", err)
	}
	if len(bindings) != 0 {
		t.Errorf("expected 0 (no env_var set), got %d", len(bindings))
	}
}

func TestAddRuleAndBindingWithEnvVar(t *testing.T) {
	s := newTestStore(t)
	_, bindingID, err := s.AddRuleAndBinding(
		"allow",
		RuleOpts{Destination: "api.openai.com", Ports: []int{443}},
		"openai_key",
		BindingOpts{Ports: []int{443}, EnvVar: "OPENAI_API_KEY"},
	)
	if err != nil {
		t.Fatalf("AddRuleAndBinding with env_var: %v", err)
	}
	if bindingID < 1 {
		t.Errorf("expected positive binding ID, got %d", bindingID)
	}

	bindings, _ := s.ListBindings()
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if bindings[0].EnvVar != "OPENAI_API_KEY" {
		t.Errorf("env_var = %q, want OPENAI_API_KEY", bindings[0].EnvVar)
	}
}

func TestAddRuleAndBindingEnvVarUniqueness(t *testing.T) {
	s := newTestStore(t)

	// First should succeed.
	_, _, err := s.AddRuleAndBinding(
		"allow",
		RuleOpts{Destination: "api.openai.com", Ports: []int{443}},
		"openai_key",
		BindingOpts{Ports: []int{443}, EnvVar: "OPENAI_API_KEY"},
	)
	if err != nil {
		t.Fatalf("first AddRuleAndBinding: %v", err)
	}

	// Second with same env_var should fail.
	_, _, err = s.AddRuleAndBinding(
		"allow",
		RuleOpts{Destination: "api.other.com", Ports: []int{443}},
		"other_key",
		BindingOpts{Ports: []int{443}, EnvVar: "OPENAI_API_KEY"},
	)
	if err == nil {
		t.Fatal("expected error for duplicate env_var in AddRuleAndBinding")
	}
}

func TestListBindingsByCredentialWithEnvVar(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddBinding("api.openai.com", "openai_key", BindingOpts{
		Ports:  []int{443},
		EnvVar: "OPENAI_API_KEY",
	})
	_, _ = s.AddBinding("api.other.com", "other_key", BindingOpts{
		Ports: []int{443},
	})

	bindings, err := s.ListBindingsByCredential("openai_key")
	if err != nil {
		t.Fatalf("ListBindingsByCredential: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1, got %d", len(bindings))
	}
	if bindings[0].EnvVar != "OPENAI_API_KEY" {
		t.Errorf("env_var = %q, want OPENAI_API_KEY", bindings[0].EnvVar)
	}
}

func TestBindingEnvVarMigrationDown(t *testing.T) {
	s := newTestStore(t)

	// Add a binding with env_var to verify data exists.
	_, err := s.AddBinding("api.example.com", "key", BindingOpts{
		Ports:  []int{443},
		EnvVar: "TEST_KEY",
	})
	if err != nil {
		t.Fatalf("add binding: %v", err)
	}

	// Run the down migration manually (recreates bindings without env_var).
	downSQL := `
		CREATE TABLE bindings_backup (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			destination TEXT NOT NULL,
			ports TEXT,
			credential TEXT NOT NULL,
			header TEXT,
			template TEXT,
			protocols TEXT,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		);
		INSERT INTO bindings_backup (id, destination, ports, credential, header, template, protocols, created_at)
			SELECT id, destination, ports, credential, header, template, protocols, created_at FROM bindings;
		DROP TABLE bindings;
		ALTER TABLE bindings_backup RENAME TO bindings;
	`
	if _, execErr := s.db.Exec(downSQL); execErr != nil {
		t.Fatalf("down migration: %v", execErr)
	}

	// The env_var column should no longer exist.
	var envVar string
	scanErr := s.db.QueryRow("SELECT env_var FROM bindings WHERE id = 1").Scan(&envVar)
	if scanErr == nil {
		t.Error("expected error querying env_var after down migration")
	}

	// Data should still be accessible without env_var.
	var dest string
	if destErr := s.db.QueryRow("SELECT destination FROM bindings WHERE id = 1").Scan(&dest); destErr != nil {
		t.Fatalf("binding data lost after down migration: %v", destErr)
	}
	if dest != "api.example.com" {
		t.Errorf("destination = %q, want api.example.com", dest)
	}
}

func TestAddBindingEnvVarFormatValidation(t *testing.T) {
	s := newTestStore(t)

	tests := []struct {
		name   string
		envVar string
		valid  bool
	}{
		{"valid uppercase", "OPENAI_API_KEY", true},
		{"valid lowercase", "my_key", true},
		{"valid underscore start", "_HIDDEN", true},
		{"invalid starts with digit", "1KEY", false},
		{"invalid has spaces", "MY KEY", false},
		{"invalid shell injection", "FOO'; rm -rf / #", false},
		{"invalid has dash", "MY-KEY", false},
		{"invalid has dot", "MY.KEY", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.AddBinding("api.example.com", tc.envVar, BindingOpts{
				Ports:  []int{443},
				EnvVar: tc.envVar,
			})
			if tc.valid && err != nil {
				t.Errorf("expected valid, got error: %v", err)
			}
			if !tc.valid && err == nil {
				t.Errorf("expected error for invalid env_var %q", tc.envVar)
			}
			// Clean up for next iteration.
			if err == nil {
				bindings, _ := s.ListBindings()
				for _, b := range bindings {
					if b.EnvVar == tc.envVar {
						_, _ = s.RemoveBinding(b.ID)
					}
				}
			}
		})
	}
}

// TestAddBindingDuplicateRejected verifies the partial UNIQUE index on
// bindings(credential, destination). Two inserts with the same pair must
// return ErrBindingDuplicate.
func TestAddBindingDuplicateRejected(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.AddBinding("api.example.com", "my_key", BindingOpts{}); err != nil {
		t.Fatalf("first add: %v", err)
	}
	_, err := s.AddBinding("api.example.com", "my_key", BindingOpts{})
	if err == nil {
		t.Fatal("expected duplicate error")
	}
	if !errors.Is(err, ErrBindingDuplicate) {
		t.Errorf("expected ErrBindingDuplicate, got %v", err)
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected descriptive error, got: %v", err)
	}
}

// TestAddRuleAndBindingDuplicateRejected ensures the rule+binding transaction
// also translates UNIQUE violations into ErrBindingDuplicate rather than
// leaving a partially-applied rule behind.
func TestAddRuleAndBindingDuplicateRejected(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.AddBinding("api.example.com", "my_key", BindingOpts{}); err != nil {
		t.Fatalf("seed binding: %v", err)
	}
	_, _, err := s.AddRuleAndBinding(
		"allow",
		RuleOpts{Destination: "api.example.com", Source: "binding-add:my_key"},
		"my_key",
		BindingOpts{},
	)
	if err == nil {
		t.Fatal("expected duplicate error")
	}
	if !errors.Is(err, ErrBindingDuplicate) {
		t.Errorf("expected ErrBindingDuplicate, got %v", err)
	}

	// The rule insert should have been rolled back with the failed binding
	// insert so no orphan rule remains.
	rules, err := s.ListRules(RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after rollback, got %d", len(rules))
	}
}

// TestRemoveRuleByBindingPair verifies that the helper removes auto-created
// rules tagged with either binding-add:<cred> or cred-add:<cred> on the
// given destination, while leaving manually-tagged rules alone.
func TestRemoveRuleByBindingPair(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.AddRule("allow", RuleOpts{
		Destination: "api.example.com",
		Source:      BindingAddSourcePrefix + "cred1",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRule("allow", RuleOpts{
		Destination: "api.example.com",
		Source:      CredAddSourcePrefix + "cred1",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRule("allow", RuleOpts{
		Destination: "api.example.com",
		Source:      "manual",
	}); err != nil {
		t.Fatal(err)
	}

	n, err := s.RemoveRuleByBindingPair("cred1", "api.example.com")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 rules removed, got %d", n)
	}

	rules, err := s.ListRules(RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule remaining (manual), got %d", len(rules))
	}
	if rules[0].Source != "manual" {
		t.Errorf("expected manual rule to remain, got source %q", rules[0].Source)
	}
}

// TestUpdateBindingWithRuleSync verifies the transactional update path:
// binding destination change + paired rule update + returned ruleFound flag.
func TestUpdateBindingWithRuleSync(t *testing.T) {
	s := newTestStore(t)
	ruleID, bindingID, err := s.AddRuleAndBinding(
		"allow",
		RuleOpts{
			Destination: "api.old.com",
			Source:      BindingAddSourcePrefix + "my_key",
		},
		"my_key",
		BindingOpts{},
	)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	newDest := "api.new.com"
	retRuleID, ruleFound, current, err := s.UpdateBindingWithRuleSync(bindingID, BindingUpdateOpts{
		Destination: &newDest,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !ruleFound {
		t.Error("expected ruleFound=true")
	}
	if retRuleID != ruleID {
		t.Errorf("ruleID = %d, want %d", retRuleID, ruleID)
	}
	if current.Destination != "api.old.com" {
		t.Errorf("current.Destination = %q, want api.old.com", current.Destination)
	}

	// Verify the row is updated.
	bindings, _ := s.ListBindings()
	if len(bindings) != 1 || bindings[0].Destination != "api.new.com" {
		t.Errorf("binding destination not updated: %+v", bindings)
	}

	// Run again with no paired rule remaining.
	_, _ = s.RemoveRule(ruleID)
	newerDest := "api.newer.com"
	_, ruleFound2, _, err := s.UpdateBindingWithRuleSync(bindingID, BindingUpdateOpts{
		Destination: &newerDest,
	})
	if err != nil {
		t.Fatalf("update without paired rule: %v", err)
	}
	if ruleFound2 {
		t.Error("expected ruleFound=false when no paired rule exists")
	}
}

// TestUpdateBindingWithRuleSyncPropagatesPortsAndProtocols verifies that
// changing a binding's ports or protocols also rewrites the paired allow
// rule's ports/protocols in the same transaction. Without this propagation
// the binding would match the new port but the paired rule would still
// authorize the old one, breaking the new port and leaking the old.
func TestUpdateBindingWithRuleSyncPropagatesPortsAndProtocols(t *testing.T) {
	s := newTestStore(t)
	ruleID, bindingID, err := s.AddRuleAndBinding(
		"allow",
		RuleOpts{
			Destination: "api.example.com",
			Ports:       []int{443},
			Protocols:   []string{"tcp"},
			Source:      BindingAddSourcePrefix + "cred",
		},
		"cred",
		BindingOpts{
			Ports:     []int{443},
			Protocols: []string{"tcp"},
		},
	)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Change ports and protocols only. Destination stays the same.
	newPorts := []int{8443}
	newProtocols := []string{"tcp", "udp"}
	retRuleID, ruleFound, _, err := s.UpdateBindingWithRuleSync(bindingID, BindingUpdateOpts{
		Ports:     &newPorts,
		Protocols: &newProtocols,
	})
	if err != nil {
		t.Fatalf("update ports/protocols: %v", err)
	}
	if !ruleFound {
		t.Fatal("expected ruleFound=true")
	}
	if retRuleID != ruleID {
		t.Errorf("ruleID mismatch: got %d want %d", retRuleID, ruleID)
	}

	// Verify binding row reflects the new values.
	bindings, _ := s.ListBindings()
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if len(bindings[0].Ports) != 1 || bindings[0].Ports[0] != 8443 {
		t.Errorf("binding ports = %v, want [8443]", bindings[0].Ports)
	}
	if len(bindings[0].Protocols) != 2 {
		t.Errorf("binding protocols = %v, want [tcp udp]", bindings[0].Protocols)
	}

	// Verify the paired allow rule also reflects the new values.
	rules, _ := s.ListRules(RuleFilter{Type: "network"})
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if len(rules[0].Ports) != 1 || rules[0].Ports[0] != 8443 {
		t.Errorf("rule ports = %v, want [8443]", rules[0].Ports)
	}
	if len(rules[0].Protocols) != 2 {
		t.Errorf("rule protocols = %v, want [tcp udp]", rules[0].Protocols)
	}

	// Clearing ports and protocols on the binding should also clear them
	// on the paired rule. An empty slice ([]int{}) is the "no ports" state
	// which the store stores as NULL.
	emptyPorts := []int{}
	emptyProtocols := []string{}
	if _, _, _, err := s.UpdateBindingWithRuleSync(bindingID, BindingUpdateOpts{
		Ports:     &emptyPorts,
		Protocols: &emptyProtocols,
	}); err != nil {
		t.Fatalf("clear ports/protocols: %v", err)
	}

	bindings, _ = s.ListBindings()
	if len(bindings[0].Ports) != 0 {
		t.Errorf("binding ports not cleared: %v", bindings[0].Ports)
	}
	if len(bindings[0].Protocols) != 0 {
		t.Errorf("binding protocols not cleared: %v", bindings[0].Protocols)
	}
	rules, _ = s.ListRules(RuleFilter{Type: "network"})
	if len(rules[0].Ports) != 0 {
		t.Errorf("rule ports not cleared: %v", rules[0].Ports)
	}
	if len(rules[0].Protocols) != 0 {
		t.Errorf("rule protocols not cleared: %v", rules[0].Protocols)
	}
}

// TestUpdateBindingWithRuleSyncRejectsInvalidPorts verifies that the
// paired-rule sync path validates port ranges before touching the rule.
func TestUpdateBindingWithRuleSyncRejectsInvalidPorts(t *testing.T) {
	s := newTestStore(t)
	_, bindingID, err := s.AddRuleAndBinding(
		"allow",
		RuleOpts{
			Destination: "api.example.com",
			Ports:       []int{443},
			Source:      BindingAddSourcePrefix + "cred",
		},
		"cred",
		BindingOpts{Ports: []int{443}},
	)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	badPorts := []int{70000}
	_, _, _, err = s.UpdateBindingWithRuleSync(bindingID, BindingUpdateOpts{Ports: &badPorts})
	if err == nil {
		t.Fatal("expected error for out-of-range port")
	}
}

// TestAddRuleAndBindingRejectsInvalidPorts ensures port-range validation
// runs inside AddRuleAndBinding instead of deferring it to engine recompile.
// Recompile errors are logged but not surfaced to API callers, so out-of-
// range ports would otherwise silently create bad rules.
func TestAddRuleAndBindingRejectsInvalidPorts(t *testing.T) {
	s := newTestStore(t)

	// Rule port out of range.
	_, _, err := s.AddRuleAndBinding(
		"allow",
		RuleOpts{Destination: "api.example.com", Ports: []int{0}},
		"cred",
		BindingOpts{},
	)
	if err == nil {
		t.Fatal("expected error for rule port 0")
	}

	// Binding port out of range.
	_, _, err = s.AddRuleAndBinding(
		"allow",
		RuleOpts{Destination: "api.example.com"},
		"cred",
		BindingOpts{Ports: []int{70000}},
	)
	if err == nil {
		t.Fatal("expected error for binding port 70000")
	}

	// Verify nothing was persisted.
	rules, _ := s.ListRules(RuleFilter{Type: "network"})
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after rejected inserts, got %d", len(rules))
	}
	bindings, _ := s.ListBindings()
	if len(bindings) != 0 {
		t.Errorf("expected 0 bindings after rejected inserts, got %d", len(bindings))
	}
}

// TestAddRuleAndBindingRejectsUnknownProtocol verifies that a typo in the
// binding or rule protocols list (e.g. "htp") is caught up front instead
// of being stored silently and surfacing later as a protocol mismatch at
// connection time. Mirrors the TOML import validator.
func TestAddRuleAndBindingRejectsUnknownProtocol(t *testing.T) {
	s := newTestStore(t)

	// Rule-level typo.
	_, _, err := s.AddRuleAndBinding(
		"allow",
		RuleOpts{Destination: "api.example.com", Protocols: []string{"htp"}},
		"cred",
		BindingOpts{},
	)
	if err == nil || !strings.Contains(err.Error(), "unknown protocol") {
		t.Fatalf("expected unknown protocol error for rule, got %v", err)
	}

	// Binding-level typo.
	_, _, err = s.AddRuleAndBinding(
		"allow",
		RuleOpts{Destination: "api.example.com"},
		"cred",
		BindingOpts{Protocols: []string{"htps"}},
	)
	if err == nil || !strings.Contains(err.Error(), "unknown protocol") {
		t.Fatalf("expected unknown protocol error for binding, got %v", err)
	}

	// Valid protocols must still succeed.
	if _, _, err := s.AddRuleAndBinding(
		"allow",
		RuleOpts{Destination: "api.example.com", Protocols: []string{"https"}},
		"cred",
		BindingOpts{Protocols: []string{"https"}},
	); err != nil {
		t.Fatalf("unexpected error for valid protocols: %v", err)
	}

	// Verify nothing was persisted from the rejected inserts. Only the
	// valid call above should have stored a rule/binding.
	rules, _ := s.ListRules(RuleFilter{Type: "network"})
	if len(rules) != 1 {
		t.Errorf("expected 1 rule after valid insert, got %d", len(rules))
	}
}

// TestAddBindingRejectsUnknownProtocol mirrors the AddRuleAndBinding test
// for the standalone AddBinding path.
func TestAddBindingRejectsUnknownProtocol(t *testing.T) {
	s := newTestStore(t)

	_, err := s.AddBinding("api.example.com", "cred", BindingOpts{Protocols: []string{"htp"}})
	if err == nil || !strings.Contains(err.Error(), "unknown protocol") {
		t.Fatalf("expected unknown protocol error, got %v", err)
	}

	// Valid protocol succeeds.
	if _, err := s.AddBinding("api.example.com", "cred", BindingOpts{Protocols: []string{"https"}}); err != nil {
		t.Fatalf("unexpected error for valid protocol: %v", err)
	}
}

// TestUpdateBindingWithRuleSyncRejectsUnknownProtocol verifies the update
// path rejects unknown protocols before any transaction runs.
func TestUpdateBindingWithRuleSyncRejectsUnknownProtocol(t *testing.T) {
	s := newTestStore(t)
	_, bindingID, err := s.AddRuleAndBinding(
		"allow",
		RuleOpts{
			Destination: "api.example.com",
			Source:      BindingAddSourcePrefix + "cred",
		},
		"cred",
		BindingOpts{},
	)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	badProtos := []string{"htp"}
	_, _, _, err = s.UpdateBindingWithRuleSync(bindingID, BindingUpdateOpts{Protocols: &badProtos})
	if err == nil || !strings.Contains(err.Error(), "unknown protocol") {
		t.Fatalf("expected unknown protocol error, got %v", err)
	}

	// Valid update succeeds.
	goodProtos := []string{"https"}
	if _, _, _, err := s.UpdateBindingWithRuleSync(bindingID, BindingUpdateOpts{Protocols: &goodProtos}); err != nil {
		t.Fatalf("unexpected error for valid update: %v", err)
	}
}

// TestUpdateBindingWithRuleSyncUpdatesBothSourcePrefixes verifies that
// when a credential owns auto-created allow rules tagged with both
// "cred-add:<cred>" and "binding-add:<cred>" at the same destination,
// updating the binding propagates the change to every matching rule,
// not just the first one the store finds. Before the fix, the loop
// returned after updating a single source prefix and left any other
// paired rule at the old values, which meant the binding's network
// scope drifted from what the remaining rule authorized.
func TestUpdateBindingWithRuleSyncUpdatesBothSourcePrefixes(t *testing.T) {
	s := newTestStore(t)

	// Seed the first rule via AddRuleAndBinding with the cred-add prefix.
	// This mirrors "sluice cred add --destination" creating the initial
	// rule+binding pair.
	credAddRuleID, bindingID, err := s.AddRuleAndBinding(
		"allow",
		RuleOpts{
			Destination: "api.example.com",
			Source:      CredAddSourcePrefix + "cred",
		},
		"cred",
		BindingOpts{},
	)
	if err != nil {
		t.Fatalf("seed cred-add rule+binding: %v", err)
	}

	// Manually insert a second rule at the same destination tagged with
	// the binding-add prefix. This simulates a later "sluice binding add"
	// that reuses the same credential+destination and produces its own
	// paired allow rule. Migration 5 normally collapses duplicates but
	// only within the same (source, destination) group, so a cred-add
	// rule and a binding-add rule at the same destination both survive.
	res, err := s.db.Exec(
		`INSERT INTO rules (verdict, destination, source, name) VALUES (?, ?, ?, ?)`,
		"allow", "api.example.com", BindingAddSourcePrefix+"cred", "auto-binding",
	)
	if err != nil {
		t.Fatalf("seed binding-add rule: %v", err)
	}
	bindingAddRuleID, _ := res.LastInsertId()

	// Change the destination via the rule-sync path. Both paired rules
	// must be rewritten to the new destination.
	newDest := "api.new.com"
	if _, _, _, err := s.UpdateBindingWithRuleSync(bindingID, BindingUpdateOpts{
		Destination: &newDest,
	}); err != nil {
		t.Fatalf("update binding destination: %v", err)
	}

	// Both rules must have moved to the new destination. Query each
	// explicitly so a bug that updates only one is caught.
	var credAddDest, bindingAddDest string
	if err := s.db.QueryRow(
		"SELECT destination FROM rules WHERE id = ?", credAddRuleID,
	).Scan(&credAddDest); err != nil {
		t.Fatalf("load cred-add rule: %v", err)
	}
	if credAddDest != newDest {
		t.Errorf("cred-add rule destination = %q, want %q", credAddDest, newDest)
	}
	if err := s.db.QueryRow(
		"SELECT destination FROM rules WHERE id = ?", bindingAddRuleID,
	).Scan(&bindingAddDest); err != nil {
		t.Fatalf("load binding-add rule: %v", err)
	}
	if bindingAddDest != newDest {
		t.Errorf("binding-add rule destination = %q, want %q", bindingAddDest, newDest)
	}
}

// TestRemoveBindingWithRuleCleanupCaseInsensitive verifies that
// RemoveBindingWithRuleCleanup deletes the paired allow rule even when the
// rule's destination differs in case from the binding's destination. Policy
// matching and the bindings UNIQUE index both treat destinations as
// case-insensitive, so an upgraded database may legitimately hold a binding
// at "api.example.com" whose paired rule is stored at "API.EXAMPLE.COM".
// A case-sensitive delete would leave the rule orphaned at the old case and
// keep allowing traffic after the binding is gone. Regression for codex
// iteration 9 finding 2.
func TestRemoveBindingWithRuleCleanupCaseInsensitive(t *testing.T) {
	s := newTestStore(t)

	// Add a binding via AddBinding (no paired rule) so we can seed the
	// paired rule at a different case without fighting the atomic
	// AddRuleAndBinding path.
	bindingID, err := s.AddBinding("api.example.com", "my_key", BindingOpts{})
	if err != nil {
		t.Fatalf("add binding: %v", err)
	}

	// Seed the paired rule manually with the destination in upper case.
	if _, err := s.db.Exec(
		`INSERT INTO rules (verdict, destination, source, name) VALUES (?, ?, ?, ?)`,
		"allow", "API.EXAMPLE.COM", BindingAddSourcePrefix+"my_key", "auto",
	); err != nil {
		t.Fatalf("seed paired rule: %v", err)
	}

	_, dest, removed, _, found, err := s.RemoveBindingWithRuleCleanup(bindingID)
	if err != nil {
		t.Fatalf("remove binding: %v", err)
	}
	if !found {
		t.Fatalf("expected binding to be found")
	}
	if dest != "api.example.com" {
		t.Errorf("expected dest %q, got %q", "api.example.com", dest)
	}
	if removed != 1 {
		t.Errorf("expected 1 paired rule removed, got %d", removed)
	}

	var ruleCount int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM rules WHERE source = ?`,
		BindingAddSourcePrefix+"my_key",
	).Scan(&ruleCount); err != nil {
		t.Fatalf("count rules after cleanup: %v", err)
	}
	if ruleCount != 0 {
		t.Errorf("expected paired rule to be deleted, got %d rules remaining", ruleCount)
	}
}

// TestUpdateBindingWithRuleSyncCaseInsensitive verifies that
// UpdateBindingWithRuleSync finds and rewrites the paired allow rule even
// when the rule's destination is stored in a different case than the
// binding's destination. Matches the case-sensitivity fix applied to
// RemoveBindingWithRuleCleanup. Regression for codex iteration 9 finding 2.
func TestUpdateBindingWithRuleSyncCaseInsensitive(t *testing.T) {
	s := newTestStore(t)

	bindingID, err := s.AddBinding("api.example.com", "my_key", BindingOpts{})
	if err != nil {
		t.Fatalf("add binding: %v", err)
	}

	// Seed the paired rule at a differently-cased destination.
	res, err := s.db.Exec(
		`INSERT INTO rules (verdict, destination, source, name) VALUES (?, ?, ?, ?)`,
		"allow", "API.EXAMPLE.COM", BindingAddSourcePrefix+"my_key", "auto",
	)
	if err != nil {
		t.Fatalf("seed paired rule: %v", err)
	}
	pairedID, _ := res.LastInsertId()

	newDest := "api.new.example.com"
	retID, ruleFound, _, err := s.UpdateBindingWithRuleSync(bindingID, BindingUpdateOpts{
		Destination: &newDest,
	})
	if err != nil {
		t.Fatalf("update binding: %v", err)
	}
	if !ruleFound {
		t.Errorf("expected paired rule to be found via case-insensitive match")
	}
	if retID != pairedID {
		t.Errorf("expected paired rule id %d, got %d", pairedID, retID)
	}

	var storedDest string
	if err := s.db.QueryRow(
		`SELECT destination FROM rules WHERE id = ?`,
		pairedID,
	).Scan(&storedDest); err != nil {
		t.Fatalf("load paired rule: %v", err)
	}
	if storedDest != newDest {
		t.Errorf("expected paired rule destination %q, got %q", newDest, storedDest)
	}
}

// TestImportTOMLValidatesDestinationGlob verifies that TOML import runs
// destination patterns through validateDestinationGlob before committing.
// Today validateDestinationGlob only rejects empty strings (every other
// input compiles cleanly because regexp.QuoteMeta escapes meta characters
// byte-by-byte), but wiring the call through the import path keeps
// validation centralized so tightening CompileGlob later fails at import
// time with row context instead of much later inside a recompile. The
// test asserts that valid patterns still import and that empty-destination
// rows are rejected from both the rule and binding import paths.
func TestImportTOMLValidatesDestinationGlob(t *testing.T) {
	s := newTestStore(t)

	// Empty destination on a rule fails before the INSERT runs.
	emptyRuleTOML := []byte(`
[[allow]]
destination = ""
`)
	if _, err := s.ImportTOML(emptyRuleTOML); err == nil {
		t.Error("expected error for empty rule destination")
	}

	// Empty destination on a binding fails before the INSERT runs.
	emptyBindingTOML := []byte(`
[[binding]]
destination = ""
credential = "cred"
`)
	if _, err := s.ImportTOML(emptyBindingTOML); err == nil {
		t.Error("expected error for empty binding destination")
	}

	// Valid patterns still import cleanly.
	goodTOML := []byte(`
[[allow]]
destination = "*.example.com"

[[binding]]
destination = "api.example.com"
credential = "cred"
`)
	if _, err := s.ImportTOML(goodTOML); err != nil {
		t.Fatalf("unexpected error for valid import: %v", err)
	}
	rules, _ := s.ListRules(RuleFilter{})
	if len(rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(rules))
	}
	bindings, _ := s.ListBindings()
	if len(bindings) != 1 {
		t.Errorf("expected 1 binding, got %d", len(bindings))
	}
}

// TestAddRuleAndBindingValidationErrorsAreTagged verifies that every
// client-facing validation failure from AddRuleAndBinding wraps
// ErrBindingValidation. The API layer uses errors.Is on this sentinel to
// decide 400 vs 500, so any validation path that forgets to wrap would
// silently masquerade as a 500.
func TestAddRuleAndBindingValidationErrorsAreTagged(t *testing.T) {
	s := newTestStore(t)

	cases := []struct {
		name     string
		verdict  string
		ruleOpts RuleOpts
		cred     string
		binding  BindingOpts
	}{
		{"empty verdict", "", RuleOpts{Destination: "x.com"}, "cred", BindingOpts{}},
		{"invalid verdict", "bogus", RuleOpts{Destination: "x.com"}, "cred", BindingOpts{}},
		{"empty destination", "allow", RuleOpts{}, "cred", BindingOpts{}},
		{"empty credential", "allow", RuleOpts{Destination: "x.com"}, "", BindingOpts{}},
		{"bad rule port", "allow", RuleOpts{Destination: "x.com", Ports: []int{70000}}, "cred", BindingOpts{}},
		{"bad binding port", "allow", RuleOpts{Destination: "x.com"}, "cred", BindingOpts{Ports: []int{0}}},
		{"bad rule protocol", "allow", RuleOpts{Destination: "x.com", Protocols: []string{"htp"}}, "cred", BindingOpts{}},
		{"bad binding protocol", "allow", RuleOpts{Destination: "x.com"}, "cred", BindingOpts{Protocols: []string{"htp"}}},
		{"bad env var", "allow", RuleOpts{Destination: "x.com"}, "cred", BindingOpts{EnvVar: "1INVALID"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := s.AddRuleAndBinding(tc.verdict, tc.ruleOpts, tc.cred, tc.binding)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, ErrBindingValidation) {
				t.Errorf("expected ErrBindingValidation, got %v", err)
			}
		})
	}
}

// TestUpdateBindingWithRuleSyncValidationErrorsAreTagged mirrors the
// AddRuleAndBinding test for the update path.
func TestUpdateBindingWithRuleSyncValidationErrorsAreTagged(t *testing.T) {
	s := newTestStore(t)
	_, bindingID, err := s.AddRuleAndBinding(
		"allow",
		RuleOpts{
			Destination: "api.example.com",
			Source:      BindingAddSourcePrefix + "cred",
		},
		"cred",
		BindingOpts{},
	)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	emptyDest := ""
	badProtos := []string{"htp"}
	badPorts := []int{0}
	badEnv := "1INVALID"

	cases := []struct {
		name string
		opts BindingUpdateOpts
	}{
		{"empty destination", BindingUpdateOpts{Destination: &emptyDest}},
		{"invalid protocol", BindingUpdateOpts{Protocols: &badProtos}},
		{"invalid port", BindingUpdateOpts{Ports: &badPorts}},
		{"invalid env var", BindingUpdateOpts{EnvVar: &badEnv}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := s.UpdateBindingWithRuleSync(bindingID, tc.opts)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, ErrBindingValidation) {
				t.Errorf("expected ErrBindingValidation, got %v", err)
			}
		})
	}
}

// TestAddBindingCaseInsensitiveDuplicate verifies that the unique index on
// (credential, LOWER(destination)) established by migration 000005 rejects
// duplicate bindings whose destinations differ only in case. Policy
// matching is case-insensitive, so these bindings target the exact same
// set of connections and must not coexist. Regression for codex iteration
// 6 finding 1.
func TestAddBindingCaseInsensitiveDuplicate(t *testing.T) {
	s := newTestStore(t)

	if _, err := s.AddBinding("api.example.com", "my_key", BindingOpts{}); err != nil {
		t.Fatalf("first add: %v", err)
	}

	_, err := s.AddBinding("API.EXAMPLE.COM", "my_key", BindingOpts{})
	if err == nil {
		t.Fatal("expected duplicate error for case-variant destination")
	}
	if !errors.Is(err, ErrBindingDuplicate) {
		t.Errorf("expected ErrBindingDuplicate, got %v", err)
	}

	// Still exactly one binding row for this pair.
	bindings, err := s.ListBindings()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	count := 0
	for _, b := range bindings {
		if b.Credential == "my_key" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 binding after case-variant insert, got %d", count)
	}
}

// TestAddRuleAndBindingCaseInsensitiveDuplicate is the AddRuleAndBinding
// counterpart of TestAddBindingCaseInsensitiveDuplicate. The combined
// rule+binding transaction must also roll back when the case-variant
// duplicate is detected so no orphan rule remains.
func TestAddRuleAndBindingCaseInsensitiveDuplicate(t *testing.T) {
	s := newTestStore(t)

	if _, _, err := s.AddRuleAndBinding(
		"allow",
		RuleOpts{Destination: "api.example.com", Source: "binding-add:my_key"},
		"my_key",
		BindingOpts{},
	); err != nil {
		t.Fatalf("first add: %v", err)
	}

	_, _, err := s.AddRuleAndBinding(
		"allow",
		RuleOpts{Destination: "API.EXAMPLE.COM", Source: "binding-add:my_key"},
		"my_key",
		BindingOpts{},
	)
	if err == nil {
		t.Fatal("expected duplicate error for case-variant destination")
	}
	if !errors.Is(err, ErrBindingDuplicate) {
		t.Errorf("expected ErrBindingDuplicate, got %v", err)
	}

	// The rolled-back second call must not leave an orphan rule behind,
	// so there is still exactly one rule (from the first successful add).
	rules, err := s.ListRules(RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("expected 1 allow rule, got %d", len(rules))
	}
}

// TestAddBindingValidation verifies that AddBinding rejects invalid
// destination globs, out-of-range ports, and unknown protocols before
// inserting anything, and wraps failures with ErrBindingValidation so API
// callers can map them to 400. Regression for codex iteration 6 finding 3.
func TestAddBindingValidation(t *testing.T) {
	s := newTestStore(t)

	cases := []struct {
		name string
		dest string
		cred string
		opts BindingOpts
	}{
		{"empty destination", "", "cred", BindingOpts{}},
		{"empty credential", "api.example.com", "", BindingOpts{}},
		{"port zero", "api.example.com", "cred", BindingOpts{Ports: []int{0}}},
		{"port too high", "api.example.com", "cred", BindingOpts{Ports: []int{70000}}},
		{"unknown protocol", "api.example.com", "cred", BindingOpts{Protocols: []string{"htp"}}},
		{"invalid env var", "api.example.com", "cred", BindingOpts{EnvVar: "1BAD"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.AddBinding(tc.dest, tc.cred, tc.opts)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, ErrBindingValidation) {
				t.Errorf("expected ErrBindingValidation, got %v", err)
			}
		})
	}

	// Valid input still succeeds on the same store.
	if _, err := s.AddBinding("api.example.com", "cred", BindingOpts{Ports: []int{443}}); err != nil {
		t.Errorf("unexpected error for valid input: %v", err)
	}
}
