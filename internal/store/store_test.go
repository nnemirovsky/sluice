package store

import (
	"fmt"
	"sync"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
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
	s.db.QueryRow("SELECT COUNT(*) FROM rules").Scan(&ruleCount)
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

// --- Rule CRUD ---

func TestAddRule(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddRule("allow", "api.example.com", []int{443, 80}, RuleOpts{
		Protocol: "https",
		Note:     "test rule",
		Source:   "seed",
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}
	if id < 1 {
		t.Fatalf("expected positive id, got %d", id)
	}

	rules, err := s.ListRules("")
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
	if r.Protocol != "https" {
		t.Errorf("protocol = %q", r.Protocol)
	}
	if r.Note != "test rule" {
		t.Errorf("note = %q", r.Note)
	}
	if r.Source != "seed" {
		t.Errorf("source = %q", r.Source)
	}
}

func TestAddRuleDefaultSource(t *testing.T) {
	s := newTestStore(t)
	_, err := s.AddRule("deny", "evil.com", nil, RuleOpts{})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}
	rules, err := s.ListRules("")
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
	if _, err := s.AddRule("", "example.com", nil, RuleOpts{}); err == nil {
		t.Error("empty verdict should fail")
	}
	if _, err := s.AddRule("allow", "", nil, RuleOpts{}); err == nil {
		t.Error("empty destination should fail")
	}
}

func TestAddRuleInvalidVerdict(t *testing.T) {
	s := newTestStore(t)
	_, err := s.AddRule("block", "example.com", nil, RuleOpts{})
	if err == nil {
		t.Error("invalid verdict should fail")
	}
}

func TestRemoveRule(t *testing.T) {
	s := newTestStore(t)
	id, _ := s.AddRule("allow", "example.com", nil, RuleOpts{})
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

func TestListRulesFilter(t *testing.T) {
	s := newTestStore(t)
	s.AddRule("allow", "a.com", nil, RuleOpts{})
	s.AddRule("deny", "b.com", nil, RuleOpts{})
	s.AddRule("ask", "c.com", nil, RuleOpts{})
	s.AddRule("allow", "d.com", nil, RuleOpts{})

	allows, _ := s.ListRules("allow")
	if len(allows) != 2 {
		t.Errorf("expected 2 allow rules, got %d", len(allows))
	}
	denies, _ := s.ListRules("deny")
	if len(denies) != 1 {
		t.Errorf("expected 1 deny rule, got %d", len(denies))
	}
	all, _ := s.ListRules("")
	if len(all) != 4 {
		t.Errorf("expected 4 total rules, got %d", len(all))
	}
}

func TestListRulesExcludesToolAndPatternRules(t *testing.T) {
	s := newTestStore(t)
	s.AddRule("allow", "a.com", nil, RuleOpts{})
	s.AddToolRule("allow", "github__list_*", "", "")
	s.AddInspectRule("block", `sk-[a-zA-Z0-9]+`, InspectRuleOpts{})

	// ListRules should only return network rules (destination IS NOT NULL).
	rules, _ := s.ListRules("")
	if len(rules) != 1 {
		t.Errorf("expected 1 network rule, got %d", len(rules))
	}
	if rules[0].Destination != "a.com" {
		t.Errorf("expected a.com, got %q", rules[0].Destination)
	}
}

// --- Tool Rule CRUD ---

func TestToolRuleCRUD(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddToolRule("allow", "github__list_*", "read-only GitHub", "seed")
	if err != nil {
		t.Fatalf("add tool rule: %v", err)
	}
	if id < 1 {
		t.Fatal("expected positive id")
	}

	rules, err := s.ListToolRules("")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1, got %d", len(rules))
	}
	r := rules[0]
	if r.Verdict != "allow" || r.Tool != "github__list_*" || r.Note != "read-only GitHub" || r.Source != "seed" {
		t.Errorf("unexpected values: %+v", r)
	}

	ok, err := s.RemoveToolRule(id)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !ok {
		t.Error("expected true")
	}
	rules, _ = s.ListToolRules("")
	if len(rules) != 0 {
		t.Error("expected empty after remove")
	}
}

func TestToolRuleValidation(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.AddToolRule("", "tool", "", ""); err == nil {
		t.Error("empty verdict should fail")
	}
	if _, err := s.AddToolRule("allow", "", "", ""); err == nil {
		t.Error("empty tool should fail")
	}
}

func TestToolRuleFilterByVerdict(t *testing.T) {
	s := newTestStore(t)
	s.AddToolRule("allow", "tool_a", "", "")
	s.AddToolRule("deny", "tool_b", "", "")
	s.AddToolRule("ask", "tool_c", "", "")

	allows, _ := s.ListToolRules("allow")
	if len(allows) != 1 {
		t.Errorf("expected 1 allow, got %d", len(allows))
	}
	all, _ := s.ListToolRules("")
	if len(all) != 3 {
		t.Errorf("expected 3 total, got %d", len(all))
	}
}

// --- Inspect Rule CRUD ---

func TestInspectRuleCRUD(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddInspectRule("block", `sk-[a-zA-Z0-9]+`, InspectRuleOpts{
		Description: "API keys",
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	rules, _ := s.ListInspectRules("")
	if len(rules) != 1 {
		t.Fatalf("expected 1, got %d", len(rules))
	}
	if rules[0].Kind != "block" || rules[0].Pattern != `sk-[a-zA-Z0-9]+` || rules[0].Description != "API keys" {
		t.Errorf("unexpected: %+v", rules[0])
	}

	// Add redact rule
	s.AddInspectRule("redact", `\d{3}-\d{2}-\d{4}`, InspectRuleOpts{
		Replacement: "[REDACTED]",
	})

	blocks, _ := s.ListInspectRules("block")
	if len(blocks) != 1 {
		t.Errorf("expected 1 block rule, got %d", len(blocks))
	}
	redacts, _ := s.ListInspectRules("redact")
	if len(redacts) != 1 {
		t.Errorf("expected 1 redact rule, got %d", len(redacts))
	}

	ok, _ := s.RemoveInspectRule(id)
	if !ok {
		t.Error("expected true on remove")
	}
}

func TestInspectRuleValidation(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.AddInspectRule("", "pattern", InspectRuleOpts{}); err == nil {
		t.Error("empty kind should fail")
	}
	if _, err := s.AddInspectRule("block", "", InspectRuleOpts{}); err == nil {
		t.Error("empty pattern should fail")
	}
	if _, err := s.AddInspectRule("invalid", "pattern", InspectRuleOpts{}); err == nil {
		t.Error("invalid kind should fail")
	}
}

// --- Config ---

func TestConfigGetSet(t *testing.T) {
	s := newTestStore(t)

	// Get default value.
	val, err := s.GetConfig("default_verdict")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if val != "deny" {
		t.Errorf("expected deny default, got %q", val)
	}

	// Set and get.
	if err := s.SetConfig("default_verdict", "ask"); err != nil {
		t.Fatalf("set: %v", err)
	}
	val, _ = s.GetConfig("default_verdict")
	if val != "ask" {
		t.Errorf("expected ask, got %q", val)
	}

	// Update.
	if err := s.SetConfig("default_verdict", "deny"); err != nil {
		t.Fatalf("update: %v", err)
	}
	val, _ = s.GetConfig("default_verdict")
	if val != "deny" {
		t.Errorf("expected deny after update, got %q", val)
	}
}

func TestConfigGetUnknownKey(t *testing.T) {
	s := newTestStore(t)
	val, err := s.GetConfig("nonexistent_key")
	if err != nil {
		t.Fatalf("get unknown key: %v", err)
	}
	if val != "" {
		t.Errorf("expected empty for unknown key, got %q", val)
	}
}

func TestConfigValidation(t *testing.T) {
	s := newTestStore(t)
	if err := s.SetConfig("", "value"); err == nil {
		t.Error("empty key should fail")
	}
}

// --- Binding CRUD ---

func TestBindingCRUD(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddBinding("api.example.com", "my_api_key", BindingOpts{
		Ports:        []int{443},
		InjectHeader: "Authorization",
		Template:     "Bearer {value}",
		Protocol:     "https",
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
	if b.InjectHeader != "Authorization" {
		t.Errorf("header = %q", b.InjectHeader)
	}
	if b.Template != "Bearer {value}" {
		t.Errorf("template = %q", b.Template)
	}
	if b.Protocol != "https" {
		t.Errorf("protocol = %q", b.Protocol)
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
	s.AddMCPUpstream("github", "npx", MCPUpstreamOpts{})
	_, err := s.AddMCPUpstream("github", "node", MCPUpstreamOpts{})
	if err == nil {
		t.Error("duplicate name should fail")
	}
}

func TestMCPUpstreamDefaultTimeout(t *testing.T) {
	s := newTestStore(t)
	s.AddMCPUpstream("test", "cmd", MCPUpstreamOpts{})
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

// --- Exists helpers ---

func TestRuleExists(t *testing.T) {
	s := newTestStore(t)
	s.AddRule("allow", "example.com", []int{443}, RuleOpts{})

	exists, _ := s.RuleExists("allow", "example.com", []int{443})
	if !exists {
		t.Error("should exist")
	}
	exists, _ = s.RuleExists("allow", "example.com", nil)
	if exists {
		t.Error("different ports should not match")
	}
	exists, _ = s.RuleExists("deny", "example.com", []int{443})
	if exists {
		t.Error("different verdict should not match")
	}
}

func TestRuleExistsNilPorts(t *testing.T) {
	s := newTestStore(t)
	s.AddRule("deny", "evil.com", nil, RuleOpts{})

	exists, _ := s.RuleExists("deny", "evil.com", nil)
	if !exists {
		t.Error("nil ports rule should exist")
	}
	exists, _ = s.RuleExists("deny", "evil.com", []int{80})
	if exists {
		t.Error("should not match when stored ports is nil")
	}
}

func TestToolRuleExists(t *testing.T) {
	s := newTestStore(t)
	s.AddToolRule("allow", "github__list_*", "", "")

	exists, _ := s.ToolRuleExists("allow", "github__list_*")
	if !exists {
		t.Error("should exist")
	}
	exists, _ = s.ToolRuleExists("deny", "github__list_*")
	if exists {
		t.Error("different verdict should not match")
	}
}

func TestBindingExists(t *testing.T) {
	s := newTestStore(t)
	s.AddBinding("api.example.com", "my_key", BindingOpts{})

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
	s.AddMCPUpstream("github", "npx", MCPUpstreamOpts{})

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
			_, err := s.AddRule("allow", dest, []int{443}, RuleOpts{Source: "test"})
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
			_, err := s.ListRules("")
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
	rules, _ := s.ListRules("")
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
			if err := s.SetConfig("vault_dir", value); err != nil {
				errs <- err
			}
			if _, err := s.GetConfig("vault_dir"); err != nil {
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
	s.AddRule("ask", "example.com", nil, RuleOpts{})

	rules, _ := s.ListRules("")
	r := rules[0]
	if r.Protocol != "" {
		t.Errorf("protocol should be empty, got %q", r.Protocol)
	}
	if r.Note != "" {
		t.Errorf("note should be empty, got %q", r.Note)
	}
}

func TestMCPUpstreamNilArgsEnv(t *testing.T) {
	s := newTestStore(t)
	s.AddMCPUpstream("simple", "cmd", MCPUpstreamOpts{})

	upstreams, _ := s.ListMCPUpstreams()
	u := upstreams[0]
	if u.Args != nil {
		t.Errorf("args should be nil, got %v", u.Args)
	}
	if u.Env != nil {
		t.Errorf("env should be nil, got %v", u.Env)
	}
}
