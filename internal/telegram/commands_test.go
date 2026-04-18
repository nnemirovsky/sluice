package telegram

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/nemirovsky/sluice/internal/channel"
	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
)

// newTestStore creates an in-memory SQLite store for tests.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// newTestHandlerWithStore creates a CommandHandler backed by an in-memory
// SQLite store. The engine is compiled from the store after setup.
func newTestHandlerWithStore(t *testing.T, s *store.Store, broker *channel.Broker, auditPath string) *CommandHandler {
	t.Helper()
	eng, err := policy.LoadFromStore(s)
	if err != nil {
		t.Fatal(err)
	}
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)
	h := NewCommandHandler(ptr, new(sync.Mutex), auditPath)
	h.SetStore(s)
	if broker != nil {
		h.SetBroker(broker)
	}
	return h
}

func TestParseCommand(t *testing.T) {
	tests := []struct {
		input   string
		wantNil bool
		name    string
		args    []string
	}{
		{"/policy show", false, "policy", []string{"show"}},
		{"/cred add github_token", false, "cred", []string{"add", "github_token"}},
		{"/audit recent 20", false, "audit", []string{"recent", "20"}},
		{"not a command", true, "", nil},
		{"", true, "", nil},
		{"/help", false, "help", nil},
		{"/policy@mybot show", false, "policy", []string{"show"}},
	}

	for _, tt := range tests {
		cmd := ParseCommand(tt.input)
		if tt.wantNil {
			if cmd != nil {
				t.Errorf("ParseCommand(%q) = %+v, want nil", tt.input, cmd)
			}
			continue
		}
		if cmd == nil {
			t.Errorf("ParseCommand(%q) = nil, want non-nil", tt.input)
			continue
		}
		if cmd.Name != tt.name {
			t.Errorf("ParseCommand(%q).Name = %q, want %q", tt.input, cmd.Name, tt.name)
		}
		if len(cmd.Args) != len(tt.args) {
			t.Errorf("ParseCommand(%q).Args = %v, want %v", tt.input, cmd.Args, tt.args)
			continue
		}
		for i, a := range cmd.Args {
			if a != tt.args[i] {
				t.Errorf("ParseCommand(%q).Args[%d] = %q, want %q", tt.input, i, a, tt.args[i])
			}
		}
	}
}

func TestHandlePolicyShow(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddRule("allow", store.RuleOpts{Destination: "api.anthropic.com", Ports: []int{443}})
	_, _ = s.AddRule("deny", store.RuleOpts{Destination: "evil.com"})

	handler := newTestHandlerWithStore(t, s, nil, "")
	result := handler.Handle(&Command{Name: "policy", Args: []string{"show"}})

	if !strings.Contains(result, "api.anthropic.com") {
		t.Error("policy show should contain allow rule destination")
	}
	if !strings.Contains(result, "evil.com") {
		t.Error("policy show should contain deny rule destination")
	}
	if !strings.Contains(result, "deny") {
		t.Error("policy show should contain default verdict")
	}
	// Store-backed show should include rule IDs.
	if !strings.Contains(result, "[") {
		t.Error("policy show should contain rule IDs in brackets")
	}
}

func TestHandlePolicyAllow(t *testing.T) {
	s := newTestStore(t)

	handler := newTestHandlerWithStore(t, s, nil, "")
	result := handler.Handle(&Command{Name: "policy", Args: []string{"allow", "example.com"}})

	if !strings.Contains(result, "Added allow rule") {
		t.Errorf("expected confirmation, got: %s", result)
	}
	// Should NOT contain in-memory warning when store is used.
	if strings.Contains(result, "in-memory only") {
		t.Errorf("should not contain in-memory warning when store is used, got: %s", result)
	}

	// Verify rule was persisted.
	rules, err := s.ListRules(store.RuleFilter{Verdict: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rules {
		if r.Destination == "example.com" {
			found = true
			if r.Source != "telegram" {
				t.Errorf("expected source 'telegram', got %q", r.Source)
			}
		}
	}
	if !found {
		t.Errorf("allow rule not persisted to store: %v", rules)
	}
}

func TestHandlePolicyDeny(t *testing.T) {
	s := newTestStore(t)

	handler := newTestHandlerWithStore(t, s, nil, "")
	result := handler.Handle(&Command{Name: "policy", Args: []string{"deny", "bad.com"}})

	if !strings.Contains(result, "Added deny rule") {
		t.Errorf("expected confirmation, got: %s", result)
	}
	if strings.Contains(result, "in-memory only") {
		t.Errorf("should not contain in-memory warning when store is used, got: %s", result)
	}

	rules, err := s.ListRules(store.RuleFilter{Verdict: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rules {
		if r.Destination == "bad.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("deny rule not persisted to store: %v", rules)
	}
}

func TestPolicyRedactCommand(t *testing.T) {
	s := newTestStore(t)

	handler := newTestHandlerWithStore(t, s, nil, "")
	result := handler.Handle(&Command{Name: "policy", Args: []string{"redact", "sk-[a-z0-9]+", "[REDACTED]"}})

	if !strings.Contains(result, "Added redact rule") {
		t.Errorf("expected confirmation, got: %s", result)
	}
	if !strings.Contains(result, "sk-[a-z0-9]+") {
		t.Errorf("expected pattern in reply, got: %s", result)
	}
	if !strings.Contains(result, "[REDACTED]") {
		t.Errorf("expected replacement in reply, got: %s", result)
	}

	rules, err := s.ListRules(store.RuleFilter{Verdict: "redact", Type: "pattern"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 redact rule in store, got %d", len(rules))
	}
	if rules[0].Pattern != "sk-[a-z0-9]+" {
		t.Errorf("pattern = %q, want sk-[a-z0-9]+", rules[0].Pattern)
	}
	if rules[0].Replacement != "[REDACTED]" {
		t.Errorf("replacement = %q, want [REDACTED]", rules[0].Replacement)
	}
	if rules[0].Source != "telegram" {
		t.Errorf("source = %q, want telegram", rules[0].Source)
	}
}

func TestPolicyRedactDefaultReplacement(t *testing.T) {
	s := newTestStore(t)

	handler := newTestHandlerWithStore(t, s, nil, "")
	// No replacement provided, default should be [REDACTED].
	result := handler.Handle(&Command{Name: "policy", Args: []string{"redact", "sk-[a-z0-9]+"}})

	if !strings.Contains(result, "Added redact rule") {
		t.Fatalf("expected confirmation, got: %s", result)
	}

	rules, err := s.ListRules(store.RuleFilter{Verdict: "redact", Type: "pattern"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 redact rule in store, got %d", len(rules))
	}
	if rules[0].Replacement != "[REDACTED]" {
		t.Errorf("replacement should default to [REDACTED], got %q", rules[0].Replacement)
	}
}

func TestPolicyRedactInvalidPattern(t *testing.T) {
	s := newTestStore(t)

	handler := newTestHandlerWithStore(t, s, nil, "")
	result := handler.Handle(&Command{Name: "policy", Args: []string{"redact", "[unclosed"}})

	if !strings.Contains(result, "Invalid regex pattern") {
		t.Errorf("expected invalid pattern error, got: %s", result)
	}

	// Confirm no rule was persisted.
	rules, err := s.ListRules(store.RuleFilter{Verdict: "redact"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 redact rules after invalid pattern, got %d", len(rules))
	}
}

func TestPolicyRedactJoinsReplacementWords(t *testing.T) {
	// /policy redact <pattern> this is the replacement -> joined with spaces.
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")
	result := handler.Handle(&Command{
		Name: "policy",
		Args: []string{"redact", "secret-[a-z]+", "this", "is", "redacted"},
	})

	if !strings.Contains(result, "Added redact rule") {
		t.Fatalf("expected confirmation, got: %s", result)
	}

	rules, err := s.ListRules(store.RuleFilter{Verdict: "redact"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Replacement != "this is redacted" {
		t.Errorf("replacement = %q, want %q", rules[0].Replacement, "this is redacted")
	}
}

func TestPolicyRedactUsageWhenMissingPattern(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")
	result := handler.Handle(&Command{Name: "policy", Args: []string{"redact"}})

	if !strings.Contains(result, "Usage: /policy redact") {
		t.Errorf("expected usage message, got: %s", result)
	}
}

func TestHandlePolicyRemove(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddRule("allow", store.RuleOpts{Destination: "removeme.com"})
	if err != nil {
		t.Fatal(err)
	}

	handler := newTestHandlerWithStore(t, s, nil, "")
	idStr := strconv.FormatInt(id, 10)
	result := handler.Handle(&Command{Name: "policy", Args: []string{"remove", idStr}})

	if !strings.Contains(result, "Removed rule ID") {
		t.Errorf("expected removal confirmation, got: %s", result)
	}

	// Verify rule was removed from store.
	rules, err := s.ListRules(store.RuleFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.ID == id {
			t.Errorf("rule should have been removed from store: %v", rules)
		}
	}
}

func TestHandlePolicyRemoveNotFound(t *testing.T) {
	s := newTestStore(t)

	handler := newTestHandlerWithStore(t, s, nil, "")
	result := handler.Handle(&Command{Name: "policy", Args: []string{"remove", "999"}})

	if !strings.Contains(result, "No rule found") {
		t.Errorf("expected not found message, got: %s", result)
	}
}

func TestHandlePolicyRemoveInvalidID(t *testing.T) {
	s := newTestStore(t)

	handler := newTestHandlerWithStore(t, s, nil, "")
	result := handler.Handle(&Command{Name: "policy", Args: []string{"remove", "notanumber"}})

	if !strings.Contains(result, "Invalid rule ID") {
		t.Errorf("expected invalid ID message, got: %s", result)
	}
}

func TestHandleStatus(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.AddRule("allow", store.RuleOpts{Destination: "example.com"})

	// Create a channel.Broker for PendingCount.
	broker := channel.NewBroker(nil)
	handler := newTestHandlerWithStore(t, s, broker, "")
	result := handler.Handle(&Command{Name: "status"})

	if !strings.Contains(result, "1 allow") {
		t.Errorf("status should show rule counts, got: %s", result)
	}
	if !strings.Contains(result, "Pending approvals: 0") {
		t.Errorf("status should show pending count, got: %s", result)
	}
}

func TestHandleAuditRecent(t *testing.T) {
	dir := t.TempDir()
	auditFile := filepath.Join(dir, "audit.jsonl")
	err := os.WriteFile(auditFile, []byte(
		`{"timestamp":"2026-01-01T00:00:00Z","destination":"a.com","verdict":"allow"}`+"\n"+
			`{"timestamp":"2026-01-01T00:00:01Z","destination":"b.com","verdict":"deny"}`+"\n"+
			`{"timestamp":"2026-01-01T00:00:02Z","destination":"c.com","verdict":"allow"}`+"\n",
	), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, auditFile)

	result := handler.Handle(&Command{Name: "audit", Args: []string{"recent", "2"}})
	if !strings.Contains(result, "b.com") {
		t.Errorf("should show second-to-last entry, got: %s", result)
	}
	if !strings.Contains(result, "c.com") {
		t.Errorf("should show last entry, got: %s", result)
	}
	if strings.Contains(result, "a.com") {
		t.Errorf("should not show first entry when requesting 2, got: %s", result)
	}
	// Verify chronological ordering (b.com should appear before c.com)
	bIdx := strings.Index(result, "b.com")
	cIdx := strings.Index(result, "c.com")
	if bIdx >= cIdx {
		t.Errorf("entries should be in chronological order (b.com before c.com), got: %s", result)
	}
}

func TestHandleAuditEmpty(t *testing.T) {
	dir := t.TempDir()
	auditFile := filepath.Join(dir, "audit.jsonl")
	err := os.WriteFile(auditFile, []byte(""), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, auditFile)

	result := handler.Handle(&Command{Name: "audit", Args: []string{"recent"}})
	if !strings.Contains(result, "empty") {
		t.Errorf("should indicate empty audit log, got: %s", result)
	}
}

func TestHandleHelp(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")
	result := handler.Handle(&Command{Name: "help"})

	if !strings.Contains(result, "/policy") {
		t.Error("help should mention /policy")
	}
	if !strings.Contains(result, "/status") {
		t.Error("help should mention /status")
	}
	if !strings.Contains(result, "/audit") {
		t.Error("help should mention /audit")
	}
}

func TestHandleCredNoVault(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")
	result := handler.Handle(&Command{Name: "cred", Args: []string{"list"}})

	if !strings.Contains(result, "not available") {
		t.Errorf("cred should say not available, got: %s", result)
	}
}

func TestHandleCredWithVault(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	dir := t.TempDir()
	vaultStore, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	handler.SetVault(vaultStore)

	// List should show empty.
	result := handler.Handle(&Command{Name: "cred", Args: []string{"list"}})
	if !strings.Contains(result, "No credentials") {
		t.Errorf("should show no credentials, got: %s", result)
	}

	// Add a credential.
	result = handler.Handle(&Command{Name: "cred", Args: []string{"add", "test_key", "secret123"}})
	if !strings.Contains(result, "Added credential") {
		t.Errorf("should confirm add, got: %s", result)
	}

	// List should show the credential.
	result = handler.Handle(&Command{Name: "cred", Args: []string{"list"}})
	if !strings.Contains(result, "test_key") {
		t.Errorf("should show test_key, got: %s", result)
	}

	// Remove the credential.
	result = handler.Handle(&Command{Name: "cred", Args: []string{"remove", "test_key"}})
	if !strings.Contains(result, "Removed credential") {
		t.Errorf("should confirm remove, got: %s", result)
	}

	// List should be empty again.
	result = handler.Handle(&Command{Name: "cred", Args: []string{"list"}})
	if !strings.Contains(result, "No credentials") {
		t.Errorf("should show no credentials after remove, got: %s", result)
	}
}

func TestHandleCredRotate(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	dir := t.TempDir()
	vaultStore, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	handler.SetVault(vaultStore)

	// Rotate non-existent credential should fail.
	result := handler.Handle(&Command{Name: "cred", Args: []string{"rotate", "nonexistent", "val"}})
	if !strings.Contains(result, "not found") {
		t.Errorf("rotate of non-existent credential should fail, got: %s", result)
	}

	// Add a credential first.
	result = handler.Handle(&Command{Name: "cred", Args: []string{"add", "test_key", "original"}})
	if !strings.Contains(result, "Added credential") {
		t.Fatalf("add should succeed, got: %s", result)
	}

	// Rotate existing credential should succeed.
	result = handler.Handle(&Command{Name: "cred", Args: []string{"rotate", "test_key", "rotated_value"}})
	if !strings.Contains(result, "Rotated credential") {
		t.Errorf("rotate should succeed, got: %s", result)
	}

	// Verify the value was updated by retrieving it.
	sb, err := vaultStore.Get("test_key")
	if err != nil {
		t.Fatalf("get after rotate: %v", err)
	}
	defer sb.Release()
	if string(sb.Bytes()) != "rotated_value" {
		t.Errorf("credential value should be updated, got: %q", string(sb.Bytes()))
	}
}

func TestHandleUnknownCommand(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")
	result := handler.Handle(&Command{Name: "foobar"})

	if !strings.Contains(result, "Unknown command") {
		t.Errorf("should report unknown command, got: %s", result)
	}
}

func TestSecureChatIDCheck(t *testing.T) {
	if !IsAuthorizedChat(12345, 12345) {
		t.Error("same chatID should be authorized")
	}
	if IsAuthorizedChat(99999, 12345) {
		t.Error("different chatID should not be authorized")
	}
}

func TestPolicyPersistence(t *testing.T) {
	s := newTestStore(t)

	handler := newTestHandlerWithStore(t, s, nil, "")

	// Add an allow rule via Telegram command.
	result := handler.Handle(&Command{Name: "policy", Args: []string{"allow", "persist.example.com"}})
	if !strings.Contains(result, "Added allow rule") {
		t.Fatalf("expected confirmation, got: %s", result)
	}

	// Simulate restart: recompile engine from store.
	eng2, err := policy.LoadFromStore(s)
	if err != nil {
		t.Fatal(err)
	}

	// The rule should survive the recompile.
	snap := eng2.Snapshot()
	found := false
	for _, r := range snap.AllowRules {
		if r.Destination == "persist.example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("allow rule should persist across engine recompile from store")
	}
}

func TestPolicyShowIncludesAllFields(t *testing.T) {
	s := newTestStore(t)

	if _, err := s.AddRule("allow", store.RuleOpts{
		Destination: "example.com",
		Ports:       []int{443},
		Protocols:   []string{"quic"},
		Name:        "test rule",
		Source:      "manual",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRule("redact", store.RuleOpts{
		Pattern:     `sk-[A-Za-z0-9]+`,
		Replacement: "sk-REDACTED",
		Source:      "seed",
	}); err != nil {
		t.Fatal(err)
	}

	handler := newTestHandlerWithStore(t, s, nil, "")
	out := handler.Handle(&Command{Name: "policy", Args: []string{"show"}})

	mustContain := []string{
		"<code>example.com</code>",
		"ports=443",
		"protocols=<code>quic</code>",
		"(test rule)",
		"[manual]",
		"<code>pattern:sk-[A-Za-z0-9]+</code>",
		"-> <code>sk-REDACTED</code>",
		"[seed]",
	}
	for _, want := range mustContain {
		if !strings.Contains(out, want) {
			t.Errorf("policy show output missing %q\nfull output:\n%s", want, out)
		}
	}

	// Section headers are bolded so the sender picks HTML parse mode,
	// which also disables Telegram's URL auto-linking inside <code>.
	if !strings.Contains(out, "<b>ALLOW</b>") {
		t.Errorf("policy show output must bold section headers: %q", out)
	}
}

func TestPolicyShowEscapesHTML(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.AddRule("deny", store.RuleOpts{
		Pattern: "<script>",
		Source:  "manual",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRule("redact", store.RuleOpts{
		Pattern:     "a&b",
		Replacement: "<x>",
	}); err != nil {
		t.Fatal(err)
	}

	handler := newTestHandlerWithStore(t, s, nil, "")
	out := handler.Handle(&Command{Name: "policy", Args: []string{"show"}})

	// Raw "<script>" must not survive the <code> wrapper. It should be
	// rendered as "<code>pattern:&lt;script&gt;</code>".
	if strings.Contains(out, "pattern:<script>") {
		t.Errorf("raw <script> must be HTML-escaped: %s", out)
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("expected &lt;script&gt; in output: %s", out)
	}
	if !strings.Contains(out, "a&amp;b") {
		t.Errorf("expected a&amp;b in output: %s", out)
	}
}

func TestPolicyRemoveThenRecompile(t *testing.T) {
	s := newTestStore(t)
	id, err := s.AddRule("allow", store.RuleOpts{Destination: "to-remove.com"})
	if err != nil {
		t.Fatal(err)
	}

	handler := newTestHandlerWithStore(t, s, nil, "")

	// Verify rule is in the engine.
	snap := handler.engine.Load().Snapshot()
	if len(snap.AllowRules) != 1 {
		t.Fatalf("expected 1 allow rule, got %d", len(snap.AllowRules))
	}

	// Remove the rule by ID.
	idStr := strconv.FormatInt(id, 10)
	result := handler.Handle(&Command{Name: "policy", Args: []string{"remove", idStr}})
	if !strings.Contains(result, "Removed rule ID") {
		t.Fatalf("expected removal, got: %s", result)
	}

	// Engine should be recompiled without the rule.
	snap = handler.engine.Load().Snapshot()
	if len(snap.AllowRules) != 0 {
		t.Errorf("rule should be removed from engine after store delete + recompile: %v", snap.AllowRules)
	}
}

func TestExtractFlag(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		flag          string
		wantValue     string
		wantRemaining []string
	}{
		{
			name:          "flag present",
			args:          []string{"value1", "--env-var", "OPENAI_API_KEY"},
			flag:          "--env-var",
			wantValue:     "OPENAI_API_KEY",
			wantRemaining: []string{"value1"},
		},
		{
			name:          "flag in the middle",
			args:          []string{"part1", "--env-var", "MY_VAR", "part2"},
			flag:          "--env-var",
			wantValue:     "MY_VAR",
			wantRemaining: []string{"part1", "part2"},
		},
		{
			name:          "flag not present",
			args:          []string{"value1", "value2"},
			flag:          "--env-var",
			wantValue:     "",
			wantRemaining: []string{"value1", "value2"},
		},
		{
			name:          "flag at end without value",
			args:          []string{"value1", "--env-var"},
			flag:          "--env-var",
			wantValue:     "",
			wantRemaining: []string{"value1", "--env-var"},
		},
		{
			name:          "empty args",
			args:          []string{},
			flag:          "--env-var",
			wantValue:     "",
			wantRemaining: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotValue, gotRemaining := extractFlag(tt.args, tt.flag)
			if gotValue != tt.wantValue {
				t.Errorf("value = %q, want %q", gotValue, tt.wantValue)
			}
			if len(gotRemaining) != len(tt.wantRemaining) {
				t.Fatalf("remaining len = %d, want %d: %v", len(gotRemaining), len(tt.wantRemaining), gotRemaining)
			}
			for i, r := range gotRemaining {
				if r != tt.wantRemaining[i] {
					t.Errorf("remaining[%d] = %q, want %q", i, r, tt.wantRemaining[i])
				}
			}
		})
	}
}

func TestCredAddWithEnvVar(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	dir := t.TempDir()
	vaultStore, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	handler.SetVault(vaultStore)

	// Add credential with --env-var flag.
	result := handler.Handle(&Command{
		Name: "cred",
		Args: []string{"add", "my_key", "secret123", "--env-var", "OPENAI_API_KEY"},
	})
	if !strings.Contains(result, "Added credential") {
		t.Fatalf("should confirm add, got: %s", result)
	}
	if !strings.Contains(result, "OPENAI_API_KEY") {
		t.Errorf("should mention env_var, got: %s", result)
	}

	// Verify binding was created with env_var in the store.
	bindings, err := s.ListBindingsWithEnvVar()
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if bindings[0].EnvVar != "OPENAI_API_KEY" {
		t.Errorf("expected env_var OPENAI_API_KEY, got %q", bindings[0].EnvVar)
	}
}

func TestCredAddWithoutEnvVar(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	dir := t.TempDir()
	vaultStore, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	handler.SetVault(vaultStore)

	// Add credential without --env-var flag.
	result := handler.Handle(&Command{
		Name: "cred",
		Args: []string{"add", "my_key", "secret123"},
	})
	if !strings.Contains(result, "Added credential") {
		t.Fatalf("should confirm add, got: %s", result)
	}

	// No binding should be created with env_var.
	bindings, err := s.ListBindingsWithEnvVar()
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 0 {
		t.Errorf("expected 0 bindings with env_var, got %d", len(bindings))
	}
}

func TestHandleMCPNoArgs(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")
	result := handler.Handle(&Command{Name: "mcp"})

	if !strings.Contains(result, "Usage: /mcp") {
		t.Errorf("should show usage when no args, got: %s", result)
	}
	if !strings.Contains(result, "list") || !strings.Contains(result, "add") || !strings.Contains(result, "remove") {
		t.Errorf("usage should mention list/add/remove, got: %s", result)
	}
}

func TestHandleMCPNoStore(t *testing.T) {
	// CommandHandler without a store should report MCP management is unavailable.
	// Build the engine from a transient store but omit SetStore on the handler.
	s := newTestStore(t)
	eng, err := policy.LoadFromStore(s)
	if err != nil {
		t.Fatal(err)
	}
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)
	handler := NewCommandHandler(ptr, new(sync.Mutex), "")
	// Deliberately do not call SetStore.

	result := handler.Handle(&Command{Name: "mcp", Args: []string{"list"}})
	if !strings.Contains(result, "not available") {
		t.Errorf("should report not available when store is not configured, got: %s", result)
	}
}

func TestHandleMCPUnknownSubcommand(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")
	result := handler.Handle(&Command{Name: "mcp", Args: []string{"bogus"}})

	if !strings.Contains(result, "Unknown mcp subcommand") {
		t.Errorf("should report unknown subcommand, got: %s", result)
	}
}

func TestHandleMCPListEmpty(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	result := handler.Handle(&Command{Name: "mcp", Args: []string{"list"}})
	if !strings.Contains(result, "No MCP upstreams") {
		t.Errorf("should report empty list, got: %s", result)
	}
}

func TestHandleMCPListWithUpstreams(t *testing.T) {
	s := newTestStore(t)
	// Add a stdio upstream with args and env.
	if _, err := s.AddMCPUpstream("github", "npx", store.MCPUpstreamOpts{
		Args:       []string{"-y", "@modelcontextprotocol/server-github"},
		Env:        map[string]string{"GITHUB_PAT": "vault:github_pat"},
		TimeoutSec: 120,
		Transport:  "stdio",
	}); err != nil {
		t.Fatal(err)
	}
	// Add an http upstream with headers and a non-default timeout.
	if _, err := s.AddMCPUpstream("notion", "https://mcp.notion.com", store.MCPUpstreamOpts{
		Headers:    map[string]string{"Authorization": "Bearer vault:notion_token"},
		TimeoutSec: 60,
		Transport:  "http",
	}); err != nil {
		t.Fatal(err)
	}

	handler := newTestHandlerWithStore(t, s, nil, "")
	out := handler.Handle(&Command{Name: "mcp", Args: []string{"list"}})

	// Expect names, transports, and commands present.
	must := []string{
		"github",
		"stdio",
		"<code>npx</code>",
		"notion",
		"http",
		"<code>https://mcp.notion.com</code>",
		"-y @modelcontextprotocol/server-github",
		"GITHUB_PAT=vault:github_pat",
		"Authorization=Bearer vault:notion_token",
		"timeout: 60s",
	}
	for _, want := range must {
		if !strings.Contains(out, want) {
			t.Errorf("mcp list output missing %q\nfull output:\n%s", want, out)
		}
	}
	// Default (120s) timeout should NOT be rendered.
	if strings.Contains(out, "timeout: 120s") {
		t.Errorf("default 120s timeout should be omitted, got: %s", out)
	}
}

func TestHandleMCPListEscapesHTML(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.AddMCPUpstream("my<srv>", "echo <hi>", store.MCPUpstreamOpts{
		Transport: "stdio",
	}); err != nil {
		t.Fatal(err)
	}

	handler := newTestHandlerWithStore(t, s, nil, "")
	out := handler.Handle(&Command{Name: "mcp", Args: []string{"list"}})

	// Raw "<srv>" and "<hi>" must be HTML-escaped so Telegram's HTML parse
	// mode does not try to render them as tags.
	if strings.Contains(out, "my<srv>") {
		t.Errorf("raw <srv> must be HTML-escaped: %s", out)
	}
	if !strings.Contains(out, "my&lt;srv&gt;") {
		t.Errorf("expected my&lt;srv&gt; in output: %s", out)
	}
	if strings.Contains(out, "echo <hi>") {
		t.Errorf("raw <hi> must be HTML-escaped: %s", out)
	}
	if !strings.Contains(out, "echo &lt;hi&gt;") {
		t.Errorf("expected escaped echo &lt;hi&gt; in output: %s", out)
	}
}

func TestHandleMCPAddStdio(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{"add", "github", "--command", "npx"},
	})
	if !strings.Contains(result, "Added MCP upstream") {
		t.Fatalf("should confirm add, got: %s", result)
	}
	if !strings.Contains(result, "github") || !strings.Contains(result, "stdio") {
		t.Errorf("expected name and transport in response, got: %s", result)
	}
	if !strings.Contains(result, "Restart sluice") {
		t.Errorf("expected restart notice in response, got: %s", result)
	}

	upstreams, err := s.ListMCPUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(upstreams))
	}
	u := upstreams[0]
	if u.Name != "github" {
		t.Errorf("name = %q, want %q", u.Name, "github")
	}
	if u.Command != "npx" {
		t.Errorf("command = %q, want %q", u.Command, "npx")
	}
	if u.Transport != "stdio" {
		t.Errorf("transport = %q, want stdio", u.Transport)
	}
	if u.TimeoutSec != 120 {
		t.Errorf("timeout = %d, want 120", u.TimeoutSec)
	}
	if len(u.Args) != 0 {
		t.Errorf("args = %v, want empty", u.Args)
	}
	if len(u.Env) != 0 {
		t.Errorf("env = %v, want empty", u.Env)
	}
}

func TestHandleMCPAddWithArgsAndEnv(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{
			"add", "github", "--command", "npx",
			"--args", "-y,@modelcontextprotocol/server-github",
			"--env", "GITHUB_PAT=vault:github_pat,DEBUG=1",
			"--timeout", "60",
		},
	})
	if !strings.Contains(result, "Added MCP upstream") {
		t.Fatalf("should confirm add, got: %s", result)
	}

	upstreams, err := s.ListMCPUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(upstreams))
	}
	u := upstreams[0]
	wantArgs := []string{"-y", "@modelcontextprotocol/server-github"}
	if len(u.Args) != len(wantArgs) {
		t.Fatalf("args = %v, want %v", u.Args, wantArgs)
	}
	for i, a := range wantArgs {
		if u.Args[i] != a {
			t.Errorf("args[%d] = %q, want %q", i, u.Args[i], a)
		}
	}
	if u.Env["GITHUB_PAT"] != "vault:github_pat" {
		t.Errorf("env[GITHUB_PAT] = %q, want vault:github_pat", u.Env["GITHUB_PAT"])
	}
	if u.Env["DEBUG"] != "1" {
		t.Errorf("env[DEBUG] = %q, want 1", u.Env["DEBUG"])
	}
	if u.TimeoutSec != 60 {
		t.Errorf("timeout = %d, want 60", u.TimeoutSec)
	}
}

func TestHandleMCPAddHTTPTransport(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{
			"add", "notion",
			"--command", "https://mcp.notion.com",
			"--transport", "http",
		},
	})
	if !strings.Contains(result, "Added MCP upstream") {
		t.Fatalf("should confirm add, got: %s", result)
	}

	upstreams, err := s.ListMCPUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(upstreams))
	}
	u := upstreams[0]
	if u.Command != "https://mcp.notion.com" {
		t.Errorf("command = %q, want URL", u.Command)
	}
	if u.Transport != "http" {
		t.Errorf("transport = %q, want http", u.Transport)
	}
}

func TestHandleMCPAddWebSocketTransport(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{
			"add", "realtime",
			"--command", "wss://mcp.example.com/ws",
			"--transport", "websocket",
		},
	})
	if !strings.Contains(result, "Added MCP upstream") {
		t.Fatalf("should confirm add, got: %s", result)
	}

	upstreams, err := s.ListMCPUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(upstreams) != 1 || upstreams[0].Transport != "websocket" {
		t.Errorf("expected websocket upstream, got %+v", upstreams)
	}
}

func TestHandleMCPAddMissingCommand(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{"add", "github"},
	})
	if !strings.Contains(result, "Usage:") {
		t.Errorf("expected usage on missing --command, got: %s", result)
	}
	upstreams, _ := s.ListMCPUpstreams()
	if len(upstreams) != 0 {
		t.Errorf("no upstream should be created when --command is missing, got %d", len(upstreams))
	}
}

func TestHandleMCPAddMissingName(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{"add", "--command", "npx"},
	})
	if !strings.Contains(result, "Usage:") {
		t.Errorf("expected usage on missing name, got: %s", result)
	}
	upstreams, _ := s.ListMCPUpstreams()
	if len(upstreams) != 0 {
		t.Errorf("no upstream should be created without a name, got %d", len(upstreams))
	}
}

func TestHandleMCPAddInvalidName(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	// "__" is a reserved namespace separator for the MCP gateway.
	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{"add", "bad__name", "--command", "npx"},
	})
	if !strings.Contains(result, "Invalid upstream name") {
		t.Errorf("expected invalid name error, got: %s", result)
	}
}

func TestHandleMCPAddInvalidTransport(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{"add", "github", "--command", "npx", "--transport", "ftp"},
	})
	if !strings.Contains(result, "Invalid transport") {
		t.Errorf("expected invalid transport error, got: %s", result)
	}
}

func TestHandleMCPAddInvalidTimeout(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	// non-numeric
	if r := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{"add", "github", "--command", "npx", "--timeout", "abc"},
	}); !strings.Contains(r, "Invalid --timeout") {
		t.Errorf("expected invalid timeout error, got: %s", r)
	}
	// zero
	if r := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{"add", "github", "--command", "npx", "--timeout", "0"},
	}); !strings.Contains(r, "Invalid --timeout") {
		t.Errorf("expected invalid timeout error for 0, got: %s", r)
	}
}

func TestHandleMCPAddInvalidEnv(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	// env value missing "="
	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{"add", "github", "--command", "npx", "--env", "NOT_A_PAIR"},
	})
	if !strings.Contains(result, "Invalid --env") {
		t.Errorf("expected invalid env error, got: %s", result)
	}
}

func TestHandleMCPAddDuplicateName(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	if _, err := s.AddMCPUpstream("github", "npx", store.MCPUpstreamOpts{}); err != nil {
		t.Fatal(err)
	}

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{"add", "github", "--command", "some-other"},
	})
	if !strings.Contains(result, "Failed to add MCP upstream") {
		t.Errorf("expected duplicate rejection, got: %s", result)
	}
}

func TestHandleMCPAddStrayPositional(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	// Second positional arg should be rejected to avoid silently swallowing
	// the intended upstream name when someone types /mcp add foo bar --command cmd.
	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{"add", "foo", "bar", "--command", "npx"},
	})
	if !strings.Contains(result, "Unexpected argument") {
		t.Errorf("expected rejection of stray arg, got: %s", result)
	}
	upstreams, _ := s.ListMCPUpstreams()
	if len(upstreams) != 0 {
		t.Errorf("no upstream should be created on parse failure, got %d", len(upstreams))
	}
}

func TestCredAddEnvVarConsumedFromValue(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	dir := t.TempDir()
	vaultStore, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	handler.SetVault(vaultStore)

	// Verify --env-var is extracted and not part of the credential value.
	result := handler.Handle(&Command{
		Name: "cred",
		Args: []string{"add", "my_key", "--env-var", "MY_VAR", "the-secret-value"},
	})
	if !strings.Contains(result, "Added credential") {
		t.Fatalf("should confirm add, got: %s", result)
	}

	// The credential value should be "the-secret-value" (not include --env-var or MY_VAR).
	sb, err := vaultStore.Get("my_key")
	if err != nil {
		t.Fatalf("get credential: %v", err)
	}
	defer sb.Release()
	if string(sb.Bytes()) != "the-secret-value" {
		t.Errorf("expected credential value 'the-secret-value', got %q", string(sb.Bytes()))
	}
}

func TestHandleMCPRemove(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.AddMCPUpstream("github", "npx", store.MCPUpstreamOpts{
		Transport: "stdio",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddMCPUpstream("notion", "https://mcp.notion.com", store.MCPUpstreamOpts{
		Transport: "http",
	}); err != nil {
		t.Fatal(err)
	}

	handler := newTestHandlerWithStore(t, s, nil, "")
	result := handler.Handle(&Command{Name: "mcp", Args: []string{"remove", "github"}})

	if !strings.Contains(result, "Removed MCP upstream") {
		t.Errorf("expected removal confirmation, got: %s", result)
	}
	if !strings.Contains(result, "github") {
		t.Errorf("expected removed name in response, got: %s", result)
	}
	if !strings.Contains(result, "Restart sluice") {
		t.Errorf("expected restart notice, got: %s", result)
	}

	// Verify github was removed but notion remains.
	upstreams, err := s.ListMCPUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(upstreams) != 1 {
		t.Fatalf("expected 1 remaining upstream, got %d", len(upstreams))
	}
	if upstreams[0].Name != "notion" {
		t.Errorf("wrong upstream remained: %q", upstreams[0].Name)
	}
}

func TestHandleMCPRemoveMissingName(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")
	result := handler.Handle(&Command{Name: "mcp", Args: []string{"remove"}})

	if !strings.Contains(result, "Usage: /mcp remove") {
		t.Errorf("expected usage on missing name, got: %s", result)
	}
}

func TestHandleMCPRemoveNotFound(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")
	result := handler.Handle(&Command{Name: "mcp", Args: []string{"remove", "nonexistent"}})

	if !strings.Contains(result, "No MCP upstream named") {
		t.Errorf("expected not-found message, got: %s", result)
	}
}

func TestHandleMCPRemoveStrayPositional(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.AddMCPUpstream("github", "npx", store.MCPUpstreamOpts{Transport: "stdio"}); err != nil {
		t.Fatal(err)
	}

	handler := newTestHandlerWithStore(t, s, nil, "")
	result := handler.Handle(&Command{Name: "mcp", Args: []string{"remove", "github", "extra"}})

	if !strings.Contains(result, "Unexpected argument") {
		t.Errorf("expected stray arg rejection, got: %s", result)
	}

	// No-op removal: github must still exist.
	upstreams, _ := s.ListMCPUpstreams()
	if len(upstreams) != 1 {
		t.Errorf("upstream should not be removed on parse failure, got %d", len(upstreams))
	}
}

// TestHandleMCPAddTriggersReinjection verifies that /mcp add re-wires the
// agent's MCP config via WireMCPGateway when a container manager and MCP URL
// are configured.
func TestHandleMCPAddTriggersReinjection(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	mgr := &mockContainerMgr{}
	handler.SetContainerManager(mgr)
	handler.SetMCPURL("http://sluice:3000/mcp")

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{"add", "github", "--command", "npx"},
	})
	if !strings.Contains(result, "Added MCP upstream") {
		t.Fatalf("should confirm add, got: %s", result)
	}
	if !mgr.wireCalled {
		t.Errorf("WireMCPGateway should be called after /mcp add")
	}
	if mgr.wireName != "sluice" {
		t.Errorf("wireName = %q, want %q", mgr.wireName, "sluice")
	}
	if mgr.wireURL != "http://sluice:3000/mcp" {
		t.Errorf("wireURL = %q, want %q", mgr.wireURL, "http://sluice:3000/mcp")
	}
	if !strings.Contains(result, "Agent MCP config re-wired") {
		t.Errorf("expected re-wired notice in response, got: %s", result)
	}
}

// TestHandleMCPRemoveTriggersReinjection verifies that /mcp remove re-wires
// the agent's MCP config via WireMCPGateway when a container manager and MCP
// URL are configured.
func TestHandleMCPRemoveTriggersReinjection(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.AddMCPUpstream("github", "npx", store.MCPUpstreamOpts{
		Transport: "stdio",
	}); err != nil {
		t.Fatal(err)
	}

	handler := newTestHandlerWithStore(t, s, nil, "")

	mgr := &mockContainerMgr{}
	handler.SetContainerManager(mgr)
	handler.SetMCPURL("http://sluice:3000/mcp")

	result := handler.Handle(&Command{Name: "mcp", Args: []string{"remove", "github"}})
	if !strings.Contains(result, "Removed MCP upstream") {
		t.Fatalf("should confirm remove, got: %s", result)
	}
	if !mgr.wireCalled {
		t.Errorf("WireMCPGateway should be called after /mcp remove")
	}
	if mgr.wireName != "sluice" {
		t.Errorf("wireName = %q, want %q", mgr.wireName, "sluice")
	}
	if mgr.wireURL != "http://sluice:3000/mcp" {
		t.Errorf("wireURL = %q, want %q", mgr.wireURL, "http://sluice:3000/mcp")
	}
	if !strings.Contains(result, "Agent MCP config re-wired") {
		t.Errorf("expected re-wired notice in response, got: %s", result)
	}
}

// TestHandleMCPReinjectionSkippedWithoutContainer verifies re-injection is a
// no-op when no container manager is configured (standalone mode).
func TestHandleMCPReinjectionSkippedWithoutContainer(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")
	handler.SetMCPURL("http://sluice:3000/mcp")
	// Intentionally do not set a container manager.

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{"add", "github", "--command", "npx"},
	})
	if !strings.Contains(result, "Added MCP upstream") {
		t.Fatalf("should confirm add, got: %s", result)
	}
	if strings.Contains(result, "Agent MCP config re-wired") {
		t.Errorf("re-wired notice should not appear without container manager, got: %s", result)
	}
	if strings.Contains(result, "Warning") {
		t.Errorf("no warning should appear when re-injection is simply skipped, got: %s", result)
	}
}

// TestHandleMCPReinjectionSkippedWithoutURL verifies re-injection is a no-op
// when no MCP URL is configured.
func TestHandleMCPReinjectionSkippedWithoutURL(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	mgr := &mockContainerMgr{}
	handler.SetContainerManager(mgr)
	// Intentionally do not set an MCP URL.

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{"add", "github", "--command", "npx"},
	})
	if !strings.Contains(result, "Added MCP upstream") {
		t.Fatalf("should confirm add, got: %s", result)
	}
	if mgr.wireCalled {
		t.Errorf("WireMCPGateway should not be called without an MCP URL")
	}
}

// TestHandleMCPReinjectionFailure verifies failures from WireMCPGateway are
// surfaced to the Telegram response as a warning but do not fail the overall
// add/remove operation.
func TestHandleMCPReinjectionFailure(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	mgr := &mockContainerMgr{wireErr: fmt.Errorf("wire failed: exec timeout")}
	handler.SetContainerManager(mgr)
	handler.SetMCPURL("http://sluice:3000/mcp")

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{"add", "github", "--command", "npx"},
	})
	if !strings.Contains(result, "Added MCP upstream") {
		t.Fatalf("should confirm add even when re-injection fails, got: %s", result)
	}
	if !strings.Contains(result, "Warning: failed to re-wire") {
		t.Errorf("expected warning about wire failure, got: %s", result)
	}

	// The upstream should still be persisted.
	upstreams, _ := s.ListMCPUpstreams()
	if len(upstreams) != 1 {
		t.Errorf("upstream should be persisted even if re-injection fails, got %d", len(upstreams))
	}
}
