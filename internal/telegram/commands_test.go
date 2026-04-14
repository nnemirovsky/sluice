package telegram

import (
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
