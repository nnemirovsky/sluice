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

		// Quote-aware tokenization. Documented forms like --args "a,b"
		// must preserve the comma-separated value as a single token so
		// downstream flag parsing sees the intended value rather than
		// two stray positional args.
		{
			`/mcp add github --command npx --args "a,b"`,
			false, "mcp",
			[]string{"add", "github", "--command", "npx", "--args", "a,b"},
		},
		{
			`/mcp add notion --command https://mcp.notion.com --env "FOO=1,BAR=2"`,
			false, "mcp",
			[]string{"add", "notion", "--command", "https://mcp.notion.com", "--env", "FOO=1,BAR=2"},
		},
		{
			`/mcp add api --header "Authorization=Bearer tok with space"`,
			false, "mcp",
			[]string{"add", "api", "--header", "Authorization=Bearer tok with space"},
		},
		// Single quotes are literal - backslash inside does not escape.
		{
			`/policy allow 'host with space'`,
			false, "policy",
			[]string{"allow", "host with space"},
		},
		// Unterminated quote is treated as not-a-command rather than
		// silently dropping the quote.
		{
			`/mcp add name --args "unterminated`,
			true, "", nil,
		},
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
	if !strings.Contains(result, "/mcp") {
		t.Error("help should mention /mcp when store is configured")
	}
	if !strings.Contains(result, "MCP Upstreams") {
		t.Error("help should include MCP Upstreams section when store is configured")
	}
}

// TestHandleHelpNoStore verifies the MCP section is omitted when store is nil,
// matching how /cred help is gated on vault availability.
func TestHandleHelpNoStore(t *testing.T) {
	ptr := new(atomic.Pointer[policy.Engine])
	eng, err := policy.LoadFromBytes([]byte(`[policy]
default = "deny"
`))
	if err != nil {
		t.Fatal(err)
	}
	ptr.Store(eng)
	handler := NewCommandHandler(ptr, new(sync.Mutex), "")
	result := handler.Handle(&Command{Name: "help"})

	if strings.Contains(result, "/mcp") {
		t.Error("help should not mention /mcp when store is nil")
	}
	if strings.Contains(result, "MCP Upstreams") {
		t.Error("help should not include MCP Upstreams section when store is nil")
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

	// Also cover the no-args path. handleMCP's store guard runs before the
	// usage banner so operators get a clear "not available" diagnostic
	// rather than a usage string that advertises commands they cannot use.
	resultNoArgs := handler.Handle(&Command{Name: "mcp", Args: nil})
	if !strings.Contains(resultNoArgs, "not available") {
		t.Errorf("should report not available on bare /mcp when store is not configured, got: %s", resultNoArgs)
	}
	if strings.Contains(resultNoArgs, "Usage: /mcp") {
		t.Errorf("store-guard must precede usage banner, got usage instead: %s", resultNoArgs)
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
	// Add a stdio upstream with args and env. The env value is a whole-value
	// vault indirection which is safe to surface verbatim.
	if _, err := s.AddMCPUpstream("github", "npx", store.MCPUpstreamOpts{
		Args:       []string{"-y", "@modelcontextprotocol/server-github"},
		Env:        map[string]string{"GITHUB_PAT": "vault:github_pat"},
		TimeoutSec: 120,
		Transport:  "stdio",
	}); err != nil {
		t.Fatal(err)
	}
	// Add an http upstream with headers and a non-default timeout. The header
	// value is a templated form ("Bearer vault:notion_token") which is NOT a
	// whole-value vault pointer, so it must be masked to "****" in the
	// rendered output.
	if _, err := s.AddMCPUpstream("notion", "https://mcp.notion.com", store.MCPUpstreamOpts{
		Headers:    map[string]string{"Authorization": "Bearer vault:notion_token"},
		TimeoutSec: 60,
		Transport:  "http",
	}); err != nil {
		t.Fatal(err)
	}

	handler := newTestHandlerWithStore(t, s, nil, "")
	out := handler.Handle(&Command{Name: "mcp", Args: []string{"list"}})

	// Expect names, transports, commands, and safe-to-show env/header forms.
	must := []string{
		"github",
		"stdio",
		"<code>npx</code>",
		"notion",
		"http",
		"<code>https://mcp.notion.com</code>",
		"-y @modelcontextprotocol/server-github",
		"GITHUB_PAT=vault:github_pat", // whole-value vault pointer is safe
		"Authorization=****",          // templated value is masked
		"timeout: 60s",
	}
	for _, want := range must {
		if !strings.Contains(out, want) {
			t.Errorf("mcp list output missing %q\nfull output:\n%s", want, out)
		}
	}
	// The raw templated header value must NOT leak into chat.
	forbidden := []string{
		"Bearer vault:notion_token",
		"notion_token",
	}
	for _, bad := range forbidden {
		if strings.Contains(out, bad) {
			t.Errorf("mcp list output must not contain %q\nfull output:\n%s", bad, out)
		}
	}
	// Default (120s) timeout should NOT be rendered.
	if strings.Contains(out, "timeout: 120s") {
		t.Errorf("default 120s timeout should be omitted, got: %s", out)
	}
}

// TestHandleMCPListRedactsSecrets asserts that raw plaintext env values and
// raw plaintext header values are masked out of /mcp list output. This locks
// in the security regression guard called out by the external review: the
// /mcp add auto-delete-on-send protection is only meaningful if the same
// values do not later reappear in chat via /mcp list.
func TestHandleMCPListRedactsSecrets(t *testing.T) {
	s := newTestStore(t)
	// Raw plaintext env value and raw plaintext header value. Neither is a
	// whole-value vault pointer, so both must be masked in the rendered
	// output.
	if _, err := s.AddMCPUpstream("leaky", "https://example.com", store.MCPUpstreamOpts{
		Transport: "http",
		Env:       map[string]string{"SUPER_SECRET": "ghp_rawtokenvalue"},
		Headers:   map[string]string{"Authorization": "Bearer sk-liveapikey"},
	}); err != nil {
		t.Fatal(err)
	}

	handler := newTestHandlerWithStore(t, s, nil, "")
	out := handler.Handle(&Command{Name: "mcp", Args: []string{"list"}})

	// Masked renders must appear.
	masked := []string{
		"SUPER_SECRET=****",
		"Authorization=****",
	}
	for _, want := range masked {
		if !strings.Contains(out, want) {
			t.Errorf("mcp list should mask value, missing %q\nfull output:\n%s", want, out)
		}
	}
	// Raw secrets must NOT appear anywhere in the output.
	leaked := []string{
		"ghp_rawtokenvalue",
		"sk-liveapikey",
		"Bearer sk-liveapikey",
	}
	for _, bad := range leaked {
		if strings.Contains(out, bad) {
			t.Errorf("mcp list leaked plaintext %q\nfull output:\n%s", bad, out)
		}
	}
}

func TestHandleMCPListEscapesHTML(t *testing.T) {
	s := newTestStore(t)
	// An http upstream exercises the args/env/header rendering paths
	// which use htmlCode wrapping internally. Name, command, args, and
	// the env/header KEYS contain "<" or "&" so we can confirm none of
	// them leak past the HTML escape. Env and header VALUES are masked
	// to "****" (see sortedKVLineRedacted and TestHandleMCPListRedactsSecrets),
	// so we deliberately do not assert on their escaped form. The key
	// side of the KEY=**** pair is still a meaningful escape target.
	if _, err := s.AddMCPUpstream("my<srv>", "https://example.com/<svc>", store.MCPUpstreamOpts{
		Transport: "http",
		Args:      []string{"--mode=<dev>", "&flag"},
		Env:       map[string]string{"X<KEY>": "v&a<l>ue"},
		Headers:   map[string]string{"X-H<dr>": "Bearer <tok>&n"},
	}); err != nil {
		t.Fatal(err)
	}

	handler := newTestHandlerWithStore(t, s, nil, "")
	out := handler.Handle(&Command{Name: "mcp", Args: []string{"list"}})

	// Raw tags must not appear. The "<" checks catch any unescaped tag
	// content directly. Value-side raw tags ("<l>", "<tok>") are covered
	// here too because the redaction mask should have already replaced
	// them, so their absence is both an escape and a redaction check.
	badRaw := []string{"<srv>", "<svc>", "<dev>", "<KEY>", "<dr>", "<tok>", "<l>", "&flag"}
	for _, s := range badRaw {
		if strings.Contains(out, s) {
			t.Errorf("unescaped substring %q in output: %s", s, out)
		}
	}
	// Escaped equivalents on the key side (name, command, args, env/header
	// keys) must appear. Value-side escapes are intentionally not asserted
	// because the values are masked.
	goodEsc := []string{
		"my&lt;srv&gt;",
		"&lt;svc&gt;",
		"&lt;dev&gt;",
		"X&lt;KEY&gt;",
		"X-H&lt;dr&gt;",
		"&amp;flag",
	}
	for _, s := range goodEsc {
		if !strings.Contains(out, s) {
			t.Errorf("expected escaped %q in output: %s", s, out)
		}
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

// TestHandleMCPAddEmptyArgs covers the bare "/mcp add" branch with no flags
// or positional arguments. The handler should return the usage banner and not
// mutate the store.
func TestHandleMCPAddEmptyArgs(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	result := handler.Handle(&Command{Name: "mcp", Args: []string{"add"}})
	if !strings.Contains(result, "Usage: /mcp add") {
		t.Errorf("expected usage banner for bare /mcp add, got: %s", result)
	}
	if upstreams, _ := s.ListMCPUpstreams(); len(upstreams) != 0 {
		t.Errorf("no upstream should be created for bare /mcp add, got %d", len(upstreams))
	}
}

// TestHandleMCPAddEnvBase64Padding verifies that --env values containing "="
// characters (e.g. base64-padded tokens) survive parsing intact. Regression
// to strings.Split on "=" would truncate "abc===padding" to "abc".
func TestHandleMCPAddEnvBase64Padding(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{
			"add", "github", "--command", "npx",
			"--env", "TOKEN=abc===padding",
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
	if got, want := upstreams[0].Env["TOKEN"], "abc===padding"; got != want {
		t.Errorf("env[TOKEN] = %q, want %q (strings.SplitN on '=' must keep the RHS intact)", got, want)
	}
}

// TestHandleMCPAddHTTPHeader verifies the --header flag is parsed for http
// upstreams so Telegram matches the CLI's --header support. --header is
// repeatable (matches CLI); pass the flag once per KEY=VAL pair.
func TestHandleMCPAddHTTPHeader(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{
			"add", "notion",
			"--command", "https://mcp.notion.com",
			"--transport", "http",
			"--header", "Authorization=Bearer vault:notion",
			"--header", "X-Custom=xyz",
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
	if u.Headers["Authorization"] != "Bearer vault:notion" {
		t.Errorf("header[Authorization] = %q, want Bearer vault:notion", u.Headers["Authorization"])
	}
	if u.Headers["X-Custom"] != "xyz" {
		t.Errorf("header[X-Custom] = %q, want xyz", u.Headers["X-Custom"])
	}
}

// TestHandleMCPAddHeaderRejectedForStdio verifies --header is rejected for
// non-http transports to match the CLI's behavior.
func TestHandleMCPAddHeaderRejectedForStdio(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{
			"add", "github", "--command", "npx",
			"--header", "Authorization=Bearer xyz",
		},
	})
	if !strings.Contains(result, "--header is only valid for --transport http") {
		t.Errorf("expected --header validation error, got: %s", result)
	}
	if upstreams, _ := s.ListMCPUpstreams(); len(upstreams) != 0 {
		t.Errorf("no upstream should be created when --header is misused, got %d", len(upstreams))
	}
}

// TestHandleMCPAddDuplicateDoesNotCallContainerManager ensures error-path
// additions do not invoke WireMCPGateway. This guards against a regression
// that reintroduces pre-validation container side effects.
func TestHandleMCPAddDuplicateDoesNotCallContainerManager(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.AddMCPUpstream("github", "npx", store.MCPUpstreamOpts{}); err != nil {
		t.Fatal(err)
	}
	handler := newTestHandlerWithStore(t, s, nil, "")
	mgr := &mockContainerMgr{}
	handler.SetContainerManager(mgr)

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{"add", "github", "--command", "some-other"},
	})
	if !strings.Contains(result, "Failed to add MCP upstream") {
		t.Errorf("expected duplicate rejection, got: %s", result)
	}
	if mgr.wireCalledSafe() {
		t.Errorf("WireMCPGateway must not be called on the add error path")
	}
}

// TestHandleMCPRemoveNotFoundDoesNotCallContainerManager mirrors the add
// case for the remove error path.
func TestHandleMCPRemoveNotFoundDoesNotCallContainerManager(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")
	mgr := &mockContainerMgr{}
	handler.SetContainerManager(mgr)

	result := handler.Handle(&Command{Name: "mcp", Args: []string{"remove", "nonexistent"}})
	if !strings.Contains(result, "No MCP upstream named") {
		t.Errorf("expected not-found message, got: %s", result)
	}
	if mgr.wireCalledSafe() {
		t.Errorf("WireMCPGateway must not be called on the remove error path")
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

	// non-numeric surfaces stdlib flag.Parse error via our
	// "Invalid argument:" wrapper.
	if r := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{"add", "github", "--command", "npx", "--timeout", "abc"},
	}); !strings.Contains(r, "Invalid argument") || !strings.Contains(r, "timeout") {
		t.Errorf("expected invalid timeout error, got: %s", r)
	}
	// zero and negative hit our own validation after flag parsing.
	for _, tv := range []string{"0", "-5"} {
		if r := handler.Handle(&Command{
			Name: "mcp",
			Args: []string{"add", "github", "--command", "npx", "--timeout", tv},
		}); !strings.Contains(r, "Invalid --timeout") {
			t.Errorf("expected invalid timeout error for %s, got: %s", tv, r)
		}
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

// TestHandleMCPAddInvalidHeader is the --header analog of
// TestHandleMCPAddInvalidEnv. The fs.Func callback for --header must
// reject a BADFORMAT token (no "=") with a user-visible error that
// surfaces through the "Invalid argument:" prefix produced by the
// stdlib flag.Parse wrapper.
func TestHandleMCPAddInvalidHeader(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{
			"add", "github",
			"--command", "https://api.example.com/mcp",
			"--transport", "http",
			"--header", "BADFORMAT",
		},
	})
	if !strings.Contains(result, "Invalid argument") || !strings.Contains(result, "--header") {
		t.Errorf("expected invalid header error mentioning --header, got: %s", result)
	}
	ups, _ := s.ListMCPUpstreams()
	if len(ups) != 0 {
		t.Errorf("no upstream should be created on parse failure, got %d", len(ups))
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

// TestHandleMCPAddDoesNotCallContainerManager verifies that /mcp add does NOT
// invoke the ContainerManager, because sluice multiplexes all upstreams via a
// single agent-side entry (mcp.servers.sluice) that is wired once at startup.
// Re-invoking WireMCPGateway on every mutation would trigger an agent gateway
// restart without changing anything meaningful. The operator-facing message
// instructs them to restart sluice so the gateway re-reads the upstream set.
func TestHandleMCPAddDoesNotCallContainerManager(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	mgr := &mockContainerMgr{}
	handler.SetContainerManager(mgr)

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{"add", "github", "--command", "npx"},
	})
	if !strings.Contains(result, "Added MCP upstream") {
		t.Fatalf("should confirm add, got: %s", result)
	}
	if !strings.Contains(result, "Restart sluice") {
		t.Errorf("response should instruct operator to restart sluice, got: %s", result)
	}
	if mgr.wireCalledSafe() {
		t.Errorf("WireMCPGateway must not be called on /mcp add (sluice URL is unchanged)")
	}
}

// TestHandleMCPRemoveDoesNotCallContainerManager mirrors the add case: the
// removal only takes effect after a sluice restart, and the agent's openclaw
// config is not touched.
func TestHandleMCPRemoveDoesNotCallContainerManager(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.AddMCPUpstream("github", "npx", store.MCPUpstreamOpts{Transport: "stdio"}); err != nil {
		t.Fatal(err)
	}
	handler := newTestHandlerWithStore(t, s, nil, "")

	mgr := &mockContainerMgr{}
	handler.SetContainerManager(mgr)

	result := handler.Handle(&Command{Name: "mcp", Args: []string{"remove", "github"}})
	if !strings.Contains(result, "Removed MCP upstream") {
		t.Fatalf("should confirm remove, got: %s", result)
	}
	if !strings.Contains(result, "Restart sluice") {
		t.Errorf("response should instruct operator to restart sluice, got: %s", result)
	}
	if mgr.wireCalledSafe() {
		t.Errorf("WireMCPGateway must not be called on /mcp remove")
	}
}

// TestHandleMCPAddEqualsFormFlag verifies that the single-token "--flag=value"
// form is accepted alongside the two-token form. Without this, operators
// typing `/mcp add github --command=npx` would hit the reorderer's two-token
// assumption.
func TestHandleMCPAddEqualsFormFlag(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{"add", "github", "--command=npx", "--transport=stdio", "--timeout=45"},
	})
	if !strings.Contains(result, "Added MCP upstream") {
		t.Fatalf("should confirm add, got: %s", result)
	}
	ups, _ := s.ListMCPUpstreams()
	if len(ups) != 1 || ups[0].Command != "npx" || ups[0].Transport != "stdio" || ups[0].TimeoutSec != 45 {
		t.Errorf("unexpected upstream state: %+v", ups)
	}
}

// TestHandleMCPListErrorPath exercises the ListMCPUpstreams error branch by
// closing the store before the handler is invoked.
func TestHandleMCPListErrorPath(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	result := handler.Handle(&Command{Name: "mcp", Args: []string{"list"}})
	if !strings.Contains(result, "Failed to list MCP upstreams") {
		t.Errorf("expected list error, got: %s", result)
	}
}

// TestHandleMCPAddErrorPath exercises the AddMCPUpstream error branch by
// closing the store before the handler is invoked. The user-facing message
// must start with the generic "Failed to add" prefix, not a panic.
func TestHandleMCPAddErrorPath(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{"add", "github", "--command", "npx"},
	})
	if !strings.Contains(result, "Failed to add MCP upstream") {
		t.Errorf("expected add error, got: %s", result)
	}
}

// TestHandleMCPRemoveErrorPath exercises the RemoveMCPUpstream error branch
// by closing the store before the handler is invoked.
func TestHandleMCPRemoveErrorPath(t *testing.T) {
	s := newTestStore(t)
	// Seed first so the later close-and-remove hits the DB rather than the
	// upfront "not found" check.
	if _, err := s.AddMCPUpstream("github", "npx", store.MCPUpstreamOpts{}); err != nil {
		t.Fatal(err)
	}
	handler := newTestHandlerWithStore(t, s, nil, "")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	result := handler.Handle(&Command{Name: "mcp", Args: []string{"remove", "github"}})
	if !strings.Contains(result, "Failed to remove MCP upstream") {
		t.Errorf("expected remove error, got: %s", result)
	}
}

// TestHandleMCPAddRepeatableHeader verifies --header can be passed multiple
// times (matching the CLI). This is the preferred form: repeatable flags
// keep header values that contain commas intact, which a CSV form would
// silently split.
func TestHandleMCPAddRepeatableHeader(t *testing.T) {
	s := newTestStore(t)
	handler := newTestHandlerWithStore(t, s, nil, "")

	result := handler.Handle(&Command{
		Name: "mcp",
		Args: []string{
			"add", "notion",
			"--command", "https://mcp.notion.com",
			"--transport", "http",
			"--header", "Authorization=Bearer xyz",
			"--header", "X-Custom=a,b,c",
		},
	})
	if !strings.Contains(result, "Added MCP upstream") {
		t.Fatalf("should confirm add, got: %s", result)
	}
	ups, _ := s.ListMCPUpstreams()
	if len(ups) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(ups))
	}
	if ups[0].Headers["Authorization"] != "Bearer xyz" {
		t.Errorf("unexpected Authorization header: %q", ups[0].Headers["Authorization"])
	}
	if ups[0].Headers["X-Custom"] != "a,b,c" {
		t.Errorf("repeatable --header must keep commas intact: %q", ups[0].Headers["X-Custom"])
	}
}
