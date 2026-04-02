package telegram

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/nemirovsky/sluice/internal/policy"
	"github.com/nemirovsky/sluice/internal/vault"
)

// newTestHandler creates a CommandHandler backed by the given engine for tests.
func newTestHandler(eng *policy.Engine, broker *ApprovalBroker, auditPath string) *CommandHandler {
	ptr := new(atomic.Pointer[policy.Engine])
	ptr.Store(eng)
	return NewCommandHandler(ptr, new(sync.Mutex), broker, auditPath)
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
	eng := &policy.Engine{
		Default: policy.Deny,
		AllowRules: []policy.Rule{
			{Destination: "api.anthropic.com", Ports: []int{443}},
		},
		DenyRules: []policy.Rule{
			{Destination: "evil.com"},
		},
	}

	handler := newTestHandler(eng, nil, "")
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
}

func TestHandlePolicyAllow(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"
`))
	if err != nil {
		t.Fatal(err)
	}

	handler := newTestHandler(eng, nil, "")
	result := handler.Handle(&Command{Name: "policy", Args: []string{"allow", "example.com"}})

	if !strings.Contains(result, "Added allow rule") {
		t.Errorf("expected confirmation, got: %s", result)
	}
	if !strings.Contains(result, "in-memory only") {
		t.Errorf("expected in-memory warning, got: %s", result)
	}
	if len(eng.AllowRules) != 1 || eng.AllowRules[0].Destination != "example.com" {
		t.Errorf("allow rule not added to engine")
	}
}

func TestHandlePolicyDeny(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "allow"
`))
	if err != nil {
		t.Fatal(err)
	}

	handler := newTestHandler(eng, nil, "")
	result := handler.Handle(&Command{Name: "policy", Args: []string{"deny", "bad.com"}})

	if !strings.Contains(result, "Added deny rule") {
		t.Errorf("expected confirmation, got: %s", result)
	}
	if !strings.Contains(result, "in-memory only") {
		t.Errorf("expected in-memory warning, got: %s", result)
	}
	if len(eng.DenyRules) != 1 {
		t.Errorf("deny rule not added")
	}
}

func TestHandlePolicyRemove(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "removeme.com"
`))
	if err != nil {
		t.Fatal(err)
	}

	handler := newTestHandler(eng, nil, "")
	result := handler.Handle(&Command{Name: "policy", Args: []string{"remove", "removeme.com"}})

	if !strings.Contains(result, "Removed rule") {
		t.Errorf("expected removal confirmation, got: %s", result)
	}
	if !strings.Contains(result, "in-memory only") {
		t.Errorf("expected in-memory warning, got: %s", result)
	}
	if len(eng.AllowRules) != 0 {
		t.Errorf("rule not removed: %v", eng.AllowRules)
	}
}

func TestHandlePolicyRemoveNotFound(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"
`))
	if err != nil {
		t.Fatal(err)
	}

	handler := newTestHandler(eng, nil, "")
	result := handler.Handle(&Command{Name: "policy", Args: []string{"remove", "nonexistent.com"}})

	if !strings.Contains(result, "No rule found") {
		t.Errorf("expected not found message, got: %s", result)
	}
}

func TestHandleStatus(t *testing.T) {
	eng, err := policy.LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "example.com"
`))
	if err != nil {
		t.Fatal(err)
	}

	broker := NewApprovalBroker()
	handler := newTestHandler(eng, broker, "")
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
	), 0600)
	if err != nil {
		t.Fatal(err)
	}

	eng, _ := policy.LoadFromBytes([]byte(`[policy]
default = "deny"
`))
	handler := newTestHandler(eng, nil, auditFile)

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
	err := os.WriteFile(auditFile, []byte(""), 0600)
	if err != nil {
		t.Fatal(err)
	}

	eng, _ := policy.LoadFromBytes([]byte(`[policy]
default = "deny"
`))
	handler := newTestHandler(eng, nil, auditFile)

	result := handler.Handle(&Command{Name: "audit", Args: []string{"recent"}})
	if !strings.Contains(result, "empty") {
		t.Errorf("should indicate empty audit log, got: %s", result)
	}
}

func TestHandleHelp(t *testing.T) {
	eng, _ := policy.LoadFromBytes([]byte(`[policy]
default = "deny"
`))
	handler := newTestHandler(eng, nil, "")
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
	eng, _ := policy.LoadFromBytes([]byte(`[policy]
default = "deny"
`))
	handler := newTestHandler(eng, nil, "")
	result := handler.Handle(&Command{Name: "cred", Args: []string{"list"}})

	if !strings.Contains(result, "not available") {
		t.Errorf("cred should say not available, got: %s", result)
	}
}

func TestHandleCredWithVault(t *testing.T) {
	eng, _ := policy.LoadFromBytes([]byte(`[policy]
default = "deny"
`))
	handler := newTestHandler(eng, nil, "")

	dir := t.TempDir()
	store, err := vault.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	handler.SetVault(store)

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

func TestHandleUnknownCommand(t *testing.T) {
	eng, _ := policy.LoadFromBytes([]byte(`[policy]
default = "deny"
`))
	handler := newTestHandler(eng, nil, "")
	result := handler.Handle(&Command{Name: "foobar"})

	if !strings.Contains(result, "Unknown command") {
		t.Errorf("should report unknown command, got: %s", result)
	}
}

func TestSecureChatIDCheck(t *testing.T) {
	// IsAuthorized should only allow the configured chatID
	if !IsAuthorizedChat(12345, 12345) {
		t.Error("same chatID should be authorized")
	}
	if IsAuthorizedChat(99999, 12345) {
		t.Error("different chatID should not be authorized")
	}
}
