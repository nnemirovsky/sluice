package policy

import (
	"fmt"
	"os"
	"testing"

	"github.com/nemirovsky/sluice/internal/store"
)

// loadFromTOMLFile is a test helper that creates an in-memory store, imports
// the given TOML file, and builds an Engine via LoadFromStore.
func loadFromTOMLFile(t *testing.T, path string) *Engine {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read TOML file: %v", err)
	}
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.ImportTOML(data); err != nil {
		t.Fatalf("import TOML: %v", err)
	}
	eng, err := LoadFromStore(s)
	if err != nil {
		t.Fatalf("load from store: %v", err)
	}
	return eng
}

func TestLoadPolicy(t *testing.T) {
	eng := loadFromTOMLFile(t, "../../testdata/policy_mixed.toml")
	if eng.Default != Deny {
		t.Errorf("expected default Deny, got %v", eng.Default)
	}
	if len(eng.AllowRules) != 2 {
		t.Errorf("expected 2 allow rules, got %d", len(eng.AllowRules))
	}
	if len(eng.DenyRules) != 2 {
		t.Errorf("expected 2 deny rules, got %d", len(eng.DenyRules))
	}
	if len(eng.AskRules) != 1 {
		t.Errorf("expected 1 ask rule, got %d", len(eng.AskRules))
	}
	if eng.TimeoutSec != 120 {
		t.Errorf("expected default timeout 120, got %d", eng.TimeoutSec)
	}
}

func TestEvaluate(t *testing.T) {
	eng := loadFromTOMLFile(t, "../../testdata/policy_mixed.toml")

	tests := []struct {
		dest string
		port int
		want Verdict
	}{
		{"api.anthropic.com", 443, Allow},
		{"api.github.com", 443, Allow},
		{"api.github.com", 80, Allow},
		{"api.github.com", 22, Deny},
		{"169.254.169.254", 80, Deny},
		{"pool.crypto-mining.example", 443, Deny},
		{"random.unknown.com", 443, Deny},
		{"api.openai.com", 443, Ask},
		{"api.openai.com", 80, Deny},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s:%d", tt.dest, tt.port), func(t *testing.T) {
			got := eng.Evaluate(tt.dest, tt.port)
			if got != tt.want {
				t.Errorf("Evaluate(%q, %d) = %v, want %v",
					tt.dest, tt.port, got, tt.want)
			}
		})
	}
}

func TestIsDenied(t *testing.T) {
	eng := loadFromTOMLFile(t, "../../testdata/policy_mixed.toml")

	tests := []struct {
		dest string
		port int
		want bool
	}{
		// Explicitly denied IP
		{"169.254.169.254", 80, true},
		// Explicitly denied domain pattern
		{"pool.crypto-mining.example", 443, true},
		// Allowed domain is NOT denied (only checks deny rules)
		{"api.github.com", 443, false},
		// Unknown IP is NOT denied (no explicit deny rule, no default fallback)
		{"140.82.112.3", 443, false},
		// Unknown domain is NOT denied
		{"random.unknown.com", 443, false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s:%d", tt.dest, tt.port), func(t *testing.T) {
			got := eng.IsDenied(tt.dest, tt.port)
			if got != tt.want {
				t.Errorf("IsDenied(%q, %d) = %v, want %v",
					tt.dest, tt.port, got, tt.want)
			}
		})
	}
}

func TestIsRestricted(t *testing.T) {
	eng := loadFromTOMLFile(t, "../../testdata/policy_mixed.toml")

	tests := []struct {
		dest string
		port int
		want bool
	}{
		// Explicitly denied IP
		{"169.254.169.254", 80, true},
		// Explicitly denied domain pattern
		{"pool.crypto-mining.example", 443, true},
		// Ask rule matches
		{"api.openai.com", 443, true},
		// Ask rule port mismatch
		{"api.openai.com", 80, false},
		// Allowed domain is NOT restricted
		{"api.github.com", 443, false},
		// Unknown IP is NOT restricted (no explicit deny or ask rule)
		{"140.82.112.3", 443, false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s:%d", tt.dest, tt.port), func(t *testing.T) {
			got := eng.IsRestricted(tt.dest, tt.port)
			if got != tt.want {
				t.Errorf("IsRestricted(%q, %d) = %v, want %v",
					tt.dest, tt.port, got, tt.want)
			}
		})
	}
}

func TestCouldBeAllowed(t *testing.T) {
	eng := loadFromTOMLFile(t, "../../testdata/policy_mixed.toml")

	tests := []struct {
		dest string
		want bool
	}{
		// Matches allow rule (*.github.com) -> could be allowed
		{"api.github.com", true},
		// Matches allow rule (api.anthropic.com) -> could be allowed
		{"api.anthropic.com", true},
		// Matches ask rule (*.openai.com) -> needs DNS resolution for approval flow
		{"api.openai.com", true},
		// Matches portless deny rule (169.254.169.254) -> definitely denied
		{"169.254.169.254", false},
		// Matches portless deny rule (*.crypto-mining.example) -> definitely denied
		{"pool.crypto-mining.example", false},
		// No rule matches, default is deny -> not allowed
		{"random.unknown.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.dest, func(t *testing.T) {
			got := eng.CouldBeAllowed(tt.dest, true)
			if got != tt.want {
				t.Errorf("CouldBeAllowed(%q, true) = %v, want %v",
					tt.dest, got, tt.want)
			}
		})
	}

	// With includeAsk=false, ask rules should NOT count as allowed.
	// api.openai.com matches only an ask rule, so it should be false.
	if eng.CouldBeAllowed("api.openai.com", false) {
		t.Error("CouldBeAllowed(api.openai.com, false) = true, want false (ask rule without broker)")
	}
	// Allow rules should still work.
	if !eng.CouldBeAllowed("api.github.com", false) {
		t.Error("CouldBeAllowed(api.github.com, false) = false, want true (allow rule)")
	}
}

func TestCouldBeAllowedDefaultAllow(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "allow"

[[deny]]
destination = "evil.com"
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	tests := []struct {
		dest string
		want bool
	}{
		// Portless deny -> definitely denied
		{"evil.com", false},
		// No rules match, default allow -> could be allowed
		{"anything.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.dest, func(t *testing.T) {
			got := eng.CouldBeAllowed(tt.dest, true)
			if got != tt.want {
				t.Errorf("CouldBeAllowed(%q, true) = %v, want %v",
					tt.dest, got, tt.want)
			}
		})
	}
}

func TestCouldBeAllowedDefaultAskNoBroker(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "ask"
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// With includeAsk=true, default=ask means unmatched destinations could be allowed
	if !eng.CouldBeAllowed("anything.com", true) {
		t.Error("CouldBeAllowed(anything.com, true) with default=ask should be true")
	}
	// With includeAsk=false, default=ask should NOT count as allowed (prevents DNS leak)
	if eng.CouldBeAllowed("anything.com", false) {
		t.Error("CouldBeAllowed(anything.com, false) with default=ask should be false")
	}
}

func TestLoadPolicyWithTools(t *testing.T) {
	eng := loadFromTOMLFile(t, "../../testdata/policy_with_tools.toml")
	if len(eng.ToolAllowRules) != 1 {
		t.Errorf("expected 1 tool_allow, got %d", len(eng.ToolAllowRules))
	}
	if len(eng.ToolDenyRules) != 1 {
		t.Errorf("expected 1 tool_deny, got %d", len(eng.ToolDenyRules))
	}
	if len(eng.ToolAskRules) != 1 {
		t.Errorf("expected 1 tool_ask, got %d", len(eng.ToolAskRules))
	}

	// Verify verdicts are set from section names
	if eng.ToolAllowRules[0].Verdict != "allow" {
		t.Errorf("tool_allow verdict = %q, want %q", eng.ToolAllowRules[0].Verdict, "allow")
	}
	if eng.ToolAllowRules[0].Tool != "github__list_*" {
		t.Errorf("tool_allow tool = %q, want %q", eng.ToolAllowRules[0].Tool, "github__list_*")
	}
	if eng.ToolDenyRules[0].Verdict != "deny" {
		t.Errorf("tool_deny verdict = %q, want %q", eng.ToolDenyRules[0].Verdict, "deny")
	}
	if eng.ToolAskRules[0].Verdict != "ask" {
		t.Errorf("tool_ask verdict = %q, want %q", eng.ToolAskRules[0].Verdict, "ask")
	}

	// Verify ToolRules() returns all combined
	allRules := eng.ToolRules()
	if len(allRules) != 3 {
		t.Errorf("ToolRules() returned %d rules, want 3", len(allRules))
	}
}

func TestLoadFromBytesErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"invalid TOML", "this is not valid [[[ toml"},
		{"unknown default verdict", "[policy]\ndefault = \"invalid\""},
		{"empty destination", "[policy]\ndefault = \"deny\"\n\n[[allow]]\ndestination = \"\""},
		{"invalid port zero", "[policy]\ndefault = \"deny\"\n\n[[allow]]\ndestination = \"x.com\"\nports = [0]"},
		{"invalid port too high", "[policy]\ndefault = \"deny\"\n\n[[allow]]\ndestination = \"x.com\"\nports = [99999]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadFromBytes([]byte(tt.input))
			if err == nil {
				t.Errorf("expected error for input %q, got nil", tt.input)
			}
		})
	}
}

func TestCanonicalizeDestination(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Trailing dots are stripped
		{"example.com.", "example.com"},
		{"example.com...", "example.com"},
		// Already canonical
		{"example.com", "example.com"},
		// IPv6 compressed
		{"0:0:0:0:0:0:0:1", "::1"},
		{"0000:0000:0000:0000:0000:0000:0000:0001", "::1"},
		// IPv6 already canonical
		{"::1", "::1"},
		// IPv4 unchanged
		{"127.0.0.1", "127.0.0.1"},
		// Glob patterns left alone (not valid IPs)
		{"*.example.com", "*.example.com"},
		{"**.example.com", "**.example.com"},
		// Trailing dot + glob
		{"*.example.com.", "*.example.com"},
		// Bare wildcard + trailing dot: kept as-is to avoid match-all
		{"*.", "*."},
		{"**.", "**."},
		{"*...", "*..."},
		// Bare wildcard without trailing dot: unchanged (no stripping needed)
		{"*", "*"},
		{"**", "**"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := canonicalizeDestination(tt.input)
			if got != tt.want {
				t.Errorf("canonicalizeDestination(%q) = %q, want %q",
					tt.input, got, tt.want)
			}
		})
	}
}

func TestDenyRuleWithTrailingDot(t *testing.T) {
	// A deny rule with trailing dot should still match the runtime
	// canonical form (no trailing dot).
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "allow"

[[deny]]
destination = "evil.com."
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if eng.Evaluate("evil.com", 443) != Deny {
		t.Error("deny rule with trailing dot should match canonical 'evil.com'")
	}
}

func TestDenyRuleWithExpandedIPv6(t *testing.T) {
	// A deny rule with expanded IPv6 should match the runtime
	// canonical (compressed) form.
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "allow"

[[deny]]
destination = "0:0:0:0:0:0:0:1"
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if eng.Evaluate("::1", 443) != Deny {
		t.Error("deny rule with expanded IPv6 should match canonical '::1'")
	}
}

func TestIsExplicitlyAllowed(t *testing.T) {
	eng := loadFromTOMLFile(t, "../../testdata/policy_mixed.toml")

	tests := []struct {
		dest string
		port int
		want bool
	}{
		// Matches allow rule
		{"api.anthropic.com", 443, true},
		{"api.github.com", 443, true},
		// Port mismatch on allow rule
		{"api.github.com", 22, false},
		// Denied but not explicitly allowed
		{"169.254.169.254", 80, false},
		// Unknown destination
		{"random.unknown.com", 443, false},
		// Ask rule does not count as allowed
		{"api.openai.com", 443, false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s:%d", tt.dest, tt.port), func(t *testing.T) {
			got := eng.IsExplicitlyAllowed(tt.dest, tt.port)
			if got != tt.want {
				t.Errorf("IsExplicitlyAllowed(%q, %d) = %v, want %v",
					tt.dest, tt.port, got, tt.want)
			}
		})
	}
}

func TestTrailingDotWildcardNotMatchAll(t *testing.T) {
	// A deny rule with destination "*." must NOT become a match-all rule.
	// Without the guard in canonicalizeDestination, trailing-dot removal
	// reduces "*." to "*" which CompileGlob treats as match-everything.
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "allow"

[[deny]]
destination = "*."
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Multi-label domains must NOT be denied (they don't match "*.")
	if eng.Evaluate("example.com", 443) != Allow {
		t.Error("'*.' deny rule should not match multi-label 'example.com'")
	}
	if eng.Evaluate("api.github.com", 443) != Allow {
		t.Error("'*.' deny rule should not match multi-label 'api.github.com'")
	}
}

func TestEvaluateNormalizesInput(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "allow"

[[deny]]
destination = "evil.com"

[[deny]]
destination = "::1"
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Trailing dot in input should still match canonical rule
	if eng.Evaluate("evil.com.", 443) != Deny {
		t.Error("Evaluate with trailing dot should match deny rule for 'evil.com'")
	}

	// Expanded IPv6 in input should match compressed rule
	if eng.Evaluate("0:0:0:0:0:0:0:1", 443) != Deny {
		t.Error("Evaluate with expanded IPv6 should match deny rule for '::1'")
	}
}

func TestCouldBeAllowedNormalizesInput(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "allow"

[[deny]]
destination = "evil.com"
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Trailing dot should be stripped before matching
	if eng.CouldBeAllowed("evil.com.", true) {
		t.Error("CouldBeAllowed with trailing dot should match deny rule for 'evil.com'")
	}
}

func TestCouldBeAllowedProtocolScopedDeny(t *testing.T) {
	// A deny rule scoped to a specific protocol should NOT block DNS
	// resolution for other protocols. Only portless AND protocol-less
	// deny rules are treated as blanket denies in CouldBeAllowed.
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "allow"

[[deny]]
destination = "example.com"
protocols = ["ssh"]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Protocol-scoped deny should NOT prevent DNS resolution.
	if !eng.CouldBeAllowed("example.com", true) {
		t.Error("CouldBeAllowed should be true: deny is scoped to ssh only, HTTPS should still work")
	}

	// But a blanket deny (no protocols) should still block.
	eng2, err := LoadFromBytes([]byte(`
[policy]
default = "allow"

[[deny]]
destination = "example.com"
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if eng2.CouldBeAllowed("example.com", true) {
		t.Error("CouldBeAllowed should be false: blanket deny with no protocol restriction")
	}
}

func TestLoadFromBytesGlobWithMetachars(t *testing.T) {
	// After regex injection fix, patterns with metacharacters compile fine as literals
	input := `
[policy]
default = "deny"

[[allow]]
destination = "test[0].example.com"
`
	eng, err := LoadFromBytes([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eng.Evaluate("test[0].example.com", 443) != Allow {
		t.Error("expected literal bracket match to allow")
	}
	if eng.Evaluate("test0.example.com", 443) != Deny {
		t.Error("expected non-literal match to deny")
	}
}

func TestLoadPolicyWithAskDefault(t *testing.T) {
	eng := loadFromTOMLFile(t, "../../testdata/policy_with_telegram.toml")
	if eng.Default != Ask {
		t.Errorf("expected default Ask, got %v", eng.Default)
	}
	if eng.TimeoutSec != 60 {
		t.Errorf("expected timeout 60, got %d", eng.TimeoutSec)
	}
	if len(eng.AllowRules) != 1 {
		t.Errorf("expected 1 allow rule, got %d", len(eng.AllowRules))
	}
	if len(eng.AskRules) != 1 {
		t.Errorf("expected 1 ask rule, got %d", len(eng.AskRules))
	}
}

func TestLoadPolicyWithInspect(t *testing.T) {
	eng := loadFromTOMLFile(t, "../../testdata/policy_with_inspect.toml")
	if len(eng.InspectBlockRules) != 2 {
		t.Errorf("expected 2 inspect_block rules, got %d", len(eng.InspectBlockRules))
	}
	if len(eng.InspectRedactRules) != 2 {
		t.Errorf("expected 2 inspect_redact rules, got %d", len(eng.InspectRedactRules))
	}
	if eng.InspectBlockRules[0].Name != "api_key_leak" {
		t.Errorf("expected block rule name %q, got %q", "api_key_leak", eng.InspectBlockRules[0].Name)
	}
	if eng.InspectRedactRules[0].Replacement != "[REDACTED_API_KEY]" {
		t.Errorf("expected redact replacement %q, got %q", "[REDACTED_API_KEY]", eng.InspectRedactRules[0].Replacement)
	}
}

// --- LoadFromStore-specific tests ---

func TestLoadFromStoreEmpty(t *testing.T) {
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer func() { _ = s.Close() }()

	eng, err := LoadFromStore(s)
	if err != nil {
		t.Fatalf("load from store: %v", err)
	}
	if eng.Default != Deny {
		t.Errorf("expected default Deny for empty store, got %v", eng.Default)
	}
	if eng.TimeoutSec != 120 {
		t.Errorf("expected default timeout 120, got %d", eng.TimeoutSec)
	}
	if len(eng.AllowRules) != 0 {
		t.Errorf("expected 0 allow rules, got %d", len(eng.AllowRules))
	}
	if err := eng.Validate(); err != nil {
		t.Errorf("validate failed: %v", err)
	}
}

func TestLoadFromStoreWithRules(t *testing.T) {
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer func() { _ = s.Close() }()

	dvAsk := "ask"
	tsVal := 60
	_ = s.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &dvAsk, TimeoutSec: &tsVal})
	_, _ = s.AddRule("allow", store.RuleOpts{Destination: "api.example.com", Ports: []int{443}})
	_, _ = s.AddRule("deny", store.RuleOpts{Destination: "evil.com", Name: "bad site"})
	_, _ = s.AddRule("ask", store.RuleOpts{Destination: "*.unknown.com", Ports: []int{80, 443}})

	eng, err := LoadFromStore(s)
	if err != nil {
		t.Fatalf("load from store: %v", err)
	}
	if eng.Default != Ask {
		t.Errorf("expected Ask, got %v", eng.Default)
	}
	if eng.TimeoutSec != 60 {
		t.Errorf("expected 60, got %d", eng.TimeoutSec)
	}
	if len(eng.AllowRules) != 1 {
		t.Errorf("expected 1 allow rule, got %d", len(eng.AllowRules))
	}
	if len(eng.DenyRules) != 1 {
		t.Errorf("expected 1 deny rule, got %d", len(eng.DenyRules))
	}
	if len(eng.AskRules) != 1 {
		t.Errorf("expected 1 ask rule, got %d", len(eng.AskRules))
	}

	// Verify evaluation works
	if eng.Evaluate("api.example.com", 443) != Allow {
		t.Error("expected Allow for api.example.com:443")
	}
	if eng.Evaluate("evil.com", 80) != Deny {
		t.Error("expected Deny for evil.com:80")
	}
	if eng.Evaluate("foo.unknown.com", 443) != Ask {
		t.Error("expected Ask for foo.unknown.com:443")
	}
	if eng.Evaluate("random.com", 443) != Ask {
		t.Error("expected Ask (default) for random.com:443")
	}
}

func TestLoadFromStoreWithToolRules(t *testing.T) {
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer func() { _ = s.Close() }()

	_, _ = s.AddRule("allow", store.RuleOpts{Tool: "github__list_*", Name: "read-only"})
	_, _ = s.AddRule("deny", store.RuleOpts{Tool: "exec__*", Name: "block exec"})
	_, _ = s.AddRule("ask", store.RuleOpts{Tool: "filesystem__write_*"})

	eng, err := LoadFromStore(s)
	if err != nil {
		t.Fatalf("load from store: %v", err)
	}
	if len(eng.ToolAllowRules) != 1 {
		t.Errorf("expected 1 tool allow, got %d", len(eng.ToolAllowRules))
	}
	if len(eng.ToolDenyRules) != 1 {
		t.Errorf("expected 1 tool deny, got %d", len(eng.ToolDenyRules))
	}
	if len(eng.ToolAskRules) != 1 {
		t.Errorf("expected 1 tool ask, got %d", len(eng.ToolAskRules))
	}
	if eng.ToolAllowRules[0].Tool != "github__list_*" {
		t.Errorf("expected tool %q, got %q", "github__list_*", eng.ToolAllowRules[0].Tool)
	}
	if eng.ToolAllowRules[0].Verdict != "allow" {
		t.Errorf("expected verdict %q, got %q", "allow", eng.ToolAllowRules[0].Verdict)
	}
}

func TestLoadFromStoreWithInspectRules(t *testing.T) {
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer func() { _ = s.Close() }()

	_, _ = s.AddRule("deny", store.RuleOpts{
		Pattern: `(?i)(sk-[a-zA-Z0-9]{20,})`,
		Name:    "api_key_leak",
	})
	_, _ = s.AddRule("redact", store.RuleOpts{
		Pattern:     `(?i)(sk-[a-zA-Z0-9]{20,})`,
		Name:        "api_key_in_response",
		Replacement: "[REDACTED]",
	})

	eng, err := LoadFromStore(s)
	if err != nil {
		t.Fatalf("load from store: %v", err)
	}
	if len(eng.InspectBlockRules) != 1 {
		t.Errorf("expected 1 block rule, got %d", len(eng.InspectBlockRules))
	}
	if len(eng.InspectRedactRules) != 1 {
		t.Errorf("expected 1 redact rule, got %d", len(eng.InspectRedactRules))
	}
	if eng.InspectBlockRules[0].Pattern != `(?i)(sk-[a-zA-Z0-9]{20,})` {
		t.Errorf("unexpected block pattern: %q", eng.InspectBlockRules[0].Pattern)
	}
	if eng.InspectRedactRules[0].Replacement != "[REDACTED]" {
		t.Errorf("unexpected redact replacement: %q", eng.InspectRedactRules[0].Replacement)
	}
}

func TestLoadFromStoreNoTelegramConfig(t *testing.T) {
	// Telegram env var names are hardcoded in main.go. The Engine no longer
	// carries TelegramConfig. Verify LoadFromStore succeeds on a fresh store.
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer func() { _ = s.Close() }()

	eng, err := LoadFromStore(s)
	if err != nil {
		t.Fatalf("load from store: %v", err)
	}
	if eng.Default != Deny {
		t.Errorf("expected default Deny, got %v", eng.Default)
	}
}

func TestLoadFromStoreInvalidDefaultVerdict(t *testing.T) {
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer func() { _ = s.Close() }()

	// With typed config, the CHECK constraint rejects invalid values at the DB level.
	invalidDV := "invalid"
	err = s.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &invalidDV})
	if err == nil {
		t.Error("expected error for invalid default verdict from CHECK constraint")
	}
}

func TestLoadFromStoreZeroTimeoutUsesDefault(t *testing.T) {
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Timeout 0 should fall back to the default (120).
	zeroTimeout := 0
	_ = s.UpdateConfig(store.ConfigUpdate{TimeoutSec: &zeroTimeout})
	eng, err := LoadFromStore(s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eng.TimeoutSec != 120 {
		t.Errorf("expected default timeout 120 for zero value, got %d", eng.TimeoutSec)
	}
}

func TestLoadFromStoreRecompile(t *testing.T) {
	// Verify that mutating the store and reloading produces an updated Engine.
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer func() { _ = s.Close() }()

	dvRC := "deny"
	_ = s.UpdateConfig(store.ConfigUpdate{DefaultVerdict: &dvRC})
	_, _ = s.AddRule("allow", store.RuleOpts{Destination: "api.example.com", Ports: []int{443}})

	eng1, err := LoadFromStore(s)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if eng1.Evaluate("api.example.com", 443) != Allow {
		t.Error("expected Allow before mutation")
	}
	if eng1.Evaluate("new.example.com", 443) != Deny {
		t.Error("expected Deny for unknown before mutation")
	}

	// Add a new rule and recompile
	_, _ = s.AddRule("allow", store.RuleOpts{Destination: "new.example.com", Ports: []int{443}, Source: "telegram"})
	eng2, err := LoadFromStore(s)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if eng2.Evaluate("new.example.com", 443) != Allow {
		t.Error("expected Allow after mutation")
	}
	// Original engine should be unchanged (immutable snapshot)
	if eng1.Evaluate("new.example.com", 443) != Deny {
		t.Error("original engine should be unchanged after store mutation")
	}
}

func TestVerdictString(t *testing.T) {
	tests := []struct {
		v    Verdict
		want string
	}{
		{Allow, "allow"},
		{Deny, "deny"},
		{Ask, "ask"},
		{Redact, "redact"},
		{Verdict(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.v.String(); got != tt.want {
			t.Errorf("Verdict(%d).String() = %q, want %q", tt.v, got, tt.want)
		}
	}
}

func TestLoadFromBytesWithUnifiedFormat(t *testing.T) {
	// Verify LoadFromBytes correctly dispatches unified TOML entries.
	input := `
[policy]
default = "deny"

[[allow]]
destination = "api.example.com"
ports = [443]

[[allow]]
tool = "github__list_*"
name = "read-only"

[[deny]]
destination = "evil.com"

[[deny]]
tool = "exec__*"

[[deny]]
pattern = "(?i)(sk-[a-zA-Z0-9]{20,})"
name = "api_key_leak"

[[ask]]
tool = "filesystem__write_*"

[[redact]]
pattern = "(?i)(secret-[a-z]+)"
replacement = "[REDACTED]"
name = "secret_in_response"
`
	eng, err := LoadFromBytes([]byte(input))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(eng.AllowRules) != 1 {
		t.Errorf("expected 1 network allow rule, got %d", len(eng.AllowRules))
	}
	if len(eng.DenyRules) != 1 {
		t.Errorf("expected 1 network deny rule, got %d", len(eng.DenyRules))
	}
	if len(eng.ToolAllowRules) != 1 {
		t.Errorf("expected 1 tool allow rule, got %d", len(eng.ToolAllowRules))
	}
	if len(eng.ToolDenyRules) != 1 {
		t.Errorf("expected 1 tool deny rule, got %d", len(eng.ToolDenyRules))
	}
	if len(eng.ToolAskRules) != 1 {
		t.Errorf("expected 1 tool ask rule, got %d", len(eng.ToolAskRules))
	}
	if len(eng.InspectBlockRules) != 1 {
		t.Errorf("expected 1 inspect block rule, got %d", len(eng.InspectBlockRules))
	}
	if len(eng.InspectRedactRules) != 1 {
		t.Errorf("expected 1 inspect redact rule, got %d", len(eng.InspectRedactRules))
	}
	if eng.ToolAllowRules[0].Name != "read-only" {
		t.Errorf("expected tool name %q, got %q", "read-only", eng.ToolAllowRules[0].Name)
	}
	if eng.InspectBlockRules[0].Name != "api_key_leak" {
		t.Errorf("expected block name %q, got %q", "api_key_leak", eng.InspectBlockRules[0].Name)
	}
	if eng.InspectRedactRules[0].Replacement != "[REDACTED]" {
		t.Errorf("expected redact replacement %q, got %q", "[REDACTED]", eng.InspectRedactRules[0].Replacement)
	}
}

func TestLoadFromStoreWithProtocols(t *testing.T) {
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer func() { _ = s.Close() }()

	_, _ = s.AddRule("allow", store.RuleOpts{
		Destination: "github.com",
		Ports:       []int{22},
		Protocols:   []string{"ssh"},
	})

	eng, err := LoadFromStore(s)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(eng.AllowRules) != 1 {
		t.Fatalf("expected 1 allow rule, got %d", len(eng.AllowRules))
	}
	if len(eng.AllowRules[0].Protocols) != 1 || eng.AllowRules[0].Protocols[0] != "ssh" {
		t.Errorf("expected protocols [ssh], got %v", eng.AllowRules[0].Protocols)
	}
}

func TestEvaluateWithProtocol(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "echo.example.com"
ports = [443]
protocols = ["wss"]

[[allow]]
destination = "grpc.example.com"
ports = [443]
protocols = ["grpc"]

[[deny]]
destination = "*.example.com"
protocols = ["ws"]

[[allow]]
destination = "dns.google"
ports = [53]
protocols = ["dns"]

[[deny]]
destination = "*"
protocols = ["quic"]
name = "block all quic"

[[allow]]
destination = "api.example.com"
ports = [443]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	tests := []struct {
		name  string
		dest  string
		port  int
		proto string
		want  Verdict
	}{
		// WSS rule matches when proto="wss"
		{"wss_match", "echo.example.com", 443, "wss", Allow},
		// Same dest+port without explicit proto falls back to portToProtocol (https) which does not match wss rule
		{"wss_no_proto", "echo.example.com", 443, "", Deny},
		// gRPC rule matches when proto="grpc"
		{"grpc_match", "grpc.example.com", 443, "grpc", Allow},
		// gRPC dest without proto falls back to https (no grpc rule matches https)
		{"grpc_no_proto", "grpc.example.com", 443, "", Deny},
		// WS deny rule
		{"ws_deny", "any.example.com", 80, "ws", Deny},
		// DNS allow rule on port 53
		{"dns_allow", "dns.google", 53, "dns", Allow},
		// DNS also works without explicit proto since portToProtocol(53) = "dns"
		{"dns_port_based", "dns.google", 53, "", Allow},
		// QUIC deny rule
		{"quic_deny", "cdn.example.com", 443, "quic", Deny},
		// Non-protocol-scoped allow rule works with port-based detection
		{"plain_https", "api.example.com", 443, "", Allow},
		// Non-protocol-scoped allow rule also works with explicit proto
		{"plain_https_explicit", "api.example.com", 443, "https", Allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := eng.EvaluateWithProtocol(tt.dest, tt.port, tt.proto)
			if got != tt.want {
				t.Errorf("EvaluateWithProtocol(%q, %d, %q) = %v, want %v",
					tt.dest, tt.port, tt.proto, got, tt.want)
			}
		})
	}
}

func TestPortToProtocolDNS(t *testing.T) {
	if got := portToProtocol(53); got != "dns" {
		t.Errorf("portToProtocol(53) = %q, want %q", got, "dns")
	}
}

func TestLoadFromStoreValidate(t *testing.T) {
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer func() { _ = s.Close() }()

	eng, err := LoadFromStore(s)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := eng.Validate(); err != nil {
		t.Errorf("validate failed on valid engine: %v", err)
	}

	// Nil engine should fail validation
	var nilEng *Engine
	if err := nilEng.Validate(); err == nil {
		t.Error("expected error for nil engine")
	}
}

func TestEvaluateQUIC(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "quic-only.example.com"
ports = [443]
protocols = ["quic"]

[[allow]]
destination = "udp-only.example.com"
ports = [443]
protocols = ["udp"]

[[deny]]
destination = "blocked.example.com"
protocols = ["quic"]

[[allow]]
destination = "blocked.example.com"
ports = [443]
protocols = ["udp"]

[[deny]]
destination = "*"
protocols = ["udp"]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	tests := []struct {
		name string
		dest string
		port int
		want Verdict
	}{
		// protocols = ["quic"] matches via EvaluateQUIC even with blanket UDP deny
		{"quic_protocol_match", "quic-only.example.com", 443, Allow},
		// protocols = ["udp"] is now blocked by blanket UDP deny
		{"udp_blanket_deny", "udp-only.example.com", 443, Deny},
		// quic deny takes priority even with udp allow
		{"quic_deny_priority", "blocked.example.com", 443, Deny},
		// unknown host is denied by default
		{"default_deny", "unknown.example.com", 443, Deny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := eng.EvaluateQUIC(tt.dest, tt.port)
			if got != tt.want {
				t.Errorf("EvaluateQUIC(%q, %d) = %v, want %v",
					tt.dest, tt.port, got, tt.want)
			}
		})
	}
}

func TestEvaluateQUIC_UDPFallback(t *testing.T) {
	// Without a blanket UDP deny, UDP allow rules still work as fallback.
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "udp-allowed.example.com"
ports = [443]
protocols = ["udp"]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	got := eng.EvaluateQUIC("udp-allowed.example.com", 443)
	if got != Allow {
		t.Errorf("EvaluateQUIC with UDP allow fallback = %v, want Allow", got)
	}
}

func TestEvaluateQUICDetailed(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "allowed.example.com"
ports = [443]
protocols = ["quic"]

[[deny]]
destination = "blocked.example.com"
protocols = ["quic"]

[[ask]]
destination = "ask-me.example.com"
ports = [443]
protocols = ["quic"]

[[ask]]
destination = "ask-udp.example.com"
ports = [443]
protocols = ["udp"]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	tests := []struct {
		name       string
		dest       string
		port       int
		wantV      Verdict
		wantSource MatchSource
	}{
		{"quic_allow_rule", "allowed.example.com", 443, Allow, RuleMatch},
		{"quic_deny_rule", "blocked.example.com", 443, Deny, RuleMatch},
		{"quic_ask_rule", "ask-me.example.com", 443, Ask, RuleMatch},
		{"udp_ask_fallback", "ask-udp.example.com", 443, Ask, RuleMatch},
		{"default_deny", "unknown.example.com", 443, Deny, DefaultVerdict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotV, gotSource := eng.EvaluateQUICDetailed(tt.dest, tt.port)
			if gotV != tt.wantV {
				t.Errorf("EvaluateQUICDetailed(%q, %d) verdict = %v, want %v",
					tt.dest, tt.port, gotV, tt.wantV)
			}
			if gotSource != tt.wantSource {
				t.Errorf("EvaluateQUICDetailed(%q, %d) source = %v, want %v",
					tt.dest, tt.port, gotSource, tt.wantSource)
			}
		})
	}
}

func TestEvaluateQUICDetailed_AskCollapsedByEvaluateQUIC(t *testing.T) {
	// EvaluateQUIC collapses Ask to Deny for backward compatibility.
	// EvaluateQUICDetailed preserves Ask for per-request policy callers.
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"

[[ask]]
destination = "ask-me.example.com"
ports = [443]
protocols = ["quic"]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// EvaluateQUICDetailed returns Ask.
	v, src := eng.EvaluateQUICDetailed("ask-me.example.com", 443)
	if v != Ask || src != RuleMatch {
		t.Errorf("EvaluateQUICDetailed = (%v, %v), want (Ask, RuleMatch)", v, src)
	}

	// EvaluateQUIC collapses Ask to Deny.
	if got := eng.EvaluateQUIC("ask-me.example.com", 443); got != Deny {
		t.Errorf("EvaluateQUIC(ask rule) = %v, want Deny (collapsed from Ask)", got)
	}
}

func TestEvaluateQUICDetailed_DenyOverridesAsk(t *testing.T) {
	// Deny rules take priority over ask rules for the same destination.
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"

[[deny]]
destination = "overlap.example.com"
protocols = ["quic"]

[[ask]]
destination = "overlap.example.com"
protocols = ["quic"]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	v, src := eng.EvaluateQUICDetailed("overlap.example.com", 443)
	if v != Deny || src != RuleMatch {
		t.Errorf("EvaluateQUICDetailed(deny+ask overlap) = (%v, %v), want (Deny, RuleMatch)", v, src)
	}
}

func TestEvaluateQUICDetailed_NilCompiled(t *testing.T) {
	// Engine with nil compiled state returns Deny with DefaultVerdict.
	eng := &Engine{}
	v, src := eng.EvaluateQUICDetailed("anything.com", 443)
	if v != Deny || src != DefaultVerdict {
		t.Errorf("EvaluateQUICDetailed(nil compiled) = (%v, %v), want (Deny, DefaultVerdict)", v, src)
	}
}

func TestEvaluateUDP_UnscopedRulesIgnored(t *testing.T) {
	// Rules without explicit protocols must NOT match EvaluateUDP or
	// EvaluateQUIC. This prevents TCP-intended allow rules from
	// inadvertently allowing UDP/QUIC traffic.
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "api.anthropic.com"
ports = [443]

[[allow]]
destination = "udp-ok.example.com"
ports = [443]
protocols = ["udp"]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Unscoped allow rule must NOT allow UDP traffic.
	if got := eng.EvaluateUDP("api.anthropic.com", 443); got != Deny {
		t.Errorf("EvaluateUDP(unscoped allow) = %v, want Deny", got)
	}

	// Unscoped allow rule must NOT allow QUIC traffic.
	if got := eng.EvaluateQUIC("api.anthropic.com", 443); got != Deny {
		t.Errorf("EvaluateQUIC(unscoped allow) = %v, want Deny", got)
	}

	// Explicitly scoped UDP rule must still work.
	if got := eng.EvaluateUDP("udp-ok.example.com", 443); got != Allow {
		t.Errorf("EvaluateUDP(scoped allow) = %v, want Allow", got)
	}

	// Regular Evaluate must still allow unscoped rules.
	if got := eng.Evaluate("api.anthropic.com", 443); got != Allow {
		t.Errorf("Evaluate(unscoped allow) = %v, want Allow", got)
	}
}

func TestEvaluate_TCPMetaProtocol(t *testing.T) {
	// Rules with protocols=["tcp"] should match any TCP-based connection
	// regardless of the detected application-level protocol, mirroring
	// how "udp" works in EvaluateUDP/EvaluateQUIC.
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "tcp-all.example.com"
protocols = ["tcp"]
name = "allow all TCP to this host"

[[deny]]
destination = "tcp-deny.example.com"
protocols = ["tcp"]
name = "deny all TCP to this host"
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	tests := []struct {
		name  string
		dest  string
		port  int
		proto string
		want  Verdict
	}{
		// TCP meta-protocol matches well-known port protocols.
		{"tcp_allows_https", "tcp-all.example.com", 443, "", Allow},
		{"tcp_allows_http", "tcp-all.example.com", 80, "", Allow},
		{"tcp_allows_ssh", "tcp-all.example.com", 22, "", Allow},
		{"tcp_allows_imap", "tcp-all.example.com", 993, "", Allow},
		{"tcp_allows_smtp", "tcp-all.example.com", 587, "", Allow},

		// TCP meta-protocol matches explicit protocol overrides.
		{"tcp_allows_explicit_wss", "tcp-all.example.com", 443, "wss", Allow},
		{"tcp_allows_explicit_grpc", "tcp-all.example.com", 443, "grpc", Allow},
		{"tcp_allows_explicit_ws", "tcp-all.example.com", 80, "ws", Allow},

		// TCP meta-protocol matches unknown ports (no portToProtocol match).
		{"tcp_allows_unknown_port", "tcp-all.example.com", 9999, "", Allow},

		// TCP deny rule takes precedence.
		{"tcp_denies_https", "tcp-deny.example.com", 443, "", Deny},
		{"tcp_denies_http", "tcp-deny.example.com", 80, "", Deny},
		{"tcp_denies_ssh", "tcp-deny.example.com", 22, "", Deny},
		{"tcp_denies_unknown_port", "tcp-deny.example.com", 9999, "", Deny},

		// TCP meta-protocol must NOT match UDP-family protocols passed
		// explicitly via EvaluateWithProtocol (e.g. DNS interceptor passes "dns").
		{"tcp_does_not_match_explicit_dns", "tcp-all.example.com", 53, "dns", Deny},
		{"tcp_does_not_match_quic", "tcp-all.example.com", 443, "quic", Deny},
		{"tcp_does_not_match_udp", "tcp-all.example.com", 53, "udp", Deny},

		// TCP CONNECT to port 53 (DNS-over-TCP) without explicit proto
		// should still be matched by protocols=["tcp"]. The port-based
		// mapping returns "dns" but proto="" means we are in the TCP
		// evaluation path, not the UDP DNS interceptor.
		{"tcp_matches_port53_no_proto", "tcp-all.example.com", 53, "", Allow},
		{"tcp_denies_port53_no_proto", "tcp-deny.example.com", 53, "", Deny},

		// Unrelated host falls through to default (deny).
		{"other_host_denied", "other.example.com", 443, "", Deny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := eng.EvaluateWithProtocol(tt.dest, tt.port, tt.proto)
			if got != tt.want {
				t.Errorf("EvaluateWithProtocol(%q, %d, %q) = %v, want %v",
					tt.dest, tt.port, tt.proto, got, tt.want)
			}
		})
	}

	// TCP meta-protocol must NOT affect UDP evaluation.
	if got := eng.EvaluateUDP("tcp-all.example.com", 443); got != Deny {
		t.Errorf("EvaluateUDP should not match tcp rule, got %v, want Deny", got)
	}
}

// ---------------------------------------------------------------------------
// Mutation methods (deprecated but still exercised for backward compat)
// ---------------------------------------------------------------------------

func TestAddDynamicAllow(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"

[[deny]]
destination = "evil.com"
`))
	if err != nil {
		t.Fatal(err)
	}

	// Before: unknown host is denied by default.
	if got := eng.Evaluate("new.example.com", 443); got != Deny {
		t.Fatalf("expected Deny before AddDynamicAllow, got %v", got)
	}

	// Add dynamic allow rule.
	if err := eng.AddDynamicAllow("new.example.com", 443); err != nil {
		t.Fatalf("AddDynamicAllow: %v", err)
	}

	// After: the host on that port is now allowed.
	if got := eng.Evaluate("new.example.com", 443); got != Allow {
		t.Errorf("expected Allow after AddDynamicAllow, got %v", got)
	}

	// Deny rule still takes priority for evil.com.
	if got := eng.Evaluate("evil.com", 443); got != Deny {
		t.Errorf("deny rule should still apply, got %v", got)
	}
}

func TestAddDynamicAllow_RollbackOnCompileError(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"
`))
	if err != nil {
		t.Fatal(err)
	}
	origCount := len(eng.AllowRules)

	// Empty destination triggers compile error.
	if err := eng.AddDynamicAllow("", 443); err == nil {
		t.Fatal("expected error for empty destination")
	}

	// Rule list should be rolled back to original length.
	if len(eng.AllowRules) != origCount {
		t.Errorf("AllowRules length = %d, want %d (rollback failed)", len(eng.AllowRules), origCount)
	}
}

func TestAddAllowRule(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"
`))
	if err != nil {
		t.Fatal(err)
	}

	if got := eng.Evaluate("api.example.com", 443); got != Deny {
		t.Fatalf("expected Deny before AddAllowRule, got %v", got)
	}

	if err := eng.AddAllowRule("api.example.com"); err != nil {
		t.Fatalf("AddAllowRule: %v", err)
	}

	// Portless allow rule matches any port.
	if got := eng.Evaluate("api.example.com", 443); got != Allow {
		t.Errorf("expected Allow on port 443, got %v", got)
	}
	if got := eng.Evaluate("api.example.com", 80); got != Allow {
		t.Errorf("expected Allow on port 80, got %v", got)
	}
}

func TestAddAllowRule_RollbackOnCompileError(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"
`))
	if err != nil {
		t.Fatal(err)
	}
	origCount := len(eng.AllowRules)

	if err := eng.AddAllowRule(""); err == nil {
		t.Fatal("expected error for empty destination")
	}
	if len(eng.AllowRules) != origCount {
		t.Errorf("AllowRules length = %d, want %d (rollback failed)", len(eng.AllowRules), origCount)
	}
}

func TestAddDenyRule(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "allow"

[[allow]]
destination = "good.example.com"
`))
	if err != nil {
		t.Fatal(err)
	}

	if got := eng.Evaluate("bad.example.com", 443); got != Allow {
		t.Fatalf("expected Allow before AddDenyRule, got %v", got)
	}

	if err := eng.AddDenyRule("bad.example.com"); err != nil {
		t.Fatalf("AddDenyRule: %v", err)
	}

	// Now denied.
	if got := eng.Evaluate("bad.example.com", 443); got != Deny {
		t.Errorf("expected Deny after AddDenyRule, got %v", got)
	}

	// Good host still allowed.
	if got := eng.Evaluate("good.example.com", 443); got != Allow {
		t.Errorf("expected Allow for good.example.com, got %v", got)
	}
}

func TestAddDenyRule_RollbackOnCompileError(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "allow"
`))
	if err != nil {
		t.Fatal(err)
	}
	origCount := len(eng.DenyRules)

	if err := eng.AddDenyRule(""); err == nil {
		t.Fatal("expected error for empty destination")
	}
	if len(eng.DenyRules) != origCount {
		t.Errorf("DenyRules length = %d, want %d (rollback failed)", len(eng.DenyRules), origCount)
	}
}

func TestAddAllowRule_ConcurrentSafety(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"
`))
	if err != nil {
		t.Fatal(err)
	}

	const n = 50
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			errs <- eng.AddAllowRule(fmt.Sprintf("host%d.example.com", i))
		}(i)
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent AddAllowRule: %v", err)
		}
	}

	// All 50 hosts should now be allowed.
	for i := 0; i < n; i++ {
		dest := fmt.Sprintf("host%d.example.com", i)
		if got := eng.Evaluate(dest, 443); got != Allow {
			t.Errorf("Evaluate(%q) = %v, want Allow", dest, got)
		}
	}
}

func TestRemoveRule(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "allowed.example.com"

[[deny]]
destination = "denied.example.com"

[[ask]]
destination = "ask.example.com"
`))
	if err != nil {
		t.Fatal(err)
	}

	// Remove from allow list.
	removed, err := eng.RemoveRule("allowed.example.com")
	if err != nil {
		t.Fatalf("RemoveRule(allow): %v", err)
	}
	if !removed {
		t.Error("expected removed=true for allow rule")
	}
	if got := eng.Evaluate("allowed.example.com", 443); got != Deny {
		t.Errorf("after removing allow rule, expected Deny, got %v", got)
	}

	// Remove from deny list.
	removed, err = eng.RemoveRule("denied.example.com")
	if err != nil {
		t.Fatalf("RemoveRule(deny): %v", err)
	}
	if !removed {
		t.Error("expected removed=true for deny rule")
	}

	// Remove from ask list.
	removed, err = eng.RemoveRule("ask.example.com")
	if err != nil {
		t.Fatalf("RemoveRule(ask): %v", err)
	}
	if !removed {
		t.Error("expected removed=true for ask rule")
	}
}

func TestRemoveRule_NonExistent(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "example.com"
`))
	if err != nil {
		t.Fatal(err)
	}

	removed, err := eng.RemoveRule("nonexistent.example.com")
	if err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}
	if removed {
		t.Error("expected removed=false for non-existent rule")
	}
}

func TestRemoveRule_CaseInsensitive(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "Example.COM"
`))
	if err != nil {
		t.Fatal(err)
	}

	removed, err := eng.RemoveRule("example.com")
	if err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}
	if !removed {
		t.Error("expected case-insensitive removal to succeed")
	}
	if got := eng.Evaluate("example.com", 443); got != Deny {
		t.Errorf("expected Deny after removal, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

func TestSnapshot(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "ask"

[[allow]]
destination = "good.example.com"
ports = [443]

[[deny]]
destination = "bad.example.com"

[[ask]]
destination = "maybe.example.com"
`))
	if err != nil {
		t.Fatal(err)
	}

	snap := eng.Snapshot()

	if snap.Default != Ask {
		t.Errorf("Snapshot.Default = %v, want Ask", snap.Default)
	}
	if len(snap.AllowRules) != 1 {
		t.Errorf("Snapshot.AllowRules len = %d, want 1", len(snap.AllowRules))
	}
	if len(snap.DenyRules) != 1 {
		t.Errorf("Snapshot.DenyRules len = %d, want 1", len(snap.DenyRules))
	}
	if len(snap.AskRules) != 1 {
		t.Errorf("Snapshot.AskRules len = %d, want 1", len(snap.AskRules))
	}

	// Verify snapshot content matches engine state.
	if snap.AllowRules[0].Destination != "good.example.com" {
		t.Errorf("AllowRules[0].Destination = %q, want %q", snap.AllowRules[0].Destination, "good.example.com")
	}
	if snap.DenyRules[0].Destination != "bad.example.com" {
		t.Errorf("DenyRules[0].Destination = %q, want %q", snap.DenyRules[0].Destination, "bad.example.com")
	}
	if snap.AskRules[0].Destination != "maybe.example.com" {
		t.Errorf("AskRules[0].Destination = %q, want %q", snap.AskRules[0].Destination, "maybe.example.com")
	}
}

func TestSnapshot_MutationIsolation(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "example.com"
`))
	if err != nil {
		t.Fatal(err)
	}

	snap := eng.Snapshot()

	// Mutate the engine after snapshot.
	if err := eng.AddAllowRule("new.example.com"); err != nil {
		t.Fatalf("AddAllowRule: %v", err)
	}

	// Snapshot should be unaffected.
	if len(snap.AllowRules) != 1 {
		t.Errorf("Snapshot AllowRules len changed to %d after engine mutation, want 1", len(snap.AllowRules))
	}

	// Mutate the snapshot slice directly.
	snap.AllowRules[0].Destination = "hacked.com"

	// Engine should be unaffected.
	newSnap := eng.Snapshot()
	if newSnap.AllowRules[0].Destination == "hacked.com" {
		t.Error("mutating snapshot slice affected engine state")
	}
}

// ---------------------------------------------------------------------------
// portToProtocol
// ---------------------------------------------------------------------------

func TestPortToProtocol(t *testing.T) {
	tests := []struct {
		port int
		want string
	}{
		{80, "http"},
		{8080, "http"},
		{443, "https"},
		{8443, "https"},
		{22, "ssh"},
		{143, "imap"},
		{993, "imap"},
		{25, "smtp"},
		{587, "smtp"},
		{465, "smtp"},
		{53, "dns"},
		{5223, "apns"},
		{9999, ""},
		{1, ""},
		{0, ""},
		{65535, ""},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("port_%d", tt.port), func(t *testing.T) {
			got := portToProtocol(tt.port)
			if got != tt.want {
				t.Errorf("portToProtocol(%d) = %q, want %q", tt.port, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestEmptyEngine(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"
`))
	if err != nil {
		t.Fatal(err)
	}

	// No rules at all. Default applies.
	if got := eng.Evaluate("anything.com", 443); got != Deny {
		t.Errorf("empty engine default=deny: got %v", got)
	}
	if eng.IsDenied("anything.com", 443) {
		t.Error("IsDenied should be false with no deny rules")
	}
	if eng.IsRestricted("anything.com", 443) {
		t.Error("IsRestricted should be false with no deny/ask rules")
	}
	if eng.IsExplicitlyAllowed("anything.com", 443) {
		t.Error("IsExplicitlyAllowed should be false with no allow rules")
	}
}

func TestEmptyEngineDefaultAllow(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "allow"
`))
	if err != nil {
		t.Fatal(err)
	}

	if got := eng.Evaluate("anything.com", 443); got != Allow {
		t.Errorf("empty engine default=allow: got %v", got)
	}
}

func TestAllRulesSameVerdict(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "a.example.com"

[[allow]]
destination = "b.example.com"

[[allow]]
destination = "c.example.com"
`))
	if err != nil {
		t.Fatal(err)
	}

	// All three should be allowed.
	for _, dest := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if got := eng.Evaluate(dest, 443); got != Allow {
			t.Errorf("Evaluate(%q) = %v, want Allow", dest, got)
		}
	}

	// Others still denied.
	if got := eng.Evaluate("d.example.com", 443); got != Deny {
		t.Errorf("Evaluate(d.example.com) = %v, want Deny", got)
	}
}

func TestOverlappingGlobPatterns(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "allow"

[[deny]]
destination = "*.example.com"

[[allow]]
destination = "safe.example.com"
`))
	if err != nil {
		t.Fatal(err)
	}

	// Deny has priority over allow in evaluation order.
	if got := eng.Evaluate("safe.example.com", 443); got != Deny {
		t.Errorf("overlapping deny should win: got %v, want Deny", got)
	}
	if got := eng.Evaluate("other.example.com", 443); got != Deny {
		t.Errorf("wildcard deny should match: got %v, want Deny", got)
	}
	// Non-matching host falls to default allow.
	if got := eng.Evaluate("totally-different.com", 443); got != Allow {
		t.Errorf("non-matching should use default: got %v, want Allow", got)
	}
}

func TestOverlappingGlobPatterns_AskVsDeny(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "allow"

[[ask]]
destination = "**.example.com"

[[deny]]
destination = "bad.sub.example.com"
`))
	if err != nil {
		t.Fatal(err)
	}

	// Deny always takes priority over ask.
	if got := eng.Evaluate("bad.sub.example.com", 443); got != Deny {
		t.Errorf("deny should beat ask: got %v, want Deny", got)
	}
	// Ask still applies to other subdomains.
	if got := eng.Evaluate("good.sub.example.com", 443); got != Ask {
		t.Errorf("ask should match: got %v, want Ask", got)
	}
}

func TestValidate(t *testing.T) {
	// Nil engine.
	var nilEng *Engine
	if err := nilEng.Validate(); err == nil {
		t.Error("Validate on nil engine should return error")
	}

	// Engine without compilation.
	uncompiledEng := &Engine{}
	if err := uncompiledEng.Validate(); err == nil {
		t.Error("Validate on uncompiled engine should return error")
	}

	// Properly loaded engine.
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Validate(); err != nil {
		t.Errorf("Validate on valid engine: %v", err)
	}
}

func TestEvaluateDetailed(t *testing.T) {
	eng := loadFromTOMLFile(t, "../../testdata/policy_mixed.toml")

	tests := []struct {
		dest       string
		port       int
		wantV      Verdict
		wantSource MatchSource
	}{
		// Explicit allow rule match.
		{"api.anthropic.com", 443, Allow, RuleMatch},
		{"api.github.com", 443, Allow, RuleMatch},
		{"api.github.com", 80, Allow, RuleMatch},
		// Explicit deny rule match.
		{"169.254.169.254", 80, Deny, RuleMatch},
		{"pool.crypto-mining.example", 443, Deny, RuleMatch},
		// Explicit ask rule match.
		{"api.openai.com", 443, Ask, RuleMatch},
		// No rule matches: default verdict (deny) with DefaultVerdict source.
		{"random.unknown.com", 443, Deny, DefaultVerdict},
		{"api.openai.com", 80, Deny, DefaultVerdict},
		// *.github.com at port 22 has no matching allow rule (port mismatch),
		// so it falls through to the default deny verdict.
		{"api.github.com", 22, Deny, DefaultVerdict},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s:%d", tt.dest, tt.port), func(t *testing.T) {
			gotV, gotSource := eng.EvaluateDetailed(tt.dest, tt.port)
			if gotV != tt.wantV {
				t.Errorf("EvaluateDetailed(%q, %d) verdict = %v, want %v",
					tt.dest, tt.port, gotV, tt.wantV)
			}
			if gotSource != tt.wantSource {
				t.Errorf("EvaluateDetailed(%q, %d) source = %v, want %v",
					tt.dest, tt.port, gotSource, tt.wantSource)
			}
		})
	}
}

func TestEvaluateDetailedDefaultAllow(t *testing.T) {
	// With default=allow, an unmatched destination should return Allow with
	// DefaultVerdict source. This is the key distinction the fast-path uses
	// to decide whether to skip per-request policy checks.
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "allow"

[[deny]]
destination = "evil.com"

[[allow]]
destination = "api.example.com"
ports = [443]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Explicit allow rule -> RuleMatch.
	v, src := eng.EvaluateDetailed("api.example.com", 443)
	if v != Allow || src != RuleMatch {
		t.Errorf("EvaluateDetailed(api.example.com, 443) = (%v, %v), want (Allow, RuleMatch)", v, src)
	}

	// Explicit deny rule -> RuleMatch.
	v, src = eng.EvaluateDetailed("evil.com", 443)
	if v != Deny || src != RuleMatch {
		t.Errorf("EvaluateDetailed(evil.com, 443) = (%v, %v), want (Deny, RuleMatch)", v, src)
	}

	// Unmatched host -> default (allow) with DefaultVerdict source.
	v, src = eng.EvaluateDetailed("random.host", 443)
	if v != Allow || src != DefaultVerdict {
		t.Errorf("EvaluateDetailed(random.host, 443) = (%v, %v), want (Allow, DefaultVerdict)", v, src)
	}
}

func TestEvaluateDetailedWithProtocol(t *testing.T) {
	eng, err := LoadFromBytes([]byte(`
[policy]
default = "deny"

[[allow]]
destination = "api.example.com"
protocols = ["https"]

[[deny]]
destination = "api.example.com"
protocols = ["http"]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Explicit protocol match via EvaluateDetailedWithProtocol.
	v, src := eng.EvaluateDetailedWithProtocol("api.example.com", 443, "https")
	if v != Allow || src != RuleMatch {
		t.Errorf("EvaluateDetailedWithProtocol(https) = (%v, %v), want (Allow, RuleMatch)", v, src)
	}

	v, src = eng.EvaluateDetailedWithProtocol("api.example.com", 80, "http")
	if v != Deny || src != RuleMatch {
		t.Errorf("EvaluateDetailedWithProtocol(http) = (%v, %v), want (Deny, RuleMatch)", v, src)
	}

	// Unmatched protocol falls to default.
	v, src = eng.EvaluateDetailedWithProtocol("unknown.host", 443, "https")
	if v != Deny || src != DefaultVerdict {
		t.Errorf("EvaluateDetailedWithProtocol(unknown) = (%v, %v), want (Deny, DefaultVerdict)", v, src)
	}
}

func TestMatchSourceString(t *testing.T) {
	if RuleMatch.String() != "rule" {
		t.Errorf("RuleMatch.String() = %q, want %q", RuleMatch.String(), "rule")
	}
	if DefaultVerdict.String() != "default" {
		t.Errorf("DefaultVerdict.String() = %q, want %q", DefaultVerdict.String(), "default")
	}
	if MatchSource(99).String() != "unknown" {
		t.Errorf("MatchSource(99).String() = %q, want %q", MatchSource(99).String(), "unknown")
	}
}
