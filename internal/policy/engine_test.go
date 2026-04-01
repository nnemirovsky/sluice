package policy

import (
	"fmt"
	"testing"
)

func TestLoadPolicy(t *testing.T) {
	eng, err := LoadFromFile("../../testdata/policy_mixed.toml")
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}
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
	eng, err := LoadFromFile("../../testdata/policy_mixed.toml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

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
	eng, err := LoadFromFile("../../testdata/policy_mixed.toml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

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
	eng, err := LoadFromFile("../../testdata/policy_mixed.toml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

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
	eng, err := LoadFromFile("../../testdata/policy_mixed.toml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

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
	eng, err := LoadFromFile("../../testdata/policy_mixed.toml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

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

func TestLoadPolicyWithTelegram(t *testing.T) {
	eng, err := LoadFromFile("../../testdata/policy_with_telegram.toml")
	if err != nil {
		t.Fatal(err)
	}
	if eng.Telegram.BotTokenEnv != "TELEGRAM_BOT_TOKEN" {
		t.Errorf("expected bot_token_env %q, got %q", "TELEGRAM_BOT_TOKEN", eng.Telegram.BotTokenEnv)
	}
	if eng.Telegram.ChatIDEnv != "TELEGRAM_CHAT_ID" {
		t.Errorf("expected chat_id_env %q, got %q", "TELEGRAM_CHAT_ID", eng.Telegram.ChatIDEnv)
	}
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

func TestLoadPolicyWithoutTelegram(t *testing.T) {
	eng, err := LoadFromFile("../../testdata/policy_mixed.toml")
	if err != nil {
		t.Fatal(err)
	}
	if eng.Telegram.BotTokenEnv != "" {
		t.Errorf("expected empty bot_token_env, got %q", eng.Telegram.BotTokenEnv)
	}
	if eng.Telegram.ChatIDEnv != "" {
		t.Errorf("expected empty chat_id_env, got %q", eng.Telegram.ChatIDEnv)
	}
}
