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
		// Matches ask rule (*.openai.com) -> treated as deny (ask = deny, no allow override)
		{"api.openai.com", false},
		// Matches portless deny rule (169.254.169.254) -> definitely denied
		{"169.254.169.254", false},
		// Matches portless deny rule (*.crypto-mining.example) -> definitely denied
		{"pool.crypto-mining.example", false},
		// No rule matches, default is deny -> not allowed
		{"random.unknown.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.dest, func(t *testing.T) {
			got := eng.CouldBeAllowed(tt.dest)
			if got != tt.want {
				t.Errorf("CouldBeAllowed(%q) = %v, want %v",
					tt.dest, got, tt.want)
			}
		})
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
			got := eng.CouldBeAllowed(tt.dest)
			if got != tt.want {
				t.Errorf("CouldBeAllowed(%q) = %v, want %v",
					tt.dest, got, tt.want)
			}
		})
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
