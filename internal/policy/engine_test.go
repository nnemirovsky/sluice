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
}

func TestEvaluate(t *testing.T) {
	eng, err := LoadFromFile("../../testdata/policy_mixed.toml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := eng.Compile(); err != nil {
		t.Fatalf("compile: %v", err)
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
