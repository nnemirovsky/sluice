package vault

import (
	"strings"
	"testing"
)

func TestGeneratePhantomToken(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
	}{
		{"anthropic_api_key", "sk-ant-phantom-"},
		{"openai_api_key", "sk-phantom-"},
		{"github_token", "ghp_phantom"},
		{"unknown_cred", "phantom-"},
	}

	for _, tt := range tests {
		token := GeneratePhantomToken(tt.name)
		if !strings.HasPrefix(token, tt.prefix) {
			t.Errorf("GeneratePhantomToken(%q) = %q, want prefix %q", tt.name, token, tt.prefix)
		}
		if len(token) < len(tt.prefix)+10 {
			t.Errorf("GeneratePhantomToken(%q) too short: %q", tt.name, token)
		}
	}

	// Verify uniqueness across calls.
	t1 := GeneratePhantomToken("anthropic_api_key")
	t2 := GeneratePhantomToken("anthropic_api_key")
	if t1 == t2 {
		t.Error("phantom tokens should be unique across calls")
	}
}

func TestGeneratePhantomEnv(t *testing.T) {
	env := GeneratePhantomEnv([]string{"anthropic_api_key", "github_token"})

	if _, ok := env["ANTHROPIC_API_KEY"]; !ok {
		t.Error("should have ANTHROPIC_API_KEY")
	}
	if _, ok := env["GITHUB_TOKEN"]; !ok {
		t.Error("should have GITHUB_TOKEN")
	}
	if !strings.HasPrefix(env["ANTHROPIC_API_KEY"], "sk-ant-phantom-") {
		t.Errorf("ANTHROPIC_API_KEY should match format: %s", env["ANTHROPIC_API_KEY"])
	}
	if !strings.HasPrefix(env["GITHUB_TOKEN"], "ghp_phantom") {
		t.Errorf("GITHUB_TOKEN should match format: %s", env["GITHUB_TOKEN"])
	}
}

func TestCredNameToEnvVar(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"anthropic_api_key", "ANTHROPIC_API_KEY"},
		{"github_token", "GITHUB_TOKEN"},
		{"my_secret", "MY_SECRET"},
		{"my-api-key", "MY_API_KEY"},
		{"cred.name.dots", "CRED_NAME_DOTS"},
	}
	for _, tt := range tests {
		got := CredNameToEnvVar(tt.name)
		if got != tt.want {
			t.Errorf("CredNameToEnvVar(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}
