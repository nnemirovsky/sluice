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

func TestGeneratePhantomTokenExported(t *testing.T) {
	// Verify GeneratePhantomToken is exported and usable for MITM phantom
	// string generation. This is the only function remaining from phantom.go
	// after the docker exec env injection migration removed file-based phantom
	// generation (GeneratePhantomEnv, CredNameToEnvVar, WriteOAuthPhantoms).
	token := GeneratePhantomToken("test_cred")
	if token == "" {
		t.Error("GeneratePhantomToken should return a non-empty string")
	}
	if !strings.HasPrefix(token, "phantom-") {
		t.Errorf("GeneratePhantomToken(%q) = %q, want phantom- prefix for unknown cred", "test_cred", token)
	}
}
