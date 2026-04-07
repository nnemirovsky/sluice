package vault

import (
	"os"
	"path/filepath"
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

// mockOAuthProvider implements Provider for testing GeneratePhantomEnv with
// OAuth credential detection.
type mockOAuthProvider struct {
	creds map[string]string
}

func (m *mockOAuthProvider) Get(name string) (SecureBytes, error) {
	val, ok := m.creds[name]
	if !ok {
		return SecureBytes{}, os.ErrNotExist
	}
	return NewSecureBytes(val), nil
}
func (m *mockOAuthProvider) List() ([]string, error) {
	var names []string
	for k := range m.creds {
		names = append(names, k)
	}
	return names, nil
}
func (m *mockOAuthProvider) Name() string { return "mock" }

func TestGeneratePhantomEnvWithOAuth(t *testing.T) {
	prov := &mockOAuthProvider{
		creds: map[string]string{
			"static_key": "sk-real-value",
			"openai_oauth": `{"access_token":"real-access","refresh_token":"real-refresh","token_url":"https://auth0.openai.com/oauth/token"}`,
		},
	}

	env := GeneratePhantomEnv([]string{"static_key", "openai_oauth"}, prov)

	// Static credential: single entry.
	if _, ok := env["STATIC_KEY"]; !ok {
		t.Error("should have STATIC_KEY entry for static credential")
	}

	// OAuth credential: two entries (_ACCESS and _REFRESH), no base entry.
	if _, ok := env["OPENAI_OAUTH"]; ok {
		t.Error("should not have base OPENAI_OAUTH entry for OAuth credential")
	}
	if _, ok := env["OPENAI_OAUTH_ACCESS"]; !ok {
		t.Error("should have OPENAI_OAUTH_ACCESS for OAuth credential")
	}
	if _, ok := env["OPENAI_OAUTH_REFRESH"]; !ok {
		t.Error("should have OPENAI_OAUTH_REFRESH for OAuth credential")
	}

	// Verify phantom tokens have correct format.
	if !strings.HasPrefix(env["OPENAI_OAUTH_ACCESS"], "sk-phantom-") {
		t.Errorf("OPENAI_OAUTH_ACCESS should match openai format: %s", env["OPENAI_OAUTH_ACCESS"])
	}
}

func TestGeneratePhantomEnvWithoutProvider(t *testing.T) {
	// When no provider is passed, all credentials get a single phantom entry.
	env := GeneratePhantomEnv([]string{"any_cred"})
	if _, ok := env["ANY_CRED"]; !ok {
		t.Error("should have ANY_CRED when no provider is passed")
	}
}

func TestWriteOAuthPhantoms(t *testing.T) {
	dir := t.TempDir()

	if err := WriteOAuthPhantoms(dir, "openai_oauth"); err != nil {
		t.Fatalf("WriteOAuthPhantoms failed: %v", err)
	}

	// Verify two files were created with correct naming.
	accessPath := filepath.Join(dir, "OPENAI_OAUTH_ACCESS")
	refreshPath := filepath.Join(dir, "OPENAI_OAUTH_REFRESH")

	accessData, err := os.ReadFile(accessPath)
	if err != nil {
		t.Fatalf("access phantom file not found: %v", err)
	}
	if !strings.HasPrefix(string(accessData), "sk-phantom-") {
		t.Errorf("access phantom should match openai format: %s", string(accessData))
	}

	refreshData, err := os.ReadFile(refreshPath)
	if err != nil {
		t.Fatalf("refresh phantom file not found: %v", err)
	}
	if len(refreshData) == 0 {
		t.Error("refresh phantom file should not be empty")
	}

	// Verify file permissions are 0600.
	info, _ := os.Stat(accessPath)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("access phantom file has mode %o, want 0600", info.Mode().Perm())
	}
	info, _ = os.Stat(refreshPath)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("refresh phantom file has mode %o, want 0600", info.Mode().Perm())
	}
}

func TestWriteOAuthPhantomsNonExistentDir(t *testing.T) {
	err := WriteOAuthPhantoms("/nonexistent/path", "cred")
	if err == nil {
		t.Error("should fail for non-existent directory")
	}
}
