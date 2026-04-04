package vault

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// GeneratePhantomToken creates a phantom token value matching the expected
// format for the given credential name. SDKs validate token prefixes, so
// phantom tokens must pass basic format checks.
func GeneratePhantomToken(credName string) string {
	rnd := randomHex(20)
	switch {
	case strings.Contains(credName, "anthropic"):
		return "sk-ant-phantom-" + rnd
	case strings.Contains(credName, "openai"):
		return "sk-phantom-" + rnd
	case strings.Contains(credName, "github"):
		return "ghp_phantom" + rnd
	default:
		return "phantom-" + rnd
	}
}

// CredNameToEnvVar converts a credential name to an environment variable name.
// Non-alphanumeric characters (hyphens, dots, etc.) are replaced with underscores
// to produce valid shell environment variable names.
func CredNameToEnvVar(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, c := range strings.ToUpper(name) {
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// GeneratePhantomEnv generates phantom token environment variables for all
// given credential names. Returns a map of ENV_VAR_NAME to phantom value.
func GeneratePhantomEnv(credNames []string) map[string]string {
	result := make(map[string]string, len(credNames))
	for _, name := range credNames {
		envVar := CredNameToEnvVar(name)
		result[envVar] = GeneratePhantomToken(name)
	}
	return result
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
