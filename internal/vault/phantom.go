package vault

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
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
// If a provider is given, OAuth credentials produce two entries
// (CRED_ACCESS and CRED_REFRESH) instead of one.
func GeneratePhantomEnv(credNames []string, providers ...Provider) map[string]string {
	result := make(map[string]string, len(credNames)*2)
	var prov Provider
	if len(providers) > 0 {
		prov = providers[0]
	}
	for _, name := range credNames {
		if prov != nil {
			secret, err := prov.Get(name)
			if err == nil {
				if IsOAuth(secret.Bytes()) {
					secret.Release()
					envBase := CredNameToEnvVar(name)
					result[envBase+"_ACCESS"] = GeneratePhantomToken(name)
					result[envBase+"_REFRESH"] = GeneratePhantomToken(name)
					continue
				}
				secret.Release()
			}
		}
		envVar := CredNameToEnvVar(name)
		result[envVar] = GeneratePhantomToken(name)
	}
	return result
}

// WriteOAuthPhantoms writes two phantom token files for an OAuth credential
// to the given directory: CRED_ACCESS and CRED_REFRESH. The file content is
// a format-matching phantom token generated via GeneratePhantomToken.
// This is called from the async goroutine in the response handler after
// vault persistence so the agent container picks up refreshed phantom values.
func WriteOAuthPhantoms(dir string, name string) error {
	envBase := CredNameToEnvVar(name)
	files := map[string]string{
		envBase + "_ACCESS":  GeneratePhantomToken(name),
		envBase + "_REFRESH": GeneratePhantomToken(name),
	}
	for fname, value := range files {
		path := filepath.Join(dir, fname)
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			return fmt.Errorf("write oauth phantom file %s: %w", fname, err)
		}
	}
	return nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
