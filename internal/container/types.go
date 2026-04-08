// Package container defines the ContainerManager interface shared by Docker,
// Apple Container, and tart (macOS VM) backends. Each backend implements this
// interface so that Telegram commands, MCP injection, and credential management
// code can work with any container runtime without knowing the specifics.
package container

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Runtime identifies the container backend in use.
type Runtime int

// Container runtime backends.
const (
	RuntimeDocker Runtime = 0
	RuntimeApple  Runtime = 1
	RuntimeNone   Runtime = 2
	RuntimeMacOS  Runtime = 3
)

// String returns a human-readable name for the runtime.
func (r Runtime) String() string {
	switch r {
	case RuntimeDocker:
		return "docker"
	case RuntimeApple:
		return "apple"
	case RuntimeNone:
		return "none"
	case RuntimeMacOS:
		return "macos"
	default:
		return "unknown"
	}
}

// ContainerManager abstracts container lifecycle and credential management
// across different container runtimes (Docker, Apple Container, macOS VM).
type ContainerManager interface { //nolint:revive // stuttering accepted for clarity
	// InjectEnvVars writes environment variables into the agent container's
	// env file (~/.openclaw/.env) via exec and signals the agent to reload.
	// Each key in envMap is an env var name and the value is the phantom
	// token value. When fullReplace is false, existing entries with the same
	// key are updated in-place (merge semantics). When fullReplace is true,
	// the file is truncated first so only entries in envMap remain
	// (reconciliation semantics for startup/reload paths).
	InjectEnvVars(ctx context.Context, envMap map[string]string, fullReplace bool) error

	// RestartWithEnv recreates the container with updated environment variables.
	RestartWithEnv(ctx context.Context, env map[string]string) error

	// InjectMCPConfig writes mcp-servers.json to the shared MCP volume and
	// signals the agent to reload MCP configuration.
	InjectMCPConfig(mcpDir, sluiceURL string) error

	// InjectCACert copies the sluice MITM CA certificate into the guest and
	// updates the system trust store so TLS interception works. hostCertPath
	// is the path to the CA cert on the host. certDir is the shared volume
	// directory where the cert is written for the guest to access.
	// Implementations should be best-effort: if trust store commands fail
	// the cert is still available via env vars (SSL_CERT_FILE, etc.).
	InjectCACert(ctx context.Context, hostCertPath, certDir string) error

	// ReloadSecrets signals the agent to re-read secrets from the env file.
	ReloadSecrets(ctx context.Context) error

	// Status returns container health information.
	Status(ctx context.Context) (ContainerStatus, error)

	// Stop stops the agent container.
	Stop(ctx context.Context) error

	// Runtime returns which backend this manager uses.
	Runtime() Runtime
}

// ContainerStatus holds container health information returned by Status.
type ContainerStatus struct { //nolint:revive // stuttering accepted for clarity
	ID      string
	Running bool
	Image   string
}

// WriteMCPConfig writes an mcp-servers.json file to the shared MCP volume
// directory. This logic is shared by all container backends.
func WriteMCPConfig(mcpDir, sluiceURL string) error {
	mcpConfig := map[string]any{
		"sluice": map[string]any{
			"url":       sluiceURL,
			"transport": "streamable-http",
		},
	}

	data, err := json.Marshal(mcpConfig)
	if err != nil {
		return fmt.Errorf("marshal mcp config: %w", err)
	}

	path := filepath.Join(mcpDir, "mcp-servers.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write mcp config: %w", err)
	}
	return nil
}

// envVarKeyRe matches valid POSIX environment variable names.
var envVarKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidateEnvVarKey checks that a key is a valid POSIX environment variable
// name. This prevents shell injection when keys are interpolated into shell
// scripts executed inside agent containers.
func ValidateEnvVarKey(key string) error {
	if !envVarKeyRe.MatchString(key) {
		return fmt.Errorf("invalid env var key %q: must match [A-Za-z_][A-Za-z0-9_]*", key)
	}
	return nil
}

// BuildEnvInjectionScript constructs a shell script that writes each key=value
// pair from envMap into ~/.openclaw/.env inside the agent container. When
// fullReplace is false, existing entries with the same key are updated
// in-place via sed and new entries are appended (merge semantics). When
// fullReplace is true, the file is truncated first so that only the entries
// in envMap remain (reconciliation semantics). The bsdSed flag controls
// whether to use BSD sed syntax (sed -i ”) or GNU sed syntax (sed -i).
//
// Both keys and values are validated/escaped to prevent shell injection:
// keys must match [A-Za-z_][A-Za-z0-9_]*, values are single-quoted with
// internal single quotes escaped, and the sed delimiter uses ASCII 0x01
// (SOH) to avoid conflicts with any printable character in values.
func BuildEnvInjectionScript(envMap map[string]string, bsdSed bool, fullReplace bool) (string, error) {
	var script strings.Builder
	script.WriteString(`ENV_FILE="$HOME/.openclaw/.env" && mkdir -p "$(dirname "$ENV_FILE")"`)
	if fullReplace {
		// Truncate the file so stale entries from removed bindings are cleared.
		script.WriteString(` && : > "$ENV_FILE"`)
	} else {
		script.WriteString(` && touch "$ENV_FILE"`)
	}

	sedFlag := "-i"
	if bsdSed {
		sedFlag = "-i ''"
	}

	for k, v := range envMap {
		if err := ValidateEnvVarKey(k); err != nil {
			return "", err
		}
		if v == "" {
			// Empty value means the env var should be removed from the file.
			// Use sed to delete the line matching ^KEY=.
			script.WriteString(fmt.Sprintf(
				" && sed %s '/^%s=/d' \"$ENV_FILE\"",
				sedFlag, k,
			))
			continue
		}
		// Use single quotes around the value with proper escaping.
		// Replace single quotes in value with '"'"' (end single-quote,
		// double-quote a single-quote, start single-quote again).
		escaped := strings.ReplaceAll(v, "'", "'\"'\"'")
		// Use ASCII SOH (0x01) as sed delimiter to avoid conflicts with
		// any printable character that might appear in phantom values.
		script.WriteString(fmt.Sprintf(
			" && if grep -q '^%s=' \"$ENV_FILE\"; then sed %s 's\x01^%s=.*\x01%s=%s\x01' \"$ENV_FILE\"; else echo '%s=%s' >> \"$ENV_FILE\"; fi",
			k, sedFlag, k, k, escaped, k, escaped,
		))
	}

	return script.String(), nil
}
