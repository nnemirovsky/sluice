// Package container defines the ContainerManager interface shared by Docker,
// Apple Container, and tart (macOS VM) backends. Each backend implements this
// interface so that Telegram commands, MCP injection, and credential management
// code can work with any container runtime without knowing the specifics.
package container

import (
	"context"
	"fmt"
	"regexp"
	"sort"
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

	// InjectCACert copies the sluice MITM CA certificate into the guest and
	// updates the system trust store so TLS interception works. hostCertPath
	// is the path to the CA cert on the host. certDir is the shared volume
	// directory where the cert is written for the guest to access.
	// Implementations should be best-effort: if trust store commands fail
	// the cert is still available via env vars (SSL_CERT_FILE, etc.).
	InjectCACert(ctx context.Context, hostCertPath, certDir string) error

	// ReloadSecrets signals the agent to re-read secrets from the env file.
	ReloadSecrets(ctx context.Context) error

	// WireMCPGateway registers sluice's MCP gateway URL under
	// mcp.servers.<name> in the agent's config so the embedded runtime
	// discovers sluice as an MCP server. Idempotent: a second call with
	// the same arguments is a noop.
	WireMCPGateway(ctx context.Context, name, sluiceURL string) error

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

// Sluice-managed env block markers. Sluice writes the keys it owns into a
// single contiguous block between BEGIN/END markers and replaces only that
// block on each injection. Anything outside the markers (keys written by
// the agent, by `hermes claw migrate`, or by an operator) is preserved
// across both incremental updates and full reconciliation runs.
//
// These constants are exported so docs and the bootstrap script can
// reference the exact strings.
const (
	EnvBlockBegin = "# BEGIN sluice-managed (do not edit)"
	EnvBlockEnd   = "# END sluice-managed"
)

// BuildEnvInjectionScript constructs a shell script that writes each key=value
// pair from envMap into the agent's env file inside the container. The path
// defaults to ~/.openclaw/.env (OpenclawProfile); pass a different profile
// via BuildEnvInjectionScriptForProfile to target Hermes or future agents.
//
// Sluice writes its keys into a single fenced block (see EnvBlockBegin /
// EnvBlockEnd). On each call the existing block is removed and a fresh
// block is appended, so any keys outside the block are preserved
// regardless of fullReplace. The bsdSed flag controls whether to use BSD
// sed syntax (sed -i ”) or GNU sed syntax (sed -i).
//
// The fullReplace flag is retained for API compatibility but no longer
// affects behavior: every call now reconciles the managed block, which
// is the safe semantic for both startup and SIGHUP-triggered reloads.
// Removing a binding's env var means it stops appearing in envMap, which
// causes the next injection to drop it from the block.
//
// Both keys and values are validated/escaped to prevent shell injection:
// keys must match [A-Za-z_][A-Za-z0-9_]*, values are single-quoted with
// internal single quotes escaped, and shell metacharacters in the marker
// strings are not interpolated from user input.
func BuildEnvInjectionScript(envMap map[string]string, bsdSed bool, fullReplace bool) (string, error) {
	return BuildEnvInjectionScriptForProfile(OpenclawProfile, envMap, bsdSed, fullReplace)
}

// BuildEnvInjectionScriptForProfile is like BuildEnvInjectionScript but
// targets the env file path declared by the given AgentProfile. A nil
// profile defaults to OpenclawProfile so existing call sites keep their
// behavior.
func BuildEnvInjectionScriptForProfile(profile *AgentProfile, envMap map[string]string, bsdSed bool, _ bool) (string, error) {
	p := resolveProfile(profile)
	if err := validateEnvFileRelPath(p.EnvFileRelPath); err != nil {
		return "", fmt.Errorf("agent profile %q: %w", p.Name, err)
	}

	// Validate and pre-format every entry up front so a bad key fails the
	// whole call before any side effects rather than partially writing
	// the block.
	keys := make([]string, 0, len(envMap))
	for k := range envMap {
		if err := ValidateEnvVarKey(k); err != nil {
			return "", err
		}
		keys = append(keys, k)
	}
	// Stable order makes the file diff-friendly across runs.
	sort.Strings(keys)

	var script strings.Builder
	script.WriteString(fmt.Sprintf(
		`ENV_FILE="$HOME/%s" && mkdir -p "$(dirname "$ENV_FILE")" && touch "$ENV_FILE"`,
		p.EnvFileRelPath,
	))

	sedFlag := "-i"
	if bsdSed {
		sedFlag = "-i ''"
	}

	// Step 1: delete any existing sluice-managed block. The pattern is an
	// exact match on the marker comment lines, so it never strikes a key
	// the agent or migration wrote.
	beginEsc := sedRegexEscape(EnvBlockBegin)
	endEsc := sedRegexEscape(EnvBlockEnd)
	script.WriteString(fmt.Sprintf(
		` && sed %s '/^%s$/,/^%s$/d' "$ENV_FILE"`,
		sedFlag, beginEsc, endEsc,
	))

	// Step 2: append a fresh block. Skip the block entirely when there is
	// nothing to manage so we do not leave empty markers behind.
	if len(keys) == 0 {
		return script.String(), nil
	}
	script.WriteString(fmt.Sprintf(` && { echo '%s'`, EnvBlockBegin))
	for _, k := range keys {
		v := envMap[k]
		// Empty value means the binding wants the key gone. The marker
		// block is rebuilt fresh on every call, so simply omitting the
		// key from the new block is enough to remove it from the file.
		if v == "" {
			continue
		}
		escaped := strings.ReplaceAll(v, "'", "'\"'\"'")
		script.WriteString(fmt.Sprintf(`; echo '%s=%s'`, k, escaped))
	}
	script.WriteString(fmt.Sprintf(`; echo '%s'; } >> "$ENV_FILE"`, EnvBlockEnd))

	return script.String(), nil
}

// sedRegexEscape escapes characters that have special meaning in a basic
// sed regex anchored on a marker comment line. We control the marker
// strings, but a brittle assumption that no future marker would contain
// a metacharacter is the kind of cleanup people forget to do.
func sedRegexEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '/', '.', '*', '[', ']', '\\', '^', '$', '(', ')':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
