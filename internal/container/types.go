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
	// InjectEnvVars writes environment variables into the agent
	// container's env file (path determined by the active AgentProfile,
	// e.g. ~/.openclaw/.env or ~/.hermes/.env) via exec and signals
	// the agent to reload. Each key in envMap is an env var name and
	// the value is the phantom token value.
	//
	// Sluice owns a fenced "BEGIN sluice-managed / END sluice-managed"
	// block inside the env file. Each call rebuilds that block from
	// envMap and leaves any keys outside the markers untouched, so
	// secrets written by the agent itself or by a migration tool
	// (e.g. `hermes claw migrate`) are preserved across both
	// incremental updates and reconciliation runs.
	//
	// fullReplace is retained for source compatibility with earlier
	// callers but no longer affects file behavior — the marker block
	// is always reconciled. To remove a key sluice previously managed,
	// simply omit it from envMap on the next call (or set its value
	// to ""); the rebuilt block will not include it.
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

// validateEnvVarValue rejects values that cannot be safely written as a
// single line of a dotenv-style file. Newlines would split one logical
// entry into multiple file lines (the second line would either be a
// silently-dropped fragment or, when sourced, an unrelated KEY=value
// assignment). NUL bytes break dotenv parsers and shell sourcing.
//
// Any other byte is allowed because the value is single-quoted inside
// the generated `echo` command, neutralizing shell metacharacters.
func validateEnvVarValue(value string) error {
	for i, r := range value {
		if r == '\n' || r == '\r' {
			return fmt.Errorf("value contains newline at byte offset %d (would split env file entry)", i)
		}
		if r == 0 {
			return fmt.Errorf("value contains NUL byte at byte offset %d (breaks dotenv parsing)", i)
		}
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
// regardless of fullReplace.
//
// The implementation uses awk to delete the old block (only when both
// markers are present) and a simple appended `echo` chain to write the
// new block. Both bsdSed and fullReplace are retained in the signature
// for source-level compatibility with earlier callers but no longer
// affect behavior: awk is portable across BSD and GNU userlands, and
// every call reconciles the managed block (the safe semantic for both
// startup and SIGHUP-triggered reloads). Removing a binding's env var
// means it stops appearing in envMap, which causes the next injection
// to drop it from the block.
//
// Validation:
//   - keys must match [A-Za-z_][A-Za-z0-9_]* (POSIX env var name).
//   - values must not contain newlines or NUL bytes; either would split
//     the entry across multiple lines in the env file and inject a
//     second KEY=value (or worse, an arbitrary shell directive when the
//     file is sourced). Values are wrapped in single quotes inside the
//     `echo` shell command so embedded single quotes, double quotes,
//     spaces, $, and backticks are inert. The bytes that land in the
//     file are the literal value with no shell interpretation.
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

	// Validate and pre-format every entry up front so a bad key/value
	// fails the whole call before any side effects rather than
	// partially writing the block.
	keys := make([]string, 0, len(envMap))
	for k, v := range envMap {
		if err := ValidateEnvVarKey(k); err != nil {
			return "", err
		}
		if err := validateEnvVarValue(v); err != nil {
			return "", fmt.Errorf("env var %q: %w", k, err)
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

	// Step 1: delete any existing sluice-managed block. We use an awk
	// pre-pass to delete the block ONLY when both BEGIN and END markers
	// are present in the file. A naive `sed '/BEGIN/,/END/d'` would
	// happily delete from BEGIN through end-of-file when END is missing
	// (e.g. partial write, manual edit) which would silently nuke any
	// foreign keys the new design promises to preserve.
	//
	// The awk script reads the file twice: once to confirm both markers
	// exist (NR==FNR pass), once to print everything outside the marker
	// pair (skip lines from BEGIN through END inclusive). When either
	// marker is missing the file is rewritten unchanged. Output is
	// staged to a sibling temp file and renamed in place so a crash
	// mid-rewrite leaves the original env file intact.
	//
	// `bsdSed` is no longer consulted here because the awk path is
	// portable across BSD and GNU userlands. The parameter remains in
	// the signature to avoid breaking existing call sites.
	_ = bsdSed
	awkBegin := awkStringEscape(EnvBlockBegin)
	awkEnd := awkStringEscape(EnvBlockEnd)
	script.WriteString(fmt.Sprintf(
		` && TMP="$ENV_FILE.sluice.$$" && awk -v B='%s' -v E='%s' '`+
			`NR==FNR { if($0==B) hb=1; if($0==E) he=1; next }`+
			` !(hb && he) { print; next }`+
			` $0==B { skip=1; next }`+
			` skip && $0==E { skip=0; next }`+
			` !skip { print }'`+
			` "$ENV_FILE" "$ENV_FILE" > "$TMP" && mv "$TMP" "$ENV_FILE"`,
		awkBegin, awkEnd,
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

// awkStringEscape escapes a string so it can be safely passed via
// `awk -v VAR='<value>'` from inside a single-quoted shell argument.
// We control the marker strings today, but the escape ensures any
// future marker edit cannot break the script.
func awkStringEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\'':
			// Close single quote, emit an escaped single quote, reopen.
			b.WriteString(`'\''`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
