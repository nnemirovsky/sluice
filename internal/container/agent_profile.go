package container

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// AgentProfile abstracts agent-specific runtime conventions so that sluice
// can manage credential and MCP wiring for more than one agent. Each agent
// stores its env file in a different location, has a different mechanism
// for picking up secret changes, and registers MCP servers in a different
// config format. A profile captures all three so that the container
// managers (Docker, Apple Container, tart) stay agent-agnostic.
type AgentProfile struct {
	// Name is the human-readable profile identifier (e.g. "openclaw").
	Name string

	// EnvFileRelPath is the path to the agent's secret env file relative
	// to the in-container HOME directory (e.g. ".openclaw/.env").
	EnvFileRelPath string

	// ReloadCmd returns the argv to exec inside the agent container in
	// order to make a freshly-written env file take effect. Returning nil
	// means the profile has no in-place reload mechanism; the caller
	// should log a notice and rely on the next agent run / container
	// restart picking up the new values.
	ReloadCmd func() []string

	// WireMCPCmd returns the argv to exec for registering sluice's MCP
	// gateway URL inside the agent's config. It is invoked once per
	// sluice startup. Returning nil means the profile cannot patch
	// config in place and the operator must wire the MCP gateway
	// manually before starting the agent.
	WireMCPCmd func(name, url string) []string
}

// OpenclawProfile is the default profile. Openclaw stores secrets at
// ~/.openclaw/.env and exposes a JSON-RPC gateway (over WebSocket) for
// reloading secrets and patching config. The embedded gateway_rpc.js
// script handles the device-signed handshake.
var OpenclawProfile = &AgentProfile{
	Name:           "openclaw",
	EnvFileRelPath: ".openclaw/.env",
	ReloadCmd: func() []string {
		return GatewayRPCNodeCommand("secrets.reload")
	},
	WireMCPCmd: func(name, url string) []string {
		return GatewayRPCNodeCommand("wire-mcp", name, url)
	},
}

// hermesMCPWireScript is a small Python script that registers an MCP
// server inside ~/.hermes/config.yaml under the mcp_servers key. Hermes
// reads MCP servers from this file at startup and on the /reload-mcp
// slash command. We rely on PyYAML being available because Hermes itself
// is a Python application that ships with PyYAML as a hard dependency.
//
// The script is idempotent: if mcp_servers.<name>.url already matches,
// the file is not rewritten.
const hermesMCPWireScript = `
import os, sys, yaml
name, url = sys.argv[1], sys.argv[2]
cfg_path = os.path.expanduser("~/.hermes/config.yaml")
os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
data = {}
if os.path.exists(cfg_path):
    with open(cfg_path) as fh:
        data = yaml.safe_load(fh) or {}
servers = data.setdefault("mcp_servers", {})
existing = servers.get(name) or {}
if existing.get("url") == url:
    sys.exit(0)
existing["url"] = url
servers[name] = existing
with open(cfg_path, "w") as fh:
    yaml.safe_dump(data, fh, sort_keys=False)
`

// HermesProfile targets nousresearch/hermes-agent. Hermes stores secrets
// at ~/.hermes/.env and MCP servers under mcp_servers in
// ~/.hermes/config.yaml. There is no documented in-process reload for
// .env, so ReloadCmd is nil and callers fall back to logging a notice;
// new credentials take effect on the next agent message.
//
// MCP wiring patches config.yaml directly. Hermes picks up the change on
// startup or via the /reload-mcp slash command (which the operator must
// invoke from the agent UI; sluice cannot trigger it remotely).
var HermesProfile = &AgentProfile{
	Name:           "hermes",
	EnvFileRelPath: ".hermes/.env",
	ReloadCmd:      nil,
	WireMCPCmd: func(name, url string) []string {
		return []string{"python3", "-c", hermesMCPWireScript, name, url}
	},
}

// builtinProfiles is the registry consulted by ProfileFromName.
var builtinProfiles = map[string]*AgentProfile{
	"openclaw": OpenclawProfile,
	"hermes":   HermesProfile,
}

// ProfileFromName returns the built-in profile matching name, or an
// error listing the known profiles.
func ProfileFromName(name string) (*AgentProfile, error) {
	if p, ok := builtinProfiles[name]; ok {
		return p, nil
	}
	known := make([]string, 0, len(builtinProfiles))
	for k := range builtinProfiles {
		known = append(known, k)
	}
	sort.Strings(known)
	return nil, fmt.Errorf("unknown agent profile %q (known: %s)", name, strings.Join(known, ", "))
}

// validateEnvFileRelPath ensures the env file path declared by an
// AgentProfile is safe to interpolate into a shell snippet inside
// double quotes. The path must be relative (no leading "/"), must
// not contain ".." segments, and must not contain shell metacharacters
// or whitespace that would let a maliciously constructed profile run
// arbitrary commands when BuildEnvInjectionScriptForProfile is called.
//
// All built-in profiles in this package are constants and pass this
// check trivially. The validation exists to keep the surface safe if
// a future caller in this internal package constructs an AgentProfile
// dynamically.
func validateEnvFileRelPath(p string) error {
	if p == "" {
		return fmt.Errorf("EnvFileRelPath is empty")
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("EnvFileRelPath %q must be relative (not absolute)", p)
	}
	cleaned := path.Clean(p)
	if cleaned != p {
		return fmt.Errorf("EnvFileRelPath %q is not in canonical form (got %q)", p, cleaned)
	}
	if strings.HasPrefix(cleaned, "../") || cleaned == ".." || strings.Contains(cleaned, "/../") {
		return fmt.Errorf("EnvFileRelPath %q must not traverse parent directories", p)
	}
	for _, r := range p {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '/' || r == '.' || r == '_' || r == '-':
		default:
			return fmt.Errorf("EnvFileRelPath %q contains disallowed character %q", p, r)
		}
	}
	return nil
}

// resolveProfile returns p when non-nil, or OpenclawProfile as the
// default. This lets existing call sites that do not pass a profile
// keep their previous behavior.
func resolveProfile(p *AgentProfile) *AgentProfile {
	if p == nil {
		return OpenclawProfile
	}
	return p
}
