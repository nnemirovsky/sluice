// Package policy provides policy evaluation for network connections and MCP
// tool calls. Rules are compiled from glob patterns and evaluated in
// deny-then-allow-then-ask priority order. Runtime state is stored in SQLite
// via the store package. TOML parsing is retained for test convenience.
package policy

// Verdict represents the policy decision for a connection request.
type Verdict int

// Policy verdicts.
const (
	Allow Verdict = iota
	Deny
	Ask
	Redact
)

func (v Verdict) String() string {
	switch v {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	case Ask:
		return "ask"
	case Redact:
		return "redact"
	default:
		return "unknown"
	}
}

// Rule represents a single policy rule. For network rules, Destination is set.
// For tool rules, Tool is set. For content inspect rules, Pattern is set.
// The fields are mutually exclusive in the unified schema.
type Rule struct {
	Destination string   `toml:"destination"`
	Tool        string   `toml:"tool"`
	Pattern     string   `toml:"pattern"`
	Replacement string   `toml:"replacement"`
	Ports       []int    `toml:"ports"`
	Protocols   []string `toml:"protocols"`
	Name        string   `toml:"name"`
}

// PolicyConfig holds top-level policy settings.
type PolicyConfig struct { //nolint:revive // stuttering accepted for clarity
	Default string `toml:"default"`
	Timeout int    `toml:"timeout_sec"`
}

// ToolRule defines a single tool-level policy rule for MCP gateway.
type ToolRule struct {
	Tool    string `toml:"tool"`
	Verdict string `toml:"verdict"`
	Name    string `toml:"name"`
}

// InspectBlockRule defines a pattern that blocks tool arguments when matched.
type InspectBlockRule struct {
	Pattern string `toml:"pattern"`
	Name    string `toml:"name"`
}

// InspectRedactRule defines a pattern that redacts matched content in tool responses.
type InspectRedactRule struct {
	Pattern     string `toml:"pattern"`
	Replacement string `toml:"replacement"`
	Name        string `toml:"name"`
}

type policyFile struct {
	Policy PolicyConfig `toml:"policy"`
	Allow  []Rule       `toml:"allow"`
	Deny   []Rule       `toml:"deny"`
	Ask    []Rule       `toml:"ask"`
	Redact []Rule       `toml:"redact"`
}
