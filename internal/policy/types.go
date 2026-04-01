package policy

// Verdict represents the policy decision for a connection request.
type Verdict int

const (
	Allow Verdict = iota
	Deny
	Ask
)

func (v Verdict) String() string {
	switch v {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	case Ask:
		return "ask"
	default:
		return "unknown"
	}
}

// Rule represents a single policy rule matching a destination pattern and optional port list.
type Rule struct {
	Destination string `toml:"destination"`
	Ports       []int  `toml:"ports"`
}

// PolicyConfig holds top-level policy settings.
type PolicyConfig struct {
	Default string `toml:"default"`
	Timeout int    `toml:"timeout_sec"`
}

type policyFile struct {
	Policy PolicyConfig `toml:"policy"`
	Allow  []Rule       `toml:"allow"`
	Deny   []Rule       `toml:"deny"`
	Ask    []Rule       `toml:"ask"`
}
