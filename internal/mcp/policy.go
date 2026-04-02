package mcp

import (
	"github.com/nemirovsky/sluice/internal/policy"
)

// ToolRule defines a single tool-level policy rule from TOML config.
type ToolRule struct {
	Tool    string `toml:"tool"`
	Verdict string `toml:"verdict"`
	Note    string `toml:"note"`
}

type compiledToolRule struct {
	glob    *policy.Glob
	verdict policy.Verdict
}

// ToolPolicy evaluates tool names against glob-based rules.
type ToolPolicy struct {
	rules    []compiledToolRule
	fallback policy.Verdict
}

// NewToolPolicy compiles tool rules and returns a ToolPolicy.
// Rules with invalid globs or unknown verdicts are silently skipped.
func NewToolPolicy(rules []ToolRule, fallback policy.Verdict) *ToolPolicy {
	compiled := make([]compiledToolRule, 0, len(rules))
	for _, r := range rules {
		g, err := policy.CompileGlob(r.Tool)
		if err != nil {
			continue
		}
		var v policy.Verdict
		switch r.Verdict {
		case "allow":
			v = policy.Allow
		case "deny":
			v = policy.Deny
		case "ask":
			v = policy.Ask
		default:
			continue
		}
		compiled = append(compiled, compiledToolRule{glob: g, verdict: v})
	}
	return &ToolPolicy{rules: compiled, fallback: fallback}
}

// Evaluate checks the tool name against rules in priority order: deny, allow, ask.
func (tp *ToolPolicy) Evaluate(toolName string) policy.Verdict {
	for _, r := range tp.rules {
		if r.verdict == policy.Deny && r.glob.Match(toolName) {
			return policy.Deny
		}
	}
	for _, r := range tp.rules {
		if r.verdict == policy.Allow && r.glob.Match(toolName) {
			return policy.Allow
		}
	}
	for _, r := range tp.rules {
		if r.verdict == policy.Ask && r.glob.Match(toolName) {
			return policy.Ask
		}
	}
	return tp.fallback
}
