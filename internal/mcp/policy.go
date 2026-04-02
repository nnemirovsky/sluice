package mcp

import (
	"fmt"
	"log"
	"sync"

	"github.com/nemirovsky/sluice/internal/policy"
)

type compiledToolRule struct {
	glob    *policy.Glob
	verdict policy.Verdict
}

// ToolPolicy evaluates tool names against glob-based rules.
type ToolPolicy struct {
	mu       sync.RWMutex
	rules    []compiledToolRule
	fallback policy.Verdict
}

// NewToolPolicy compiles tool rules and returns a ToolPolicy.
// Returns an error if any rule has an invalid glob pattern or unknown verdict.
func NewToolPolicy(rules []policy.ToolRule, fallback policy.Verdict) (*ToolPolicy, error) {
	compiled := make([]compiledToolRule, 0, len(rules))
	for _, r := range rules {
		g, err := policy.CompileGlob(r.Tool)
		if err != nil {
			return nil, fmt.Errorf("compile tool rule %q: %w", r.Tool, err)
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
			return nil, fmt.Errorf("tool rule %q: unknown verdict %q", r.Tool, r.Verdict)
		}
		compiled = append(compiled, compiledToolRule{glob: g, verdict: v})
	}
	return &ToolPolicy{rules: compiled, fallback: fallback}, nil
}

// AddDynamicAllow appends a runtime allow rule for the given tool name.
// The rule is not persisted to disk.
func (tp *ToolPolicy) AddDynamicAllow(toolName string) {
	g, err := policy.CompileGlob(toolName)
	if err != nil {
		log.Printf("[MCP POLICY] failed to add dynamic allow for %q: %v", toolName, err)
		return
	}
	tp.mu.Lock()
	// Copy-on-write: create a new backing array so that concurrent readers
	// iterating the old slice are not affected by this append.
	newRules := make([]compiledToolRule, len(tp.rules)+1)
	copy(newRules, tp.rules)
	newRules[len(tp.rules)] = compiledToolRule{glob: g, verdict: policy.Allow}
	tp.rules = newRules
	tp.mu.Unlock()
}

// Evaluate checks the tool name against rules in priority order: deny, allow, ask.
func (tp *ToolPolicy) Evaluate(toolName string) policy.Verdict {
	tp.mu.RLock()
	rules := tp.rules
	tp.mu.RUnlock()

	for _, r := range rules {
		if r.verdict == policy.Deny && r.glob.Match(toolName) {
			return policy.Deny
		}
	}
	for _, r := range rules {
		if r.verdict == policy.Allow && r.glob.Match(toolName) {
			return policy.Allow
		}
	}
	for _, r := range rules {
		if r.verdict == policy.Ask && r.glob.Match(toolName) {
			return policy.Ask
		}
	}
	return tp.fallback
}
