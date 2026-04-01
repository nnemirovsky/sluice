package policy

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type compiledRule struct {
	glob  *Glob
	ports map[int]bool
}

type compiledEngine struct {
	allowRules []compiledRule
	denyRules  []compiledRule
	askRules   []compiledRule
}

// Engine holds the parsed policy rules and provides evaluation.
type Engine struct {
	Default    Verdict
	AllowRules []Rule
	DenyRules  []Rule
	AskRules   []Rule
	TimeoutSec int
	compiled   *compiledEngine
}

// LoadFromFile reads and parses a policy TOML file.
func LoadFromFile(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	return LoadFromBytes(data)
}

// LoadFromBytes parses policy from raw TOML bytes.
func LoadFromBytes(data []byte) (*Engine, error) {
	var pf policyFile
	if err := toml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse policy TOML: %w", err)
	}

	defaultVerdict := Deny
	switch pf.Policy.Default {
	case "allow":
		defaultVerdict = Allow
	case "deny":
		defaultVerdict = Deny
	case "ask":
		defaultVerdict = Ask
	default:
		if pf.Policy.Default != "" {
			return nil, fmt.Errorf("unknown default verdict: %q", pf.Policy.Default)
		}
	}

	timeout := pf.Policy.Timeout
	if timeout == 0 {
		timeout = 120
	}

	eng := &Engine{
		Default:    defaultVerdict,
		AllowRules: pf.Allow,
		DenyRules:  pf.Deny,
		AskRules:   pf.Ask,
		TimeoutSec: timeout,
	}
	if err := eng.Compile(); err != nil {
		return nil, fmt.Errorf("compile policy rules: %w", err)
	}
	return eng, nil
}

func compileRules(rules []Rule) ([]compiledRule, error) {
	out := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		g, err := CompileGlob(r.Destination)
		if err != nil {
			return nil, fmt.Errorf("compile rule %q: %w", r.Destination, err)
		}
		ports := make(map[int]bool, len(r.Ports))
		for _, p := range r.Ports {
			ports[p] = true
		}
		out = append(out, compiledRule{glob: g, ports: ports})
	}
	return out, nil
}

// Compile compiles all glob patterns in the policy rules for fast matching.
func (e *Engine) Compile() error {
	var err error
	e.compiled = &compiledEngine{}
	e.compiled.allowRules, err = compileRules(e.AllowRules)
	if err != nil {
		return err
	}
	e.compiled.denyRules, err = compileRules(e.DenyRules)
	if err != nil {
		return err
	}
	e.compiled.askRules, err = compileRules(e.AskRules)
	if err != nil {
		return err
	}
	return nil
}

func matchRules(rules []compiledRule, dest string, port int) bool {
	for _, r := range rules {
		if !r.glob.Match(dest) {
			continue
		}
		if len(r.ports) == 0 || r.ports[port] {
			return true
		}
	}
	return false
}

// Evaluate checks a destination and port against the compiled policy rules.
// Deny rules are checked first, then allow, then ask. Falls back to default.
func (e *Engine) Evaluate(dest string, port int) Verdict {
	if matchRules(e.compiled.denyRules, dest, port) {
		return Deny
	}
	if matchRules(e.compiled.allowRules, dest, port) {
		return Allow
	}
	if matchRules(e.compiled.askRules, dest, port) {
		return Ask
	}
	return e.Default
}
