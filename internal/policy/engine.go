package policy

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

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
	mu         sync.RWMutex
	Default    Verdict
	AllowRules []Rule
	DenyRules  []Rule
	AskRules   []Rule
	TimeoutSec int
	Telegram   TelegramConfig
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
		Telegram:   pf.Telegram,
	}
	if err := eng.Compile(); err != nil {
		return nil, fmt.Errorf("compile policy rules: %w", err)
	}
	return eng, nil
}

// normalizeDestination normalizes a runtime destination to the canonical form
// used by compiled rules: trailing dots are stripped and IPv6 addresses are
// compressed. This ensures callers of the public Engine API get consistent
// results regardless of whether the destination has a trailing dot or uses
// an expanded IPv6 form.
func normalizeDestination(dest string) string {
	dest = strings.TrimRight(dest, ".")
	if ip := net.ParseIP(dest); ip != nil {
		return ip.String()
	}
	return dest
}

// canonicalizeDestination normalizes a rule destination so it matches the
// canonical form used at runtime: trailing dots are stripped (DNS FQDN
// normalization) and IPv6 addresses are compressed (net.IP.String() form).
func canonicalizeDestination(dest string) string {
	normalized := normalizeDestination(dest)
	// Guard: do not let trailing-dot removal reduce a glob pattern to a
	// bare wildcard. "*." means single-label-then-dot in glob syntax;
	// reducing it to "*" makes CompileGlob treat it as match-all, silently
	// widening the rule scope. Keep the original so the rule compiles
	// harmlessly (won't match dot-free runtime destinations).
	if normalized != dest && (normalized == "*" || normalized == "**") {
		return dest
	}
	return normalized
}

func compileRules(rules []Rule) ([]compiledRule, error) {
	out := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		if r.Destination == "" {
			return nil, fmt.Errorf("rule has empty destination")
		}
		dest := canonicalizeDestination(r.Destination)
		g, err := CompileGlob(dest)
		if err != nil {
			return nil, fmt.Errorf("compile rule %q: %w", r.Destination, err)
		}
		ports := make(map[int]bool, len(r.Ports))
		for _, p := range r.Ports {
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("rule %q: invalid port %d (must be 1-65535)", r.Destination, p)
			}
			ports[p] = true
		}
		out = append(out, compiledRule{glob: g, ports: ports})
	}
	return out, nil
}

// Compile compiles all glob patterns in the policy rules for fast matching.
// On failure the existing compiled state is preserved.
func (e *Engine) Compile() error {
	ce := &compiledEngine{}
	var err error
	ce.allowRules, err = compileRules(e.AllowRules)
	if err != nil {
		return err
	}
	ce.denyRules, err = compileRules(e.DenyRules)
	if err != nil {
		return err
	}
	ce.askRules, err = compileRules(e.AskRules)
	if err != nil {
		return err
	}
	e.compiled = ce
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

// IsDenied checks whether a destination and port match any explicit deny rule.
// Unlike Evaluate, this does not fall back to the default verdict.
func (e *Engine) IsDenied(dest string, port int) bool {
	dest = normalizeDestination(dest)
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.compiled == nil {
		return false
	}
	return matchRules(e.compiled.denyRules, dest, port)
}

// IsRestricted checks whether a destination and port match any explicit deny
// or ask rule. Unlike Evaluate, this does not fall back to the default verdict.
// Used for DNS rebinding checks where the original FQDN was already allowed
// and we need to verify the resolved IP is not explicitly restricted.
func (e *Engine) IsRestricted(dest string, port int) bool {
	dest = normalizeDestination(dest)
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.compiled == nil {
		return false
	}
	return matchRules(e.compiled.denyRules, dest, port) ||
		matchRules(e.compiled.askRules, dest, port)
}

// IsExplicitlyAllowed checks whether a destination and port match any explicit
// allow rule. Unlike Evaluate, this does not fall back to the default verdict.
// Used for DNS rebinding checks where we need to know if a resolved private IP
// is independently allowed by policy.
func (e *Engine) IsExplicitlyAllowed(dest string, port int) bool {
	dest = normalizeDestination(dest)
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.compiled == nil {
		return false
	}
	return matchRules(e.compiled.allowRules, dest, port)
}

// CouldBeAllowed reports whether a destination could be allowed on any port.
// Used by the resolver to decide whether to perform DNS resolution. Returns
// false only when certain the destination is denied on all ports, preventing
// DNS leaks for definitely-denied hosts. Ask rules require DNS resolution so
// the approval flow can proceed.
func (e *Engine) CouldBeAllowed(dest string) bool {
	dest = normalizeDestination(dest)
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.compiled == nil {
		return e.Default == Allow || e.Default == Ask
	}

	// A portless deny rule denies all ports and takes precedence over
	// allow/ask rules in Evaluate, so the destination cannot be allowed.
	for _, r := range e.compiled.denyRules {
		if len(r.ports) == 0 && r.glob.Match(dest) {
			return false
		}
	}

	// If any allow rule matches (ignoring ports), the destination
	// might be allowed on some port.
	for _, r := range e.compiled.allowRules {
		if r.glob.Match(dest) {
			return true
		}
	}

	// Ask rules need DNS resolution so the approval flow can work.
	for _, r := range e.compiled.askRules {
		if r.glob.Match(dest) {
			return true
		}
	}

	// No explicit allow or ask match: only default=allow or default=ask
	// permits the destination.
	return e.Default == Allow || e.Default == Ask
}

// AddDynamicAllow appends a new allow rule for the given destination and port,
// then recompiles the engine so the rule takes effect immediately. On compile
// failure the rule is rolled back and the engine state is unchanged.
func (e *Engine) AddDynamicAllow(dest string, port int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	rule := Rule{Destination: dest, Ports: []int{port}}
	e.AllowRules = append(e.AllowRules, rule)
	if err := e.Compile(); err != nil {
		e.AllowRules = e.AllowRules[:len(e.AllowRules)-1]
		return err
	}
	return nil
}

// AddAllowRule appends a portless allow rule and recompiles.
// On failure the rule is rolled back.
func (e *Engine) AddAllowRule(dest string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	rule := Rule{Destination: dest}
	e.AllowRules = append(e.AllowRules, rule)
	if err := e.Compile(); err != nil {
		e.AllowRules = e.AllowRules[:len(e.AllowRules)-1]
		return err
	}
	return nil
}

// AddDenyRule appends a portless deny rule and recompiles.
// On failure the rule is rolled back.
func (e *Engine) AddDenyRule(dest string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	rule := Rule{Destination: dest}
	e.DenyRules = append(e.DenyRules, rule)
	if err := e.Compile(); err != nil {
		e.DenyRules = e.DenyRules[:len(e.DenyRules)-1]
		return err
	}
	return nil
}

// RemoveRule removes the first rule matching dest from any rule list and recompiles.
// Returns true if a rule was found and removed.
func (e *Engine) RemoveRule(dest string) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var removed bool
	e.AllowRules, removed = removeRuleFromSlice(e.AllowRules, dest)
	if !removed {
		e.DenyRules, removed = removeRuleFromSlice(e.DenyRules, dest)
	}
	if !removed {
		e.AskRules, removed = removeRuleFromSlice(e.AskRules, dest)
	}
	if !removed {
		return false, nil
	}
	if err := e.Compile(); err != nil {
		return true, err
	}
	return true, nil
}

func removeRuleFromSlice(rules []Rule, dest string) ([]Rule, bool) {
	for i, r := range rules {
		if r.Destination == dest {
			return append(rules[:i], rules[i+1:]...), true
		}
	}
	return rules, false
}

// RulesSnapshot returns a thread-safe copy of the current rules and default verdict.
type RulesSnapshot struct {
	Default    Verdict
	AllowRules []Rule
	DenyRules  []Rule
	AskRules   []Rule
}

// Snapshot returns a thread-safe copy of the current rules and default verdict.
func (e *Engine) Snapshot() RulesSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return RulesSnapshot{
		Default:    e.Default,
		AllowRules: append([]Rule(nil), e.AllowRules...),
		DenyRules:  append([]Rule(nil), e.DenyRules...),
		AskRules:   append([]Rule(nil), e.AskRules...),
	}
}

// Evaluate checks a destination and port against the compiled policy rules.
// Deny rules are checked first, then allow, then ask. Falls back to default.
func (e *Engine) Evaluate(dest string, port int) Verdict {
	dest = normalizeDestination(dest)
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.compiled == nil {
		return e.Default
	}
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
