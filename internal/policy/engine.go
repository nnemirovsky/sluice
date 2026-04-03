package policy

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
)

type compiledRule struct {
	glob      *Glob
	ports     map[int]bool
	protocols map[string]bool
}

// portToProtocol maps well-known ports to protocol names for protocol-scoped
// rule matching. Returns "" for non-standard ports where the protocol is
// ambiguous.
func portToProtocol(port int) string {
	switch port {
	case 80, 8080:
		return "http"
	case 443, 8443:
		return "https"
	case 22:
		return "ssh"
	case 143, 993:
		return "imap"
	case 25, 587, 465:
		return "smtp"
	default:
		return ""
	}
}

type compiledEngine struct {
	allowRules []compiledRule
	denyRules  []compiledRule
	askRules   []compiledRule
}

// Engine holds the parsed policy rules and provides evaluation.
type Engine struct {
	mu                 sync.RWMutex
	Default            Verdict
	AllowRules         []Rule
	DenyRules          []Rule
	AskRules           []Rule
	ToolAllowRules     []ToolRule
	ToolDenyRules      []ToolRule
	ToolAskRules       []ToolRule
	InspectBlockRules  []InspectBlockRule
	InspectRedactRules []InspectRedactRule
	TimeoutSec         int
	compiled           *compiledEngine
}

// LoadFromBytes parses policy from raw TOML bytes. Used by tests that
// construct policy inline. Runtime code should use LoadFromStore instead.
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

	// Separate unified rules by type based on which field is set.
	var allowRules, denyRules, askRules []Rule
	var toolAllow, toolDeny, toolAsk []ToolRule
	var inspectBlock []InspectBlockRule
	var inspectRedact []InspectRedactRule

	var dispatchErr error
	dispatchRules := func(rules []Rule, verdict string) {
		for _, r := range rules {
			switch {
			case r.Tool != "":
				tr := ToolRule{Tool: r.Tool, Verdict: verdict, Note: r.Name}
				switch verdict {
				case "allow":
					toolAllow = append(toolAllow, tr)
				case "deny":
					toolDeny = append(toolDeny, tr)
				case "ask":
					toolAsk = append(toolAsk, tr)
				}
			case r.Pattern != "":
				if verdict == "deny" {
					inspectBlock = append(inspectBlock, InspectBlockRule{
						Pattern: r.Pattern,
						Name:    r.Name,
					})
				} else {
					dispatchErr = fmt.Errorf("pattern rules only support deny verdict in [[deny]] sections, got [[%s]] with pattern %q", verdict, r.Pattern)
					return
				}
			default:
				// Network rule (destination set or empty for validation).
				switch verdict {
				case "allow":
					allowRules = append(allowRules, r)
				case "deny":
					denyRules = append(denyRules, r)
				case "ask":
					askRules = append(askRules, r)
				}
			}
		}
	}

	dispatchRules(pf.Allow, "allow")
	dispatchRules(pf.Deny, "deny")
	dispatchRules(pf.Ask, "ask")
	if dispatchErr != nil {
		return nil, dispatchErr
	}

	// [[redact]] entries are always pattern-based content redact rules.
	for _, r := range pf.Redact {
		if r.Destination != "" {
			return nil, fmt.Errorf("[[redact]] rule %q: destination and pattern are mutually exclusive", r.Name)
		}
		if r.Tool != "" {
			return nil, fmt.Errorf("[[redact]] rule %q: tool and pattern are mutually exclusive", r.Name)
		}
		inspectRedact = append(inspectRedact, InspectRedactRule{
			Pattern:     r.Pattern,
			Replacement: r.Replacement,
			Name:        r.Name,
		})
	}

	eng := &Engine{
		Default:            defaultVerdict,
		AllowRules:         allowRules,
		DenyRules:          denyRules,
		AskRules:           askRules,
		ToolAllowRules:     toolAllow,
		ToolDenyRules:      toolDeny,
		ToolAskRules:       toolAsk,
		InspectBlockRules:  inspectBlock,
		InspectRedactRules: inspectRedact,
		TimeoutSec:         timeout,
	}
	if err := eng.compile(); err != nil {
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
		protocols := make(map[string]bool, len(r.Protocols))
		for _, p := range r.Protocols {
			protocols[p] = true
		}
		out = append(out, compiledRule{glob: g, ports: ports, protocols: protocols})
	}
	return out, nil
}

// compile compiles all glob patterns in the policy rules for fast matching.
// On failure the existing compiled state is preserved.
//
// Callers must hold e.mu (write lock) when the engine is shared. The only
// exception is LoadFromBytes which calls compile before the engine is returned.
func (e *Engine) compile() error {
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
		if len(r.ports) > 0 && !r.ports[port] {
			continue
		}
		if len(r.protocols) > 0 {
			proto := portToProtocol(port)
			if proto == "" || !r.protocols[proto] {
				continue
			}
		}
		return true
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
// DNS leaks for definitely-denied hosts.
//
// When includeAsk is true, Ask rules are treated as potentially-allowed
// (DNS resolution is needed so the approval flow can proceed). When false,
// Ask rules are ignored and default=Ask is treated as Deny. Pass false when
// no approval broker is configured to prevent DNS leaks for Ask-only matches.
func (e *Engine) CouldBeAllowed(dest string, includeAsk bool) bool {
	dest = normalizeDestination(dest)
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.compiled == nil {
		if includeAsk {
			return e.Default == Allow || e.Default == Ask
		}
		return e.Default == Allow
	}

	// A portless, protocol-less deny rule denies all traffic and takes
	// precedence over allow/ask rules in Evaluate, so the destination
	// cannot be allowed. Protocol-scoped deny rules (e.g. protocols=["ssh"])
	// only deny that protocol, so DNS must still be resolved for other
	// protocols to work.
	for _, r := range e.compiled.denyRules {
		if len(r.ports) == 0 && len(r.protocols) == 0 && r.glob.Match(dest) {
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

	// Ask rules need DNS resolution so the approval flow can work,
	// but only when an approval broker is available.
	if includeAsk {
		for _, r := range e.compiled.askRules {
			if r.glob.Match(dest) {
				return true
			}
		}
	}

	// No explicit allow (or ask) match: check the default verdict.
	if includeAsk {
		return e.Default == Allow || e.Default == Ask
	}
	return e.Default == Allow
}

// AddDynamicAllow appends a new allow rule for the given destination and port,
// then recompiles the engine so the rule takes effect immediately. On compile
// failure the rule is rolled back and the engine state is unchanged.
//
// Deprecated: Mutations should go through the SQLite store, then recompile
// via LoadFromStore. Retained for backward compatibility during migration.
func (e *Engine) AddDynamicAllow(dest string, port int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	rule := Rule{Destination: dest, Ports: []int{port}}
	e.AllowRules = append(e.AllowRules, rule)
	if err := e.compile(); err != nil {
		e.AllowRules = e.AllowRules[:len(e.AllowRules)-1]
		return err
	}
	return nil
}

// AddAllowRule appends a portless allow rule and recompiles.
// On failure the rule is rolled back.
//
// Deprecated: Mutations should go through the SQLite store. Retained for
// backward compatibility during migration.
func (e *Engine) AddAllowRule(dest string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	rule := Rule{Destination: dest}
	e.AllowRules = append(e.AllowRules, rule)
	if err := e.compile(); err != nil {
		e.AllowRules = e.AllowRules[:len(e.AllowRules)-1]
		return err
	}
	return nil
}

// AddDenyRule appends a portless deny rule and recompiles.
// On failure the rule is rolled back.
//
// Deprecated: Mutations should go through the SQLite store. Retained for
// backward compatibility during migration.
func (e *Engine) AddDenyRule(dest string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	rule := Rule{Destination: dest}
	e.DenyRules = append(e.DenyRules, rule)
	if err := e.compile(); err != nil {
		e.DenyRules = e.DenyRules[:len(e.DenyRules)-1]
		return err
	}
	return nil
}

// RemoveRule removes the first rule matching dest from any rule list and recompiles.
// On compile failure the removal is rolled back. Returns true if a rule was found and removed.
//
// Deprecated: Mutations should go through the SQLite store. Retained for
// backward compatibility during migration.
func (e *Engine) RemoveRule(dest string) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Deep-copy originals for rollback. removeRuleFromSlice uses append
	// which mutates the backing array in-place, so a simple slice header
	// copy would share the corrupted array on rollback.
	origAllow := append([]Rule(nil), e.AllowRules...)
	origDeny := append([]Rule(nil), e.DenyRules...)
	origAsk := append([]Rule(nil), e.AskRules...)

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
	if err := e.compile(); err != nil {
		e.AllowRules = origAllow
		e.DenyRules = origDeny
		e.AskRules = origAsk
		return true, err
	}
	return true, nil
}

func removeRuleFromSlice(rules []Rule, dest string) ([]Rule, bool) {
	dest = strings.ToLower(normalizeDestination(dest))
	for i, r := range rules {
		if strings.ToLower(normalizeDestination(r.Destination)) == dest {
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

// ToolRules returns all tool-level policy rules combined from allow, deny, and ask sections.
func (e *Engine) ToolRules() []ToolRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var rules []ToolRule
	rules = append(rules, e.ToolAllowRules...)
	rules = append(rules, e.ToolDenyRules...)
	rules = append(rules, e.ToolAskRules...)
	return rules
}

// Validate performs a smoke-test to catch nil or inconsistent engine state.
// Call this on a newly loaded engine before swapping it into the live pointer
// to avoid storing a broken engine that would panic on first evaluation.
func (e *Engine) Validate() error {
	if e == nil {
		return fmt.Errorf("engine is nil")
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.compiled == nil {
		return fmt.Errorf("engine has no compiled rules")
	}
	return nil
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
