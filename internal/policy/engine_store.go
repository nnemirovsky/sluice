package policy

import (
	"fmt"

	"github.com/nemirovsky/sluice/internal/store"
)

// LoadFromStore builds a read-only Engine from a SQLite store. Network rules,
// tool rules, inspect rules, and config values are all read from the database.
// The returned Engine is compiled and ready for evaluation.
func LoadFromStore(s *store.Store) (*Engine, error) {
	cfg, err := s.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	defaultVerdict := Deny
	switch cfg.DefaultVerdict {
	case "allow":
		defaultVerdict = Allow
	case "deny":
		defaultVerdict = Deny
	case "ask":
		defaultVerdict = Ask
	case "":
		// Use default (Deny)
	default:
		return nil, fmt.Errorf("unknown default verdict: %q", cfg.DefaultVerdict)
	}

	timeout := cfg.TimeoutSec
	if timeout == 0 {
		timeout = 120
	}

	// Read network rules (destination set).
	allowRules, err := loadNetworkRules(s, "allow")
	if err != nil {
		return nil, err
	}
	denyRules, err := loadNetworkRules(s, "deny")
	if err != nil {
		return nil, err
	}
	askRules, err := loadNetworkRules(s, "ask")
	if err != nil {
		return nil, err
	}

	// Read tool rules (tool set).
	toolAllow, err := loadToolRulesFromStore(s, "allow")
	if err != nil {
		return nil, err
	}
	toolDeny, err := loadToolRulesFromStore(s, "deny")
	if err != nil {
		return nil, err
	}
	toolAsk, err := loadToolRulesFromStore(s, "ask")
	if err != nil {
		return nil, err
	}

	// Read inspect block rules (pattern set, verdict=deny).
	blockRules, err := loadInspectBlockFromStore(s)
	if err != nil {
		return nil, err
	}

	// Read inspect redact rules (pattern set, verdict=redact).
	redactRules, err := loadInspectRedactFromStore(s)
	if err != nil {
		return nil, err
	}

	eng := &Engine{
		Default:            defaultVerdict,
		AllowRules:         allowRules,
		DenyRules:          denyRules,
		AskRules:           askRules,
		ToolAllowRules:     toolAllow,
		ToolDenyRules:      toolDeny,
		ToolAskRules:       toolAsk,
		InspectBlockRules:  blockRules,
		InspectRedactRules: redactRules,
		TimeoutSec:         timeout,
	}
	if err := eng.compile(); err != nil {
		return nil, fmt.Errorf("compile policy rules: %w", err)
	}
	return eng, nil
}

func loadNetworkRules(s *store.Store, verdict string) ([]Rule, error) {
	rows, err := s.ListRules(store.RuleFilter{Verdict: verdict, Type: "network"})
	if err != nil {
		return nil, fmt.Errorf("list %s rules: %w", verdict, err)
	}
	rules := make([]Rule, len(rows))
	for i, r := range rows {
		rules[i] = Rule{
			Destination: r.Destination,
			Ports:       r.Ports,
			Protocols:   r.Protocols,
			Name:        r.Name,
		}
	}
	return rules, nil
}

func loadToolRulesFromStore(s *store.Store, verdict string) ([]ToolRule, error) {
	rows, err := s.ListRules(store.RuleFilter{Verdict: verdict, Type: "tool"})
	if err != nil {
		return nil, fmt.Errorf("list tool_%s rules: %w", verdict, err)
	}
	rules := make([]ToolRule, len(rows))
	for i, r := range rows {
		rules[i] = ToolRule{
			Tool:    r.Tool,
			Verdict: verdict,
			Note:    r.Name,
		}
	}
	return rules, nil
}

func loadInspectBlockFromStore(s *store.Store) ([]InspectBlockRule, error) {
	rows, err := s.ListRules(store.RuleFilter{Verdict: "deny", Type: "pattern"})
	if err != nil {
		return nil, fmt.Errorf("list inspect_block rules: %w", err)
	}
	rules := make([]InspectBlockRule, len(rows))
	for i, r := range rows {
		rules[i] = InspectBlockRule{
			Pattern: r.Pattern,
			Name:    r.Name,
		}
	}
	return rules, nil
}

func loadInspectRedactFromStore(s *store.Store) ([]InspectRedactRule, error) {
	rows, err := s.ListRules(store.RuleFilter{Verdict: "redact", Type: "pattern"})
	if err != nil {
		return nil, fmt.Errorf("list inspect_redact rules: %w", err)
	}
	rules := make([]InspectRedactRule, len(rows))
	for i, r := range rows {
		rules[i] = InspectRedactRule{
			Pattern:     r.Pattern,
			Replacement: r.Replacement,
			Name:        r.Name,
		}
	}
	return rules, nil
}
