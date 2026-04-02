package policy

import (
	"fmt"
	"strconv"

	"github.com/nemirovsky/sluice/internal/store"
)

// LoadFromStore builds a read-only Engine from a SQLite store. Network rules,
// tool rules, inspect rules, and config values are all read from the database.
// The returned Engine is compiled and ready for evaluation.
func LoadFromStore(s *store.Store) (*Engine, error) {
	// Read default verdict.
	defaultVerdict := Deny
	if dv, err := s.GetConfig("default_verdict"); err != nil {
		return nil, fmt.Errorf("read default_verdict: %w", err)
	} else if dv != "" {
		switch dv {
		case "allow":
			defaultVerdict = Allow
		case "deny":
			defaultVerdict = Deny
		case "ask":
			defaultVerdict = Ask
		default:
			return nil, fmt.Errorf("unknown default verdict: %q", dv)
		}
	}

	// Read timeout.
	timeout := 120
	if ts, err := s.GetConfig("timeout_sec"); err != nil {
		return nil, fmt.Errorf("read timeout_sec: %w", err)
	} else if ts != "" {
		if v, err := strconv.Atoi(ts); err != nil {
			return nil, fmt.Errorf("invalid timeout_sec %q: %w", ts, err)
		} else {
			timeout = v
		}
	}

	// Read Telegram config.
	var telegram TelegramConfig
	if v, err := s.GetConfig("telegram_bot_token_env"); err != nil {
		return nil, fmt.Errorf("read telegram_bot_token_env: %w", err)
	} else {
		telegram.BotTokenEnv = v
	}
	if v, err := s.GetConfig("telegram_chat_id_env"); err != nil {
		return nil, fmt.Errorf("read telegram_chat_id_env: %w", err)
	} else {
		telegram.ChatIDEnv = v
	}

	// Read network rules.
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

	// Read tool rules.
	toolAllow, err := loadToolRules(s, "allow")
	if err != nil {
		return nil, err
	}
	toolDeny, err := loadToolRules(s, "deny")
	if err != nil {
		return nil, err
	}
	toolAsk, err := loadToolRules(s, "ask")
	if err != nil {
		return nil, err
	}

	// Read inspect rules.
	blockRules, err := loadInspectBlockRules(s)
	if err != nil {
		return nil, err
	}
	redactRules, err := loadInspectRedactRules(s)
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
		Telegram:           telegram,
	}
	if err := eng.compile(); err != nil {
		return nil, fmt.Errorf("compile policy rules: %w", err)
	}
	return eng, nil
}

func loadNetworkRules(s *store.Store, verdict string) ([]Rule, error) {
	rows, err := s.ListRules(verdict)
	if err != nil {
		return nil, fmt.Errorf("list %s rules: %w", verdict, err)
	}
	rules := make([]Rule, len(rows))
	for i, r := range rows {
		rules[i] = Rule{
			Destination: r.Destination,
			Ports:       r.Ports,
		}
	}
	return rules, nil
}

func loadToolRules(s *store.Store, verdict string) ([]ToolRule, error) {
	rows, err := s.ListToolRules(verdict)
	if err != nil {
		return nil, fmt.Errorf("list tool_%s rules: %w", verdict, err)
	}
	rules := make([]ToolRule, len(rows))
	for i, r := range rows {
		rules[i] = ToolRule{
			Tool:    r.Tool,
			Verdict: r.Verdict,
			Note:    r.Note,
		}
	}
	return rules, nil
}

func loadInspectBlockRules(s *store.Store) ([]InspectBlockRule, error) {
	rows, err := s.ListInspectRules("block")
	if err != nil {
		return nil, fmt.Errorf("list inspect_block rules: %w", err)
	}
	rules := make([]InspectBlockRule, len(rows))
	for i, r := range rows {
		rules[i] = InspectBlockRule{
			Pattern: r.Pattern,
			Name:    r.Description,
		}
	}
	return rules, nil
}

func loadInspectRedactRules(s *store.Store) ([]InspectRedactRule, error) {
	rows, err := s.ListInspectRules("redact")
	if err != nil {
		return nil, fmt.Errorf("list inspect_redact rules: %w", err)
	}
	rules := make([]InspectRedactRule, len(rows))
	for i, r := range rows {
		rules[i] = InspectRedactRule{
			Pattern:     r.Pattern,
			Replacement: r.Replacement,
			Name:        r.Description,
		}
	}
	return rules, nil
}
