package store

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/BurntSushi/toml"
)

// ImportResult reports what happened during a TOML import.
type ImportResult struct {
	RulesInserted     int
	RulesSkipped      int
	ToolRulesInserted int
	ToolRulesSkipped  int
	InspectInserted   int
	BindingsInserted  int
	BindingsSkipped   int
	UpstreamsInserted int
	UpstreamsSkipped  int
	ConfigSet         int
}

// importRule is the TOML representation of a network rule with all optional fields.
type importRule struct {
	Destination string `toml:"destination"`
	Ports       []int  `toml:"ports"`
	Protocol    string `toml:"protocol"`
	Note        string `toml:"note"`
}

// importToolRule is the TOML representation of a tool policy rule.
type importToolRule struct {
	Tool string `toml:"tool"`
	Note string `toml:"note"`
}

// importInspectBlock is the TOML representation of an inspect_block rule.
type importInspectBlock struct {
	Pattern string `toml:"pattern"`
	Name    string `toml:"name"`
	Note    string `toml:"note"`
}

// importInspectRedact is the TOML representation of an inspect_redact rule.
type importInspectRedact struct {
	Pattern     string `toml:"pattern"`
	Replacement string `toml:"replacement"`
	Name        string `toml:"name"`
	Note        string `toml:"note"`
}

// importBinding is the TOML representation of a credential binding.
type importBinding struct {
	Destination  string `toml:"destination"`
	Ports        []int  `toml:"ports"`
	Credential   string `toml:"credential"`
	InjectHeader string `toml:"inject_header"`
	Template     string `toml:"template"`
	Protocol     string `toml:"protocol"`
}

// importMCPUpstream is the TOML representation of an MCP upstream server.
type importMCPUpstream struct {
	Name       string            `toml:"name"`
	Command    string            `toml:"command"`
	Args       []string          `toml:"args"`
	Env        map[string]string `toml:"env"`
	TimeoutSec int               `toml:"timeout_sec"`
}

type importPolicyConfig struct {
	Default    string `toml:"default"`
	TimeoutSec int    `toml:"timeout_sec"`
}

type importTelegramConfig struct {
	BotTokenEnv string `toml:"bot_token_env"`
	ChatIDEnv   string `toml:"chat_id_env"`
}

// importVaultConfig is the TOML representation of the [vault] section.
type importVaultConfig struct {
	Provider  string                `toml:"provider"`
	Providers []string              `toml:"providers"`
	Dir       string                `toml:"dir"`
	HashiCorp importHashiCorpConfig `toml:"hashicorp"`
}

// importHashiCorpConfig is the TOML representation of [vault.hashicorp].
type importHashiCorpConfig struct {
	Addr        string `toml:"addr"`
	Mount       string `toml:"mount"`
	Prefix      string `toml:"prefix"`
	Auth        string `toml:"auth"`
	Token       string `toml:"token"`
	RoleID      string `toml:"role_id"`
	SecretID    string `toml:"secret_id"`
	RoleIDEnv   string `toml:"role_id_env"`
	SecretIDEnv string `toml:"secret_id_env"`
}

// importFile is the top-level TOML structure for policy import.
type importFile struct {
	Policy        importPolicyConfig    `toml:"policy"`
	Telegram      importTelegramConfig  `toml:"telegram"`
	Vault         importVaultConfig     `toml:"vault"`
	Allow         []importRule          `toml:"allow"`
	Deny          []importRule          `toml:"deny"`
	Ask           []importRule          `toml:"ask"`
	ToolAllow     []importToolRule      `toml:"tool_allow"`
	ToolDeny      []importToolRule      `toml:"tool_deny"`
	ToolAsk       []importToolRule      `toml:"tool_ask"`
	InspectBlock  []importInspectBlock  `toml:"inspect_block"`
	InspectRedact []importInspectRedact `toml:"inspect_redact"`
	Bindings      []importBinding       `toml:"binding"`
	MCPUpstreams  []importMCPUpstream   `toml:"mcp_upstream"`
}

// ImportTOML parses TOML policy data and inserts rules into the store with
// merge semantics. Duplicate rules (matched by verdict+destination+ports for
// network rules, verdict+tool for tool rules, destination+credential for
// bindings, name for upstreams) are skipped. The entire import runs in a
// single transaction so malformed data causes no partial writes.
func (s *Store) ImportTOML(data []byte) (*ImportResult, error) {
	var f importFile
	if err := toml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse TOML: %w", err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	res := &ImportResult{}

	// Import network rules.
	ruleVerdict := []struct {
		verdict string
		rules   []importRule
	}{
		{"allow", f.Allow},
		{"deny", f.Deny},
		{"ask", f.Ask},
	}
	for _, rv := range ruleVerdict {
		for _, r := range rv.rules {
			inserted, err := insertNetworkRuleIfNew(tx, rv.verdict, r)
			if err != nil {
				return nil, err
			}
			if inserted {
				res.RulesInserted++
			} else {
				res.RulesSkipped++
			}
		}
	}

	// Import tool rules.
	toolVerdict := []struct {
		verdict string
		rules   []importToolRule
	}{
		{"allow", f.ToolAllow},
		{"deny", f.ToolDeny},
		{"ask", f.ToolAsk},
	}
	for _, tv := range toolVerdict {
		for _, r := range tv.rules {
			inserted, err := insertToolRuleIfNew(tx, tv.verdict, r)
			if err != nil {
				return nil, err
			}
			if inserted {
				res.ToolRulesInserted++
			} else {
				res.ToolRulesSkipped++
			}
		}
	}

	// Import inspect rules.
	for _, r := range f.InspectBlock {
		desc := r.Name
		if desc == "" {
			desc = r.Note
		}
		if _, err := tx.Exec(
			`INSERT INTO inspect_rules (kind, pattern, description) VALUES (?, ?, ?)`,
			"block", r.Pattern, nilIfEmpty(desc),
		); err != nil {
			return nil, fmt.Errorf("insert inspect_block rule: %w", err)
		}
		res.InspectInserted++
	}
	for _, r := range f.InspectRedact {
		desc := r.Name
		if desc == "" {
			desc = r.Note
		}
		if _, err := tx.Exec(
			`INSERT INTO inspect_rules (kind, pattern, description, replacement) VALUES (?, ?, ?, ?)`,
			"redact", r.Pattern, nilIfEmpty(desc), nilIfEmpty(r.Replacement),
		); err != nil {
			return nil, fmt.Errorf("insert inspect_redact rule: %w", err)
		}
		res.InspectInserted++
	}

	// Import config values.
	if f.Policy.Default != "" {
		if err := upsertConfig(tx, "default_verdict", f.Policy.Default); err != nil {
			return nil, err
		}
		res.ConfigSet++
	}
	if f.Policy.TimeoutSec > 0 {
		if err := upsertConfig(tx, "timeout_sec", fmt.Sprintf("%d", f.Policy.TimeoutSec)); err != nil {
			return nil, err
		}
		res.ConfigSet++
	}
	if f.Telegram.BotTokenEnv != "" {
		if err := upsertConfig(tx, "telegram_bot_token_env", f.Telegram.BotTokenEnv); err != nil {
			return nil, err
		}
		res.ConfigSet++
	}
	if f.Telegram.ChatIDEnv != "" {
		if err := upsertConfig(tx, "telegram_chat_id_env", f.Telegram.ChatIDEnv); err != nil {
			return nil, err
		}
		res.ConfigSet++
	}

	// Import vault config.
	vaultConfigKeys := []struct {
		key   string
		value string
	}{
		{"vault_provider", f.Vault.Provider},
		{"vault_dir", f.Vault.Dir},
		{"vault_hashicorp_addr", f.Vault.HashiCorp.Addr},
		{"vault_hashicorp_mount", f.Vault.HashiCorp.Mount},
		{"vault_hashicorp_prefix", f.Vault.HashiCorp.Prefix},
		{"vault_hashicorp_auth", f.Vault.HashiCorp.Auth},
		{"vault_hashicorp_token", f.Vault.HashiCorp.Token},
		{"vault_hashicorp_role_id", f.Vault.HashiCorp.RoleID},
		{"vault_hashicorp_secret_id", f.Vault.HashiCorp.SecretID},
		{"vault_hashicorp_role_id_env", f.Vault.HashiCorp.RoleIDEnv},
		{"vault_hashicorp_secret_id_env", f.Vault.HashiCorp.SecretIDEnv},
	}
	if len(f.Vault.Providers) > 0 {
		b, _ := json.Marshal(f.Vault.Providers)
		vaultConfigKeys = append(vaultConfigKeys, struct {
			key   string
			value string
		}{"vault_providers", string(b)})
	}
	for _, kv := range vaultConfigKeys {
		if kv.value != "" {
			if err := upsertConfig(tx, kv.key, kv.value); err != nil {
				return nil, err
			}
			res.ConfigSet++
		}
	}

	// Import bindings.
	for _, b := range f.Bindings {
		inserted, err := insertBindingIfNew(tx, b)
		if err != nil {
			return nil, err
		}
		if inserted {
			res.BindingsInserted++
		} else {
			res.BindingsSkipped++
		}
	}

	// Import MCP upstreams.
	for _, u := range f.MCPUpstreams {
		inserted, err := insertUpstreamIfNew(tx, u)
		if err != nil {
			return nil, err
		}
		if inserted {
			res.UpstreamsInserted++
		} else {
			res.UpstreamsSkipped++
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return res, nil
}

// insertNetworkRuleIfNew inserts a network rule if no matching
// verdict+destination+ports combination exists. Returns true if inserted.
func insertNetworkRuleIfNew(tx *sql.Tx, verdict string, r importRule) (bool, error) {
	portsJSON := portsToJSON(r.Ports)

	var count int
	var err error
	if portsJSON != nil {
		err = tx.QueryRow(
			"SELECT COUNT(*) FROM rules WHERE verdict = ? AND destination = ? AND ports = ?",
			verdict, r.Destination, *portsJSON,
		).Scan(&count)
	} else {
		err = tx.QueryRow(
			"SELECT COUNT(*) FROM rules WHERE verdict = ? AND destination = ? AND ports IS NULL",
			verdict, r.Destination,
		).Scan(&count)
	}
	if err != nil {
		return false, fmt.Errorf("check rule exists: %w", err)
	}
	if count > 0 {
		return false, nil
	}

	if _, err := tx.Exec(
		`INSERT INTO rules (verdict, destination, ports, protocol, note, source) VALUES (?, ?, ?, ?, ?, ?)`,
		verdict, r.Destination, portsJSON, nilIfEmpty(r.Protocol), nilIfEmpty(r.Note), "seed",
	); err != nil {
		return false, fmt.Errorf("insert %s rule %q: %w", verdict, r.Destination, err)
	}
	return true, nil
}

// insertToolRuleIfNew inserts a tool rule if no matching verdict+tool
// combination exists. Returns true if inserted.
func insertToolRuleIfNew(tx *sql.Tx, verdict string, r importToolRule) (bool, error) {
	var count int
	err := tx.QueryRow(
		"SELECT COUNT(*) FROM tool_rules WHERE verdict = ? AND tool = ?",
		verdict, r.Tool,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check tool rule exists: %w", err)
	}
	if count > 0 {
		return false, nil
	}

	if _, err := tx.Exec(
		`INSERT INTO tool_rules (verdict, tool, note, source) VALUES (?, ?, ?, ?)`,
		verdict, r.Tool, nilIfEmpty(r.Note), "seed",
	); err != nil {
		return false, fmt.Errorf("insert tool_%s rule %q: %w", verdict, r.Tool, err)
	}
	return true, nil
}

// insertBindingIfNew inserts a binding if no matching destination+credential
// combination exists. Returns true if inserted.
func insertBindingIfNew(tx *sql.Tx, b importBinding) (bool, error) {
	var count int
	err := tx.QueryRow(
		"SELECT COUNT(*) FROM bindings WHERE destination = ? AND credential = ?",
		b.Destination, b.Credential,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check binding exists: %w", err)
	}
	if count > 0 {
		return false, nil
	}

	portsJSON := portsToJSON(b.Ports)
	if _, err := tx.Exec(
		`INSERT INTO bindings (destination, ports, credential, inject_header, template, protocol) VALUES (?, ?, ?, ?, ?, ?)`,
		b.Destination, portsJSON, b.Credential,
		nilIfEmpty(b.InjectHeader), nilIfEmpty(b.Template), nilIfEmpty(b.Protocol),
	); err != nil {
		return false, fmt.Errorf("insert binding %q->%q: %w", b.Destination, b.Credential, err)
	}
	return true, nil
}

// insertUpstreamIfNew inserts an MCP upstream if no matching name exists.
// Returns true if inserted.
func insertUpstreamIfNew(tx *sql.Tx, u importMCPUpstream) (bool, error) {
	var count int
	err := tx.QueryRow(
		"SELECT COUNT(*) FROM mcp_upstreams WHERE name = ?",
		u.Name,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check upstream exists: %w", err)
	}
	if count > 0 {
		return false, nil
	}

	timeoutSec := u.TimeoutSec
	if timeoutSec == 0 {
		timeoutSec = 120
	}
	var argsJSON, envJSON *string
	if len(u.Args) > 0 {
		b, _ := json.Marshal(u.Args)
		a := string(b)
		argsJSON = &a
	}
	if len(u.Env) > 0 {
		b, _ := json.Marshal(u.Env)
		e := string(b)
		envJSON = &e
	}

	if _, err := tx.Exec(
		`INSERT INTO mcp_upstreams (name, command, args, env, timeout_sec) VALUES (?, ?, ?, ?, ?)`,
		u.Name, u.Command, argsJSON, envJSON, timeoutSec,
	); err != nil {
		return false, fmt.Errorf("insert upstream %q: %w", u.Name, err)
	}
	return true, nil
}

func upsertConfig(tx *sql.Tx, key, value string) error {
	_, err := tx.Exec(
		`INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	if err != nil {
		return fmt.Errorf("set config %q: %w", key, err)
	}
	return nil
}

func portsToJSON(ports []int) *string {
	if len(ports) == 0 {
		return nil
	}
	b, _ := json.Marshal(ports)
	s := string(b)
	return &s
}
