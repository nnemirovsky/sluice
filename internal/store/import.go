package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/BurntSushi/toml"
)

// ImportResult reports what happened during a TOML import.
type ImportResult struct {
	RulesInserted    int
	RulesSkipped     int
	BindingsInserted int
	BindingsSkipped  int
	UpstreamsInserted int
	UpstreamsSkipped  int
	ConfigSet        int
}

// importRule is the TOML representation of a unified rule. Exactly one of
// Destination, Tool, or Pattern must be set. The verdict comes from the
// TOML section name ([[allow]], [[deny]], [[ask]]).
type importRule struct {
	Destination string   `toml:"destination"`
	Tool        string   `toml:"tool"`
	Pattern     string   `toml:"pattern"`
	Ports       []int    `toml:"ports"`
	Protocols   []string `toml:"protocols"`
	Name        string   `toml:"name"`
}

// importRedactRule is the TOML representation of a [[redact]] section entry.
type importRedactRule struct {
	Pattern     string   `toml:"pattern"`
	Replacement string   `toml:"replacement"`
	Name        string   `toml:"name"`
	Destination string   `toml:"destination"`
	Ports       []int    `toml:"ports"`
	Protocols   []string `toml:"protocols"`
}

// importBinding is the TOML representation of a credential binding.
type importBinding struct {
	Destination string   `toml:"destination"`
	Ports       []int    `toml:"ports"`
	Credential  string   `toml:"credential"`
	Header      string   `toml:"header"`
	Template    string   `toml:"template"`
	Protocols   []string `toml:"protocols"`
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

// importFile is the top-level TOML structure for config import.
type importFile struct {
	Policy       importPolicyConfig `toml:"policy"`
	Vault        importVaultConfig  `toml:"vault"`
	Allow        []importRule       `toml:"allow"`
	Deny         []importRule       `toml:"deny"`
	Ask          []importRule       `toml:"ask"`
	Redact       []importRedactRule `toml:"redact"`
	Bindings     []importBinding    `toml:"binding"`
	MCPUpstreams []importMCPUpstream `toml:"mcp_upstream"`
}

// ImportTOML parses TOML config data and inserts rules into the store with
// merge semantics. Duplicate rules (matched by verdict+destination+ports for
// network rules, verdict+tool for tool rules, verdict+pattern for content
// rules, destination+credential for bindings, name for upstreams) are
// skipped. The entire import runs in a single transaction so malformed data
// causes no partial writes.
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

	// Import allow/deny/ask rules (unified: destination, tool, or pattern).
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
			inserted, err := insertRuleIfNew(tx, rv.verdict, r)
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

	// Import redact rules.
	for _, r := range f.Redact {
		inserted, err := insertRedactRuleIfNew(tx, r)
		if err != nil {
			return nil, err
		}
		if inserted {
			res.RulesInserted++
		} else {
			res.RulesSkipped++
		}
	}

	// Import config values.
	if f.Policy.Default != "" {
		switch f.Policy.Default {
		case "allow", "deny", "ask":
		default:
			return nil, fmt.Errorf("invalid default verdict %q: must be allow, deny, or ask", f.Policy.Default)
		}
		if err := updateConfigColumn(tx, "default_verdict", f.Policy.Default); err != nil {
			return nil, err
		}
		res.ConfigSet++
	}
	if f.Policy.TimeoutSec > 0 {
		if err := updateConfigColumn(tx, "timeout_sec", fmt.Sprintf("%d", f.Policy.TimeoutSec)); err != nil {
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
			if err := updateConfigColumn(tx, kv.key, kv.value); err != nil {
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

// insertRuleIfNew inserts a unified rule (network, tool, or content deny)
// if no matching duplicate exists. Exactly one of r.Destination, r.Tool,
// or r.Pattern must be set. Returns true if inserted.
func insertRuleIfNew(tx *sql.Tx, verdict string, r importRule) (bool, error) {
	set := 0
	if r.Destination != "" {
		set++
	}
	if r.Tool != "" {
		set++
	}
	if r.Pattern != "" {
		set++
	}
	if set == 0 {
		return false, fmt.Errorf("%s rule has no destination, tool, or pattern", verdict)
	}
	if set > 1 {
		return false, fmt.Errorf("%s rule: destination, tool, and pattern are mutually exclusive", verdict)
	}

	for _, p := range r.Ports {
		if p < 1 || p > 65535 {
			return false, fmt.Errorf("rule: invalid port %d (must be 1-65535)", p)
		}
	}

	// Validate regex for pattern rules.
	if r.Pattern != "" {
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return false, fmt.Errorf("rule pattern %q: invalid regex: %w", r.Pattern, err)
		}
	}

	// Check for duplicates.
	exists, err := ruleExistsTx(tx, verdict, r.Destination, r.Tool, r.Pattern, r.Ports)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}

	portsJSON := portsToJSON(r.Ports)
	var protocolsJSON *string
	if len(r.Protocols) > 0 {
		b, _ := json.Marshal(r.Protocols)
		ps := string(b)
		protocolsJSON = &ps
	}

	if _, err := tx.Exec(
		`INSERT INTO rules (verdict, destination, tool, pattern, ports, protocols, name, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		verdict,
		nilIfEmpty(r.Destination),
		nilIfEmpty(r.Tool),
		nilIfEmpty(r.Pattern),
		portsJSON, protocolsJSON,
		nilIfEmpty(r.Name), "seed",
	); err != nil {
		return false, fmt.Errorf("insert %s rule: %w", verdict, err)
	}
	return true, nil
}

// insertRedactRuleIfNew inserts a redact rule if no matching verdict+pattern
// combination exists. Returns true if inserted.
func insertRedactRuleIfNew(tx *sql.Tx, r importRedactRule) (bool, error) {
	if r.Pattern == "" {
		return false, fmt.Errorf("redact rule has empty pattern")
	}
	if r.Destination != "" {
		return false, fmt.Errorf("redact rule: destination and pattern are mutually exclusive")
	}
	if _, err := regexp.Compile(r.Pattern); err != nil {
		return false, fmt.Errorf("redact rule %q: invalid regex: %w", r.Pattern, err)
	}

	exists, err := ruleExistsTx(tx, "redact", r.Destination, "", r.Pattern, r.Ports)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}

	portsJSON := portsToJSON(r.Ports)
	var protocolsJSON *string
	if len(r.Protocols) > 0 {
		b, _ := json.Marshal(r.Protocols)
		ps := string(b)
		protocolsJSON = &ps
	}

	if _, err := tx.Exec(
		`INSERT INTO rules (verdict, destination, pattern, replacement, ports, protocols, name, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"redact",
		nilIfEmpty(r.Destination),
		r.Pattern,
		nilIfEmpty(r.Replacement),
		portsJSON, protocolsJSON,
		nilIfEmpty(r.Name), "seed",
	); err != nil {
		return false, fmt.Errorf("insert redact rule %q: %w", r.Pattern, err)
	}
	return true, nil
}

// ruleExistsTx checks for an existing rule within a transaction. For network
// rules, dedup is verdict+destination+ports. For tool rules, verdict+tool.
// For pattern rules, verdict+pattern.
func ruleExistsTx(tx *sql.Tx, verdict, destination, tool, pattern string, ports []int) (bool, error) {
	var query string
	var args []any

	switch {
	case destination != "":
		portsJSON := portsToJSON(ports)
		if portsJSON != nil {
			query = "SELECT COUNT(*) FROM rules WHERE verdict = ? AND destination = ? AND ports = ?"
			args = []any{verdict, destination, *portsJSON}
		} else {
			query = "SELECT COUNT(*) FROM rules WHERE verdict = ? AND destination = ? AND ports IS NULL"
			args = []any{verdict, destination}
		}
	case tool != "":
		query = "SELECT COUNT(*) FROM rules WHERE verdict = ? AND tool = ?"
		args = []any{verdict, tool}
	case pattern != "":
		query = "SELECT COUNT(*) FROM rules WHERE verdict = ? AND pattern = ?"
		args = []any{verdict, pattern}
	default:
		return false, nil
	}

	var count int
	if err := tx.QueryRow(query, args...).Scan(&count); err != nil {
		return false, fmt.Errorf("check rule exists: %w", err)
	}
	return count > 0, nil
}

// insertBindingIfNew inserts a binding if no matching destination+credential+ports
// combination exists. Returns true if inserted. Ports are included in the dedupe
// check so that distinct bindings for the same credential on different ports
// (e.g., SMTP vs IMAP) are not collapsed.
func insertBindingIfNew(tx *sql.Tx, b importBinding) (bool, error) {
	if b.Destination == "" {
		return false, fmt.Errorf("binding has empty destination")
	}
	if b.Credential == "" {
		return false, fmt.Errorf("binding has empty credential")
	}
	for _, p := range b.Ports {
		if p < 1 || p > 65535 {
			return false, fmt.Errorf("binding %q->%q: invalid port %d (must be 1-65535)", b.Destination, b.Credential, p)
		}
	}
	portsJSON := portsToJSON(b.Ports)
	var count int
	err := tx.QueryRow(
		"SELECT COUNT(*) FROM bindings WHERE destination = ? AND credential = ? AND ports IS ?",
		b.Destination, b.Credential, portsJSON,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check binding exists: %w", err)
	}
	if count > 0 {
		return false, nil
	}

	var protocolsJSON *string
	if len(b.Protocols) > 0 {
		pb, _ := json.Marshal(b.Protocols)
		ps := string(pb)
		protocolsJSON = &ps
	}
	if _, err := tx.Exec(
		`INSERT INTO bindings (destination, ports, credential, header, template, protocols) VALUES (?, ?, ?, ?, ?, ?)`,
		b.Destination, portsJSON, b.Credential,
		nilIfEmpty(b.Header), nilIfEmpty(b.Template), protocolsJSON,
	); err != nil {
		return false, fmt.Errorf("insert binding %q->%q: %w", b.Destination, b.Credential, err)
	}
	return true, nil
}

// insertUpstreamIfNew inserts an MCP upstream if no matching name exists.
// Returns true if inserted.
func insertUpstreamIfNew(tx *sql.Tx, u importMCPUpstream) (bool, error) {
	if u.Name == "" {
		return false, fmt.Errorf("MCP upstream has empty name")
	}
	if u.Command == "" {
		return false, fmt.Errorf("MCP upstream %q has empty command", u.Name)
	}

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

// configColumns maps config key names to column names in the typed config table.
var configColumns = map[string]string{
	"default_verdict":               "default_verdict",
	"timeout_sec":                   "timeout_sec",
	"vault_provider":                "vault_provider",
	"vault_dir":                     "vault_dir",
	"vault_providers":               "vault_providers",
	"vault_hashicorp_addr":          "vault_hashicorp_addr",
	"vault_hashicorp_mount":         "vault_hashicorp_mount",
	"vault_hashicorp_prefix":        "vault_hashicorp_prefix",
	"vault_hashicorp_auth":          "vault_hashicorp_auth",
	"vault_hashicorp_token":         "vault_hashicorp_token",
	"vault_hashicorp_role_id":       "vault_hashicorp_role_id",
	"vault_hashicorp_secret_id":     "vault_hashicorp_secret_id",
	"vault_hashicorp_role_id_env":   "vault_hashicorp_role_id_env",
	"vault_hashicorp_secret_id_env": "vault_hashicorp_secret_id_env",
}

// updateConfigColumn updates a single column in the typed config singleton row.
func updateConfigColumn(tx *sql.Tx, column, value string) error {
	col, ok := configColumns[column]
	if !ok || col == "" {
		return fmt.Errorf("unknown config column %q", column)
	}
	_, err := tx.Exec("UPDATE config SET "+col+" = ? WHERE id = 1", value)
	if err != nil {
		return fmt.Errorf("set config %q: %w", column, err)
	}
	return nil
}

// portsToJSON is an alias for portsToJSONPtr (defined in store.go) kept for
// readability in import code.
var portsToJSON = portsToJSONPtr
