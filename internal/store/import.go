package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/BurntSushi/toml"
	"github.com/nemirovsky/sluice/internal/container"
)

// ImportResult reports what happened during a TOML import.
type ImportResult struct {
	RulesInserted     int
	RulesSkipped      int
	BindingsInserted  int
	BindingsSkipped   int
	UpstreamsInserted int
	UpstreamsSkipped  int
	ConfigSet         int
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
	Tool        string   `toml:"tool"`
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
	EnvVar      string   `toml:"env_var"`
}

// importMCPUpstream is the TOML representation of an MCP upstream server.
type importMCPUpstream struct {
	Name       string            `toml:"name"`
	Command    string            `toml:"command"`
	Args       []string          `toml:"args"`
	Env        map[string]string `toml:"env"`
	TimeoutSec int               `toml:"timeout_sec"`
	Transport  string            `toml:"transport"`
}

type importPolicyConfig struct {
	Default    string `toml:"default"`
	TimeoutSec int    `toml:"timeout_sec"`
}

// importVaultConfig is the TOML representation of the [vault] section.
type importVaultConfig struct {
	Provider    string                  `toml:"provider"`
	Providers   []string                `toml:"providers"`
	Dir         string                  `toml:"dir"`
	HashiCorp   importHashiCorpConfig   `toml:"hashicorp"`
	OnePassword importOnePasswordConfig `toml:"1password"`
	Bitwarden   importBitwardenConfig   `toml:"bitwarden"`
	KeePass     importKeePassConfig     `toml:"keepass"`
	Gopass      importGopassConfig      `toml:"gopass"`
}

// importOnePasswordConfig is the TOML representation of [vault.1password].
type importOnePasswordConfig struct {
	Token string `toml:"token"`
	Vault string `toml:"vault"`
	Field string `toml:"field"`
}

// importBitwardenConfig is the TOML representation of [vault.bitwarden].
type importBitwardenConfig struct {
	Token string `toml:"token"`
	OrgID string `toml:"org_id"`
}

// importKeePassConfig is the TOML representation of [vault.keepass].
type importKeePassConfig struct {
	Path    string `toml:"path"`
	KeyFile string `toml:"key_file"`
}

// importGopassConfig is the TOML representation of [vault.gopass].
type importGopassConfig struct {
	Store string `toml:"store"`
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
	Policy       importPolicyConfig  `toml:"policy"`
	Vault        importVaultConfig   `toml:"vault"`
	Allow        []importRule        `toml:"allow"`
	Deny         []importRule        `toml:"deny"`
	Ask          []importRule        `toml:"ask"`
	Redact       []importRedactRule  `toml:"redact"`
	Bindings     []importBinding     `toml:"binding"`
	MCPUpstreams []importMCPUpstream `toml:"mcp_upstream"`
}

// validProtocolNames lists recognized protocol names for validation during
// TOML import. These correspond 1:1 with the Protocol enum values in the
// proxy package (proxy.protocolNames). Keep in sync with proxy.protocolNames;
// TestValidProtocolNamesSync verifies this.
//
// Note: "tcp" and "udp" are transport-level meta-protocols used in policy
// rules. "udp" is evaluated via EvaluateUDP/EvaluateQUIC in the policy
// engine. "tcp" is evaluated as a meta-protocol in Evaluate/EvaluateWithProtocol,
// matching any TCP-based connection regardless of application-level protocol.
var validProtocolNames = map[string]bool{
	"generic": true,
	"http":    true,
	"https":   true,
	"ssh":     true,
	"imap":    true,
	"smtp":    true,
	"ws":      true,
	"wss":     true,
	"grpc":    true,
	"dns":     true,
	"quic":    true,
	"apns":    true,
	"tcp":     true,
	"udp":     true,
}

// validateProtocols checks that all protocol names are recognized.
func validateProtocols(protocols []string, context string) error {
	for _, p := range protocols {
		if !validProtocolNames[p] {
			return fmt.Errorf("%s: unknown protocol %q", context, p)
		}
	}
	return nil
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
	defer func() { _ = tx.Rollback() }()

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
		{"vault_1password_token", f.Vault.OnePassword.Token},
		{"vault_1password_vault", f.Vault.OnePassword.Vault},
		{"vault_1password_field", f.Vault.OnePassword.Field},
		{"vault_bitwarden_token", f.Vault.Bitwarden.Token},
		{"vault_bitwarden_org_id", f.Vault.Bitwarden.OrgID},
		{"vault_keepass_path", f.Vault.KeePass.Path},
		{"vault_keepass_key_file", f.Vault.KeePass.KeyFile},
		{"vault_gopass_store", f.Vault.Gopass.Store},
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

	if r.Pattern != "" && verdict != "deny" && verdict != "redact" {
		return false, fmt.Errorf("pattern rules only support deny or redact verdict, got %q", verdict)
	}
	if r.Tool != "" && len(r.Ports) > 0 {
		return false, fmt.Errorf("tool rule %q: ports not supported on tool rules", r.Tool)
	}
	if r.Tool != "" && len(r.Protocols) > 0 {
		return false, fmt.Errorf("tool rule %q: protocols not supported on tool rules", r.Tool)
	}
	if r.Pattern != "" && len(r.Ports) > 0 {
		return false, fmt.Errorf("pattern rule %q: ports not supported on pattern rules", r.Pattern)
	}
	if r.Pattern != "" && len(r.Protocols) > 0 {
		return false, fmt.Errorf("pattern rule %q: protocols not supported on pattern rules", r.Pattern)
	}

	for _, p := range r.Ports {
		if p < 1 || p > 65535 {
			return false, fmt.Errorf("rule: invalid port %d (must be 1-65535)", p)
		}
	}

	if err := validateProtocols(r.Protocols, fmt.Sprintf("%s rule %q", verdict, r.Destination+r.Tool+r.Pattern)); err != nil {
		return false, err
	}

	// Validate destination glob up front so a bad seed fails the import
	// with a clear error instead of sneaking a row into the database that
	// only blows up later when policy.LoadFromStore recompiles live state.
	if r.Destination != "" {
		if err := validateDestinationGlob(r.Destination); err != nil {
			return false, fmt.Errorf("%s rule: %w", verdict, err)
		}
	}

	// Validate regex for pattern rules.
	if r.Pattern != "" {
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return false, fmt.Errorf("rule pattern %q: invalid regex: %w", r.Pattern, err)
		}
	}

	// Check for duplicates.
	exists, err := ruleExistsTx(tx, verdict, r.Destination, r.Tool, r.Pattern, r.Ports, r.Protocols)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}

	portsJSON := portsToJSONPtr(r.Ports)
	protocolsJSON := protocolsToJSONPtr(r.Protocols)

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
	if r.Tool != "" {
		return false, fmt.Errorf("redact rule %q: tool and pattern are mutually exclusive", r.Pattern)
	}
	if len(r.Ports) > 0 {
		return false, fmt.Errorf("redact rule %q: ports not supported on pattern-only rules", r.Pattern)
	}
	if len(r.Protocols) > 0 {
		return false, fmt.Errorf("redact rule %q: protocols not supported on pattern-only rules", r.Pattern)
	}
	if _, err := regexp.Compile(r.Pattern); err != nil {
		return false, fmt.Errorf("redact rule %q: invalid regex: %w", r.Pattern, err)
	}

	exists, err := ruleExistsTx(tx, "redact", r.Destination, "", r.Pattern, r.Ports, r.Protocols)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}

	if _, err := tx.Exec(
		`INSERT INTO rules (verdict, destination, tool, pattern, replacement, name, source) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"redact",
		nil, nil,
		r.Pattern,
		nilIfEmpty(r.Replacement),
		nilIfEmpty(r.Name), "seed",
	); err != nil {
		return false, fmt.Errorf("insert redact rule %q: %w", r.Pattern, err)
	}
	return true, nil
}

// ruleExistsTx checks for an existing rule within a transaction. For network
// rules, dedup is verdict+destination+ports+protocols. For tool rules,
// verdict+tool. For pattern rules, verdict+pattern.
func ruleExistsTx(tx *sql.Tx, verdict, destination, tool, pattern string, ports []int, protocols []string) (bool, error) {
	var query string
	var args []any

	switch {
	case destination != "":
		portsJSON := portsToJSONPtr(ports)
		protocolsJSON := protocolsToJSONPtr(protocols)
		if portsJSON != nil {
			query = "SELECT COUNT(*) FROM rules WHERE verdict = ? AND destination = ? AND ports = ?"
			args = []any{verdict, destination, *portsJSON}
		} else {
			query = "SELECT COUNT(*) FROM rules WHERE verdict = ? AND destination = ? AND ports IS NULL"
			args = []any{verdict, destination}
		}
		if protocolsJSON != nil {
			query += " AND protocols = ?"
			args = append(args, *protocolsJSON)
		} else {
			query += " AND protocols IS NULL"
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

// insertBindingIfNew inserts a binding if no matching (credential, destination)
// pair already exists. Returns true if inserted. Migration 000005 enforces
// a global UNIQUE index on (credential, destination), so the dedupe key here
// must match that uniqueness: keying on the full behavioral tuple
// (ports/header/template/protocols/env_var) would miss an existing row that
// differs only in those fields and then abort the whole import with a UNIQUE
// violation when the INSERT fires. Import uses merge semantics (skip
// duplicates, preserving existing rows) to match how rule imports behave.
func insertBindingIfNew(tx *sql.Tx, b importBinding) (bool, error) {
	if b.Destination == "" {
		return false, fmt.Errorf("binding has empty destination")
	}
	if b.Credential == "" {
		return false, fmt.Errorf("binding has empty credential")
	}
	// Validate destination glob before hitting the DB so a bad seed fails
	// the import with row context instead of landing as a row that only
	// fails later when vault.NewBindingResolver recompiles globs.
	if err := validateDestinationGlob(b.Destination); err != nil {
		return false, fmt.Errorf("binding %q->%q: %w", b.Destination, b.Credential, err)
	}
	for _, p := range b.Ports {
		if p < 1 || p > 65535 {
			return false, fmt.Errorf("binding %q->%q: invalid port %d (must be 1-65535)", b.Destination, b.Credential, p)
		}
	}
	if err := validateProtocols(b.Protocols, fmt.Sprintf("binding %q->%q", b.Destination, b.Credential)); err != nil {
		return false, err
	}
	// Validate env_var format and uniqueness when set.
	if b.EnvVar != "" {
		if err := container.ValidateEnvVarKey(b.EnvVar); err != nil {
			return false, fmt.Errorf("binding %q->%q: %w", b.Destination, b.Credential, err)
		}
		if err := checkEnvVarUniqueWith(tx, b.EnvVar, b.Credential); err != nil {
			return false, fmt.Errorf("binding %q->%q: %w", b.Destination, b.Credential, err)
		}
	}

	// Migration 000007 enforces case-insensitive uniqueness on
	// (credential, LOWER(destination)). Dedup here must match that so an
	// import of "API.example.com" when "api.example.com" is already stored
	// skips the row cleanly instead of hitting the unique index and aborting
	// the whole import.
	var count int
	err := tx.QueryRow(
		"SELECT COUNT(*) FROM bindings WHERE credential = ? AND LOWER(destination) = LOWER(?)",
		b.Credential, b.Destination,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check binding exists: %w", err)
	}
	if count > 0 {
		return false, nil
	}

	portsJSON := portsToJSONPtr(b.Ports)
	protocolsJSON := protocolsToJSONPtr(b.Protocols)
	if _, err := tx.Exec(
		`INSERT INTO bindings (destination, ports, credential, header, template, protocols, env_var) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		b.Destination, portsJSON, b.Credential,
		nilIfEmpty(b.Header), nilIfEmpty(b.Template), protocolsJSON,
		nilIfEmpty(b.EnvVar),
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

	transport := u.Transport
	if transport == "" {
		transport = "stdio"
	}
	validTransports := map[string]bool{"stdio": true, "http": true, "websocket": true}
	if !validTransports[transport] {
		return false, fmt.Errorf("MCP upstream %q: invalid transport %q (must be stdio, http, or websocket)", u.Name, transport)
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
		`INSERT INTO mcp_upstreams (name, command, args, env, timeout_sec, transport) VALUES (?, ?, ?, ?, ?, ?)`,
		u.Name, u.Command, argsJSON, envJSON, timeoutSec, transport,
	); err != nil {
		return false, fmt.Errorf("insert upstream %q: %w", u.Name, err)
	}
	return true, nil
}

// validConfigColumns is the allowlist of columns in the typed config table.
var validConfigColumns = map[string]bool{
	"default_verdict":               true,
	"timeout_sec":                   true,
	"vault_provider":                true,
	"vault_dir":                     true,
	"vault_providers":               true,
	"vault_hashicorp_addr":          true,
	"vault_hashicorp_mount":         true,
	"vault_hashicorp_prefix":        true,
	"vault_hashicorp_auth":          true,
	"vault_hashicorp_token":         true,
	"vault_hashicorp_role_id":       true,
	"vault_hashicorp_secret_id":     true,
	"vault_hashicorp_role_id_env":   true,
	"vault_hashicorp_secret_id_env": true,
	"vault_1password_token":         true,
	"vault_1password_vault":         true,
	"vault_1password_field":         true,
	"vault_bitwarden_token":         true,
	"vault_bitwarden_org_id":        true,
	"vault_keepass_path":            true,
	"vault_keepass_key_file":        true,
	"vault_gopass_store":            true,
}

// updateConfigColumn updates a single column in the typed config singleton row.
func updateConfigColumn(tx *sql.Tx, column, value string) error {
	if !validConfigColumns[column] {
		return fmt.Errorf("unknown config column %q", column)
	}
	_, err := tx.Exec("UPDATE config SET "+column+" = ? WHERE id = 1", value)
	if err != nil {
		return fmt.Errorf("set config %q: %w", column, err)
	}
	return nil
}
