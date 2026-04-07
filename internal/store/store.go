// Package store provides a SQLite-backed policy store for runtime state.
// All policy rules (unified: network, tool, and content inspection), typed
// config, bindings, channels, and MCP upstreams are persisted in a single
// SQLite database.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/nemirovsky/sluice/internal/container"
	_ "modernc.org/sqlite" // SQLite driver registration
)

// Store wraps a SQLite database for policy and configuration persistence.
type Store struct {
	db *sql.DB
}

// DB returns the underlying *sql.DB for use by the data_version watcher.
func (s *Store) DB() *sql.DB {
	return s.db
}

// New opens or creates a SQLite database at the given path and runs
// schema migrations. Use ":memory:" for an in-memory database (tests).
func New(path string) (*Store, error) {
	dsn := path
	if path == ":memory:" {
		// Shared cache ensures all connections in the pool see the same
		// in-memory database (needed for concurrent access in tests).
		dsn = "file::memory:?cache=shared"
	} else {
		// Create the file with restricted permissions (0600) before SQLite
		// opens it. The DB may contain sensitive config values (e.g.
		// HashiCorp Vault tokens). If the file already exists, tighten
		// permissions in case it was created with a wider umask.
		if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
			f, createErr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
			if createErr != nil {
				return nil, fmt.Errorf("create db file %q: %w", path, createErr)
			}
			_ = f.Close()
		} else if statErr == nil {
			_ = os.Chmod(path, 0o600)
		}
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", path, err)
	}
	// SQLite PRAGMAs like foreign_keys and busy_timeout are per-connection
	// settings. With database/sql's connection pool, new connections would
	// not inherit them. Limiting to one connection ensures the PRAGMAs
	// apply to all queries, which is also the standard recommendation for
	// SQLite since it serializes writes anyway.
	db.SetMaxOpenConns(1)
	// Enable WAL mode for better concurrent read performance.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}
	// Set busy timeout so concurrent writers retry instead of returning
	// SQLITE_BUSY immediately. 5 seconds covers typical contention windows
	// between the proxy, CLI, and Telegram bot writing to the same DB.
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}
	// Enable foreign keys.
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}
	s := &Store{db: db}
	if err := runMigrations(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}
	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

func validVerdict(v string) bool {
	return v == "allow" || v == "deny" || v == "ask" || v == "redact"
}

// --- Rule types ---

// Rule represents a row in the unified rules table.
type Rule struct {
	ID          int64
	Verdict     string // "allow", "deny", "ask", "redact"
	Destination string // network rules
	Tool        string // tool rules
	Pattern     string // content deny/redact rules
	Replacement string // only for verdict="redact"
	Ports       []int
	Protocols   []string
	Name        string
	Source      string
	CreatedAt   string
}

// RuleOpts holds fields for AddRule.
type RuleOpts struct {
	Destination string
	Tool        string
	Pattern     string
	Replacement string
	Ports       []int
	Protocols   []string
	Name        string
	Source      string
}

// RuleFilter holds optional filters for ListRules.
type RuleFilter struct {
	Verdict string // filter by verdict (allow/deny/ask/redact)
	Type    string // "network", "tool", "pattern" - filter by which field is set
}

// RuleExistsOpts holds fields for RuleExists dedup check.
type RuleExistsOpts struct {
	Destination string
	Tool        string
	Pattern     string
	Ports       []int
	Protocols   []string
}

// AddRule inserts a rule into the unified rules table and returns its ID.
// Exactly one of opts.Destination, opts.Tool, or opts.Pattern must be set.
func (s *Store) AddRule(verdict string, opts RuleOpts) (int64, error) {
	if verdict == "" {
		return 0, fmt.Errorf("verdict is required")
	}
	if !validVerdict(verdict) {
		return 0, fmt.Errorf("invalid verdict %q: must be allow, deny, ask, or redact", verdict)
	}
	set := 0
	if opts.Destination != "" {
		set++
	}
	if opts.Tool != "" {
		set++
	}
	if opts.Pattern != "" {
		set++
	}
	if set == 0 {
		return 0, fmt.Errorf("one of destination, tool, or pattern is required")
	}
	if set > 1 {
		return 0, fmt.Errorf("destination, tool, and pattern are mutually exclusive")
	}
	if opts.Pattern != "" && verdict != "deny" && verdict != "redact" {
		return 0, fmt.Errorf("pattern rules only support deny or redact verdict, got %q", verdict)
	}
	if verdict == "redact" && opts.Pattern == "" {
		return 0, fmt.Errorf("redact rules require a pattern")
	}
	if opts.Tool != "" && len(opts.Ports) > 0 {
		return 0, fmt.Errorf("tool rules do not support ports")
	}
	if opts.Tool != "" && len(opts.Protocols) > 0 {
		return 0, fmt.Errorf("tool rules do not support protocols")
	}
	if opts.Pattern != "" && len(opts.Ports) > 0 {
		return 0, fmt.Errorf("pattern rules do not support ports")
	}
	if opts.Pattern != "" && len(opts.Protocols) > 0 {
		return 0, fmt.Errorf("pattern rules do not support protocols")
	}
	if opts.Pattern != "" {
		if _, regexErr := regexp.Compile(opts.Pattern); regexErr != nil {
			return 0, fmt.Errorf("pattern %q: invalid regex: %w", opts.Pattern, regexErr)
		}
	}
	for _, p := range opts.Ports {
		if p < 1 || p > 65535 {
			return 0, fmt.Errorf("invalid port %d (must be 1-65535)", p)
		}
	}
	source := opts.Source
	if source == "" {
		source = "manual"
	}
	portsJSON := portsToJSONPtr(opts.Ports)
	protocolsJSON := protocolsToJSONPtr(opts.Protocols)
	res, err := s.db.Exec(
		`INSERT INTO rules (verdict, destination, tool, pattern, replacement, ports, protocols, name, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		verdict,
		nilIfEmpty(opts.Destination),
		nilIfEmpty(opts.Tool),
		nilIfEmpty(opts.Pattern),
		nilIfEmpty(opts.Replacement),
		portsJSON, protocolsJSON,
		nilIfEmpty(opts.Name), source,
	)
	if err != nil {
		return 0, fmt.Errorf("insert rule: %w", err)
	}
	return res.LastInsertId()
}

// RemoveRule deletes a rule by ID. Returns true if a row was deleted.
func (s *Store) RemoveRule(id int64) (bool, error) {
	res, err := s.db.Exec("DELETE FROM rules WHERE id = ?", id)
	if err != nil {
		return false, fmt.Errorf("delete rule: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListRules returns rules from the unified table, optionally filtered by
// verdict and/or type. Type values: "network" (destination set), "tool"
// (tool set), "pattern" (pattern set). Empty filter returns all rules.
func (s *Store) ListRules(filter RuleFilter) ([]Rule, error) {
	query := "SELECT id, verdict, destination, tool, pattern, replacement, ports, protocols, name, source, created_at FROM rules WHERE 1=1"
	var args []any
	if filter.Verdict != "" {
		query += " AND verdict = ?"
		args = append(args, filter.Verdict)
	}
	switch filter.Type {
	case "network":
		query += " AND destination IS NOT NULL"
	case "tool":
		query += " AND tool IS NOT NULL"
	case "pattern":
		query += " AND pattern IS NOT NULL"
	}
	query += " ORDER BY id"
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanRules(rows)
}

// RuleExists checks if a rule matching the given verdict and identifying
// fields already exists. Used for merge/dedup during import.
func (s *Store) RuleExists(verdict string, opts RuleExistsOpts) (bool, error) {
	var query string
	var args []any

	switch {
	case opts.Destination != "":
		portsJSON := portsToJSONPtr(opts.Ports)
		protocolsJSON := protocolsToJSONPtr(opts.Protocols)
		if portsJSON != nil {
			query = "SELECT COUNT(*) FROM rules WHERE verdict = ? AND destination = ? AND ports = ?"
			args = []any{verdict, opts.Destination, *portsJSON}
		} else {
			query = "SELECT COUNT(*) FROM rules WHERE verdict = ? AND destination = ? AND ports IS NULL"
			args = []any{verdict, opts.Destination}
		}
		if protocolsJSON != nil {
			query += " AND protocols = ?"
			args = append(args, *protocolsJSON)
		} else {
			query += " AND protocols IS NULL"
		}
	case opts.Tool != "":
		query = "SELECT COUNT(*) FROM rules WHERE verdict = ? AND tool = ?"
		args = []any{verdict, opts.Tool}
	case opts.Pattern != "":
		query = "SELECT COUNT(*) FROM rules WHERE verdict = ? AND pattern = ?"
		args = []any{verdict, opts.Pattern}
	default:
		return false, fmt.Errorf("one of destination, tool, or pattern is required")
	}

	var count int
	if err := s.db.QueryRow(query, args...).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// --- Config ---

// Config represents the typed singleton row in the config table.
type Config struct {
	DefaultVerdict            string
	TimeoutSec                int
	VaultProvider             string
	VaultDir                  string
	VaultProviders            []string
	VaultHashicorpAddr        string
	VaultHashicorpMount       string
	VaultHashicorpPrefix      string
	VaultHashicorpAuth        string
	VaultHashicorpToken       string
	VaultHashicorpRoleID      string
	VaultHashicorpSecretID    string
	VaultHashicorpRoleIDEnv   string
	VaultHashicorpSecretIDEnv string
	Vault1PasswordToken       string
	Vault1PasswordVault       string
	Vault1PasswordField       string
	VaultBitwardenToken       string
	VaultBitwardenOrgID       string
	VaultKeePassPath          string
	VaultKeePassKeyFile       string
	VaultGopassStore          string
}

// ConfigUpdate holds optional fields for UpdateConfig. Only non-nil fields are written.
type ConfigUpdate struct {
	DefaultVerdict            *string
	TimeoutSec                *int
	VaultProvider             *string
	VaultDir                  *string
	VaultProviders            *[]string
	VaultHashicorpAddr        *string
	VaultHashicorpMount       *string
	VaultHashicorpPrefix      *string
	VaultHashicorpAuth        *string
	VaultHashicorpToken       *string
	VaultHashicorpRoleID      *string
	VaultHashicorpSecretID    *string
	VaultHashicorpRoleIDEnv   *string
	VaultHashicorpSecretIDEnv *string
	Vault1PasswordToken       *string
	Vault1PasswordVault       *string
	Vault1PasswordField       *string
	VaultBitwardenToken       *string
	VaultBitwardenOrgID       *string
	VaultKeePassPath          *string
	VaultKeePassKeyFile       *string
	VaultGopassStore          *string
}

// GetConfig reads the typed singleton config row.
func (s *Store) GetConfig() (*Config, error) {
	var cfg Config
	var vaultDir, vaultProviders sql.NullString
	var hcAddr, hcMount, hcPrefix, hcAuth, hcToken sql.NullString
	var hcRoleID, hcSecretID, hcRoleIDEnv, hcSecretIDEnv sql.NullString
	var opToken, opVault, opField sql.NullString
	var bwToken, bwOrgID sql.NullString
	var kpPath, kpKeyFile sql.NullString
	var gpStore sql.NullString

	err := s.db.QueryRow(`SELECT default_verdict, timeout_sec, vault_provider,
		vault_dir, vault_providers,
		vault_hashicorp_addr, vault_hashicorp_mount, vault_hashicorp_prefix,
		vault_hashicorp_auth, vault_hashicorp_token,
		vault_hashicorp_role_id, vault_hashicorp_secret_id,
		vault_hashicorp_role_id_env, vault_hashicorp_secret_id_env,
		vault_1password_token, vault_1password_vault, vault_1password_field,
		vault_bitwarden_token, vault_bitwarden_org_id,
		vault_keepass_path, vault_keepass_key_file,
		vault_gopass_store
		FROM config WHERE id = 1`).Scan(
		&cfg.DefaultVerdict, &cfg.TimeoutSec, &cfg.VaultProvider,
		&vaultDir, &vaultProviders,
		&hcAddr, &hcMount, &hcPrefix,
		&hcAuth, &hcToken,
		&hcRoleID, &hcSecretID,
		&hcRoleIDEnv, &hcSecretIDEnv,
		&opToken, &opVault, &opField,
		&bwToken, &bwOrgID,
		&kpPath, &kpKeyFile,
		&gpStore,
	)
	if err != nil {
		return nil, fmt.Errorf("get config: %w", err)
	}
	cfg.VaultDir = vaultDir.String
	if vaultProviders.Valid && vaultProviders.String != "" {
		_ = json.Unmarshal([]byte(vaultProviders.String), &cfg.VaultProviders)
	}
	cfg.VaultHashicorpAddr = hcAddr.String
	cfg.VaultHashicorpMount = hcMount.String
	cfg.VaultHashicorpPrefix = hcPrefix.String
	cfg.VaultHashicorpAuth = hcAuth.String
	cfg.VaultHashicorpToken = hcToken.String
	cfg.VaultHashicorpRoleID = hcRoleID.String
	cfg.VaultHashicorpSecretID = hcSecretID.String
	cfg.VaultHashicorpRoleIDEnv = hcRoleIDEnv.String
	cfg.VaultHashicorpSecretIDEnv = hcSecretIDEnv.String
	cfg.Vault1PasswordToken = opToken.String
	cfg.Vault1PasswordVault = opVault.String
	cfg.Vault1PasswordField = opField.String
	cfg.VaultBitwardenToken = bwToken.String
	cfg.VaultBitwardenOrgID = bwOrgID.String
	cfg.VaultKeePassPath = kpPath.String
	cfg.VaultKeePassKeyFile = kpKeyFile.String
	cfg.VaultGopassStore = gpStore.String
	return &cfg, nil
}

// UpdateConfig updates the config singleton row. Only non-nil fields in the
// update struct are written.
func (s *Store) UpdateConfig(u ConfigUpdate) error {
	var setClauses []string
	var args []any

	if u.DefaultVerdict != nil {
		switch *u.DefaultVerdict {
		case "allow", "deny", "ask":
			// valid
		default:
			return fmt.Errorf("invalid default_verdict %q: must be allow, deny, or ask", *u.DefaultVerdict)
		}
		setClauses = append(setClauses, "default_verdict = ?")
		args = append(args, *u.DefaultVerdict)
	}
	if u.TimeoutSec != nil {
		setClauses = append(setClauses, "timeout_sec = ?")
		args = append(args, *u.TimeoutSec)
	}
	if u.VaultProvider != nil {
		setClauses = append(setClauses, "vault_provider = ?")
		args = append(args, *u.VaultProvider)
	}
	if u.VaultDir != nil {
		setClauses = append(setClauses, "vault_dir = ?")
		args = append(args, nilIfEmpty(*u.VaultDir))
	}
	if u.VaultProviders != nil {
		if len(*u.VaultProviders) == 0 {
			setClauses = append(setClauses, "vault_providers = NULL")
		} else {
			b, _ := json.Marshal(*u.VaultProviders)
			setClauses = append(setClauses, "vault_providers = ?")
			args = append(args, string(b))
		}
	}
	if u.VaultHashicorpAddr != nil {
		setClauses = append(setClauses, "vault_hashicorp_addr = ?")
		args = append(args, nilIfEmpty(*u.VaultHashicorpAddr))
	}
	if u.VaultHashicorpMount != nil {
		setClauses = append(setClauses, "vault_hashicorp_mount = ?")
		args = append(args, nilIfEmpty(*u.VaultHashicorpMount))
	}
	if u.VaultHashicorpPrefix != nil {
		setClauses = append(setClauses, "vault_hashicorp_prefix = ?")
		args = append(args, nilIfEmpty(*u.VaultHashicorpPrefix))
	}
	if u.VaultHashicorpAuth != nil {
		setClauses = append(setClauses, "vault_hashicorp_auth = ?")
		args = append(args, nilIfEmpty(*u.VaultHashicorpAuth))
	}
	if u.VaultHashicorpToken != nil {
		setClauses = append(setClauses, "vault_hashicorp_token = ?")
		args = append(args, nilIfEmpty(*u.VaultHashicorpToken))
	}
	if u.VaultHashicorpRoleID != nil {
		setClauses = append(setClauses, "vault_hashicorp_role_id = ?")
		args = append(args, nilIfEmpty(*u.VaultHashicorpRoleID))
	}
	if u.VaultHashicorpSecretID != nil {
		setClauses = append(setClauses, "vault_hashicorp_secret_id = ?")
		args = append(args, nilIfEmpty(*u.VaultHashicorpSecretID))
	}
	if u.VaultHashicorpRoleIDEnv != nil {
		setClauses = append(setClauses, "vault_hashicorp_role_id_env = ?")
		args = append(args, nilIfEmpty(*u.VaultHashicorpRoleIDEnv))
	}
	if u.VaultHashicorpSecretIDEnv != nil {
		setClauses = append(setClauses, "vault_hashicorp_secret_id_env = ?")
		args = append(args, nilIfEmpty(*u.VaultHashicorpSecretIDEnv))
	}
	if u.Vault1PasswordToken != nil {
		setClauses = append(setClauses, "vault_1password_token = ?")
		args = append(args, nilIfEmpty(*u.Vault1PasswordToken))
	}
	if u.Vault1PasswordVault != nil {
		setClauses = append(setClauses, "vault_1password_vault = ?")
		args = append(args, nilIfEmpty(*u.Vault1PasswordVault))
	}
	if u.Vault1PasswordField != nil {
		setClauses = append(setClauses, "vault_1password_field = ?")
		args = append(args, nilIfEmpty(*u.Vault1PasswordField))
	}
	if u.VaultBitwardenToken != nil {
		setClauses = append(setClauses, "vault_bitwarden_token = ?")
		args = append(args, nilIfEmpty(*u.VaultBitwardenToken))
	}
	if u.VaultBitwardenOrgID != nil {
		setClauses = append(setClauses, "vault_bitwarden_org_id = ?")
		args = append(args, nilIfEmpty(*u.VaultBitwardenOrgID))
	}
	if u.VaultKeePassPath != nil {
		setClauses = append(setClauses, "vault_keepass_path = ?")
		args = append(args, nilIfEmpty(*u.VaultKeePassPath))
	}
	if u.VaultKeePassKeyFile != nil {
		setClauses = append(setClauses, "vault_keepass_key_file = ?")
		args = append(args, nilIfEmpty(*u.VaultKeePassKeyFile))
	}
	if u.VaultGopassStore != nil {
		setClauses = append(setClauses, "vault_gopass_store = ?")
		args = append(args, nilIfEmpty(*u.VaultGopassStore))
	}
	if len(setClauses) == 0 {
		return nil
	}
	query := "UPDATE config SET " + strings.Join(setClauses, ", ") + " WHERE id = 1"
	if _, err := s.db.Exec(query, args...); err != nil {
		return fmt.Errorf("update config: %w", err)
	}
	return nil
}

// --- Bindings ---

// BindingRow represents a row in the bindings table.
type BindingRow struct {
	ID          int64
	Destination string
	Ports       []int
	Credential  string
	Header      string
	Template    string
	Protocols   []string
	EnvVar      string
	CreatedAt   string
}

// BindingOpts holds optional fields for AddBinding.
type BindingOpts struct {
	Ports     []int
	Header    string
	Template  string
	Protocols []string
	EnvVar    string
}

// AddBinding inserts a binding and returns its ID.
func (s *Store) AddBinding(destination, credential string, opts BindingOpts) (int64, error) {
	if destination == "" || credential == "" {
		return 0, fmt.Errorf("destination and credential are required")
	}
	if opts.EnvVar != "" {
		if err := container.ValidateEnvVarKey(opts.EnvVar); err != nil {
			return 0, err
		}
		if err := checkEnvVarUniqueWith(s.db, opts.EnvVar); err != nil {
			return 0, err
		}
	}
	portsJSON := portsToJSONPtr(opts.Ports)
	protocolsJSON := protocolsToJSONPtr(opts.Protocols)
	res, err := s.db.Exec(
		`INSERT INTO bindings (destination, ports, credential, header, template, protocols, env_var) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		destination, portsJSON, credential,
		nilIfEmpty(opts.Header), nilIfEmpty(opts.Template), protocolsJSON,
		nilIfEmpty(opts.EnvVar),
	)
	if err != nil {
		return 0, fmt.Errorf("insert binding: %w", err)
	}
	return res.LastInsertId()
}

// RemoveBinding deletes a binding by ID. Returns true if a row was deleted.
func (s *Store) RemoveBinding(id int64) (bool, error) {
	res, err := s.db.Exec("DELETE FROM bindings WHERE id = ?", id)
	if err != nil {
		return false, fmt.Errorf("delete binding: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListBindings returns all bindings.
func (s *Store) ListBindings() ([]BindingRow, error) {
	rows, err := s.db.Query(
		"SELECT id, destination, ports, credential, header, template, protocols, env_var, created_at FROM bindings ORDER BY id",
	)
	if err != nil {
		return nil, fmt.Errorf("list bindings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanBindings(rows)
}

// --- MCP Upstreams ---

// MCPUpstreamRow represents a row in the mcp_upstreams table.
type MCPUpstreamRow struct {
	ID         int64
	Name       string
	Command    string
	Args       []string
	Env        map[string]string
	TimeoutSec int
	Transport  string
	CreatedAt  string
}

// MCPUpstreamOpts holds optional fields for AddMCPUpstream.
type MCPUpstreamOpts struct {
	Args       []string
	Env        map[string]string
	TimeoutSec int
	Transport  string // "stdio" (default), "http", or "websocket"
}

// AddMCPUpstream inserts an MCP upstream and returns its ID.
func (s *Store) AddMCPUpstream(name, command string, opts MCPUpstreamOpts) (int64, error) {
	if name == "" || command == "" {
		return 0, fmt.Errorf("name and command are required")
	}
	timeoutSec := opts.TimeoutSec
	if timeoutSec == 0 {
		timeoutSec = 120
	}
	transport := opts.Transport
	if transport == "" {
		transport = "stdio"
	}
	validTransports := map[string]bool{"stdio": true, "http": true, "websocket": true}
	if !validTransports[transport] {
		return 0, fmt.Errorf("invalid transport %q: must be stdio, http, or websocket", transport)
	}
	var argsJSON, envJSON *string
	if len(opts.Args) > 0 {
		b, _ := json.Marshal(opts.Args)
		a := string(b)
		argsJSON = &a
	}
	if len(opts.Env) > 0 {
		b, _ := json.Marshal(opts.Env)
		e := string(b)
		envJSON = &e
	}
	res, err := s.db.Exec(
		`INSERT INTO mcp_upstreams (name, command, args, env, timeout_sec, transport) VALUES (?, ?, ?, ?, ?, ?)`,
		name, command, argsJSON, envJSON, timeoutSec, transport,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			return 0, fmt.Errorf("upstream %q already exists", name)
		}
		return 0, fmt.Errorf("insert upstream: %w", err)
	}
	return res.LastInsertId()
}

// RemoveMCPUpstream deletes an MCP upstream by name. Returns true if a row was deleted.
func (s *Store) RemoveMCPUpstream(name string) (bool, error) {
	res, err := s.db.Exec("DELETE FROM mcp_upstreams WHERE name = ?", name)
	if err != nil {
		return false, fmt.Errorf("delete upstream: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListMCPUpstreams returns all MCP upstreams.
func (s *Store) ListMCPUpstreams() ([]MCPUpstreamRow, error) {
	rows, err := s.db.Query(
		"SELECT id, name, command, args, env, timeout_sec, transport, created_at FROM mcp_upstreams ORDER BY id",
	)
	if err != nil {
		return nil, fmt.Errorf("list upstreams: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var upstreams []MCPUpstreamRow
	for rows.Next() {
		var u MCPUpstreamRow
		var argsJSON, envJSON sql.NullString
		if err := rows.Scan(&u.ID, &u.Name, &u.Command, &argsJSON, &envJSON, &u.TimeoutSec, &u.Transport, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan upstream: %w", err)
		}
		if argsJSON.Valid {
			if err := json.Unmarshal([]byte(argsJSON.String), &u.Args); err != nil {
				return nil, fmt.Errorf("unmarshal args for upstream %d: %w", u.ID, err)
			}
		}
		if envJSON.Valid {
			if err := json.Unmarshal([]byte(envJSON.String), &u.Env); err != nil {
				return nil, fmt.Errorf("unmarshal env for upstream %d: %w", u.ID, err)
			}
		}
		upstreams = append(upstreams, u)
	}
	return upstreams, rows.Err()
}

// --- Channels ---

// Channel represents a row in the channels table.
type Channel struct {
	ID            int64
	Type          int
	Enabled       bool
	WebhookURL    string
	WebhookSecret string
	CreatedAt     string
}

// ChannelUpdate holds optional fields for UpdateChannel. Only non-nil fields are written.
type ChannelUpdate struct {
	Enabled       *bool
	WebhookURL    *string
	WebhookSecret *string
}

// GetChannel returns a channel by ID.
func (s *Store) GetChannel(id int64) (*Channel, error) {
	var ch Channel
	var enabled int
	var webhookURL, webhookSecret sql.NullString
	err := s.db.QueryRow(
		"SELECT id, type, enabled, webhook_url, webhook_secret, created_at FROM channels WHERE id = ?", id,
	).Scan(&ch.ID, &ch.Type, &enabled, &webhookURL, &webhookSecret, &ch.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get channel %d: %w", id, err)
	}
	ch.Enabled = enabled == 1
	ch.WebhookURL = webhookURL.String
	ch.WebhookSecret = webhookSecret.String
	return &ch, nil
}

// UpdateChannel updates a channel row. Only non-nil fields in the update struct are written.
func (s *Store) UpdateChannel(id int64, u ChannelUpdate) error {
	var setClauses []string
	var args []any
	if u.Enabled != nil {
		setClauses = append(setClauses, "enabled = ?")
		if *u.Enabled {
			args = append(args, 1)
		} else {
			args = append(args, 0)
		}
	}
	if u.WebhookURL != nil {
		setClauses = append(setClauses, "webhook_url = ?")
		args = append(args, nilIfEmpty(*u.WebhookURL))
	}
	if u.WebhookSecret != nil {
		setClauses = append(setClauses, "webhook_secret = ?")
		args = append(args, nilIfEmpty(*u.WebhookSecret))
	}
	if len(setClauses) == 0 {
		return nil
	}
	args = append(args, id)
	query := "UPDATE channels SET " + strings.Join(setClauses, ", ") + " WHERE id = ?"
	if _, err := s.db.Exec(query, args...); err != nil {
		return fmt.Errorf("update channel %d: %w", id, err)
	}
	return nil
}

// AddChannelOpts holds optional fields for AddChannel.
type AddChannelOpts struct {
	WebhookURL    string
	WebhookSecret string
}

// AddChannel inserts a new channel row with the given type and enabled state.
func (s *Store) AddChannel(chType int, enabled bool, opts ...AddChannelOpts) (int64, error) {
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	var webhookURL, webhookSecret *string
	if len(opts) > 0 {
		webhookURL = nilIfEmpty(opts[0].WebhookURL)
		webhookSecret = nilIfEmpty(opts[0].WebhookSecret)
	}
	res, err := s.db.Exec(
		"INSERT INTO channels (type, enabled, webhook_url, webhook_secret) VALUES (?, ?, ?, ?)",
		chType, enabledInt, webhookURL, webhookSecret,
	)
	if err != nil {
		return 0, fmt.Errorf("add channel: %w", err)
	}
	return res.LastInsertId()
}

// ListChannels returns all channels.
func (s *Store) ListChannels() ([]Channel, error) {
	rows, err := s.db.Query("SELECT id, type, enabled, webhook_url, webhook_secret, created_at FROM channels ORDER BY id")
	if err != nil {
		return nil, fmt.Errorf("list channels: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var channels []Channel
	for rows.Next() {
		var ch Channel
		var enabled int
		var webhookURL, webhookSecret sql.NullString
		if err := rows.Scan(&ch.ID, &ch.Type, &enabled, &webhookURL, &webhookSecret, &ch.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan channel: %w", err)
		}
		ch.Enabled = enabled == 1
		ch.WebhookURL = webhookURL.String
		ch.WebhookSecret = webhookSecret.String
		channels = append(channels, ch)
	}
	return channels, rows.Err()
}

// RemoveChannel deletes a channel by ID. Returns true if a row was deleted.
func (s *Store) RemoveChannel(id int64) (bool, error) {
	res, err := s.db.Exec("DELETE FROM channels WHERE id = ?", id)
	if err != nil {
		return false, fmt.Errorf("delete channel: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// CountEnabledChannels returns the number of enabled channels.
func (s *Store) CountEnabledChannels() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM channels WHERE enabled = 1").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count enabled channels: %w", err)
	}
	return count, nil
}

// --- Exists helpers ---

// BindingExists checks if a binding with the given destination and credential already exists.
func (s *Store) BindingExists(destination, credential string) (bool, error) {
	var count int
	err := s.db.QueryRow(
		"SELECT COUNT(*) FROM bindings WHERE destination = ? AND credential = ?",
		destination, credential,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// MCPUpstreamExists checks if an MCP upstream with the given name already exists.
func (s *Store) MCPUpstreamExists(name string) (bool, error) {
	var count int
	err := s.db.QueryRow(
		"SELECT COUNT(*) FROM mcp_upstreams WHERE name = ?",
		name,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// ListBindingsByCredential returns all bindings for a given credential name.
func (s *Store) ListBindingsByCredential(credential string) ([]BindingRow, error) {
	rows, err := s.db.Query(
		"SELECT id, destination, ports, credential, header, template, protocols, env_var, created_at FROM bindings WHERE credential = ? ORDER BY id",
		credential,
	)
	if err != nil {
		return nil, fmt.Errorf("list bindings by credential: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanBindings(rows)
}

// ListBindingsWithEnvVar returns all bindings where env_var is set (not empty).
func (s *Store) ListBindingsWithEnvVar() ([]BindingRow, error) {
	rows, err := s.db.Query(
		"SELECT id, destination, ports, credential, header, template, protocols, env_var, created_at FROM bindings WHERE env_var IS NOT NULL AND env_var != '' ORDER BY id",
	)
	if err != nil {
		return nil, fmt.Errorf("list bindings with env_var: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanBindings(rows)
}

// queryRower abstracts *sql.DB and *sql.Tx for shared query logic.
type queryRower interface {
	QueryRow(query string, args ...any) *sql.Row
}

// checkEnvVarUniqueWith verifies that no other binding uses the same env_var.
// The qr parameter allows this to work both inside and outside transactions.
func checkEnvVarUniqueWith(qr queryRower, envVar string) error {
	var count int
	err := qr.QueryRow(
		"SELECT COUNT(*) FROM bindings WHERE env_var = ?",
		envVar,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("check env_var uniqueness: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("env_var %q is already used by another binding", envVar)
	}
	return nil
}

// RemoveBindingsByCredential deletes all bindings for a credential. Returns the number deleted.
func (s *Store) RemoveBindingsByCredential(credential string) (int64, error) {
	res, err := s.db.Exec("DELETE FROM bindings WHERE credential = ?", credential)
	if err != nil {
		return 0, fmt.Errorf("delete bindings by credential: %w", err)
	}
	return res.RowsAffected()
}

// RemoveRulesBySource deletes all rules matching a source tag.
// Returns the number deleted.
func (s *Store) RemoveRulesBySource(source string) (int64, error) {
	res, err := s.db.Exec("DELETE FROM rules WHERE source = ?", source)
	if err != nil {
		return 0, fmt.Errorf("delete rules by source: %w", err)
	}
	return res.RowsAffected()
}

// RemoveRulesByName deletes all rules matching a name.
// Returns the number deleted.
func (s *Store) RemoveRulesByName(name string) (int64, error) {
	res, err := s.db.Exec("DELETE FROM rules WHERE name = ?", name)
	if err != nil {
		return 0, fmt.Errorf("delete rules by name: %w", err)
	}
	return res.RowsAffected()
}

// --- Store queries ---

// IsEmpty returns true if the store has no rules, bindings, or MCP upstreams.
// The config and channels tables always have a default row, so they are excluded.
func (s *Store) IsEmpty() (bool, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT (SELECT COUNT(*) FROM rules) +
		        (SELECT COUNT(*) FROM bindings) +
		        (SELECT COUNT(*) FROM mcp_upstreams)`,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check store empty: %w", err)
	}
	return count == 0, nil
}

// AddRuleAndBinding atomically inserts an allow rule and a binding in a
// single transaction. If either insert fails, both are rolled back.
// Returns the rule ID and binding ID.
func (s *Store) AddRuleAndBinding(
	verdict string, ruleOpts RuleOpts,
	credential string, bindingOpts BindingOpts,
) (ruleID, bindingID int64, err error) {
	if verdict == "" {
		return 0, 0, fmt.Errorf("verdict is required")
	}
	if !validVerdict(verdict) {
		return 0, 0, fmt.Errorf("invalid verdict %q: must be allow, deny, ask, or redact", verdict)
	}
	if ruleOpts.Destination == "" {
		return 0, 0, fmt.Errorf("destination is required for rule+binding")
	}
	if credential == "" {
		return 0, 0, fmt.Errorf("credential name is required")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Insert rule.
	source := ruleOpts.Source
	if source == "" {
		source = "manual"
	}
	portsJSON := portsToJSONPtr(ruleOpts.Ports)
	protocolsJSON := protocolsToJSONPtr(ruleOpts.Protocols)
	res, err := tx.Exec(
		`INSERT INTO rules (verdict, destination, ports, protocols, name, source) VALUES (?, ?, ?, ?, ?, ?)`,
		verdict, nilIfEmpty(ruleOpts.Destination), portsJSON, protocolsJSON, nilIfEmpty(ruleOpts.Name), source,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("insert rule: %w", err)
	}
	ruleID, _ = res.LastInsertId()

	// Validate and check env_var uniqueness before inserting (uses tx to
	// avoid deadlock with the single-connection pool).
	if bindingOpts.EnvVar != "" {
		if valErr := container.ValidateEnvVarKey(bindingOpts.EnvVar); valErr != nil {
			return 0, 0, valErr
		}
		if uniqueErr := checkEnvVarUniqueWith(tx, bindingOpts.EnvVar); uniqueErr != nil {
			return 0, 0, uniqueErr
		}
	}

	// Insert binding.
	bPortsJSON := portsToJSONPtr(bindingOpts.Ports)
	bProtocolsJSON := protocolsToJSONPtr(bindingOpts.Protocols)
	res, err = tx.Exec(
		`INSERT INTO bindings (destination, ports, credential, header, template, protocols, env_var) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ruleOpts.Destination, bPortsJSON, credential,
		nilIfEmpty(bindingOpts.Header), nilIfEmpty(bindingOpts.Template), bProtocolsJSON,
		nilIfEmpty(bindingOpts.EnvVar),
	)
	if err != nil {
		return 0, 0, fmt.Errorf("insert binding: %w", err)
	}
	bindingID, _ = res.LastInsertId()

	if err = tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit transaction: %w", err)
	}
	return ruleID, bindingID, nil
}

// --- Credential Meta ---

// CredentialMeta represents a row in the credential_meta table.
// It stores per-credential metadata (type, token URL) separately from bindings
// since one credential can have multiple bindings.
type CredentialMeta struct {
	Name      string
	CredType  string // "static" or "oauth"
	TokenURL  string
	CreatedAt string
}

// AddCredentialMeta inserts a credential metadata row.
func (s *Store) AddCredentialMeta(name, credType, tokenURL string) error {
	if name == "" {
		return fmt.Errorf("credential name is required")
	}
	if credType == "" {
		credType = "static"
	}
	if credType != "static" && credType != "oauth" {
		return fmt.Errorf("invalid credential type %q: must be static or oauth", credType)
	}
	if credType == "oauth" && tokenURL == "" {
		return fmt.Errorf("token_url is required for oauth credentials")
	}
	_, err := s.db.Exec(
		`INSERT INTO credential_meta (name, cred_type, token_url)
		 VALUES (?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET cred_type = excluded.cred_type, token_url = excluded.token_url`,
		name, credType, nilIfEmpty(tokenURL),
	)
	if err != nil {
		return fmt.Errorf("insert credential meta: %w", err)
	}
	return nil
}

// GetCredentialMeta returns a credential metadata row by name, or nil if not found.
func (s *Store) GetCredentialMeta(name string) (*CredentialMeta, error) {
	var meta CredentialMeta
	var tokenURL sql.NullString
	err := s.db.QueryRow(
		"SELECT name, cred_type, token_url, created_at FROM credential_meta WHERE name = ?", name,
	).Scan(&meta.Name, &meta.CredType, &tokenURL, &meta.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get credential meta %q: %w", name, err)
	}
	meta.TokenURL = tokenURL.String
	return &meta, nil
}

// ListCredentialMeta returns all credential metadata rows ordered by name.
func (s *Store) ListCredentialMeta() ([]CredentialMeta, error) {
	rows, err := s.db.Query(
		"SELECT name, cred_type, token_url, created_at FROM credential_meta ORDER BY name",
	)
	if err != nil {
		return nil, fmt.Errorf("list credential meta: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var metas []CredentialMeta
	for rows.Next() {
		var m CredentialMeta
		var tokenURL sql.NullString
		if err := rows.Scan(&m.Name, &m.CredType, &tokenURL, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan credential meta: %w", err)
		}
		m.TokenURL = tokenURL.String
		metas = append(metas, m)
	}
	return metas, rows.Err()
}

// RemoveCredentialMeta deletes a credential metadata row by name. Returns true
// if a row was deleted.
func (s *Store) RemoveCredentialMeta(name string) (bool, error) {
	res, err := s.db.Exec("DELETE FROM credential_meta WHERE name = ?", name)
	if err != nil {
		return false, fmt.Errorf("delete credential meta: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// --- Helpers ---

// nilIfEmpty returns nil for empty strings, allowing SQLite to store NULL.
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// scanRules scans rule rows from a query result.
func scanRules(rows *sql.Rows) ([]Rule, error) {
	var rules []Rule
	for rows.Next() {
		var r Rule
		var dest, tool, pattern, replacement, portsJSON, protocolsJSON, name sql.NullString
		if err := rows.Scan(&r.ID, &r.Verdict, &dest, &tool, &pattern, &replacement, &portsJSON, &protocolsJSON, &name, &r.Source, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan rule: %w", err)
		}
		r.Destination = dest.String
		r.Tool = tool.String
		r.Pattern = pattern.String
		r.Replacement = replacement.String
		r.Name = name.String
		if portsJSON.Valid {
			if err := json.Unmarshal([]byte(portsJSON.String), &r.Ports); err != nil {
				return nil, fmt.Errorf("unmarshal ports for rule %d: %w", r.ID, err)
			}
		}
		if protocolsJSON.Valid {
			if err := json.Unmarshal([]byte(protocolsJSON.String), &r.Protocols); err != nil {
				return nil, fmt.Errorf("unmarshal protocols for rule %d: %w", r.ID, err)
			}
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// portsToJSONPtr converts a port slice to a JSON string pointer.
func portsToJSONPtr(ports []int) *string {
	if len(ports) == 0 {
		return nil
	}
	b, _ := json.Marshal(ports)
	s := string(b)
	return &s
}

// protocolsToJSONPtr converts a protocol slice to a JSON string pointer.
func protocolsToJSONPtr(protocols []string) *string {
	if len(protocols) == 0 {
		return nil
	}
	b, _ := json.Marshal(protocols)
	s := string(b)
	return &s
}

// scanBindings scans binding rows from a query result.
func scanBindings(rows *sql.Rows) ([]BindingRow, error) {
	var bindings []BindingRow
	for rows.Next() {
		var b BindingRow
		var portsJSON, header, tmpl, protocolsJSON, envVar sql.NullString
		if err := rows.Scan(&b.ID, &b.Destination, &portsJSON, &b.Credential, &header, &tmpl, &protocolsJSON, &envVar, &b.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan binding: %w", err)
		}
		if portsJSON.Valid {
			if err := json.Unmarshal([]byte(portsJSON.String), &b.Ports); err != nil {
				return nil, fmt.Errorf("unmarshal ports for binding %d: %w", b.ID, err)
			}
		}
		b.Header = header.String
		b.Template = tmpl.String
		b.EnvVar = envVar.String
		if protocolsJSON.Valid {
			if err := json.Unmarshal([]byte(protocolsJSON.String), &b.Protocols); err != nil {
				return nil, fmt.Errorf("unmarshal protocols for binding %d: %w", b.ID, err)
			}
		}
		bindings = append(bindings, b)
	}
	return bindings, rows.Err()
}
