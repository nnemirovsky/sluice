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

// Source tag prefixes for rules auto-created by credential and binding
// management. They are shared between the CLI and the REST API so that
// cleanup and paired-rule lookups use identical tags regardless of code path.
const (
	// CredAddSourcePrefix tags rules auto-created by "sluice cred add
	// --destination" or the equivalent POST /api/credentials path.
	CredAddSourcePrefix = "cred-add:"
	// BindingAddSourcePrefix tags rules auto-created by "sluice binding add"
	// or the equivalent POST /api/bindings path.
	BindingAddSourcePrefix = "binding-add:"
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

// AddBinding inserts a binding and returns its ID. Returns
// ErrBindingDuplicate when a binding on the same (credential, destination)
// pair already exists (enforced by a partial UNIQUE index).
//
// The env_var uniqueness check and the INSERT run inside a single
// transaction so concurrent AddBinding callers cannot race past a
// check-then-insert window after migration 000005 dropped the DB-level
// env_var unique index. With SetMaxOpenConns(1), the shared tx
// serializes both operations on the same connection, making
// cross-credential env_var collisions impossible.
func (s *Store) AddBinding(destination, credential string, opts BindingOpts) (int64, error) {
	if destination == "" {
		return 0, fmt.Errorf("%w: destination is required", ErrBindingValidation)
	}
	if credential == "" {
		return 0, fmt.Errorf("%w: credential is required", ErrBindingValidation)
	}
	// Validate the destination glob up front so invalid patterns are
	// rejected before the insert. Without this, a malformed glob would
	// only surface later at engine recompile time (rebuildResolver), long
	// after the bad row was persisted. Mirrors AddRuleAndBinding and
	// updateBindingTx so every store write path enforces the same
	// validation contract.
	if err := validateDestinationGlob(destination); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrBindingValidation, err)
	}
	// Port range validation (1-65535) matches AddRule and
	// AddRuleAndBinding. Out-of-range ports would otherwise be persisted
	// and silently skipped at connection-match time.
	for _, p := range opts.Ports {
		if p < 1 || p > 65535 {
			return 0, fmt.Errorf("%w: invalid binding port %d (must be 1-65535)", ErrBindingValidation, p)
		}
	}
	// Reject unknown protocol names up front. Without this, a typo like
	// "htp" would be stored silently and later fail protocol matching at
	// connection time, making the binding look broken for no apparent
	// reason. Share the allow list with TOML import via validateProtocols.
	if err := validateProtocols(opts.Protocols, fmt.Sprintf("binding %q->%q", destination, credential)); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrBindingValidation, err)
	}
	if opts.EnvVar != "" {
		if err := container.ValidateEnvVarKey(opts.EnvVar); err != nil {
			return 0, fmt.Errorf("%w: %w", ErrBindingValidation, err)
		}
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Uniqueness check runs on the same tx as the INSERT so the single
	// connection serializes them. Without this, concurrent callers could
	// both observe no collision and then both insert the same env_var
	// for different credentials, making env injection nondeterministic.
	if opts.EnvVar != "" {
		if err := checkEnvVarUniqueWith(tx, opts.EnvVar, credential); err != nil {
			return 0, err
		}
	}

	portsJSON := portsToJSONPtr(opts.Ports)
	protocolsJSON := protocolsToJSONPtr(opts.Protocols)
	res, err := tx.Exec(
		`INSERT INTO bindings (destination, ports, credential, header, template, protocols, env_var) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		destination, portsJSON, credential,
		nilIfEmpty(opts.Header), nilIfEmpty(opts.Template), protocolsJSON,
		nilIfEmpty(opts.EnvVar),
	)
	if err != nil {
		if isBindingUniqueViolation(err) {
			// Query via the same tx because the single-connection pool
			// still owns this connection until commit/rollback.
			return 0, duplicateBindingError(tx, credential, destination)
		}
		return 0, fmt.Errorf("insert binding: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("last insert id: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit transaction: %w", err)
	}
	committed = true
	return id, nil
}

// ErrBindingNotFound is returned by UpdateBindingWithRuleSync when the
// binding row identified by id does not exist. Callers should test with
// errors.Is so the API layer can map it to a 404 response and the CLI to
// a clean exit code without parsing error strings.
var ErrBindingNotFound = fmt.Errorf("binding not found")

// ErrBindingDuplicate is returned by AddBinding / AddRuleAndBinding when a
// binding with the same (credential, destination) pair already exists.
// Callers that want to show a friendlier message can use errors.Is to
// detect this sentinel.
var ErrBindingDuplicate = fmt.Errorf("binding already exists for credential/destination")

// ErrBindingValidation wraps all client-facing validation errors raised
// by AddRuleAndBinding and updateBindingTx (empty destination, bad port
// range, invalid protocol, invalid env var key, invalid destination
// glob). The API layer tests with errors.Is to return 400 for these and
// 500 for anything else (SQL errors, transaction failures, etc). Without
// this sentinel every store failure collapses into a 400, hiding real
// server faults from clients.
var ErrBindingValidation = fmt.Errorf("binding validation failed")

// isBindingUniqueViolation detects the SQLite UNIQUE constraint violation
// that indicates a duplicate binding on (credential, destination).
func isBindingUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	if !strings.Contains(msg, "UNIQUE constraint") {
		return false
	}
	// The partial index name shows up in the driver error for SQLite.
	return strings.Contains(msg, "idx_bindings_credential_destination") ||
		(strings.Contains(msg, "bindings.credential") && strings.Contains(msg, "bindings.destination"))
}

// duplicateBindingError builds a user-facing error for a duplicate binding
// attempt. When the existing row can be looked up, the error includes its
// ID so the operator knows which binding to update instead. The qr may be
// nil (no lookup) or an open *sql.Tx (lookup happens inside the same
// transaction). It must never be the outer *sql.DB while a transaction is
// in flight on a single-connection pool because that would deadlock.
func duplicateBindingError(qr queryRower, credential, destination string) error {
	if qr != nil {
		var id int64
		// Lookup matches the unique index, which is case-insensitive on
		// destination (migration 000005). Using LOWER() here means that a
		// duplicate detected on, for example, "API.example.com" can still
		// point the caller at the existing "api.example.com" row instead
		// of returning the anonymous fallback message below.
		err := qr.QueryRow(
			"SELECT id FROM bindings WHERE credential = ? AND LOWER(destination) = LOWER(?) ORDER BY id LIMIT 1",
			credential, destination,
		).Scan(&id)
		if err == nil {
			return fmt.Errorf(
				"%w: credential %q on destination %q already exists as id %d; use \"sluice binding update %d\" to modify it",
				ErrBindingDuplicate, credential, destination, id, id,
			)
		}
	}
	return fmt.Errorf(
		"%w: credential %q on destination %q",
		ErrBindingDuplicate, credential, destination,
	)
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

// RemoveBindingWithRuleCleanup atomically reads a binding by id, deletes it,
// and removes the paired auto-created allow rule (matched on
// BindingAddSourcePrefix or CredAddSourcePrefix) in a single transaction.
// This eliminates the TOCTOU window between the ListBindings -> RemoveBinding
// -> RemoveRuleByBindingPair sequence used by earlier code paths, where a
// concurrent writer could update the binding's destination between snapshot
// and delete and leave an orphaned rule pointing at the previous destination.
//
// Returns the credential and destination that were attached to the binding
// (so callers can refresh env vars and log mutations), the number of paired
// rules removed, a boolean indicating whether the binding existed, and any
// error. When found is false the other return values are zero/empty and err
// is nil.
func (s *Store) RemoveBindingWithRuleCleanup(id int64) (credential, destination string, removedRules int64, envVar string, found bool, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", "", 0, "", false, fmt.Errorf("begin transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var envVarNS sql.NullString
	row := tx.QueryRow(
		"SELECT credential, destination, env_var FROM bindings WHERE id = ?",
		id,
	)
	if scanErr := row.Scan(&credential, &destination, &envVarNS); scanErr != nil {
		if scanErr == sql.ErrNoRows {
			return "", "", 0, "", false, nil
		}
		return "", "", 0, "", false, fmt.Errorf("load binding %d: %w", id, scanErr)
	}
	envVar = envVarNS.String

	res, err := tx.Exec("DELETE FROM bindings WHERE id = ?", id)
	if err != nil {
		return "", "", 0, "", false, fmt.Errorf("delete binding %d: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// The row vanished between the SELECT and DELETE. This can only
		// happen with concurrent writers on the same connection, which
		// SQLite serializes, so it should not occur in practice. Treat
		// it the same as "not found" rather than asserting.
		return "", "", 0, "", false, nil
	}

	// Match the destination case-insensitively. Policy compilation and the
	// bindings UNIQUE index both treat destinations as case-insensitive, so
	// upgraded databases may still carry a paired rule whose destination
	// differs in case from the binding. A case-sensitive delete would leave
	// that rule orphaned.
	res, err = tx.Exec(
		`DELETE FROM rules
		 WHERE LOWER(destination) = LOWER(?)
		   AND source IN (?, ?)`,
		destination,
		BindingAddSourcePrefix+credential,
		CredAddSourcePrefix+credential,
	)
	if err != nil {
		return "", "", 0, "", false, fmt.Errorf("delete paired rule for binding %d: %w", id, err)
	}
	removedRules, _ = res.RowsAffected()

	if err := tx.Commit(); err != nil {
		return "", "", 0, "", false, fmt.Errorf("commit transaction: %w", err)
	}
	committed = true
	return credential, destination, removedRules, envVar, true, nil
}

// BindingUpdateOpts holds optional fields for UpdateBindingWithRuleSync.
// Only non-nil fields are written. Nil fields are left unchanged.
type BindingUpdateOpts struct {
	Destination *string
	Ports       *[]int
	Header      *string
	Template    *string
	Protocols   *[]string
	EnvVar      *string
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
	Headers    map[string]string
	TimeoutSec int
	Transport  string
	CreatedAt  string
}

// MCPUpstreamOpts holds optional fields for AddMCPUpstream.
type MCPUpstreamOpts struct {
	Args       []string
	Env        map[string]string
	Headers    map[string]string
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
	var argsJSON, envJSON, headersJSON *string
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
	if len(opts.Headers) > 0 {
		b, _ := json.Marshal(opts.Headers)
		h := string(b)
		headersJSON = &h
	}
	res, err := s.db.Exec(
		`INSERT INTO mcp_upstreams (name, command, args, env, headers, timeout_sec, transport) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		name, command, argsJSON, envJSON, headersJSON, timeoutSec, transport,
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
		"SELECT id, name, command, args, env, headers, timeout_sec, transport, created_at FROM mcp_upstreams ORDER BY id",
	)
	if err != nil {
		return nil, fmt.Errorf("list upstreams: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var upstreams []MCPUpstreamRow
	for rows.Next() {
		var u MCPUpstreamRow
		var argsJSON, envJSON, headersJSON sql.NullString
		if err := rows.Scan(&u.ID, &u.Name, &u.Command, &argsJSON, &envJSON, &headersJSON, &u.TimeoutSec, &u.Transport, &u.CreatedAt); err != nil {
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
		if headersJSON.Valid {
			if err := json.Unmarshal([]byte(headersJSON.String), &u.Headers); err != nil {
				return nil, fmt.Errorf("unmarshal headers for upstream %d: %w", u.ID, err)
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

// checkEnvVarUniqueWith verifies that no binding belonging to a different
// credential uses the same env_var. Multiple bindings for the same credential
// are allowed to share one env_var because they all resolve to the same
// phantom value (the phantom is derived from the credential name), so no
// container injection conflict can arise. The qr parameter allows this to
// work both inside and outside transactions.
func checkEnvVarUniqueWith(qr queryRower, envVar, credential string) error {
	var count int
	err := qr.QueryRow(
		"SELECT COUNT(*) FROM bindings WHERE env_var = ? AND credential != ?",
		envVar, credential,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("check env_var uniqueness: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("env_var %q is already used by another credential's binding", envVar)
	}
	return nil
}

// checkEnvVarUniqueWithExcluding is like checkEnvVarUniqueWith but ignores a
// specific binding ID. Used by UpdateBindingWithRuleSync so a binding can
// keep its own env_var during a partial update without tripping the
// uniqueness check. Like checkEnvVarUniqueWith, bindings that belong to the
// same credential are excluded from the collision check.
func checkEnvVarUniqueWithExcluding(qr queryRower, envVar, credential string, excludeID int64) error {
	var count int
	err := qr.QueryRow(
		"SELECT COUNT(*) FROM bindings WHERE env_var = ? AND credential != ? AND id != ?",
		envVar, credential, excludeID,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("check env_var uniqueness: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("env_var %q is already used by another credential's binding", envVar)
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

// RemoveRuleByBindingPair deletes the auto-created allow rule paired with a
// binding on the given credential and destination. It tries both
// BindingAddSourcePrefix and CredAddSourcePrefix source tags (either code
// path could have created the rule). Returns the number of rules deleted.
// A zero return is not an error: the rule may have been removed manually.
// The destination match is case-insensitive because policy compilation and
// the bindings UNIQUE index both treat destinations as case-insensitive.
// A case-sensitive delete would leave the rule orphaned when an upgraded
// database stored the binding and rule at different cases.
func (s *Store) RemoveRuleByBindingPair(credential, destination string) (int64, error) {
	if credential == "" || destination == "" {
		return 0, fmt.Errorf("credential and destination are required")
	}
	res, err := s.db.Exec(
		`DELETE FROM rules
		 WHERE LOWER(destination) = LOWER(?)
		   AND source IN (?, ?)`,
		destination,
		BindingAddSourcePrefix+credential,
		CredAddSourcePrefix+credential,
	)
	if err != nil {
		return 0, fmt.Errorf("delete paired rule: %w", err)
	}
	return res.RowsAffected()
}

// UpdateBindingWithRuleSync updates a binding and, when the destination
// changes, atomically syncs the paired auto-created allow rule in the same
// transaction. Returns the paired rule ID, a boolean indicating whether a
// paired rule was found and updated, and any error. When the destination is
// not changing, the rule sync is skipped and (0, false, nil) is returned for
// the rule portion of the result. A missing binding is reported via
// ErrBindingNotFound (use errors.Is to detect it).
//
// The binding read, the binding update, and the rule update all run inside
// a single database transaction. Combined with the single-connection pool
// that serializes writes, this eliminates the TOCTOU window between the
// ListBindings / update / rule-update sequence used in earlier versions of
// the code.
func (s *Store) UpdateBindingWithRuleSync(id int64, u BindingUpdateOpts) (ruleID int64, ruleFound bool, current BindingRow, err error) {
	// Validate the destination glob and protocol names before opening a
	// transaction so a malformed pattern or typo is rejected with a clean
	// error message instead of failing later inside the transaction (which
	// surfaces as a less helpful "update binding" error).
	if u.Destination != nil {
		if err := validateDestinationGlob(*u.Destination); err != nil {
			return 0, false, BindingRow{}, fmt.Errorf("%w: %w", ErrBindingValidation, err)
		}
	}
	if u.Protocols != nil {
		if err := validateProtocols(*u.Protocols, fmt.Sprintf("binding id %d", id)); err != nil {
			return 0, false, BindingRow{}, fmt.Errorf("%w: %w", ErrBindingValidation, err)
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, false, BindingRow{}, fmt.Errorf("begin transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Load the current binding inside the transaction so the destination we
	// read matches the one we update.
	row := tx.QueryRow(
		"SELECT id, destination, ports, credential, header, template, protocols, env_var, created_at FROM bindings WHERE id = ?",
		id,
	)
	var b BindingRow
	var portsStr, protocolsStr sql.NullString
	var header, template, envVar sql.NullString
	if scanErr := row.Scan(&b.ID, &b.Destination, &portsStr, &b.Credential, &header, &template, &protocolsStr, &envVar, &b.CreatedAt); scanErr != nil {
		if scanErr == sql.ErrNoRows {
			return 0, false, BindingRow{}, fmt.Errorf("%w: id %d", ErrBindingNotFound, id)
		}
		return 0, false, BindingRow{}, fmt.Errorf("load binding %d: %w", id, scanErr)
	}
	if portsStr.Valid && portsStr.String != "" {
		if jsonErr := json.Unmarshal([]byte(portsStr.String), &b.Ports); jsonErr != nil {
			return 0, false, BindingRow{}, fmt.Errorf("unmarshal ports for binding %d: %w", id, jsonErr)
		}
	}
	if protocolsStr.Valid && protocolsStr.String != "" {
		if jsonErr := json.Unmarshal([]byte(protocolsStr.String), &b.Protocols); jsonErr != nil {
			return 0, false, BindingRow{}, fmt.Errorf("unmarshal protocols for binding %d: %w", id, jsonErr)
		}
	}
	b.Header = header.String
	b.Template = template.String
	b.EnvVar = envVar.String

	// Apply the update. The credential is passed in so updateBindingTx does
	// not have to re-query the bindings table for the env_var uniqueness
	// check or the duplicate-destination error path.
	if err := updateBindingTx(tx, id, b.Credential, u); err != nil {
		return 0, false, BindingRow{}, err
	}

	// If destination, ports, or protocols changed, sync the paired allow
	// rule in the same transaction so concurrent writers cannot leave an
	// orphan rule. Header, template, and env_var are binding-only and do
	// not affect the paired rule.
	destChanged := u.Destination != nil && *u.Destination != b.Destination
	portsChanged := u.Ports != nil
	protocolsChanged := u.Protocols != nil
	if destChanged || portsChanged || protocolsChanged {
		sync := pairedRuleSync{}
		if destChanged {
			sync.newDestination = u.Destination
		}
		if portsChanged {
			sync.newPorts = u.Ports
		}
		if protocolsChanged {
			sync.newProtocols = u.Protocols
		}
		ruleID, ruleFound, err = updatePairedRuleTx(tx, b.Credential, b.Destination, sync)
		if err != nil {
			return 0, false, BindingRow{}, err
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, false, BindingRow{}, fmt.Errorf("commit transaction: %w", err)
	}
	committed = true
	return ruleID, ruleFound, b, nil
}

// updateBindingTx contains the shared UPDATE-binding logic used by
// UpdateBindingWithRuleSync. It runs inside an existing *sql.Tx and
// returns an error if the binding does not exist or if any field fails
// validation. The credential is passed in by the caller (which has already
// loaded the row) so this helper does not need to re-query the bindings
// table for the env_var uniqueness check or the duplicate-destination
// error path.
func updateBindingTx(tx *sql.Tx, id int64, credential string, u BindingUpdateOpts) error {
	// Validate protocol names up front so a typo like "htp" is rejected
	// with a clean error before any UPDATE runs. Shares the allow list
	// with TOML import via validateProtocols.
	if u.Protocols != nil {
		if err := validateProtocols(*u.Protocols, fmt.Sprintf("binding id %d", id)); err != nil {
			return fmt.Errorf("%w: %w", ErrBindingValidation, err)
		}
	}
	// Port range is validated before building the SET clause so a bad
	// value does not reach the DB; matches AddRuleAndBinding.
	if u.Ports != nil {
		for _, p := range *u.Ports {
			if p < 1 || p > 65535 {
				return fmt.Errorf("%w: invalid binding port %d (must be 1-65535)", ErrBindingValidation, p)
			}
		}
	}
	var setClauses []string
	var args []any
	if u.Destination != nil {
		if err := validateDestinationGlob(*u.Destination); err != nil {
			return fmt.Errorf("%w: %w", ErrBindingValidation, err)
		}
		setClauses = append(setClauses, "destination = ?")
		args = append(args, *u.Destination)
	}
	if u.Ports != nil {
		setClauses = append(setClauses, "ports = ?")
		args = append(args, portsToJSONPtr(*u.Ports))
	}
	if u.Header != nil {
		setClauses = append(setClauses, "header = ?")
		args = append(args, nilIfEmpty(*u.Header))
	}
	if u.Template != nil {
		setClauses = append(setClauses, "template = ?")
		args = append(args, nilIfEmpty(*u.Template))
	}
	if u.Protocols != nil {
		setClauses = append(setClauses, "protocols = ?")
		args = append(args, protocolsToJSONPtr(*u.Protocols))
	}
	if u.EnvVar != nil {
		if *u.EnvVar != "" {
			if err := container.ValidateEnvVarKey(*u.EnvVar); err != nil {
				return fmt.Errorf("%w: %w", ErrBindingValidation, err)
			}
			// The uniqueness check excludes this binding so other bindings
			// of the same credential can share an env_var (they resolve to
			// the same phantom value).
			if err := checkEnvVarUniqueWithExcluding(tx, *u.EnvVar, credential, id); err != nil {
				return fmt.Errorf("%w: %w", ErrBindingValidation, err)
			}
		}
		setClauses = append(setClauses, "env_var = ?")
		args = append(args, nilIfEmpty(*u.EnvVar))
	}
	if len(setClauses) == 0 {
		// Empty update is treated as a no-op once the caller has confirmed
		// the row exists. UpdateBindingWithRuleSync already loaded the row
		// before calling us, so we know the binding exists at this point.
		return nil
	}
	args = append(args, id)
	query := "UPDATE bindings SET " + strings.Join(setClauses, ", ") + " WHERE id = ?"
	res, err := tx.Exec(query, args...)
	if err != nil {
		if isBindingUniqueViolation(err) && u.Destination != nil {
			return duplicateBindingError(tx, credential, *u.Destination)
		}
		return fmt.Errorf("update binding %d: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected for binding %d: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("%w: id %d", ErrBindingNotFound, id)
	}
	return nil
}

// pairedRuleSync describes the fields a caller wants to propagate from a
// binding update to the paired auto-created allow rule. Non-nil fields are
// written to the rule, nil fields are left untouched. newDestination is also
// used to locate the paired rule (together with the old destination) so
// updates stay idempotent when callers pass only ports/protocols changes.
type pairedRuleSync struct {
	newDestination *string
	newPorts       *[]int
	newProtocols   *[]string
}

// updatePairedRuleTx finds the auto-created allow rules paired with a
// binding (tagged "binding-add:<credential>" or "cred-add:<credential>")
// at the old destination and rewrites the requested fields. Destination,
// ports, and protocols are propagated to each matching rule when present
// in sync. Header, template, and env_var are binding-only and are not
// handled here. It runs inside an existing *sql.Tx so the rule update
// joins the binding update in the same serialized write, avoiding any
// TOCTOU window.
//
// Both source prefixes are walked even when the first query returns a
// match. A credential may carry an auto-created rule from its initial
// "cred add --destination" (cred-add:<cred>) alongside a later
// "binding add" against the same destination (binding-add:<cred>).
// Updating only one leaves the other stale, so we update every matching
// row and return the id of the first match (or 0 if nothing matched)
// plus a bool indicating whether any rule was found. The caller uses
// the returned id only for logging.
func updatePairedRuleTx(tx *sql.Tx, credential, oldDestination string, sync pairedRuleSync) (int64, bool, error) {
	if sync.newDestination != nil && *sync.newDestination == "" {
		return 0, false, fmt.Errorf("%w: new destination cannot be empty", ErrBindingValidation)
	}
	if sync.newPorts != nil {
		for _, p := range *sync.newPorts {
			if p < 1 || p > 65535 {
				return 0, false, fmt.Errorf("%w: invalid port %d (must be 1-65535)", ErrBindingValidation, p)
			}
		}
	}

	// Collect ids across both source prefixes. A credential may legitimately
	// own rules tagged with both prefixes at the same destination, so we
	// cannot stop after the first hit. Iterating with rows.Next() would keep
	// the read cursor open across the UPDATE below; buffer into a slice
	// instead so the UPDATE does not contend with an open query.
	var ruleIDs []int64
	for _, src := range []string{
		BindingAddSourcePrefix + credential,
		CredAddSourcePrefix + credential,
	} {
		// Match destinations case-insensitively. Policy compilation and
		// the bindings UNIQUE index both treat destinations as
		// case-insensitive, so upgraded databases may still carry a
		// paired rule whose destination differs in case from the binding.
		// A case-sensitive lookup would miss that rule and leave it
		// orphaned after an update.
		rows, err := tx.Query(
			"SELECT id FROM rules WHERE source = ? AND LOWER(destination) = LOWER(?) ORDER BY id",
			src, oldDestination,
		)
		if err != nil {
			return 0, false, fmt.Errorf("find rule by source: %w", err)
		}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return 0, false, fmt.Errorf("scan rule id: %w", err)
			}
			ruleIDs = append(ruleIDs, id)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return 0, false, fmt.Errorf("iterate rule ids: %w", err)
		}
		if err := rows.Close(); err != nil {
			return 0, false, fmt.Errorf("close rule query: %w", err)
		}
	}

	if len(ruleIDs) == 0 {
		return 0, false, nil
	}

	var setClauses []string
	var baseArgs []any
	if sync.newDestination != nil {
		setClauses = append(setClauses, "destination = ?")
		baseArgs = append(baseArgs, *sync.newDestination)
	}
	if sync.newPorts != nil {
		setClauses = append(setClauses, "ports = ?")
		baseArgs = append(baseArgs, portsToJSONPtr(*sync.newPorts))
	}
	if sync.newProtocols != nil {
		setClauses = append(setClauses, "protocols = ?")
		baseArgs = append(baseArgs, protocolsToJSONPtr(*sync.newProtocols))
	}
	if len(setClauses) == 0 {
		// Nothing to propagate, but we still report the match so the caller
		// can log a clean "paired rule found" path instead of "no rule".
		return ruleIDs[0], true, nil
	}

	query := "UPDATE rules SET " + strings.Join(setClauses, ", ") + " WHERE id = ?"
	for _, id := range ruleIDs {
		args := append(append([]any(nil), baseArgs...), id)
		if _, err := tx.Exec(query, args...); err != nil {
			return 0, false, fmt.Errorf("update paired rule %d: %w", id, err)
		}
	}
	return ruleIDs[0], true, nil
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
		return 0, 0, fmt.Errorf("%w: verdict is required", ErrBindingValidation)
	}
	if !validVerdict(verdict) {
		return 0, 0, fmt.Errorf("%w: invalid verdict %q: must be allow, deny, ask, or redact", ErrBindingValidation, verdict)
	}
	if ruleOpts.Destination == "" {
		return 0, 0, fmt.Errorf("%w: destination is required for rule+binding", ErrBindingValidation)
	}
	if err := validateDestinationGlob(ruleOpts.Destination); err != nil {
		return 0, 0, fmt.Errorf("%w: %w", ErrBindingValidation, err)
	}
	if credential == "" {
		return 0, 0, fmt.Errorf("%w: credential name is required", ErrBindingValidation)
	}
	// Validate port ranges up front so bad input is rejected before the
	// insert. AddRule performs the same 1-65535 check for plain rule adds;
	// without this here, out-of-range ports only fail later at engine
	// recompile time, which the API layer logs but does not surface.
	for _, p := range ruleOpts.Ports {
		if p < 1 || p > 65535 {
			return 0, 0, fmt.Errorf("%w: invalid rule port %d (must be 1-65535)", ErrBindingValidation, p)
		}
	}
	for _, p := range bindingOpts.Ports {
		if p < 1 || p > 65535 {
			return 0, 0, fmt.Errorf("%w: invalid binding port %d (must be 1-65535)", ErrBindingValidation, p)
		}
	}
	// Validate protocol names on both the rule and the binding before
	// touching the database. Without this, a typo like "htp" would be
	// stored silently and only surface as a protocol mismatch at
	// connection time. Share the allow list with TOML import via
	// validateProtocols.
	if err := validateProtocols(ruleOpts.Protocols, fmt.Sprintf("rule %q", ruleOpts.Destination)); err != nil {
		return 0, 0, fmt.Errorf("%w: %w", ErrBindingValidation, err)
	}
	if err := validateProtocols(bindingOpts.Protocols, fmt.Sprintf("binding %q->%q", ruleOpts.Destination, credential)); err != nil {
		return 0, 0, fmt.Errorf("%w: %w", ErrBindingValidation, err)
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
			return 0, 0, fmt.Errorf("%w: %w", ErrBindingValidation, valErr)
		}
		if uniqueErr := checkEnvVarUniqueWith(tx, bindingOpts.EnvVar, credential); uniqueErr != nil {
			return 0, 0, fmt.Errorf("%w: %w", ErrBindingValidation, uniqueErr)
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
		if isBindingUniqueViolation(err) {
			// Query via the same transaction because the pool holds one
			// connection and the outer tx still owns it.
			return 0, 0, duplicateBindingError(tx, credential, ruleOpts.Destination)
		}
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

// RemoveCredentialMetaCAS deletes a credential metadata row only when its
// current cred_type and token_url match the supplied expected values. It is
// the compare-and-swap counterpart to RemoveCredentialMeta and is used during
// rollback after a failed cred add path: a concurrent writer may have
// upserted the row with different values in between our insert and our
// rollback, and deleting blindly would wipe their state.
//
// Returned values:
//   - removed=true, noConcurrent=true: the row matched and was deleted
//   - removed=false, noConcurrent=true: the row was already gone
//   - removed=false, noConcurrent=false: the row exists but was modified by
//     a concurrent writer. The caller should log a warning and leave it alone
//   - err is non-nil only on a real I/O failure
func (s *Store) RemoveCredentialMetaCAS(name, expectedType, expectedTokenURL string) (removed, noConcurrent bool, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, false, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var credType string
	var tokenURL sql.NullString
	row := tx.QueryRow("SELECT cred_type, token_url FROM credential_meta WHERE name = ?", name)
	if scanErr := row.Scan(&credType, &tokenURL); scanErr != nil {
		if scanErr == sql.ErrNoRows {
			// Row is already gone. Treat this as a benign no-op: the caller
			// was going to delete it anyway, so there is nothing left to
			// protect.
			if commitErr := tx.Commit(); commitErr != nil {
				return false, true, fmt.Errorf("commit: %w", commitErr)
			}
			return false, true, nil
		}
		return false, false, fmt.Errorf("read credential meta for CAS: %w", scanErr)
	}

	if credType != expectedType || tokenURL.String != expectedTokenURL {
		// Concurrent writer has overwritten the row. Leave it alone.
		return false, false, nil
	}

	res, err := tx.Exec("DELETE FROM credential_meta WHERE name = ? AND cred_type = ? AND COALESCE(token_url, '') = ?",
		name, expectedType, expectedTokenURL)
	if err != nil {
		return false, false, fmt.Errorf("delete credential meta: %w", err)
	}
	if commitErr := tx.Commit(); commitErr != nil {
		return false, false, fmt.Errorf("commit: %w", commitErr)
	}
	n, _ := res.RowsAffected()
	return n > 0, true, nil
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
