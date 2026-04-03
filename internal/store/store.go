// Package store provides a SQLite-backed policy store for runtime state.
// All policy rules, tool rules, inspect rules, config, bindings, and MCP
// upstreams are persisted in a single SQLite database.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// Store wraps a SQLite database for policy and configuration persistence.
type Store struct {
	db *sql.DB
}

// New opens or creates a SQLite database at the given path and runs
// schema migrations. Use ":memory:" for an in-memory database (tests).
func New(path string) (*Store, error) {
	dsn := path
	if path == ":memory:" {
		// Shared cache ensures all connections in the pool see the same
		// in-memory database (needed for concurrent access in tests).
		dsn = "file::memory:?cache=shared"
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
		db.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}
	// Set busy timeout so concurrent writers retry instead of returning
	// SQLITE_BUSY immediately. 5 seconds covers typical contention windows
	// between the proxy, CLI, and Telegram bot writing to the same DB.
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}
	// Enable foreign keys.
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}
	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(schema)
	return err
}

const schema = `
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    verdict TEXT NOT NULL CHECK(verdict IN ('allow', 'deny', 'ask')),
    destination TEXT NOT NULL,
    ports TEXT,
    protocol TEXT,
    note TEXT,
    source TEXT NOT NULL DEFAULT 'manual',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tool_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    verdict TEXT NOT NULL CHECK(verdict IN ('allow', 'deny', 'ask')),
    tool TEXT NOT NULL,
    note TEXT,
    source TEXT NOT NULL DEFAULT 'manual',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS inspect_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK(kind IN ('block', 'redact')),
    pattern TEXT NOT NULL,
    description TEXT,
    target TEXT,
    replacement TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bindings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    destination TEXT NOT NULL,
    ports TEXT,
    credential TEXT NOT NULL,
    inject_header TEXT,
    template TEXT,
    protocol TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS mcp_upstreams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    command TEXT NOT NULL,
    args TEXT,
    env TEXT,
    timeout_sec INTEGER DEFAULT 120,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`

// --- Rule types ---

// NetworkRule represents a row in the rules table.
type NetworkRule struct {
	ID          int64
	Verdict     string
	Destination string
	Ports       []int
	Protocol    string
	Note        string
	Source      string
	CreatedAt   string
}

// RuleOpts holds optional fields for AddRule.
type RuleOpts struct {
	Protocol string
	Note     string
	Source   string
}

// AddRule inserts a network rule and returns its ID.
func (s *Store) AddRule(verdict, destination string, ports []int, opts RuleOpts) (int64, error) {
	if verdict == "" || destination == "" {
		return 0, fmt.Errorf("verdict and destination are required")
	}
	source := opts.Source
	if source == "" {
		source = "manual"
	}
	var portsJSON *string
	if len(ports) > 0 {
		b, _ := json.Marshal(ports)
		ps := string(b)
		portsJSON = &ps
	}
	res, err := s.db.Exec(
		`INSERT INTO rules (verdict, destination, ports, protocol, note, source) VALUES (?, ?, ?, ?, ?, ?)`,
		verdict, destination, portsJSON, nilIfEmpty(opts.Protocol), nilIfEmpty(opts.Note), source,
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

// ListRules returns rules, optionally filtered by verdict (empty string = all).
func (s *Store) ListRules(verdict string) ([]NetworkRule, error) {
	query := "SELECT id, verdict, destination, ports, protocol, note, source, created_at FROM rules"
	var args []any
	if verdict != "" {
		query += " WHERE verdict = ?"
		args = append(args, verdict)
	}
	query += " ORDER BY id"
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	defer rows.Close()

	var rules []NetworkRule
	for rows.Next() {
		var r NetworkRule
		var portsJSON, protocol, note sql.NullString
		if err := rows.Scan(&r.ID, &r.Verdict, &r.Destination, &portsJSON, &protocol, &note, &r.Source, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan rule: %w", err)
		}
		if portsJSON.Valid {
			if err := json.Unmarshal([]byte(portsJSON.String), &r.Ports); err != nil {
				return nil, fmt.Errorf("unmarshal ports for rule %d: %w", r.ID, err)
			}
		}
		r.Protocol = protocol.String
		r.Note = note.String
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// --- Tool Rules ---

// ToolRuleRow represents a row in the tool_rules table.
type ToolRuleRow struct {
	ID        int64
	Verdict   string
	Tool      string
	Note      string
	Source    string
	CreatedAt string
}

// AddToolRule inserts a tool rule and returns its ID.
func (s *Store) AddToolRule(verdict, tool, note, source string) (int64, error) {
	if verdict == "" || tool == "" {
		return 0, fmt.Errorf("verdict and tool are required")
	}
	if source == "" {
		source = "manual"
	}
	res, err := s.db.Exec(
		`INSERT INTO tool_rules (verdict, tool, note, source) VALUES (?, ?, ?, ?)`,
		verdict, tool, nilIfEmpty(note), source,
	)
	if err != nil {
		return 0, fmt.Errorf("insert tool rule: %w", err)
	}
	return res.LastInsertId()
}

// RemoveToolRule deletes a tool rule by ID. Returns true if a row was deleted.
func (s *Store) RemoveToolRule(id int64) (bool, error) {
	res, err := s.db.Exec("DELETE FROM tool_rules WHERE id = ?", id)
	if err != nil {
		return false, fmt.Errorf("delete tool rule: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListToolRules returns tool rules, optionally filtered by verdict.
func (s *Store) ListToolRules(verdict string) ([]ToolRuleRow, error) {
	query := "SELECT id, verdict, tool, note, source, created_at FROM tool_rules"
	var args []any
	if verdict != "" {
		query += " WHERE verdict = ?"
		args = append(args, verdict)
	}
	query += " ORDER BY id"
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list tool rules: %w", err)
	}
	defer rows.Close()

	var rules []ToolRuleRow
	for rows.Next() {
		var r ToolRuleRow
		var note sql.NullString
		if err := rows.Scan(&r.ID, &r.Verdict, &r.Tool, &note, &r.Source, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan tool rule: %w", err)
		}
		r.Note = note.String
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// --- Inspect Rules ---

// InspectRuleRow represents a row in the inspect_rules table.
type InspectRuleRow struct {
	ID          int64
	Kind        string
	Pattern     string
	Description string
	Target      string
	Replacement string
	CreatedAt   string
}

// InspectRuleOpts holds optional fields for AddInspectRule.
type InspectRuleOpts struct {
	Description string
	Target      string
	Replacement string
}

// AddInspectRule inserts an inspect rule and returns its ID.
func (s *Store) AddInspectRule(kind, pattern string, opts InspectRuleOpts) (int64, error) {
	if kind == "" || pattern == "" {
		return 0, fmt.Errorf("kind and pattern are required")
	}
	res, err := s.db.Exec(
		`INSERT INTO inspect_rules (kind, pattern, description, target, replacement) VALUES (?, ?, ?, ?, ?)`,
		kind, pattern, nilIfEmpty(opts.Description), nilIfEmpty(opts.Target), nilIfEmpty(opts.Replacement),
	)
	if err != nil {
		return 0, fmt.Errorf("insert inspect rule: %w", err)
	}
	return res.LastInsertId()
}

// RemoveInspectRule deletes an inspect rule by ID. Returns true if a row was deleted.
func (s *Store) RemoveInspectRule(id int64) (bool, error) {
	res, err := s.db.Exec("DELETE FROM inspect_rules WHERE id = ?", id)
	if err != nil {
		return false, fmt.Errorf("delete inspect rule: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListInspectRules returns all inspect rules, optionally filtered by kind.
func (s *Store) ListInspectRules(kind string) ([]InspectRuleRow, error) {
	query := "SELECT id, kind, pattern, description, target, replacement, created_at FROM inspect_rules"
	var args []any
	if kind != "" {
		query += " WHERE kind = ?"
		args = append(args, kind)
	}
	query += " ORDER BY id"
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list inspect rules: %w", err)
	}
	defer rows.Close()

	var rules []InspectRuleRow
	for rows.Next() {
		var r InspectRuleRow
		var desc, target, repl sql.NullString
		if err := rows.Scan(&r.ID, &r.Kind, &r.Pattern, &desc, &target, &repl, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan inspect rule: %w", err)
		}
		r.Description = desc.String
		r.Target = target.String
		r.Replacement = repl.String
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// --- Config ---

// GetConfig returns the value for a config key. Returns empty string and no
// error if the key does not exist.
func (s *Store) GetConfig(key string) (string, error) {
	var value string
	err := s.db.QueryRow("SELECT value FROM config WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get config %q: %w", key, err)
	}
	return value, nil
}

// SetConfig upserts a config key-value pair.
func (s *Store) SetConfig(key, value string) error {
	if key == "" {
		return fmt.Errorf("config key is required")
	}
	_, err := s.db.Exec(
		`INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	if err != nil {
		return fmt.Errorf("set config %q: %w", key, err)
	}
	return nil
}

// --- Bindings ---

// BindingRow represents a row in the bindings table.
type BindingRow struct {
	ID           int64
	Destination  string
	Ports        []int
	Credential   string
	InjectHeader string
	Template     string
	Protocol     string
	CreatedAt    string
}

// BindingOpts holds optional fields for AddBinding.
type BindingOpts struct {
	Ports        []int
	InjectHeader string
	Template     string
	Protocol     string
}

// AddBinding inserts a binding and returns its ID.
func (s *Store) AddBinding(destination, credential string, opts BindingOpts) (int64, error) {
	if destination == "" || credential == "" {
		return 0, fmt.Errorf("destination and credential are required")
	}
	var portsJSON *string
	if len(opts.Ports) > 0 {
		b, _ := json.Marshal(opts.Ports)
		ps := string(b)
		portsJSON = &ps
	}
	res, err := s.db.Exec(
		`INSERT INTO bindings (destination, ports, credential, inject_header, template, protocol) VALUES (?, ?, ?, ?, ?, ?)`,
		destination, portsJSON, credential,
		nilIfEmpty(opts.InjectHeader), nilIfEmpty(opts.Template), nilIfEmpty(opts.Protocol),
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
		"SELECT id, destination, ports, credential, inject_header, template, protocol, created_at FROM bindings ORDER BY id",
	)
	if err != nil {
		return nil, fmt.Errorf("list bindings: %w", err)
	}
	defer rows.Close()

	var bindings []BindingRow
	for rows.Next() {
		var b BindingRow
		var portsJSON, header, tmpl, proto sql.NullString
		if err := rows.Scan(&b.ID, &b.Destination, &portsJSON, &b.Credential, &header, &tmpl, &proto, &b.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan binding: %w", err)
		}
		if portsJSON.Valid {
			if err := json.Unmarshal([]byte(portsJSON.String), &b.Ports); err != nil {
				return nil, fmt.Errorf("unmarshal ports for binding %d: %w", b.ID, err)
			}
		}
		b.InjectHeader = header.String
		b.Template = tmpl.String
		b.Protocol = proto.String
		bindings = append(bindings, b)
	}
	return bindings, rows.Err()
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
	CreatedAt  string
}

// MCPUpstreamOpts holds optional fields for AddMCPUpstream.
type MCPUpstreamOpts struct {
	Args       []string
	Env        map[string]string
	TimeoutSec int
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
		`INSERT INTO mcp_upstreams (name, command, args, env, timeout_sec) VALUES (?, ?, ?, ?, ?)`,
		name, command, argsJSON, envJSON, timeoutSec,
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
		"SELECT id, name, command, args, env, timeout_sec, created_at FROM mcp_upstreams ORDER BY id",
	)
	if err != nil {
		return nil, fmt.Errorf("list upstreams: %w", err)
	}
	defer rows.Close()

	var upstreams []MCPUpstreamRow
	for rows.Next() {
		var u MCPUpstreamRow
		var argsJSON, envJSON sql.NullString
		if err := rows.Scan(&u.ID, &u.Name, &u.Command, &argsJSON, &envJSON, &u.TimeoutSec, &u.CreatedAt); err != nil {
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

// --- RuleExists helpers ---

// RuleExists checks if a network rule with the given verdict, destination, and
// ports already exists. Used for merge/dedup during import.
func (s *Store) RuleExists(verdict, destination string, ports []int) (bool, error) {
	var portsJSON *string
	if len(ports) > 0 {
		b, _ := json.Marshal(ports)
		ps := string(b)
		portsJSON = &ps
	}
	var count int
	var err error
	if portsJSON != nil {
		err = s.db.QueryRow(
			"SELECT COUNT(*) FROM rules WHERE verdict = ? AND destination = ? AND ports = ?",
			verdict, destination, *portsJSON,
		).Scan(&count)
	} else {
		err = s.db.QueryRow(
			"SELECT COUNT(*) FROM rules WHERE verdict = ? AND destination = ? AND ports IS NULL",
			verdict, destination,
		).Scan(&count)
	}
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// ToolRuleExists checks if a tool rule with the given verdict and tool already exists.
func (s *Store) ToolRuleExists(verdict, tool string) (bool, error) {
	var count int
	err := s.db.QueryRow(
		"SELECT COUNT(*) FROM tool_rules WHERE verdict = ? AND tool = ?",
		verdict, tool,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

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
		"SELECT id, destination, ports, credential, inject_header, template, protocol, created_at FROM bindings WHERE credential = ? ORDER BY id",
		credential,
	)
	if err != nil {
		return nil, fmt.Errorf("list bindings by credential: %w", err)
	}
	defer rows.Close()

	var bindings []BindingRow
	for rows.Next() {
		var b BindingRow
		var portsJSON, header, tmpl, proto sql.NullString
		if err := rows.Scan(&b.ID, &b.Destination, &portsJSON, &b.Credential, &header, &tmpl, &proto, &b.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan binding: %w", err)
		}
		if portsJSON.Valid {
			if err := json.Unmarshal([]byte(portsJSON.String), &b.Ports); err != nil {
				return nil, fmt.Errorf("unmarshal ports for binding %d: %w", b.ID, err)
			}
		}
		b.InjectHeader = header.String
		b.Template = tmpl.String
		b.Protocol = proto.String
		bindings = append(bindings, b)
	}
	return bindings, rows.Err()
}

// RemoveBindingsByCredential deletes all bindings for a credential. Returns the number deleted.
func (s *Store) RemoveBindingsByCredential(credential string) (int64, error) {
	res, err := s.db.Exec("DELETE FROM bindings WHERE credential = ?", credential)
	if err != nil {
		return 0, fmt.Errorf("delete bindings by credential: %w", err)
	}
	return res.RowsAffected()
}

// RemoveRulesByDestinationAndSource deletes rules matching a destination and source.
// Returns the number deleted.
func (s *Store) RemoveRulesByDestinationAndSource(destination, source string) (int64, error) {
	res, err := s.db.Exec("DELETE FROM rules WHERE destination = ? AND source = ?", destination, source)
	if err != nil {
		return 0, fmt.Errorf("delete rules by destination+source: %w", err)
	}
	return res.RowsAffected()
}

// --- Store queries ---

// IsEmpty returns true if the store has no rules, tool rules, bindings, config
// entries, inspect rules, or MCP upstreams. Used to detect a fresh database
// that should be seeded.
func (s *Store) IsEmpty() (bool, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT (SELECT COUNT(*) FROM rules) +
		        (SELECT COUNT(*) FROM tool_rules) +
		        (SELECT COUNT(*) FROM config) +
		        (SELECT COUNT(*) FROM bindings) +
		        (SELECT COUNT(*) FROM inspect_rules) +
		        (SELECT COUNT(*) FROM mcp_upstreams)`,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check store empty: %w", err)
	}
	return count == 0, nil
}

// --- Helpers ---

// nilIfEmpty returns nil for empty strings, allowing SQLite to store NULL.
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

