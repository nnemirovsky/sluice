package store

import (
	"database/sql"
	"fmt"
	"time"
)

// PoolStrategyFailover is the only supported pool strategy. Round-robin and
// weighted strategies are reserved for future work; the schema CHECK keeps
// the column constrained to this value.
const PoolStrategyFailover = "failover"

// Pool is a named group of OAuth credentials backing a single phantom
// identity. Members are returned ordered by position (failover order).
type Pool struct {
	Name      string
	Strategy  string
	CreatedAt string
	Members   []PoolMember
}

// PoolMember is one credential entry in a pool. Position determines the
// failover order (lowest first).
type PoolMember struct {
	Credential string
	Position   int
}

// CredentialHealth records whether a credential is currently eligible for
// injection. A cooled-down member is skipped during active-member selection
// until CooldownUntil passes (lazy recovery, no scheduler).
type CredentialHealth struct {
	Credential        string
	Status            string    // "healthy" or "cooldown"
	CooldownUntil     time.Time // zero when Status == "healthy" or unset
	LastFailureReason string
	UpdatedAt         string
}

// parseHealthTime parses a cooldown_until value. Values are written as
// RFC3339 (SetCredentialHealth), but a NULL or empty string yields the zero
// time. A legacy "2006-01-02 15:04:05" SQLite datetime form is also accepted
// defensively.
func parseHealthTime(s sql.NullString) time.Time {
	if !s.Valid || s.String == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s.String); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02 15:04:05", s.String); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

// PoolExists reports whether a pool with the given name exists.
func (s *Store) PoolExists(name string) (bool, error) {
	var one int
	err := s.db.QueryRow("SELECT 1 FROM credential_pools WHERE name = ?", name).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check pool exists %q: %w", name, err)
	}
	return true, nil
}

// validatePoolMemberTx verifies a credential is an existing OAuth credential
// with a non-empty token_url. Static credentials are rejected because the
// pool failover machinery is OAuth-specific (phantom indirection, refresh
// attribution). Runs inside the supplied transaction so the check and the
// member insert are atomic.
func validatePoolMemberTx(tx *sql.Tx, credential string) error {
	var credType string
	var tokenURL sql.NullString
	err := tx.QueryRow(
		"SELECT cred_type, token_url FROM credential_meta WHERE name = ?", credential,
	).Scan(&credType, &tokenURL)
	if err == sql.ErrNoRows {
		return fmt.Errorf("credential %q does not exist (add it with --type oauth first)", credential)
	}
	if err != nil {
		return fmt.Errorf("look up credential %q: %w", credential, err)
	}
	if credType != "oauth" {
		return fmt.Errorf("credential %q is %s, pools require oauth credentials", credential, credType)
	}
	if tokenURL.String == "" {
		return fmt.Errorf("credential %q has no token_url; pools require oauth credentials with a token endpoint", credential)
	}
	return nil
}

// CreatePoolWithMembers creates a pool and its ordered members atomically.
// Member positions are assigned from the slice order (0-based). It enforces
// the pool/credential namespace mutual-exclusion (a pool name must not
// collide with an existing credential) and validates every member is an
// existing oauth credential with a token_url. At least two members are
// required for failover to be meaningful, but a single-member pool is
// permitted (it degrades to a plain indirection with no failover target).
func (s *Store) CreatePoolWithMembers(name, strategy string, members []string) error {
	if name == "" {
		return fmt.Errorf("pool name is required")
	}
	if strategy == "" {
		strategy = PoolStrategyFailover
	}
	if strategy != PoolStrategyFailover {
		return fmt.Errorf("invalid pool strategy %q: only %q is supported", strategy, PoolStrategyFailover)
	}
	if len(members) == 0 {
		return fmt.Errorf("pool %q requires at least one member", name)
	}
	seen := make(map[string]bool, len(members))
	for _, m := range members {
		if m == "" {
			return fmt.Errorf("pool %q has an empty member name", name)
		}
		if seen[m] {
			return fmt.Errorf("pool %q lists credential %q more than once", name, m)
		}
		seen[m] = true
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Namespace mutual-exclusion: a pool must not shadow a credential.
	var credName string
	switch err := tx.QueryRow("SELECT name FROM credential_meta WHERE name = ?", name).Scan(&credName); {
	case err == nil:
		return fmt.Errorf("name %q is already a credential; pool and credential names share one namespace", name)
	case err == sql.ErrNoRows:
		// ok
	default:
		return fmt.Errorf("check name collision for %q: %w", name, err)
	}

	if _, err := tx.Exec(
		"INSERT INTO credential_pools (name, strategy) VALUES (?, ?)", name, strategy,
	); err != nil {
		return fmt.Errorf("insert pool %q: %w", name, err)
	}

	for i, m := range members {
		if err := validatePoolMemberTx(tx, m); err != nil {
			return err
		}
		if _, err := tx.Exec(
			"INSERT INTO credential_pool_members (pool, credential, position) VALUES (?, ?, ?)",
			name, m, i,
		); err != nil {
			return fmt.Errorf("insert pool member %q: %w", m, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// GetPool returns a pool by name with members ordered by position, or nil if
// the pool does not exist.
func (s *Store) GetPool(name string) (*Pool, error) {
	var p Pool
	err := s.db.QueryRow(
		"SELECT name, strategy, created_at FROM credential_pools WHERE name = ?", name,
	).Scan(&p.Name, &p.Strategy, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get pool %q: %w", name, err)
	}

	rows, err := s.db.Query(
		"SELECT credential, position FROM credential_pool_members WHERE pool = ? ORDER BY position", name,
	)
	if err != nil {
		return nil, fmt.Errorf("list pool members %q: %w", name, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var m PoolMember
		if err := rows.Scan(&m.Credential, &m.Position); err != nil {
			return nil, fmt.Errorf("scan pool member: %w", err)
		}
		p.Members = append(p.Members, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &p, nil
}

// ListPools returns all pools with their members ordered by position.
func (s *Store) ListPools() ([]Pool, error) {
	rows, err := s.db.Query("SELECT name, strategy, created_at FROM credential_pools ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("list pools: %w", err)
	}
	var names []string
	pools := make(map[string]*Pool)
	for rows.Next() {
		var p Pool
		if err := rows.Scan(&p.Name, &p.Strategy, &p.CreatedAt); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan pool: %w", err)
		}
		cp := p
		pools[p.Name] = &cp
		names = append(names, p.Name)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()

	mrows, err := s.db.Query(
		"SELECT pool, credential, position FROM credential_pool_members ORDER BY pool, position",
	)
	if err != nil {
		return nil, fmt.Errorf("list pool members: %w", err)
	}
	defer func() { _ = mrows.Close() }()
	for mrows.Next() {
		var pool string
		var m PoolMember
		if err := mrows.Scan(&pool, &m.Credential, &m.Position); err != nil {
			return nil, fmt.Errorf("scan pool member: %w", err)
		}
		if p, ok := pools[pool]; ok {
			p.Members = append(p.Members, m)
		}
	}
	if err := mrows.Err(); err != nil {
		return nil, err
	}

	result := make([]Pool, 0, len(names))
	for _, n := range names {
		result = append(result, *pools[n])
	}
	return result, nil
}

// RemovePool deletes a pool and (via ON DELETE CASCADE) its members. Returns
// true if a pool row was deleted.
func (s *Store) RemovePool(name string) (bool, error) {
	res, err := s.db.Exec("DELETE FROM credential_pools WHERE name = ?", name)
	if err != nil {
		return false, fmt.Errorf("delete pool %q: %w", name, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// PoolsForMember returns the names of all pools that include the given
// credential as a member. Used to block "cred remove" of a live pool member
// so no dangling member rows are left behind.
func (s *Store) PoolsForMember(credential string) ([]string, error) {
	rows, err := s.db.Query(
		"SELECT pool FROM credential_pool_members WHERE credential = ? ORDER BY pool", credential,
	)
	if err != nil {
		return nil, fmt.Errorf("list pools for member %q: %w", credential, err)
	}
	defer func() { _ = rows.Close() }()
	var pools []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("scan pool name: %w", err)
		}
		pools = append(pools, p)
	}
	return pools, rows.Err()
}

// SetCredentialHealth upserts a credential's health row. When status is
// "healthy" the cooldown is cleared. cooldown_until is stored as RFC3339.
func (s *Store) SetCredentialHealth(credential, status string, cooldownUntil time.Time, reason string) error {
	if credential == "" {
		return fmt.Errorf("credential name is required")
	}
	if status != "healthy" && status != "cooldown" {
		return fmt.Errorf("invalid health status %q: must be healthy or cooldown", status)
	}
	var cu interface{}
	if status == "cooldown" && !cooldownUntil.IsZero() {
		cu = cooldownUntil.UTC().Format(time.RFC3339)
	} else {
		cu = nil
	}
	_, err := s.db.Exec(
		`INSERT INTO credential_health (credential, status, cooldown_until, last_failure_reason, updated_at)
		 VALUES (?, ?, ?, ?, datetime('now'))
		 ON CONFLICT(credential) DO UPDATE SET
		   status = excluded.status,
		   cooldown_until = excluded.cooldown_until,
		   last_failure_reason = excluded.last_failure_reason,
		   updated_at = excluded.updated_at`,
		credential, status, cu, nilIfEmpty(reason),
	)
	if err != nil {
		return fmt.Errorf("set credential health %q: %w", credential, err)
	}
	return nil
}

// GetCredentialHealth returns the health row for a credential, or nil if no
// row exists (which callers treat as healthy). This is an intentional
// single-row introspection surface (tests, and a targeted lookup the
// failover/reconcile paths can use instead of scanning ListCredentialHealth);
// it is not currently on a hot path.
func (s *Store) GetCredentialHealth(credential string) (*CredentialHealth, error) {
	var h CredentialHealth
	var cu, reason sql.NullString
	err := s.db.QueryRow(
		"SELECT credential, status, cooldown_until, last_failure_reason, updated_at FROM credential_health WHERE credential = ?",
		credential,
	).Scan(&h.Credential, &h.Status, &cu, &reason, &h.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get credential health %q: %w", credential, err)
	}
	h.CooldownUntil = parseHealthTime(cu)
	h.LastFailureReason = reason.String
	return &h, nil
}

// ListCredentialHealth returns all credential health rows ordered by name.
func (s *Store) ListCredentialHealth() ([]CredentialHealth, error) {
	rows, err := s.db.Query(
		"SELECT credential, status, cooldown_until, last_failure_reason, updated_at FROM credential_health ORDER BY credential",
	)
	if err != nil {
		return nil, fmt.Errorf("list credential health: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []CredentialHealth
	for rows.Next() {
		var h CredentialHealth
		var cu, reason sql.NullString
		if err := rows.Scan(&h.Credential, &h.Status, &cu, &reason, &h.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan credential health: %w", err)
		}
		h.CooldownUntil = parseHealthTime(cu)
		h.LastFailureReason = reason.String
		out = append(out, h)
	}
	return out, rows.Err()
}
