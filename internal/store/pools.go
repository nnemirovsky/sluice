package store

import (
	"database/sql"
	"errors"
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
// failover order (lowest first). Epoch is the value of the monotonic
// pool_membership_epoch counter at the time this membership row was
// inserted: a remove/re-add of the same (pool, credential) yields a
// strictly greater epoch, so a stale in-flight failover write that carries
// the OLD epoch can be told apart from its re-created successor and no-ops
// instead of parking the new member with the old response's cooldown.
type PoolMember struct {
	Credential string
	Position   int
	Epoch      int64
}

// bumpMembershipEpochTx increments the single-row monotonic
// pool_membership_epoch counter inside the supplied transaction and returns
// the NEW value. Called on every pool create and pool remove so any
// membership change advances the epoch; member inserts in the same
// transaction stamp the returned value onto their rows. Monotonic across
// the process lifetime and across restarts (the counter is durable).
func bumpMembershipEpochTx(tx *sql.Tx) (int64, error) {
	if _, err := tx.Exec(
		"UPDATE pool_membership_epoch SET epoch = epoch + 1 WHERE id = 1",
	); err != nil {
		return 0, fmt.Errorf("bump membership epoch: %w", err)
	}
	var ep int64
	if err := tx.QueryRow(
		"SELECT epoch FROM pool_membership_epoch WHERE id = 1",
	).Scan(&ep); err != nil {
		return 0, fmt.Errorf("read membership epoch: %w", err)
	}
	return ep, nil
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
	if errors.Is(err, sql.ErrNoRows) {
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
	if errors.Is(err, sql.ErrNoRows) {
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

// assertCredentialNotInAnotherPoolTx fails if the credential is already a
// member of a pool other than newPool. A credential may belong to at most
// one pool: proxy attribution (PoolResolver.PoolForMember) maps a member
// back to a SINGLE pool, so a token response for a second pool would be
// persisted/audited against the first pool's phantom, leaving the agent
// with an unreplaceable phantom (Finding 5). Runs inside the supplied
// transaction so the check and the member insert are atomic.
func assertCredentialNotInAnotherPoolTx(tx *sql.Tx, credential, newPool string) error {
	var existing string
	err := tx.QueryRow(
		"SELECT pool FROM credential_pool_members WHERE credential = ? AND pool != ? LIMIT 1",
		credential, newPool,
	).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check existing pool membership for %q: %w", credential, err)
	}
	return fmt.Errorf("credential %q is already a member of pool %q; a credential may belong to at most one pool", credential, existing)
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
	collErr := tx.QueryRow("SELECT name FROM credential_meta WHERE name = ?", name).Scan(&credName)
	switch {
	case collErr == nil:
		return fmt.Errorf("name %q is already a credential; pool and credential names share one namespace", name)
	case errors.Is(collErr, sql.ErrNoRows):
		// ok
	default:
		return fmt.Errorf("check name collision for %q: %w", name, collErr)
	}

	if _, err := tx.Exec(
		"INSERT INTO credential_pools (name, strategy) VALUES (?, ?)", name, strategy,
	); err != nil {
		return fmt.Errorf("insert pool %q: %w", name, err)
	}

	// Advance the monotonic membership epoch and stamp it on every member
	// inserted here. A pool removed and re-created under the same name (or a
	// member removed and re-added) gets a strictly greater epoch, so a stale
	// failover write carrying the OLD epoch cannot apply to the successor.
	epoch, err := bumpMembershipEpochTx(tx)
	if err != nil {
		return err
	}

	for i, m := range members {
		if err := validatePoolMemberTx(tx, m); err != nil {
			return err
		}
		if err := assertCredentialNotInAnotherPoolTx(tx, m, name); err != nil {
			return err
		}
		if _, err := tx.Exec(
			"INSERT INTO credential_pool_members (pool, credential, position, epoch) VALUES (?, ?, ?, ?)",
			name, m, i, epoch,
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
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get pool %q: %w", name, err)
	}

	rows, err := s.db.Query(
		"SELECT credential, position, epoch FROM credential_pool_members WHERE pool = ? ORDER BY position", name,
	)
	if err != nil {
		return nil, fmt.Errorf("list pool members %q: %w", name, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var m PoolMember
		if err := rows.Scan(&m.Credential, &m.Position, &m.Epoch); err != nil {
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
		"SELECT pool, credential, position, epoch FROM credential_pool_members ORDER BY pool, position",
	)
	if err != nil {
		return nil, fmt.Errorf("list pool members: %w", err)
	}
	defer func() { _ = mrows.Close() }()
	for mrows.Next() {
		var pool string
		var m PoolMember
		if err := mrows.Scan(&pool, &m.Credential, &m.Position, &m.Epoch); err != nil {
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
//
// The members' credential_health rows are deleted in the SAME transaction so
// a cooled member taken out with its pool does not leave a stale durable
// cooldown. loadPoolResolver seeds the shared PoolHealth from ALL
// credential_health rows, so an orphaned cooldown would otherwise be
// inherited by the same credential when it is re-added to a new pool before
// the old TTL expires. A member that is still a live member of ANOTHER pool
// keeps its health row (its cooldown is still meaningful for that pool); only
// members no longer in any pool after this delete have their health row
// removed.
func (s *Store) RemovePool(name string) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Snapshot the pool's members before the cascade wipes the membership
	// rows so we know whose health rows to consider for cleanup.
	mrows, err := tx.Query(
		"SELECT credential FROM credential_pool_members WHERE pool = ?", name,
	)
	if err != nil {
		return false, fmt.Errorf("list members of pool %q: %w", name, err)
	}
	var members []string
	for mrows.Next() {
		var c string
		if scanErr := mrows.Scan(&c); scanErr != nil {
			_ = mrows.Close()
			return false, fmt.Errorf("scan pool member: %w", scanErr)
		}
		members = append(members, c)
	}
	if mrowsErr := mrows.Err(); mrowsErr != nil {
		_ = mrows.Close()
		return false, fmt.Errorf("iterate pool members: %w", mrowsErr)
	}
	_ = mrows.Close()

	res, err := tx.Exec("DELETE FROM credential_pools WHERE name = ?", name)
	if err != nil {
		return false, fmt.Errorf("delete pool %q: %w", name, err)
	}
	n, _ := res.RowsAffected()

	if n > 0 {
		// Advance the membership epoch on removal too. A guarded write or a
		// MarkCooldown still carrying this pool generation's epoch will no
		// longer find a matching (credential, pool, epoch) row once the
		// CASCADE has wiped the membership, so a late failover cannot
		// resurrect the removed member's cooldown for a re-created successor.
		if _, err := bumpMembershipEpochTx(tx); err != nil {
			return false, err
		}
		// The CASCADE has now removed this pool's credential_pool_members
		// rows. For each former member, drop its health row UNLESS it is
		// still a member of some OTHER pool (the membership query runs
		// post-cascade, so any remaining row means another pool still owns
		// the credential and its cooldown stays meaningful).
		for _, c := range members {
			var stillPooled int
			err := tx.QueryRow(
				"SELECT 1 FROM credential_pool_members WHERE credential = ? LIMIT 1", c,
			).Scan(&stillPooled)
			switch {
			case errors.Is(err, sql.ErrNoRows):
				if _, delErr := tx.Exec(
					"DELETE FROM credential_health WHERE credential = ?", c,
				); delErr != nil {
					return false, fmt.Errorf("delete health for former pool member %q: %w", c, delErr)
				}
			case err != nil:
				return false, fmt.Errorf("check residual pool membership for %q: %w", c, err)
			default:
				// Still a member of another pool; leave its health row.
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
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

// credentialHealthUpsertSQL is the monotonic-extend upsert shared by the
// unconditional SetCredentialHealth and the guarded
// SetCredentialHealthIfPoolMember. Both paths must apply the identical
// cooldown-extend semantics so a guarded failover write and a manual-rotate
// write cannot diverge in how they collapse competing cooldown TTLs.
//
// Monotonic extend for the durable row, mirroring MarkCooldown's in-memory
// invariant. When the incoming write is a cooldown AND the stored row already
// has a cooldown_until strictly in the future that is LATER than the incoming
// one, keep the stored (longer) value: a short rate-limit cooldown must never
// shorten a longer auth-failure cooldown, even on the durable side, so restart
// durability matches the resolver. Any transition to "healthy"
// (excluded.status = 'healthy', whose cooldown_until is NULL) always
// overwrites, so the recovery/heal path is intact. cooldown_until is always
// written as UTC RFC3339 by the callers, so the string comparison is a valid
// chronological ordering; the datetime('now') guard makes an already expired
// stored cooldown lose to the fresh future one (lazy expiry preserved).
const credentialHealthUpsertSQL = `INSERT INTO credential_health (credential, status, cooldown_until, last_failure_reason, updated_at)
	 VALUES (?, ?, ?, ?, datetime('now'))
	 ON CONFLICT(credential) DO UPDATE SET
	   cooldown_until = CASE
	     WHEN excluded.status = 'cooldown'
	       AND credential_health.cooldown_until IS NOT NULL
	       AND credential_health.cooldown_until > strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
	       AND credential_health.cooldown_until > excluded.cooldown_until
	     THEN credential_health.cooldown_until
	     ELSE excluded.cooldown_until
	   END,
	   status = CASE
	     WHEN excluded.status = 'cooldown'
	       AND credential_health.cooldown_until IS NOT NULL
	       AND credential_health.cooldown_until > strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
	       AND credential_health.cooldown_until > excluded.cooldown_until
	     THEN credential_health.status
	     ELSE excluded.status
	   END,
	   last_failure_reason = CASE
	     WHEN excluded.status = 'cooldown'
	       AND credential_health.cooldown_until IS NOT NULL
	       AND credential_health.cooldown_until > strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
	       AND credential_health.cooldown_until > excluded.cooldown_until
	     THEN credential_health.last_failure_reason
	     ELSE excluded.last_failure_reason
	   END,
	   updated_at = excluded.updated_at`

// validateCredentialHealthArgs validates the inputs shared by both health
// upsert entry points and returns the cooldown_until bind value (string or
// nil) the upsert SQL expects.
func validateCredentialHealthArgs(credential, status string, cooldownUntil time.Time) (interface{}, error) {
	if credential == "" {
		return nil, fmt.Errorf("credential name is required")
	}
	if status != "healthy" && status != "cooldown" {
		return nil, fmt.Errorf("invalid health status %q: must be healthy or cooldown", status)
	}
	if status == "cooldown" && !cooldownUntil.IsZero() {
		return cooldownUntil.UTC().Format(time.RFC3339), nil
	}
	return nil, nil
}

// SetCredentialHealth upserts a credential's health row UNCONDITIONALLY. When
// status is "healthy" the cooldown is cleared. cooldown_until is stored as
// RFC3339. Used by callers that operate on a credential known to be live (the
// manual-rotate path cools the resolver's currently-active member) and by the
// store unit tests that exercise the raw upsert. The failover durable write
// must NOT use this — it can race a pool/credential removal; it uses
// SetCredentialHealthIfPoolMember instead.
func (s *Store) SetCredentialHealth(credential, status string, cooldownUntil time.Time, reason string) error {
	cu, err := validateCredentialHealthArgs(credential, status, cooldownUntil)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(credentialHealthUpsertSQL, credential, status, cu, nilIfEmpty(reason)); err != nil {
		return fmt.Errorf("set credential health %q: %w", credential, err)
	}
	return nil
}

// SetCredentialHealthIfPoolMember performs the same monotonic-extend upsert as
// SetCredentialHealth, but ONLY when the credential is still a live member of
// some pool, with the membership check and the upsert in a SINGLE
// transaction. This closes the failover-vs-removal race: a detached failover
// goroutine that fires AFTER a pool/credential removal (which deletes the
// credential_health row in its own transaction) must not resurrect a health
// row for a credential that no longer belongs to any pool. credential_health
// is not FK-tied to live membership, so a resurrected stale cooldown would
// otherwise be inherited by a later same-named credential the next time
// loadPoolResolver seeds PoolHealth from ALL credential_health rows.
//
// Returns wrote=true when the row was upserted (credential is a live pool
// member: CRITICAL-1 restart durability preserved) and wrote=false when the
// write was skipped because the credential is no longer in any pool (a benign
// no-op the caller logs — a removed member legitimately needs no cooldown).
// The membership SELECT and the upsert share one transaction so a concurrent
// removal cannot interleave between the check and the write.
func (s *Store) SetCredentialHealthIfPoolMember(credential, status string, cooldownUntil time.Time, reason string) (wrote bool, err error) {
	return s.setCredentialHealthGuarded(credential, "", -1, status, cooldownUntil, reason)
}

// SetCredentialHealthIfPoolMemberEpoch is the pool+epoch-scoped guarded
// write. It commits the monotonic-extend cooldown upsert ONLY when a
// credential_pool_members row exists for exactly (credential, pool, epoch),
// with the membership check and the upsert in ONE transaction.
//
// This closes the remove/re-add aliasing hole that the name-only guard left
// open (Cluster A #1/#2/#3). Sequence: pool P with member c (epoch e1) takes
// a 429; remove P; recreate c into a new pool Q (epoch e2 > e1); the
// detached failover goroutine — or a stale old-generation MarkCooldown, or
// a raced `pool rotate` — fires SetCredentialHealthIfPoolMemberEpoch(c, "P",
// e1, ...). The name-only guard would find c present (now in Q) and wrongly
// persist the OLD response's cooldown onto the NEW member. The (pool, epoch)
// predicate finds no row matching ("P", e1) and no-ops (wrote=false). A
// genuinely-still-live member fires with its CURRENT (pool, epoch) and the
// row matches, so CRITICAL-1 restart durability and the round-9/11/14/15
// fixes are preserved.
//
// pool=="" with epoch<0 falls back to the legacy name-only predicate so
// callers without pool/epoch context (and the store unit tests that
// exercise the name-only path) are not regressed.
func (s *Store) SetCredentialHealthIfPoolMemberEpoch(credential, pool string, epoch int64, status string, cooldownUntil time.Time, reason string) (wrote bool, err error) {
	return s.setCredentialHealthGuarded(credential, pool, epoch, status, cooldownUntil, reason)
}

func (s *Store) setCredentialHealthGuarded(credential, pool string, epoch int64, status string, cooldownUntil time.Time, reason string) (wrote bool, err error) {
	cu, verr := validateCredentialHealthArgs(credential, status, cooldownUntil)
	if verr != nil {
		return false, verr
	}

	tx, err := s.db.Begin()
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var live int
	var qerr error
	if pool == "" && epoch < 0 {
		// Legacy name-only predicate (no pool/epoch context).
		qerr = tx.QueryRow(
			"SELECT 1 FROM credential_pool_members WHERE credential = ? LIMIT 1", credential,
		).Scan(&live)
	} else {
		// Pool+epoch-scoped predicate. A stale write carrying the OLD epoch
		// (the membership row was removed and the credential re-added under
		// the same name into another pool with a strictly greater epoch)
		// finds no matching row and is a no-op.
		qerr = tx.QueryRow(
			"SELECT 1 FROM credential_pool_members WHERE credential = ? AND pool = ? AND epoch = ? LIMIT 1",
			credential, pool, epoch,
		).Scan(&live)
	}
	switch {
	case errors.Is(qerr, sql.ErrNoRows):
		// Not a live member of THIS pool at THIS epoch: skip the durable
		// write entirely so a removed/superseded membership's health row is
		// never resurrected onto a re-created successor. No commit needed.
		return false, nil
	case qerr != nil:
		return false, fmt.Errorf("check pool membership for %q: %w", credential, qerr)
	}

	if _, err := tx.Exec(credentialHealthUpsertSQL, credential, status, cu, nilIfEmpty(reason)); err != nil {
		return false, fmt.Errorf("set credential health %q: %w", credential, err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return true, nil
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
	if errors.Is(err, sql.ErrNoRows) {
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
