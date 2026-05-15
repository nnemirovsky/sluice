package vault

import (
	"log"
	"sync"
	"time"

	"github.com/nemirovsky/sluice/internal/store"
)

// Cooldown TTLs applied when a pool member is failed over. A rate-limited
// account usually recovers within the provider's window, so it is retried
// relatively soon. An auth failure (revoked/expired refresh token, bad
// client) will not self-heal quickly, so it is parked far longer to avoid
// thrashing a broken account on every request.
const (
	RateLimitCooldown = 60 * time.Second
	AuthFailCooldown  = 300 * time.Second
)

// memberHealth is the in-memory health view for one credential. Status is
// derived: a credential with a zero cooldownUntil is healthy.
type memberHealth struct {
	cooldownUntil time.Time
	reason        string
}

// PoolResolver maps a pool name to its currently active member. It is the
// single chokepoint every credential consumer routes through (injection
// passes, OAuthIndex.Has gating, persist attribution), so a pool name is
// expanded to a real credential in exactly one place.
//
// Locking discipline: pool membership is immutable for the lifetime of a
// PoolResolver instance (membership changes rebuild a fresh resolver that
// the server atomically pointer-swaps). Health, by contrast, is mutated
// synchronously on the response path during Phase 2 failover, so the health
// map is guarded by mu. ResolveActive takes mu.RLock; MarkCooldown takes
// mu.Lock. Readers therefore always observe a consistent active member even
// while a concurrent response is recording a failover.
type PoolResolver struct {
	// pools maps pool name -> ordered member credential names.
	pools map[string][]string
	// memberOf maps a credential name -> the pools that contain it.
	memberOf map[string][]string

	mu     sync.RWMutex
	health map[string]memberHealth
}

// NewPoolResolver builds a resolver from store snapshots. Health rows with
// status "cooldown" and a future cooldown_until seed the in-memory health
// map; healthy rows and expired cooldowns are treated as eligible.
func NewPoolResolver(pools []store.Pool, healthRows []store.CredentialHealth) *PoolResolver {
	pr := &PoolResolver{
		pools:    make(map[string][]string, len(pools)),
		memberOf: make(map[string][]string),
		health:   make(map[string]memberHealth),
	}
	for _, p := range pools {
		members := make([]string, 0, len(p.Members))
		for _, m := range p.Members {
			members = append(members, m.Credential)
			pr.memberOf[m.Credential] = append(pr.memberOf[m.Credential], p.Name)
		}
		pr.pools[p.Name] = members
	}
	for _, h := range healthRows {
		if h.Status == "cooldown" && !h.CooldownUntil.IsZero() {
			pr.health[h.Credential] = memberHealth{
				cooldownUntil: h.CooldownUntil,
				reason:        h.LastFailureReason,
			}
		}
	}
	return pr
}

// IsPool reports whether name is a configured pool.
func (pr *PoolResolver) IsPool(name string) bool {
	if pr == nil {
		return false
	}
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	_, ok := pr.pools[name]
	return ok
}

// PoolForMember returns the first pool that contains the given credential,
// or "" if the credential is not a pool member. Used by the response path to
// attribute a failover/refresh to its pool for audit + Telegram.
func (pr *PoolResolver) PoolForMember(credential string) string {
	if pr == nil {
		return ""
	}
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if pools := pr.memberOf[credential]; len(pools) > 0 {
		return pools[0]
	}
	return ""
}

// Members returns the ordered member list for a pool (copy), or nil.
func (pr *PoolResolver) Members(pool string) []string {
	if pr == nil {
		return nil
	}
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	m, ok := pr.pools[pool]
	if !ok {
		return nil
	}
	return append([]string(nil), m...)
}

// ResolveActive expands a name to the credential that should actually be
// used. For a plain credential (not a pool) the name is returned unchanged.
// For a pool, the first member that is healthy or whose cooldown has expired
// (in position order) is returned. If every member is still cooling down,
// the member with the soonest recovery is returned and a WARNING is logged
// (degraded: sluice keeps serving with the least-bad account rather than
// failing the request outright).
func (pr *PoolResolver) ResolveActive(name string) (member string, ok bool) {
	if pr == nil {
		return name, true
	}
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	members, isPool := pr.pools[name]
	if !isPool {
		// Plain credential: passthrough unchanged.
		return name, true
	}
	if len(members) == 0 {
		return "", false
	}

	now := time.Now()
	var soonest string
	var soonestUntil time.Time
	for _, m := range members {
		h, tracked := pr.health[m]
		if !tracked || h.cooldownUntil.IsZero() || !h.cooldownUntil.After(now) {
			return m, true
		}
		if soonest == "" || h.cooldownUntil.Before(soonestUntil) {
			soonest = m
			soonestUntil = h.cooldownUntil
		}
	}
	log.Printf("[POOL] all %d members of pool %q are in cooldown; degrading to %q (recovers %s)",
		len(members), name, soonest, soonestUntil.Format(time.RFC3339))
	return soonest, true
}

// MarkCooldown records, in memory and synchronously, that a member should be
// skipped until `until`. Phase 2 failover calls this on the response path
// BEFORE the response returns so the very next request injects the next
// member; the durable store write only reconciles afterwards. Calling with a
// zero/past `until` clears the cooldown (recovery).
func (pr *PoolResolver) MarkCooldown(credential string, until time.Time, reason string) {
	if pr == nil {
		return
	}
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if until.IsZero() || !until.After(time.Now()) {
		delete(pr.health, credential)
		return
	}
	pr.health[credential] = memberHealth{cooldownUntil: until, reason: reason}
}

// CooldownUntil returns the in-memory cooldown expiry for a credential and
// whether it is currently cooling down (future expiry).
func (pr *PoolResolver) CooldownUntil(credential string) (time.Time, bool) {
	if pr == nil {
		return time.Time{}, false
	}
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	h, ok := pr.health[credential]
	if !ok || h.cooldownUntil.IsZero() || !h.cooldownUntil.After(time.Now()) {
		return time.Time{}, false
	}
	return h.cooldownUntil, true
}
