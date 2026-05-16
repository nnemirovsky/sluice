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

// PoolHealth is the mutex-guarded credential cooldown map. It is
// deliberately a SEPARATE object from PoolResolver so it can outlive any
// single resolver generation.
//
// CRITICAL-1: pool membership is immutable per resolver, but a membership
// change (or any unrelated DB write triggering the 2s data_version
// watcher, or a SIGHUP) rebuilds a fresh PoolResolver that the server
// atomically pointer-swaps. Phase 2 failover's MarkCooldown runs on the
// response path WITHOUT holding ReloadMu, so a MarkCooldown landing on the
// old generation between a swap's snapshot and store could be lost; and a
// merge that chains only one generation back loses a cooldown permanently
// if the detached durable SetCredentialHealth write fails.
//
// The fix: construct ONE PoolHealth at process start and inject the SAME
// instance into every NewPoolResolver. MarkCooldown on any generation and
// ResolveActive on the current generation then mutate/read the SAME
// underlying map under the SAME mutex, so a cooldown can never be lost
// across a pointer swap and never depends on a durable write succeeding.
// Store rows still seed the map at startup (Seed) for cross-restart
// durability, and the seed is monotonic (never shortens a live in-memory
// cooldown).
// Finding 3 (round-15): a response handled by an OLD resolver generation can
// call MarkCooldown AFTER a NEW generation already pruned non-members during
// resolver rebuild (StorePool/MergeLiveCooldowns shared path). If that
// credential was removed from every pool in the new generation, the
// unguarded MarkCooldown would re-insert a stale in-memory cooldown that a
// later same-named re-add inherits before its TTL. The fix is to store the
// CURRENT generation's authoritative member set on the shared PoolHealth and
// update it under the SAME mutex that guards the cooldown map, so the prune
// (member-set replace) and a concurrent MarkCooldown cannot interleave to
// leave a non-member cooldown entry behind. MarkCooldown, under the lock,
// no-ops when the credential is not in currentMembers (and currentMembers is
// non-nil). currentMembers stays nil until SetCurrentMembers is called the
// first time (ad-hoc/private resolvers that never set it keep the old
// permissive behavior, so single-generation callers are not regressed).
type PoolHealth struct {
	mu     sync.RWMutex
	health map[string]memberHealth
	// currentMembers is the authoritative member set of the CURRENT
	// resolver generation. nil = "not tracked" (gate disabled, legacy
	// permissive behavior). Non-nil but missing a credential = that
	// credential is not a member of any pool in the current generation, so
	// MarkCooldown must NOT write a cooldown for it (write-after-prune
	// guard). Mutated only under mu, the same lock the cooldown map uses.
	currentMembers map[string]struct{}
}

// NewPoolHealth returns an empty shared health map. Call this exactly once
// per process and thread the result through every NewPoolResolver so all
// resolver generations share one cooldown view.
func NewPoolHealth() *PoolHealth {
	return &PoolHealth{health: make(map[string]memberHealth)}
}

// SetCurrentMembers atomically replaces the authoritative member set for the
// current resolver generation. Called when a fresh generation takes over
// (NewPoolResolverShared with a shared map, and the MergeLiveCooldowns
// shared-path prune) so MarkCooldown can reject write-after-prune attempts
// from a stale (old-generation) response path. The replace happens under the
// same mutex as the cooldown writes, so a concurrent MarkCooldown either
// observes the OLD member set entirely or the NEW one entirely — it can never
// observe a half-updated set, and it can never slip a non-member cooldown in
// between the prune and the member-set swap.
func (ph *PoolHealth) SetCurrentMembers(members map[string]struct{}) {
	if ph == nil {
		return
	}
	ph.mu.Lock()
	ph.currentMembers = members
	ph.mu.Unlock()
}

// Seed merges store-persisted cooldown rows into the shared map. It is
// monotonic: a store row never shortens or clears a live in-memory
// cooldown (the in-memory value is authoritative because Phase 2 failover
// updates it synchronously and the durable write is best-effort/detached).
// Expired rows are ignored. Safe to call on every resolver rebuild.
func (ph *PoolHealth) Seed(healthRows []store.CredentialHealth) {
	if ph == nil {
		return
	}
	now := time.Now()
	ph.mu.Lock()
	defer ph.mu.Unlock()
	for _, h := range healthRows {
		if h.Status != "cooldown" || h.CooldownUntil.IsZero() || !h.CooldownUntil.After(now) {
			continue
		}
		existing, ok := ph.health[h.Credential]
		if !ok || h.CooldownUntil.After(existing.cooldownUntil) {
			ph.health[h.Credential] = memberHealth{
				cooldownUntil: h.CooldownUntil,
				reason:        h.LastFailureReason,
			}
		}
	}
}

// PoolResolver maps a pool name to its currently active member. It is the
// single chokepoint every credential consumer routes through (injection
// passes, OAuthIndex.Has gating, persist attribution), so a pool name is
// expanded to a real credential in exactly one place.
//
// Locking discipline: pool membership is immutable for the lifetime of a
// PoolResolver instance (membership changes rebuild a fresh resolver that
// the server atomically pointer-swaps). Health, by contrast, is mutated
// synchronously on the response path during Phase 2 failover and MUST
// survive resolver pointer swaps, so it lives in a SHARED *PoolHealth
// (one instance per process, injected into every generation). ResolveActive
// takes the shared RLock; MarkCooldown takes the shared Lock. A failover
// recorded on any generation is therefore visible to ResolveActive on the
// current generation regardless of how many reloads happened in between,
// and a cooldown can never be lost across a swap (CRITICAL-1).
type PoolResolver struct {
	// pools maps pool name -> ordered member credential names.
	pools map[string][]string
	// memberOf maps a credential name -> the pools that contain it.
	memberOf map[string][]string

	// health is the shared, swap-surviving cooldown map. Never nil after
	// NewPoolResolver (a fresh PoolHealth is allocated when none is given,
	// preserving the old single-generation behavior for ad-hoc callers).
	health *PoolHealth
}

// NewPoolResolver builds a resolver from store snapshots with a PRIVATE
// per-instance health map. Use this for short-lived throwaway resolvers
// (CLI `pool` subcommands that build a resolver, print, and discard it).
// The long-lived proxy server MUST use NewPoolResolverShared so cooldowns
// survive resolver pointer swaps (CRITICAL-1). Health rows with status
// "cooldown" and a future cooldown_until seed the map; healthy rows and
// expired cooldowns are treated as eligible.
func NewPoolResolver(pools []store.Pool, healthRows []store.CredentialHealth) *PoolResolver {
	return NewPoolResolverShared(pools, healthRows, nil)
}

// NewPoolResolverShared builds a resolver that shares the given PoolHealth
// across every resolver generation. Pass the process-wide *PoolHealth here
// (NewPoolHealth, created once) so MarkCooldown on any generation and
// ResolveActive on the current generation operate on the SAME mutex-guarded
// map — a cooldown can never be lost across an atomic pointer swap and
// never depends on the detached durable write succeeding (CRITICAL-1).
// When shared is nil a fresh private PoolHealth is allocated, preserving
// the old single-generation semantics for ad-hoc callers.
//
// healthRows seed the (possibly shared) map monotonically: an existing
// live in-memory cooldown is never shortened by a store row. Seeding the
// shared map on every rebuild is therefore safe and idempotent.
func NewPoolResolverShared(pools []store.Pool, healthRows []store.CredentialHealth, shared *PoolHealth) *PoolResolver {
	explicitShared := shared != nil
	if shared == nil {
		shared = NewPoolHealth()
	}
	pr := &PoolResolver{
		pools:    make(map[string][]string, len(pools)),
		memberOf: make(map[string][]string),
		health:   shared,
	}
	for _, p := range pools {
		members := make([]string, 0, len(p.Members))
		for _, m := range p.Members {
			members = append(members, m.Credential)
			pr.memberOf[m.Credential] = append(pr.memberOf[m.Credential], p.Name)
		}
		pr.pools[p.Name] = members
	}
	shared.Seed(healthRows)
	// Finding 3 (round-15): on the server path (an explicit process-wide
	// shared PoolHealth) publish THIS generation's authoritative member set
	// so the write-after-prune gate in MarkCooldown is active from the very
	// first generation onward, not only after the first MergeLiveCooldowns
	// shared-path prune runs. The member-set replace and the cooldown writes
	// share PoolHealth.mu, so a concurrent stale MarkCooldown observes either
	// the old or the new set atomically. Ad-hoc/private resolvers (shared ==
	// nil, e.g. CLI `pool` subcommands) leave currentMembers nil to preserve
	// the old permissive single-generation behavior.
	if explicitShared {
		cm := make(map[string]struct{}, len(pr.memberOf))
		for cred := range pr.memberOf {
			cm[cred] = struct{}{}
		}
		shared.SetCurrentMembers(cm)
	}
	return pr
}

// IsPool reports whether name is a configured pool. Pool membership is
// immutable for a resolver instance (a membership change builds a fresh
// resolver), so no lock is needed.
func (pr *PoolResolver) IsPool(name string) bool {
	if pr == nil {
		return false
	}
	_, ok := pr.pools[name]
	return ok
}

// PoolForMember returns the first pool that contains the given credential,
// or "" if the credential is not a pool member. Used by the response path to
// attribute a failover/refresh to its pool for audit + Telegram. Membership
// is immutable per instance, so no lock is needed.
func (pr *PoolResolver) PoolForMember(credential string) string {
	if pr == nil {
		return ""
	}
	if pools := pr.memberOf[credential]; len(pools) > 0 {
		return pools[0]
	}
	return ""
}

// Members returns the ordered member list for a pool (copy), or nil. Exposed
// as an introspection surface for tests and potential future `pool status`
// detail output; not on any hot path. Membership is immutable per instance,
// so no lock is needed.
func (pr *PoolResolver) Members(pool string) []string {
	if pr == nil {
		return nil
	}
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

	members, isPool := pr.pools[name]
	if !isPool {
		// Plain credential: passthrough unchanged.
		return name, true
	}
	if len(members) == 0 {
		return "", false
	}

	// Read the shared health map under its RLock. A concurrent failover's
	// MarkCooldown takes the same map's write lock, so this observes a
	// consistent cooldown view regardless of resolver generation.
	pr.health.mu.RLock()
	defer pr.health.mu.RUnlock()

	now := time.Now()
	var soonest string
	var soonestUntil time.Time
	for _, m := range members {
		h, tracked := pr.health.health[m]
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
	// Mutate the SHARED health map. Because every resolver generation points
	// at the same *PoolHealth, a MarkCooldown that lands on an
	// about-to-be-replaced generation is still observed by ResolveActive on
	// the new generation — the pointer swap no longer races the cooldown
	// (CRITICAL-1). Monotonic clear/set semantics are unchanged: a zero/past
	// `until` clears the cooldown (recovery).
	pr.health.mu.Lock()
	defer pr.health.mu.Unlock()
	// Finding 3 (round-15) write-after-prune guard. A response handled by an
	// OLD resolver generation can reach this AFTER a NEW generation pruned
	// non-members and swapped in its member set (both happen under THIS same
	// mu, so we either see the pre-prune or post-prune state, never a torn
	// one). If currentMembers is tracked (non-nil) and this credential is not
	// in it, the credential belongs to no pool in the current generation:
	// writing a cooldown would resurrect a non-member entry that a later
	// same-named re-add inherits before its TTL. Skip the write. A clear
	// (zero/past `until`) is always allowed through below — deleting a stale
	// entry for a non-member is only ever beneficial. currentMembers == nil
	// means the gate is disabled (ad-hoc/private resolver that never called
	// SetCurrentMembers): preserve the old permissive behavior so
	// single-generation callers are not regressed.
	isClear := until.IsZero() || !until.After(time.Now())
	if !isClear && pr.health.currentMembers != nil {
		if _, isMember := pr.health.currentMembers[credential]; !isMember {
			return
		}
	}
	if isClear {
		delete(pr.health.health, credential)
		return
	}
	// Monotonic extend: a member parked for an auth failure (300s) that
	// subsequently trips a rate-limit (60s) must NOT have its cooldown
	// shortened — a known-bad credential would become eligible far too
	// early. Keep the LATER of the existing future cooldown and the new
	// one. This is ONLY the extend path: an explicit clear/recover (the
	// zero/past `until` branch above, and SetCredentialHealth "healthy"
	// on the durable side) still shortens/clears, and a strictly later
	// `until` still extends. Lazy expiry in ResolveActive/CooldownUntil
	// is unaffected because an expired existing cooldown is in the past
	// and `until.After(existing.cooldownUntil)` is true, so the fresh
	// future cooldown wins.
	if existing, ok := pr.health.health[credential]; ok &&
		existing.cooldownUntil.After(time.Now()) &&
		!until.After(existing.cooldownUntil) {
		return
	}
	pr.health.health[credential] = memberHealth{cooldownUntil: until, reason: reason}
}

// MergeLiveCooldowns is retained for API compatibility but is now a
// near-no-op. CRITICAL-1's race and permanent-loss bugs were fixed by
// making the cooldown map a process-wide shared *PoolHealth that every
// resolver generation points at (NewPoolResolverShared), so a cooldown
// recorded via MarkCooldown on any generation is already visible to
// ResolveActive on the new generation — there is nothing to "carry
// forward" because both generations mutate the SAME map under the SAME
// mutex. The pointer swap can no longer lose a cooldown, and durability no
// longer depends on the detached store write succeeding.
//
// When prev and pr happen to share the same *PoolHealth (the normal server
// path) this is a pure no-op. The only case where it still does work is a
// defensive one: prev was built with a DIFFERENT (e.g. nil-defaulted)
// PoolHealth than pr — then still-live cooldowns are copied forward
// monotonically and orphaned members dropped, exactly as before, so the
// old single-generation callers are not regressed.
func (pr *PoolResolver) MergeLiveCooldowns(prev *PoolResolver) {
	if pr == nil || prev == nil || prev.health == nil || pr.health == nil {
		return
	}
	if pr.health == prev.health {
		// Shared health map: both generations already see the same
		// cooldowns, so there is nothing to carry forward — this is the
		// CRITICAL-1 fix. But the shared map can still hold stale entries
		// for credentials this new generation no longer tracks as a pool
		// member (a member removed from a pool, or removed and recreated
		// under the same name). Without pruning, a re-add before the old
		// TTL expires would inherit the stale cooldown and ResolveActive
		// would skip the member even though the store snapshot no longer
		// records it (Finding 2, round-9).
		//
		// Pruning only NON-members preserves both invariants: a current
		// member's (possibly synchronously-recorded) cooldown is never
		// touched, so the monotonic-cooldown invariant and CRITICAL-1
		// shared-map durability for live members are intact; only entries
		// for credentials absent from the new resolver's member set are
		// dropped.
		pr.health.mu.Lock()
		for cred := range pr.health.health {
			if _, stillMember := pr.memberOf[cred]; !stillMember {
				delete(pr.health.health, cred)
			}
		}
		// Finding 3 (round-15): publish THIS generation's authoritative
		// member set on the shared PoolHealth under the SAME lock as the
		// prune above. After this, a MarkCooldown arriving from a stale
		// old-generation response path sees the new member set and no-ops
		// for any credential this generation no longer owns — the prune
		// and the member-set swap are one atomic critical section, so no
		// non-member cooldown can be slipped in between them.
		cm := make(map[string]struct{}, len(pr.memberOf))
		for cred := range pr.memberOf {
			cm[cred] = struct{}{}
		}
		pr.health.currentMembers = cm
		pr.health.mu.Unlock()
		return
	}
	now := time.Now()
	prev.health.mu.RLock()
	prevHealth := make(map[string]memberHealth, len(prev.health.health))
	for k, v := range prev.health.health {
		prevHealth[k] = v
	}
	prev.health.mu.RUnlock()

	pr.health.mu.Lock()
	defer pr.health.mu.Unlock()
	for cred, ph := range prevHealth {
		if ph.cooldownUntil.IsZero() || !ph.cooldownUntil.After(now) {
			continue // expired in the old resolver; nothing to carry
		}
		// Only carry cooldowns for credentials this resolver still tracks as a
		// pool member; an orphaned cooldown for a removed member is dropped.
		if _, stillMember := pr.memberOf[cred]; !stillMember {
			continue
		}
		existing, ok := pr.health.health[cred]
		if !ok || ph.cooldownUntil.After(existing.cooldownUntil) {
			pr.health.health[cred] = ph
		}
	}
}

// CooldownUntil returns the in-memory cooldown expiry for a credential and
// whether it is currently cooling down (future expiry). Exposed as an
// introspection surface for tests and potential future `pool status`
// detail output; not on any hot path.
func (pr *PoolResolver) CooldownUntil(credential string) (time.Time, bool) {
	if pr == nil {
		return time.Time{}, false
	}
	pr.health.mu.RLock()
	defer pr.health.mu.RUnlock()
	h, ok := pr.health.health[credential]
	if !ok || h.cooldownUntil.IsZero() || !h.cooldownUntil.After(time.Now()) {
		return time.Time{}, false
	}
	return h.cooldownUntil, true
}
