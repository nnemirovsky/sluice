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

// ManualRotateReason is the cooldown reason stamped by `sluice pool rotate`
// when it parks the previously-active member. A member parked for this
// reason is operationally deprioritized BY AN OPERATOR, not unhealthy: it
// must still be skipped for normal position-order active selection (so the
// rotated-to member wins), but it REMAINS a valid failover / degrade target.
// A manual park must never strand the pool with no servable member when the
// rotated-to member subsequently fails — otherwise a rotate onto an
// exhausted account self-loops instead of falling back to the parked-but-
// healthy peer. The literal is shared with cmd/sluice's rotate writer so the
// two stay in sync.
const ManualRotateReason = "manual rotate"

// memberHealth is the in-memory health view for one credential. Status is
// derived: a credential with a zero cooldownUntil is healthy.
type memberHealth struct {
	cooldownUntil time.Time
	reason        string
}

// memberIdentity is the pool+epoch identity of a credential in the CURRENT
// resolver generation. A remove/re-add of the same credential name yields a
// strictly greater epoch (and possibly a different pool), so a stale
// MarkCooldown carrying the OLD identity can be told apart from its
// re-created successor and rejected. The zero value (pool=="", epoch==0) is
// never a live identity because every membership row is stamped with a
// post-bump epoch >= 1.
type memberIdentity struct {
	pool  string
	epoch int64
}

// activeEntry is the sticky pointer's value: the member ResolveActive last
// settled on PLUS the (pool, epoch) identity of the generation that wrote it.
// Finding 3: storing only the member NAME let a remove/re-create of the same
// pool name with an overlapping member name be accepted by a later
// generation as a valid sticky hold even though that name belongs to the OLD
// epoch/order. Carrying the epoch (the same monotonic membership epoch the
// cooldown gate keys on via memberIdentity) lets ResolveActive reject a
// stored sticky entry whose epoch no longer matches this generation's
// identity for the pool and advance fresh instead.
type activeEntry struct {
	member string
	epoch  int64
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
// Finding 3 (round-15) + Cluster A (round-18): a response handled by an OLD
// resolver generation can call MarkCooldown AFTER a NEW generation already
// pruned/replaced membership during resolver rebuild. The round-15 gate
// keyed only on the credential NAME being present in SOME pool, so a
// remove/re-add of the same name into a DIFFERENT pool would let the stale
// write through and the new member would inherit the OLD response's
// cooldown. The fix is to key the gate on the credential's pool+epoch
// IDENTITY (memberIdentity) for the current generation, updated under the
// SAME mutex that guards the cooldown map, so the membership replace and a
// concurrent stale MarkCooldown cannot interleave AND a stale write whose
// (pool, epoch) no longer matches the live identity no-ops. currentMembers
// stays nil until SetCurrentMembers is called the first time
// (ad-hoc/private resolvers that never set it keep the old permissive
// behavior, so single-generation callers are not regressed).
type PoolHealth struct {
	mu     sync.RWMutex
	health map[string]memberHealth
	// currentMembers maps a credential name -> its pool+epoch identity in
	// the CURRENT resolver generation. nil = "not tracked" (gate disabled,
	// legacy permissive behavior). Non-nil but missing a credential = that
	// credential is not a member of any pool in the current generation.
	// Present but with a DIFFERENT (pool, epoch) than the stale write
	// carries = the credential was removed and re-added (a later
	// same-named successor) so the stale write must NOT apply. Mutated only
	// under mu, the same lock the cooldown map uses.
	currentMembers map[string]memberIdentity
	// active maps a pool name -> the credential ResolveActive last settled
	// on (the sticky pointer). It lives here, NOT on PoolResolver, for the
	// exact same CRITICAL-1 reason cooldowns do: a membership change / SIGHUP
	// / 2s data_version watcher rebuilds a fresh PoolResolver that the server
	// atomically pointer-swaps, and ResolveActive on the new generation must
	// keep serving the member it switched to instead of snapping back to
	// position 0 (the flap that spams cred_failover + Telegram). Reads and
	// writes are under the SAME mu as the cooldown map (no second lock, no
	// lock-ordering hazard). It survives swaps because every generation
	// shares one *PoolHealth; a stale generation cannot clobber it because
	// ResolveActive only ever writes a member of THIS generation's member
	// list, AND the entry is epoch-scoped (activeEntry.epoch): a write records
	// the writing generation's membership epoch, and ResolveActive ignores a
	// stored entry whose epoch no longer matches THIS generation's identity
	// for the pool (Finding 3 — a same-pool-name re-create with overlapping
	// member names bumps the epoch, so the stale sticky hold is rejected and
	// the pointer advances fresh). Both live reload paths that swap the member
	// set — NewPoolResolverShared -> SetCurrentMembers AND
	// MergeLiveCooldowns's shared-map branch — prune this map for any pool no
	// longer present, whose recorded member is no longer in that pool, or
	// whose recorded epoch no longer matches the new generation (mirrors the
	// cooldown prune).
	active map[string]activeEntry
}

// NewPoolHealth returns an empty shared health map. Call this exactly once
// per process and thread the result through every NewPoolResolver so all
// resolver generations share one cooldown view.
func NewPoolHealth() *PoolHealth {
	return &PoolHealth{
		health: make(map[string]memberHealth),
		active: make(map[string]activeEntry),
	}
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
//
// It ALSO prunes the sticky-pointer map under the same lock so this live
// path stays consistent with MergeLiveCooldowns's shared-map prune (Finding
// 1): on the server reload path NewPoolResolverShared calls this BEFORE
// StorePool reaches MergeLiveCooldowns, so without pruning here a dropped or
// epoch-bumped pool would briefly keep a stale sticky entry that
// ResolveActive could observe. A sticky entry is dropped when the pool's
// recorded member is no longer present in the new member set, or its epoch
// no longer matches the new generation (Finding 3); an entry for a pool with
// no surviving members is also dropped (every member of that pool would be
// absent from `members`).
func (ph *PoolHealth) SetCurrentMembers(members map[string]memberIdentity) {
	if ph == nil {
		return
	}
	ph.mu.Lock()
	defer ph.mu.Unlock()
	ph.currentMembers = members
	ph.pruneActiveLocked(members)
}

// pruneActiveLocked drops sticky-pointer entries that are no longer valid for
// the generation described by `members` (cred -> pool+epoch). An entry
// survives only when its recorded member still maps to the SAME pool with the
// SAME epoch. Caller must hold ph.mu. Shared by SetCurrentMembers and
// MergeLiveCooldowns so both live reload paths prune identically.
func (ph *PoolHealth) pruneActiveLocked(members map[string]memberIdentity) {
	for poolName, ent := range ph.active {
		id, stillMember := members[ent.member]
		if !stillMember || id.pool != poolName || id.epoch != ent.epoch {
			delete(ph.active, poolName)
		}
	}
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
	// identity maps a credential name -> its pool+epoch identity in THIS
	// generation. Threaded into MarkCooldown and the FailoverEvent so a
	// stale write carrying an old (pool, epoch) cannot apply to a
	// re-created same-name successor. A credential belongs to at most one
	// pool (store enforces this), so a single identity per credential.
	identity map[string]memberIdentity

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
		identity: make(map[string]memberIdentity),
		health:   shared,
	}
	for _, p := range pools {
		members := make([]string, 0, len(p.Members))
		for _, m := range p.Members {
			members = append(members, m.Credential)
			pr.memberOf[m.Credential] = append(pr.memberOf[m.Credential], p.Name)
			pr.identity[m.Credential] = memberIdentity{pool: p.Name, epoch: m.Epoch}
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
		cm := make(map[string]memberIdentity, len(pr.identity))
		for cred, id := range pr.identity {
			cm[cred] = id
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
//
// For a pool the selection is STICKY (there is no "main" / position-0
// account):
//
//   - If a current-active member is recorded for this pool, is still a
//     member of THIS generation, and is healthy (no active cooldown), it is
//     returned unchanged — a sticky hold. A lower-position member recovering
//     from cooldown does NOT cause a switch back to it (this is the flap fix:
//     re-probing an exhausted-upstream member every 60s and snapping back to
//     it was wrong and spammed cred_failover + Telegram).
//   - Otherwise the next eligible member is chosen by position order
//     STARTING AFTER the current-active member's position and WRAPPING
//     (advance forward, never snap back to position 0). Members in active
//     cooldown are skipped. The chosen member becomes the new sticky
//     current-active for the pool.
//   - If EVERY member is cooling, sluice keeps serving with the least-bad
//     account (degraded): an operator-parked-but-healthy member
//     (ManualRotateReason) is preferred over a genuinely failed one, else
//     the soonest-recovering member; a WARNING is logged. The sticky pointer
//     is NOT moved in this case, so when a member recovers the next call
//     advances forward to it rather than snapping to absolute position 0.
//
// The current-active pointer lives on the shared *PoolHealth and is read/
// written under the same mu as the cooldown map, so it survives resolver
// pointer swaps (CRITICAL-1) and a stale generation cannot clobber it: a
// write only ever stores a member of THIS generation's member list.
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

	// THIS generation's membership epoch for the pool. Every member of a pool
	// shares one epoch (the store stamps all rows of a membership generation
	// with the same monotonic value), so the first member's identity epoch is
	// the pool's epoch. Used to reject a sticky entry written by an older
	// generation after a same-pool-name re-create bumped the epoch (Finding
	// 3). identity is immutable for this resolver, so it is read lock-free.
	genEpoch := pr.identity[members[0]].epoch

	// Finding 1: one time snapshot for the whole resolve. cooling() runs once
	// per member in the scan loops; calling time.Now() per invocation made the
	// cooldown gate observe a drifting clock within a single resolve (and was
	// needless syscall churn). Capture now ONCE here so the RLock fast path and
	// the write-lock advance/degrade slow path evaluate every member against
	// one coherent instant. Semantics are unchanged: a member is cooling iff
	// cooldownUntil.After(now).
	now := time.Now()

	cooling := func(m string) bool {
		// Caller holds ph.mu (R or W). Compared against the resolve-wide `now`
		// snapshot (Finding 1), not a fresh time.Now() per call.
		h, tracked := pr.health.health[m]
		return tracked && !h.cooldownUntil.IsZero() && h.cooldownUntil.After(now)
	}

	// Read-mostly fast path (Finding 2): the common case is a sticky hold —
	// the recorded active member is still a member of THIS generation, its
	// epoch matches, and it is not cooling. That requires no mutation, so it
	// runs under the shared RLock and does not serialize with other resolves.
	pr.health.mu.RLock()
	if ent, set := pr.health.active[name]; set && ent.epoch == genEpoch {
		for _, m := range members {
			if m != ent.member {
				continue
			}
			if !cooling(ent.member) {
				pr.health.mu.RUnlock()
				return ent.member, true
			}
			break
		}
	}
	pr.health.mu.RUnlock()

	// Slow path: the sticky pointer must be advanced/initialized (unset,
	// stale-epoch, no longer a member, or cooling). Go's RWMutex has no
	// in-place upgrade, so drop the RLock and take the WRITE lock, then
	// RE-CHECK the sticky-hold condition: another goroutine may have advanced
	// the pointer between RUnlock and Lock, in which case return it without
	// re-advancing. The write lock keeps the sticky pointer consistent with
	// the cooldown view a concurrent failover's MarkCooldown writes (same mu,
	// no second lock, no lock-ordering hazard).
	pr.health.mu.Lock()
	// Finding 3: the write lock is held ONLY for the sticky-pointer
	// re-check, the advance mutation, and the degrade-target selection.
	// Each slow-path exit Unlocks EXPLICITLY before its return/log.Printf
	// (no `defer`), so the lock never spans logging or the value return and
	// concurrent ResolveActive / MarkCooldown are not serialized behind log
	// I/O. Every path below unlocks exactly once before returning; there is
	// no path that returns while still holding the lock and none unlocks
	// twice.

	// Position of the current sticky member in THIS generation's member
	// list. startIdx == -1 (no valid current) makes the scan start at
	// position 0; otherwise it starts AFTER cur and wraps. A stored entry
	// whose epoch does not match this generation is treated as "no current
	// active" (Finding 3): it belongs to an old epoch/order, so advance
	// fresh rather than honor a cross-generation name collision.
	startIdx := -1
	if ent, set := pr.health.active[name]; set && ent.epoch == genEpoch {
		for i, m := range members {
			if m != ent.member {
				continue
			}
			// Re-check under the write lock: still a member of this
			// generation and healthy — another resolver may have just
			// advanced here, or it was a benign RLock->Lock race. Keep
			// serving it; do not move.
			if !cooling(ent.member) {
				pr.health.mu.Unlock()
				return ent.member, true
			}
			startIdx = i
			break
		}
	}

	// Advance forward from AFTER the current member (or position 0 when
	// there is no valid current), wrapping, picking the first non-cooling
	// member. Never snap back to position 0 on a flap.
	n := len(members)
	for off := 1; off <= n; off++ {
		idx := (startIdx + off) % n
		m := members[idx]
		if !cooling(m) {
			pr.health.active[name] = activeEntry{member: m, epoch: genEpoch}
			pr.health.mu.Unlock()
			return m, true
		}
	}

	// Every member is cooling: degrade (do NOT move the sticky pointer, so a
	// recovery advances forward rather than snapping to position 0).
	var soonest, soonestParked string
	var soonestUntil, soonestParkedUntil time.Time
	for _, m := range members {
		h := pr.health.health[m]
		if soonest == "" || h.cooldownUntil.Before(soonestUntil) {
			soonest = m
			soonestUntil = h.cooldownUntil
		}
		// A "manual rotate" park is an operator deprioritization, not a
		// health failure: the member is still servable. When EVERY member
		// is cooling, such a member is a strictly better degrade target
		// than a genuinely failed (rate-limited / auth-failed) one — this
		// is what lets a `pool rotate` onto an exhausted member still fail
		// over to the parked-but-healthy peer instead of self-looping on
		// the exhausted one.
		if h.reason == ManualRotateReason {
			if soonestParked == "" || h.cooldownUntil.Before(soonestParkedUntil) {
				soonestParked = m
				soonestParkedUntil = h.cooldownUntil
			}
		}
	}
	// Finding 3: the degrade TARGET (and the values the WARNING needs) are
	// fully computed above under the write lock; the sticky pointer is
	// deliberately NOT moved in the degrade case. Release the lock here,
	// BEFORE the log.Printf and return, so logging never serializes
	// concurrent ResolveActive / MarkCooldown. memberCount/name/soonest*
	// are locals captured under the lock; the post-Unlock log/return only
	// reads them, never the shared map.
	memberCount := len(members)
	pr.health.mu.Unlock()
	if soonestParked != "" {
		log.Printf("[POOL] all %d members of pool %q are cooling; degrading to operator-parked-but-healthy %q",
			memberCount, name, soonestParked)
		return soonestParked, true
	}
	log.Printf("[POOL] all %d members of pool %q are in cooldown; degrading to %q (recovers %s)",
		memberCount, name, soonest, soonestUntil.Format(time.RFC3339))
	return soonest, true
}

// IdentityForMember returns the pool+epoch identity of a credential in THIS
// resolver generation. ok is false when the credential is not a member of
// any pool in this generation. The failover path captures this at the time
// the cooldown decision is made and threads (pool, epoch) through to
// MarkCooldown and the durable guarded write so a stale write cannot apply
// to a re-created same-name successor (Cluster A).
func (pr *PoolResolver) IdentityForMember(credential string) (pool string, epoch int64, ok bool) {
	if pr == nil {
		return "", 0, false
	}
	id, ok := pr.identity[credential]
	if !ok {
		return "", 0, false
	}
	return id.pool, id.epoch, true
}

// MarkCooldown records, in memory and synchronously, that a member should be
// skipped until `until`. Phase 2 failover calls this on the response path
// BEFORE the response returns so the very next request injects the next
// member; the durable store write only reconciles afterwards. Calling with a
// zero/past `until` clears the cooldown (recovery).
//
// This is the legacy identity-UNSCOPED form: it keeps the round-15
// name-only write-after-prune guard but does NOT distinguish a removed and
// re-added same-name credential. The response/failover path MUST use
// MarkCooldownScoped so a stale write cannot park a re-created successor
// (Cluster A #1). Single-generation callers (CLI tools, unit tests) keep
// using this.
func (pr *PoolResolver) MarkCooldown(credential string, until time.Time, reason string) {
	pr.markCooldown(credential, "", -1, until, reason)
}

// MarkCooldownScoped is the pool+epoch identity-scoped form used by the
// Phase 2 failover response path. pool+epoch identify WHICH membership
// generation the cooldown decision was made against. The gate commits the
// in-memory write only if that exact (pool, epoch) is still the live
// identity for `credential` in the current generation: a stale write whose
// membership was removed and the name re-added (a strictly greater epoch,
// or a different pool) no-ops, so the re-created successor does NOT inherit
// the old response's cooldown (Cluster A #1).
func (pr *PoolResolver) MarkCooldownScoped(credential, pool string, epoch int64, until time.Time, reason string) {
	pr.markCooldown(credential, pool, epoch, until, reason)
}

func (pr *PoolResolver) markCooldown(credential, pool string, epoch int64, until time.Time, reason string) {
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
		live, isMember := pr.health.currentMembers[credential]
		if !isMember {
			// Not a member of any pool in the current generation:
			// write-after-prune guard (round-15).
			return
		}
		// Cluster A #1: identity-scoped guard. When the caller carries a
		// pool+epoch (epoch >= 0), reject the write unless it still matches
		// the live identity. A removed+re-added same-name credential has a
		// strictly greater epoch (or a different pool), so an old in-flight
		// 429's MarkCooldown does NOT park the re-created successor. A
		// caller that opts out (epoch < 0) keeps the round-15 name-only
		// behavior.
		if epoch >= 0 && (live.pool != pool || live.epoch != epoch) {
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
		cm := make(map[string]memberIdentity, len(pr.identity))
		for cred, id := range pr.identity {
			cm[cred] = id
		}
		pr.health.currentMembers = cm
		// Sticky-pointer prune (mirrors the cooldown prune above): drop the
		// recorded active member for any pool this generation no longer has,
		// whose recorded member is no longer in that pool, or whose recorded
		// epoch no longer matches this generation (Finding 3 — a same-pool-
		// name re-create with overlapping member names bumps the epoch). A
		// surviving pool with a still-valid same-epoch member keeps its sticky
		// member so a benign reload does NOT snap it back to position 0 (the
		// whole point of CRITICAL-1 for the pointer). Same predicate as
		// SetCurrentMembers via the shared helper so both live reload paths
		// prune identically (Finding 1).
		pr.health.pruneActiveLocked(cm)
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
