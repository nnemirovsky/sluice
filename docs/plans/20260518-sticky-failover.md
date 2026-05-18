# Sticky Pool Failover (no "main" account)

## Problem

Live on knuth: `pool openai_pool failed over openai_oauth -> openai_oauth_2 (429)` repeats
every few minutes (20+ messages). Hermes keeps working. Root cause is a flap:

- `openai_oauth` is position 0 (the de-facto "main"). Its OpenAI quota is exhausted, so it
  429s on every request.
- On 429 sluice fails over to `openai_oauth_2` and parks `openai_oauth` for only
  `vault.RateLimitCooldown` = 60s.
- `PoolResolver.ResolveActive` picks the **first member in position order** that is healthy
  or whose cooldown expired. 60s later `openai_oauth`'s cooldown lapses, so it is re-selected
  even though `openai_oauth_2` was serving fine.
- `openai_oauth` is still quota-exhausted upstream -> 429 -> failover again -> another
  identical Telegram notice. Repeats on every request gap > 60s.

The real OpenAI Codex quota window is hours/weekly, so re-probing the exhausted account
every 60s and snapping back to it is wrong.

## Desired behavior (user decision)

Sticky failover: there is no "main" account. Stay on whichever member is currently active
until **that** member exhausts, then advance to the next member. A lower-position member
recovering from cooldown must NOT cause a switch back to it. A new failover (and its single
Telegram notice) happens only on a genuine exhaustion transition, not on cooldown lapse.

Mode toggle (position-priority vs sticky as selectable strategies) is explicitly out of
scope for this change; sticky becomes the behavior. Note it as a possible follow-up.

## Design

`ResolveActive` is the single source of truth: `internal/proxy/pool_failover.go` calls
`pr.ResolveActive(pool)` to compute the new active ("to") after cooling the old member, so
making selection sticky fixes the flap, the failover events, and the notification spam in
one place.

1. Add a per-pool current-active pointer to the swap-surviving shared `PoolHealth`
   (`internal/vault/pool.go`), guarded by the same mutex as the cooldown map, so it
   survives `NewPoolResolverShared` regeneration and atomic swaps (same lifecycle as
   cooldowns; carry it the way cooldowns are carried).
2. Sticky `ResolveActive(pool)`:
   - Let `cur` = shared current-active for the pool, if set and still a member of this
     generation.
   - If `cur` is set and healthy (no active cooldown) -> return `cur` (sticky hold).
   - Else pick the next eligible member by position **starting after `cur`'s position and
     wrapping** (so we advance forward, never snap back to position 0); skip members in
     active cooldown; treat `ManualRotateReason` parks with the existing
     better-degrade-target semantics. Set shared current-active to the picked member and
     return it.
   - If every member is cooling: keep the existing degrade behavior (operator-parked-but-
     healthy first, else soonest-recovering) and do NOT move the sticky pointer, so when a
     member recovers the next call advances to a healthy one rather than the absolute
     position-0 member.
3. Operator `sluice pool rotate` semantics unchanged at the surface: it still parks the
   current active so the next `ResolveActive` advances; with sticky that advance lands on
   the next member and stays there (no snap-back), which is the intended rotate behavior.
4. Keep all existing concurrency invariants: sticky pointer reads/writes under the same
   `PoolHealth.mu`; never lost across atomic pointer swap; a stale resolver generation must
   not clobber it (mirror the cooldown CRITICAL-1 handling).

## Out of scope

- Strategy/mode toggle across CLI/REST/Telegram + schema (`credential_pools.strategy`) —
  follow-up only; note the synergy, do not build.
- Honoring upstream `Retry-After` / changing `RateLimitCooldown` constant — sticky makes
  the short cooldown harmless (we no longer re-probe the cooled member until forced), so a
  cooldown-duration change is unnecessary for this fix.

## Testing strategy

- Unit (vault): sticky hold — active member stays selected across many `ResolveActive`
  calls while a lower-position member is healthy.
- Unit (vault): flap regression — fail member A (cooldown), `ResolveActive` returns B; A's
  cooldown expires; `ResolveActive` still returns B (no snap-back). B then cools ->
  advance to next, wrapping.
- Unit (vault): all-cooling degrade unchanged; operator-parked degrade-target preserved.
- Unit (vault): sticky pointer survives `NewPoolResolverShared` regeneration + swap, and a
  stale generation cannot clobber it (extend the existing CRITICAL-1 style test).
- Unit (proxy): the failover path emits exactly ONE `cred_failover` + one notice per real
  exhaustion transition, and emits NOTHING when a non-active member's cooldown merely
  lapses (the spam regression, fail-before/pass-after).
- Full `go test ./...`, `-race` on `internal/vault` and `internal/proxy`, gofumpt,
  golangci-lint, `go vet ./...` and `-tags=e2e ./e2e/`.

## Steps

### Task 1: Sticky selection in vault.PoolResolver
- [x] Add swap-surviving per-pool current-active to shared `PoolHealth` (same mutex)
- [x] Rewrite `ResolveActive` to the sticky algorithm above; preserve degrade + parked semantics
- [x] Preserve CRITICAL-1 invariants (no loss/clobber across swap; stale generation safe)
- [x] Unit tests: sticky hold, flap regression (no snap-back), advance+wrap, degrade unchanged, swap-survival
- [x] `go test ./internal/vault/ -race`, gofumpt, vet

### Task 2: Failover path + notification spam regression
- [x] Confirm `pool_failover.go` from->to now changes only on real exhaustion (sticky source of truth); adjust only if it bypasses `ResolveActive`
- [x] Test: one `cred_failover`+notice per real transition; zero events when a non-active member's cooldown lapses (fail-before/pass-after)
- [x] `go test ./internal/proxy/ -race`, gofumpt, vet

### Task 3: Docs + final validation
- [x] Update CLAUDE.md credential-pools section to describe sticky selection (replace the position-priority wording) and note the mode-toggle follow-up
- [x] `gofumpt -l` clean; `golangci-lint run ./...` 0 issues; full `go test ./...`; `go vet ./...`; `go vet -tags=e2e ./e2e/`
- [x] Independently verify committed HEAD builds and tests pass (do not trust subagent green)
