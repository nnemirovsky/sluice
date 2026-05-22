# Pool Exhaustion Handling + Agent Auth Auto-Reset

## Overview

Two coupled problems observed live (knuth, hermes + `openai_pool` of two Codex OAuth accounts):

1. **Failover flap + Telegram notice spam.** Both pool members hit the OpenAI Codex
   *usage-limit* 429 (a multi-hour quota window). sluice cools each member for a flat
   `RateLimitCooldown = 60s`, then `ResolveActive`'s all-cooling **degrade** path re-serves
   the soonest-recovering member, which 429s again. The result is a perpetual
   `openai_oauth ⇄ openai_oauth_2` flap emitting ~2 notices/min forever. The sticky-failover
   fix (#48, `docs/plans/completed/.../20260518-sticky-failover.md`) stopped the *snap-to-0*
   flap but explicitly deferred the cooldown-window fix on the assumption that sticky made the
   60s cooldown harmless — the **degrade-path** flap proves it did not.

2. **Agent stuck after pool exhaustion.** When the whole pool is exhausted, hermes latches
   "usage limit reached", retries 3×, and gives up — it will not self-recover even after the
   quota window passes, because its local auth state is latched. It needs an explicit
   `hermes auth reset <target>` to un-latch and retry.

This plan delivers three fixes for (1) and an auto-reset for (2):

- **A1** — correct exhaustion detection: classify the pool as exhausted when *no healthy
  member exists*, not only when `to == from`; collapse the exhausted notice dedup key so the
  flap direction cannot produce two keys.
- **A2** — edge-triggered notices: emit "pool exhausted" once on the healthy→exhausted edge
  and "pool recovered" once on the way back; no periodic spam.
- **B1** — honor the real recovery window: derive the cooldown from the upstream
  `Retry-After` / rate-limit-reset hints (clamped), so a quota-exhausted member stays cooled
  for the real window instead of being re-probed every 60s. This is what makes the degrade
  flap structurally impossible and makes "recovered" mean recovered.
- **Auto-reset (problem 2)** — opt-in, per-pool: when a pool with a configured
  `auth_reset_target` transitions exhausted→recovered, sluice runs the agent's auth-reset
  command (hermes profile, **as the runtime UID 10000:10000**) so the agent un-latches.

## Context (from discovery)

- Language/stack: Go, pure-Go SQLite (`modernc.org/sqlite`), go-mitmproxy addon model.
- Failover logic: `internal/proxy/pool_failover.go` (`handlePoolFailover`, `classifyFailover`,
  `FormatFailoverNotice`, `shouldEmitPoolNotice`, dedup key `pool+from+to+tag`, 30s window).
- Resolver/health: `internal/vault/pool.go` (`PoolResolver`, shared `PoolHealth`,
  `ResolveActive` sticky pointer + all-cooling **degrade returns a still-cooling member with
  ok=true**, `MarkCooldownScoped`, `CooldownUntil`, `cooling()` = `cooldownUntil.After(now)`,
  constants `RateLimitCooldown=60s` / `AuthFailCooldown=300s`).
- Addon state: `internal/proxy/addon.go` (`SluiceAddon` incl. `onFailover`,
  `poolNoticeMu`/`poolNoticeAt`); `SetOnFailover` on `internal/proxy/server.go`.
- Failover side-effects wiring: `cmd/sluice/main.go:489` (`srv.SetOnFailover(...)` → durable
  health write + Telegram notice, fresh `context.WithTimeout(Background,10s)` per send).
  Container manager var `containerMgr` (main.go:242); `ReloadSecrets` pattern at main.go:673.
- Agent abstraction: `internal/container/agent_profile.go` (`AgentProfile.ReloadCmd`,
  `WireMCPCmd`); `ContainerManager` interface `internal/container/types.go`; backends
  `docker.go` / `apple.go` / `tart.go` / standalone. **`ExecInContainer(ctx,name,cmd)` takes
  NO user** (`docker.go:18`, `docker_socket.go:245`; `execCreateRequest` at
  `docker_socket.go:247` has no `User`) → today an exec runs as root, which root-chowns
  hermes `auth.json` and bricks the gateway (CLAUDE.local.md). `InjectEnvVars` avoids this by
  chowning inside its script (types.go:299-321) — that trick does NOT help a command that
  writes files itself, so `hermes auth reset` genuinely must exec as 10000:10000.
- Pools store + channel-agnostic ops: `internal/store/pools.go`, migrations
  `internal/store/migrations/000006_credential_pools.*` (down `DROP TABLE`s all three:
  `credential_pools`, `credential_pool_members` FK→pools(name), `credential_health`;
  `pool_membership_epoch` machinery in pools.go:78-97), `internal/poolops`.
- **REST is generated**: `internal/api/api.gen.go` is `DO NOT EDIT`, produced by
  `make generate` → `oapi-codegen --config config.yaml ../../api/openapi.yaml`
  (Makefile:64, generate.go). Existing pool routes: `GetApiPools`/`PostApiPools`/
  `DeleteApiPoolsName`/`GetApiPoolsName`/`PostApiPoolsNameRotate` (api.gen.go:911-935).
  New surface = edit `openapi.yaml` → `make generate` → implement the new generated
  `ServerInterface` method in `internal/api/server.go`. Action-route style
  (`POST .../rotate`) is the established mutation pattern.
- **No server run loop**: `ListenAndServe` just calls `s.socks.Serve`; shutdown is
  `GracefulShutdown`/`Close` flipping `s.closed` (server.go:2864/2876/2891). A new monitor
  goroutine needs its own explicit stop signaled from BOTH shutdown paths.
- Pools are **not** TOML-exportable (no `[[pool]]` in `policy export`/`examples/config.toml`),
  so the new field needs no TOML surface.
- The data-version watcher fires only on DB writes (`internal/store/watcher.go`, main.go:810)
  — it is NOT a timer, so recovery-edge detection needs its own monitor.
- `f.Response.Header.Get(...)` is available on the mitmproxy Flow (used in `addon.go` DLP).

## Development Approach

- **Testing approach: Regular** (implement, then table-driven tests in the same task).
- Complete each task fully (code + tests + green) before the next.
- **Every task includes new/updated unit tests** (success + error/edge), as separate checklist
  items. All tests pass before moving on.
- Preserve all existing pool concurrency invariants (CRITICAL-1 shared `PoolHealth`,
  identity/epoch-scoped writes, sticky-pointer survival across resolver swaps).
- Channel feature parity is mandatory (CLAUDE.md): any new store-backed pool field must be
  reachable from CLI **and** REST **and** Telegram via the channel-agnostic `internal/poolops`.
- gofumpt before committing (CI enforces it). `go vet`, `golangci-lint`, `-race` on touched
  packages, `make generate` clean tree, and `-tags=e2e ./e2e/` build.

## Testing Strategy

- **Unit (vault)**: cooldown-from-hints parsing (each header form, clamp floor/ceiling);
  `HasHealthyMember` mirrors `cooling()` lazy-expiry exactly; `SoonestCooldown` strictly-future;
  degrade unchanged; exhaustion detection edge.
- **Unit (proxy)**: exactly one "exhausted" notice per healthy→exhausted edge regardless of
  flap direction; one "recovered" notice on the reverse edge; recovery monitor reschedules on
  *unequal* member cooldowns (B1 parks memA 60s, memB 6h → wake at ~60s, recover once);
  monitor stops on shutdown; B1 cooldown applied from headers.
- **Unit (store)**: migration up→down→up with a **populated** pool + members + health rows;
  `auth_reset_target` round-trips; default empty.
- **Unit (poolops/channels)**: create/update with target through the channel-agnostic layer;
  one adapter test per channel asserting it routes through poolops (no inline logic).
- **Unit (container)**: exec-user threading; `ResetAuth` argv per profile; nil-cmd no-ops with
  a notice; (docker) exec carries the runtime UID.
- No UI e2e here (backend/CLI only); keep the existing `-tags=e2e` suite building.

## Progress Tracking
- mark completed items `[x]` immediately; add ➕ for new tasks, ⚠️ for blockers.
- keep this file in sync if scope shifts during implementation.

## Solution Overview

**B1 — real recovery window.** Add `cooldownFromResponse(class, resp) time.Duration` in
`pool_failover.go`. Precedence: `Retry-After` (delta-seconds or HTTP-date) → known
rate-limit-reset headers (`x-ratelimit-reset`, OpenAI `x-ratelimit-reset-requests` /
`x-ratelimit-reset-tokens`; delta-seconds or epoch). **No body parsing in v1** (deferred to
Post-Completion until a real Codex 429 is captured). Clamp to `[minFloor(class), maxCooldown]`
where `maxCooldown = 6h`, `minFloor(rate-limit) = 10s` (a parsed short window must be honored —
the whole point is 60s is too *long*-floored, not too short — so do NOT floor up to the 60s
class default), `minFloor(auth-failure) = AuthFailCooldown` (a revoked/expired token must not
be retried in seconds). When **no** hint header is present, fall back to the class default
(60s / 300s). `handlePoolFailover` uses this instead of the flat `ttl`. **Task-1 tests assert
parsing/clamp mechanics generically; they must NOT bake in which header OpenAI's usage-limit
429 actually sends** — that is resolved by the Post-Completion capture, and a guessed winner
here would contradict it.

**A1 — correct exhaustion detection.** Add `PoolResolver.HasHealthyMember(pool) bool`
(RLock, single `now`, true iff some member has `!cooling()` — mirrors `ResolveActive`'s
`cooling()` lazy-expiry exactly, NOT a status-field check). In `handlePoolFailover`, after
`MarkCooldownScoped(from)`, set `exhausted = !pr.HasHealthyMember(pool)` (replaces
`to == from`). When exhausted, collapse the dedup so flap direction yields one key:
`shouldEmitPoolNotice(pool, "*", "*", "exhausted")` (only the exhausted path; real
transitions keep `from/to/tag`).

**A2 — edge-triggered notices + recovery monitor (authoritative for the exhausted notice).**
Per-pool exhaustion state lives on the long-lived `Server` (NOT on `PoolHealth`): exhaustion
is per-process notification bookkeeping, not per-resolver-generation health, so it must
survive resolver pointer swaps and must NOT be pruned on a membership change — putting it on
`PoolHealth` would wrongly prune it. `handlePoolFailover` flips `false→true` on the first
exhausted classification, emits the one-time "exhausted" notice on that edge, and wakes the
monitor (non-blocking buffered cap-1 send). **Edge-gating in A2 supersedes A1's 30s-window
dedup for the exhausted notice** — the edge owns it; the window dedup remains only for real
`from→to` transitions. A dedicated **recovery monitor** goroutine sleeps until the pool's
soonest *strictly-future* member cooldown (clamped to a `minReschedule = 1s` floor so a
just-expired-but-still-unhealthy state can't spin), `Load()`s the current resolver on every
wake (never caches it), and when `HasHealthyMember(pool)` becomes true flips `true→false`,
emits "pool recovered", and invokes `onPoolRecovered(pool)`. Server-driven (time-based, not
traffic-based) because the latched agent will not emit a recovering 2xx on its own. A pool
removed while exhausted has its state entry cleaned up so no recovered-notice fires for a
deleted pool.

**Auto-reset (problem 2).** Per-pool `auth_reset_target TEXT` (migration 000007); non-empty =
opt-in. New `AgentProfile.ResetAuthCmd(target) []string` + `AgentProfile.ExecUser() string`
(hermes → `"10000:10000"`, openclaw → ""), `ContainerManager.ResetAuth(ctx, target)` parallel
to `ReloadCmd`/`ReloadSecrets`. `HermesProfile.ResetAuthCmd` → pure-argv
`["/opt/hermes/.venv/bin/hermes","auth","reset",target]` (no `sh -c`, so no shell-metachar
threat). `OpenclawProfile.ResetAuthCmd` nil pending verification openclaw latches
(Post-Completion). `onPoolRecovered` (wired in main.go) looks up the recovered pool's
`auth_reset_target`; if set, calls `containerMgr.ResetAuth(ctx, target)` in a detached
goroutine with a fresh `context.WithTimeout(Background, …)` (mirroring the `SetOnFailover`
precedent) and emits an `agent_auth_reset` audit event.

## Technical Details

- **New constants** (`internal/vault/pool.go`): `maxCooldown = 6h`, `minRateLimitFloor = 10s`,
  `minReschedule = 1s`.
- **New resolver methods** (`internal/vault/pool.go`, both RLock-only, single `now`):
  `HasHealthyMember(pool) bool`; `SoonestCooldown(pool) (time.Time, bool)` returning the
  minimum `cooldownUntil` **strictly greater than a freshly-sampled `now`** (bool=false when
  no member is currently cooling).
- **Exec-user plumbing** (Task 6): add `User string` to `execCreateRequest`
  (`docker_socket.go`), thread an optional user through `ExecInContainer` on both
  `ContainerClient` and `SocketClient` (default "" = unchanged root behavior), update the
  `mockClient` in `docker_test.go` and all existing callers (no-op default).
- **Migration `000007_pool_auth_reset.{up,down}.sql`**: up = `ALTER TABLE credential_pools
  ADD COLUMN auth_reset_target TEXT NOT NULL DEFAULT ''`. down = the SQLite 12-step rebuild of
  `credential_pools` only, wrapped in `PRAGMA foreign_keys=OFF;` … `=ON;` so the
  `credential_pool_members` FK→`credential_pools(name)` is not orphaned/failed (golang-migrate
  runs each file as a script).
- **Store** (`internal/store/pools.go`): add `AuthResetTarget` to `Pool`; include in
  create/list; add `SetPoolAuthResetTarget(name, target) error`. No TOML change (pools aren't
  TOML-exportable).
- **Recovery state on `Server`**: `poolExhaustMu sync.Mutex`, `poolExhausted map[string]bool`,
  `recoveryWake chan struct{}` (buffered cap-1, non-blocking send), `monitorStop chan struct{}`
  + `monitorStopOnce sync.Once`, `onPoolRecovered func(pool string)` via `SetOnPoolRecovered`.
  Monitor launched once (in `New`/a `StartMonitors`), stopped idempotently from BOTH `Close`
  and `GracefulShutdown`.
- **Audit**: new action `agent_auth_reset` (`Verdict:"recover"`, `Credential:` recovered pool,
  `Reason:` target). Keep `pool_exhausted` for the entry edge; add a recovered audit/notice.
- **Target validation**: non-empty, no NUL, allowlisted charset (mirror `ValidateEnvVarKey`
  style) — argv form, so shell-metachar checks are the wrong model.

## What Goes Where
- **Implementation Steps** (`[ ]`): all code, migrations, generated-API regen, tests, in-repo docs.
- **Post-Completion** (no checkboxes): openclaw latch verification + `ResetAuthCmd`; live
  knuth validation; capturing a real OpenAI 429 to fix B1's header precedence + `maxCooldown`.

## Implementation Steps

### Task 1: B1 — derive cooldown from upstream recovery hints

**Files:**
- Modify: `internal/vault/pool.go` (constants `maxCooldown`, `minRateLimitFloor`)
- Modify: `internal/proxy/pool_failover.go`
- Modify: `internal/proxy/pool_failover_test.go`

- [x] add `maxCooldown = 6*time.Hour` and `minRateLimitFloor = 10*time.Second` near the TTLs
  (exported as `MaxCooldown`/`MinRateLimitFloor` so the proxy package can clamp against them,
  mirroring `RateLimitCooldown`/`AuthFailCooldown`)
- [x] add `cooldownFromResponse(class failoverClass, header http.Header) time.Duration`
  (takes `http.Header` directly so it works against the go-mitmproxy Flow's `Response.Header`):
  parse `Retry-After` (delta-seconds + HTTP-date), then `x-ratelimit-reset` /
  `x-ratelimit-reset-requests` / `x-ratelimit-reset-tokens` (delta or epoch); clamp to
  `[minFloor(class), MaxCooldown]` (rate-limit floor `MinRateLimitFloor`, auth-failure floor
  `AuthFailCooldown`); **no hint → class default**. No body parsing in v1.
- [x] in `handlePoolFailover` replace the flat `ttl` with `cooldownFromResponse(class, f.Response.Header)`
- [x] write tests (generic parsing/clamp, NOT a Codex-specific header winner): Retry-After
  seconds; Retry-After HTTP-date; epoch reset header; delta reset header; no headers → class
  default; absurd value → `MaxCooldown`; tiny rate-limit value honored down to
  `MinRateLimitFloor`; auth-failure floored at `AuthFailCooldown`
- [x] run `go test ./internal/proxy/ ./internal/vault/ -race`; gofumpt; vet — pass before Task 2

### Task 2: A1 — exhaustion = no healthy member, collapse dedup key

**Files:**
- Modify: `internal/vault/pool.go` (`HasHealthyMember`, `SoonestCooldown`)
- Modify: `internal/proxy/pool_failover.go`
- Modify: `internal/vault/pool_test.go`, `internal/proxy/pool_failover_test.go`

- [x] add `HasHealthyMember(pool) bool` (RLock, single `now`, `!cooling()` for some member —
  mirror `cooling()`/lazy-expiry, not a status field) and `SoonestCooldown(pool)
  (time.Time, bool)` (strictly-future min vs a fresh `now`)
- [x] in `handlePoolFailover` set `exhausted = !pr.HasHealthyMember(pool)` (drop `to == from`);
  keep computing `to` for the real-transition notice/audit
- [x] when `exhausted`, key the dedup as `shouldEmitPoolNotice(pool, "*", "*", "exhausted")`
  so flap direction can't create two keys (real transitions unchanged)
- [x] write tests: 2-member pool both cooling → exhausted true; one healthy (incl. a
  lazily-expired cooldown still in the map) → false; `SoonestCooldown` skips already-passed
  entries; exhausted dedup collapses both flap directions to one notice within the window
  (fail-before/pass-after). NOTE: Task 3 re-gates this to an edge — update this assertion there.
- [x] run `go test ./internal/vault/ ./internal/proxy/ -race`; gofumpt; vet — pass before Task 3

### Task 3: A2 — per-pool exhaustion state machine, edge notices, recovery monitor

**Files:**
- Modify: `internal/proxy/server.go` (state, monitor goroutine, lifecycle, `SetOnPoolRecovered`)
- Modify: `internal/proxy/addon.go` (exhaustion-edge hook into the server state)
- Modify: `internal/proxy/pool_failover.go` (entry-edge gating; recovered notice formatter)
- Modify: `internal/proxy/server_test.go` (+ focused new test file as needed)

- [x] add `poolExhaustMu`/`poolExhausted`/`recoveryWake`(cap-1)/`monitorStop`+`monitorStopOnce`/
  `onPoolRecovered` to `Server`; `SetOnPoolRecovered`; document WHY state is on `Server` not
  `PoolHealth` (survives swaps, must not be pruned on membership change). Also added a separate
  `onPoolRecoveredNotice` callback (notice always fires; auth-reset stays opt-in per Task 8) and
  a test-shortenable `recoveryMinReschedule` field.
- [x] launch the monitor once (in `New`); stop it idempotently from BOTH
  `Close` and `GracefulShutdown` (via `monitorStopOnce`/`stopMonitors`)
- [x] gate the "exhausted" notice on the `false→true` edge (one notice on entry; this edge —
  not the 30s window — is authoritative for the exhausted notice); record state; wake the
  monitor with a non-blocking `select { case recoveryWake <- struct{}{}: default: }`. Wired via
  addon `onPoolExhausted` hook (`SetOnPoolExhausted`, mirroring `SetOnFailover`); addon-only
  tests with no Server fall back to the A1 30s-window collapse.
- [x] implement the monitor: each wake `Load()` the current resolver (never cache); compute
  `sleep = max(SoonestCooldown(pool).Sub(time.Now()), minReschedule)`; on wake, for each
  exhausted pool flip `true→false` when `HasHealthyMember` is true, emit "pool recovered",
  call `onPoolRecovered(pool)`; reschedule while still exhausted; drop state for pools no
  longer present
- [x] add a recovered-notice formatter (plain text, sentence style) alongside
  `FormatFailoverNotice` (`FormatPoolRecoveredNotice`)
- [x] update the Task-2 exhausted-notice test to assert EDGE behavior (one notice per
  healthy→exhausted edge across many failing responses), not 30s-window behavior. Added
  `TestExhaustedNoticeEdgeAcrossManyResponses` (Server-wired edge path); the existing addon-only
  Task-2 tests retain the 30s-window assertion for the no-Server fallback path.
- [x] write tests: entry edge emits exactly one exhausted notice; recovery edge emits exactly
  one recovered notice + one `onPoolRecovered` call; **unequal cooldowns** (memA short, memB 6h)
  → monitor wakes ~soonest, recovers once though memB still cools; monitor stops on shutdown
  (double-stop no panic); a pool removed while exhausted fires no recovered notice
- [x] run `go test ./internal/proxy/ -race`; gofumpt; vet — pass before Task 4

### Task 4: Schema + store for per-pool `auth_reset_target`

**Files:**
- Create: `internal/store/migrations/000007_pool_auth_reset.up.sql`
- Create: `internal/store/migrations/000007_pool_auth_reset.down.sql`
- Modify: `internal/store/pools.go`
- Modify: `internal/store/pools_test.go`

- [x] up: `ALTER TABLE credential_pools ADD COLUMN auth_reset_target TEXT NOT NULL DEFAULT ''`
  (migration `000008_pool_auth_reset` — `000007` was already taken by `pool_membership_epoch`)
- [x] down: SQLite 12-step rebuild of `credential_pools` only; because golang-migrate runs each
  script inside a transaction and SQLite ignores `PRAGMA foreign_keys=OFF` while a transaction is
  open, the FK-referencing `credential_pool_members` rows are snapshotted to a temp table and
  restored after the rebuild instead (cascade-safe, FK preserved)
- [x] add `AuthResetTarget` to `Pool`; include in create/list reads; add
  `SetPoolAuthResetTarget(name, target) error`
- [x] write tests: migrate up→down→up against a **populated** table (pool + members + health
  rows survive/round-trip); default empty; create with target; set/clear target; list reflects it
- [x] run `go test ./internal/store/ -race`; gofumpt; vet — pass before Task 5

### Task 5: Channel parity — `auth_reset_target` on CLI + REST + Telegram

**Files:**
- Modify: `internal/poolops/*.go` (set/clear + create-with-target operation logic)
- Modify: `cmd/sluice/pool.go` (flag on `pool create`; `pool set-auth-reset`)
- Modify: `api/openapi.yaml`; then `make generate` → implement new method in `internal/api/server.go`
- Modify: Telegram `/pool` handler
- Modify: matching `_test.go` for poolops + each channel adapter

- [ ] add the operation to `internal/poolops` (channel-agnostic) so all channels are thin
  adapters (CLAUDE.md anti-pattern note)
- [ ] CLI: `--auth-reset-target` on `pool create`; `pool set-auth-reset <name> <target|->`
  (set/clear); show target in `pool status`/`pool list`
- [ ] REST: accept on `POST /api/pools`; add an **action route** `POST
  /api/pools/{name}/auth-reset-target` (mirrors the existing `/rotate` style, not a bespoke
  PATCH); edit `api/openapi.yaml`, run `make generate`, implement the generated
  `ServerInterface` method in `server.go`
- [ ] Telegram: accept on `/pool create`; add `/pool set-auth-reset <name> <target|->`
- [ ] write tests: poolops set/clear/create-with-target; one adapter test per channel
  asserting it routes through poolops (no inline logic)
- [ ] run `go test ./... -race` for touched packages; `make generate` clean; gofumpt; vet —
  pass before Task 6

### Task 6: Add optional exec user to the container exec path (prerequisite for hermes reset)

**Files:**
- Modify: `internal/container/types.go` (`ExecInContainer` signature / `ContainerClient`)
- Modify: `internal/container/docker.go`, `internal/container/docker_socket.go`
  (`execCreateRequest.User`)
- Modify: `internal/container/docker_test.go` (`mockClient`) + any other `ExecInContainer` callers
- Modify: `internal/container/agent_profile.go` (`AgentProfile.ExecUser() string`)

- [ ] add `User string` to `execCreateRequest`; thread an optional user arg through
  `ExecInContainer` on `ContainerClient` + `SocketClient` (empty "" = current root behavior)
- [ ] update `mockClient` and every existing `ExecInContainer` caller (no-op default, no
  behavior change)
- [ ] add `ExecUser() string` to `AgentProfile` (hermes `"10000:10000"`, openclaw "")
- [ ] write tests: socket exec body carries `User` when set and omits/empties it otherwise;
  profile `ExecUser` values; existing callers unaffected
- [ ] run `go test ./internal/container/ -race`; gofumpt; vet — pass before Task 7

### Task 7: Profile `ResetAuthCmd` + `ContainerManager.ResetAuth`

**Files:**
- Modify: `internal/container/agent_profile.go`
- Modify: `internal/container/types.go`
- Modify: `internal/container/docker.go`, `apple.go`, `tart.go`, standalone (`none`)
- Modify: `internal/container/agent_profile_test.go`, `docker_test.go`

- [ ] add `ResetAuthCmd func(target string) []string` to `AgentProfile`; `HermesProfile` →
  pure-argv `["/opt/hermes/.venv/bin/hermes","auth","reset",target]`;
  `OpenclawProfile.ResetAuthCmd` nil (documented; Post-Completion verification)
- [ ] add `ResetAuth(ctx, target string) error` to `ContainerManager`; implement per backend;
  nil `ResetAuthCmd` → log notice, return nil (mirror `ReloadSecrets`); docker exec passes
  `profile.ExecUser()` (Task 6) so hermes runs as 10000:10000
- [ ] validate `target` (non-empty, no NUL, allowlisted charset) before exec
- [ ] write tests: argv per profile; nil-cmd no-ops with notice; empty/invalid target
  rejected; **docker exec uses the runtime UID from `ExecUser` (now passable, Task 6)**
- [ ] run `go test ./internal/container/ -race`; gofumpt; vet — pass before Task 8

### Task 8: Wire auto-reset on the recovery edge (opt-in, per pool)

**Files:**
- Modify: `cmd/sluice/main.go` (`srv.SetOnPoolRecovered(...)`)
- Modify: `internal/proxy/pool_failover.go` / audit usage (`agent_auth_reset` action)
- Modify: relevant `_test.go`

- [ ] in main.go register `SetOnPoolRecovered`: look up the recovered pool's
  `auth_reset_target`; if non-empty and `containerMgr != nil`, call
  `containerMgr.ResetAuth(ctx, target)` in a detached goroutine using a fresh
  `context.WithTimeout(context.Background(), …)` (never block; never reuse a wake-scoped ctx);
  log + emit `agent_auth_reset`; empty target → no reset (opt-out default)
- [ ] keep the recovered Telegram notice (Task 3) and the reset independent (notice always;
  reset only when target set); a `ResetAuth` error is logged, not fatal
- [ ] write tests: target set → recovery triggers `ResetAuth(target)` once; no target → no
  reset, notice still emitted; `ResetAuth` error logged not fatal
- [ ] run `go test ./... -race` for touched packages; gofumpt; vet — pass before Task 9

### Task 9: Verify acceptance criteria
- [ ] both members exhausted → exactly one "pool exhausted" notice (no flap stream)
- [ ] B1 cooldown reflects the upstream window (member not re-probed every 60s)
- [ ] recovery edge → one "pool recovered" notice; auth reset fires only for pools with a
  target; hermes reset runs as 10000:10000 (no root-chown of auth.json)
- [ ] channel parity verified: `auth_reset_target` settable+readable via CLI, REST, Telegram
- [ ] full `go test ./...`; `go vet ./...`; `go vet -tags=e2e ./e2e/`; `gofumpt -l` clean;
  `golangci-lint run ./...` 0 issues; `make generate` then `git diff --exit-code
  internal/api/api.gen.go` clean
- [ ] independently verify committed HEAD builds + tests pass (do not trust subagent green)

### Task 10: [Final] Documentation
- [ ] update `CLAUDE.md` credential-pools section: B1 cooldown-from-hints, A1/A2
  exhaustion+edge notices (replacing the per-window dedup wording), per-pool
  `auth_reset_target` + recovery auto-reset, the `agent_auth_reset` audit action, and the
  `ResetAuthCmd`/`ExecUser` profile hooks in the Agent Profiles table
- [ ] cross-check the CLI subcommand list + the auto-generated `api/openapi.yaml` in CLAUDE.md
- [ ] move this plan to `docs/plans/completed/`

## Post-Completion
*Items requiring manual intervention or external systems — informational only*

**Manual verification:**
- Deploy `sluice:dev` to knuth (build→scp→load loop), set `auth_reset_target = openai-codex`
  on `openai_pool`, exhaust both Codex accounts, and confirm: one exhausted notice, no flap;
  after the real window, one recovered notice + hermes auth un-latches and resumes without a
  manual `hermes auth reset`; `auth.json` stays owned by 10000.
- **Capture a real OpenAI Codex usage-limit 429** (headers + body) to confirm which recovery
  hint is present (`Retry-After` vs `x-ratelimit-reset*` vs body) and fix B1's header
  precedence / `maxCooldown` accordingly. Add the body-hint parser only if the capture proves
  no usable header exists.

**External / follow-up:**
- **openclaw latch**: verify whether openclaw latches on usage-limit and, if so, implement
  `OpenclawProfile.ResetAuthCmd` (gateway RPC, like `ReloadCmd`). hermes-only until confirmed.
- Selectable pool strategy (position-priority vs sticky) remains the previously-noted
  follow-up; out of scope here.
