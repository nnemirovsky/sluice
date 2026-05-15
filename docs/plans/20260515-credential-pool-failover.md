# Credential Pool with Auto-Failover (multi-account OAuth)

## Overview

Let a single phantom identity the agent sees be backed by **N real OAuth
credentials** (a "pool"), with sluice picking which real account to inject and
**auto-failing-over to the next member when the upstream returns 429
(rate-limited) or 401 / `invalid_grant` (auth-failure)**. Primary use case: two
OpenAI Codex OAuth accounts driven by one Hermes agent, so quota exhaustion on
one account transparently rolls onto the other.

The agent always holds **one pool-scoped phantom pair**
(`SLUICE_PHANTOM:<pool>.access` / `.refresh`). Sluice maps the pool phantom to
the *currently active member's* real token at injection time, and persists
refreshed tokens back to the member that actually issued them.

**Phantom-stability decision (resolved — see Risk R3):** OpenAI Codex access
tokens are JWTs and `resignJWT` (`internal/proxy/oauth_response.go:49-69`) is
deterministic *per real token*, not per pool — so the naive design would emit a
**different** phantom JWT after every cross-member refresh, breaking the
"agent never notices" property. Phase 1 therefore makes pooled OAuth
credentials use a **pool-stable synthetic resign**: the phantom JWT is built
from a deterministic synthetic payload keyed on the *pool name* (stable
`sub`/`iss`, far-future `exp`), HMAC'd with the existing fixed key, so the
phantom is byte-identical across member switches while remaining a
structurally valid JWT. (Fallback if Codex/Hermes is verified to treat the
access token as opaque: emit the static `SLUICE_PHANTOM:<pool>.access` form.
The synthetic-JWT path is primary because `resignJWT` exists specifically
because *something* parses the JWT client-side; we must not assume opacity.)

## Context

Verified against the working tree on `main` (tip `20cc367`; all symbol/line
references checked against current files, not a fixed SHA):

- `internal/vault/oauth.go:9-54` — `OAuthCredential{AccessToken, RefreshToken, TokenURL, ExpiresAt}`; `UpdateTokens()` recomputes `ExpiresAt`. `ExpiresAt` is stored but **never read** before injection today.
- `internal/proxy/phantom.go:42-44` — `PhantomToken(name) = "SLUICE_PHANTOM:"+name`. OAuth variant `SLUICE_PHANTOM:<cred>.access` / `.refresh`. Phantom strings derive purely from the credential name — this is what makes a *pool-scoped* phantom feasible.
- `internal/proxy/oauth_response.go` — `oauthPhantomAccess(credName, realToken...)` `:27`, `resignJWT(realToken)` `:49-69` (HMACs `header.payload` with a fixed key; **per-real-token deterministic, NOT per-pool** — root of Risk R3).
- `internal/vault/binding.go:78-134` — `BindingResolver.Resolve`/`ResolveForProtocol` return the **first** match only. `CredentialsForDestination` `:184-214` returns all matching cred names (used by phantom-swap pass 2).
- `internal/proxy/addon.go`:
  - `injectHeaders` `:532`, pass-1 single-credential header inject `~:553` (`provider.Get(binding.Credential)`).
  - response credential match `idx.Match(f.Request.URL)` at `~:768` and `~:895` — **no per-stream linkage to the request that was injected** (root of Risk R1).
  - `swapOAuthTokens` `:1059`, `persistAddonOAuthTokens` `:1098-1162` (singleflight key `"persist:"+credName`), `connState` keyed by `ClientConn.Id` `:42` (one client conn, many h2 streams).
  - `extractInjectableSecret` / `OAuthIndex.Has(credName)` gate JSON-envelope vs raw injection — **a pool name is not in `credential_meta`, so `Has(pool)` is false** unless pool indirection is applied at every consumer (Important I2).
- `internal/proxy/oauth_index.go:81-95` — `OAuthIndex.Match(url) -> (credName, ok)` strict **1:1** token_url→credential. `OAuthIndex.Has` `:114`. Two Codex accounts share `auth.openai.com`'s token URL → they collide here; response attribution **must not** use this for pooled creds (Risk R1).
- `internal/store/store.go`: `BindingRow` `:539`, `AddBinding` `:570-650`, UNIQUE `(credential, LOWER(destination))` (`migrations/000005_...sql`). `CredentialMeta{Name,CredType,TokenURL,CreatedAt}` `:1689`, `AddCredentialMeta` upsert `:1697`, `ListCredentialMeta` `:1740`. Latest migration is `000005`; new one is `000006`.
- Hot-reload: `cmd/sluice/main.go:649-716` `reloadAll` rebuilds engine, `StoreResolver`, `UpdateOAuthIndex`, env injection; triggered by SIGHUP and the **2s** `PRAGMA data_version` watcher (this 2s lag is a correctness amplifier for failover — Important I1).
- No existing failover / rotation / health / round-robin logic anywhere (grep-confirmed).

Decision (confirmed with user): **auto-failover on 429/401**. Manual `pool
rotate` is an operator override, not the primary mechanism.

## Development Approach

- **Testing approach**: Regular (code first, then tests). Tests are enumerated as explicit per-task checklist items, not deferred to phase exits.
- gofumpt before every commit (`feedback_gofumpt`); PR to `main`, never direct push (`feedback_pr_workflow`).
- Phased — each phase independently shippable and testable. Do not start a phase before the previous one's tests pass.
- This is a `feat`; new migration `000006` (next in sequence). No major bump implied (no CLI/schema break to existing surface).

## Testing Strategy

- **Unit**: pool CRUD + member ordering; active-member selection (healthy / in-cooldown / all-down degrade); **pool→active-member resolution at the single chokepoint**; **OAuth refresh attribution by injected real refresh token, including the two-members-one-token-URL collision (must land on the correct member)**; **fail-closed when the member tag is absent (skip persist, log, no guess)**; **phantom access token byte-identical across a member switch** (synthetic-JWT path); failover classification (429 / 403+`insufficient_quota` / 401 / `invalid_grant` / 200 / 5xx-noop); cooldown expiry.
- **Unit**: migration up/down; CLI parse + error paths; pool/credential namespace mutual-exclusion.
- **E2e** (`e2e` tag): two fake OAuth upstreams behind one pool; assert (a) A used until it 429s, (b) sluice switches to B for the *next* request, (c) B's refreshed tokens land in B's vault entry not A's, (d) the phantom access token the agent receives is byte-identical before and after failover (test upstream must return real **JWT** tokens so this assertion is meaningful).

## Phases

### Task 1: Phase 0 — Data model + CLI (no runtime behavior change)

- [x] Migration `internal/store/migrations/000006_credential_pools.{up,down}.sql`: `credential_pools`, `credential_pool_members`, `credential_health` tables with the documented CHECK constraints.
- [x] Store API `internal/store/store.go`/`pools.go`: pool CRUD + member ordering + `Set/Get/ListCredentialHealth`; reject `static` members; `cred remove` errors on a live pool member.
- [x] CLI `cmd/sluice/pool.go`: `pool create/list/status/rotate/remove`.
- [x] Namespace mutual-exclusion (pool name vs credential name) at create time.
- [x] `reloadAll` loads pool + health into an atomic-pointer-swapped `PoolResolver` (no injection consumption yet).
- [x] re-run `go test ./internal/store/... ./internal/vault/... ./cmd/...` to confirm Phase 0 still green after merge.

### Task 2: Phase 1 — Phantom indirection (pool phantom → active member)

**Files:** `internal/vault/pool.go`, `internal/proxy/addon.go`, `internal/proxy/oauth_response.go`, `internal/proxy/oauth_index.go`, `cmd/sluice/main.go` + tests

- [ ] `PoolResolver.IsPool(name)` + `ResolveActive(name)` (healthy/expired-cooldown first by position; all-in-cooldown → soonest-recovering + WARNING; plain cred returned unchanged).
- [ ] Route EVERY `binding.Credential` / `OAuthIndex.Has` / `extractInjectableSecret` / `findAdder`/persist consumer through `ResolveActive` at one chokepoint (grep `binding.Credential`, `\.Has(`, `extractInjectableSecret`; do not scatter `IsPool` checks).
- [ ] Injection (`addon.go` pass-1 header + pass-2 phantom swap) injects the active member's real value while matching/replacing the pool-scoped phantom string.
- [ ] R1 per-request member tag: record `realRefreshToken → member` (short-TTL map) when pass-2 swaps `SLUICE_PHANTOM:<pool>.refresh`; on token-endpoint response recover member by that real refresh token; persist to that member (`persistAddonOAuthTokens(member,...)`, singleflight `"persist:"+member`).
- [ ] R1 fail-closed: if member unrecoverable, do NOT guess, do NOT fall back to `OAuthIndex.Match` for pooled token URLs — WARNING + skip vault write.
- [ ] R1 dedicated unit test: two members, same token URL — B-refresh never overwrites A; missing tag → zero writes.
- [ ] R3 pool-stable phantom: pooled OAuth `oauthPhantomAccess`/`resignJWT` build the JWT from a deterministic synthetic payload keyed on the pool name (byte-identical across member switch). Unit test asserts byte-identity across a switch; document static-form fallback.
- [ ] `cmd/sluice/main.go:reloadAll` builds & swaps `PoolResolver` + health snapshot alongside existing swaps.
- [ ] `go test ./... -timeout 120s` green; build clean; gofumpt.

### Task 3: Phase 2 — Auto-failover on 429 / 401

**Files:** `internal/proxy/addon.go`, `internal/vault/pool.go`, audit logger, telegram + tests

- [ ] Failure classification in `SluiceAddon.Response` for pooled destinations: 429 or 403+`insufficient_quota` → rate-limited; 401 or token-body `invalid_grant`/`invalid_token` → auth-failure; 5xx/other → no-op.
- [ ] Prompt failover: synchronously update in-memory `PoolResolver` health BEFORE the response returns (documented locking discipline); also `SetCredentialHealth(member,'cooldown',now+ttl,reason)` for durability (2s watcher only reconciles). Cooldown TTL consts: rate-limit 60s, auth-fail 300s; lazy recovery in `ResolveActive`.
- [ ] Audit `cred_failover` with `Reason = "<pool>:<from>-><to>:<429|403|401|invalid_grant>"`.
- [ ] Telegram best-effort non-blocking notice "pool `<name>` failed over `<a>`→`<b>` (<reason>)".
- [ ] No in-flight retry (documented); next request uses new member.
- [ ] Unit tests for classification + synchronous health swap + cooldown TTL/lazy recovery; `go test ./... -timeout 120s` green; build clean; gofumpt.

### Task 4: Verify acceptance + docs

- [ ] full `go test ./... -timeout 120s`; e2e `go test -tags=e2e ./e2e/ -count=1 -timeout=300s` (if e2e cannot run here, state so explicitly in the progress file, do not silently skip).
- [ ] update CLAUDE.md credential-pool/failover notes.
- [ ] move plan to `docs/plans/completed/`.

## Out of scope / future work

Transparent in-flight retry; round-robin/weighted (`strategy` reserved, `failover` only); active health probes / half-open; multi-agent pools with independent active pointers.

## Risks / decisions

- **R1 (critical, resolved in Phase 1.3):** refresh-token mis-attribution corrupts both accounts (rotating refresh tokens are single-use; filing B's new token under A invalidates A and bricks B's old one). Join key is the real **refresh** token sluice injected, not the access token, not the client connection. Fail-closed, never guess. Dedicated collision unit test mandatory.
- **R3 (critical, resolved in Phase 1.4):** `resignJWT` is per-real-token, so the agent's phantom would change on every cross-member refresh — the headline guarantee. Resolved via pool-keyed synthetic JWT; byte-identity unit test mandatory; static-form fallback documented.
- **I1 (important, resolved in Phase 2.2):** the 2s data-version watcher must not gate the active-member switch — synchronous in-memory health update on `Response`, store write only reconciles.
- **I2 (important, resolved in Phase 1.1):** all `binding.Credential`/`OAuthIndex.Has`/`extractInjectableSecret`/`findAdder` consumers routed through one `ResolveActive` chokepoint, not just the two injection passes.
- Namespace collision resolved by mutual-exclusion at create time (Phase 0.4). Orphan pool members resolved by blocking `cred remove` of a live member (Phase 0.2).
- Alternative rejected for this use case: scheduled `sluice cred update` rotation — cannot react to a 429 in real time and races the async OAuth vault writer.
