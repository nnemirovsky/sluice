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

### Phase 0 — Data model + CLI (no runtime behavior change)

1. **Migration** `internal/store/migrations/000006_credential_pools.up.sql` (+`.down.sql`):
   - `credential_pools(name TEXT PRIMARY KEY, strategy TEXT NOT NULL DEFAULT 'failover' CHECK(strategy IN ('failover')), created_at TEXT)`.
   - `credential_pool_members(pool TEXT, credential TEXT, position INTEGER NOT NULL, PRIMARY KEY(pool,credential), FOREIGN KEY(pool) REFERENCES credential_pools(name) ON DELETE CASCADE)`.
   - `credential_health(credential TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'healthy' CHECK(status IN ('healthy','cooldown')), cooldown_until TEXT, last_failure_reason TEXT, updated_at TEXT)`.
2. **Store API** `internal/store/store.go`: `CreatePool`, `AddPoolMember`, `ListPools`, `GetPool` (members ordered by `position`), `RemovePool`; `SetCredentialHealth`, `GetCredentialHealth`, `ListCredentialHealth`. App-layer CHECK: a member must be an existing `oauth` cred with non-empty `token_url`; reject `static`.
   - **Orphan-member cleanup**: `cred remove <c>` of a pooled member must either cascade-remove the member row or mark it missing. Decision: `cred remove` errors if the credential is a live pool member ("remove it from pool `<p>` first"); document in CLI help. (No silent dangling rows.)
3. **CLI** `cmd/sluice/cred.go` new `pool` subtree: `pool create <name> --members a,b[,c] [--strategy failover]`, `pool list`, `pool status <name>` (member order + health + active), `pool rotate <name>` (manual override), `pool remove <name>`.
4. **Namespace**: pool names and credential names share one namespace. `pool create` rejects a name that collides with an existing credential; `cred add` rejects a name colliding with an existing pool. Bind a pool via `sluice binding add <pool> --destination <host>` (pool name stored verbatim in `bindings.credential`).

Phase 0 exit: pools definable/inspectable; `reloadAll` loads pool + health tables into a new in-memory `PoolResolver` (atomic-pointer-swapped, parallel to `StoreResolver`), but injection does not consult it.

### Phase 1 — Phantom indirection (pool phantom → active member)

Active member changes only via `pool rotate` in this phase.

1. **Single chokepoint for pool→member expansion** `internal/vault/pool.go` (new):
   - `PoolResolver.IsPool(name) bool`; `ResolveActive(name) (member string, ok bool)` — if `name` is a pool, first member whose health is `healthy` or whose `cooldown_until <= now`, in `position` order; if all in cooldown, return the soonest-recovering member and log a WARNING. If `name` is a plain credential, return it unchanged.
   - **Mandatory task: enumerate and route every `binding.Credential` / `OAuthIndex.Has` / `extractInjectableSecret` / `findAdder`/persist consumer through `ResolveActive` at one chokepoint** (grep `binding.Credential`, `\.Has(`, `extractInjectableSecret`). Do **not** scatter `IsPool` checks across pass-1/pass-2 only — that was the original gap.
2. **Injection** `internal/proxy/addon.go`: pass-1 header and pass-2 phantom swap call the chokepoint so the *real* value injected is the active member's, while the agent's pool-scoped phantom string is what gets matched/replaced.
3. **Per-request member tag — precise join key** (resolves Risk R1):
   - When pass-2 swaps the agent's `SLUICE_PHANTOM:<pool>.refresh` to a real refresh token in an outbound token-endpoint request, sluice **records `realRefreshToken → member`** in a short-TTL map (the refresh token value is sluice's own injected bytes, unique per member, and is the field actually present in an RFC-6749 refresh-grant body — *not* the access token, which a refresh POST need not carry). `connState` keyed by `ClientConn.Id` is insufficient (one client conn multiplexes both members' h2 streams), so the join key is the real refresh-token value, not the connection.
   - On the token-endpoint **response**, the handler recovers `member` from that map by the real refresh token sluice sent in the matching request. Persist refreshed tokens to *that member* (`persistAddonOAuthTokens(member,...)`, singleflight `"persist:"+member`).
   - **Fail-closed (mandatory enumerated task + unit test):** if the member cannot be recovered, do **not** guess and do **not** fall back to `OAuthIndex.Match` for pooled token URLs — log a WARNING and skip the vault write so the next refresh retries. Dedicated unit test: two members, same token URL, assert a B-refresh never overwrites A's vault entry, and a missing tag results in zero writes.
4. **Pool-stable phantom** (resolves Risk R3): for pooled OAuth creds, `oauthPhantomAccess`/`resignJWT` produce a JWT from a deterministic synthetic payload keyed on the **pool name** (not the member's real token), so it is byte-identical across member switches. Enumerated unit test asserts byte-identity across a switch. Document the static-form fallback and the reason it is not the default.
5. `cmd/sluice/main.go:reloadAll` builds & swaps `PoolResolver` + health snapshot alongside the existing swaps.

Phase 1 exit: `pool rotate` flips the backing account; agent's phantom unchanged byte-for-byte; refreshes attributed correctly; fail-closed proven by test.

### Phase 2 — Auto-failover on 429 / 401

1. **Failure classification** in `SluiceAddon.Response` for pooled destinations:
   - `429`, or `403` with body error `insufficient_quota`/quota-exhaustion → rate-limited.
   - `401`, or token-endpoint body `invalid_grant`/`invalid_token` → auth-failure.
   - `5xx` and everything else → no-op (upstream-side; failing over would thrash both accounts — documented choice).
2. **Prompt failover (resolves Important I1):** on classification, update the in-memory `PoolResolver` health **synchronously before the response returns** (atomic-pointer swap or dedicated mutex on the health map — call out the locking discipline), so the *very next* request injects the new active member. Also write `SetCredentialHealth(member, 'cooldown', now+ttl, reason)` to the store for durability; the 2s data-version watcher then merely reconciles. Do **not** rely on the 2s watcher for the active-member change — that lag was an error amplifier.
   - Cooldown TTLs as named consts in `internal/vault/pool.go`: rate-limit 60s, auth-fail 300s (a broken refresh token will not self-heal quickly). Lazy recovery: `ResolveActive` treats expired cooldown as eligible — no scheduler.
3. **Audit**: emit `cred_failover` with `Reason = "<pool>:<from>-><to>:<429|403|401|invalid_grant>"`.
4. **Telegram notify** (best-effort, non-blocking, never blocks injection): one-line "pool `<name>` failed over `<a>`→`<b>` (<reason>)".
5. **No in-flight retry** of the triggering request in Phase 2 (it returns its error; the next request uses the new member). Transparent retry is out of scope (needs body buffering; unsafe for non-idempotent calls).

Phase 2 exit: e2e proves A 429 → next request uses B → B's refresh persists to B → phantom byte-unchanged.

## Out of scope / future work

Transparent in-flight retry; round-robin/weighted (`strategy` reserved, `failover` only); active health probes / half-open; multi-agent pools with independent active pointers.

## Risks / decisions

- **R1 (critical, resolved in Phase 1.3):** refresh-token mis-attribution corrupts both accounts (rotating refresh tokens are single-use; filing B's new token under A invalidates A and bricks B's old one). Join key is the real **refresh** token sluice injected, not the access token, not the client connection. Fail-closed, never guess. Dedicated collision unit test mandatory.
- **R3 (critical, resolved in Phase 1.4):** `resignJWT` is per-real-token, so the agent's phantom would change on every cross-member refresh — the headline guarantee. Resolved via pool-keyed synthetic JWT; byte-identity unit test mandatory; static-form fallback documented.
- **I1 (important, resolved in Phase 2.2):** the 2s data-version watcher must not gate the active-member switch — synchronous in-memory health update on `Response`, store write only reconciles.
- **I2 (important, resolved in Phase 1.1):** all `binding.Credential`/`OAuthIndex.Has`/`extractInjectableSecret`/`findAdder` consumers routed through one `ResolveActive` chokepoint, not just the two injection passes.
- Namespace collision resolved by mutual-exclusion at create time (Phase 0.4). Orphan pool members resolved by blocking `cred remove` of a live member (Phase 0.2).
- Alternative rejected for this use case: scheduled `sluice cred update` rotation — cannot react to a 429 in real time and races the async OAuth vault writer.
