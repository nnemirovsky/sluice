# Channel Feature Parity (pools on HTTP API + Telegram) and Token-Host Grant Scoping

## Overview

Two follow-ups surfaced while operating the credential-pool feature live:

1. **Pools are CLI-only.** `sluice pool create|list|status|rotate|remove` exists, but there are **no HTTP API endpoints** and **no Telegram `/pool` commands**. Every other store-backed management surface (policy, credentials, bindings, MCP upstreams) is reachable from CLI **and** REST **and** Telegram. Pools must reach parity.
2. **Token-host phantom expansion is grant-blind.** sluice rewrites *every* request to a pool's shared OAuth token host (e.g. `auth.openai.com`), including non-refresh grants. A fresh in-container `codex login --device-auth` (a `device_code` grant) is therefore corrupted into `400 token_exchange_user_error`. The expansion must act only on `grant_type=refresh_token`.

This plan also codifies a general **channel feature-parity principle** (CLI / HTTP API / Telegram / future channels expose the same management features unless there is a documented single-channel rationale) in `CLAUDE.md` and `CONTRIBUTING.md` so future store-backed features do not regress into a single channel again.

## Context

- Store (already complete, channel-agnostic): `internal/store/pools.go` — `CreatePoolWithMembers`, `GetPool`, `ListPools`, `RemovePoolIfUnreferenced`, `PoolsForMember`, `SetCredentialHealthIfPoolMemberEpoch`, `ListCredentialHealth`, `ErrCredentialInUseByPool`, `PoolReferencedError`.
- Pool resolution / status / rotate logic currently lives in `cmd/sluice/pool.go` (`handlePoolStatus`, `handlePoolRotate`) — the epoch-guarded `SetCredentialHealthIfPoolMemberEpoch(active, name, epoch, "cooldown", until, vault.ManualRotateReason)` write and the `vault.NewPoolResolver(...).ResolveActive` derivation. This is **not** reusable by other channels yet — it must be lifted into a shared package.
- REST: spec-first. `api/openapi.yaml` is the source of truth; `make generate` regenerates `internal/api/api.gen.go`; handlers implement the generated `ServerInterface` in `internal/api/server.go`. Existing resource patterns to mirror: `/api/credentials`, `/api/bindings`, `/api/mcp/upstreams` (collection + `/{id}` item).
- Telegram: command dispatch switch in `internal/telegram/commands.go` (~line 245: `case "policy" | "cred" | "mcp"`). Mirror an existing multi-subcommand handler (`/mcp add|list|remove`). Pool create carries **no secrets** (member credential names only) so the `/mcp add` auto-delete-message behavior is **not** needed.
- Token-host expansion: `internal/proxy/addon.go` — the `[ADDON-INJECT] token-host phantom expansion for pool ... (auth.openai.com)` path (`buildPhantomPairs` / `buildOAuthPhantomPairs` token-host branch). The request body / `grant_type` is available on the flow at injection time.
- Failover attribution already keys on `grant_type=refresh_token` bodies in `internal/proxy/pool_failover.go` (`classifyFailover` token-endpoint path) — reuse the same form-parse helper rather than writing a new one.

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- CRITICAL: every task MUST include new/updated tests
- CRITICAL: all tests must pass before starting the next task
- gofumpt for Go formatting; scoped Conventional Commits; PR to `main` (never direct push)
- REST changes follow the spec-first workflow: edit `api/openapi.yaml` → `make generate` → implement handler → `go test ./internal/api/` → `make lint-api`. Never hand-edit `api.gen.go`.

## Testing Strategy

- **Unit tests**: shared pool-ops package (create/list/status/rotate/remove) success + error paths (namespace collision, static member rejection, in-use-by-pool, unknown pool, epoch-raced rotate).
- **Unit tests**: REST handlers — happy path + 400 (validation) + 404 (unknown pool) + 409 (`ErrCredentialInUseByPool` / `PoolReferencedError`), mirroring the credentials/bindings handler tests.
- **Unit tests**: Telegram `/pool` handler — each subcommand success + error rendering.
- **Unit tests**: token-host expansion — a `refresh_token` grant is still expanded (regression guard); a `device_code` / `authorization_code` grant is **passed through untouched** (fail-before/pass-after).
- **E2E** (optional, if a pool e2e harness slot is cheap): a pooled upstream managed entirely via REST then via Telegram resolves identically to the CLI path.

## Solution Overview

1. **Lift pool ops into a shared, channel-agnostic package** (`internal/poolops` or a method set on `*store.Store` + a small `vault` helper) exposing `Create`, `List`, `Status`, `Rotate`, `Remove` returning typed results/errors. CLI, REST, and Telegram all call it. The epoch-guarded rotate write and the `ResolveActive`-based status derivation live here exactly once, so the three channels cannot drift (this is the root cause of the parity gap — the logic was written inline in `cmd/sluice`).
2. **REST**: add `/api/pools` (GET list, POST create), `/api/pools/{name}` (GET status, DELETE remove), `/api/pools/{name}/rotate` (POST). Spec-first.
3. **Telegram**: add `/pool create|list|status|rotate|remove` dispatching to the shared package, rendered like `/mcp`.
4. **Token-host grant scope**: gate the pool token-host phantom expansion on `grant_type=refresh_token`; pass other grants through unmodified.
5. **Docs/process**: add the channel-parity principle to `CLAUDE.md` and `CONTRIBUTING.md` (done in this PR for the docs; the code tasks below are the follow-up implementation).

## Implementation Steps

### Task 1: Extract channel-agnostic pool operations

**Files:**
- Add: `internal/poolops/poolops.go`
- Add: `internal/poolops/poolops_test.go`
- Modify: `cmd/sluice/pool.go` (call the shared package instead of inline logic)

- [ ] Define `Create(store, name, strategy, members)`, `List(store)`, `Status(store, name)`, `Rotate(store, name)`, `Remove(store, name)` with typed results and sentinel errors (reuse `store.ErrCredentialInUseByPool`, `store.PoolReferencedError`)
- [ ] Move the epoch-guarded rotate write (`SetCredentialHealthIfPoolMemberEpoch` + `vault.ManualRotateReason`) and the `vault.NewPoolResolver(...).ResolveActive` status derivation into `Status`/`Rotate`
- [ ] Rewrite `cmd/sluice/pool.go` handlers to thin wrappers over `internal/poolops` (no behavior change; existing CLI tests must still pass)
- [ ] Tests: every op, success + each sentinel error; rotate epoch-race no-op
- [ ] Run tests

### Task 2: REST endpoints for pools (spec-first)

**Files:**
- Modify: `api/openapi.yaml`
- Regenerate: `internal/api/api.gen.go` (via `make generate` — do not hand-edit)
- Modify: `internal/api/server.go`
- Modify: `internal/api/server_test.go`

- [ ] Add to `api/openapi.yaml`: `/api/pools` (GET, POST), `/api/pools/{name}` (GET, DELETE), `/api/pools/{name}/rotate` (POST), with schemas mirroring the credentials/bindings style
- [ ] `make generate`; implement the new `ServerInterface` methods in `server.go` calling `internal/poolops`
- [ ] Map errors: validation → 400, unknown pool → 404, `ErrCredentialInUseByPool` / `PoolReferencedError` → 409, else 500 (mirror the existing cred-removal mapping at `server.go:~1287`)
- [ ] Tests: list/create/status/rotate/remove happy paths + 400/404/409
- [ ] `make lint-api`; run `go test ./internal/api/`

### Task 3: Telegram `/pool` commands

**Files:**
- Modify: `internal/telegram/commands.go`
- Modify: `internal/telegram/commands_test.go`
- Modify: command help/menu registration (wherever `/policy`,`/cred`,`/mcp` are listed)

- [ ] Add `case "pool":` to the dispatch switch; subcommands `create|list|status|rotate|remove` calling `internal/poolops`
- [ ] Render `status` like the CLI (`* [i] member  healthy|cooldown … reason`); render errors as plain text
- [ ] No message auto-delete (pool args carry no secrets — unlike `/mcp add`); add `/pool` to the grouped help/command menu
- [ ] Tests: each subcommand success + error
- [ ] Run tests

### Task 4: Scope pool token-host phantom expansion to refresh grants

**Files:**
- Modify: `internal/proxy/addon.go`
- Modify: `internal/proxy/addon_test.go` (or `pool_phantom_test.go`)

- [ ] At the pool token-host expansion site, parse the request body form and only expand when `grant_type == "refresh_token"`; pass `device_code`/`authorization_code`/absent-grant requests through unmodified (reuse the form-parse already used by `classifyFailover`)
- [ ] Tests (fail-before/pass-after): `refresh_token` grant still expanded (regression guard); `device_code` grant body + headers reach upstream byte-unchanged so a fresh in-container `codex login --device-auth` is not corrupted
- [ ] Run tests; `go vet ./...` and `go vet -tags=e2e ./e2e/`

### Task 5: Final validation

**Files:** none (validation only)

- [ ] `gofumpt -l` clean; `golangci-lint run ./...` 0 issues
- [ ] Full `go test ./...` + `-race` on `internal/proxy`,`internal/api`,`internal/telegram`,`internal/poolops`,`internal/store`
- [ ] `go build ./...`; `go vet ./...`; `go vet -tags=e2e ./e2e/`
- [ ] Independently verify the committed HEAD (no conflict markers; `git diff --stat HEAD` empty) before pushing

## Out of Scope

- In-flight retry on pooled 429/401 (the agent's own retry + synchronous member switch already covers it; documented non-goal).
- Streaming-response failover (documented known limitation, separate work).
- A pool-management web dashboard surface (tracked by `docs/plans/20260406-web-dashboard.md`; once `internal/poolops` exists the dashboard reuses it for free — note the synergy there rather than duplicating here).
