# Docker Exec Phantom Injection

## Overview

Replace the phantom file volume with direct docker exec-based environment variable injection. Currently, sluice writes phantom token files to a shared volume (`/phantoms/`) that the agent container reads. This is unreliable because OpenClaw doesn't auto-read files from `/phantoms/`, and the fallback `RestartWithEnv` recreates the entire container.

The new approach: sluice sets env vars on the agent container via `docker exec` and calls `openclaw secrets reload`. No shared phantom volume, no phantom files, no `-phantom-dir` flag.

Credentials gain an `env_var` field specifying which environment variable the phantom should be injected as (e.g., `OPENAI_API_KEY`, `TELEGRAM_BOT_TOKEN`). This field is set via CLI, API, and Telegram.

## Context

- `internal/container/docker.go` -- `DockerManager.ReloadSecrets()` writes phantom files + calls `docker exec openclaw openclaw secrets reload`. `RestartWithEnv()` recreates container with updated env vars.
- `internal/container/types.go` -- `ContainerManager` interface with `ReloadSecrets(ctx, phantomDir, phantomEnv)` and `WritePhantomFiles()`.
- `internal/vault/phantom.go` -- `GeneratePhantomEnv()` generates env var name -> phantom value map. `CredNameToEnvVar()` uppercases credential name.
- `internal/proxy/server.go` -- `SetPhantomDir()` configures phantom dir on injector.
- `cmd/sluice/main.go` -- `-phantom-dir` flag, phantom dir wiring, `MCP auto-injection` via `InjectMCPConfig()`.
- `cmd/sluice/cred.go` -- `cred add` creates phantom files after adding credential.
- `compose.yml` / `compose.dev.yml` -- `sluice-phantoms` volume mounted in sluice and openclaw.
- `internal/store/store.go` -- `bindings` table. No `env_var` field currently.
- `internal/api/server.go` -- credential CRUD handlers.
- `internal/telegram/commands.go` -- Telegram `/cred` command.

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- **CRITICAL: every task MUST include new/updated tests**
- **CRITICAL: all tests must pass before starting next task**
- Run `go test ./... -timeout 30s` after each change
- Maintain backward compatibility for non-Docker runtimes (Apple Container, tart, standalone).

## Testing Strategy

- **Unit tests**: Go tests for env var injection, store schema, CLI flags, API handlers
- **E2e tests**: Manual testing with Docker Compose

## Progress Tracking

- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with + prefix
- Document issues/blockers with ! prefix

## Solution Overview

### Current flow (phantom files)

```
sluice cred add mykey
  -> vault.Add(name, secret)
  -> store.AddBinding(...)
  -> WritePhantomFiles(/phantoms/, {MY_KEY: phantom-xxx})
  -> docker exec openclaw openclaw secrets reload (fails, openclaw doesn't read /phantoms/)
  -> fallback: RestartWithEnv (recreates container with MY_KEY=phantom-xxx)
```

### New flow (docker exec env injection)

```
sluice cred add mykey --env-var OPENAI_API_KEY
  -> vault.Add(name, secret)
  -> store.AddBinding(..., env_var=OPENAI_API_KEY)
  -> docker exec openclaw sh -c 'echo "OPENAI_API_KEY=phantom-xxx" >> ~/.openclaw/.env'
  -> docker exec openclaw openclaw secrets reload
```

The key change: credentials have an explicit `env_var` field that maps the phantom to the agent's expected environment variable name. No more `CredNameToEnvVar()` auto-naming.

### Data model changes

Add `env_var` column to `bindings` table:

```sql
ALTER TABLE bindings ADD COLUMN env_var TEXT;
```

When `env_var` is set, the phantom value is injected as that env var into the agent container. When empty, no env injection (credential is only used for MITM header injection).

### CLI changes

```bash
sluice cred add openai_key --env-var OPENAI_API_KEY --destination api.openai.com --ports 443
sluice cred add telegram_bot --env-var TELEGRAM_BOT_TOKEN --destination api.telegram.org --ports 443
```

### Injection mechanism

`DockerManager.InjectEnvVars(ctx, envMap)`:
1. For each key=value pair, write to `~/.openclaw/.env` inside the container via `docker exec`. Check for existing entries with the same key and update in-place (no duplicates). Use sed or a small inline script.
2. Call `docker exec openclaw openclaw secrets reload`

On startup: check if `~/.openclaw/.env` already has the phantom entries (it persists across restarts since `~/.openclaw/` is in a volume). Only inject if missing or stale. This avoids unnecessary container exec on every proxy restart.

**Env var name uniqueness**: enforce at the store level. `AddBinding()` rejects duplicate `env_var` values across all bindings to prevent one credential's phantom from overwriting another's.

### MCP config injection

Keep `mcp-servers.json` as file-based. Move it out of the phantoms folder to a separate shared volume (e.g., `sluice-mcp` mounted at `/mcp` in both containers). The phantoms volume is removed but MCP config still needs a shared path.

### What gets removed

- `-phantom-dir` flag
- `WritePhantomFiles()` function
- `sluice-phantoms` volume from compose files
- `GeneratePhantomEnv()` (replaced by per-credential env injection)
- `CredNameToEnvVar()` (replaced by explicit `env_var` field)
- `phantomDir` field from Injector struct
- Phantom file writes from OAuth response handler
- `WriteOAuthPhantoms()` function

## What Goes Where

- **Implementation Steps**: schema migration, store/CLI/API/Telegram changes, docker exec injection, cleanup
- **Post-Completion**: manual testing with Docker Compose, update server deployment

## Implementation Steps

### Task 1: Add env_var column to bindings schema

**Files:**
- Create: `internal/store/migrations/000003_binding_env_var.up.sql`
- Create: `internal/store/migrations/000003_binding_env_var.down.sql`
- Modify: `internal/store/store.go`

- [ ] Create migration: `ALTER TABLE bindings ADD COLUMN env_var TEXT`
- [ ] Add `EnvVar` field to `BindingRow` and `BindingOpts` structs
- [ ] Update `AddBinding()` to accept and store env_var
- [ ] Update `ListBindings()` and `ListBindingsByCredential()` to return env_var
- [ ] Add `ListBindingsWithEnvVar() ([]BindingRow, error)` that returns bindings where env_var is not empty
- [ ] Write tests for migration
- [ ] Write tests for AddBinding with env_var
- [ ] Write tests for ListBindingsWithEnvVar
- [ ] Run tests: `go test ./internal/store/ -timeout 30s`

### Task 2: Update CLI cred add with --env-var flag

**Files:**
- Modify: `cmd/sluice/cred.go`

- [ ] Add `--env-var` flag to `sluice cred add` (optional, specifies which env var the phantom maps to)
- [ ] Pass env_var to `AddBinding()` (via `BindingOpts`)
- [ ] Remove phantom file writing from `cred add` (remove `WritePhantomFiles` calls)
- [ ] Remove phantom env var printing (the auto-generated `CRED_ACCESS`/`CRED_REFRESH` messages)
- [ ] Update `sluice cred list` to show env_var column when set
- [ ] Write tests for --env-var flag parsing
- [ ] Write tests for cred add with env_var
- [ ] Run tests: `go test ./cmd/sluice/ -timeout 30s`

### Task 3: Implement docker exec env injection in DockerManager

**Files:**
- Modify: `internal/container/docker.go`
- Modify: `internal/container/types.go`

- [ ] Add `InjectEnvVars(ctx context.Context, envMap map[string]string) error` to `ContainerManager` interface
- [ ] Implement in `DockerManager`: write env vars to `~/.openclaw/.env` via `docker exec`, then call `openclaw secrets reload`
- [ ] Change `ReloadSecrets` signature: remove `phantomDir` parameter, accept `envMap` only
- [ ] Remove `WritePhantomFiles()` function from types.go
- [ ] Update `AppleManager` and `TartManager` to match new interface (stub or equivalent implementation)
- [ ] Write tests for InjectEnvVars (mock docker exec)
- [ ] Write tests for new ReloadSecrets without phantomDir
- [ ] Run tests: `go test ./internal/container/ -timeout 30s`

### Task 4: Wire env injection into proxy server startup and reload

**Files:**
- Modify: `internal/proxy/server.go`
- Modify: `cmd/sluice/main.go`

- [ ] Remove `-phantom-dir` flag from main.go
- [ ] Remove `-agent-env-file` flag from main.go (stashed, not committed)
- [ ] Remove `SetPhantomDir()` calls
- [ ] On startup: read all bindings with env_var set, generate phantom values, call `containerManager.InjectEnvVars()`
- [ ] In `reloadAll()`: after credential/binding changes, regenerate phantom env and call `InjectEnvVars()`
- [ ] Remove `phantomDir` field from `Injector` struct
- [ ] Update OAuth response handler's async persist to call `InjectEnvVars()` instead of `WriteOAuthPhantoms()`
- [ ] Write tests for startup env injection
- [ ] Run tests: `go test ./... -timeout 30s`

### Task 5: Move MCP config to separate shared volume

**Files:**
- Modify: `compose.yml`
- Modify: `compose.dev.yml`
- Modify: `cmd/sluice/main.go`
- Modify: `internal/container/docker.go`

- [ ] Add `sluice-mcp` volume to compose files, mounted at `/home/sluice/mcp` in sluice and `/mcp:ro` in openclaw
- [ ] Update `InjectMCPConfig()` to use the new MCP volume path instead of phantom dir
- [ ] Update main.go MCP auto-injection to use new path (`-mcp-dir` flag or derived from existing config)
- [ ] Write tests for MCP config path change
- [ ] Run tests: `go test ./... -timeout 30s`

### Task 6: Update API and Telegram for env_var field

**Files:**
- Modify: `api/openapi.yaml`
- Modify: `internal/api/server.go`
- Modify: `internal/api/api.gen.go` (regenerated)
- Modify: `internal/telegram/commands.go`

- [ ] Add `env_var` field to credential create and binding create request schemas in OpenAPI spec
- [ ] Add `env_var` field to binding response schema
- [ ] Regenerate API code: `go generate ./internal/api/`
- [ ] Update `PostApiCredentials` handler to pass env_var to binding creation
- [ ] Update `PostApiBindings` handler to accept env_var
- [ ] Update `GetApiBindings` handler to return env_var
- [ ] Update Telegram `/cred add` command to accept env_var parameter
- [ ] Write tests for API credential creation with env_var
- [ ] Write tests for API binding creation with env_var
- [ ] Run tests: `go test ./internal/api/ -timeout 30s`

### Task 7: Remove phantom volume and cleanup

**Files:**
- Modify: `compose.yml`
- Modify: `compose.dev.yml`
- Modify: `compose.e2e.yml`
- Modify: `Dockerfile`
- Modify: `internal/vault/phantom.go`

- [ ] Remove `sluice-phantoms` volume from compose.yml, compose.dev.yml
- [ ] Remove phantom volume mount from sluice and openclaw services
- [ ] Remove phantom dir creation from Dockerfile
- [ ] Remove `-phantom-dir` from Dockerfile CMD
- [ ] Remove `GeneratePhantomEnv()`, `CredNameToEnvVar()`, `WriteOAuthPhantoms()` from phantom.go
- [ ] Remove or update `GeneratePhantomToken()` (still needed for MITM phantom strings)
- [ ] Check compose.e2e.yml for phantom volume references
- [ ] Write test verifying phantom.go still exports `GeneratePhantomToken()` for MITM use
- [ ] Run tests: `go test ./... -timeout 30s`

### Task 8: Verify acceptance criteria

- [ ] Verify `sluice cred add --env-var OPENAI_API_KEY` sets env var in agent container
- [ ] Verify `openclaw secrets reload` picks up new env vars
- [ ] Verify OAuth token refresh updates env var in agent container
- [ ] Verify MCP config injection works without shared volume
- [ ] Verify existing MITM phantom swap still works (request-side)
- [ ] Verify DB watcher triggers env injection on credential changes
- [ ] Verify no phantom files or volumes are created
- [ ] Run full test suite: `go test ./... -v -timeout 30s`

### Task 9: [Final] Update documentation

- [ ] Update CLAUDE.md: remove phantom dir references, add --env-var documentation
- [ ] Update README.md: update credential setup instructions
- [ ] Move this plan to `docs/plans/completed/`

## Post-Completion

**Manual verification:**
- Test with Docker Compose: add credential, verify env var appears in OpenClaw container
- Test OpenClaw onboarding with OAuth through sluice MITM
- Test Telegram /cred add with env_var parameter
- Verify server deployment (knuth) works after updating compose files

**Migration notes:**
- Users with existing deployments need to: recreate containers (env vars are injected fresh on startup), remove orphaned `sluice-phantoms` volume
- No data loss: credentials in vault and DB are unchanged
