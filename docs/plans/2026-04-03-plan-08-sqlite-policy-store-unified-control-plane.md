# Plan 8: SQLite Policy Store and Unified Control Plane

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

## Overview

Replace the TOML-file-based policy engine with SQLite as the runtime store. Add a unified CLI for policy/credential/MCP management. Switch credential injection from container restarts to hot-reload via shared volume + docker exec. Add `sluice mcp add` for registering MCP upstreams at runtime.

**Problem:** Dynamic rules (Telegram "Always Allow", `/policy allow`) are lost on restart. Credential changes require full container recreation. MCP upstreams can only be configured via TOML file. Three different interfaces (TOML file, Telegram, approval buttons) with inconsistent persistence behavior.

**Solution:** SQLite becomes the single source of truth for all runtime state (policy rules, MCP upstreams, credential bindings). TOML is retained only for initial seeding via `sluice policy import`. CLI, Telegram, and approval buttons all write to the same DB. Credential hot-reload uses shared-volume files + `docker exec openclaw secrets reload` instead of container restart.

**Key changes:**
- `internal/policy/` -- New `store.go` with SQLite-backed policy store
- `internal/docker/` -- `ReloadSecrets()` method replacing `RestartWithEnv()`
- `cmd/sluice/` -- New `policy` subcommand with add/list/remove/import/export
- `cmd/sluice/` -- Extended `mcp` subcommand with add/list/remove
- `internal/mcp/` -- Dynamic upstream registration
- `internal/telegram/` -- Commands updated to use SQLite store

## Context (from discovery)

**Files directly importing TOML (must change):**
- `cmd/sluice/main.go` (lines 17, 130-132, 295)
- `cmd/sluice/mcp.go` (lines 14, 65)
- `internal/policy/engine.go` (lines 10, 53)

**Files with TOML struct tags (must update):**
- `internal/policy/types.go` -- policyFile, Rule, PolicyConfig, TelegramConfig, ToolRule, InspectBlockRule, InspectRedactRule
- `internal/mcp/upstream.go` -- UpstreamConfig
- `internal/vault/provider.go` -- VaultConfig, HashiCorpConfig

**Docker/credential files (must change):**
- `internal/docker/manager.go` -- RestartWithEnv, GeneratePhantomEnv
- `internal/telegram/commands.go` -- credMutationComplete (lines 273-299)

**Test files affected:** 26 test files + 6 testdata/ TOML fixtures

**New dependency:** `modernc.org/sqlite` (pure Go SQLite, no CGO)

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- All tests must pass before starting next task
- TOML import is kept as a seeding mechanism; SQLite is the runtime store
- Import uses merge semantics (skip duplicates)
- Backward compatibility: existing TOML configs can be imported into the new DB

## Testing Strategy

- **Unit tests**: Required for every task. SQLite tests use in-memory DBs (`:memory:`) for speed.
- **Migration tests**: Verify TOML import produces correct SQLite state.
- **Integration tests**: Verify CLI commands write to DB and proxy reads from DB.

## Implementation Steps

### Task 1: Create SQLite policy store

New file `internal/store/store.go` with a `Store` type that wraps SQLite. This is the foundation everything else builds on.

**Files:**
- Create: `internal/store/store.go`
- Create: `internal/store/store_test.go`

**Schema:**
```sql
CREATE TABLE rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    verdict TEXT NOT NULL CHECK(verdict IN ('allow', 'deny', 'ask')),
    destination TEXT NOT NULL,
    ports TEXT,           -- JSON array, e.g. "[443,80]" or NULL for any port
    protocol TEXT,        -- override protocol detection
    note TEXT,
    source TEXT NOT NULL DEFAULT 'manual',  -- 'seed', 'manual', 'telegram', 'approval'
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE tool_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    verdict TEXT NOT NULL CHECK(verdict IN ('allow', 'deny', 'ask')),
    tool TEXT NOT NULL,   -- glob pattern
    note TEXT,
    source TEXT NOT NULL DEFAULT 'manual',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE inspect_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK(kind IN ('block', 'redact')),
    pattern TEXT NOT NULL,
    description TEXT,
    target TEXT,          -- for redact: 'response' field targeting
    replacement TEXT,     -- for redact: replacement string
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- Seeds: default_verdict, timeout_sec, telegram_bot_token_env, telegram_chat_id_env

CREATE TABLE bindings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    destination TEXT NOT NULL,
    ports TEXT,
    credential TEXT NOT NULL,
    inject_header TEXT,
    template TEXT,
    protocol TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE mcp_upstreams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    command TEXT NOT NULL,
    args TEXT,            -- JSON array
    env TEXT,             -- JSON object
    timeout_sec INTEGER DEFAULT 120,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

- [x] Add `modernc.org/sqlite` dependency
- [x] Create `internal/store/store.go` with `New(path string)` that opens/creates SQLite DB and runs migrations
- [x] Implement schema creation with `CREATE TABLE IF NOT EXISTS` for all 6 tables
- [x] Implement `AddRule(verdict, destination, ports, opts)` and `RemoveRule(id)`
- [x] Implement `ListRules(verdict)` returning all rules or filtered by verdict
- [x] Implement `AddToolRule(verdict, tool, note)` and `RemoveToolRule(id)`
- [x] Implement `ListToolRules(verdict)`
- [x] Implement `AddInspectRule(kind, pattern, opts)` and `RemoveInspectRule(id)`
- [x] Implement `GetConfig(key)` and `SetConfig(key, value)` for config table
- [x] Implement `AddBinding(...)`, `RemoveBinding(id)`, `ListBindings()`
- [x] Implement `AddMCPUpstream(...)`, `RemoveMCPUpstream(name)`, `ListMCPUpstreams()`
- [x] Write tests for all CRUD operations (success + error cases)
- [x] Write tests for schema migration on fresh DB
- [x] Write tests for concurrent access (goroutine safety)
- [x] Run tests: `go test ./internal/store/ -v -timeout 30s`

### Task 2: TOML import into SQLite store

Add `ImportTOML(data []byte)` to the store that parses TOML and inserts rules with merge semantics (skip duplicates).

**Files:**
- Modify: `internal/store/store.go`
- Create: `internal/store/import.go`
- Create: `internal/store/import_test.go`

- [x] Create `ImportTOML(data []byte) (*ImportResult, error)` that parses TOML using existing `policy.policyFile` struct
- [x] Import network rules (allow/deny/ask) with source="seed"
- [x] Import tool rules with source="seed"
- [x] Import inspect rules (block/redact)
- [x] Import config values (default verdict, timeout, telegram config)
- [x] Import bindings from `[[binding]]` sections
- [x] Import MCP upstreams from `[[mcp_upstream]]` sections
- [x] Implement merge: skip if destination+ports+verdict combination already exists
- [x] Return `ImportResult` with counts: inserted, skipped, errors
- [x] Write tests using existing testdata/ TOML fixtures
- [x] Write tests for merge semantics (import twice, verify no duplicates)
- [x] Write tests for malformed TOML (returns error, no partial writes)
- [x] Run tests: `go test ./internal/store/ -v -timeout 30s`

### Task 3: Build policy.Engine from SQLite store

Replace `LoadFromFile`/`LoadFromBytes` with `LoadFromStore`. The Engine becomes a read-only snapshot built from the DB. Mutations go through the store, then a new Engine is compiled.

**Files:**
- Modify: `internal/policy/engine.go`
- Modify: `internal/policy/types.go`
- Create: `internal/policy/engine_store.go`
- Modify: `internal/policy/engine_test.go`

- [ ] Create `LoadFromStore(s *store.Store) (*Engine, error)` that reads all rules from SQLite and compiles them
- [ ] Keep `LoadFromBytes` for backward compatibility (tests, import path) but mark as internal
- [ ] Remove `LoadFromFile` (replaced by store-based loading)
- [ ] Remove dynamic mutation methods from Engine (`AddDynamicAllow`, `AddAllowRule`, `AddDenyRule`, `RemoveRule`). Mutations now go through the store.
- [ ] Add `Engine.Validate()` that checks compiled state is consistent
- [ ] Update engine_test.go: tests that used LoadFromBytes can stay; tests that used LoadFromFile switch to LoadFromStore with in-memory SQLite
- [ ] Write tests for LoadFromStore with various rule combinations
- [ ] Run tests: `go test ./internal/policy/ -v -timeout 30s`

### Task 4: Wire SQLite store into proxy server and SIGHUP handler

Replace TOML file loading in main.go with SQLite store. The SIGHUP handler recompiles the Engine from the DB (no file re-reading).

**Files:**
- Modify: `cmd/sluice/main.go`
- Modify: `cmd/sluice/main_test.go`

- [ ] Add `--db` flag (default `sluice.db`) for SQLite database path
- [ ] On startup: open store, compile Engine from store, pass to proxy
- [ ] Keep `--policy` flag but change semantics: if specified and DB is empty, auto-import the TOML file as seed
- [ ] Refactor SIGHUP handler: instead of re-reading TOML, recompile Engine from store (picks up any rule changes from Telegram/CLI)
- [ ] Remove `BurntSushi/toml` import from main.go (TOML parsing moves to store/import.go)
- [ ] Remove `sluiceConfig` struct and secondary TOML decode
- [ ] Read vault config and bindings from store instead of TOML
- [ ] Update main_test.go: tests use temp SQLite DB instead of temp TOML files
- [ ] Write test for startup with empty DB + TOML seed import
- [ ] Write test for SIGHUP recompile from store
- [ ] Run tests: `go test ./cmd/sluice/ -v -timeout 30s`

### Task 5: Add `sluice policy` CLI subcommand

New CLI for managing policy rules directly.

**Files:**
- Create: `cmd/sluice/policy.go`
- Create: `cmd/sluice/policy_test.go`
- Modify: `cmd/sluice/main.go` (add case "policy" to subcommand switch)

- [ ] Implement `sluice policy list [--verdict allow|deny|ask]` -- lists all network rules
- [ ] Implement `sluice policy add allow <destination> [--ports 443,80] [--note "reason"]`
- [ ] Implement `sluice policy add deny <destination> [--note "reason"]`
- [ ] Implement `sluice policy add ask <destination> [--ports 443] [--note "reason"]`
- [ ] Implement `sluice policy remove <id>`
- [ ] Implement `sluice policy import <path.toml>` -- calls store.ImportTOML with merge semantics
- [ ] Implement `sluice policy export` -- dumps current rules as TOML to stdout
- [ ] Wire into main.go subcommand switch
- [ ] Write tests for each subcommand (success + error cases)
- [ ] Run tests: `go test ./cmd/sluice/ -v -timeout 30s`

### Task 6: Update Telegram commands to use SQLite store

Replace in-memory Engine mutations with store writes. After writing, recompile Engine and swap atomically.

**Files:**
- Modify: `internal/telegram/commands.go`
- Modify: `internal/telegram/commands_test.go`

- [ ] Add `store *store.Store` field to `CommandHandler`
- [ ] `/policy allow <dest>`: Write to store, then recompile and swap Engine
- [ ] `/policy deny <dest>`: Write to store, then recompile and swap Engine
- [ ] `/policy remove <id>`: Delete from store, then recompile and swap Engine
- [ ] `/policy show`: Read from store instead of Engine snapshot
- [ ] Update "Always Allow" flow in proxy: write to store with source="approval", recompile Engine
- [ ] Update "Always Allow" flow in MCP gateway: same pattern
- [ ] Update tests to use in-memory SQLite store
- [ ] Write tests verifying persistence (add rule, recompile, rule still present)
- [ ] Run tests: `go test ./internal/telegram/ -v -timeout 30s`

### Task 7: Hot credential reload via shared volume

Replace `docker.Manager.RestartWithEnv` with file-based phantom token injection + `docker exec` reload.

**Files:**
- Modify: `internal/docker/manager.go`
- Modify: `internal/docker/manager_test.go`
- Modify: `internal/telegram/commands.go` (credMutationComplete)

- [ ] Add `ReloadSecrets(ctx, phantomDir string, phantomEnv map[string]string) error` to Manager
- [ ] `ReloadSecrets` writes each phantom token as a file (e.g. `/phantoms/ANTHROPIC_API_KEY`) in the shared volume
- [ ] `ReloadSecrets` calls `docker exec <container> openclaw secrets reload` via the Docker API exec endpoint
- [ ] Add `ExecInContainer(ctx, containerName, cmd []string) error` to `ContainerClient` interface
- [ ] Implement `ExecInContainer` in `SocketClient` using Docker exec API
- [ ] Update `credMutationComplete` in commands.go: call `ReloadSecrets` instead of `RestartWithEnv`
- [ ] Keep `RestartWithEnv` as fallback (called if exec fails with "command not found")
- [ ] Update compose.dev.yml and compose.yml: add shared `sluice-phantoms` volume mounted in both sluice and openclaw
- [ ] Write tests for file-based phantom token writing
- [ ] Write tests for exec-based reload (mock Docker API)
- [ ] Write tests for fallback to restart on exec failure
- [ ] Run tests: `go test ./internal/docker/ -v -timeout 30s`

### Task 8: Add `sluice mcp add/list/remove` CLI subcommands

Allow MCP upstream registration at runtime. Upstreams are stored in SQLite.

**Files:**
- Modify: `cmd/sluice/mcp.go`
- Modify: `cmd/sluice/mcp_test.go`

- [ ] Add subcommand routing: `sluice mcp` (no args) starts gateway as before; `sluice mcp add|list|remove` manages upstreams
- [ ] Implement `sluice mcp add <name> --command <cmd> [--args "arg1,arg2"] [--env "KEY=VAL,..."] [--timeout 120]`
- [ ] Implement `sluice mcp list` -- shows all registered upstreams from DB
- [ ] Implement `sluice mcp remove <name>` -- removes upstream from DB
- [ ] Gateway startup reads upstreams from store instead of TOML
- [ ] Remove TOML parsing from mcp.go (upstreams come from store)
- [ ] Write tests for add/list/remove subcommands
- [ ] Write test for gateway starting with store-backed upstreams
- [ ] Run tests: `go test ./cmd/sluice/ -v -timeout 30s`

### Task 9: Add `sluice cred` integration with policy rules

When a credential is added with `--destination`, auto-create the corresponding allow rule and binding.

**Files:**
- Modify: `cmd/sluice/cred.go`
- Modify: `cmd/sluice/cred_test.go`

- [ ] Extend `sluice cred add <name>` with optional `--destination`, `--ports`, `--header`, `--template` flags
- [ ] When `--destination` is provided: add credential to vault, create allow rule in store, create binding in store
- [ ] `sluice cred list` shows credentials with their bindings (joined from store)
- [ ] `sluice cred remove <name>` removes credential + associated binding + allow rule
- [ ] Write tests for integrated cred+policy+binding workflow
- [ ] Run tests: `go test ./cmd/sluice/ -v -timeout 30s`

### Task 10: Cleanup and remove TOML runtime dependency

Remove BurntSushi/toml from runtime imports. It stays only in `store/import.go` for seeding.

**Files:**
- Modify: `cmd/sluice/main.go`
- Modify: `cmd/sluice/mcp.go`
- Modify: `internal/policy/engine.go`
- Modify: `internal/policy/types.go`
- Remove or update: `testdata/*.toml` (keep for import tests only)

- [ ] Remove `toml` struct tags from types that no longer need them (Engine internals)
- [ ] Keep `toml` tags on types used by `store/import.go` (policyFile, Rule, etc.)
- [ ] Verify `go.mod` still lists `BurntSushi/toml` only as needed by import.go
- [ ] Remove any dead code paths that were TOML-specific
- [ ] Run `go vet ./...`
- [ ] Run tests: `go test ./... -v -timeout 30s`

### Task 11: Verify acceptance criteria

- [ ] Verify `sluice policy add allow example.com` persists across restart
- [ ] Verify Telegram "Always Allow" persists across restart
- [ ] Verify `sluice policy import policy.toml` seeds an empty DB correctly
- [ ] Verify `sluice policy import` skips duplicates on second run
- [ ] Verify `sluice mcp add github --command npx --args "-y,@mcp/server-github"` registers upstream
- [ ] Verify credential hot-reload works without container restart
- [ ] Verify `sluice cred add mykey --destination api.example.com --ports 443` creates credential + rule + binding
- [ ] Verify SIGHUP recompiles Engine from store (not file)
- [ ] Run full test suite: `go test ./... -v -timeout 60s -race`
- [ ] Run linter: `go vet ./...`

### Task 12: [Final] Update documentation

- [ ] Update CLAUDE.md: replace TOML-centric architecture description with SQLite store
- [ ] Update CLAUDE.md: document new CLI subcommands (policy, mcp add/list/remove)
- [ ] Update CLAUDE.md: document hot credential reload
- [ ] Update CONTRIBUTING.md if development workflow changed
- [ ] Update examples/policy.toml header comment explaining it's a seed file
- [ ] Update compose.yml and compose.dev.yml with phantom volume

## Technical Details

### SQLite database location

Default: `~/.sluice/sluice.db` (same directory as vault credentials).
In Docker: `/home/sluice/.sluice/sluice.db` (persisted via `sluice-vault` volume).

### Engine recompile flow

```
Store mutation (CLI/Telegram/approval)
    |
    v
store.AddRule(...)  -- persists to SQLite
    |
    v
policy.LoadFromStore(store)  -- reads all rules, compiles glob patterns
    |
    v
srv.StoreEngine(newEngine)  -- atomic pointer swap
```

This replaces the current SIGHUP-based reload for dynamic changes. SIGHUP can still trigger a recompile for operational consistency.

### Hot credential reload flow

```
sluice cred add anthropic_api_key
    |
    v
vault.Store.Add("anthropic_api_key", realValue)
    |
    v
docker.GeneratePhantomEnv(names) -> map[string]string
    |
    v
Write phantom files to /phantoms/ volume:
    /phantoms/ANTHROPIC_API_KEY -> "sk-ant-phantom-abc123..."
    |
    v
docker exec openclaw openclaw secrets reload
    |
    v
OpenClaw re-reads SecretRef file sources, atomic swap in memory
```

### Unified control plane interfaces

| Action | CLI | Telegram | Approval Flow |
|--------|-----|----------|---------------|
| Add allow rule | `sluice policy add allow ...` | `/policy allow ...` | "Always Allow" button |
| Add deny rule | `sluice policy add deny ...` | `/policy deny ...` | -- |
| Remove rule | `sluice policy remove <id>` | `/policy remove <id>` | -- |
| Add credential | `sluice cred add <name>` | `/cred add <name>` | -- |
| Add MCP upstream | `sluice mcp add <name> ...` | `/mcp add <name> ...` | -- |
| Import TOML seed | `sluice policy import f.toml` | -- | -- |
| Export current rules | `sluice policy export` | `/policy show` | -- |

All three interfaces write to the same SQLite database.

### Dependency

`modernc.org/sqlite` -- Pure Go SQLite implementation. No CGO required. Works with `CGO_ENABLED=0` builds (important for Alpine Docker image). Well-maintained, production-ready.

## Post-Completion

**Manual verification:**
- Deploy three-container stack, add credentials via CLI, verify OpenClaw picks them up without restart
- Test `sluice policy import examples/policy.toml` on fresh DB
- Test Telegram `/policy allow` persists across `docker compose restart sluice`
- Test `sluice mcp add` and verify gateway serves the new upstream's tools
- Performance: verify policy evaluation latency is not degraded by SQLite reads (Engine is still an in-memory compiled snapshot)

**Migration guide for existing users:**
- Run `sluice policy import policy.toml` once to seed the DB
- Remove `--policy` flag from Docker CMD (or keep for auto-seed on empty DB)
- Update compose volumes to include `sluice-phantoms` for hot reload
- Update OpenClaw SecretRefs to use file sources from `/phantoms/` directory
