# Plan 9: Schema Refactor and Channel Abstraction

## Overview

Refactor the SQLite store schema and codebase to unify rules tables, add proper migrations, abstract the Telegram bot into a Channel interface, fix phantom token injection scope, and clean up naming inconsistencies. This is a design cleanup after the initial SQLite migration (Plan 8), incorporating decisions from the architecture review discussion.

**Key changes:**
1. Unify `rules`, `tool_rules`, `inspect_rules` into single `rules` table with verdict allow/deny/ask/redact
2. Replace key-value `config` table with typed singleton row
3. Add `channels` table with integer type enum
4. Rename `inject_header` to `header` in bindings, `note` to `name` in rules, `protocol` to `protocols` (plural, JSON array)
5. Use `golang-migrate` with embedded SQL files (PhantomPay pattern)
6. Abstract Telegram into Channel interface with ChannelType enum
7. Replace phantom tokens in ALL MITMed traffic (not just bound destinations)
8. Rename `policy.toml` to `config.toml`, hardcode Telegram env var names
9. Auto-import config.toml in Docker on first startup

## Context

**Current state (post Plan 8):**
- 6 SQLite tables: `rules`, `tool_rules`, `inspect_rules`, `config` (KV), `bindings`, `mcp_upstreams`
- 30+ CRUD methods in `internal/store/store.go` (719 lines)
- 9 import struct types in `internal/store/import.go` (501 lines)
- 44 tests across `store_test.go` and `import_test.go`
- Telegram tightly coupled to `internal/telegram/` package
- Phantom token injection scoped to binding-matched requests only (`inject.go:189`)
- Config stored as key-value pairs (string only)
- No versioned migration system

**Files that will change:**
- `internal/store/store.go` -- schema, all CRUD methods, type definitions
- `internal/store/import.go` -- import structs, ImportTOML method
- `internal/store/store_test.go` -- 31 tests
- `internal/store/import_test.go` -- 13 tests
- `internal/policy/engine_store.go` -- LoadFromStore reads from store
- `internal/policy/types.go` -- Verdict enum (add Redact), Rule struct
- `internal/telegram/approval.go` -- extract Channel interface
- `internal/telegram/commands.go` -- use store for channel config, remove env name indirection
- `internal/telegram/bot.go` -- implement Channel interface
- `internal/proxy/inject.go` -- phantom replacement in all MITMed traffic
- `cmd/sluice/main.go` -- hardcode env var names, rename --policy to --config
- `Dockerfile` -- rename policy.toml to config.toml in CMD
- `examples/policy.toml` -- rename to `examples/config.toml`, update format
- `compose.yml`, `compose.dev.yml` -- update volume mount paths
- New: `internal/channel/channel.go` -- Channel interface + ChannelType enum
- New: `internal/store/migrations/000001_init.up.sql` and `.down.sql`
- New: `internal/store/migrate.go` -- golang-migrate integration with embed

**Dependencies to add:**
- `github.com/golang-migrate/migrate/v4` (migration framework)

**Reference:** PhantomPay/Backend migration pattern at `internal/platform/database/migrate.go`

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- All tests must pass before starting next task
- This plan builds on top of the Plan 8 branch (plan-08-sqlite-policy-store-unified-control-plane)

## Testing Strategy

- **Unit tests**: Required for every task. SQLite tests use `:memory:` DBs.
- **Migration tests**: Verify fresh DB creates correct schema.
- **Integration tests**: Verify CRUD operations work with unified schema.

## Implementation Steps

### Task 1: Add golang-migrate infrastructure with embedded SQL

Set up the migration framework using the PhantomPay pattern but with embedded SQL files instead of filesystem reads. Write the initial migration (000001_init) with the new unified schema.

**Files:**
- Create: `internal/store/migrations/000001_init.up.sql`
- Create: `internal/store/migrations/000001_init.down.sql`
- Create: `internal/store/migrate.go`
- Modify: `internal/store/store.go` (replace inline schema with migration runner)
- Modify: `go.mod` (add golang-migrate)

**Target schema (000001_init.up.sql):**

```sql
CREATE TABLE rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    verdict TEXT NOT NULL CHECK(verdict IN ('allow', 'deny', 'ask', 'redact')),
    destination TEXT,
    tool TEXT,
    pattern TEXT,
    replacement TEXT,
    ports TEXT,
    protocols TEXT,
    name TEXT,
    source TEXT NOT NULL DEFAULT 'manual',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    CHECK(
        (destination IS NOT NULL AND tool IS NULL AND pattern IS NULL) OR
        (tool IS NOT NULL AND destination IS NULL AND pattern IS NULL) OR
        (pattern IS NOT NULL AND destination IS NULL AND tool IS NULL)
    )
);

CREATE TABLE config (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    default_verdict TEXT NOT NULL DEFAULT 'deny' CHECK(default_verdict IN ('allow', 'deny', 'ask')),
    timeout_sec INTEGER NOT NULL DEFAULT 120,
    vault_provider TEXT NOT NULL DEFAULT 'age',
    vault_dir TEXT,
    vault_providers TEXT,
    vault_hashicorp_addr TEXT,
    vault_hashicorp_mount TEXT DEFAULT 'secret',
    vault_hashicorp_prefix TEXT,
    vault_hashicorp_auth TEXT DEFAULT 'token',
    vault_hashicorp_token TEXT,
    vault_hashicorp_role_id TEXT,
    vault_hashicorp_secret_id TEXT,
    vault_hashicorp_role_id_env TEXT,
    vault_hashicorp_secret_id_env TEXT
);

INSERT OR IGNORE INTO config (id) VALUES (1);

CREATE TABLE bindings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    destination TEXT NOT NULL,
    ports TEXT,
    credential TEXT NOT NULL,
    header TEXT,
    template TEXT,
    protocols TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE mcp_upstreams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    command TEXT NOT NULL,
    args TEXT,
    env TEXT,
    timeout_sec INTEGER DEFAULT 120,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO channels (id, type) VALUES (1, 0);
```

- [x] Add `github.com/golang-migrate/migrate/v4` dependency
- [x] Create `internal/store/migrations/000001_init.up.sql` with unified schema (5 tables: rules, config, bindings, mcp_upstreams, channels)
- [x] Create `internal/store/migrations/000001_init.down.sql` with DROP TABLE statements
- [x] Create `internal/store/migrate.go` with `//go:embed migrations/*.sql`, using `source/iofs` driver and `database/sqlite` driver from golang-migrate
- [x] Replace inline `schema` const and `migrate()` in store.go with call to `runMigrations(db)`
- [x] Write test that creates a fresh DB and verifies all 5 tables exist with correct columns
- [x] Write test that migrations are idempotent (run twice, no error)
- [x] Run tests: `go test ./internal/store/ -v -timeout 30s`

### Task 2: Rewrite store CRUD for unified rules table

Replace `NetworkRule`/`ToolRuleRow`/`InspectRuleRow` types with a single `Rule` type. Replace all separate CRUD methods with unified methods.

**Files:**
- Modify: `internal/store/store.go` -- remove old types/methods, add unified Rule type and methods

**New unified Rule type:**
```go
type Rule struct {
    ID          int64
    Verdict     string    // "allow", "deny", "ask", "redact"
    Destination string    // network rules
    Tool        string    // tool rules
    Pattern     string    // content deny/redact rules
    Replacement string    // only for verdict="redact"
    Ports       []int
    Protocols   []string
    Name        string
    Source      string
    CreatedAt   string
}
```

- [x] Remove `NetworkRule`, `ToolRuleRow`, `InspectRuleRow` types and all their CRUD methods
- [x] Create unified `Rule` struct with all fields
- [x] Implement `AddRule(verdict string, opts RuleOpts) (int64, error)` where RuleOpts has Destination, Tool, Pattern, Replacement, Ports, Protocols, Name, Source. Validate mutual exclusivity of destination/tool/pattern in Go code.
- [x] Implement `RemoveRule(id int64) (bool, error)`
- [x] Implement `ListRules(filter RuleFilter) ([]Rule, error)` where RuleFilter has optional Verdict, Type (network/tool/pattern) fields
- [x] Implement `RuleExists(verdict string, opts RuleExistsOpts) (bool, error)` for dedup during import
- [x] Remove `AddToolRule`, `RemoveToolRule`, `ListToolRules`, `ToolRuleExists`
- [x] Remove `AddInspectRule`, `RemoveInspectRule`, `ListInspectRules`
- [x] Update `RemoveRulesByDestinationAndSource` to work with unified table
- [x] Write tests for unified CRUD (network, tool, pattern, redact rules)
- [x] Write tests for mutual exclusivity validation (destination+tool = error)
- [x] Write tests for ListRules with filters (by verdict, by type)
- [x] Run tests: `go test ./internal/store/ -v -timeout 30s`

### Task 3: Rewrite config and bindings CRUD for new schema

Replace key-value config with typed singleton. Rename `inject_header` to `header`, `protocol` to `protocols` in bindings.

**Files:**
- Modify: `internal/store/store.go`

**New Config type:**
```go
type Config struct {
    DefaultVerdict          string
    TimeoutSec              int
    VaultProvider           string
    VaultDir                string
    VaultProviders          []string
    VaultHashicorpAddr      string
    VaultHashicorpMount     string
    VaultHashicorpPrefix    string
    VaultHashicorpAuth      string
    VaultHashicorpToken     string
    VaultHashicorpRoleID    string
    VaultHashicorpSecretID  string
    VaultHashicorpRoleIDEnv string
    VaultHashicorpSecretIDEnv string
}
```

- [x] Remove `GetConfig(key)` and `SetConfig(key, value)` methods
- [x] Create `Config` struct with typed fields matching config table columns
- [x] Implement `GetConfig() (*Config, error)` that reads the singleton row
- [x] Implement `UpdateConfig(updates ConfigUpdate) error` that updates only non-zero fields
- [x] Update `BindingRow`: rename `InjectHeader` to `Header`, rename `Protocol string` to `Protocols []string`
- [x] Update `AddBinding`, `ListBindings`, `ListBindingsByCredential` for renamed columns and JSON array protocols
- [x] Add channels CRUD: `GetChannel(id) (*Channel, error)`, `UpdateChannel(id, updates) error`, `ListChannels() ([]Channel, error)`
- [x] Write tests for typed config CRUD (get defaults, update partial, update full)
- [x] Write tests for binding CRUD with new field names
- [x] Write tests for channels CRUD
- [x] Run tests: `go test ./internal/store/ -v -timeout 30s`

### Task 4: Create Channel interface and ChannelType enum

Abstract Telegram into a Channel interface. Create ChannelType enum following PhantomPay's Chain enum pattern.

**Files:**
- Create: `internal/channel/channel.go`
- Create: `internal/channel/channel_test.go`

```go
// ChannelType enumerates supported notification/approval channels.
type ChannelType int

const (
    ChannelTelegram ChannelType = 0
    ChannelHTTP     ChannelType = 1
)

// Channel is a single notification/approval endpoint (Telegram bot, HTTP webhook, etc.).
// Channels handle delivery only. The Broker coordinates across multiple channels.
type Channel interface {
    // RequestApproval delivers an approval prompt to this channel (non-blocking).
    RequestApproval(ctx context.Context, req ApprovalRequest) error
    // CancelApproval cleans up a resolved/timed-out approval on this channel
    // (e.g. edit Telegram message, POST cancellation webhook).
    CancelApproval(id string) error
    // Commands returns incoming admin commands from this channel (nil if unsupported).
    Commands() <-chan Command
    // Notify sends a one-way message (fire and forget).
    Notify(ctx context.Context, msg string) error
    Start() error
    Stop()
    Type() ChannelType
}

// Broker coordinates approval flow across multiple enabled channels.
// Broadcasts requests to all channels, first response wins.
type Broker struct {
    channels []Channel
    // ... waiters map, rate limiting, pending queue (moved from telegram.ApprovalBroker)
}
```

The Broker moves from `internal/telegram/approval.go` to `internal/channel/broker.go`. It becomes channel-agnostic. Approval requests are broadcast to all enabled channels. First `Resolve()` call wins. Other channels get `CancelApproval()` for cleanup.

- [x] Create `internal/channel/channel.go` with `ChannelType` enum (ChannelTelegram = 0, ChannelHTTP = 1) and `String()` method
- [x] Define `Channel` interface with non-blocking `RequestApproval`, `CancelApproval`, `Commands`, `Notify`, lifecycle methods
- [x] Define `ApprovalRequest`, `Response` (allow/deny/always-allow), and `Command` types in this package
- [x] Create `internal/channel/broker.go` with `Broker` struct: holds `[]Channel`, manages waiters, rate limiting, broadcast-and-first-wins logic
- [x] Implement `Broker.Request(dest, port, timeout)`: broadcast to all channels, wait for first `Resolve()`, cancel on remaining channels
- [x] Implement `Broker.Resolve(id, resp)`: first call wins (idempotent), triggers `CancelApproval` on other channels
- [x] Implement `Broker.CancelAll()`: deny all pending, call `CancelApproval` on all channels
- [x] Move rate limiting logic (MaxPendingRequests, per-destination limits) from telegram.ApprovalBroker to Broker
- [x] Write tests for ChannelType.String()
- [x] Write tests for Broker broadcast + first-response-wins logic
- [x] Write tests for cross-channel cancellation cleanup
- [x] Write tests for race condition (two channels resolve simultaneously)
- [x] Run tests: `go test ./internal/channel/ -v -timeout 30s`

### Task 5: Refactor Telegram bot to implement Channel interface

Move the ApprovalBroker logic and Bot into a Telegram-specific Channel implementation.

**Files:**
- Modify: `internal/telegram/approval.go` -- implement channel.Channel
- Modify: `internal/telegram/bot.go` -- wire to Channel interface
- Modify: `internal/telegram/commands.go` -- use channel types
- Modify: `internal/telegram/approval_test.go`
- Modify: `internal/telegram/bot_test.go`
- Modify: `internal/telegram/commands_test.go`

- [x] Create `TelegramChannel` struct implementing `channel.Channel` (wraps Bot + Telegram API interactions)
- [x] Implement non-blocking `RequestApproval`: send inline keyboard to Telegram (was sync in old broker, now async)
- [x] Implement `CancelApproval`: edit Telegram message to show "resolved via another channel"
- [x] Implement `Commands() <-chan channel.Command`: forward Telegram /commands as `channel.Command` values
- [x] Move `Response` enum (AllowOnce, Deny, AlwaysAllow) to `internal/channel/` package, update all references
- [x] Move `ApprovalRequest` type to `internal/channel/` package, update all references
- [x] Remove `ApprovalBroker` from `internal/telegram/` (logic moved to `channel.Broker` in Task 4)
- [x] Add `Type() channel.ChannelType` returning `channel.ChannelTelegram`
- [x] Update all callers in `internal/proxy/server.go`, `internal/mcp/gateway.go`, `cmd/sluice/main.go` to use `*channel.Broker` instead of `*telegram.ApprovalBroker`
- [x] main.go: read all enabled channels from store, instantiate each, pass slice to `channel.NewBroker(channels, opts...)`
- [x] Update tests to use channel.Broker and channel.Channel interface types
- [x] Run tests: `go test ./internal/telegram/ -v -timeout 30s`
- [x] Run tests: `go test ./... -v -timeout 30s`

### Task 6: Rewrite TOML import for unified schema

Update import.go to write to the unified rules table, typed config, and renamed binding fields. Rename the seed file from `policy.toml` to `config.toml`.

**Files:**
- Modify: `internal/store/import.go`
- Modify: `internal/store/import_test.go`
- Rename: `examples/policy.toml` to `examples/config.toml`
- Update: `examples/config.toml` -- new TOML format

**New TOML seed format (config.toml):**
```toml
[policy]
default = "ask"
timeout_sec = 120

[vault]
provider = "age"

# Network rules
[[allow]]
destination = "api.anthropic.com"
ports = [443]

# Tool rules (same sections, distinguished by field)
[[allow]]
tool = "github__list_*"
name = "read-only github"

# Content deny rules
[[deny]]
pattern = "(?i)(sk-[a-zA-Z0-9_-]{20,})"
name = "api key in tool arguments"

# Redact rules
[[redact]]
pattern = "(?i)(sk-[a-zA-Z0-9]{20,})"
replacement = "[REDACTED_API_KEY]"
name = "api key in responses"

# Bindings
[[binding]]
destination = "api.anthropic.com"
ports = [443]
credential = "anthropic_api_key"
header = "x-api-key"

# MCP upstreams
[[mcp_upstream]]
name = "github"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
timeout_sec = 60
# [mcp_upstream.env]
# GITHUB_TOKEN = "phantom-token-here"
```

- [x] Update `importFile` struct: remove `ToolAllow`, `ToolDeny`, `ToolAsk`, `InspectBlock`, `InspectRedact` fields. `[[allow]]`/`[[deny]]`/`[[ask]]` entries now carry either `destination`, `tool`, or `pattern`. Add `Redact []importRedactRule` for `[[redact]]` section.
- [x] Update `importRule` struct: add `Tool`, `Pattern`, `Protocols []string`, rename `Note` to `Name`
- [x] Create `importRedactRule` struct: `Pattern`, `Replacement`, `Name`, `Destination`, `Ports`, `Protocols`
- [x] Remove `importToolRule`, `importInspectBlock`, `importInspectRedact` structs
- [x] Update `importBinding`: rename `InjectHeader` to `Header`, rename `Protocol` to `Protocols []string`
- [x] Remove `importTelegramConfig` struct (hardcoded env var names, no longer in config)
- [x] Update `ImportTOML` to write all rules to unified `rules` table using `AddRule`
- [x] Update `ImportTOML` to write config as typed `UpdateConfig` call
- [x] Update all insert helpers for unified schema
- [x] Rename `examples/policy.toml` to `examples/config.toml` with updated format
- [x] Update all testdata/*.toml fixtures to new format
- [x] Rewrite import tests for unified schema
- [x] Run tests: `go test ./internal/store/ -v -timeout 30s`

### Task 7: Update policy engine to read from unified store

Rewrite `LoadFromStore` to read from the unified rules table and typed config.

**Files:**
- Modify: `internal/policy/engine_store.go`
- Modify: `internal/policy/types.go`
- Modify: `internal/policy/engine.go`
- Modify: `internal/policy/engine_test.go`

- [x] Add `Redact` to the `Verdict` enum in types.go
- [x] Update `Rule` struct: rename `Protocol` to `Protocols []string`
- [x] Remove `TelegramConfig` from Engine (hardcoded env vars, not in policy anymore)
- [x] Rewrite `LoadFromStore`: read all rules from unified table, filter by presence of destination/tool/pattern to populate AllowRules/DenyRules/AskRules/ToolAllowRules/ToolDenyRules/ToolAskRules/InspectBlockRules/InspectRedactRules
- [x] Read config via `store.GetConfig()` typed method instead of string keys
- [x] Update tests
- [x] Run tests: `go test ./internal/policy/ -v -timeout 30s`

### Task 8: Hardcode Telegram env vars and wire Channel interface in main.go

Remove configurable env var name indirection. Use channel.Channel interface. Rename --policy to --config.

**Files:**
- Modify: `cmd/sluice/main.go`
- Modify: `cmd/sluice/main_test.go`
- Modify: `Dockerfile`
- Modify: `compose.yml`, `compose.dev.yml`

- [x] Hardcode `os.Getenv("TELEGRAM_BOT_TOKEN")` and `os.Getenv("TELEGRAM_CHAT_ID")` directly. Remove the indirection that reads env var names from the engine/config.
- [x] Remove the `eng.Telegram.BotTokenEnv` / `eng.Telegram.ChatIDEnv` lookups
- [x] Rename `--policy` flag to `--config` (same auto-seed behavior)
- [x] Update Dockerfile CMD: replace `-policy /etc/sluice/policy.toml` with `-config /etc/sluice/config.toml`
- [x] Update compose.yml: rename volume mount from `./policy.toml:/etc/sluice/policy.toml:ro` to `./config.toml:/etc/sluice/config.toml:ro`
- [x] Update compose.dev.yml: rename `./examples/policy.toml` to `./examples/config.toml`
- [x] Use `channel.Channel` interface for broker throughout main.go instead of `*telegram.ApprovalBroker`
- [x] Update Telegram commands to use typed config from store (no more string key lookups)
- [x] Update tests
- [x] Run tests: `go test ./cmd/sluice/ -v -timeout 30s`

### Task 9: Fix phantom token injection to cover all MITMed traffic

Currently `injectCredentials` in inject.go only replaces phantom tokens for requests matching a binding. Phantom tokens should be replaced in ALL MITMed traffic to prevent leaks.

**Files:**
- Modify: `internal/proxy/inject.go`
- Modify: `internal/proxy/inject_test.go`

- [ ] In `injectCredentials`, after the binding-specific header injection, add a second pass that replaces ALL known phantom tokens in ALL request headers and body regardless of binding match
- [ ] Get the list of all credential names from the vault provider (`provider.List()`) and compute phantom tokens for each
- [ ] For each phantom token, do find-and-replace in headers and body
- [ ] Keep the binding-specific header injection (sets the configured header). The global replacement is an additional safety net.
- [ ] Write test: request to a host WITHOUT a binding but containing a phantom token in the body. Verify the phantom is replaced.
- [ ] Write test: request to a host WITH a binding. Verify both header injection AND body phantom replacement work.
- [ ] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 10: Update Telegram commands for unified store

Update all `/policy` commands to use unified rule methods and typed config.

**Files:**
- Modify: `internal/telegram/commands.go`
- Modify: `internal/telegram/commands_test.go`

- [ ] Update `policyShowFromStore()`: use `store.GetConfig()` typed method, `store.ListRules(filter)` unified method
- [ ] Update `policyAllow()`/`policyDeny()`: call `store.AddRule()` with appropriate RuleOpts (destination or tool)
- [ ] Update `policyRemove()`: call `store.RemoveRule(id)` (works on unified table)
- [ ] Update "Always Allow" in proxy (`server.go`): call `store.AddRule()` with source="approval"
- [ ] Update "Always Allow" in MCP gateway (`gateway.go`): same pattern
- [ ] Update tests
- [ ] Run tests: `go test ./internal/telegram/ -v -timeout 30s`
- [ ] Run tests: `go test ./... -v -timeout 30s`

### Task 11: Verify acceptance criteria

- [ ] Verify unified rules table stores network, tool, pattern, and redact rules correctly
- [ ] Verify CHECK constraint rejects rules with multiple of destination/tool/pattern set
- [ ] Verify typed config singleton returns correct defaults and accepts updates
- [ ] Verify channels table exists with default Telegram row (type=0, enabled=1)
- [ ] Verify `config.toml` import works with unified format (allow/deny/ask with destination/tool/pattern, [[redact]])
- [ ] Verify import merge semantics (no duplicates on re-import)
- [ ] Verify Telegram env var names are hardcoded (no config-based indirection)
- [ ] Verify phantom tokens are replaced in ALL MITMed traffic (not just bound destinations)
- [ ] Verify Channel interface is used throughout (no direct telegram.ApprovalBroker references outside telegram package)
- [ ] Verify golang-migrate runs on fresh DB and creates correct schema
- [ ] Run full test suite: `go test ./... -v -timeout 60s -race`
- [ ] Run linter: `go vet ./...`

### Task 12: [Final] Update documentation

- [ ] Update CLAUDE.md: new schema description, unified rules table, typed config, channels table
- [ ] Update CLAUDE.md: remove references to tool_allow/tool_deny/tool_ask and inspect_block/inspect_redact TOML sections
- [ ] Update CLAUDE.md: document Channel interface and ChannelType enum
- [ ] Update CLAUDE.md: document phantom token replacement in all MITMed traffic
- [ ] Update CLAUDE.md: rename policy.toml references to config.toml
- [ ] Update CONTRIBUTING.md if file structure changed
- [ ] Update examples/config.toml header comment explaining the seed format

## Technical Details

### Unified rules table -- rule type dispatch

The `verdict` column combined with which nullable field is populated determines the rule type:

| Verdict | destination | tool | pattern | replacement | Rule type |
|---------|------------|------|---------|-------------|-----------|
| allow | set | NULL | NULL | NULL | Network allow |
| allow | NULL | set | NULL | NULL | Tool allow |
| deny | set | NULL | NULL | NULL | Network deny |
| deny | NULL | set | NULL | NULL | Tool deny |
| deny | NULL | NULL | set | NULL | Content deny (block) |
| ask | set | NULL | NULL | NULL | Network ask |
| ask | NULL | set | NULL | NULL | Tool ask |
| redact | NULL | NULL | set | set | Content redact |
| redact | set | NULL | set | set | Scoped content redact (filter by destination) |

The `CHECK` constraint enforces mutual exclusivity of destination/tool/pattern at the database level. Additional validation in Go code provides better error messages.

### golang-migrate with embedded SQL

```go
//go:embed migrations/*.sql
var migrationsFS embed.FS

func runMigrations(db *sql.DB) error {
    driver, _ := sqlite.WithInstance(db, &sqlite.Config{})
    source, _ := iofs.New(migrationsFS, "migrations")
    m, _ := migrate.NewWithInstance("iofs", source, "sqlite", driver)
    if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
        return err
    }
    return nil
}
```

SQL files are compiled into the binary. No external files needed at runtime.

### Channel interface wiring

```
cmd/sluice/main.go
    |
    v
channel.Channel (interface)
    |
    v
telegram.TelegramChannel (concrete)
    |-- ApprovalBroker (request/resolve/cancel)
    |-- Bot (Telegram API, inline keyboards, commands)
    
proxy/server.go uses channel.Channel for approval flow
mcp/gateway.go uses channel.Channel for tool approval
```

Future HTTP channel implementation (Plan 10) satisfies the same interface without touching proxy or gateway code. The Broker broadcasts to all enabled channels and coordinates first-response-wins resolution.

### Phantom token global replacement

```go
func (inj *Injector) injectCredentials(r *http.Request, ctx *goproxy.ProxyCtx) {
    // 1. Binding-specific header injection (existing logic)
    if binding, ok := inj.resolver.Resolve(host, port); ok {
        // Set configured header, template formatting, etc.
    }

    // 2. Global phantom replacement (NEW: all MITMed traffic)
    names, _ := inj.provider.List()
    for _, name := range names {
        phantom := PhantomToken(name)
        secret, err := inj.provider.Get(name)
        if err != nil { continue }
        // Replace in headers and body
        secret.Release()
    }
}
```

This ensures a phantom token can never leak to an upstream, even if the agent sends it to an unexpected destination.

## Post-Completion

**Manual verification:**
- Deploy with `docker compose -f compose.dev.yml up --build`
- Verify `config.toml` is auto-imported on first startup
- Verify `sluice policy list` shows unified rules (network + tool + redact)
- Verify phantom tokens are replaced when sent to a host without a binding
- Verify Telegram approval flow works through Channel interface

**Follow-up plans:**
- Plan 10: HTTP channel (REST API + webhook delivery) and multi-channel support
- Plan 11: `sluice setup` interactive onboarding wizard
