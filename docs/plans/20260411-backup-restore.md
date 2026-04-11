# Backup and Restore

## Overview

Add a backup and restore mechanism for sluice state. Today, a lost SQLite file and vault directory means every policy, binding, credential, MCP upstream, and channel configuration must be recreated by hand.

This plan adds a first-class workflow:

- **Manual backup** triggered from the CLI (`sluice backup`), the REST API (`POST /api/backup`), or the Telegram bot (`/backup`).
- **Scheduled backups** driven by a crontab expression stored in the config table. Scheduled runs fire inside the same process as the proxy/gateway, deliver the resulting archive to every **enabled** connected channel (Telegram chat + any HTTP webhook), and keep the last N archives on disk.
- **Restore** from an archive via `sluice restore <path>`, `POST /api/restore`, or `/restore` in the Telegram bot. Destructive and gated behind explicit confirmation on every surface.

A backup archive is a single `tar.gz` containing:
- `sluice.db` dumped via `VACUUM INTO` (portable consistent dump supported by modernc/sqlite, safe to run while the proxy serves traffic on WAL)
- Encrypted credential files from the age vault directory — only when the active vault provider is `age` (or the provider chain includes `age`). Other providers are skipped with an audit note.
- A `manifest.json` with sluice version, schema version, timestamp, hostname, top-level archive sha256 (computed after writing), and a flat file list

Restore unpacks into a temp dir, verifies the top-level archive hash, runs the embedded migrations against the restored DB to bring it up to the current schema if needed, then atomically swaps files. After restore, sluice reloads and runs exactly as it did when the backup was taken: same rules, bindings, credential metadata, MCP upstreams, channel config, and (for age-managed credentials) same secret values.

Non-goals:
- Replicating third-party vault providers (hashicorp, 1password, bitwarden, keepass, gopass, env). Those are managed externally.
- Including the age identity file in backups. The identity is intentionally left on the host. Operators running a full disaster recovery must back up `vault-key.txt` out of band.
- Hot-swap during traffic. Restore is a maintenance operation and requires the daemon to be stopped.

## Context (from discovery)

Integration points and patterns (from exploration of the current tree):

- **CLI dispatch**: `cmd/sluice/main.go` routes top-level subcommands via a switch. A new `backup` and `restore` case wires to `handleBackupCommand` / `handleRestoreCommand` in a new `cmd/sluice/backup.go`, matching the existing `policy.go`, `binding.go`, `cred.go` pattern.
- **Reload mutex and reloadAll closure**: `cmd/sluice/main.go:617` defines a `reloadAll` closure that acquires `srv.ReloadMu().Lock()` and reloads policy, bindings, and OAuth index. SIGHUP and the `store.NewWatcher` at `main.go:681` both call `reloadAll`. This is the hook point for the scheduler to reload its cron expression after config changes.
- **Telegram commands**: `internal/telegram/commands.go` `CommandHandler.Handle(cmd *Command) string` returns text only. There is no existing path to send a binary attachment from a command handler. This plan introduces a new `CommandResult` return type with optional attachment bytes and updates the message loop to route attachments via the channel. The callback-button pattern lives in `internal/telegram/approval.go` `handleCallback` and is reused for the `/restore` two-step confirmation.
- **registerCommands**: `internal/telegram/approval.go:215` registers the bot's `/`-menu command list. New `backup` / `restore` / `backup_config` commands go here.
- **HTTP API**: `internal/api/server.go` exposes receiver methods on `Server` wired through `api.gen.go` from `api/openapi.yaml`. Bearer-token middleware covers mutation endpoints. API endpoints currently return JSON only, so the backup download endpoint will be JSON (manifest + base64 or a `GET /api/backup/{name}` fetch) rather than streaming binary.
- **Channel interface**: `internal/channel/channel.go` `Channel` interface has `Notify(ctx, msg)` but no binary attachment method. This plan extends the interface with `NotifyAttachment(ctx, name, data, size)` and updates every implementer and every test-double in a single task.
- **Config table**: `internal/store/migrations/000001_init.up.sql` defines the singleton `config` row. Latest migration is `000005_binding_unique_cred_dest`. The new migration is `000006_backup_config`. Accessors `GetConfig` / `UpdateConfig` already exist on `store.Store` around `store.go:332-420`; new backup columns plug into the same pattern.
- **Age vault detection**: `internal/vault/provider.go` keys on `cfg.Provider == "age"` or chain membership. `internal/vault/store.go:32` stores the identity at `<dir>/vault-key.txt`. Credential files live at `<dir>/credentials/*.age`.
- **Goroutine lifecycle**: `cmd/sluice/main.go` spawns background tasks with `go func()` and ties shutdown to signal handlers. A new `backup.Scheduler` starts alongside the proxy and stops on shutdown.
- **Audit log**: `internal/audit/logger.go` `Event` has an `Action` field. Backup/restore emit `backup_start`, `backup_complete`, `backup_failed`, `restore_start`, `restore_complete`, `restore_failed` events with the archive sha256 as the `Reason` field.

## Development Approach

- **testing approach**: Regular (code first, then tests) — matches the binding-cli plan
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task
- **CRITICAL: all tests must pass before starting next task** — no exceptions
- Run `go test ./... -timeout 120s` after each change
- Run `gofumpt -l cmd/sluice/ internal/` before commit (must be empty)
- Run `golangci-lint run ./...` before commit (must be 0 issues)
- Every CLI `fs.Parse` call MUST go through `reorderFlagsBeforePositional` (v0.8.1 rule)
- Maintain backward compatibility: existing installs that never configure backups must keep working unchanged

## Testing Strategy

- **Unit tests**: Go tests for the archive builder, restore validator, cron scheduler, CLI commands, API handlers, Telegram command handlers, channel attachment implementations. Each task lands tests in the same commit.
- **Integration tests**: Full round-trip archive create -> extract into a fresh store -> verify `sluice policy list`, `binding list`, `cred list`, `mcp list`, `channel list` outputs are byte-identical to pre-backup snapshot. Done as Go tests at the store level, not as e2e.
- **Crash recovery test**: Simulate a restore interruption between file moves and assert the pre-restore state is recoverable via the documented manual procedure.
- **E2e tests**: Deferred to manual verification.

## Progress Tracking

- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with `+` prefix
- Document issues/blockers with `!` prefix
- Update plan if implementation deviates from original scope

## Solution Overview

### Concurrency model (two code paths)

**In-process path** — used by the scheduler and REST API handlers. Acquires `srv.ReloadMu()` for the duration of the DB snapshot phase only (releases before vault enumeration). This is the same mutex that guards policy/binding reloads, so a scheduled backup cannot race a SIGHUP reload. A process-local `sync.Mutex` in the backup package prevents two concurrent builds within the same process (API call while a scheduled tick is running returns `ErrBackupInProgress`).

**Out-of-process path** — used by the CLI (`sluice backup`) when invoked from a shell against the DB of a running daemon, or against a stopped daemon's files. The CLI cannot acquire the daemon's in-memory mutex. It relies on SQLite WAL + `VACUUM INTO` for DB consistency and takes a best-effort snapshot of the credentials directory. The CLI documents this trade-off in its `--help` text ("when run against a live daemon, credential files may be captured at slightly different points in wall-clock time than the DB"). Cross-process coordination is out of scope, same as the rest of the codebase.

### Archive format

Single `tar.gz` using stdlib `archive/tar` + `compress/gzip` (no new dependency). Layout:

```
manifest.json
sluice.db
vault/
  credentials/
    <name>.age
    ...
```

The age identity file (`vault-key.txt`) is **not** included. Backups are useless to anyone without the identity, but this keeps the identity out of archives that end up in chat channels or webhooks.

`manifest.json` fields:

```json
{
  "sluice_version": "v0.8.1",
  "schema_version": 5,
  "created_at": "2026-04-11T14:27:52Z",
  "hostname": "knuth",
  "vault_provider": "age",
  "files": ["sluice.db", "vault/credentials/foo.age"]
}
```

The archive's top-level sha256 is computed after the tar.gz is written and returned in `BuildResult` so callers (API, scheduler, CLI) can log and publish it. The sha256 is not stored in the manifest itself (circular). Restore verifies the archive hash against a caller-supplied expected hash when one is provided (API confirmation flow), otherwise it just logs the computed hash.

Why gzip instead of zstd: stdlib gzip keeps the dependency surface flat. Measured backup sizes for realistic sluice DBs are well under Telegram's 50 MB document limit, so zstd's 15-20% edge over gzip is not worth the new dependency. If this changes, switching compressors is a one-file change in `internal/backup/builder.go`.

### Archive builder (`internal/backup/builder.go`)

1. Start a transaction-scoped snapshot via `VACUUM INTO <tempfile>`. modernc/sqlite supports this and produces a consistent file even under concurrent writers on WAL.
2. Compute sha256 of the vacuumed DB as it's streamed into the tarball.
3. If the active vault provider is `age`, enumerate `<vault_dir>/credentials/*.age` and append each to the archive. Skip `vault-key.txt`.
4. If the active vault provider is anything else, skip credential enumeration and emit an audit note so the operator knows the archive is DB-only.
5. Build `manifest.json` with the file list (no per-entry hashes).
6. Close the gzip writer, rename the temp archive into its final location atomically.
7. Return `BuildResult{Archive, Size, ArchiveSHA256, Elapsed}`.

Builder methods accept a `context.Context`. The in-process path passes a context with a deadline (default 120s) derived from the handler timeout. `Build` returns `ErrBackupInProgress` when a second caller hits the process-local mutex.

### Scheduler (`internal/backup/scheduler.go`)

Wraps `github.com/robfig/cron/v3` (5-field crontab syntax, minute precision, `cron.WithLocation(time.UTC)` for deterministic scheduling across containers).

Lifecycle:
- `Start(ctx)` — read `config.backup_cron`. If empty, register nothing and return nil (scheduler idle). Otherwise parse and register the callback.
- `Reload()` — called from the shared `reloadAll` closure in `main.go`. Stops the current entry and re-registers from the latest config value. Called after SIGHUP AND after the db watcher detects any config change, so `sluice backup config set-cron "..."` from CLI takes effect immediately.
- `TriggerOnce(ctx)` — test hook; bypasses cron timing and runs the fire callback synchronously. Used in unit tests in place of a fake clock.
- `Stop()` — cancels context and drains in-flight fires.

On each fire:
1. Re-read the enabled channel set from the store (only `enabled=1` rows) so a disabled channel is skipped even if it was enabled at Start time.
2. Build the archive to `backup_dir/sluice-YYYYMMDD-HHMMSS.tar.gz`.
3. For each enabled channel, call `NotifyAttachment` with a short retry + backoff (max 3 attempts at 1s / 5s / 30s). Failures are logged to audit but do not block other channels.
4. Prune `backup_dir` to the last `backup_retention` archives (delete oldest, keep manifest file list consistent).
5. Emit `audit.Event{Action: "backup_complete", Reason: "<archive path> sha256=<hash>"}`.

### Channel attachment delivery

Extend `internal/channel/channel.go`:

```go
type Channel interface {
    // ... existing methods
    NotifyAttachment(ctx context.Context, name string, data io.Reader, size int64) error
}
```

Every test-double and every production implementation must be updated in a single task so the interface change compiles across the module.

- **Telegram**: uses the Bot API `sendDocument`. Size check against 50 MB: over-limit archives log a notification ("backup <name> is <size> MB, over Telegram's 50 MB limit, retrieve via `sluice backup list` or the REST API") and return nil so the scheduler treats it as non-fatal.
- **HTTP webhook**: multipart POST with fields `name`, `created_at`, `archive_sha256`, and `archive` (the file bytes). HMAC-SHA256 signature over the entire multipart body in header `X-Sluice-Signature: sha256=<hex>` using the existing `webhook_secret`. Signature format matches the approval webhook payloads for consistency. Documented in `docs/webhooks.md`.

### Restore (`internal/backup/restore.go`)

Restore is a maintenance operation. It refuses to run while another sluice instance is listening on the health address and requires the daemon to be stopped first (or `--force` to override at the operator's risk).

Flow:
1. Pre-flight: probe `http://127.0.0.1:<health port>/healthz`. If reachable, refuse with a clear message ("stop sluice before restoring, or pass --force").
2. Parse the `tar.gz` header-by-header into a temp dir.
3. Read `manifest.json`. Validate: schema_version is equal-or-older than current. Newer schema is refused without `--force`.
4. If schema_version is older, run embedded migrations against the restored DB to bring it up to current.
5. Compute the archive sha256 as the tar.gz streams in. If the caller provided an expected hash, compare and reject on mismatch.
6. **Atomic swap ordering (prevents the no-DB window)**:
   a. Move restored files into staging locations: `data/sluice.db.restore-<ts>` and `<vault_dir>/credentials.restore-<ts>`.
   b. Rename the CURRENT files aside: `data/sluice.db` -> `data/sluice.db.pre-restore-<ts>`, `<vault_dir>/credentials` -> `<vault_dir>/credentials.pre-restore-<ts>`.
   c. Rename staging into place: `data/sluice.db.restore-<ts>` -> `data/sluice.db`, `<vault_dir>/credentials.restore-<ts>` -> `<vault_dir>/credentials`.
   d. If any step in (c) fails, roll back (b) by reversing the renames so the system is left in the pre-restore state.
7. Emit `audit.Event{Action: "restore_complete", Reason: "archive=<name> sha256=<hash> pre-restore-suffix=<ts>"}`.
8. Print a success message with the `.pre-restore-<ts>` suffix so the operator can recover manually if restore is later found to be wrong.
9. Exit with instructions to start sluice.

Crash recovery: if restore is killed mid-swap, the operator runs `sluice restore --resolve` (a small helper that inspects the directory for `.restore-<ts>` and `.pre-restore-<ts>` leftovers and either completes or rolls back the swap based on which files are present).

Confirmation gating:
- **CLI**: require `--yes` or an interactive `y/N` prompt on stdin.
- **API**: two-step flow. `POST /api/restore/preview` uploads the archive, returns `{"confirm_token": "<opaque>", "manifest": {...}, "archive_sha256": "<hash>"}`, and stores the archive bytes in a process-local staging dir with a short TTL (60s). `POST /api/restore` takes the token and performs the swap. Staging dir is wiped on process restart.
- **Telegram**: `/restore <archive_name>` looks up the archive in `backup_dir`, replies with manifest summary and an inline confirm button. The callback handler (`handleCallback` in `approval.go`) executes the swap on second tap.

### Config schema

Migration `000006_backup_config.up.sql`:

```sql
ALTER TABLE config ADD COLUMN backup_cron TEXT NOT NULL DEFAULT '';
ALTER TABLE config ADD COLUMN backup_retention INTEGER NOT NULL DEFAULT 7;
ALTER TABLE config ADD COLUMN backup_dir TEXT NOT NULL DEFAULT '';
```

`000006_backup_config.down.sql` drops those columns via the `CREATE TABLE config_new ... INSERT SELECT ... DROP TABLE config ... ALTER TABLE config_new RENAME` dance because SQLite < 3.35 does not support `ALTER TABLE ... DROP COLUMN`. Verify target SQLite version supports drop-column before using the shorter form.

Accessors on `store.Store` extend the existing `BackupConfig` struct pattern:
- `GetBackupConfig() (BackupConfig, error)` — returns struct with Cron, Retention, Dir, with Dir defaulting at runtime to `<home>/.sluice/backups` if empty.
- `SetBackupConfig(BackupConfig) error` — validates cron via `cron.ParseStandard` before writing. Empty cron is allowed and means "no scheduled backups".

### CLI surface

```
sluice backup [--out <path>] [--db <path>]
sluice backup config set-cron "<expr>" [--db <path>]
sluice backup config set-retention <n> [--db <path>]
sluice backup config set-dir <path> [--db <path>]
sluice backup config show [--db <path>]
sluice backup list [--db <path>]

sluice restore <archive> [--yes] [--force] [--db <path>]
sluice restore --resolve [--db <path>]        # recovery from interrupted swap
```

Scope-trimmed: dropped `sluice backup send <path>` (scope creep per review) and `--include-identity` (security sensitive, not requested).

### REST API surface

```
POST /api/backup                  -> 202 Accepted + manifest JSON; archive persisted in backup_dir
GET  /api/backup                  -> list archives in backup_dir
GET  /api/backup/{name}           -> JSON with {manifest, archive_sha256, download_url}
GET  /api/backup/{name}/download  -> raw archive bytes (octet-stream)
GET  /api/backup/config           -> BackupConfig JSON
PUT  /api/backup/config           -> update cron / retention / dir
POST /api/restore/preview         -> multipart archive upload, returns confirm_token + manifest
POST /api/restore                 -> {"confirm_token": "..."} body, performs the swap
```

All endpoints use the existing Bearer middleware. `POST /api/backup` holds `srv.ReloadMu()` only during the DB snapshot phase. Binary download is confined to one endpoint (`/download`) so the rest of the API stays JSON-only.

Dropped from the earlier revision: `POST /api/backup/{name}/send` (scope creep), `?metadata-only=true` on POST (avoid dual-shape responses), single-step `POST /api/restore` (replaced by two-step preview/confirm).

### Telegram surface

```
/backup                       # manual backup, delivered to requesting chat only
/backup_config                # show current cron + retention
/backup_set_cron <expr>       # update cron
/restore <archive_name>       # two-step flow with inline confirm button
```

All gated by `IsAuthorizedChat`. `registerCommands` list in `internal/telegram/approval.go:215` updated to include the new commands in the `/`-menu auto-complete.

## Technical Details

### CommandHandler.Handle signature change

Today: `Handle(cmd *Command) string`. Callers ignore any non-text reply and push the string through the regular message path.

New: `Handle(cmd *Command) CommandResult` where:

```go
type CommandResult struct {
    Text        string
    Attachment  *CommandAttachment  // nil when no attachment
    Callback    *InlineKeyboard     // nil when no callback buttons
}

type CommandAttachment struct {
    Name string
    Data []byte  // kept small; builder writes to bytes.Buffer
    Size int64
}
```

The message loop in the caller (see `internal/telegram/bot.go` handler) inspects the result:
- If `Attachment != nil`, call `channel.NotifyAttachment` on the Telegram channel.
- If `Callback != nil`, build an inline keyboard on the outgoing message (same pattern as `approval.go` approve/deny flow).
- `Text` is always sent.

All existing handlers (`handleStart`, `handlePolicy`, `handleCred`, `handleStatus`, `handleAudit`, `handleHelp`) change from `return "..."` to `return CommandResult{Text: "..."}`. This is a mechanical rewrite.

### Scheduler lifecycle

```go
type Scheduler struct {
    mu       sync.Mutex
    cron     *cron.Cron
    entryID  cron.EntryID
    expr     string
    builder  *Builder
    broker   channel.Broker
    store    *store.Store
    audit    *audit.Logger
}

func NewScheduler(b *Builder, br channel.Broker, s *store.Store, a *audit.Logger) *Scheduler
func (s *Scheduler) Start(ctx context.Context) error
func (s *Scheduler) Reload() error        // called from reloadAll closure
func (s *Scheduler) TriggerOnce(context.Context) error  // test hook
func (s *Scheduler) Stop()
```

Started from `cmd/sluice/main.go`:

```go
backupBuilder := backup.NewBuilder(db, vaultStore, vaultDir)
backupSched := backup.NewScheduler(backupBuilder, broker, db, auditLogger)
if err := backupSched.Start(ctx); err != nil {
    log.Printf("[WARN] backup scheduler start failed: %v", err)
}
defer backupSched.Stop()
```

and wired into the existing `reloadAll` closure so config changes take effect without SIGHUP:

```go
reloadAll := func() {
    srv.ReloadMu().Lock()
    defer srv.ReloadMu().Unlock()
    // ... existing reloads
    if err := backupSched.Reload(); err != nil {
        log.Printf("[WARN] backup scheduler reload failed: %v", err)
    }
}
```

### Archive builder signature

```go
type Builder struct {
    store    *store.Store
    vault    vault.Provider
    vaultDir string
    reloadMu *sync.RWMutex   // nil for CLI path, set for in-process path
    mu       sync.Mutex      // serialises concurrent Build calls within the process
}

type BuildOptions struct {
    Out string  // absolute path for the final archive; empty means auto-derive in backup_dir
}

type BuildResult struct {
    Archive       string
    Size          int64
    ArchiveSHA256 string
    Manifest      Manifest
    Elapsed       time.Duration
}

func (b *Builder) Build(ctx context.Context, opts BuildOptions) (BuildResult, error)
```

When `reloadMu != nil`, Build locks it for the DB snapshot phase then releases it before enumerating vault credentials. The CLI constructs Builder with `reloadMu = nil` and just runs the snapshot unguarded.

### Dependencies

- `github.com/robfig/cron/v3` — 5-field crontab parser + scheduler. Single dependency, MIT, pure Go, widely used.
- **No** `klauspost/compress/zstd`. Stdlib `compress/gzip` is used for the archive compressor.

## What Goes Where

- **Implementation Steps** (`[ ]` checkboxes): store migration, archive builder, restore logic, scheduler, channel interface extension, CLI, API, Telegram commands, main.go wiring, tests
- **Post-Completion** (no checkboxes): manual verification on the knuth deployment, documentation of the webhook multipart format

## Implementation Steps

### Task 1: Store migration for backup config

**Files:**
- Create: `internal/store/migrations/000006_backup_config.up.sql`
- Create: `internal/store/migrations/000006_backup_config.down.sql`
- Modify: `internal/store/store.go`
- Modify: `internal/store/store_test.go`

- [ ] create migration 000006 adding `backup_cron TEXT`, `backup_retention INTEGER DEFAULT 7`, `backup_dir TEXT` columns
- [ ] write the down migration with the `CREATE TABLE config_new ... INSERT SELECT ... DROP ... RENAME` dance for safe column drop
- [ ] add `BackupConfig` struct and `GetBackupConfig` / `SetBackupConfig` methods on `*Store`
- [ ] validate cron via `cron.ParseStandard` in `SetBackupConfig`; empty allowed; invalid rejected with clear error
- [ ] write tests for `SetBackupConfig` happy path, empty cron, invalid cron, retention bounds
- [ ] write migration round-trip test (apply 1-5, seed config, apply 6, assert defaults; apply down; assert columns gone)
- [ ] run `go test ./internal/store/ -timeout 30s` — must pass before next task

### Task 2a: Archive manifest + tar.gz writer

**Files:**
- Create: `internal/backup/manifest.go`
- Create: `internal/backup/builder.go` (partial — writer + manifest only)
- Create: `internal/backup/builder_test.go` (partial)

- [ ] define `Manifest`, `BuildResult`, `ErrBackupInProgress`
- [ ] implement `writeArchive(dst, dbPath, vaultFiles, manifest) (ArchiveSHA256, error)` using `archive/tar` + `compress/gzip` + streaming `sha256.Hash`
- [ ] ensure the archive top-level sha256 is computed as bytes are written
- [ ] write tests for manifest JSON round-trip, writeArchive writes a valid tarball with expected entries, stream hash matches a fresh sha256 of the final file
- [ ] run `go test ./internal/backup/ -timeout 30s` — must pass before next task

### Task 2b: Archive builder (DB snapshot + vault enumeration)

**Files:**
- Modify: `internal/backup/builder.go`
- Modify: `internal/backup/builder_test.go`

- [ ] implement `Builder` struct with optional `reloadMu *sync.RWMutex`
- [ ] implement `Build(ctx, opts)` that runs `VACUUM INTO <tempfile>`, compresses into archive via writeArchive from Task 2a
- [ ] for age provider, enumerate `<vault_dir>/credentials/*.age`; for other providers, skip and return manifest noting `vault_provider` for transparency
- [ ] guard concurrent calls with `sync.Mutex`; second caller gets `ErrBackupInProgress`
- [ ] honour ctx cancellation; return ctx.Err() if the deadline fires mid-snapshot
- [ ] write tests: round-trip (build -> extract -> compare DB row counts for every table), non-age vault produces DB-only archive, concurrent-call rejected, context cancellation surfaces, reloadMu is held only during snapshot phase (use a test that asserts the mutex is released before the vault enumeration by grabbing it from another goroutine)
- [ ] run `go test ./internal/backup/ -timeout 30s`

### Task 3: Restore logic

**Files:**
- Create: `internal/backup/restore.go`
- Create: `internal/backup/restore_test.go`

- [ ] implement `Restore(ctx, archivePath, opts) (RestoreResult, error)` that extracts `tar.gz` into a temp dir, reads manifest, validates schema_version and sluice_version
- [ ] run embedded golang-migrate on the restored DB when its schema_version is older than current
- [ ] refuse newer schema without `--force`; refuse to run while the daemon is healthy at `--health-addr` without `--force`
- [ ] implement the 3-step atomic swap: stage restored files -> rename current aside -> move staged into place; on any failure in step 3, roll back step 2
- [ ] implement `Restore --resolve` that inspects the directory for leftover `.restore-<ts>` / `.pre-restore-<ts>` files and completes or rolls back
- [ ] emit `audit.Event{Action: "restore_complete"}` with archive hash and pre-restore suffix
- [ ] write tests: full round-trip (Task 2b archive -> Restore -> store state identical via `ListRules/ListBindings/ListCredentialMeta/ListMCPUpstreams/ListChannels` comparison), refuse newer schema without force, bad archive sha256 rejected, missing manifest rejected, simulated swap-crash recovers via `--resolve`
- [ ] run `go test ./internal/backup/ -timeout 30s`

### Task 4: Channel attachment delivery

**Files:**
- Modify: `internal/channel/channel.go` (interface)
- Modify: `internal/telegram/channel.go` (or wherever TelegramChannel implements Channel)
- Modify: `internal/channel/http/http.go`
- Modify: every test-double that implements `Channel`: find via `grep -rn "channel.ChannelType" internal/` and `grep -rn "NotifyAttachment\|Notify(ctx" internal/` and `grep -rn "Reply(" internal/`; expected files include `internal/channel/channel_test.go`, `internal/telegram/approval_test.go`, `internal/api/server_test.go` (if it stubs channels), and any test files that compile against the interface

- [ ] add `NotifyAttachment(ctx context.Context, name string, data io.Reader, size int64) error` to the `Channel` interface
- [ ] implement Telegram `NotifyAttachment` via `sendDocument`. Size > 50 MB returns nil after sending a text fallback via `Notify`.
- [ ] implement HTTP webhook `NotifyAttachment` as a multipart POST with fields `name`, `created_at`, `archive_sha256`, `archive`; sign the body via HMAC-SHA256 with the existing `webhook_secret`; header `X-Sluice-Signature: sha256=<hex>`
- [ ] update EVERY test-double in the module so the test suite still compiles
- [ ] write tests: Telegram sendDocument is called with the right URL, form fields, and size-limit fallback path; HTTP webhook multipart tests assert each part present and the signature header matches an independent HMAC computation
- [ ] run `go test ./internal/channel/... ./internal/telegram/... -timeout 30s`

### Task 5: Scheduler

**Files:**
- Create: `internal/backup/scheduler.go`
- Create: `internal/backup/scheduler_test.go`
- Modify: `go.mod` / `go.sum` (add `github.com/robfig/cron/v3`)

- [ ] define `Scheduler` wrapping `cron.Cron` (UTC location) with `Start`, `Reload`, `TriggerOnce`, `Stop`
- [ ] on Start: read `config.backup_cron`, skip registration if empty
- [ ] on fire (and in TriggerOnce): re-read enabled channels from store, call Builder, deliver to each channel with 3-retry backoff 1s/5s/30s, prune `backup_dir` to last `backup_retention` archives, emit audit events
- [ ] a failing channel does not block delivery to other channels
- [ ] write tests using `TriggerOnce` as the timing bypass: manual trigger fires the backup, stub channels record delivery, a deliberately-failing stub gets retried 3 times with the right backoff (use a fake clock for the backoff intervals OR assert call count with a pass-through stub)
- [ ] write test: retention prunes old archives
- [ ] write test: disabled channel is skipped on each fire even if it was enabled at Start time
- [ ] write test: Reload swaps the schedule after a config change
- [ ] run `go test ./internal/backup/ -timeout 30s`

### Task 6a: CLI backup commands

**Files:**
- Create: `cmd/sluice/backup.go` (partial — backup subcommands only)
- Create: `cmd/sluice/backup_test.go` (partial)
- Modify: `cmd/sluice/main.go` (add `case "backup"`)

- [ ] add `sluice backup [--out] [--db]`
- [ ] add `sluice backup config set-cron "<expr>"`, `set-retention <n>`, `set-dir <path>`, `show`
- [ ] add `sluice backup list`
- [ ] every `fs.Parse` call wrapped with `reorderFlagsBeforePositional` (v0.8.1 rule)
- [ ] wire `case "backup"` in main.go
- [ ] write tests for each subcommand, including a positional-before-flags test per remove/destructive subcommand
- [ ] run `go test ./cmd/sluice/ -timeout 30s`

### Task 6b: CLI restore command

**Files:**
- Modify: `cmd/sluice/backup.go` (add restore handler)
- Modify: `cmd/sluice/backup_test.go`
- Modify: `cmd/sluice/main.go` (add `case "restore"`)

- [ ] add `sluice restore <archive> [--yes] [--force] [--db]`
- [ ] add `sluice restore --resolve` for post-crash cleanup
- [ ] interactive `y/N` prompt when `--yes` is absent (use `stdin.Scan` unless a mockable reader is already in place)
- [ ] every `fs.Parse` call wrapped with `reorderFlagsBeforePositional`
- [ ] write tests: restore refuses without --yes, proceeds with --yes against a builder archive, --resolve completes a simulated partial swap
- [ ] run `go test ./cmd/sluice/ -timeout 30s`

### Task 7: REST API backup endpoints

**Files:**
- Modify: `api/openapi.yaml`
- Modify: `internal/api/server.go`
- Modify: `internal/api/api.gen.go` (regenerate via `go generate ./internal/api/`)
- Modify: `internal/api/server_test.go`

- [ ] add the new endpoints to the OpenAPI spec with request/response schemas: `POST /api/backup`, `GET /api/backup`, `GET /api/backup/{name}`, `GET /api/backup/{name}/download`, `GET/PUT /api/backup/config`, `POST /api/restore/preview`, `POST /api/restore`
- [ ] run `go generate ./internal/api/` and commit the regenerated file
- [ ] implement each handler. `POST /api/backup` acquires `s.reloadMu` for the snapshot phase only, writes the archive to `backup_dir`, returns 202 with the manifest + archive sha256
- [ ] `GET /api/backup/{name}/download` streams the archive bytes with `Content-Type: application/gzip`
- [ ] `POST /api/restore/preview` parses multipart, writes the archive to a process-local staging dir, returns `{"confirm_token": "<uuid>", "manifest": ..., "archive_sha256": ...}` with a 60s TTL stored in memory
- [ ] `POST /api/restore` consumes the confirm_token, refuses with 410 if expired, performs the swap via `backup.Restore`
- [ ] error classification: validation -> 400, in-progress -> 409 `ErrBackupInProgress`, schema mismatch -> 409, confirm token expired -> 410, internal -> 500
- [ ] write handler tests for each endpoint (success + error cases + concurrent `POST /api/backup` getting 409)
- [ ] run `go test ./internal/api/ -timeout 30s`

### Task 8a: Telegram CommandResult refactor

**Files:**
- Modify: `internal/telegram/commands.go` (change Handle return type)
- Modify: `internal/telegram/commands_test.go` (update all existing assertions)
- Modify: any caller of `Handle` (the message loop in `internal/telegram/bot.go` or wherever `.Handle(cmd)` is invoked)

- [ ] define `CommandResult` with `Text`, `Attachment *CommandAttachment`, `Callback *InlineKeyboard`
- [ ] change `CommandHandler.Handle(cmd) string` to `CommandHandler.Handle(cmd) CommandResult`
- [ ] update every existing handler (`handleStart`, `handlePolicy`, `handleCred`, `handleStatus`, `handleAudit`, `handleHelp`) to wrap their string result in `CommandResult{Text: ...}`
- [ ] update the message loop to route text, attachments, and callbacks
- [ ] update existing command tests to assert `.Text` field instead of the bare string
- [ ] run `go test ./internal/telegram/ -timeout 30s` — must pass before adding backup commands in Task 8b

### Task 8b: Telegram backup and restore commands

**Files:**
- Modify: `internal/telegram/commands.go` (new handlers)
- Modify: `internal/telegram/commands_test.go`
- Modify: `internal/telegram/approval.go` (update `registerCommands` / `handleCallback`)

- [ ] add `backup`, `backup_config`, `backup_set_cron`, `restore` cases to `Handle`
- [ ] `/backup` calls Builder and returns `CommandResult{Attachment: ...}` so the message loop delivers the archive via `NotifyAttachment`
- [ ] `/restore <archive>` returns `CommandResult{Text: summary, Callback: confirmButton}`; the callback handler in `approval.go` executes `backup.Restore` on confirm
- [ ] update `registerCommands` in `approval.go:215` to include `backup`, `backup_config`, `restore` in the bot's `/`-menu
- [ ] all gated by the existing `IsAuthorizedChat` check
- [ ] write tests using the existing command-handler test harness (fake bot transport) covering the attachment path, the callback round-trip, and the over-50MB fallback
- [ ] run `go test ./internal/telegram/ -timeout 30s`

### Task 9: Wire scheduler into main.go

**Files:**
- Modify: `cmd/sluice/main.go`

- [ ] instantiate `backup.Builder` (with `srv.ReloadMu()`) and `backup.Scheduler` after the proxy starts
- [ ] call `backupSched.Start(ctx)` alongside the existing background tasks
- [ ] add `backupSched.Reload()` call to the `reloadAll` closure so CLI-driven config changes take effect immediately via the db watcher
- [ ] call `backupSched.Stop()` from the shutdown path
- [ ] write a smoke test that verifies `Start` was called (or at minimum a `go build ./cmd/sluice/` compiles the new wiring)
- [ ] run `go build ./... && go test ./cmd/sluice/ -timeout 30s`

### Task 10: Verify acceptance criteria

- [ ] verify `sluice backup` produces a valid `tar.gz` and a temp store built from it has identical `ListRules` / `ListBindings` / `ListCredentialMeta` / `ListMCPUpstreams` / `ListChannels` output
- [ ] verify `sluice backup config set-cron "*/5 * * * *"` schedules the job and `TriggerOnce` delivers to a stub channel
- [ ] verify `sluice restore <archive> --yes` against a freshly-built archive restores state so that `sluice policy list` / `binding list` / `cred list` outputs match pre-backup snapshot byte-for-byte
- [ ] verify `sluice restore --resolve` recovers from a simulated partial swap (rename aside, interrupt before rename into place)
- [ ] verify REST API: success cases, 409 ErrBackupInProgress, 410 expired confirm_token, 400 on bad manifest, schema mismatch 409
- [ ] verify Telegram `/backup` delivers the archive as a document (under 50 MB) and falls back to text for oversized archives
- [ ] verify non-age vault providers produce DB-only archives cleanly (no error, audit note present)
- [ ] run full test suite: `go test ./... -v -timeout 120s`
- [ ] run `gofumpt -l cmd/sluice/ internal/` (must be empty)
- [ ] run `golangci-lint run ./...` (must be 0 issues)
- [ ] run tests — must pass before Task 11

### Task 11: [Final] Update documentation

- [ ] update `CLAUDE.md` CLI subcommands with `sluice backup` and `sluice restore`
- [ ] add a "Backup and restore" section to `CLAUDE.md` describing archive format, restore safety semantics, and the `.pre-restore-<ts>` recovery procedure
- [ ] document the HTTP webhook multipart backup payload (fields + `X-Sluice-Signature` header format) in `docs/webhooks.md`, creating the file if it does not exist
- [ ] move this plan to `docs/plans/completed/`

## Post-Completion

**Manual verification on the knuth deployment:**
- Configure `backup_cron` via `sluice backup config set-cron "*/30 * * * *"` and observe the archive land in the backup dir on the next tick
- Deliver one scheduled archive to the live Telegram chat, verify the file opens and the manifest is readable
- Take a full backup, stop sluice, pretend to lose the DB by moving `data/sluice.db` aside, run `sluice restore <archive> --yes`, start sluice, verify the proxy comes back with the same policies and credentials
- Stress test: send 5 concurrent `POST /api/backup` requests, assert exactly one succeeds and the rest return 409 `ErrBackupInProgress`
- Channel-failure stress: break the HTTP webhook URL, trigger a manual backup, assert Telegram still receives the archive and audit log records the webhook failure with retry counts
- Oversized-archive test: `truncate` a large fake archive to 60 MB, trigger the Telegram delivery path, verify the text fallback fires

**External system updates:**
- If any downstream tooling consumes the webhook body, update its parser to handle the new multipart backup payload distinct from approval payloads (inspect `Content-Type`)
- Document the archive retention trade-off for operators choosing between small `backup_retention` (low disk, fewer recovery points) and large (more disk, more redundancy)
