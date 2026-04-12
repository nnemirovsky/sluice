# Default Verdict CLI and Telegram Commands

## Overview

Add the ability to view and set the default policy verdict from the CLI and Telegram bot. The REST API already supports this via `GET/PATCH /api/config`. The CLI and Telegram are missing dedicated commands, and the policy listing does not display the current default.

## Context

- Store: `internal/store/store.go` (GetConfig, UpdateConfig with DefaultVerdict field)
- Policy engine: `internal/policy/engine_store.go` (loads default from store)
- API: `internal/api/server.go` (GET/PATCH /api/config already works)
- CLI: `cmd/sluice/policy.go` (list/add/remove/import/export subcommands)
- Telegram: `internal/telegram/commands.go` (/policy show/allow/deny/remove)
- Default is stored in `config` table singleton, validated to allow/deny/ask
- Existing Telegram handlers use `recompileAndSwap()` under `reloadMu` for engine updates (not SIGHUP)
- `/policy show` already displays default in header text as "Current policy (default: X)". Replace with `[default]` row for consistency with CLI.

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- CRITICAL: every task MUST include new/updated tests
- CRITICAL: all tests must pass before starting next task
- Uses gofumpt for Go formatting

## Testing Strategy

- **Unit tests**: test CLI command output and store interaction (success + error cases)
- **Unit tests**: test Telegram command handler for /policy default (success + error cases)

## Solution Overview

Four changes that share the same store API (GetConfig/UpdateConfig):

1. **CLI `sluice policy default [allow|deny|ask]`**: no args shows current default, with arg sets it. Requires `--db` flag like other policy commands.
2. **CLI `sluice policy list`**: display default verdict as first row `[default] <verdict>`.
3. **Telegram `/policy default [allow|deny|ask]`**: no args shows current, with arg sets it. Recompiles engine inline via `recompileAndSwap()` under `reloadMu`.
4. **Telegram `/policy show`**: replace header "Current policy (default: X)" with `[default] <verdict>` as first row for consistency with CLI.

After setting the default via CLI, the running sluice process needs a SIGHUP to reload (same as `policy add`/`remove`). After setting via Telegram or API, the engine is recompiled inline.

## Implementation Steps

### Task 1: Add `sluice policy default` CLI command

**Files:**
- Modify: `cmd/sluice/policy.go`
- Modify: `cmd/sluice/policy_test.go`

- [ ] Add `policyDefaultCmd` subcommand under `policyCmd` with `--db` flag
- [ ] No args: read store via `GetConfig`, print current default verdict
- [ ] With arg: validate against allow/deny/ask (same pattern as `handlePolicyAdd`), call `store.UpdateConfig`, print confirmation
- [ ] Update usage string in `handlePolicyCommand` to include `default`
- [ ] Write tests: get current default, set valid default, reject invalid default
- [ ] Run tests

### Task 2: Show default verdict in `sluice policy list` output

**Files:**
- Modify: `cmd/sluice/policy.go`
- Modify: `cmd/sluice/policy_test.go`

- [ ] In `policyListCmd` handler, read config and prepend default verdict as first row: `[default] <verdict>`
- [ ] Show before numbered rules. When no rules exist, still show default row (skip "no rules found" message since default is always present)
- [ ] Write test for list output including default row
- [ ] Run tests

### Task 3: Add `/policy default` Telegram command

**Files:**
- Modify: `internal/telegram/commands.go`
- Modify: `internal/telegram/commands_test.go`

- [ ] Add `default` case to the `/policy` command dispatcher
- [ ] No args: read config from store via `GetConfig`, reply with current default
- [ ] With arg: validate against allow/deny/ask, call `store.UpdateConfig` under `reloadMu`, then `recompileAndSwap()`, reply with confirmation
- [ ] Update usage string in `handlePolicy` and help text in `handleHelp` to include `default`
- [ ] Write tests: get default, set valid default, reject invalid default, store-not-configured fallback
- [ ] Run tests

### Task 4: Show default verdict in `/policy show` Telegram output

**Files:**
- Modify: `internal/telegram/commands.go`
- Modify: `internal/telegram/commands_test.go`

- [ ] In `policyShowFromStore`, replace header "Current policy (default: X)" with `[default] <verdict>` as first row before numbered rules
- [ ] Apply same change to engine-backed `policyShow` fallback
- [ ] Write test for show output with default row
- [ ] Run tests

### Task 5: Verify acceptance criteria

- [ ] `sluice policy default` shows current default
- [ ] `sluice policy default ask` sets default to ask
- [ ] `sluice policy default invalid` returns error
- [ ] `sluice policy list` shows default as first row
- [ ] Telegram `/policy default` shows current default
- [ ] Telegram `/policy default deny` sets and confirms
- [ ] Telegram `/policy show` shows default as first row
- [ ] `sluice policy export` still shows default verdict correctly
- [ ] Run full test suite: `go test ./... -v -timeout 30s`

### Task 6: [Final] Update documentation

- [ ] Update CLAUDE.md CLI subcommands section with `sluice policy default`
- [ ] Move this plan to `docs/plans/completed/`

## Post-Completion

**Manual verification:**
- Deploy to knuth and test via Telegram /policy default
- Verify sluice policy list output on the server
