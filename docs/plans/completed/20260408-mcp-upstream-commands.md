# MCP Upstream CRUD Commands

## Overview

Add MCP upstream management to the Telegram bot and verify full coverage across all interfaces (CLI, HTTP API, Telegram). Currently:

| Operation | CLI | HTTP API | Telegram |
|-----------|-----|----------|----------|
| List | `sluice mcp list` | `GET /api/mcp/upstreams` | missing |
| Add | `sluice mcp add` | `POST /api/mcp/upstreams` | missing |
| Remove | `sluice mcp remove` | `DELETE /api/mcp/upstreams/{name}` | missing |

After this plan, Telegram will have `/mcp list`, `/mcp add`, and `/mcp remove`.

## Context

- Telegram commands: `internal/telegram/commands.go` (CommandHandler, Handle dispatch)
- HTTP API: `internal/api/server.go` (MCP upstream handlers)
- API spec: `internal/api/api.gen.go` (generated from OpenAPI)
- CLI: `cmd/sluice/mcp.go` (mcp subcommand)
- MCP store: `internal/store/store.go` (AddMCPUpstream, ListMCPUpstreams, RemoveMCPUpstream)
- MCP gateway: `internal/mcp/gateway.go` (upstream lifecycle)
- Auto-injection: `cmd/sluice/main.go` (MCP config write to shared volume)

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- CRITICAL: every task MUST include new/updated tests
- CRITICAL: all tests must pass before starting next task

## Testing Strategy

- Unit tests for dispatch and subcommand parsing: `internal/telegram/commands_test.go`
- Unit tests for nil-store guard behavior: `internal/telegram/commands_test.go`
- Unit tests for MCP re-injection trigger: `internal/telegram/commands_test.go`
- Existing store and API tests cover persistence layer

## Progress Tracking

- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with + prefix

## Implementation Steps

### Task 1: Add /mcp dispatch and /mcp list

**Files:**
- Modify: `internal/telegram/commands.go`
- Test: `internal/telegram/commands_test.go`

- [x] Add `case "mcp"` to Handle() dispatch
- [x] Add nil-store guard (check `h.store != nil` like handleCred does)
- [x] Implement `handleMCP(args)` with subcommand routing: list, add, remove
- [x] `/mcp list` - list registered upstreams with name, transport, command
- [x] Format list output for Telegram readability (not JSON)
- [x] Write tests for dispatch, nil-store guard, and list subcommand
- [x] Run tests - must pass before next task

### Task 2: Add /mcp add with flag parsing

**Files:**
- Modify: `internal/telegram/commands.go`
- Test: `internal/telegram/commands_test.go`

- [x] `/mcp add <name> --command <cmd>` - add stdio upstream (parse flags from args)
- [x] `/mcp add <name> --command <url> --transport http` - add HTTP/WebSocket upstream (use `--command` for URLs, matching CLI convention)
- [x] Support optional flags: `--transport`, `--args`, `--env`, `--timeout`
- [x] Note: `--env` flag may contain secrets. Delete the Telegram message after processing (same treatment as `/cred add`)
- [x] Write tests for add subcommand with various flag combinations
- [x] Run tests - must pass before next task

### Task 3: Add /mcp remove with auto-injection

**Files:**
- Modify: `internal/telegram/commands.go`
- Test: `internal/telegram/commands_test.go`

- [x] `/mcp remove <name>` - remove upstream by name
- [x] Re-injection via `WireMCPGateway` was implemented and then removed during iter-1 code review. Sluice multiplexes every upstream behind a single agent-side entry (`mcp.servers.sluice = {url: http://sluice:3000/mcp}`) which is wired once at sluice startup and never changes on mutation. Re-calling `WireMCPGateway("sluice", url)` after /mcp add would not surface the new upstream to the agent (the gateway reads the upstream set from SQLite at startup) but would trigger an agent gateway restart. The agreed UX is: store mutation succeeds, response instructs the operator to restart sluice, no container-side RPC is issued on /mcp add or /mcp remove.
- [x] Write tests for remove subcommand and regression guards that `WireMCPGateway` is NOT called on /mcp add or /mcp remove (see `TestHandleMCPAddDoesNotCallContainerManager` and `TestHandleMCPRemoveDoesNotCallContainerManager`).
- [x] Run tests - must pass before next task

### Task 4: Add /mcp to Telegram command menu

**Files:**
- Modify: `internal/telegram/approval.go`
- Test: `internal/telegram/approval_test.go`

- [x] Add `{Command: "mcp", Description: "Manage MCP upstreams"}` to registerCommands
- [x] Update help output to include MCP section
- [x] Write tests for updated help and command registration
- [x] Run tests - must pass before next task

### Task 5: Verify acceptance criteria

- [x] Verify `/mcp list` in Telegram shows upstreams (verified via unit tests: `TestHandleMCPListEmpty`, `TestHandleMCPListWithUpstreams`, `TestHandleMCPListEscapesHTML`, `TestHandleMessageMCPListNotDeleted`)
- [x] Verify `/mcp add` creates upstream (verified via unit tests: `TestHandleMCPAddStdio`, `TestHandleMCPAddWithArgsAndEnv`, `TestHandleMCPAddHTTPTransport`, `TestHandleMCPAddWebSocketTransport`, `TestHandleMCPAddDoesNotCallContainerManager`, `TestHandleMessageMCPAddDeletesMessage`)
- [x] Verify `/mcp remove` removes upstream (verified via unit tests: `TestHandleMCPRemove`, `TestHandleMCPRemoveNotFound`, `TestHandleMCPRemoveStrayPositional`, `TestHandleMCPRemoveDoesNotCallContainerManager`)
- [x] Run full test suite: `go test ./... -v -timeout 30s` -- all 2389 tests passing across 12 packages

### Task 6: [Final] Update documentation

- [x] Update CLAUDE.md: iter 2 added `--header "K=V"` to the documented `sluice mcp add` flag list (CLI Subcommands section) and expanded the MCP Gateway Setup section to cover all three management surfaces (CLI, REST, Telegram) plus the `mcp.servers.sluice={url}` wiring and the sluice-restart requirement for upstream mutations.
- [x] Move this plan to `docs/plans/completed/`

## Post-Completion

**Manual verification:**
- Deploy to a live sluice stack
- Add an MCP upstream via Telegram: `/mcp add test-server --command "echo hello"`
- Verify it appears in `/mcp list`
- Restart sluice (the gateway builds its upstream set at startup)
- Re-run an agent session and confirm the new tools are exposed under the `test-server__*` namespace
- Remove it: `/mcp remove test-server`, restart sluice, confirm the tools are gone

**Future work:**
- Update/edit support for MCP upstreams (CLI, API, Telegram). Users can remove+add for now.
