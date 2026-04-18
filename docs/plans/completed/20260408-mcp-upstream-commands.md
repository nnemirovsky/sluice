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
- [x] After add/remove: trigger MCP config re-injection into agent container. Added `mcpURL` field to `CommandHandler` with `SetMCPURL` setter and `MCPURL` in `ChannelConfig`. The `reinjectMCPConfig` helper calls `ContainerManager.WireMCPGateway(ctx, "sluice", mcpURL)` after both `/mcp add` and `/mcp remove` successes. Wired from `cmd/sluice/main.go` via `deriveMCPBaseURL(*mcpBaseURL, *healthAddr)`. (Plan referenced an older `mcpDir`/`mcp-servers.json` write path; current code uses `WireMCPGateway` WebSocket RPC instead.)
- [x] Write tests for remove subcommand and re-injection trigger
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
- [x] Verify `/mcp add` creates upstream and triggers auto-injection (verified via unit tests: `TestHandleMCPAddStdio`, `TestHandleMCPAddWithArgsAndEnv`, `TestHandleMCPAddHTTPTransport`, `TestHandleMCPAddWebSocketTransport`, `TestHandleMCPAddTriggersReinjection`, `TestHandleMessageMCPAddDeletesMessage`)
- [x] Verify `/mcp remove` removes upstream (verified via unit tests: `TestHandleMCPRemove`, `TestHandleMCPRemoveNotFound`, `TestHandleMCPRemoveStrayPositional`, `TestHandleMCPRemoveTriggersReinjection`)
- [x] Run full test suite: `go test ./... -v -timeout 30s` -- all 2389 tests passing across 12 packages

### Task 6: [Final] Update documentation

- [x] Update CLAUDE.md CLI subcommands section if needed (no update needed: CLAUDE.md has no Telegram commands listing section, and the CLI subcommands section already documents `sluice mcp add/list/remove`)
- [x] Move this plan to `docs/plans/completed/`

## Post-Completion

**Manual verification:**
- Deploy to knuth
- Add an MCP upstream via Telegram: `/mcp add test-server --command "echo hello"`
- Verify it appears in `/mcp list`
- Verify `mcp-servers.json` is written to shared volume
- Verify OpenClaw discovers the new MCP server
- Remove it: `/mcp remove test-server`

**Future work:**
- Update/edit support for MCP upstreams (CLI, API, Telegram). Users can remove+add for now.
