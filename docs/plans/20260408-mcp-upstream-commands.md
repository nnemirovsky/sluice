# MCP Upstream CRUD Commands

## Overview

Add MCP upstream management to the Telegram bot and verify full CRUD coverage across all interfaces (CLI, HTTP API, Telegram). Currently:

| Operation | CLI | HTTP API | Telegram |
|-----------|-----|----------|----------|
| List | `sluice mcp list` | `GET /api/mcp/upstreams` | missing |
| Add | `sluice mcp add` | `POST /api/mcp/upstreams` | missing |
| Remove | `sluice mcp remove` | `DELETE /api/mcp/upstreams/{name}` | missing |
| Update | missing | missing | missing |

After this plan, Telegram will have `/mcp list`, `/mcp add`, `/mcp remove`, and an update command will be available across all interfaces.

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

- Unit tests for new Telegram command handlers
- Existing store and API tests cover persistence layer

## Progress Tracking

- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with + prefix

## Implementation Steps

### Task 1: Add /mcp commands to Telegram bot

**Files:**
- Modify: `internal/telegram/commands.go`

- [ ] Add `case "mcp"` to Handle() dispatch
- [ ] Implement `handleMCP(args)` with subcommands: list, add, remove
- [ ] `/mcp list` - list registered upstreams with name, transport, command/URL
- [ ] `/mcp add <name> --command <cmd>` - add stdio upstream (parse flags from args)
- [ ] `/mcp add <name> --url <url>` - add HTTP/WebSocket upstream
- [ ] `/mcp remove <name>` - remove upstream by name
- [ ] After add/remove: trigger MCP config re-injection into agent container
- [ ] Format list output for Telegram readability (not JSON)
- [ ] Write tests for each subcommand
- [ ] Run tests

### Task 2: Add /mcp to Telegram command menu

**Files:**
- Modify: `internal/telegram/approval.go`

- [ ] Add `{Command: "mcp", Description: "Manage MCP upstreams"}` to registerCommands
- [ ] Update help output to include MCP section
- [ ] Write tests for updated help
- [ ] Run tests

### Task 3: Add update/edit support to CLI and store

**Files:**
- Modify: `internal/store/store.go`
- Modify: `cmd/sluice/mcp.go`

- [ ] Add `UpdateMCPUpstream(name, opts)` to store (update command, transport, args, env, timeout)
- [ ] Add `sluice mcp update <name> [--command <cmd>] [--timeout N]` CLI subcommand
- [ ] Write tests for store update
- [ ] Write tests for CLI update
- [ ] Run tests

### Task 4: Add update endpoint to HTTP API

**Files:**
- Modify: `internal/api/server.go`
- Modify: `api/openapi.yaml` (if exists)

- [ ] Add `PATCH /api/mcp/upstreams/{name}` handler
- [ ] Accept partial update (only fields provided are changed)
- [ ] Write tests for PATCH endpoint
- [ ] Run tests

### Task 5: Verify acceptance criteria

- [ ] Verify `/mcp list` in Telegram shows upstreams
- [ ] Verify `/mcp add` creates upstream and triggers auto-injection
- [ ] Verify `/mcp remove` removes upstream
- [ ] Verify CLI `sluice mcp update` works
- [ ] Verify API `PATCH /api/mcp/upstreams/{name}` works
- [ ] Run full test suite: `go test ./... -v -timeout 30s`

### Task 6: [Final] Update documentation

- [ ] Update CLAUDE.md CLI subcommands section with mcp update
- [ ] Update help command output
- [ ] Move this plan to `docs/plans/completed/`

## Post-Completion

**Manual verification:**
- Deploy to knuth
- Add an MCP upstream via Telegram: `/mcp add test-server --command "echo hello"`
- Verify it appears in `/mcp list`
- Verify `mcp-servers.json` is written to shared volume
- Verify OpenClaw discovers the new MCP server
- Remove it: `/mcp remove test-server`
