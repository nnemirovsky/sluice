# Plan 14: MCP Multi-Transport and Auto-Injection

## Overview

Add Streamable HTTP and WebSocket transports to the MCP gateway (currently stdio only). Add the ability for sluice to auto-inject itself as an MCP server into the OpenClaw container, so the operator doesn't need to manually configure OpenClaw to use sluice's gateway.

**Problem:** The MCP gateway only supports stdio transport (child processes). Remote MCP servers that expose Streamable HTTP or WebSocket endpoints cannot be used as upstreams. Additionally, setting up OpenClaw to use sluice as its MCP gateway requires manual configuration inside the OpenClaw container.

**Solution:** Add Streamable HTTP client (for connecting to remote MCP servers as upstreams) and WebSocket client support. Add an MCP server mode that exposes sluice's aggregated tools via Streamable HTTP (so OpenClaw can connect to sluice over HTTP instead of stdio). Add auto-injection that writes sluice's MCP config into OpenClaw's config via Docker exec or shared volume.

**Depends on:** Plan 9 (unified store for MCP upstreams). Plan 10 (HTTP server on port 3000).

## Context

**Current MCP architecture:**
```
OpenClaw -> stdio -> sluice MCP gateway -> stdio -> upstream MCP servers
```

**Target architecture:**
```
OpenClaw -> Streamable HTTP -> sluice MCP gateway -> stdio (local servers)
                                                  -> Streamable HTTP (remote servers)
                                                  -> WebSocket (real-time servers)
```

**Auto-injection:** On startup or credential change, sluice writes its MCP config to OpenClaw's `openclaw.json` (or equivalent) and triggers a reload. OpenClaw sees sluice as just another MCP server.

**Files that will change:**
- `internal/mcp/upstream.go` -- add HTTP and WebSocket upstream types
- `internal/mcp/transport.go` -- currently stdio only, add HTTP and WS transports
- `internal/mcp/gateway.go` -- serve tools via Streamable HTTP
- `internal/mcp/types.go` -- UpstreamConfig transport field
- `internal/docker/manager.go` -- auto-inject MCP config
- `cmd/sluice/main.go` -- expose MCP gateway on HTTP

**New dependencies:**
- `github.com/coder/websocket` (WebSocket client, pure Go, modern)
- Or use `mark3labs/mcp-go` for MCP transport abstractions if mature enough

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- All tests must pass before starting next task

## Testing Strategy

- **Unit tests**: Transport connection, message parsing, session management.
- **Integration tests**: Connect to mock Streamable HTTP and WebSocket MCP servers.

## Implementation Steps

### Task 1: Add transport field to upstream config

Allow upstreams to specify their transport type. Default remains stdio for backward compatibility.

**Files:**
- Modify: `internal/mcp/types.go`
- Modify: `internal/store/store.go` (add transport column to mcp_upstreams)
- Create migration: `internal/store/migrations/000003_upstream_transport.up.sql`

**Transport types:**
```go
const (
    TransportStdio    = "stdio"      // child process (current)
    TransportHTTP     = "http"       // Streamable HTTP client
    TransportWS       = "websocket"  // WebSocket client
)
```

- [ ] Add `transport` column to `mcp_upstreams` table (default "stdio") via migration 000003
- [ ] Add `Transport string` field to `UpstreamConfig` and `MCPUpstreamRow`
- [ ] Update `AddMCPUpstream`, `ListMCPUpstreams` for new column
- [ ] Update TOML import to parse `transport` field from `[[mcp_upstream]]`
- [ ] Update `sluice mcp add` CLI to accept `--transport stdio|http|websocket` (default stdio)
- [ ] Write tests for transport field CRUD
- [ ] Run tests: `go test ./internal/store/ -v -timeout 30s`

### Task 2: Streamable HTTP upstream client

Connect to remote MCP servers via Streamable HTTP (POST to single endpoint, `Mcp-Session-Id` header for session management).

**Files:**
- Create: `internal/mcp/transport_http.go`
- Create: `internal/mcp/transport_http_test.go`

- [ ] Implement `HTTPUpstream` struct that satisfies the same interface as `Upstream` (SendRequest, Initialize, DiscoverTools, Stop)
- [ ] On `Initialize`: POST `initialize` JSON-RPC to the upstream URL, read `Mcp-Session-Id` from response header, store for subsequent requests
- [ ] On `SendRequest`: POST JSON-RPC with `Mcp-Session-Id` header, read response
- [ ] Handle SSE streaming responses (for long-running tool calls that stream progress)
- [ ] Support `DELETE` request to close session on `Stop`
- [ ] Configurable timeout per-upstream (from `timeout_sec`)
- [ ] Write tests with httptest mock MCP server
- [ ] Write tests for session ID management
- [ ] Write tests for streaming response handling
- [ ] Run tests: `go test ./internal/mcp/ -v -timeout 30s`

### Task 3: WebSocket upstream client

Connect to remote MCP servers via WebSocket (`mcp` subprotocol).

**Files:**
- Create: `internal/mcp/transport_ws.go`
- Create: `internal/mcp/transport_ws_test.go`

- [ ] Add `github.com/coder/websocket` dependency
- [ ] Implement `WSUpstream` struct satisfying the same interface as `Upstream`
- [ ] On `Initialize`: WebSocket dial with `Sec-WebSocket-Protocol: mcp`, send `initialize` JSON-RPC, read response
- [ ] On `SendRequest`: write JSON-RPC text frame, read response frame
- [ ] Handle bidirectional communication (server-initiated notifications)
- [ ] Support session ID via subprotocol (`mcp.session-id.<ID>`) or query parameter
- [ ] Write tests with mock WebSocket MCP server
- [ ] Write tests for reconnection on connection drop
- [ ] Run tests: `go test ./internal/mcp/ -v -timeout 30s`

### Task 4: Wire transports into gateway startup

Route upstream creation to the correct transport based on config.

**Files:**
- Modify: `internal/mcp/gateway.go`
- Modify: `internal/mcp/gateway_test.go`

- [ ] In `NewGateway`: check `UpstreamConfig.Transport` and instantiate `Upstream` (stdio), `HTTPUpstream`, or `WSUpstream`
- [ ] All three satisfy the same interface: `Initialize`, `DiscoverTools`, `SendRequest`, `Stop`
- [ ] Mixed upstreams work: some stdio (local), some HTTP (remote), some WebSocket (real-time)
- [ ] Write test with mixed upstream types
- [ ] Run tests: `go test ./internal/mcp/ -v -timeout 30s`

### Task 5: Expose gateway via Streamable HTTP server

Allow OpenClaw (or any MCP client) to connect to sluice's gateway via HTTP instead of stdio. This runs on the existing port 3000 alongside `/healthz` and `/api/*`.

**Files:**
- Create: `internal/mcp/server_http.go`
- Create: `internal/mcp/server_http_test.go`
- Modify: `cmd/sluice/main.go` (mount MCP HTTP handler)

- [ ] Implement `MCPHTTPHandler` that serves `POST /mcp` endpoint following the Streamable HTTP spec
- [ ] Generate `Mcp-Session-Id` on `initialize` request, track sessions
- [ ] Route `tools/list` and `tools/call` through the existing `Gateway.HandleToolCall` (same policy enforcement, audit, approval flow)
- [ ] Support SSE streaming for long-running tool calls
- [ ] Support `DELETE /mcp` to close session
- [ ] Mount on the HTTP server at `/mcp` (only when MCP gateway mode is active)
- [ ] Write tests with httptest verifying full MCP handshake + tool call
- [ ] Run tests: `go test ./internal/mcp/ -v -timeout 30s`

### Task 6: Auto-inject sluice as MCP server into OpenClaw

On startup (and after MCP upstream changes), automatically configure OpenClaw to use sluice as its MCP gateway.

**Files:**
- Modify: `internal/docker/manager.go`
- Create: `internal/docker/mcp_inject.go`
- Modify: `internal/docker/manager_test.go`

**Injection approach:** Write sluice's MCP config to a shared volume file that OpenClaw reads, then trigger OpenClaw to reload.

```json
// /phantoms/mcp-servers.json (shared volume)
{
  "sluice": {
    "url": "http://localhost:3000/mcp",
    "transport": "streamable-http"
  }
}
```

- [ ] Implement `InjectMCPConfig(ctx, phantomDir, sluiceURL string) error` that writes `mcp-servers.json` to the shared phantoms volume
- [ ] Call `docker exec openclaw openclaw mcp reload` (or equivalent) to trigger OpenClaw to re-read MCP config
- [ ] If exec fails, fall back to writing config and restarting the container
- [ ] Call `InjectMCPConfig` on sluice startup (after gateway is ready) and after `sluice mcp add/remove`
- [ ] Add `--auto-inject-mcp` flag (default true in Docker, false otherwise) to control this behavior
- [ ] Write tests for config file generation
- [ ] Write tests for injection flow (mock Docker API)
- [ ] Run tests: `go test ./internal/docker/ -v -timeout 30s`

### Task 7: Verify acceptance criteria

- [ ] Verify stdio upstreams still work (no regression)
- [ ] Verify Streamable HTTP upstream connects to a remote MCP server
- [ ] Verify WebSocket upstream connects to a WebSocket MCP server
- [ ] Verify mixed upstream types in one gateway (stdio + HTTP + WebSocket)
- [ ] Verify `/mcp` endpoint serves tools to an MCP client over Streamable HTTP
- [ ] Verify OpenClaw auto-injection writes correct config and OpenClaw picks it up
- [ ] Verify policy enforcement applies equally across all transports
- [ ] Verify `sluice mcp add <name> --transport http --command https://remote-server/mcp` works
- [ ] Run full test suite: `go test ./... -v -timeout 60s -race`
- [ ] Run linter: `go vet ./...`

### Task 8: [Final] Update documentation

- [ ] Update CLAUDE.md: document MCP transport types (stdio, http, websocket)
- [ ] Update CLAUDE.md: document `/mcp` Streamable HTTP server endpoint
- [ ] Update CLAUDE.md: document auto-injection into OpenClaw
- [ ] Update examples/config.toml: add remote MCP upstream examples with transport field
- [ ] Update compose.yml: document auto-injection behavior

## Technical Details

### Streamable HTTP MCP flow (client side, upstream)

```
POST https://remote-server/mcp
Content-Type: application/json

{"jsonrpc": "2.0", "method": "initialize", "params": {...}, "id": 1}

Response:
Mcp-Session-Id: abc123
{"jsonrpc": "2.0", "result": {"capabilities": {...}}, "id": 1}

Subsequent requests include:
Mcp-Session-Id: abc123
```

### Streamable HTTP MCP flow (server side, sluice)

```
POST /mcp  (from OpenClaw)
{"jsonrpc": "2.0", "method": "tools/list", "id": 2}

Response:
Mcp-Session-Id: <generated>
{"jsonrpc": "2.0", "result": {"tools": [...]}, "id": 2}
```

### Auto-injection sequence

```
1. Sluice starts, MCP gateway initializes
2. Gateway discovers tools from all upstreams
3. Sluice writes /phantoms/mcp-servers.json with its own URL
4. Sluice runs: docker exec openclaw openclaw mcp reload
5. OpenClaw reads mcp-servers.json, connects to sluice:3000/mcp
6. OpenClaw sees all upstream tools (namespaced) through sluice
7. All tool calls go through sluice's policy engine
```

### TOML config for remote upstreams

```toml
# Local stdio upstream (existing)
[[mcp_upstream]]
name = "filesystem"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"]

# Remote Streamable HTTP upstream (new)
[[mcp_upstream]]
name = "github"
transport = "http"
command = "https://mcp.github.com/v1"
timeout_sec = 60

# Remote WebSocket upstream (new)
[[mcp_upstream]]
name = "realtime-data"
transport = "websocket"
command = "wss://mcp.example.com/ws"
timeout_sec = 30
```

For HTTP/WebSocket upstreams, `command` holds the URL instead of a binary path. `args` and `env` are unused.

## Post-Completion

**Manual verification:**
- Test with a real remote MCP server (e.g., GitHub MCP server if available)
- Test auto-injection with a real OpenClaw container
- Verify tool discovery works across mixed transports

**Future considerations:**
- MCP server mode over WebSocket (in addition to Streamable HTTP)
- Legacy SSE support for older MCP servers
- mTLS for authenticated MCP connections
