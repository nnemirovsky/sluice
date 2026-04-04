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

- [x] Add `transport` column to `mcp_upstreams` table (default "stdio") via migration 000003
- [x] Add `Transport string` field to `UpstreamConfig` and `MCPUpstreamRow`
- [x] Update `AddMCPUpstream`, `ListMCPUpstreams` for new column
- [x] Update TOML import to parse `transport` field from `[[mcp_upstream]]`
- [x] Update `sluice mcp add` CLI to accept `--transport stdio|http|websocket` (default stdio)
- [x] Write tests for transport field CRUD
- [x] Run tests: `go test ./internal/store/ -v -timeout 30s`

### Task 2: Streamable HTTP upstream client

Connect to remote MCP servers via Streamable HTTP (POST to single endpoint, `Mcp-Session-Id` header for session management).

**Files:**
- Create: `internal/mcp/transport_http.go`
- Create: `internal/mcp/transport_http_test.go`

- [x] Implement `HTTPUpstream` struct that satisfies the same interface as `Upstream` (SendRequest, Initialize, DiscoverTools, Stop)
- [x] On `Initialize`: POST `initialize` JSON-RPC to the upstream URL, read `Mcp-Session-Id` from response header, store for subsequent requests
- [x] On `SendRequest`: POST JSON-RPC with `Mcp-Session-Id` header, read response
- [x] Handle SSE streaming responses (for long-running tool calls that stream progress)
- [x] Support `DELETE` request to close session on `Stop`
- [x] Configurable timeout per-upstream (from `timeout_sec`)
- [x] Write tests with httptest mock MCP server
- [x] Write tests for session ID management
- [x] Write tests for streaming response handling
- [x] Run tests: `go test ./internal/mcp/ -v -timeout 30s`

### Task 3: WebSocket upstream client

Connect to remote MCP servers via WebSocket (`mcp` subprotocol).

**Files:**
- Create: `internal/mcp/transport_ws.go`
- Create: `internal/mcp/transport_ws_test.go`

- [x] Add `github.com/coder/websocket` dependency
- [x] Implement `WSUpstream` struct satisfying the same interface as `Upstream`
- [x] On `Initialize`: WebSocket dial with `Sec-WebSocket-Protocol: mcp`, send `initialize` JSON-RPC, read response
- [x] On `SendRequest`: write JSON-RPC text frame, read response frame
- [x] Handle bidirectional communication (server-initiated notifications)
- [x] Support session ID via subprotocol (`mcp.session-id.<ID>`) or query parameter
- [x] Write tests with mock WebSocket MCP server
- [x] Write tests for reconnection on connection drop
- [x] Run tests: `go test ./internal/mcp/ -v -timeout 30s`

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

### Task 5: MCP upstream credential injection via env vars

Inject real credentials from the vault into MCP upstream child processes as environment variables. The env config in `[[mcp_upstream]]` specifies vault credential names. Sluice resolves them to real values at spawn time. The agent never sees the credentials. MCP tool policy and response redaction prevent credential leakage to the agent.

**Files:**
- Modify: `internal/mcp/upstream.go` (resolve credentials before process spawn)
- Modify: `internal/mcp/gateway.go` (pass vault provider to upstream spawner)
- Modify: `internal/mcp/upstream_test.go`

**Flow:**
```toml
[[mcp_upstream]]
name = "github"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
# [mcp_upstream.env]
# GITHUB_PERSONAL_ACCESS_TOKEN = "vault:github_token"
```

```
Startup:
  1. Read env config: GITHUB_PERSONAL_ACCESS_TOKEN = "vault:github_token"
  2. Resolve "vault:github_token" -> real credential from vault
  3. Set env var on child process: GITHUB_PERSONAL_ACCESS_TOKEN=ghp_real_xxx
  4. Child process (server-github) uses it normally
  5. Agent calls github__create_repo -> tool policy check -> forward to child
  6. Response -> redact rules strip any leaked credentials -> return to agent
```

The `vault:` prefix in env values signals that the value is a vault credential name to resolve. Plain values are passed through as-is.

- [ ] In `StartUpstream`: scan env map for values with `vault:` prefix
- [ ] For each `vault:` value: call `provider.Get(name)`, set the real credential as the env var value
- [ ] Plain env values (no prefix) pass through unchanged
- [ ] Release credential memory after setting env (best-effort, Go copies strings)
- [ ] On credential rotation (vault change): stop and restart the upstream process to pick up new credentials
- [ ] Write test: env value with `vault:` prefix is resolved from mock provider
- [ ] Write test: env value without prefix is passed through unchanged
- [ ] Write test: missing vault credential returns clear error on startup
- [ ] Run tests: `go test ./internal/mcp/ -v -timeout 30s`

### Task 6: Expose gateway via Streamable HTTP server

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

### Task 7: Auto-inject sluice as MCP server into OpenClaw

On startup (and after MCP upstream changes), automatically configure OpenClaw to use sluice as its MCP gateway via Streamable HTTP. No Docker socket needed in the OpenClaw container.

**Approach:** Write sluice's MCP config to the shared phantoms volume. OpenClaw reads it on startup or reload. The connection uses Streamable HTTP (`http://sluice:3000/mcp`), which goes through the Docker internal network. The SOCKS5 proxy auto-bypasses connections to sluice's own address so MCP traffic is not double-checked.

**Files:**
- Create: `internal/docker/mcp_inject.go`
- Modify: `internal/docker/manager.go`
- Modify: `internal/docker/manager_test.go`
- Modify: `internal/proxy/server.go` (add self-bypass for sluice's own address)

```json
// /phantoms/mcp-servers.json (shared volume, read by OpenClaw)
{
  "sluice": {
    "url": "http://sluice:3000/mcp",
    "transport": "streamable-http"
  }
}
```

- [ ] Implement `InjectMCPConfig(phantomDir, sluiceURL string) error` that writes `mcp-servers.json` to the shared phantoms volume
- [ ] Call `InjectMCPConfig` on sluice startup (after gateway is ready) and after `sluice mcp add/remove`
- [ ] Trigger OpenClaw to re-read MCP config via `docker exec openclaw openclaw mcp reload`. If exec fails, OpenClaw picks it up on next restart.
- [ ] Add SOCKS5 self-bypass: auto-allow connections to sluice's own listener addresses (health/MCP server) without policy evaluation. Hardcoded, not configurable.
- [ ] Add `--auto-inject-mcp` flag (default true in Docker, false otherwise) to control this behavior
- [ ] Write tests for config file generation
- [ ] Write tests for self-bypass (connection to sluice's own address bypasses policy)
- [ ] Run tests: `go test ./internal/docker/ -v -timeout 30s`
- [ ] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 8: Verify acceptance criteria

- [ ] Verify stdio upstreams still work (no regression)
- [ ] Verify Streamable HTTP upstream connects to a remote MCP server
- [ ] Verify WebSocket upstream connects to a WebSocket MCP server
- [ ] Verify mixed upstream types in one gateway (stdio + HTTP + WebSocket)
- [ ] Verify `/mcp` endpoint serves tools to an MCP client over Streamable HTTP
- [ ] Verify OpenClaw auto-injection writes mcp-servers.json and OpenClaw connects via Streamable HTTP
- [ ] Verify SOCKS5 self-bypass: OpenClaw's connection to sluice:3000/mcp is auto-allowed without policy rules
- [ ] Verify OpenClaw container does NOT have Docker socket mounted
- [ ] Verify policy enforcement applies equally across all transports
- [ ] Verify `sluice mcp add <name> --transport http --command https://remote-server/mcp` works
- [ ] Run full test suite: `go test ./... -v -timeout 60s -race`
- [ ] Run linter: `go vet ./...`

### Task 9: [Final] Update documentation

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
1. Sluice starts, MCP gateway initializes on :3000/mcp
2. Gateway discovers tools from all upstreams (stdio/HTTP/WS)
3. Sluice writes /phantoms/mcp-servers.json with {"url": "http://sluice:3000/mcp"}
4. Sluice runs: docker exec openclaw openclaw mcp reload (best-effort)
5. OpenClaw reads mcp-servers.json, connects to sluice:3000/mcp via Streamable HTTP
6. Connection from OpenClaw to sluice:3000 goes through tun2proxy -> SOCKS5
7. SOCKS5 self-bypass: auto-allows traffic to sluice's own address (no policy check)
8. OpenClaw sees all upstream tools (namespaced) through sluice
9. All tool calls go through sluice's policy engine (tool rules, approval, inspect)
10. Upstream HTTP calls from MCP servers go directly from sluice's container (no proxy loop)
```

Note: OpenClaw container does NOT need Docker socket. The shared phantoms volume
is the only communication channel. Docker exec for reload is called from the sluice
container (which already has the socket for credential management).

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
