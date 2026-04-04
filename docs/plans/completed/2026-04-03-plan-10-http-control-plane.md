# Plan 10: HTTP Control Plane

## Overview

Add a HTTP Channel implementation and a full REST API to sluice using spec-first OpenAPI code generation. The OpenAPI spec defines all endpoints. `oapi-codegen` generates types, server interface, and chi router. Hand-written handlers implement the interface. The HTTP channel delivers approval requests via HTTP POST, with both sync and async response paths.

**Problem:** Currently sluice can only be managed via CLI (local access) or Telegram. No HTTP-based management surface for CI/CD pipelines, custom dashboards, or automated tooling. Approval flow is Telegram-only.

**Solution:** Write an OpenAPI 3.0 spec, generate a chi-server with typed models, implement handlers that wrap the existing SQLite store. Add HTTP Channel implementation for HTTP-based approvals. Three management surfaces: CLI, Telegram, HTTP API. All write to the same SQLite store.

**Depends on:** Plan 9 (Channel interface, unified schema) must be completed first.

**Reference:** PhantomPay/Backend uses the same pattern: `api/openapi.yaml` -> `oapi-codegen` -> `internal/api/api.gen.go` + hand-written `server.go`.

## Context

**Existing infrastructure to extend:**
- Health check server on `:3000` (`cmd/sluice/main.go`) -- currently serves only `/healthz`
- `channel.Channel` interface (from Plan 9) -- webhook is the second implementation
- `internal/store/` -- all CRUD methods exist, handlers just wrap them

**New files:**
- `api/openapi.yaml` -- OpenAPI 3.0 spec
- `internal/api/generate.go` -- `//go:generate oapi-codegen` directive
- `internal/api/config.yaml` -- oapi-codegen config
- `internal/api/api.gen.go` -- generated types, server interface, chi router
- `internal/api/server.go` -- handler implementations
- `internal/api/server_test.go` -- handler tests
- `internal/channel/http/http.go` -- HTTP Channel implementation
- `internal/channel/http/http_test.go`

**Dependencies to add:**
- `github.com/oapi-codegen/oapi-codegen/v2` (code generator, dev tool only)
- `github.com/oapi-codegen/runtime` (runtime helpers for generated code)
- `github.com/go-chi/chi/v5` (HTTP router, used by generated code)
- `github.com/getkin/kin-openapi/openapi3` (OpenAPI spec embedding)

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Spec-first: write OpenAPI spec, generate code, implement handlers
- Complete each task fully before moving to the next
- All tests must pass before starting next task

## Testing Strategy

- **Unit tests**: Required for every task. HTTP handlers tested with `httptest` and generated client helpers.
- **Integration tests**: Webhook delivery + callback flow end to end.

## Implementation Steps

### Task 1: Write OpenAPI spec and set up code generation

Define the full API surface in OpenAPI 3.0 YAML. Set up oapi-codegen with chi-server generation.

**Files:**
- Create: `api/openapi.yaml`
- Create: `internal/api/generate.go`
- Create: `internal/api/config.yaml`
- Modify: `go.mod` (add oapi-codegen, chi, kin-openapi dependencies)
- Modify: `Makefile` (add `generate` target)

**OpenAPI spec structure:**

```
/healthz                        GET    -- health check (no auth)
/api/approvals                  GET    -- list pending approvals
/api/approvals/{id}/resolve     POST   -- resolve approval
/api/rules                      GET    -- list rules (?verdict=, ?type=)
/api/rules                      POST   -- add rule
/api/rules/{id}                 DELETE -- remove rule
/api/rules/import               POST   -- import config.toml
/api/rules/export               GET    -- export TOML
/api/config                     GET    -- get config
/api/config                     PATCH  -- update config
/api/credentials                GET    -- list credential names
/api/credentials                POST   -- add credential
/api/credentials/{name}         DELETE -- remove credential
/api/bindings                   GET    -- list bindings
/api/bindings                   POST   -- add binding
/api/bindings/{id}              DELETE -- remove binding
/api/mcp/upstreams              GET    -- list upstreams
/api/mcp/upstreams              POST   -- add upstream
/api/mcp/upstreams/{name}       DELETE -- remove upstream
/api/audit/recent               GET    -- recent audit entries
/api/audit/verify               GET    -- verify hash chain
/api/channels                   GET    -- list channels
/api/channels/{id}              PATCH  -- update channel
/api/status                     GET    -- proxy stats
```

- [ ] Write `api/openapi.yaml` with all endpoints, request/response schemas, bearer auth security scheme. `/healthz` has no security. All `/api/*` require bearerAuth.
- [ ] Define schemas for all request/response types: Rule, Config, Binding, MCPUpstream, Channel, ApprovalRequest, Credential, AuditEntry, VerifyResult, ImportResult, StatusResponse
- [ ] Create `internal/api/config.yaml` with oapi-codegen config (package: api, chi-server: true, models: true, embedded-spec: true)
- [ ] Create `internal/api/generate.go` with `//go:generate oapi-codegen --config config.yaml ../../api/openapi.yaml`
- [ ] Add oapi-codegen, chi, kin-openapi, oapi-codegen/runtime dependencies to go.mod
- [ ] Run `go generate ./internal/api/` to produce `api.gen.go`
- [ ] Add `generate` target to Makefile: `cd internal/api && oapi-codegen --config config.yaml ../../api/openapi.yaml`
- [ ] Add `lint-api` target to Makefile: `npx @redocly/cli lint api/openapi.yaml`
- [ ] Verify generated code compiles: `go build ./internal/api/`
- [ ] Run tests: `go test ./... -v -timeout 30s`

### Task 2: Implement approval and status handlers

Implement the generated server interface for approval and status endpoints. These are needed first because the HTTP channel depends on the approval resolve endpoint.

**Files:**
- Create: `internal/api/server.go` (implements generated ServerInterface)
- Create: `internal/api/server_test.go`
- Modify: `cmd/sluice/main.go` (mount generated chi router on health server)

- [ ] Create `Server` struct in `internal/api/server.go` holding references to store, broker, vault, audit path, proxy server
- [ ] Implement `GetHealthz` handler (returns 200 ok when proxy is listening)
- [ ] Implement `GetApiApprovals` handler (returns pending approval requests from broker)
- [ ] Implement `PostApiApprovalsIdResolve` handler (calls broker.Resolve with verdict)
- [ ] Implement `GetApiStatus` handler (proxy listening state, pending count, channel statuses)
- [ ] Add bearer token auth middleware using `SLUICE_API_TOKEN` env var. If not set, all `/api/*` return 403.
- [ ] Gate API routes: `/api/*` returns 403 `{"error": "HTTP channel is not enabled", "code": "channel_disabled"}` when no channels row has type=1 (HTTP) and enabled=1. `/healthz` always active regardless. Auth check (401/403 `unauthorized`) runs before channel check so bad tokens never reveal channel state.
- [ ] Mount the generated chi handler on the existing health check server in main.go (replace simple `/healthz` mux)
- [ ] Write tests for each handler using httptest
- [ ] Write tests for auth middleware (valid/missing/wrong token, disabled API)
- [ ] Run tests: `go test ./internal/api/ -v -timeout 30s`

### Task 3: Implement rule management handlers

**Files:**
- Modify: `internal/api/server.go`
- Modify: `internal/api/server_test.go`

- [ ] Implement `GetApiRules` with query param filtering (?verdict=, ?type=network|tool|pattern)
- [ ] Implement `PostApiRules` accepting generated request type, calls store.AddRule, recompiles engine
- [ ] Implement `DeleteApiRulesId` calls store.RemoveRule, recompiles engine
- [ ] Implement `PostApiRulesImport` accepting multipart TOML file upload, calls store.ImportTOML
- [ ] Implement `GetApiRulesExport` returning TOML representation
- [ ] Implement `GetApiConfig` returning typed config as generated response type
- [ ] Implement `PatchApiConfig` accepting partial update, calls store.UpdateConfig, recompiles engine
- [ ] Write tests for each handler (success + error cases)
- [ ] Run tests: `go test ./internal/api/ -v -timeout 30s`

### Task 4: Implement credential, binding, MCP, audit, and channel handlers

**Files:**
- Modify: `internal/api/server.go`
- Modify: `internal/api/server_test.go`

- [ ] Implement `GetApiCredentials` (list names via vault.Store.List)
- [ ] Implement `PostApiCredentials` (add to vault, optionally create binding + allow rule, trigger phantom regen + hot reload)
- [ ] Implement `DeleteApiCredentialsName` (remove credential + associated bindings/rules)
- [ ] Implement binding CRUD handlers (GetApiBindings, PostApiBindings, DeleteApiBindingsId)
- [ ] Implement MCP upstream CRUD handlers (GetApiMcpUpstreams, PostApiMcpUpstreams, DeleteApiMcpUpstreamsName)
- [ ] Implement `GetApiAuditRecent` (read last N lines from audit log, ?limit= param)
- [ ] Implement `GetApiAuditVerify` (call audit.VerifyChain, return result)
- [ ] Implement `GetApiChannels` and `PatchApiChannelsId` for channel management
- [ ] Write tests for all handlers
- [ ] Run tests: `go test ./internal/api/ -v -timeout 30s`

### Task 5: Implement HTTP Channel

Create the HTTP Channel implementation satisfying `channel.Channel` from Plan 9.

**Files:**
- Create: `internal/channel/http/http.go`
- Create: `internal/channel/http/http_test.go`
- Modify: `internal/channel/channel.go` (add ChannelHTTP = 1 to enum)

**Webhook approval flow:**
```
1. channel.RequestApproval(req) called
2. POST to configured webhook_url with signed JSON body
3a. Sync: response body has {"verdict": "allow"} -> resolved immediately
3b. Async: 202 Accepted -> waits for callback to POST /api/approvals/:id/resolve
```

- [ ] Add `ChannelHTTP ChannelType = 1` to enum in channel.go
- [ ] Create `HTTPChannel` struct implementing `channel.Channel`
- [ ] Implement `RequestApproval`: POST to webhook_url with HMAC-SHA256 signature. Parse sync response or wait for async callback.
- [ ] Implement `CancelApproval`, `CancelAll`: POST cancellation notification, auto-deny pending requests
- [ ] Implement `Commands() <-chan channel.Command`: return nil (webhook doesn't support incoming commands)
- [ ] Implement `Notify`: POST notification to webhook_url (fire and forget)
- [ ] Implement `Type()`: return ChannelHTTP
- [ ] Add retry logic: 3 attempts with exponential backoff for delivery failures
- [ ] Write tests with httptest mock server for webhook target
- [ ] Write tests for sync response path
- [ ] Write tests for async callback path
- [ ] Write tests for retry and timeout
- [ ] Run tests: `go test ./internal/channel/webhook/ -v -timeout 30s`

### Task 6: Add webhook config migration and channel wiring

**Files:**
- Create: `internal/store/migrations/000002_webhook_channel.up.sql`
- Create: `internal/store/migrations/000002_webhook_channel.down.sql`
- Modify: `internal/store/store.go` (update Channel struct for new columns)
- Modify: `cmd/sluice/main.go` (instantiate channel based on DB config)

**Migration 000002:**
```sql
ALTER TABLE channels ADD COLUMN webhook_url TEXT;
ALTER TABLE channels ADD COLUMN webhook_secret TEXT;
```

- [ ] Create migration 000002 adding webhook_url and webhook_secret columns to channels table
- [ ] Update Channel CRUD in store.go for new columns
- [ ] In main.go, read ALL enabled channels from store. Instantiate each by type (Telegram or HTTP). Pass all to `channel.NewBroker(channels)`.
- [ ] Support multiple channels simultaneously: Telegram (row 1, type=0) + HTTP (row 2, type=1) can both be enabled
- [ ] Add `sluice channel list`, `sluice channel add --type http --url <url> [--secret <secret>]`, `sluice channel update <id> --enabled true/false`, `sluice channel remove <id>` CLI
- [ ] Wire HTTP channel's async resolve path to the API's approval resolve endpoint (Task 2)
- [ ] Write tests for migration
- [ ] Write tests for multi-channel instantiation (both Telegram + HTTP enabled)
- [ ] Write tests for approval broadcast across both channels with first-response-wins
- [ ] Run tests: `go test ./... -v -timeout 30s`

### Task 7: Verify acceptance criteria

- [ ] Verify `go generate ./internal/api/` produces valid code from OpenAPI spec
- [ ] Verify all REST API endpoints work with bearer token auth
- [ ] Verify API returns 403 when SLUICE_API_TOKEN is not set
- [ ] Verify API routes return 403 with `{"error": "HTTP channel is not enabled", "code": "channel_disabled"}` when HTTP channel is disabled
- [ ] Verify `/healthz` stays active even when HTTP channel is disabled
- [ ] Verify HTTP channel delivers approvals via HTTP POST with HMAC signature
- [ ] Verify sync response path (verdict in webhook response body)
- [ ] Verify async callback path (202 + POST /api/approvals/:id/resolve)
- [ ] Verify multi-channel: Telegram + HTTP both enabled, approval broadcast to both, first response wins
- [ ] Verify cross-channel cancellation: Telegram approves, HTTP prompt gets cancelled (and vice versa)
- [ ] Verify `sluice channel add --type http --url https://...` creates new channel row
- [ ] Verify `sluice channel list` shows all channels with status
- [ ] Verify `sluice channel remove <id>` removes channel (cannot remove last enabled channel)
- [ ] Verify policy CRUD via API writes to store and recompiles engine
- [ ] Verify credential management via API triggers phantom regen + hot reload
- [ ] Run full test suite: `go test ./... -v -timeout 60s -race`
- [ ] Run linter: `go vet ./...`

### Task 8: [Final] Update documentation

- [ ] Update CLAUDE.md: document REST API, OpenAPI spec location, code generation workflow
- [ ] Update CLAUDE.md: document HTTP channel type and configuration
- [ ] Update CONTRIBUTING.md: add API development workflow (edit spec -> generate -> implement)
- [ ] Add API development section to Makefile help
- [ ] Update examples/config.toml: add HTTP channel example (commented)
- [ ] Update compose.yml: document SLUICE_API_TOKEN env var

## Technical Details

### Spec-first code generation workflow

```
1. Edit api/openapi.yaml (the spec is the source of truth)
2. Run: make generate (or go generate ./internal/api/)
3. oapi-codegen reads spec, generates:
   - Go types for all request/response schemas
   - ServerInterface with one method per operation
   - Chi router that validates requests and routes to interface methods
   - Embedded spec for runtime validation
4. Implement/update methods in server.go to satisfy ServerInterface
5. Compile and test
```

**oapi-codegen config (internal/api/config.yaml):**
```yaml
package: api
output: api.gen.go
generate:
  chi-server: true
  models: true
  embedded-spec: true
```

### Authentication

Bearer token via `SLUICE_API_TOKEN` env var:
```
Authorization: Bearer <token>
```

Defined as `bearerAuth` security scheme in OpenAPI spec. `/healthz` explicitly has `security: []` (no auth).

### Webhook delivery format

```
POST https://external-system.com/sluice/approvals
Content-Type: application/json
X-Sluice-Signature: sha256=<hmac of body using webhook_secret>

{
  "id": "abc123",
  "type": "approval",
  "destination": "api.github.com",
  "port": 443,
  "tool": "",
  "timestamp": "2026-04-03T10:00:00Z"
}
```

Sync response: `200 {"verdict": "allow"}`
Async response: `202` then callback to `POST /api/approvals/abc123/resolve`

### REST API endpoint summary

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /healthz | No | Health check |
| GET | /api/status | Yes | Proxy stats |
| GET | /api/approvals | Yes | Pending approvals |
| POST | /api/approvals/{id}/resolve | Yes | Resolve approval |
| GET | /api/rules | Yes | List rules |
| POST | /api/rules | Yes | Add rule |
| DELETE | /api/rules/{id} | Yes | Remove rule |
| POST | /api/rules/import | Yes | Import TOML |
| GET | /api/rules/export | Yes | Export TOML |
| GET | /api/config | Yes | Get config |
| PATCH | /api/config | Yes | Update config |
| GET | /api/credentials | Yes | List cred names |
| POST | /api/credentials | Yes | Add credential |
| DELETE | /api/credentials/{name} | Yes | Remove credential |
| GET | /api/bindings | Yes | List bindings |
| POST | /api/bindings | Yes | Add binding |
| DELETE | /api/bindings/{id} | Yes | Remove binding |
| GET | /api/mcp/upstreams | Yes | List upstreams |
| POST | /api/mcp/upstreams | Yes | Add upstream |
| DELETE | /api/mcp/upstreams/{name} | Yes | Remove upstream |
| GET | /api/audit/recent | Yes | Recent audit entries |
| GET | /api/audit/verify | Yes | Verify hash chain |
| GET | /api/channels | Yes | List channels |
| PATCH | /api/channels/{id} | Yes | Update channel |

## Post-Completion

**Manual verification:**
- Test webhook delivery with a simple HTTP server
- Test all REST API endpoints with curl
- Verify OpenAPI spec validates: `npx @redocly/cli lint api/openapi.yaml`
- Load test webhook delivery (100 concurrent approvals)

**Future considerations:**
- WebSocket upgrade for real-time approval streaming
- Multiple API tokens with scoped permissions
- Rate limiting on API endpoints
- SDK generation from OpenAPI spec for client libraries
