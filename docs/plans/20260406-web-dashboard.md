# Web Dashboard

## Overview

Separate Go application (`sluice-web`) providing a web dashboard for sluice. Communicates with sluice exclusively via its REST API. Distributed as its own binary and Docker image, independent of the core sluice proxy.

Features: policy rule management, credential management, audit log viewing and verification, live approval requests via SSE, MCP upstream management, notification channel management, and system status overview.

The dashboard proxies all API calls to sluice server-side. It registers its own HTTP webhook channel with sluice on startup to receive real-time approval events, then broadcasts them to connected browsers via Server-Sent Events.

## Context

- `api/openapi.yaml` -- sluice REST API spec (rules, credentials, bindings, audit, approvals, config, channels, MCP)
- `internal/api/server.go` -- sluice API server (oapi-codegen generated interface)
- `internal/channel/http/http.go` -- HTTP webhook channel (sends approval/cancel/notify payloads with HMAC-SHA256)
- `internal/channel/broker.go` -- broker coordinates approvals across channels (broadcast-and-first-wins)
- `internal/store/store.go` -- SQLite store with `channels` table (type, enabled, webhook_url, webhook_secret)
- `cmd/sluice/main.go` -- channels loaded from store at startup, no runtime hot-reload

**Missing in sluice core (prerequisites):**
- No `POST /api/channels` endpoint to create channels via API
- No `DELETE /api/channels/{id}` endpoint to remove channels
- No broker hot-reload (channels only created at startup). Broker assumes immutable channel list set at construction. `broadcast()` iterates `b.channels` without holding any lock.
- `ChannelGateMiddleware` blocks ALL `/api/*` routes when no HTTP channel is enabled. Dashboard cannot call `POST /api/channels` to register itself if no HTTP channel exists yet (chicken-and-egg).
- No `offset` parameter on `GET /api/audit/recent` for pagination. Current implementation uses a circular buffer of size `limit` that reads the entire audit file.

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- **Stack**: Go + htmx + Alpine.js + Go html/template + Pico CSS
- **Why this stack?** Single binary, no build step, no node/npm. htmx handles server-driven page updates (CRUD, pagination, SSE). Alpine.js handles small client-side interactions (dropdowns, modals, filter toggles). Pico CSS provides classless semantic styling with light/dark theme support. Go html/template renders all HTML server-side.
- **Architecture**: Dashboard is a standalone HTTP server that proxies API calls to sluice. Holds sluice API token server-side. Has its own auth (password).
- **CRITICAL: every task MUST include new/updated tests**
- **CRITICAL: all tests must pass before starting next task**
- Run `go test ./... -timeout 30s` after each change

## Testing Strategy

- **Unit tests**: Go tests for handlers, proxy client, webhook receiver, SSE broadcaster, auth middleware
- **E2e tests**: Manual browser testing for v1
- **Frontend tests**: None for v1 (htmx + Alpine, tested manually)

## Progress Tracking

- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with + prefix
- Document issues/blockers with ! prefix

## Solution Overview

### Architecture

```
Browser <---> Dashboard (:8080)
                |
                +--> /              (serves HTML pages via Go templates + htmx)
                +--> /events        (SSE stream for real-time approvals)
                +--> /webhook       (receives webhook POSTs from sluice)
                |
                +--[server-side]--> Sluice API (:3000/api/*)
                                    Authorization: Bearer <SLUICE_API_TOKEN>
```

### Configuration (env vars)

```
SLUICE_URL=http://localhost:3000     # sluice API base URL
SLUICE_API_TOKEN=<token>             # sluice bearer token (server-side only)
DASHBOARD_PASSWORD=<password>        # dashboard login password
DASHBOARD_ADDR=:8080                 # dashboard listen address (default :8080)
DASHBOARD_WEBHOOK_URL=               # optional: override webhook callback URL
                                     # default: auto-detect from DASHBOARD_ADDR
```

### Dashboard pages

1. **Overview** (default `/`): proxy status, connection stats, pending approval count, component health
2. **Policy Rules** (`/rules`): table with CRUD, verdict badges, TOML import/export
3. **Credentials** (`/credentials`): credential names (never values), associated bindings, add/remove
4. **Audit Log** (`/audit`): paginated table with filters (verdict, protocol), hash chain verification
5. **Approvals** (`/approvals`): live pending approvals via SSE, approve/deny/always-allow buttons, history
6. **MCP Upstreams** (`/mcp`): list/add/remove, transport type, command, timeout
7. **Channels** (`/channels`): manage notification channels, enable/disable, webhook URLs

### Webhook and SSE flow

1. Dashboard starts, generates random HMAC secret
2. Calls `POST /api/channels` to register webhook: `{ type: "http", enabled: true, webhook_url: "<self>/webhook", webhook_secret: "<secret>" }`
3. Stores returned channel ID for cleanup
4. Sluice broker creates live HTTPChannel, wires to broker
5. When approval needed: sluice POSTs to dashboard's `/webhook` with HMAC signature
6. Dashboard validates signature, renders approval card template, broadcasts via SSE
7. Browser htmx SSE extension swaps card into approvals area
8. User clicks approve/deny, htmx POSTs to dashboard, dashboard proxies to sluice
9. On shutdown: dashboard calls `DELETE /api/channels/{id}` to deregister

### Authentication

- Dashboard password stored in `DASHBOARD_PASSWORD` env var
- Login page validates password, sets HTTP-only session cookie (HMAC-signed, 24h expiry)
- Session signing key: random generated at startup. All sessions invalidate on dashboard restart. Acceptable for v1 since the dashboard is stateless.
- Auth middleware checks cookie on all routes except `/login`, `/static/*`, and `/webhook`
- Webhook endpoint authenticated via HMAC signature (not session cookie)

### Theme support

- Pico CSS with `data-theme` attribute: `auto` (OS preference), `light`, `dark`
- Toggle button in header, preference stored in localStorage
- Alpine.js manages toggle state

### File structure

```
cmd/sluice-web/
  main.go                    # entry point, config, lifecycle

internal/web/
  dashboard.go               # Dashboard struct, server setup, route registration
  config.go                  # config from env vars
  auth.go                    # session middleware, login/logout handlers
  proxy.go                   # sluice API client (proxies requests)
  webhook.go                 # webhook receiver, HMAC validation
  sse.go                     # SSE broadcaster (hub pattern)
  overview.go                # overview page handler
  rules.go                   # policy rules handlers (list, add, delete, import, export)
  credentials.go             # credentials handlers (list, add, delete) + bindings
  audit.go                   # audit log handlers (list, verify)
  approvals.go               # approvals handlers (list, resolve)
  mcp.go                     # MCP upstream handlers (list, add, delete)
  channels.go                # channels handlers (list, update)
  templates/
    layout.html              # base layout: sidebar, header, theme toggle, main content area
    login.html               # login page (no sidebar)
    overview.html             # overview page content
    rules.html                # rules page (full)
    rules_table.html          # rules table fragment (htmx swap)
    rules_form.html           # add rule form fragment
    credentials.html          # credentials page (full)
    credentials_table.html    # credentials table fragment
    credentials_form.html     # add credential form fragment
    audit.html                # audit page (full)
    audit_table.html          # audit table fragment
    approvals.html            # approvals page (full)
    approval_card.html        # single approval card (SSE fragment)
    mcp.html                  # MCP page (full)
    mcp_table.html            # MCP table fragment
    mcp_form.html             # add MCP upstream form fragment
    channels.html             # channels page (full)
    channels_table.html       # channels table fragment
  static/
    htmx.min.js               # htmx library (embedded)
    htmx-sse.min.js           # htmx SSE extension (embedded)
    alpine.min.js             # Alpine.js (embedded)
    pico.min.css              # Pico CSS (embedded)
    app.css                   # custom styles: sidebar, verdict badges, approval cards
```

## Technical Details

### htmx patterns used

- `hx-get` / `hx-post` / `hx-delete` for CRUD operations
- `hx-target` + `hx-swap` for replacing table rows and sections
- `hx-trigger="load"` for initial data fetch on page load
- `hx-confirm` for delete confirmations
- `hx-ext="sse"` + `sse-connect` + `sse-swap` for live approvals
- `hx-push-url` for browser history integration
- `hx-indicator` for loading spinners
- `hx-vals` for passing form data

### Alpine.js patterns used

- `x-data` for theme toggle state, filter dropdowns, modal open/close
- `x-show` for conditional visibility (filter panels, modals)
- `x-on:click` for theme toggle, dropdown items
- `x-init` for reading localStorage theme preference

### SSE event format

```
event: approval
data: <div class="approval-card" id="approval-abc123">...</div>

event: cancel
data: <div id="approval-abc123" hx-swap-oob="delete"></div>

event: notification
data: <div class="toast">Rule added: allow api.github.com</div>
```

### Proxy client

Thin Go HTTP client wrapping sluice API calls:
- Adds `Authorization: Bearer <token>` header
- Forwards response status codes
- Parses JSON responses into lightweight local structs defined in `proxy.go` (not imported from `internal/api` to avoid pulling the entire sluice dependency tree into the dashboard binary)
- Timeout: 10s per request
- For TOML import: multipart form forwarding
- For TOML export: streams response body directly

### Static library versions

Pin versions in embedded static files:
- htmx 2.0.x
- htmx SSE extension (matching htmx version)
- Alpine.js 3.x
- Pico CSS 2.x

## What Goes Where

- **Implementation Steps**: sluice core API additions, dashboard Go code, templates, static assets
- **Post-Completion**: browser testing, Docker image, CI pipeline

## Implementation Steps

### Task 1: Sluice core - Add channel CRUD endpoints and broker hot-reload

**Files:**
- Modify: `api/openapi.yaml`
- Modify: `internal/api/server.go`
- Modify: `internal/api/api.gen.go` (regenerated)
- Modify: `internal/channel/broker.go`
- Modify: `cmd/sluice/main.go`

- [ ] Add `POST /api/channels` to OpenAPI spec (request: type, enabled, webhook_url, webhook_secret; response: Channel)
- [ ] Add `DELETE /api/channels/{id}` to OpenAPI spec (response: 204 or 404)
- [ ] Regenerate API code: `go generate ./internal/api/`
- [ ] Make broker channel list thread-safe for runtime mutations: use copy-on-write pattern (copy slice, append/remove, swap atomically under `b.mu`). `broadcast()` and `cancelOnChannels()` must snapshot the slice under lock before iterating.
- [ ] Add `AddChannel(ch Channel)` and `RemoveChannel(chType ChannelType, id int64)` methods to Broker using the copy-on-write pattern
- [ ] Add `liveChannels map[int64]channel.Channel` to API Server for tracking dynamically created channels. On DELETE, call `Stop()` on the channel before removing from broker to prevent goroutine leaks.
- [ ] Exempt `POST /api/channels` and `DELETE /api/channels/{id}` from `ChannelGateMiddleware` so the dashboard can self-register when no HTTP channel exists yet
- [ ] Implement `PostApiChannels` handler: validate input, store in DB, create live HTTPChannel, call `SetBroker()`, call `Start()`, add to broker via `AddChannel()`, track in `liveChannels`
- [ ] Implement `DeleteApiChannelsId` handler: look up in `liveChannels`, call `Stop()`, remove from broker via `RemoveChannel()`, delete from DB, remove from `liveChannels`
- [ ] Write tests for POST /api/channels (success, invalid input, duplicate)
- [ ] Write tests for DELETE /api/channels/{id} (success, not found, verify Stop called)
- [ ] Write tests for broker AddChannel/RemoveChannel (including concurrent broadcast during mutation)
- [ ] Write test: POST /api/channels works when no HTTP channel exists (ChannelGateMiddleware bypass)
- [ ] Run tests: `go test ./... -timeout 30s`

### Task 2: Sluice core - Add audit pagination offset

**Files:**
- Modify: `api/openapi.yaml`
- Modify: `internal/api/server.go`
- Modify: `internal/api/api.gen.go` (regenerated)

- [ ] Add `offset` query parameter to `GET /api/audit/recent` in OpenAPI spec. Semantics: skip first `offset` entries from the tail (entries `[offset, offset+limit)` counting backward from end).
- [ ] Regenerate API code: `go generate ./internal/api/`
- [ ] Implement offset: adjust circular buffer to read `limit + offset` entries from the audit file, then return only the `[offset, offset+limit)` slice
- [ ] Write test for offset parameter (offset=0, offset=10, offset > total)
- [ ] Run tests: `go test ./internal/api/ -timeout 30s`

### Task 3: Dashboard scaffolding - server, config, embedded statics

**Files:**
- Create: `cmd/sluice-web/main.go`
- Create: `internal/web/dashboard.go`
- Create: `internal/web/config.go`
- Create: `internal/web/static/htmx.min.js` (download)
- Create: `internal/web/static/htmx-sse.min.js` (download)
- Create: `internal/web/static/alpine.min.js` (download)
- Create: `internal/web/static/pico.min.css` (download)
- Create: `internal/web/static/app.css`

- [ ] Create `internal/web/config.go`: parse env vars (SLUICE_URL, SLUICE_API_TOKEN, DASHBOARD_PASSWORD, DASHBOARD_ADDR, DASHBOARD_WEBHOOK_URL)
- [ ] Create `internal/web/dashboard.go`: Dashboard struct, `//go:embed` for templates and static, chi router setup, static file serving, graceful shutdown
- [ ] Create `cmd/sluice-web/main.go`: config loading, Dashboard init, signal handling, lifecycle (start server, register webhook on startup, deregister on shutdown)
- [ ] Download and embed htmx.min.js, htmx-sse.min.js, alpine.min.js, pico.min.css
- [ ] Create `internal/web/static/app.css` with custom styles: sidebar layout, verdict badges (allow=green, deny=red, ask=yellow, redact=blue), approval cards, toast notifications, loading indicators
- [ ] Write test: static file serving returns correct Content-Type
- [ ] Write test: config parsing with defaults
- [ ] Run tests: `go test ./internal/web/ -timeout 30s`

### Task 4: Auth middleware and login page

**Files:**
- Create: `internal/web/auth.go`
- Create: `internal/web/templates/login.html`
- Create: `internal/web/templates/layout.html`

- [ ] Create `internal/web/auth.go`: session cookie middleware (HMAC-signed cookie, 24h expiry), login handler (POST validates password, sets cookie), logout handler (clears cookie)
- [ ] Create `internal/web/templates/login.html`: password input form, error display, no sidebar
- [ ] Create `internal/web/templates/layout.html`: base layout with sidebar navigation (7 pages), header with theme toggle (Alpine.js), main content area, toast container for notifications
- [ ] Register auth middleware on all routes except `/login`, `/static/*`, `/webhook`
- [ ] Write test: login success sets cookie, redirects to /
- [ ] Write test: login failure shows error
- [ ] Write test: unauthenticated request redirects to /login
- [ ] Write test: /webhook bypasses auth
- [ ] Run tests: `go test ./internal/web/ -timeout 30s`

### Task 5: Sluice API proxy client

**Files:**
- Create: `internal/web/proxy.go`

- [ ] Create `internal/web/proxy.go`: SluiceClient struct wrapping http.Client with base URL and bearer token
- [ ] Define lightweight local request/response structs in proxy.go that mirror the sluice API JSON shapes (do NOT import `internal/api` to avoid pulling sluice's full dependency tree into the dashboard binary)
- [ ] Implement methods: GetStatus, GetRules, PostRule, DeleteRule, ImportRules, ExportRules, GetCredentials, PostCredential, DeleteCredential, GetBindings, PostBinding, DeleteBinding, GetAuditRecent, GetAuditVerify, GetApprovals, ResolveApproval, GetMCPUpstreams, PostMCPUpstream, DeleteMCPUpstream, GetChannels, PatchChannel, PostChannel, DeleteChannel
- [ ] Handle error responses (4xx/5xx) with structured error type
- [ ] Write tests for CRUD proxy methods (GetRules, PostRule, DeleteRule)
- [ ] Write tests for streaming methods (ImportRules multipart, ExportRules download)
- [ ] Write test for error response handling (4xx/5xx mapping)
- [ ] Run tests: `go test ./internal/web/ -timeout 30s`

### Task 6: Webhook receiver and SSE broadcaster

**Files:**
- Create: `internal/web/webhook.go`
- Create: `internal/web/sse.go`

- [ ] Create `internal/web/sse.go`: SSE hub (register/unregister clients, broadcast events). Thread-safe client map. Event types: approval, cancel, notification. Sends HTML fragments as event data.
- [ ] Create `internal/web/webhook.go`: POST /webhook handler validates HMAC-SHA256 signature, parses payload (approval/cancel/notify), renders HTML fragment via template, broadcasts to SSE hub
- [ ] Implement GET /events handler: SSE endpoint, registers client with hub, streams events, cleans up on disconnect
- [ ] Add webhook auto-registration in Dashboard.Start(): generate random secret, call POST /api/channels, store channel ID
- [ ] Add webhook deregistration in Dashboard.Stop(): call DELETE /api/channels/{id}
- [ ] Handle idempotent registration: on startup, list channels via GET /api/channels, find existing channel with matching webhook_url, update it via PATCH instead of creating a duplicate. This handles crash recovery (previous instance didn't deregister). Failed webhook deliveries to a dead URL during the gap are handled by HTTPChannel's retry + deny fallback.
- [ ] Write test: webhook HMAC validation (valid signature, invalid signature, missing signature)
- [ ] Write test: SSE client registration and broadcast
- [ ] Write test: webhook payload parsing and template rendering
- [ ] Run tests: `go test ./internal/web/ -timeout 30s`

### Task 7: Overview page

**Files:**
- Create: `internal/web/overview.go`
- Create: `internal/web/templates/overview.html`

- [ ] Create `internal/web/overview.go`: GET / handler fetches /api/status and /healthz, renders overview template
- [ ] Create `internal/web/templates/overview.html`: status cards (proxy listening, pending approvals, channel status), health indicator (green/red dot), basic connection stats
- [ ] Use `hx-get="/" hx-trigger="every 30s"` for auto-refresh of status cards
- [ ] Write test: overview handler renders with mock data
- [ ] Run tests: `go test ./internal/web/ -timeout 30s`

### Task 8: Policy Rules page

**Files:**
- Create: `internal/web/rules.go`
- Create: `internal/web/templates/rules.html`
- Create: `internal/web/templates/rules_table.html`
- Create: `internal/web/templates/rules_form.html`

- [ ] Create `internal/web/rules.go`: handlers for GET /rules (full page), GET /rules/table (htmx fragment), POST /rules (add), DELETE /rules/{id} (remove), GET /rules/export (download TOML), POST /rules/import (upload TOML)
- [ ] Create `internal/web/templates/rules.html`: full page with table and add form
- [ ] Create `internal/web/templates/rules_table.html`: table fragment with columns (ID, verdict, destination/tool/pattern, ports, protocols, name, source, actions). Verdict column uses colored badges. Delete button with hx-delete and hx-confirm.
- [ ] Create `internal/web/templates/rules_form.html`: add rule form (verdict dropdown, destination/tool/pattern input, ports, name). hx-post submits, hx-target swaps updated table.
- [ ] Add TOML import button (file upload) and export button (download link)
- [ ] Write test: rules list handler returns HTML with rules
- [ ] Write test: add rule handler creates rule and returns updated table
- [ ] Write test: delete rule handler removes rule
- [ ] Run tests: `go test ./internal/web/ -timeout 30s`

### Task 9: Credentials page

**Files:**
- Create: `internal/web/credentials.go`
- Create: `internal/web/templates/credentials.html`
- Create: `internal/web/templates/credentials_table.html`
- Create: `internal/web/templates/credentials_form.html`

- [ ] Create `internal/web/credentials.go`: handlers for GET /credentials (full page), GET /credentials/table (fragment), POST /credentials (add), DELETE /credentials/{name} (remove)
- [ ] Create `internal/web/templates/credentials.html`: full page with credentials table and add form
- [ ] Create `internal/web/templates/credentials_table.html`: table showing credential names with associated bindings (fetched from /api/bindings, joined server-side by credential name). Delete button per row. Never show credential values.
- [ ] Create `internal/web/templates/credentials_form.html`: add credential form (name, value as password input, optional destination/ports/header/template for auto-binding). hx-post submits.
- [ ] Write test: credentials list includes bindings
- [ ] Write test: add credential handler
- [ ] Write test: delete credential handler
- [ ] Run tests: `go test ./internal/web/ -timeout 30s`

### Task 10: Audit Log page

**Files:**
- Create: `internal/web/audit.go`
- Create: `internal/web/templates/audit.html`
- Create: `internal/web/templates/audit_table.html`

- [ ] Create `internal/web/audit.go`: handlers for GET /audit (full page), GET /audit/table (fragment with limit+offset params), POST /audit/verify (trigger verification)
- [ ] Create `internal/web/templates/audit.html`: full page with table, filter controls (Alpine.js dropdowns for verdict, protocol), pagination, verify button
- [ ] Create `internal/web/templates/audit_table.html`: table fragment with columns (timestamp, destination, port, protocol, verdict, tool, action, reason). Verdict badges. Pagination controls (prev/next) using hx-get with offset.
- [ ] Add hash chain verification: verify button calls /api/audit/verify, displays result (valid/broken with details)
- [ ] Use Alpine.js for filter dropdowns that modify hx-get URL params
- [ ] Write test: audit list with pagination (offset/limit)
- [ ] Write test: verify handler displays result
- [ ] Run tests: `go test ./internal/web/ -timeout 30s`

### Task 11: Approvals page (live SSE)

**Files:**
- Create: `internal/web/approvals.go`
- Create: `internal/web/templates/approvals.html`
- Create: `internal/web/templates/approval_card.html`

- [ ] Create `internal/web/approvals.go`: handlers for GET /approvals (full page), POST /approvals/{id}/resolve (proxy to sluice)
- [ ] Create `internal/web/templates/approvals.html`: page with SSE connection (`hx-ext="sse" sse-connect="/events" sse-swap="approval"`), pending approvals container, resolved approvals history (fetched on load)
- [ ] Create `internal/web/templates/approval_card.html`: approval card with destination, port, protocol, timestamp, approve/deny/always-allow buttons. hx-post to /approvals/{id}/resolve. Card ID matches approval ID for SSE cancel (out-of-band delete).
- [ ] Show approval count badge in sidebar navigation (updated via SSE or polling)
- [ ] Write test: approvals page renders pending approvals
- [ ] Write test: resolve handler proxies to sluice and returns updated view
- [ ] Run tests: `go test ./internal/web/ -timeout 30s`

### Task 12: MCP Upstreams page

**Files:**
- Create: `internal/web/mcp.go`
- Create: `internal/web/templates/mcp.html`
- Create: `internal/web/templates/mcp_table.html`
- Create: `internal/web/templates/mcp_form.html`

- [ ] Create `internal/web/mcp.go`: handlers for GET /mcp (full page), GET /mcp/table (fragment), POST /mcp (add), DELETE /mcp/{name} (remove)
- [ ] Create templates: table (name, command, transport, args, timeout, actions), add form (name, command, transport dropdown, args, timeout). hx-post/hx-delete for CRUD.
- [ ] Write test: MCP list handler
- [ ] Write test: add/delete handlers
- [ ] Run tests: `go test ./internal/web/ -timeout 30s`

### Task 13: Channels page

**Files:**
- Create: `internal/web/channels.go`
- Create: `internal/web/templates/channels.html`
- Create: `internal/web/templates/channels_table.html`

- [ ] Create `internal/web/channels.go`: handlers for GET /channels (full page), GET /channels/table (fragment), PATCH /channels/{id} (update via proxy)
- [ ] Create templates: table (ID, type, enabled toggle, webhook URL, actions). Enable/disable toggle via hx-patch. Identify dashboard's own channel by matching stored channel ID from registration, mark as "(this dashboard)" in the table (read-only, cannot disable).
- [ ] Write test: channels list handler
- [ ] Write test: channel update handler (enable/disable)
- [ ] Run tests: `go test ./internal/web/ -timeout 30s`

### Task 14: Verify acceptance criteria

- [ ] Build dashboard: `go build -o sluice-web ./cmd/sluice-web/`
- [ ] Verify dashboard starts and connects to sluice API
- [ ] Verify webhook auto-registration on startup, deregistration on shutdown
- [ ] Verify login flow (password, session cookie, redirect)
- [ ] Verify all 7 pages render correctly
- [ ] Verify CRUD operations: rules (add/delete/import/export), credentials (add/delete), MCP (add/delete)
- [ ] Verify audit log pagination and hash chain verification
- [ ] Verify live approval flow: trigger ask rule, see card appear via SSE, resolve
- [ ] Verify theme toggle (auto/light/dark) works and persists
- [ ] Verify sluice API endpoints still work independently
- [ ] Run full test suite: `go test ./... -v -timeout 30s`

### Task 15: [Final] Update documentation

- [ ] Update CLAUDE.md with sluice-web build command and architecture
- [ ] Update README.md with dashboard setup instructions (env vars, running)
- [ ] Add Dockerfile for sluice-web (separate from sluice core)
- [ ] Move this plan to `docs/plans/completed/`

## Post-Completion

**Manual verification:**
- Test with real sluice instance running proxy + MCP gateway
- Test approval flow end-to-end (agent triggers ask -> dashboard shows card -> user approves)
- Test on Chrome, Safari, Firefox
- Verify light and dark themes look correct
- Test webhook reconnection (restart sluice, verify dashboard re-registers)

**CI/CD:**
- Add GitHub Actions workflow for sluice-web Docker image build/push
- Add separate binary release for sluice-web in release workflow

**Future work:**
- WebSocket upgrade for SSE (if SSE reconnection proves unreliable)
- Audit log timeline/graph visualization
- Rule testing simulator (input destination, see which rule matches)
- Mobile-responsive layout improvements
- Multi-user auth (beyond single shared password)
