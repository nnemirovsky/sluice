# Plan 23: Web Dashboard

## Overview

Add a web dashboard to Sluice for audit browsing, policy editing, risk monitoring, approval history, and component health. The dashboard is a static single-page application served by Sluice's existing HTTP server on port 3000 alongside `/healthz`, `/api/*`, and `/mcp`.

Sluice already has a comprehensive REST API (`api/openapi.yaml`) covering rules CRUD, credentials, bindings, MCP upstreams, channels, audit, approvals, config, and status. The dashboard is a frontend for this existing API.

Inspired by Prism's dashboard sidecar (audit browsing, config editing, allow-action workflows, component health probing).

## Context

- `api/openapi.yaml` -- OpenAPI 3.0.3 spec with all endpoints
- `internal/api/server.go` -- REST API server implementing generated ServerInterface
- `internal/api/api.gen.go` -- oapi-codegen generated types and router
- `internal/api/generate.go` -- go:generate directive for oapi-codegen
- `internal/api/config.yaml` -- oapi-codegen configuration
- Port 3000 already serves `/healthz`, `/api/*`, and `/mcp` (when MCP gateway active)

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- **Frontend stack**: Vanilla HTML/CSS/JS with no build step. Served as embedded static files via Go's `embed` package. No npm, no bundler, no framework. This keeps the single-binary deployment model intact.
- **Why no framework?** Sluice is a Go binary. Adding a Node.js build pipeline for a dashboard would complicate the build and add a large dependency tree. A vanilla SPA with fetch() calls to the existing API is sufficient for the feature set.
- **CRITICAL: every task MUST include new/updated tests**
- **CRITICAL: all tests must pass before starting next task**
- Run `go test ./... -timeout 30s` after each change

## Testing Strategy

- **Unit tests**: Go tests for embed/serve, API response format
- **E2e tests**: Manual browser testing (no Playwright for this plan)
- **Frontend tests**: None for v1 (vanilla JS, tested manually)

## Progress Tracking

- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with + prefix
- Document issues/blockers with ! prefix

## Solution Overview

```
Browser -> http://127.0.0.1:3000/
    |
    +--> /              -> Serve index.html (embedded static files)
    +--> /assets/*      -> Serve CSS, JS, icons (embedded)
    +--> /api/*         -> Existing REST API (unchanged)
    +--> /healthz       -> Existing health check (unchanged)
    +--> /mcp           -> Existing MCP Streamable HTTP (unchanged)
```

### Dashboard Pages

1. **Overview** (default): Proxy status, connection stats, pending approvals count, risk level summary (from Plan 21), component health
2. **Audit Log**: Paginated table of audit events with filters (verdict, protocol, tool, time range). Search. Hash chain status indicator.
3. **Policy Rules**: Table of all rules with add/edit/delete. TOML import/export buttons. Verdict color coding.
4. **Credentials**: List credentials (names only, never values). Add/remove. Show associated bindings.
5. **MCP Upstreams**: List upstream servers with status. Add/remove.
6. **Approvals**: Live pending approvals with approve/deny buttons. History of resolved approvals.
7. ~~**Sessions** (deferred to future work, requires Plan 21)~~

### UI Design

Minimal, dark-themed dashboard. No CSS framework. CSS custom properties for theming. Responsive layout with sidebar navigation. Tables with sorting and filtering. Real-time updates via polling (5s interval for approvals, 30s for everything else).

### Authentication

Reuse the existing API bearer token authentication (`security: bearerAuth`). Dashboard prompts for token on first load, stores in sessionStorage. API requests include `Authorization: Bearer <token>` header.

## Technical Details

### File Structure

```
internal/api/web/
  index.html          -- SPA shell, sidebar nav, page containers
  assets/
    style.css         -- Dashboard styles, dark theme, tables, cards
    app.js            -- Router, API client, page renderers
    icons.svg         -- Inline SVG sprite for nav icons
```

Embedded via Go `embed` package (paths relative to the file containing the directive, matching the existing pattern in `internal/store/migrate.go`):

```go
// internal/api/static.go
//go:embed all:web
var webFS embed.FS
```

Note: `all:web` (not `web/*`) is required to recursively embed subdirectories like `web/assets/`.

### SPA Router

Hash-based routing (`#/audit`, `#/rules`, `#/credentials`, etc.). Each route maps to a render function that fetches from the API and updates the page container.

### API Client

Thin wrapper around `fetch()` with:
- Base URL detection (same origin)
- Bearer token from sessionStorage
- JSON parse/error handling
- Polling manager for live updates

### Key Components

- **AuditTable**: Fetches `/api/audit/recent?limit=N`, renders sortable table with verdict badges
- **RulesTable**: Fetches `/api/rules`, renders with inline add/edit/delete. CRUD via POST/DELETE `/api/rules`
- **ApprovalPanel**: Fetches `/api/approvals`, renders pending with approve/deny buttons, POST `/api/approvals/{id}/resolve`
- **StatusCard**: Fetches `/api/status`, renders connection stats and proxy info
- **HealthIndicator**: Fetches `/healthz`, shows green/red dot

### New API Endpoints Needed

The existing API covers most needs. One addition:

1. **`GET /api/audit/recent` enhancement**: Add `offset` parameter for pagination (currently only `limit`). Note: the existing implementation uses a circular buffer. Adding offset means holding `limit + offset` entries in the ring buffer.

Sessions page (Plan 21 dependency) is deferred to future work.

### Auth Bypass for Static Files

The existing `BearerAuthMiddleware` and `ChannelGateMiddleware` block all non-`/healthz` routes. Static file routes (`/`, `/assets/*`) must bypass auth so the login page itself can load. Approach: register static file handler on the `http.ServeMux` in `cmd/sluice/main.go` BEFORE the chi handler pattern, or add `/` and `/assets/` to the middleware bypass list alongside `/healthz`. The SPA fallback (serving `index.html` for unknown paths) should use chi's `r.NotFound()` handler to avoid shadowing API 404s.

### API Data Shape Notes

- `GET /api/credentials` only returns credential names (not binding details). Dashboard must fetch `/api/bindings` separately and join client-side.
- `GET /api/approvals` returns `id`, `destination`, `port`, `created_at` only. Protocol and tool args are not in the current schema. Dashboard renders available fields only for v1.

## What Goes Where

- **Implementation Steps**: Static files, Go embed, route registration, API enhancements
- **Post-Completion**: UI polish, real-world testing with agents

## Implementation Steps

### Task 1: Create dashboard HTML shell and styles

**Files:**
- Create: `internal/api/web/index.html`
- Create: `internal/api/web/assets/style.css`

- [ ] Create `internal/api/web/index.html` with:
  - Minimal HTML5 skeleton
  - Sidebar navigation (Overview, Audit, Rules, Credentials, MCP, Approvals)
  - Page container div for SPA content
  - Script and CSS references
  - Login prompt overlay (token input)
- [ ] Create `internal/api/web/assets/style.css` with:
  - CSS custom properties for dark theme colors
  - Sidebar layout (fixed left, content right)
  - Table styles (striped rows, sortable headers)
  - Card components for status overview
  - Badge styles for verdicts (allow=green, deny=red, ask=yellow, redact=blue)
  - Form styles for rule/credential creation
  - Responsive breakpoints
- [ ] Verify HTML renders correctly by opening directly in browser (no JS yet)

### Task 2: Implement SPA router and API client

**Files:**
- Create: `internal/api/web/assets/app.js`

- [ ] Implement hash-based router: `window.addEventListener('hashchange', route)`
- [ ] Implement API client class with:
  - `get(path)`, `post(path, body)`, `del(path)` methods
  - Bearer token from sessionStorage
  - Error handling (401 -> show login, 4xx/5xx -> show error)
- [ ] Implement login flow: prompt for token, store in sessionStorage, redirect to `#/`
- [ ] Implement polling manager: configurable interval per route, cancel on route change
- [ ] Implement Overview page: fetch `/api/status`, render stats cards
- [ ] Verify navigation between routes works

### Task 3: Implement audit log page

**Files:**
- Modify: `web/assets/app.js`
- Modify: `internal/api/server.go` (add offset to audit endpoint)
- Modify: `api/openapi.yaml` (add offset parameter)

- [ ] Add `offset` query parameter to `GET /api/audit/recent` endpoint
- [ ] Update OpenAPI spec with offset parameter
- [ ] Regenerate API code: `go generate ./internal/api/`
- [ ] Implement audit page in app.js:
  - Fetch `/api/audit/recent?limit=50&offset=0`
  - Render table with columns: timestamp, destination, port, protocol, verdict, tool, action, reason
  - Verdict column uses colored badges
  - Pagination controls (prev/next)
  - Filter dropdowns: verdict, protocol
  - Search input filtering visible rows
- [ ] Write Go test for offset parameter in audit endpoint
- [ ] Run tests: `go test ./internal/api/ -v -timeout 30s`

### Task 4: Implement policy rules page

**Files:**
- Modify: `web/assets/app.js`

- [ ] Implement rules page in app.js:
  - Fetch `/api/rules` and render table
  - Columns: ID, verdict, destination/tool/pattern, ports, protocols, name, source, actions
  - Add rule form: verdict dropdown, destination/tool/pattern input, ports, name
  - Delete button per row (confirm dialog) -> DELETE `/api/rules/{id}`
  - Import button: file input for TOML -> POST `/api/rules/import`
  - Export button: GET `/api/rules/export` -> download as .toml
- [ ] Verify CRUD operations work against running sluice instance
- [ ] Run tests: `go test ./... -timeout 30s` (verify no regressions)

### Task 5: Implement credentials and MCP upstreams pages

**Files:**
- Modify: `web/assets/app.js`

- [ ] Implement credentials page:
  - Fetch `/api/credentials` (returns names only) and `/api/bindings` separately
  - Render credentials table (name) with associated bindings shown inline (joined client-side by credential name)
  - Add credential form: name, value (password input), optional destination/ports/header/template
  - Delete button per row -> DELETE `/api/credentials/{name}`
- [ ] Implement MCP upstreams page:
  - Fetch `/api/mcp/upstreams` and render table (name, command, transport, timeout)
  - Add upstream form: name, command, transport dropdown, args, timeout
  - Delete button per row -> DELETE `/api/mcp/upstreams/{name}`
- [ ] Verify CRUD operations work
- [ ] Run tests: `go test ./... -timeout 30s` (verify no regressions)

### Task 6: Implement approvals page with live updates

**Files:**
- Modify: `web/assets/app.js`

- [ ] Implement approvals page:
  - Fetch `/api/approvals` every 5 seconds
  - Render pending approvals as cards: destination, port, created_at (only fields available in current API schema)
  - Allow Once / Always Allow / Deny buttons -> POST `/api/approvals/{id}/resolve`
  - Visual feedback on resolution (card fades out)
  - Show approval count badge in sidebar nav
- [ ] Verify approval flow works: trigger Ask rule, see approval in dashboard, resolve it
- [ ] Run tests: `go test ./... -timeout 30s` (verify no regressions)

### Task 7: Embed static files and serve from Go

**Files:**
- Create: `internal/api/static.go`
- Modify: `internal/api/server.go`
- Modify: `cmd/sluice/main.go`

- [ ] Create `internal/api/static.go` with `//go:embed all:web` directive
- [ ] Add `ServeDashboard(mux *http.ServeMux)` function that:
  - Strips `web/` prefix from embedded FS
  - Serves `index.html` for `/` (SPA entry point)
  - Serves static files at their paths (`/assets/style.css`, etc.)
- [ ] Register dashboard routes in `cmd/sluice/main.go` on the `http.ServeMux` BEFORE the chi handler pattern, so static files are served without hitting chi's middleware
- [ ] Add `/` and `/assets/` to `BearerAuthMiddleware` bypass list (alongside `/healthz`) so the login page loads without a token. Alternatively, register static routes outside chi entirely.
- [ ] Use chi's `r.NotFound()` for SPA fallback on unknown non-API paths (serves index.html) to avoid shadowing API 404s
- [ ] Write test: GET `/` returns index.html with correct Content-Type (no auth required)
- [ ] Write test: GET `/assets/style.css` returns CSS with correct Content-Type
- [ ] Write test: GET `/nonexistent-route` returns index.html (SPA fallback)
- [ ] Write test: GET `/api/status` still returns JSON (not index.html)
- [ ] Run tests: `go test ./internal/api/ -v -timeout 30s`

### Task 8: Verify acceptance criteria

- [ ] Verify dashboard loads at http://127.0.0.1:3000/
- [ ] Verify all pages render with mock data
- [ ] Verify CRUD operations work for rules, credentials, MCP upstreams
- [ ] Verify audit log pagination and filtering
- [ ] Verify approval flow (pending -> resolve)
- [ ] Verify auth flow (token prompt, sessionStorage, 401 redirect)
- [ ] Verify existing API endpoints still work
- [ ] Verify /healthz and /mcp endpoints unaffected
- [ ] Run full test suite: `go test ./... -v -timeout 30s`

### Task 9: [Final] Update documentation

- [ ] Update CLAUDE.md with dashboard description and file structure
- [ ] Update README.md with dashboard access instructions
- [ ] Move this plan to `docs/plans/completed/`

## Post-Completion

**Manual verification:**
- Test with real sluice instance running proxy + MCP gateway
- Test approval flow end-to-end (agent triggers Ask -> dashboard shows -> user approves)
- Test on different browsers (Chrome, Safari, Firefox)
- Verify dark theme readability

**Future work:**
- Sessions page with risk visualization, signal history, escalation events (requires Plan 21 + `GET /api/sessions` endpoint)
- WebSocket for real-time updates instead of polling
- Audit log graph/timeline visualization
- Rule testing simulator (input destination, see which rule matches)
- Mobile-responsive layout improvements
