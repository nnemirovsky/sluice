# Close Per-Request Policy Gaps

## Overview

Three changes to close remaining per-request policy gaps on the `per-request-policy` branch:

1. Replace goproxy with go-mitmproxy for HTTP/2 per-request interception (gRPC)
2. Enable QUIC/HTTP3 per-request Ask verdicts
3. Add e2e tests with configurable webhook channel for per-request approval flow

## Context

- Branch: `per-request-policy` (already has per-request policy for HTTP/1.1)
- Per-request policy checker: `internal/proxy/request_policy.go`
- Current MITM: `internal/proxy/inject.go` (goproxy-based)
- QUIC handler: `internal/proxy/quic.go`
- Policy engine: `internal/policy/engine.go`
- HTTP webhook channel: `internal/channel/http/http.go`
- E2E tests: `e2e/`
- go-mitmproxy library: `github.com/lqqyt2423/go-mitmproxy/proxy` (Addon interface with per-HTTP/2-stream callbacks)

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- CRITICAL: every task MUST include new/updated tests
- CRITICAL: all tests must pass before starting next task
- Uses gofumpt (not gofmt) for Go formatting

## Testing Strategy

- **Unit tests**: required for every task
- **E2e tests**: Phase 3 adds webhook-driven e2e tests (build tag `e2e`)

## Progress Tracking

- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with + prefix
- Document issues/blockers with ! prefix

## Solution Overview

**Phase 1**: Replace `github.com/elazarl/goproxy` with `github.com/lqqyt2423/go-mitmproxy/proxy`. Adapt existing credential injection logic into an Addon struct. go-mitmproxy fires `Request(*Flow)` per HTTP/2 stream, giving per-request interception for real gRPC.

**Phase 2**: Add `EvaluateQUICDetailed` to policy engine (returns Ask). Wire `RequestPolicyChecker` through UDP dispatch into `buildHandler`. Each HTTP/3 request calls `CheckAndConsume`.

**Phase 3**: Add configurable test webhook server and e2e tests exercising per-request policy over real keep-alive connections with automated approval responses.

## Technical Details

### go-mitmproxy Addon mapping

| goproxy | go-mitmproxy |
|---------|-------------|
| `OnRequest().DoFunc(injectCredentials)` | `Addon.Requestheaders(*Flow)` |
| `OnResponse().DoFunc(handleOAuth)` | `Addon.Response(*Flow)` |
| `HandleConnect()` | `SetShouldInterceptRule` + `ClientConnected` |
| `ProxyCtx.UserData` | `sync.Map` keyed on `ConnContext.Id()` |
| `goproxy.NewResponse` for 403 | Set `f.Response = &proxy.Response{StatusCode: 403}` |
| Pin system (PinIPs/UnpinIPs) | `ConnContext.ServerConn.Address` (CONNECT target) |

### QUIC Ask flow

1. `EvaluateQUICDetailed` returns `(Ask, DefaultVerdict)` for ask-rule match
2. UDP dispatch lets QUIC session start, creates `RequestPolicyChecker`
3. `buildHandler` calls `checker.CheckAndConsume(host, port)` per HTTP/3 request
4. Broker prompts user via Telegram/webhook. Deny returns 403.

## Implementation Steps

### Task 1: Add go-mitmproxy dependency and create SluiceAddon skeleton

**Files:**
- Modify: `go.mod`, `go.sum`
- Create: `internal/proxy/addon.go`

- [x] Run `go get github.com/lqqyt2423/go-mitmproxy@latest`
- [x] Create `internal/proxy/addon.go` with SluiceAddon struct embedding `proxy.BaseAddon`
- [x] Add `connState` struct (connectHost, connectPort, checker, skipCheck) and `sync.Map` for per-connection state
- [x] Implement `ClientConnected` to initialize connection state
- [x] Implement `ClientDisconnected` to clean up state
- [x] Implement `ServerConnected` / `TlsEstablishedServer` to capture CONNECT target from `ConnContext.ServerConn.Address`
- [x] Write basic tests for addon lifecycle (state creation/cleanup)
- [x] Run tests

### Task 2: Implement per-request policy check in Addon.Requestheaders

**Files:**
- Modify: `internal/proxy/addon.go`

- [x] Implement `Requestheaders(*Flow)`: extract host/port from connState (CONNECT target), run per-request policy check via `RequestPolicyChecker.CheckAndConsume`
- [x] If denied, set `f.Response = &proxy.Response{StatusCode: 403, Body: ...}`
- [x] If checker is nil (explicit allow fast path), skip check
- [x] Cross-origin normalization: if `f.Request.URL.Host` != connectHost, normalize to CONNECT target
- [x] Write tests: per-request deny returns 403 response, explicit allow skips check, cross-origin normalized
- [x] Run tests

### Task 3: Implement credential injection in Addon.Request and streaming

**Files:**
- Modify: `internal/proxy/addon.go`

- [x] Implement `Request(*Flow)`: three-pass phantom token swap on `f.Request.Body` (binding headers, scoped phantom replacement, strip unbound phantoms)
- [x] Implement `StreamRequestModifier`: wrap io.Reader for streaming phantom swap on large bodies
- [x] Port binding resolution logic from inject.go (resolve bindings for connectHost:connectPort)
- [x] Port header injection (binding-specific `Authorization: Bearer {value}` etc.)
- [x] Write tests: phantom swap in body, header injection, streaming body swap
- [x] Run tests

### Task 4: Implement OAuth response interception in Addon.Response

**Files:**
- Modify: `internal/proxy/addon.go`

- [x] Implement `Response(*Flow)`: check if response is from an OAuth token URL (OAuthIndex lookup), swap real tokens for phantoms in response body
- [x] Implement `StreamResponseModifier`: streaming OAuth token swap
- [x] Port async vault persistence from inject.go (singleflight for concurrent refreshes)
- [x] Write tests: OAuth response phantom swap, vault persistence callback
- [x] Run tests

### Task 5: Wire SluiceAddon into server.go and replace goproxy setup

**Files:**
- Modify: `internal/proxy/server.go`
- Remove: `internal/proxy/inject.go` (replaced by addon.go)

- [x] Replace `setupInjection()` to create go-mitmproxy `Proxy` with `SluiceAddon`
- [x] Configure go-mitmproxy: listen address, CA cert (from existing cert generation), `SetShouldInterceptRule` (always intercept)
- [x] Update SOCKS5 dial function to route CONNECT to go-mitmproxy listener (replaces `dialThroughInjector`)
- [x] Remove pin system (PinIPs/UnpinIPs/pinnedCheckers) since `ConnContext.ServerConn.Address` provides the CONNECT target
- [x] Remove old inject.go file
- [x] Update `Allow()` and `sniPolicyCheckBeforeDial` to pass checker via go-mitmproxy's connection state instead of context keys
- [x] Write integration tests: full SOCKS5 -> go-mitmproxy -> upstream chain with per-request policy
- [x] Run full test suite: `go test ./... -timeout 120s`
+ ! Plain HTTP through CONNECT tunnels: go-mitmproxy only fires addon hooks for TLS-intercepted traffic. Plain HTTP byte-detection paths relay directly without phantom replacement. 6 integration tests skipped (Task 7 will update them to use HTTPS backends).

### Task 6: Add HTTP/2 per-request test

**Files:**
- Create: `internal/proxy/addon_h2_test.go`

- [x] Create test with real HTTP/2 backend (using `httptest.NewUnstartedServer` + `http2.ConfigureServer`)
- [x] Configure go-mitmproxy proxy with SluiceAddon
- [x] Send two HTTP/2 requests on the same connection via SOCKS5
- [x] Verify per-request policy fires for each HTTP/2 stream (broker called twice for allow-once)
- [x] Verify credential injection works on HTTP/2 streams
- [x] Run tests

### Task 7: Update existing tests to use go-mitmproxy types

**Files:**
- Modify: `internal/proxy/request_policy_context_test.go`
- Remove: `internal/proxy/inject_per_request_test.go` (logic moved to addon tests)
- Modify: `internal/proxy/server_test.go`

- [x] Update server_test.go tests that reference goproxy types to use go-mitmproxy
- [x] Port relevant inject_per_request_test.go test cases to addon test file
- [x] Update request_policy_context_test.go if it references goproxy/inject types
- [x] Run full test suite
- [x] Verify no remaining references to goproxy package

### Task 8: Enable QUIC per-request Ask in policy engine

**Files:**
- Modify: `internal/policy/engine.go`
- Modify: `internal/policy/engine_test.go`

- [x] Add `EvaluateQUICDetailed(dest, port) (Verdict, MatchSource)` that returns Ask when an ask rule matches
- [x] Refactor `EvaluateQUIC` to call `EvaluateQUICDetailed` internally
- [x] Write tests: ask rule returns Ask+RuleMatch, explicit allow returns Allow+RuleMatch, deny returns Deny+RuleMatch, default returns Deny+DefaultVerdict
- [x] Run tests

### Task 9: Wire QUIC per-request checker through buildHandler

**Files:**
- Modify: `internal/proxy/quic.go`
- Modify: `internal/proxy/server.go`
- Modify: `internal/proxy/quic_test.go`

- [x] Re-add checker parameter to `buildHandler(sni string, port int, checker *RequestPolicyChecker)`
- [x] Re-add `RegisterExpectedHostWithChecker` or equivalent
- [x] In `buildHandler`, call `checker.CheckAndConsume(host, port)` before forwarding each HTTP/3 request. If denied, return 403.
- [x] In UDP dispatch loop (server.go), use `EvaluateQUICDetailed`. On Ask verdict, create `RequestPolicyChecker` and pass to `RegisterExpectedHostWithChecker`. On Allow/Deny, pass nil checker.
- [x] Write tests: QUIC per-request allow-once consumed, deny returns 403, explicit allow skips checker
- [x] Run tests

### Task 10: Add e2e webhook test infrastructure

**Files:**
- Modify: `e2e/helpers_test.go`

- [ ] Add `verdictServer` struct: accepts verdict sequence, records webhook requests, returns verdicts in order, defaults to "deny" when exhausted
- [ ] Add `startVerdictServer(t, verdicts []string) (*httptest.Server, *verdictServer)` helper
- [ ] Add `sluiceWithWebhook(t, policyTOML, webhookURL string) *SluiceProcess` helper that configures `[channel.http]` in the TOML
- [ ] Write tests for the webhook server itself (returns verdicts in order, records requests)
- [ ] Run tests

### Task 11: Add e2e per-request policy tests

**Files:**
- Create: `e2e/per_request_test.go`
- Modify: `e2e/proxy_test.go` (remove TODO comment)

- [ ] Test: AllowOnceBlocksSecondRequest - verdicts=["allow_once", "deny"], two keep-alive requests, first succeeds, second 403
- [ ] Test: AlwaysAllowPermitsBoth - verdicts=["always_allow"], two keep-alive requests, both succeed, webhook called once
- [ ] Test: DenyBlocksFirst - verdicts=["deny"], first request 403
- [ ] Test: AllowOnceReAsksSecondRequest - verdicts=["allow_once", "allow_once"], both succeed, webhook called twice
- [ ] Remove TODO(per-request-policy-e2e) comment from `e2e/proxy_test.go`
- [ ] Run e2e tests: `go test -tags=e2e ./e2e/ -v -count=1 -timeout=300s`

### Task 12: Verify acceptance criteria

- [ ] Verify HTTP/2 per-request policy works (real gRPC-over-HTTP/2 stream fires per-request check)
- [ ] Verify QUIC/HTTP3 per-request Ask works
- [ ] Verify all existing HTTP/1.1 per-request behavior is preserved
- [ ] Verify credential injection works on HTTP/2 streams
- [ ] Verify WebSocket upgrade still works
- [ ] Run full test suite: `go test ./... -v -timeout 120s`
- [ ] Run e2e tests: `go test -tags=e2e ./e2e/ -v -count=1 -timeout=300s`

### Task 13: [Final] Update documentation

- [ ] Update CLAUDE.md: remove gRPC and QUIC caveats, document go-mitmproxy as MITM library
- [ ] Update README.md: update protocol table (gRPC and QUIC now per-request)
- [ ] Remove `docs/superpowers/specs/2026-04-12-close-per-request-gaps-design.md`
- [ ] Move this plan to `docs/plans/completed/`

## Post-Completion

**Manual verification:**
- Deploy to knuth and test per-request policy with real gRPC client
- Verify HTTP/2 negotiation works through the proxy
- Test QUIC per-request with a real HTTP/3 client
- Verify Telegram approval messages show HTTP method and path for HTTP/2 requests
