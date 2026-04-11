# Per-Request Policy Evaluation for HTTP/HTTPS and QUIC/HTTP3

## Overview

Move policy evaluation from the SOCKS5 CONNECT level (per-TCP-connection) to the HTTP request level for HTTP/HTTPS and QUIC/HTTP3. Currently "Allow Once" allows all HTTP requests on a keep-alive connection because policy is only checked when the TCP connection is established.

After this change, "Allow Once" means one HTTP request. Subsequent requests on the same keep-alive connection re-trigger the approval flow. gRPC is covered automatically since it rides over HTTP/2 through the same goproxy handler.

**Out of scope**: WebSocket (per-upgrade is correct since it's a single session), SSH (per-connection is correct since channels are part of one session), IMAP/SMTP (per-connection is correct since it's one mailbox session). Per-message/per-command policy on these protocols would hit the broker's 5/min rate limit and break normal usage.

## Context

- Policy evaluation: `internal/proxy/server.go` (Allow method)
- HTTP/HTTPS MITM: `internal/proxy/inject.go` (goproxy OnRequest handler, `injectCredentials()`)
- QUIC/HTTP3: `internal/proxy/quic.go` (HTTP handler in `buildHandler()`)
- Approval broker: `internal/channel/broker.go`
- Policy engine: `internal/policy/engine.go` (`Evaluate()`)
- Telegram messages: `internal/telegram/bot.go` (`FormatApprovalMessage()`)

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- CRITICAL: every task MUST include new/updated tests
- CRITICAL: all tests must pass before starting next task

## Testing Strategy

- **Unit tests**: mock the broker and policy engine to test allow-once consumption, fast-path skip, and approval blocking
- **Integration tests**: existing proxy tests in `internal/proxy/server_test.go` exercise the full SOCKS5 -> MITM -> upstream chain. Add test cases for allow-once with two sequential HTTP requests on the same connection.
- **e2e tests**: add an e2e test that makes two HTTP requests to an ask-verdict destination on the same keep-alive connection and verifies the second request triggers a new approval

## What Goes Where

- **Implementation Steps**: code changes, tests, documentation
- **Post-Completion**: manual deployment verification, performance measurement

## Solution Overview

Add a per-connection `RequestPolicyChecker` that HTTP handlers call before forwarding each request.

**Lifecycle**: one `RequestPolicyChecker` per SOCKS5 connection. Created in `Allow()`, stored in the request context, passed to the goproxy handler via `ProxyCtx.UserData`.

**Fast path**: if the SOCKS5 CONNECT evaluated to "allow" from an explicit rule match (not default verdict), per-request checks are skipped. This requires `EvaluateDetailed()` on the policy engine to distinguish rule-match from default.

**Allow-once flow**: when an "ask" verdict is approved once, the checker permits one HTTP request then marks the approval as consumed. The next request on the same connection re-triggers the ask flow via the broker.

**Always-allow/deny**: these persist rules to the store and recompile the engine. Subsequent connections (and requests) are handled by the engine directly. No per-request tracking needed.

## Technical Details

**RequestPolicyChecker** (per-SOCKS5-connection):
- `CheckAndConsume(dest, port) -> (Verdict, error)`: evaluates policy, triggers broker if "ask", consumes allow-once approval, returns final verdict
- Internal state: `allowedOnce map[string]bool` keyed on `dest:port`, set to true on first allow-once approval, deleted after consumption
- Thread-safe (multiple HTTP requests can arrive concurrently on HTTP/2)

**EvaluateDetailed** on policy.Engine:
- Returns `(Verdict, MatchSource)` where MatchSource is `RuleMatch` or `DefaultVerdict`
- Allows the fast path to distinguish "this host is explicitly allowed" from "default verdict is allow"

**goproxy plumbing**:
- `ProxyCtx.UserData` currently carries pin ID (string). Change to a struct `proxyConnState{pinID string, checker *RequestPolicyChecker}`
- The SOCKS5 dial function (`server.go dial()`) sets UserData when routing through the injector

## Progress Tracking

- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with + prefix
- Document issues/blockers with ! prefix
- Update plan if implementation deviates from original scope

## Implementation Steps

### Task 1: Add EvaluateDetailed to policy engine

**Files:**
- Modify: `internal/policy/engine.go`
- Modify: `internal/policy/engine_test.go`

- [x] Add `MatchSource` type (`RuleMatch`, `DefaultVerdict`)
- [x] Add `EvaluateDetailed(dest, port) (Verdict, MatchSource)` method
- [x] Refactor existing `Evaluate()` to call `EvaluateDetailed()` internally
- [x] Write tests for EvaluateDetailed: explicit rule returns RuleMatch
- [x] Write tests for EvaluateDetailed: default verdict returns DefaultVerdict
- [x] Run tests

### Task 2: Add RequestPolicyChecker

**Files:**
- Create: `internal/proxy/request_policy.go`
- Create: `internal/proxy/request_policy_test.go`

- [x] Create `RequestPolicyChecker` struct with `allowedOnce` map and mutex
- [x] Implement `CheckAndConsume(dest, port) (Verdict, error)` that checks engine, triggers broker if ask, tracks allow-once
- [x] On allow-once response: permit current request, mark `(dest, port)` as consumed
- [x] On subsequent check for consumed `(dest, port)`: re-trigger ask flow
- [x] On always-allow response: permit without tracking (engine handles persistence)
- [x] Write tests: allow-once consumed after one call
- [x] Write tests: second call to consumed dest re-triggers ask
- [x] Write tests: always-allow not consumed
- [x] Write tests: deny returns immediately
- [x] Run tests

### Task 3: Wire RequestPolicyChecker into SOCKS5 context

**Files:**
- Modify: `internal/proxy/server.go`
- Modify: `internal/proxy/inject.go`

- [ ] Add context key `ctxKeyPerRequestPolicy`
- [ ] In `Allow()`, use `EvaluateDetailed()`. If verdict is allow + RuleMatch, set context flag "skip per-request"
- [ ] In `Allow()`, for ask-approved connections, create `RequestPolicyChecker` and store in context
- [ ] For SNI-deferred connections, create checker in `sniPolicyCheck()`
- [ ] Change `ProxyCtx.UserData` from string to `proxyConnState` struct carrying pin ID and checker
- [ ] Update `dial()` to pass checker via UserData
- [ ] Write tests for context propagation
- [ ] Run tests

### Task 4: Per-request policy in HTTP/HTTPS MITM

**Files:**
- Modify: `internal/proxy/inject.go`

- [ ] In `injectCredentials()`, extract checker from `ProxyCtx.UserData`
- [ ] If checker is nil (explicit allow, no per-request check), proceed as before
- [ ] If checker present, call `CheckAndConsume(host, port)` before credential injection
- [ ] If verdict is deny/timeout, return `goproxy.NewResponse` with 403
- [ ] If verdict is allow (from ask approval), proceed with injection
- [ ] Note: gRPC is automatically covered (same handler, uses HTTP/2 path in goproxy)
- [ ] Write tests: allow-once blocks second request on same connection
- [ ] Write tests: explicit allow skips per-request check
- [ ] Write tests: gRPC request goes through per-request check
- [ ] Run tests

### Task 5: Per-request policy in QUIC/HTTP3

**Files:**
- Modify: `internal/proxy/quic.go`

- [ ] In `buildHandler()` HTTP handler, add checker from connection state
- [ ] Same logic as HTTP/HTTPS: check before injection, deny with 403, consume allow-once
- [ ] Write tests for QUIC per-request policy
- [ ] Run tests

### Task 6: Update Telegram approval messages with request context

**Files:**
- Modify: `internal/channel/channel.go`
- Modify: `internal/telegram/bot.go`

- [ ] Add optional `Method` and `Path` fields to `ApprovalRequest`
- [ ] Update `FormatApprovalMessage()`: show "GET https://example.com/path" for per-request approvals
- [ ] Add "(per-request)" label to distinguish from connection-level approvals
- [ ] Write tests for updated message formatting
- [ ] Run tests

### Task 7: Verify acceptance criteria

- [ ] Verify "Allow Once" blocks second HTTP request to same host on same connection
- [ ] Verify "Always Allow" allows all requests (rule persisted, engine handles it)
- [ ] Verify explicit allow rules skip per-request checks (no performance regression)
- [ ] Verify per-request policy works for QUIC/HTTP3
- [ ] Verify gRPC requests trigger per-request checks
- [ ] Run full test suite: `go test ./... -v -timeout 30s`
- [ ] Verify test coverage meets 70% threshold

### Task 8: [Final] Update documentation

- [ ] Update CLAUDE.md: document per-request policy for HTTP/HTTPS/QUIC, note that WebSocket/SSH/IMAP stay connection-level
- [ ] Update README.md protocol table
- [ ] Move this plan to `docs/plans/completed/`

## Post-Completion

**Manual verification:**
- Deploy to knuth and test "Allow Once" with HTTP keep-alive (fetch same URL twice)
- Verify approval messages show HTTP method and path
- Verify WebSocket connections (MCP gateway) still work without per-message approval
- Measure latency impact of per-request policy checks under normal usage
