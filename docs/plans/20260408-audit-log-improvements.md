# Audit Log Improvements

## Overview

Expand the audit log to capture all security-relevant events (not just policy verdicts) and format the Telegram `/audit` output for readability. Currently the audit log only records allow/deny/ask verdicts from the SOCKS5 policy layer. Credential injections, phantom token swaps, content redactions, OAuth token refreshes, and MCP tool evaluations are invisible.

The Telegram `/audit recent N` command dumps raw JSON lines which are unreadable on mobile. This plan adds human-readable formatting.

## Context

- Audit logger: `internal/audit/audit.go` (FileLogger, Event struct, Log method)
- Audit CLI: `cmd/sluice/audit.go` (verify subcommand)
- Telegram audit command: `internal/telegram/commands.go` (handleAudit)
- MITM credential injection: `internal/proxy/inject.go` (injectCredentials, phantom swap)
- WebSocket content rules: `internal/proxy/ws.go` (deny/redact in frame interceptor)
- OAuth response handler: `internal/proxy/oauth_response.go` (token refresh interception)
- MCP gateway: `internal/mcp/gateway.go` (tool policy evaluation)
- DNS interceptor: `internal/proxy/dns.go` (NXDOMAIN for denied domains)

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- CRITICAL: every task MUST include new/updated tests
- CRITICAL: all tests must pass before starting next task

## Testing Strategy

- Unit tests for new event types and formatting functions
- Integration tests verifying audit events are written during proxy operations
- Existing `audit_test.go` and `e2e/audit_test.go` cover hash chain integrity

## What Goes Where

- **Implementation Steps**: code changes, tests
- **Post-Completion**: deploy and verify on knuth, check Telegram output

## Solution Overview

1. Extend the `audit.Event` struct with an `EventType` field and add new event types
2. Add audit logging calls in credential injection, content inspection, OAuth refresh, and MCP evaluation code paths
3. Reformat Telegram `/audit recent N` output as a compact human-readable list

## Progress Tracking

- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with + prefix
- Document issues/blockers with ! prefix

## Implementation Steps

### Task 1: Extend audit Event with event types

**Files:**
- Modify: `internal/audit/audit.go`
- Modify: `internal/audit/audit_test.go`

- [ ] Add `EventType string` field to `Event` struct (backward compatible, empty = legacy verdict event)
- [ ] Define event type constants: `EventVerdict`, `EventInject`, `EventRedact`, `EventOAuthRefresh`, `EventMCPTool`, `EventDNS`, `EventPhantomStrip`
- [ ] Ensure hash chain integrity is preserved with new fields
- [ ] Write tests for new event types serialization
- [ ] Write tests for backward compat (empty EventType still works)
- [ ] Run tests

### Task 2: Add injection audit events

**Files:**
- Modify: `internal/proxy/inject.go`

- [ ] Log `EventInject` when a credential is injected (binding-based header injection)
- [ ] Log `EventInject` when a phantom token is swapped in request body/headers
- [ ] Log `EventPhantomStrip` when unbound phantom tokens are stripped as safety net
- [ ] Include credential name, destination, port in the event
- [ ] Do NOT log the credential value itself (security)
- [ ] Write tests verifying inject events are logged
- [ ] Run tests

### Task 3: Add content inspection audit events

**Files:**
- Modify: `internal/proxy/ws.go`
- Modify: `internal/mcp/gateway.go`

- [ ] Log `EventRedact` when WebSocket text frame content is redacted by rules
- [ ] Log `EventRedact` when WebSocket text frame is denied by content rules
- [ ] Log `EventMCPTool` when MCP tool call is evaluated (allow/deny/ask + tool name)
- [ ] Log `EventRedact` when MCP response content is redacted by ContentInspector
- [ ] Write tests for content inspection events
- [ ] Run tests

### Task 4: Add OAuth refresh audit events

**Files:**
- Modify: `internal/proxy/oauth_response.go`

- [ ] Log `EventOAuthRefresh` when an OAuth token endpoint response is intercepted
- [ ] Include credential name and whether vault update succeeded
- [ ] Write tests for OAuth refresh events
- [ ] Run tests

### Task 5: Format Telegram audit output

**Files:**
- Modify: `internal/telegram/commands.go`

- [ ] Parse JSON audit lines in `handleAudit`
- [ ] Format each entry as a compact one-liner: `HH:MM:SS VERDICT dest:port (protocol) [reason]`
- [ ] For inject events: `HH:MM:SS INJECT cred_name -> dest:port`
- [ ] For redact events: `HH:MM:SS REDACT dest:port (rule match)`
- [ ] For OAuth events: `HH:MM:SS OAUTH cred_name (refreshed)`
- [ ] For MCP events: `HH:MM:SS MCP tool_name ALLOW|DENY`
- [ ] Group consecutive identical entries with count: `x3` suffix
- [ ] Write tests for formatting functions
- [ ] Run tests

### Task 6: Verify acceptance criteria

- [ ] Verify `/audit recent 10` shows formatted output in Telegram
- [ ] Verify credential injections appear in audit log
- [ ] Verify content redactions appear in audit log
- [ ] Verify hash chain integrity still passes: `sluice audit verify`
- [ ] Run full test suite: `go test ./... -v -timeout 30s`

### Task 7: [Final] Update documentation

- [ ] Update CLAUDE.md audit section with new event types
- [ ] Move this plan to `docs/plans/completed/`

## Post-Completion

**Manual verification:**
- Deploy to knuth, trigger various operations (web fetch, credential injection, MCP tool call)
- Run `/audit recent 20` in sluice Telegram bot and verify readable output
- Run `sluice audit verify` to confirm hash chain integrity
