# Plan 21: MCP Session Risk Engine

## Overview

Add a session-scoped risk accumulation engine to the MCP gateway. Suspicious events (injection detections, denied tool calls, blocked arguments) contribute risk to the current session. Risk decays over time via TTL. When session risk crosses thresholds, the gateway dynamically escalates policy: Allow -> Ask, Ask -> Deny.

This addresses the gap where Sluice treats every MCP request independently with no memory of prior suspicion. An agent that triggers multiple low-grade signals across tool calls should face increasing scrutiny.

Inspired by Prism's session risk engine with TTL decay and thresholded escalation.

## Context

- `internal/mcp/gateway.go` -- HandleToolCall is the single enforcement point for all MCP tool calls
- `internal/mcp/server_http.go` -- mcpSession tracks session ID, createdAt, lastAccessedAt via sync.Map
- `internal/mcp/transport.go` -- RunStdio implicitly has one session (one stdin/stdout pipe)
- `internal/mcp/inspect.go` -- ContentInspector produces InspectionResult and Findings
- `internal/mcp/injection.go` -- InjectionScorer (from Plan 20) produces scores and InjectionFindings
- `internal/audit/logger.go` -- Event struct, FileLogger with blake3 chain
- `internal/policy/types.go` -- Verdict enum

**Key constraint:** The SOCKS5 proxy layer has no session concept. Risk accumulation is MCP-only. In the single-agent deployment model (one container = one agent), MCP session risk effectively represents the agent's overall suspicion level.

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- **Dependency**: Plan 20 (content security pipeline) should be implemented first since injection scoring feeds risk signals. However, the risk engine can be built independently using generic risk signal types. Plan 20 wires InjectionScorer findings into the risk engine.
- Complete each task fully before moving to the next
- **CRITICAL: every task MUST include new/updated tests**
- **CRITICAL: all tests must pass before starting next task**
- Run `go test ./... -timeout 30s` after each change

## Testing Strategy

- **Unit tests**: Required for every task
- **E2e tests**: Not applicable (internal engine, no new CLI/network surface)

## Progress Tracking

- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with + prefix
- Document issues/blockers with ! prefix

## Solution Overview

```
HandleToolCall(req)
    |
    v
[1] Resolve session ID (HTTP: Mcp-Session-Id header, stdio: fixed "stdio" session)
    |
    v
[2] Check session risk level -> escalate verdict if above threshold
    |         Allow + high risk = Ask
    |         Ask + high risk = Deny
    v
[3] Normal flow (policy eval, inspect args, upstream call, inspect response)
    |
    v
[4] After response: feed risk signals from this call
    |         - Injection score from response scanning
    |         - Denied/blocked tool calls
    |         - Blocked arguments
    v
[5] Return result (possibly with escalated verdict metadata)
```

### Risk Signal Types

| Signal | Source | Default Weight |
|--------|--------|---------------|
| `injection_warn` | InjectionScorer score >= warn threshold | 0.3 |
| `injection_block` | InjectionScorer score >= block threshold | 0.8 |
| `tool_denied` | Policy verdict = Deny | 0.2 |
| `tool_ask_denied` | User denied Ask approval | 0.4 |
| `args_blocked` | ContentInspector blocked arguments | 0.6 |
| `response_redacted` | ContentInspector redacted response content | 0.1 |

### Risk Accumulation

- Each signal adds `weight` to session risk level
- Risk entries carry a TTL (default 5 minutes)
- Expired entries are swept on each `GetRisk()` call (lazy sweep)
- Session risk = sum of non-expired signal weights
- Max risk capped at 1.0

### Escalation Thresholds

| Session Risk | Escalation |
|-------------|------------|
| < 0.3 | No escalation |
| 0.3 - 0.7 | Allow -> Ask |
| > 0.7 | Allow -> Deny, Ask -> Deny |

Thresholds configurable via store config table.

## Technical Details

### Data Structures

```go
// internal/mcp/risk.go

type RiskSignal struct {
    Type      string    // signal type name
    Weight    float64   // 0.0-1.0
    Reason    string    // human-readable reason
    ExpiresAt time.Time // TTL-based expiration
}

type SessionRisk struct {
    mu      sync.Mutex
    signals []RiskSignal
}

type RiskEngine struct {
    sessions sync.Map // session ID -> *SessionRisk
    config   RiskConfig
}

type RiskConfig struct {
    SignalTTL          time.Duration // default 5m
    EscalateAskAt      float64       // default 0.3
    EscalateDenyAt     float64       // default 0.7
}
// Note: SignalWeights map removed (YAGNI). Default weights are hardcoded
// constants. Add configurable weights only when there is a real need.
```

### Integration Points

1. **Session ID resolution**: The session ID must be threaded through the `handleRequest` intermediary (transport.go line 55) which sits between `handlePost`/`RunStdio` and `HandleToolCall`. Options: add session ID parameter to `handleRequest`, or add a non-serialized field to `JSONRPCRequest`, or use a context-based approach. HTTP path: `handlePost` extracts from `Mcp-Session-Id` header, passes to `handleRequest`. Stdio path: `RunStdio` uses constant "stdio", passes to `handleRequest`.

2. **Post-evaluation escalation**: After `policy.Evaluate()` returns a verdict, check session risk. If risk >= threshold, override the verdict upward (Allow->Ask, Ask->Deny). Never downgrade (Deny stays Deny).

3. **Post-call signal feeding**: After HandleToolCall completes (success or failure), feed appropriate risk signals based on what happened during the call.

4. **Audit integration**: Log risk level and any escalation in audit events. New audit fields: `risk_level`, `escalated_from`.

## What Goes Where

- **Implementation Steps**: All code changes, tests, schema migration
- **Post-Completion**: Threshold tuning, observability dashboard integration (Plan D)

## Implementation Steps

### Task 1: Implement core RiskEngine

**Files:**
- Create: `internal/mcp/risk.go`
- Create: `internal/mcp/risk_test.go`

- [ ] Define `RiskSignal`, `SessionRisk`, `RiskEngine`, `RiskConfig` types
- [ ] Implement `NewRiskEngine(cfg RiskConfig) *RiskEngine`
- [ ] Implement `AddSignal(sessionID string, signal RiskSignal)` -- appends signal to session
- [ ] Implement `GetRisk(sessionID string) float64` -- returns sum of non-expired weights, capped at 1.0, with lazy sweep of expired entries
- [ ] Implement `Escalate(sessionID string, verdict policy.Verdict) policy.Verdict` -- returns escalated verdict based on risk thresholds
- [ ] Implement `ClearSession(sessionID string)` -- removes session from map
- [ ] Define default signal weights as package-level map
- [ ] Write tests: AddSignal increases risk level
- [ ] Write tests: GetRisk returns 0 for unknown session
- [ ] Write tests: TTL expiry removes signals from risk calculation
- [ ] Write tests: Risk capped at 1.0 when many signals added
- [ ] Write tests: Escalate returns correct verdict at each threshold level
- [ ] Write tests: Escalate never downgrades (Deny stays Deny)
- [ ] Write tests: ClearSession resets risk to 0
- [ ] Run tests: `go test ./internal/mcp/ -v -timeout 30s`

### Task 2: Thread session ID through MCP gateway

**Files:**
- Modify: `internal/mcp/gateway.go`
- Modify: `internal/mcp/server_http.go`
- Modify: `internal/mcp/transport.go`
- Modify: `internal/mcp/types.go`

- [ ] Add `SessionID string` field to `CallToolParams`
- [ ] Modify `handleRequest(req JSONRPCRequest)` in transport.go to accept session ID parameter: `handleRequest(req JSONRPCRequest, sessionID string)`
- [ ] In `MCPHTTPHandler.handlePost`, extract session ID from `Mcp-Session-Id` header, pass to `handleRequest`
- [ ] In `RunStdio`, pass constant session ID "stdio" to `handleRequest`
- [ ] In `handleRequest`, set `params.SessionID = sessionID` before calling `HandleToolCall`
- [ ] Add `RiskEngine *RiskEngine` field to `Gateway` struct and `GatewayConfig`
- [ ] Verify existing tests still pass with nil RiskEngine (no-op path)
- [ ] Write test: session ID correctly propagated from HTTP handler
- [ ] Write test: stdio transport uses "stdio" session ID
- [ ] Run tests: `go test ./internal/mcp/ -v -timeout 30s`

### Task 3: Integrate risk escalation into HandleToolCall

**Files:**
- Modify: `internal/mcp/gateway.go`
- Modify: `internal/mcp/gateway_test.go`

- [ ] In HandleToolCall, after policy.Evaluate(), call `riskEngine.Escalate(sessionID, verdict)` to get potentially escalated verdict
- [ ] Feed risk signals at appropriate points:
  - After policy Deny: `tool_denied` signal
  - After Ask denied by user: `tool_ask_denied` signal
  - After InspectArguments blocks: `args_blocked` signal
  - After injection scan warn: `injection_warn` signal (requires Plan 20; no-op until InjectionScorer exists)
  - After injection scan block: `injection_block` signal (requires Plan 20; no-op until InjectionScorer exists)
  - After RedactResponse modifies content: `response_redacted` signal (requires modifying RedactResponse to return `(string, bool)` where bool indicates whether any redaction occurred)
- [ ] Add `escalated_from` field to audit event when verdict was escalated
- [ ] Add `risk_level` to governance metadata in tool result
- [ ] Write test: tool call with prior suspicious signals gets escalated from Allow to Ask
- [ ] Write test: tool call with high risk gets escalated from Allow to Deny
- [ ] Write test: denied tool call feeds tool_denied signal
- [ ] Write test: blocked arguments feed args_blocked signal
- [ ] Write test: clean session (no signals) has no escalation
- [ ] Write test: nil RiskEngine skips all risk logic (backward compatibility)
- [ ] Run tests: `go test ./internal/mcp/ -v -timeout 30s`

### Task 4: Add risk configuration to store

**Files:**
- Create: `internal/store/migrations/000003_risk_config.up.sql` (000003 if Plan 20 takes 000002)
- Create: `internal/store/migrations/000003_risk_config.down.sql`
- Modify: `internal/store/store.go`
- Modify: `cmd/sluice/mcp.go`

- [ ] Create migration 000003: `ALTER TABLE config ADD COLUMN risk_signal_ttl_sec INTEGER DEFAULT 300`, `ALTER TABLE config ADD COLUMN risk_escalate_ask REAL DEFAULT 0.3`, `ALTER TABLE config ADD COLUMN risk_escalate_deny REAL DEFAULT 0.7`
- [ ] Create down migration to drop columns
- [ ] Add `RiskSignalTTLSec`, `RiskEscalateAsk`, `RiskEscalateDeny` fields to `Config` struct
- [ ] Update `GetConfig()` SELECT query and Scan call to include new columns
- [ ] Update `ConfigUpdate` struct and `UpdateConfig()` to handle new fields
- [ ] Wire store config fields into RiskConfig when building MCP gateway in cmd/sluice/mcp.go
- [ ] Write tests for GetConfig with default risk config values
- [ ] Write tests for UpdateConfig with custom risk config values
- [ ] Run tests: `go test ./... -timeout 30s`

### Task 5: Add session cleanup on HTTP session delete

**Files:**
- Modify: `internal/mcp/server_http.go`

- [ ] In `handleDelete`, call `gw.riskEngine.ClearSession(sessionID)` when session is deleted
- [ ] In `pruneOldestSession`, call `gw.riskEngine.ClearSession(oldestID)` for evicted sessions
- [ ] Write test: deleting HTTP session clears risk state
- [ ] Write test: pruned session clears risk state
- [ ] Run tests: `go test ./internal/mcp/ -v -timeout 30s`

### Task 6: Verify acceptance criteria

- [ ] Verify risk accumulates across multiple tool calls in same session
- [ ] Verify TTL expiry reduces risk over time
- [ ] Verify escalation thresholds work correctly at boundaries
- [ ] Verify session cleanup on HTTP DELETE and LRU eviction
- [ ] Verify backward compatibility with nil RiskEngine
- [ ] Verify audit events include risk_level and escalation info
- [ ] Run full test suite: `go test ./... -v -timeout 30s`

### Task 7: [Final] Update documentation

- [ ] Update CLAUDE.md with risk engine description
- [ ] Document risk signal types, weights, and escalation thresholds
- [ ] Move this plan to `docs/plans/completed/`

## Post-Completion

**Manual verification:**
- Test risk accumulation with real agent workflows
- Tune signal weights and thresholds based on false escalation rates
- Monitor whether 5-minute TTL is appropriate for typical agent sessions

**Future work:**
- Cross-layer risk: MCP risk escalation triggering SOCKS5 policy tightening
- Risk visualization in web dashboard (Plan D)
- Persistent risk state across gateway restarts
- Per-upstream risk isolation (risk from one upstream doesn't affect others)
