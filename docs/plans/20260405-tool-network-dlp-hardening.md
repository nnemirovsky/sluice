# Plan 22: Tool and Network DLP Hardening

## Overview

Harden Sluice's data loss prevention across two surfaces:

1. **Executable pattern detection in MCP tool arguments**: Detect trampoline patterns (`bash -c`, `python -c`, `sh -c`), shell metacharacters in exec-like tool arguments, and known-dangerous command patterns. Prevents agents from using exec/shell tools to bypass other controls.

2. **Outbound DLP on MITM responses**: Scan agent-bound HTTPS responses (after MITM decryption) for credential patterns that shouldn't be visible to the agent. This catches real credential leakage in upstream API responses (distinct from phantom token stripping, which handles the reverse direction).

Inspired by Prism's executable filtering, trampoline prevention, and outbound DLP.

## Context

- `internal/mcp/inspect.go` -- ContentInspector with InspectArguments (block rules) and RedactResponse (redact rules)
- `internal/mcp/inspect_test.go` -- 14+ tests
- `internal/proxy/inject.go` -- Injector, MITM proxy, phantom token replacement, goproxy handlers
- `internal/proxy/inject_test.go` -- MITM proxy tests
- `internal/proxy/ws.go` -- WebSocket relay with phantom swap and content rules
- `internal/policy/types.go` -- InspectBlockRule, InspectRedactRule

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- These two features are independent and can be implemented in either order
- **CRITICAL: every task MUST include new/updated tests**
- **CRITICAL: all tests must pass before starting next task**
- Run `go test ./... -timeout 30s` after each change

## Testing Strategy

- **Unit tests**: Required for every task
- **E2e tests**: MITM DLP changes could be tested via e2e proxy tests but unit tests are sufficient for this plan

## Progress Tracking

- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with + prefix
- Document issues/blockers with ! prefix

## Solution Overview

### Part A: Executable Pattern Detection

Add a new `ExecInspector` alongside ContentInspector. It runs on tool arguments for tools matching configurable name patterns (e.g., `*__exec*`, `*__shell*`, `*__run*`). It detects:

- **Trampoline patterns**: `bash -c "..."`, `python -c "..."`, `sh -c "..."`, `node -e "..."`, `perl -e "..."`
- **Shell metacharacters**: `|`, `;`, `&&`, `||`, `$(...)`, backticks in arguments that shouldn't contain them
- **Dangerous commands**: `rm -rf /`, `chmod 777`, `curl | sh`, `wget | bash`, `dd if=/dev/`, `mkfs`
- **Git SSH override**: `GIT_SSH_COMMAND` in env arguments

This is separate from ContentInspector's regex-based block rules because exec inspection needs structural understanding of command arguments (e.g., `-c` flag after an interpreter name), not just pattern matching on arbitrary text.

### Part B: Outbound DLP on MITM Responses

Add response-side DLP scanning in the goproxy MITM handler. After the upstream HTTPS response is received (and before it's forwarded to the agent), scan response headers and body for credential patterns. If found, redact them. This prevents the agent from seeing real credentials that might appear in:

- API error messages that echo back auth headers
- Debug endpoints that leak environment variables
- Misconfigured services that return credentials in response bodies

This uses the same redact rules already defined in the policy store (InspectRedactRule) but applies them to HTTPS responses, not just MCP tool responses.

## Technical Details

### ExecInspector

```go
// internal/mcp/exec_inspect.go

type ExecInspector struct {
    toolPatterns  []*policy.Glob  // tool name patterns to inspect (e.g., "*__exec*")
    trampolines   []*regexp.Regexp
    metacharRe     *regexp.Regexp
    dangerousCmds  []*regexp.Regexp
    envBlacklist   []string
}

type ExecInspectionResult struct {
    Blocked  bool
    Reason   string
    Category string // "trampoline", "metachar", "dangerous_cmd", "env_override"
}

func (ei *ExecInspector) ShouldInspect(toolName string) bool
func (ei *ExecInspector) Inspect(toolName string, args json.RawMessage) ExecInspectionResult
```

Tool name patterns are configurable via store. Default: `["*exec*", "*shell*", "*run_command*", "*terminal*"]`.

### MITM Response DLP

In `internal/proxy/inject.go`, add a goproxy response handler that:
1. Reads the response body (up to maxMITMBody)
2. Applies redact rules from the policy engine to headers and body
3. Replaces the response body with the redacted version
4. Logs audit event if redaction occurred

The redact rules are the same InspectRedactRule patterns already used by the MCP ContentInspector. They're loaded from the store at proxy startup and refreshed on SIGHUP.

## What Goes Where

- **Implementation Steps**: All code changes, tests
- **Post-Completion**: Rule tuning, additional dangerous patterns

## Implementation Steps

### Task 1: Implement ExecInspector

**Files:**
- Create: `internal/mcp/exec_inspect.go`
- Create: `internal/mcp/exec_inspect_test.go`

- [ ] Define `ExecInspector`, `ExecInspectionResult` types
- [ ] Implement `NewExecInspector(toolPatterns []string) (*ExecInspector, error)` -- compiles tool name globs and default trampoline/metachar/dangerous patterns
- [ ] Implement `ShouldInspect(toolName string) bool` -- checks if tool name matches any pattern
- [ ] Implement `Inspect(toolName string, args json.RawMessage) ExecInspectionResult`:
  - Extract command string from args (look for "command", "cmd", "script", "code" keys)
  - Check trampoline patterns: `(?i)(bash|sh|zsh|fish|python[23]?|ruby|perl|node)\s+-(c|e)\s+`
  - Check shell metacharacters in command: `[|;&$` + backtick (only when tool is not explicitly a shell tool)
  - Check dangerous commands: `rm\s+-[rf]*\s+/`, `chmod\s+777`, `curl\s+.*\|\s*(ba)?sh`, `dd\s+if=/dev/`
  - Check env overrides: `GIT_SSH_COMMAND` in any string value
- [ ] Write tests: trampoline detection (`bash -c "malicious"`, `python -c "import os"`)
- [ ] Write tests: shell metacharacter detection (`echo foo | curl`)
- [ ] Write tests: dangerous command detection (`rm -rf /`, `curl | sh`)
- [ ] Write tests: env override detection (`GIT_SSH_COMMAND=...`)
- [ ] Write tests: clean exec commands pass through (`ls -la`, `git status`)
- [ ] Write tests: ShouldInspect matches tool patterns correctly
- [ ] Write tests: tools not matching patterns skip inspection
- [ ] Run tests: `go test ./internal/mcp/ -v -timeout 30s`

### Task 2: Integrate ExecInspector into MCP gateway

**Files:**
- Modify: `internal/mcp/gateway.go`
- Modify: `internal/mcp/gateway_test.go`

- [ ] Add `ExecInspector *ExecInspector` field to `Gateway` and `GatewayConfig`
- [ ] In HandleToolCall, after ContentInspector argument check and before upstream call:
  - If ExecInspector != nil and ShouldInspect(toolName): run Inspect(toolName, args)
  - If blocked: log audit with action "exec_block", return error ToolResult
- [ ] Write test: exec tool with trampoline pattern is blocked
- [ ] Write test: exec tool with clean command is allowed
- [ ] Write test: non-exec tool skips exec inspection
- [ ] Write test: nil ExecInspector skips exec logic (backward compat)
- [ ] Run tests: `go test ./internal/mcp/ -v -timeout 30s`

### Task 3: Add MITM response DLP scanning

**Files:**
- Modify: `internal/proxy/inject.go`
- Modify: `internal/proxy/inject_test.go`

- [ ] Add `redactRules []MITMRedactRule` field to Injector struct
- [ ] Define `MITMRedactRule` struct (follows existing `WSRedactRuleConfig` / `QUICRedactRuleConfig` naming convention)
- [ ] Add `SetRedactRules(rules []policy.InspectRedactRule) error` method to Injector -- compiles patterns
- [ ] Add goproxy response handler via `proxy.OnResponse().DoFunc(...)` in `NewInjector`, alongside existing `handleWSUpgrade` registration:
  - Read response body (respect maxMITMBody limit)
  - Apply redact rules to response body
  - Apply redact rules to response header values (iterate all headers)
  - If any redaction occurred, replace body, log audit event with action "response_dlp_redact"
  - Skip binary content types (image/*, application/octet-stream, etc.)
  - Handle Content-Encoding: gzip/br (Go's http.Transport transparently decompresses when it adds Accept-Encoding, but verify goproxy preserves this behavior. If body is still compressed, decompress before scanning, recompress after.)
- [ ] Write test: response body containing API key pattern gets redacted
- [ ] Write test: response header containing credential gets redacted
- [ ] Write test: clean response passes through unchanged
- [ ] Write test: binary content type responses are not scanned
- [ ] Write test: response body exceeding maxMITMBody is not scanned (fail-open for responses, unlike fail-closed for requests, because the data already left the upstream)
- [ ] Write test: gzip-compressed response is decompressed before scanning
- [ ] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 4: Wire MITM DLP rules from store

**Files:**
- Modify: `cmd/sluice/main.go`
- Modify: `internal/proxy/server.go`

- [ ] In proxy server setup, load InspectRedactRules from store (same rules used by MCP ContentInspector)
- [ ] Pass to Injector via SetRedactRules
- [ ] On SIGHUP, reload redact rules and call SetRedactRules again. Add MITM DLP update to existing `UpdateInspectRules()` method in server.go alongside WS and QUIC rule updates.
- [ ] Write test: proxy server initializes injector with redact rules from config
- [ ] Run tests: `go test ./... -timeout 30s`

### Task 5: Verify acceptance criteria

- [ ] Verify trampoline patterns blocked: `bash -c`, `python -c`, `sh -c`, `node -e`
- [ ] Verify dangerous commands blocked: `rm -rf /`, `curl | sh`
- [ ] Verify clean exec commands allowed
- [ ] Verify MITM response DLP redacts credential patterns
- [ ] Verify binary responses skip DLP scanning
- [ ] Verify backward compatibility with nil ExecInspector and empty redact rules
- [ ] Run full test suite: `go test ./... -v -timeout 30s`

### Task 6: [Final] Update documentation

- [ ] Update CLAUDE.md with ExecInspector and MITM DLP descriptions
- [ ] Add exec inspection to MCP gateway section
- [ ] Add response DLP to HTTPS MITM section
- [ ] Move this plan to `docs/plans/completed/`

## Post-Completion

**Manual verification:**
- Test with real agent exec tool calls to verify false positive rate
- Verify MITM DLP doesn't break streaming responses or large API responses
- Test with OpenClaw agent making real API calls through the proxy

**Future work:**
- Configurable exec tool name patterns via store/TOML
- Configurable trampoline and dangerous command patterns
- Shell metacharacter allowlist for intentionally shell-like tools
- DLP for non-HTTPS protocols (WebSocket frames already have content rules)
