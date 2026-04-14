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

- [x] Define `ExecInspector`, `ExecInspectionResult` types
- [x] Implement `NewExecInspector(toolPatterns []string) (*ExecInspector, error)` -- compiles tool name globs and default trampoline/metachar/dangerous patterns
- [x] Implement `ShouldInspect(toolName string) bool` -- checks if tool name matches any pattern
- [x] Implement `Inspect(toolName string, args json.RawMessage) ExecInspectionResult`:
  - Extract command string from args (look for "command", "cmd", "script", "code" keys)
  - Check trampoline patterns: `(?i)(bash|sh|zsh|fish|python[23]?|ruby|perl|node)\s+-(c|e)\s+`
  - Check shell metacharacters in command: `[|;&$` + backtick (only when tool is not explicitly a shell tool)
  - Check dangerous commands: `rm\s+-[rf]*\s+/`, `chmod\s+777`, `curl\s+.*\|\s*(ba)?sh`, `dd\s+if=/dev/`
  - Check env overrides: `GIT_SSH_COMMAND` in any string value
- [x] Write tests: trampoline detection (`bash -c "malicious"`, `python -c "import os"`)
- [x] Write tests: shell metacharacter detection (`echo foo | curl`)
- [x] Write tests: dangerous command detection (`rm -rf /`, `curl | sh`)
- [x] Write tests: env override detection (`GIT_SSH_COMMAND=...`)
- [x] Write tests: clean exec commands pass through (`ls -la`, `git status`)
- [x] Write tests: ShouldInspect matches tool patterns correctly
- [x] Write tests: tools not matching patterns skip inspection
- [x] Run tests: `go test ./internal/mcp/ -v -timeout 30s`

### Task 2: Integrate ExecInspector into MCP gateway

**Files:**
- Modify: `internal/mcp/gateway.go`
- Modify: `internal/mcp/gateway_test.go`

- [x] Add `ExecInspector *ExecInspector` field to `Gateway` and `GatewayConfig`
- [x] In HandleToolCall, after ContentInspector argument check and before upstream call:
  - If ExecInspector != nil and ShouldInspect(toolName): run Inspect(toolName, args)
  - If blocked: log audit with action "exec_block", return error ToolResult
- [x] Write test: exec tool with trampoline pattern is blocked
- [x] Write test: exec tool with clean command is allowed
- [x] Write test: non-exec tool skips exec inspection
- [x] Write test: nil ExecInspector skips exec logic (backward compat)
- [x] Run tests: `go test ./internal/mcp/ -v -timeout 30s`

### Task 3: Add MITM response DLP scanning

**Files:**
- Modify: `internal/proxy/addon.go` (plan said `inject.go`, renamed after go-mitmproxy migration; response DLP wired into existing `SluiceAddon.Response` method instead of `proxy.OnResponse().DoFunc`)
- Create: `internal/proxy/response_dlp.go` (new file for `MITMRedactRule`, `SetRedactRules`, `scanResponseForDLP`, `applyResponseDLP`, `isBinaryContentType`, `isHopByHopHeader`, `logDLPAudit`)
- Create: `internal/proxy/response_dlp_test.go` (tests added here rather than `inject_test.go`)

- [x] Add `redactRules []MITMRedactRule` field to Injector struct (added to `SluiceAddon` as `atomic.Pointer[[]mitmRedactRule]` for lock-free hot reload)
- [x] Define `MITMRedactRule` struct (follows existing `WSRedactRuleConfig` / `QUICRedactRuleConfig` naming convention)
- [x] Add `SetRedactRules(rules []policy.InspectRedactRule) error` method to Injector -- compiles patterns (method on `SluiceAddon`, atomic swap)
- [x] Add goproxy response handler via `proxy.OnResponse().DoFunc(...)` in `NewInjector`, alongside existing `handleWSUpgrade` registration (implemented instead via go-mitmproxy's `SluiceAddon.Response` callback which fires on every response):
  - Read response body (respect maxMITMBody limit) -- use existing `maxProxyBody` (16 MiB) from `phantom_pairs.go`
  - Apply redact rules to response body
  - Apply redact rules to response header values (iterate all headers)
  - If any redaction occurred, replace body, log audit event with action "response_dlp_redact"
  - Skip binary content types (image/*, application/octet-stream, etc.)
  - Handle Content-Encoding: gzip/br -- go-mitmproxy's attacker sets `DisableCompression: true` on its transport, so compressed bodies reach `Response`. Use `f.Response.ReplaceToDecodedBody()` (supports gzip, br, deflate, zstd) before scanning; agent then receives plaintext (`Content-Encoding` removed).
- [x] Write test: response body containing API key pattern gets redacted (`TestResponseDLP_BodyRedacted`)
- [x] Write test: response header containing credential gets redacted (`TestResponseDLP_HeaderRedacted`)
- [x] Write test: clean response passes through unchanged (`TestResponseDLP_CleanResponseUnchanged`)
- [x] Write test: binary content type responses are not scanned (`TestResponseDLP_BinaryContentTypeSkipped`)
- [x] Write test: response body exceeding maxMITMBody is not scanned (`TestResponseDLP_OversizedBodySkipped`, fail-open)
- [x] Write test: gzip-compressed response is decompressed before scanning (`TestResponseDLP_GzipDecompressedAndScanned`)
- [x] Run tests: `go test ./internal/proxy/ -v -timeout 60s`

### Task 4: Wire MITM DLP rules from store

**Files:**
- Modify: `internal/proxy/server.go` (startup load in `setupInjection` and SIGHUP path in `UpdateInspectRules`; `cmd/sluice/main.go` needs no changes because its SIGHUP handler already calls `srv.UpdateInspectRules`)
- Modify: `internal/proxy/server_test.go` (tests added here: `TestServerLoadsInitialMITMRedactRules`, `TestServerNoInitialMITMRedactRulesWhenEmpty`, `TestUpdateInspectRulesPropagatesToMITMAddon`)

- [x] In proxy server setup, load InspectRedactRules from store (same rules used by MCP ContentInspector) -- wired in `setupInjection` after `NewSluiceAddon`, reading from `cfg.Policy.InspectRedactRules`
- [x] Pass to Injector via SetRedactRules (method exists on `SluiceAddon`; plan errata confirmed the real type name)
- [x] On SIGHUP, reload redact rules and call SetRedactRules again. Add MITM DLP update to existing `UpdateInspectRules()` method in server.go alongside WS and QUIC rule updates.
- [x] Write test: proxy server initializes injector with redact rules from config (`TestServerLoadsInitialMITMRedactRules`, plus `TestServerNoInitialMITMRedactRulesWhenEmpty` for the empty case and `TestUpdateInspectRulesPropagatesToMITMAddon` for the SIGHUP path)
- [x] Run tests: `go test ./... -timeout 30s`

### Task 5: Verify acceptance criteria

- [x] Verify trampoline patterns blocked: `bash -c`, `python -c`, `sh -c`, `node -e` -- covered by `TestExecInspectorTrampolineDetection` subtests `bash_-c`, `sh_-c`, `python_-c`, `node_-e` (plus `zsh_-c`, `dash_-c`, `python3_-c`, `ruby_-e`, `perl_-e`, `nodejs_-e`) in `internal/mcp/exec_inspect_test.go`. Gateway-level integration covered by `TestGatewayExecInspectorBlocksTrampoline` in `internal/mcp/gateway_test.go`.
- [x] Verify dangerous commands blocked: `rm -rf /`, `curl | sh` -- covered by `TestExecInspectorDangerousCommandDetection` subtests `rm_-rf_root`, `curl_pipe_sh` (plus `rm_-rf_home`, `chmod_777`, `curl_pipe_bash`, `wget_pipe_sh`, `dd_if_dev`, `mkfs`) in `internal/mcp/exec_inspect_test.go`. Audit side effect covered by `TestGatewayExecInspectorBlockAuditLogged` which exercises `rm -rf /` end-to-end.
- [x] Verify clean exec commands allowed -- covered by `TestExecInspectorCleanCommands` (ls, git status, go test, cat, pwd, whoami, find) in `internal/mcp/exec_inspect_test.go` and `TestGatewayExecInspectorAllowsCleanCommand` in `internal/mcp/gateway_test.go`.
- [x] Verify MITM response DLP redacts credential patterns -- covered by `TestResponseDLP_BodyRedacted` (uses `AKIA[A-Z0-9]{16}` AWS access-key pattern) and `TestResponseDLP_HeaderRedacted` (Bearer token pattern) in `internal/proxy/response_dlp_test.go`. `TestResponseDLP_MultipleRulesApplied`, `TestResponseDLP_GzipDecompressedAndScanned`, and `TestResponseDLP_BrotliDecompressedAndScanned` extend coverage.
- [x] Verify binary responses skip DLP scanning -- covered by `TestResponseDLP_BinaryContentTypeSkipped` (tests image/png, image/jpeg, video/mp4, audio/mpeg, application/octet-stream, application/pdf, application/zip, font/woff2) and the pure unit test `TestIsBinaryContentType` in `internal/proxy/response_dlp_test.go`.
- [x] Verify backward compatibility with nil ExecInspector and empty redact rules -- nil ExecInspector covered by `TestGatewayNilExecInspectorSkipsLogic` in `internal/mcp/gateway_test.go` and by `TestExecInspectorNilSafe` in `internal/mcp/exec_inspect_test.go`. Empty redact rules covered by `TestResponseDLP_NoRulesNoOp` and `TestSetRedactRules_EmptyDisables` in `internal/proxy/response_dlp_test.go`.
- [x] Run full test suite: `go test ./... -v -timeout 30s` -- full suite passes with the default 30s timeout. All packages green (`cmd/sluice`, `internal/api`, `internal/audit`, `internal/channel`, `internal/channel/http`, `internal/container`, `internal/mcp`, `internal/policy`, `internal/proxy`, `internal/store`, `internal/telegram`, `internal/vault`). `gofumpt -l internal/ cmd/ e2e/` prints nothing. `go vet ./...` reports no issues.

### Task 6: [Final] Update documentation

- [x] Update CLAUDE.md with ExecInspector and MITM DLP descriptions
- [x] Add exec inspection to MCP gateway section
- [x] Add response DLP to HTTPS MITM section
- [x] Move this plan to `docs/plans/completed/`

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
- **Stream-aware DLP scanning.** go-mitmproxy auto-promotes `Content-Type: text/event-stream` responses (SSE, LLM streaming completions) and bodies above `StreamLargeBodies` (default 5 MiB) to `f.Stream=true`, which skips the `Response` addon callback. Today sluice logs a one-shot per-connection WARNING when DLP rules are configured and the stream path fires, but does not scan the stream. Implementing chunked regex scanning over the streaming reader (via `StreamResponseModifier`) closes this gap for the SSE and 5 MiB to 16 MiB body ranges. `TestResponseDLP_SSEStreamingBypassed` documents the current (flawed) behavior so the regression is visible when a future PR addresses this.
