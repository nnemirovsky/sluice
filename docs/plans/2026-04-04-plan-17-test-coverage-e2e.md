# Plan 17: Test Coverage and End-to-End Testing

## Overview

Raise test coverage from 59.5% to 85%+ with meaningful tests (not coverage padding), add a comprehensive end-to-end test suite under `e2e/`, and add GitHub Actions workflows for e2e testing on both Linux (Docker) and macOS (Apple Container) runners.

**Problem:** Several critical packages are under-tested: `cmd/sluice` (33.6%), `internal/telegram` (45.2%), `internal/proxy` (56.9%), `internal/policy` (67.9%). The entire approval system (`approval.go`) is a 1-line stub. No e2e tests exist. CI only runs unit tests. Real integration scenarios (proxy + policy + credential injection + MCP gateway + Telegram approval) are never tested together.

**Solution:** Fill unit test gaps in all packages below 80%. Build an e2e test suite that spins up sluice, configures policies, makes connections through the proxy, verifies credential injection, and tests the full MCP gateway flow. Add CI workflows for both platforms.

**Depends on:** Plans 8-9 (SQLite store, Channel interface) completed. Plan 16 (Apple Container) for macOS e2e tests.

## Context

**Current coverage:**

| Package | Coverage | Target |
|---------|----------|--------|
| cmd/sluice | 33.6% | 75%+ |
| internal/telegram | 45.2% | 80%+ |
| internal/proxy | 56.9% | 80%+ |
| internal/policy | 67.9% | 85%+ |
| internal/vault | 70.2% | 85%+ |
| internal/store | 75.6% | 85%+ |
| internal/mcp | 77.9% | 85%+ |
| internal/docker | 85.6% | 85%+ |
| internal/channel | 84.7% | 85%+ |
| internal/audit | 85.7% | 85%+ |

**Key untested areas:**
- CLI entry points and all policy subcommand handlers
- Certificate generation (`cert generate`)
- Policy engine mutation methods (AddDynamicAllow, RemoveRule, etc.)
- Entire Telegram approval flow (approval.go is a 1-line stub)
- Proxy internals: dialThroughInjector, IP pinning, protocol context
- Proxy setup with credential injection pipeline

**New files:**
- `e2e/` directory with test files
- `.github/workflows/e2e-linux.yml`
- `.github/workflows/e2e-macos.yml`

## Development Approach

- **Testing approach**: Regular (write the code/refactoring, then tests)
- This plan IS about writing tests, so every task is primarily test code
- No coverage-padding tricks (empty assertions, testing getters). Every test verifies real behavior.
- Use `//go:build e2e` tag for e2e tests so they don't run during regular `go test ./...`
- Use `//go:build darwin` tag for macOS-specific e2e tests

## Implementation Steps

### Task 1: Fill cmd/sluice unit test gaps (33.6% -> 75%+)

The CLI handlers are the biggest gap. Most are untested because they call `os.Exit` or read from stdin. Refactor to make them testable.

**Files:**
- Modify: `cmd/sluice/policy.go` (refactor handlers to return errors instead of os.Exit)
- Modify: `cmd/sluice/policy_test.go`
- Modify: `cmd/sluice/cred.go`
- Modify: `cmd/sluice/cred_test.go`
- Modify: `cmd/sluice/cert.go`
- Create: `cmd/sluice/cert_test.go` (expand beyond current minimal tests)
- Modify: `cmd/sluice/main.go`
- Modify: `cmd/sluice/main_test.go`

- [x] Refactor CLI handlers that call `os.Exit` or `log.Fatalf` to return errors. Keep a thin wrapper at the top level that calls `os.Exit` based on the returned error.
- [x] Write tests for `handlePolicyList` with various filter flags (--verdict allow, --verdict deny, no filter)
- [x] Write tests for `handlePolicyAdd` (allow, deny, ask with destination, tool, pattern variants)
- [x] Write tests for `handlePolicyRemove` (valid ID, invalid ID, non-existent ID)
- [x] Write tests for `handlePolicyImport` (valid TOML file, malformed file, non-existent file)
- [x] Write tests for `handlePolicyExport` (verify TOML output matches store contents)
- [x] Write tests for `handleCertGenerate` (verify CA cert created, idempotent on re-run)
- [x] Write tests for `envDefault` helper
- [x] Write tests for `main()` startup with various flag combinations (--db, --config, --listen, --health-addr)
- [x] Write tests for auto-seed behavior (empty DB + config.toml present -> import)
- [x] Run tests: `go test ./cmd/sluice/ -v -timeout 30s -cover`

### Task 2: Fill internal/telegram unit test gaps (45.2% -> 80%+)

The Telegram approval flow and channel implementation are almost entirely untested.

**Files:**
- Modify: `internal/telegram/approval.go`
- Rewrite: `internal/telegram/approval_test.go` (currently 1-line stub)
- Modify: `internal/telegram/commands.go`
- Modify: `internal/telegram/commands_test.go`

- [ ] Write tests for `NewTelegramChannel` initialization
- [ ] Write tests for `RequestApproval` (sends message via Telegram API mock, returns on resolve)
- [ ] Write tests for `CancelApproval` (edits Telegram message to show cancelled)
- [ ] Write tests for `Start`/`Stop` lifecycle
- [ ] Write tests for Telegram callback handling (allow once, always allow, deny button taps)
- [ ] Write tests for stale approval cleanup (request times out while Telegram API call is in flight)
- [ ] Write tests for `SetDockerManager`, `SetPhantomDir`, `SetResolverPtr` setters
- [ ] Write tests for `/cred` Telegram commands with mock vault and docker manager
- [ ] Write tests for `/policy` Telegram commands verifying store writes and engine recompile
- [ ] Use mock Telegram API (httptest server returning canned BotAPI responses)
- [ ] Run tests: `go test ./internal/telegram/ -v -timeout 30s -cover`

### Task 3: Fill internal/proxy unit test gaps (56.9% -> 80%+)

Core proxy internals like credential injection setup, IP pinning, and protocol detection are untested.

**Files:**
- Modify: `internal/proxy/server_test.go`
- Modify: `internal/proxy/inject_test.go`
- Modify: `internal/proxy/protocol_test.go`

- [ ] Write tests for `ProtocolFromContext` (extract protocol from request context)
- [ ] Write tests for `setupInjection` (verify CA cert loading, injector creation, SSH jump host setup, mail proxy setup)
- [ ] Write tests for `dialThroughInjector` (mock injector listener, verify CONNECT request)
- [ ] Write tests for `PinIPs` / `UnpinIPs` (pin IPs, verify dial uses pinned addresses, unpin, verify cleanup)
- [ ] Write tests for `generatePinID` (verify uniqueness across goroutines)
- [ ] Write tests for `dialWithHandler` (mock handler, verify bidirectional connection)
- [ ] Write tests for proxy server graceful shutdown (in-flight connections drain, pending approvals auto-denied)
- [ ] Write tests for SIGHUP engine recompile via proxy (add rule to store, recompile, verify new rule applies)
- [ ] Write tests for the full SOCKS5 + MITM + credential injection pipeline (proxy server with vault, binding, and injector wired together)
- [ ] Run tests: `go test ./internal/proxy/ -v -timeout 30s -cover`

### Task 4: Fill internal/policy unit test gaps (67.9% -> 85%+)

Policy mutation methods and helper functions lack tests.

**Files:**
- Modify: `internal/policy/engine_test.go`
- Modify: `internal/policy/glob_test.go`

- [ ] Write tests for `AddDynamicAllow` (add rule, verify evaluation changes)
- [ ] Write tests for `AddAllowRule` / `AddDenyRule` (add, verify, check concurrent safety)
- [ ] Write tests for `RemoveRule` (remove by ID, verify evaluation changes, remove non-existent)
- [ ] Write tests for `Snapshot` (verify snapshot reflects current state, mutations after snapshot don't affect it)
- [ ] Write tests for `portToProtocol` (all known ports, unknown port returns generic)
- [ ] Write tests for `Glob.String()` representation
- [ ] Write tests for edge cases: empty engine (no rules), all rules same verdict, overlapping glob patterns
- [ ] Run tests: `go test ./internal/policy/ -v -timeout 30s -cover`

### Task 5: Fill remaining package gaps to 85%+

Bring vault, store, mcp, channel packages to 85%+.

**Files:**
- Modify: test files in vault, store, mcp, channel packages

- [ ] `internal/vault`: test HashiCorp provider edge cases (token renewal failure, connection timeout, malformed response)
- [ ] `internal/vault`: test ChainProvider with all providers failing (verify error propagation)
- [ ] `internal/vault`: test SecureBytes release and re-use after release
- [ ] `internal/store`: test migration on corrupted DB (verify graceful error)
- [ ] `internal/store`: test concurrent import (two goroutines importing simultaneously)
- [ ] `internal/store`: test all config fields (get/update each typed field)
- [ ] `internal/mcp`: test gateway with upstream that crashes mid-call (verify error handling)
- [ ] `internal/mcp`: test tool namespace collision (two upstreams with same tool name)
- [ ] `internal/channel`: test broker with zero channels (verify error)
- [ ] `internal/channel`: test broker with channel that panics (verify recovery)
- [ ] Run tests: `go test ./... -v -timeout 60s -cover`

### Task 6: Create e2e test infrastructure

Set up the e2e test directory, helper utilities, and build tags.

**Files:**
- Create: `e2e/helpers_test.go` -- shared test utilities
- Create: `e2e/doc.go` -- package doc with build tag
- Modify: `Makefile` -- add e2e targets

**Build tags:**
- `//go:build e2e` -- all e2e tests
- `//go:build e2e && darwin` -- macOS-specific (Apple Container)
- `//go:build e2e && linux` -- Linux-specific (Docker)

**Compose file:**
- Create: `compose.e2e.yml` -- stripped-down compose for e2e: sluice + tun2proxy + test runner container (no OpenClaw). Test runner has go toolchain and runs the e2e binary.

**Makefile targets:**
```makefile
test-e2e:
	go test -tags=e2e ./e2e/ -v -count=1 -timeout=300s

test-e2e-docker:
	docker compose -f compose.e2e.yml up --build --abort-on-container-exit --exit-code-from test-runner
	docker compose -f compose.e2e.yml down -v

test-e2e-macos:
	go test -tags="e2e darwin" ./e2e/ -v -count=1 -timeout=300s
```

- [ ] Create `compose.e2e.yml` with three services: sluice (build from source), tun2proxy, test-runner (runs `go test -tags="e2e linux"` inside the compose network). Test-runner uses `network_mode: "service:tun2proxy"` so its traffic routes through sluice.
- [ ] Create `e2e/doc.go` with `//go:build e2e` and package documentation
- [ ] Create `e2e/helpers_test.go` with shared utilities: `startSluice(t, opts)`, `stopSluice(t)`, `connectSOCKS5(t, addr)`, `importConfig(t, toml)`, `waitForHealthy(t, addr)`
- [ ] Helper: `startSluice` spawns sluice binary with temp DB, temp config, temp audit log. Returns cleanup func.
- [ ] Helper: `connectSOCKS5` creates a SOCKS5 dialer to sluice's proxy port
- [ ] Helper: `startEchoServer(t)` starts an HTTP/HTTPS echo server for proxy tests
- [ ] Add Makefile targets for e2e tests
- [ ] Write a smoke test: start sluice, check /healthz returns 200, stop
- [ ] Run: `go test -tags=e2e ./e2e/ -v -timeout 60s`

### Task 7: E2e tests -- proxy and policy enforcement

Test the full SOCKS5 proxy flow with policy evaluation end-to-end.

**Files:**
- Create: `e2e/proxy_test.go`

- [ ] Test: allow rule permits connection (connect through SOCKS5 to echo server, verify response)
- [ ] Test: deny rule blocks connection (connect to denied destination, verify connection refused)
- [ ] Test: ask rule without broker auto-denies
- [ ] Test: default verdict applies when no rule matches
- [ ] Test: glob patterns in rules (* matches single label, ** matches across dots)
- [ ] Test: port-specific rules (allow port 443 but deny port 80 for same destination)
- [ ] Test: protocol-specific rules (`protocols = ["https"]` only matches TLS connections)
- [ ] Test: policy import via CLI (`sluice policy import config.toml`) then verify proxy enforces imported rules
- [ ] Test: dynamic rule add via CLI (`sluice policy add allow example.com`) then verify proxy allows
- [ ] Test: dynamic rule remove via CLI then verify proxy denies
- [ ] Run: `go test -tags=e2e ./e2e/ -v -timeout 120s`

### Task 8: E2e tests -- credential injection

Test phantom token replacement through the full MITM pipeline.

**Files:**
- Create: `e2e/credential_test.go`

- [ ] Test: add credential via CLI, configure binding, make HTTPS request through proxy, verify upstream receives real credential in header
- [ ] Test: phantom token in request body is replaced
- [ ] Test: phantom token in request to host WITHOUT binding is still replaced (global replacement)
- [ ] Test: response from upstream with pattern-matched content is redacted before reaching client
- [ ] Test: credential rotation (add new value, verify next request uses new credential)
- [ ] Test: multiple credentials for different destinations (each gets correct injection)
- [ ] Test: SSH credential injection (connect through SOCKS5 to SSH echo server, verify key authentication)
- [ ] Run: `go test -tags=e2e ./e2e/ -v -timeout 120s`

### Task 9: E2e tests -- MCP gateway

Test the full MCP gateway flow with upstream tool discovery, policy, and inspection.

**Files:**
- Create: `e2e/mcp_test.go`

- [ ] Test: register MCP upstream via CLI, start gateway, verify tools discoverable via tools/list
- [ ] Test: tool call with allowed policy succeeds (verify correct response from upstream)
- [ ] Test: tool call with denied policy returns error
- [ ] Test: tool call with ask policy and no broker returns error
- [ ] Test: argument inspection blocks tool call containing pattern match
- [ ] Test: response redaction strips pattern-matched content from tool response
- [ ] Test: multiple upstreams with namespaced tools (github__list, fs__read)
- [ ] Test: upstream timeout (slow upstream exceeds timeout_sec, verify error)
- [ ] Run: `go test -tags=e2e ./e2e/ -v -timeout 120s`

### Task 10: E2e tests -- audit log integrity

Test the full audit trail from proxy events to hash chain verification.

**Files:**
- Create: `e2e/audit_test.go`

- [ ] Test: proxy connections create audit entries (allowed + denied)
- [ ] Test: MCP tool calls create audit entries
- [ ] Test: audit log hash chain is valid after multiple operations (`sluice audit verify` exits 0)
- [ ] Test: tampering detection (modify a line, verify returns non-zero exit)
- [ ] Test: audit log continuity across sluice restart (stop, start, write more, verify chain unbroken)
- [ ] Run: `go test -tags=e2e ./e2e/ -v -timeout 120s`

### Task 11: E2e tests -- Docker-specific (Linux)

Docker-specific integration tests using docker compose.

**Files:**
- Create: `e2e/docker_test.go` (build tag: `//go:build e2e && linux`)

- [ ] Test: `docker compose -f compose.dev.yml up --build` succeeds and all services healthy
- [ ] Test: sluice healthcheck responds 200 from within the compose network
- [ ] Test: traffic from openclaw container routes through sluice (make HTTP request from openclaw, verify audit log entry in sluice)
- [ ] Test: credential hot-reload via shared volume (write phantom file, exec reload, verify openclaw picks up new value)
- [ ] Test: MCP auto-injection (verify mcp-servers.json written, openclaw connects to sluice gateway)
- [ ] Cleanup: `docker compose -f compose.dev.yml down -v`
- [ ] Run: `go test -tags="e2e linux" ./e2e/ -v -timeout 300s`

### Task 12: E2e tests -- Apple Container-specific (macOS)

macOS-specific tests using Apple Container runtime. Gated behind build tag and runtime check.

**Files:**
- Create: `e2e/apple_test.go` (build tag: `//go:build e2e && darwin`)

- [ ] Skip if `container` CLI not available (`t.Skip("Apple Container not installed")`)
- [ ] Test: sluice starts with `--runtime apple`, VM boots with correct env vars
- [ ] Test: pf rules applied (verify bridge interface routing)
- [ ] Test: traffic from Apple Container VM routes through sluice SOCKS5
- [ ] Test: credential injection works through the pf + tun2proxy chain
- [ ] Test: CA cert trusted by VM (HTTPS request succeeds through MITM)
- [ ] Test: cleanup on shutdown (pf rules removed, VM stopped)
- [ ] Run: `go test -tags="e2e darwin" ./e2e/ -v -timeout 300s`

### Task 13: GitHub Actions workflows for e2e tests

Add CI workflows for both platforms.

**Files:**
- Create: `.github/workflows/e2e-linux.yml`
- Create: `.github/workflows/e2e-macos.yml`
- Modify: `.github/workflows/ci.yml` (add coverage reporting)

**Linux workflow:**
```yaml
on: [push, pull_request]
runs-on: ubuntu-latest
services:
  # Docker-in-Docker for compose tests
steps:
  - go test -tags="e2e linux" ./e2e/ -v -timeout 300s
```

**macOS workflow:**
```yaml
on: [push, pull_request]
runs-on: macos-15  # Sequoia with Apple Container support
steps:
  - go test -tags="e2e darwin" ./e2e/ -v -timeout 300s
```

- [ ] Create `.github/workflows/e2e-linux.yml`: ubuntu-latest runner, install Docker Compose, build sluice, run e2e tests with `linux` tag
- [ ] Create `.github/workflows/e2e-macos.yml`: macos-15 runner, check for Apple Container availability, run e2e tests with `darwin` tag. Skip gracefully if Apple Container not available on the runner.
- [ ] Update `.github/workflows/ci.yml`: add coverage report step (`go test -coverprofile`), upload as artifact
- [ ] Add coverage badge or threshold check (fail CI if coverage drops below 80%)
- [ ] Run workflows manually to verify: `gh workflow run e2e-linux.yml`

### Task 14: Verify acceptance criteria

- [ ] Verify overall test coverage is 85%+ (`go test ./... -cover`)
- [ ] Verify cmd/sluice coverage is 75%+
- [ ] Verify internal/telegram coverage is 80%+
- [ ] Verify internal/proxy coverage is 80%+
- [ ] Verify internal/policy coverage is 85%+
- [ ] Verify all e2e tests pass on Linux: `make test-e2e-linux`
- [ ] Verify all e2e tests pass on macOS: `make test-e2e-macos` (if Apple Container available)
- [ ] Verify CI workflows succeed on push
- [ ] Verify no test uses empty assertions or tests only getters (manual audit of new test code)
- [ ] Run full unit test suite: `go test ./... -v -timeout 60s -race`
- [ ] Run linter: `go vet ./...`

### Task 15: [Final] Update documentation

- [ ] Update CLAUDE.md: document e2e test infrastructure, build tags, how to run
- [ ] Update CONTRIBUTING.md: add testing section (unit tests, e2e tests, coverage requirements)
- [ ] Update Makefile help: document test-e2e, test-e2e-linux, test-e2e-macos targets
- [ ] Update README.md: add test coverage badge

## Technical Details

### E2e test architecture

```
e2e/
  doc.go                 # //go:build e2e, package documentation
  helpers_test.go        # shared: startSluice, connectSOCKS5, startEchoServer, etc.
  proxy_test.go          # proxy + policy enforcement scenarios
  credential_test.go     # phantom token injection scenarios
  mcp_test.go            # MCP gateway tool call scenarios
  audit_test.go          # audit log integrity scenarios
  docker_test.go         # //go:build e2e && linux -- Docker compose tests
  apple_test.go          # //go:build e2e && darwin -- Apple Container tests
```

### E2e helper pattern

```go
func startSluice(t *testing.T, opts SluiceOpts) *SluiceProcess {
    t.Helper()
    
    // Create temp dirs for DB, audit, config
    dbPath := filepath.Join(t.TempDir(), "sluice.db")
    auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
    
    // Build sluice binary if not already built
    binary := buildSluice(t)
    
    // Start process
    cmd := exec.Command(binary,
        "--listen", "127.0.0.1:0",  // random port
        "--db", dbPath,
        "--audit", auditPath,
    )
    // ... start, wait for healthy, return process handle
    
    t.Cleanup(func() { cmd.Process.Kill() })
    return &SluiceProcess{cmd, addr, dbPath, auditPath}
}
```

### CI coverage enforcement

```yaml
# In ci.yml
- name: Check coverage threshold
  run: |
    coverage=$(go test ./... -cover | grep 'total' | awk '{print $NF}' | tr -d '%')
    if (( $(echo "$coverage < 80" | bc -l) )); then
      echo "Coverage $coverage% is below 80% threshold"
      exit 1
    fi
```

## Post-Completion

**Manual verification:**
- Review all new tests for meaningful assertions (not just "didn't panic")
- Run e2e tests locally on both macOS and Linux
- Verify CI workflows pass on GitHub

**Future considerations:**
- Fuzz testing for protocol parsers (WebSocket frames, DNS queries, QUIC packets)
- Benchmark tests for proxy throughput
- Chaos testing (kill upstream mid-request, network partitions)
- Load testing (concurrent connections through proxy)
