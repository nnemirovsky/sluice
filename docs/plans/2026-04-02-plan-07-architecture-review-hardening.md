# Sluice Plan 7: Full Architecture Review and Hardening

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Address all findings from a comprehensive architectural review of the Sluice codebase. Fix security issues, fill test coverage gaps, implement the HashiCorp Vault provider, add production readiness features, and improve documentation.

**Why:** Sluice is functional at alpha stage (7,368 LOC, 260 tests, all passing) but has gaps that block production use: a policy reload race condition, missing health checks, test coverage at ~34%, a stub vault provider, and no godoc on exported types.

**Scope:** Security and correctness first, then test coverage, then production readiness, then documentation.

**Tech Stack:** Go 1.26.1, existing dependencies plus `github.com/hashicorp/vault/api`

**Development Approach:**
- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- All tests must pass before starting next task
- Update this plan file when scope changes during implementation

---

## Context

### Codebase Metrics (as of 2026-04-02)

| Category | Value |
|----------|-------|
| Total Go source lines | 7,368 |
| Total test lines | 3,839 |
| Test files | 23 |
| Tests passing | 260 |
| Estimated coverage | ~34% |
| Packages | 8 (audit, docker, mcp, policy, proxy, telegram, vault, cmd/sluice) |
| Dependencies | 9 direct |

### Findings by Severity

**Critical (5):**
1. Policy reload race condition in SIGHUP handler (no mutex around LoadFromFile + ReloadPolicy)
2. No Docker HEALTHCHECK directive
3. HashiCorp Vault provider is a stub that errors at runtime
4. MCP upstream timeout hardcoded at 120s, not configurable
5. No tests for `proxy/ca.go` (224 lines) or `mcp/gateway.go` (246 lines)

**High (5):**
6. CA cert 10-year validity (should be 1-2 years for MITM CA)
7. No rate limiting on Telegram approval requests
8. No `/healthz` HTTP endpoint
9. CLI subcommands untested (cred.go, audit.go, mcp.go)
10. Missing godoc on all exported types

**Medium (4):**
11. No restart policy in docker-compose.yml
12. Docker socket format handling assumes unix only
13. No graceful shutdown timeout
14. Port 3000 exposed in Dockerfile but unused

**Low (2):**
15. Host cert 24h validity is fine but document the rotation strategy
16. Consider ECDSA P-384 migration path (P-256 is fine for now)

### Files Involved

**Security fixes:**
- `cmd/sluice/main.go` - Reload race condition
- `internal/proxy/ca.go` - CA cert validity
- `internal/telegram/commands.go` - Rate limiting

**HashiCorp Vault:**
- `internal/vault/provider_hashicorp.go` - Full implementation
- `internal/vault/provider_test.go` - Test coverage

**Test coverage:**
- `internal/proxy/ca_test.go` - New test file
- `internal/mcp/gateway_test.go` - New test file
- `cmd/sluice/*_test.go` - CLI subcommand tests

**Production readiness:**
- `Dockerfile` - HEALTHCHECK
- `docker-compose.yml` - Restart policies, health checks
- `cmd/sluice/main.go` - /healthz endpoint, graceful shutdown

**Documentation:**
- All exported types across all packages

---

## Implementation Steps

### Task 1: Fix policy reload race condition

The SIGHUP handler in main.go calls `policy.LoadFromFile` then `srv.ReloadPolicy` without holding the reload mutex. If two SIGHUPs arrive in quick succession, the second could overwrite the first's engine swap mid-operation.

**Files:**
- Modify: `cmd/sluice/main.go`

- [x] Wrap the SIGHUP handler's `LoadFromFile` + `ReloadPolicy` + config drift checks inside `srv.ReloadMu().Lock()`/`Unlock()`
- [x] Add a `select` with `default` to drain duplicate SIGHUPs that arrive during reload
- [x] Validate new policy config before swapping (catch malformed TOML post-swap)
- [x] Write test that simulates rapid SIGHUP delivery and verifies no panic or data race
- [x] Run tests: `go test ./... -v -timeout 30s -race`

### Task 2: Reduce CA cert validity and add rotation

The self-signed MITM CA in `proxy/ca.go` has a 10-year NotAfter. For a MITM CA this is excessive. Should be 1-2 years with documented rotation.

**Files:**
- Modify: `internal/proxy/ca.go`
- Create: `internal/proxy/ca_test.go`

- [x] Reduce CA cert NotAfter from 10 years to 2 years
- [x] Add `IsCACertExpiring(path string, threshold time.Duration) (bool, error)` function that checks if the CA cert expires within the threshold
- [x] Log a warning on startup if CA cert expires within 30 days
- [x] Write tests for CA generation (verify cert fields, key type, validity period)
- [x] Write tests for `IsCACertExpiring` (expired, expiring soon, valid)
- [x] Write test for atomic CA file creation (concurrent calls don't corrupt)
- [x] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 3: Add rate limiting to Telegram approval requests

An attacker could spam connections to Ask-policy destinations, flooding the Telegram approval queue. Add a pending request limit and per-destination cooldown.

**Files:**
- Modify: `internal/telegram/approval.go`
- Modify: `internal/telegram/approval_test.go`

- [ ] Add `MaxPendingRequests` field to `ApprovalBroker` (default 50)
- [ ] Return auto-deny when pending count exceeds limit, with audit log entry
- [ ] Add per-destination rate limiting: max 5 requests per minute per destination
- [ ] Write tests for pending limit exceeded behavior
- [ ] Write tests for per-destination rate limiting
- [ ] Run tests: `go test ./internal/telegram/ -v -timeout 30s`

### Task 4: Implement HashiCorp Vault provider

Replace the stub in `provider_hashicorp.go` with a working implementation using the HashiCorp Vault API SDK. Support KV v2 secrets engine.

**Files:**
- Modify: `internal/vault/provider_hashicorp.go`
- Modify: `internal/vault/provider_test.go`
- Modify: `go.mod` (add `github.com/hashicorp/vault/api`)

- [ ] Add `github.com/hashicorp/vault/api` dependency
- [ ] Implement `NewHashiCorpProvider(cfg HashiCorpConfig) (*HashiCorpProvider, error)` with Vault client initialization
- [ ] Implement `Get(name string) (SecureBytes, error)` reading from KV v2 at configurable mount/path
- [ ] Implement `List() ([]string, error)` listing available secret keys
- [ ] Support VAULT_ADDR and VAULT_TOKEN env vars, plus config overrides
- [ ] Support AppRole auth as alternative to token auth
- [ ] Write tests using a mock HTTP server that simulates Vault KV v2 responses
- [ ] Write tests for auth methods (token, AppRole)
- [ ] Write tests for error cases (connection refused, auth denied, secret not found)
- [ ] Run tests: `go test ./internal/vault/ -v -timeout 30s`

### Task 5: Make MCP upstream timeout configurable

The MCP upstream timeout is hardcoded at 120s in `upstream.go`. Users need to configure this per-upstream for slow tools.

**Files:**
- Modify: `internal/mcp/upstream.go`
- Modify: `internal/mcp/types.go` (add TimeoutSec to UpstreamConfig)
- Modify: `internal/mcp/upstream_test.go`

- [ ] Add `TimeoutSec int` field to `UpstreamConfig` in types.go
- [ ] Use `TimeoutSec` in `StartUpstream` if set, fall back to 120s default
- [ ] Parse `timeout_sec` from `[[mcp_upstream]]` TOML sections
- [ ] Write test verifying custom timeout is applied
- [ ] Write test verifying default timeout when not specified
- [ ] Run tests: `go test ./internal/mcp/ -v -timeout 30s`

### Task 6: Add MCP gateway tests

`mcp/gateway.go` (246 lines) has no unit tests. It handles upstream discovery, tool listing, and request routing.

**Files:**
- Create: `internal/mcp/gateway_test.go`

- [ ] Write test for `NewGateway` initialization
- [ ] Write test for `StartUpstream` with mock process (verify handshake and tool discovery)
- [ ] Write test for `tools/list` aggregation across multiple upstreams with namespace prefixing
- [ ] Write test for `tools/call` routing to correct upstream after namespace stripping
- [ ] Write test for tool policy enforcement (deny/allow/ask) during `tools/call`
- [ ] Write test for content inspection (argument blocking, response redaction) during `tools/call`
- [ ] Run tests: `go test ./internal/mcp/ -v -timeout 30s`

### Task 7: Add CLI subcommand tests

CLI subcommands (cred, audit, mcp) have no tests. `cert_test.go` exists but coverage is minimal.

**Files:**
- Create: `cmd/sluice/cred_test.go`
- Create: `cmd/sluice/audit_test.go`
- Create: `cmd/sluice/mcp_test.go`

- [ ] Write tests for `handleCredCommand` (add, list, remove subcommands with mock vault)
- [ ] Write tests for `handleAuditCommand` (verify subcommand with temp audit file)
- [ ] Write tests for `handleMCPCommand` (config parsing, upstream validation)
- [ ] Write tests for error cases (missing args, invalid paths, permission denied)
- [ ] Run tests: `go test ./cmd/sluice/ -v -timeout 30s`

### Task 8: Add health check endpoint and Docker hardening

No health endpoint exists. Docker containers have no HEALTHCHECK or restart policies.

**Files:**
- Modify: `cmd/sluice/main.go` (add /healthz HTTP server on port 3000)
- Modify: `Dockerfile` (add HEALTHCHECK)
- Modify: `docker-compose.yml` (add restart policies and health checks)

- [ ] Add a minimal HTTP server on `:3000` in main.go serving `/healthz` (returns 200 if proxy is listening)
- [ ] Add `HEALTHCHECK --interval=10s --timeout=3s CMD wget -qO- http://localhost:3000/healthz || exit 1` to Dockerfile
- [ ] Add `restart: unless-stopped` to all three services in docker-compose.yml
- [ ] Add `healthcheck` blocks to sluice and tun2proxy services in docker-compose.yml
- [ ] Validate Docker socket format in `resolveDockerSocket` (reject non-unix schemes with clear error)
- [ ] Write test for `/healthz` endpoint (returns 200 when proxy is up)
- [ ] Run tests: `go test ./cmd/sluice/ -v -timeout 30s`

### Task 9: Add graceful shutdown with timeout

Currently `srv.Close()` is called on SIGINT/SIGTERM but there's no drain period for in-flight connections or pending Telegram approvals.

**Files:**
- Modify: `cmd/sluice/main.go`
- Modify: `internal/proxy/server.go` (if Shutdown method needed)

- [ ] Add a `--shutdown-timeout` flag (default 10s)
- [ ] On SIGINT/SIGTERM, stop accepting new connections, wait for in-flight to complete up to timeout
- [ ] Cancel pending Telegram approval requests on shutdown (auto-deny with reason "shutting down")
- [ ] Close audit logger after all connections drain
- [ ] Write test for graceful shutdown behavior (in-flight connection completes before close)
- [ ] Run tests: `go test ./... -v -timeout 30s`

### Task 10: Add godoc comments to exported types

All exported types lack documentation comments. Add package-level and type-level godoc.

**Files:**
- Modify: all packages with exported types

- [ ] Add package-level doc comments to each package (audit, docker, mcp, policy, proxy, telegram, vault)
- [ ] Add doc comments to all exported structs (Event, FileLogger, VerifyResult, Manager, Gateway, Engine, Server, Bot, Store, etc.)
- [ ] Add doc comments to all exported interfaces (Provider, ContainerClient)
- [ ] Add doc comments to all exported functions not already documented
- [ ] Run `go vet ./...` to verify no issues
- [ ] Run tests: `go test ./... -v -timeout 30s`

### Task 11: Verify acceptance criteria

- [ ] Verify policy reload is race-free under concurrent SIGHUP (test with -race)
- [ ] Verify CA cert validity is 2 years (check generated cert)
- [ ] Verify Telegram rate limiting works (exceed limit, verify auto-deny)
- [ ] Verify HashiCorp Vault provider works against mock server
- [ ] Verify MCP upstream timeout is configurable via TOML
- [ ] Verify /healthz returns 200 when proxy is running
- [ ] Verify Docker health checks work (`docker compose up`, check health status)
- [ ] Verify graceful shutdown drains in-flight connections
- [ ] Verify all exported types have godoc comments
- [ ] Run full test suite with race detector: `go test ./... -v -timeout 60s -race`
- [ ] Run linter: `go vet ./...`

### Task 12: [Final] Update documentation

- [ ] Update CLAUDE.md Libraries section with `github.com/hashicorp/vault/api`
- [ ] Update CLAUDE.md Implementation Details with health check endpoint, graceful shutdown, rate limiting
- [ ] Update examples/policy.toml with HashiCorp Vault config example and MCP upstream timeout_sec
- [ ] Update docker-compose.yml comments to document health check and restart behavior

## Technical Details

### Policy reload mutex fix

```go
// Before (race-prone):
for range sighupCh {
    newEng, err := policy.LoadFromFile(*policyPath)
    srv.ReloadPolicy(newEng)
}

// After (safe):
for range sighupCh {
    srv.ReloadMu().Lock()
    newEng, err := policy.LoadFromFile(*policyPath)
    if err != nil {
        srv.ReloadMu().Unlock()
        log.Printf("reload policy failed: %v", err)
        continue
    }
    srv.ReloadPolicy(newEng) // already locks internally, adjust to use unlocked variant
    srv.ReloadMu().Unlock()
}
```

### HashiCorp Vault KV v2 API

```
GET /v1/{mount}/data/{path}
Response: {"data": {"data": {"key": "value"}, "metadata": {...}}}

LIST /v1/{mount}/metadata/{path}
Response: {"data": {"keys": ["key1", "key2"]}}
```

Auth methods:
- Token: `VAULT_TOKEN` env or config
- AppRole: `POST /v1/auth/approle/login` with role_id + secret_id

### Health check endpoint

Minimal HTTP server on `:3000`:
```go
http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
    if srv.IsListening() {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("ok"))
    } else {
        w.WriteHeader(http.StatusServiceUnavailable)
    }
})
```

### Rate limiting design

```go
type ApprovalBroker struct {
    // existing fields...
    maxPending    int
    destLimiter   map[string]*rate.Limiter // per-destination, 5 req/min
}
```

## Post-Completion

**Manual verification:**
- Deploy three-container stack and verify health checks propagate correctly
- Test SIGHUP reload with `kill -HUP <pid>` while proxy is handling traffic
- Test HashiCorp Vault integration against a real Vault dev server (`vault server -dev`)
- Load test Telegram approval queue to verify rate limiting kicks in
- Verify CA cert rotation logging appears when cert is near expiry

**Future considerations:**
- Prometheus metrics exporter (connection counts, approval latency, vault lookups)
- ECDSA P-384 migration (P-256 is fine for now, revisit when NIST updates guidance)
- Audit log rotation (logrotate or built-in size-based rotation)
- MCP gateway HTTP transport (currently stdio only)
