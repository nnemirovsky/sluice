# Fix upstream TLS for SNI-deferred connections

## Overview

When a SOCKS5 CONNECT arrives with a raw IP and the connection is SNI-deferred, the custom `handleConnect` calls `s.dial()` before `sniPolicyCheck`. The dial function routes through the injector with the raw IP as the CONNECT target. goproxy reconstructs the upstream URL as `https://<IP>:443/...` and connects to the real server using the IP for TLS ServerName verification. The real server's cert only has DNS SANs (e.g. `*.telegram.org`), not IP SANs, so verification fails with `x509: cannot validate certificate for <IP> because it doesn't contain any IP SANs`.

The MITM cert generation is not the problem (goproxy's `sniAwareTLSConfig` correctly reads SNI from the ClientHello for client-side certs). The issue is the upstream connection using the raw IP as TLS ServerName.

Observed in production: OpenClaw's Telegram client falls back to direct IP connections when DNS-resolved IPs are unreachable, causing all Telegram communication to break.

**Acceptance criteria:**
- SNI-deferred IP connections to HTTPS servers with hostname-only certs complete successfully
- No x509 IP SANs errors in sluice logs for SNI-deferred connections
- Credential injection works for IP-only Telegram connections

## Context

- Custom connect handler: `internal/proxy/server.go` (handleConnect, sniPolicyCheck)
- SNI extraction: `internal/proxy/sni.go` (extractSNI, peekSNI)
- Injector dial: `internal/proxy/server.go` (dial, dialThroughInjector)
- FQDN context key: `internal/proxy/server.go` (ctxKeyFQDN)
- goproxy upstream URL: goproxy reconstructs from CONNECT target host

**Root cause:** In `handleConnect`, `s.dial()` is called at line ~1090 BEFORE `sniPolicyCheck` at line ~1107. By the time SNI is extracted, the injector already has CONNECT to the raw IP. The fix must extract SNI BEFORE dialing.

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- CRITICAL: every task MUST include new/updated tests
- CRITICAL: all tests must pass before starting next task

## Testing Strategy

- Unit tests in `internal/proxy/sni_test.go` for SNI extraction (existing)
- New integration tests in `internal/proxy/server_test.go` for the SNI-deferred MITM pipeline
- Test infrastructure: SOCKS5 client sending IP-only CONNECT with a TLS ClientHello containing hostname SNI, upstream HTTPS server with hostname-only cert

## Implementation Steps

### Task 1: Restructure handleConnect for SNI-deferred connections

**Files:**
- Modify: `internal/proxy/server.go`
- Test: `internal/proxy/server_test.go`

- [ ] For SNI-deferred connections (ctxKeySNIDeferred is true), change the flow:
  1. Send SOCKS5 CONNECT success to client (already done)
  2. Peek ClientHello from client reader to extract SNI
  3. Evaluate policy with recovered hostname (existing sniPolicyCheck logic)
  4. Update context ctxKeyFQDN with the recovered hostname
  5. THEN call s.dial() which routes through injector with correct hostname
  6. Relay data with the peeked bytes prepended to client reader
- [ ] Move sniPolicyCheck call BEFORE s.dial() in the SNI-deferred branch
- [ ] Update sniPolicyCheck to return the recovered hostname so handleConnect can update context
- [ ] For non-deferred connections, keep the existing flow unchanged
- [ ] Write test: IP-only SOCKS5 CONNECT with hostname SNI routes upstream using hostname as TLS ServerName
- [ ] Write test: IP-only CONNECT where SNI extraction fails (no TLS / malformed ClientHello) falls back to IP
- [ ] Write test: policy denial after SNI extraction closes connection
- [ ] Run tests - must pass before next task

### Task 2: Verify acceptance criteria

- [ ] Run full test suite: `go test ./... -v -timeout 30s`
- [ ] Verify no x509 IP SANs warnings in test output
- [ ] Run linter: `golangci-lint run ./...`

### Task 3: [Final] Update documentation

- [ ] Update CLAUDE.md SNI deferral section to note the dial ordering fix
- [ ] Move this plan to `docs/plans/completed/`

## Post-Completion

**Manual verification:**
- Deploy to knuth, restart stack
- Verify OpenClaw's Telegram fallback IP connections work through MITM
- Verify no `IP SANs` errors in sluice logs
- Verify credential injection works for IP-only Telegram connections
- Force fallback by temporarily blocking DNS for api.telegram.org
