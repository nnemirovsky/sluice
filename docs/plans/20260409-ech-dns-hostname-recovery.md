# ECH-aware hostname recovery via HTTPS/SVCB DNS records

## Overview

Add HTTPS/SVCB DNS record parsing to the DNS interceptor. When a DNS response contains HTTPS/SVCB records with `ipv4hint`/`ipv6hint` SvcParams, extract the IP addresses and store hostname -> IP mappings in a separate SVCB cache. This cache is always populated but only used as a hostname source when SNI disagrees with it (ECH connections where the real SNI is encrypted and the outer SNI is a dummy).

The hostname recovery priority becomes:
1. FQDN from SOCKS5 CONNECT (if client sends hostname)
2. SNI from TLS ClientHello (happy path for most TLS)
3. SVCB DNS hint (when SNI disagrees with SVCB cache for the same IP, indicating ECH)
4. A/AAAA DNS reverse cache (existing, for non-TLS)
5. Raw IP (last resort)

## Context

- DNS interceptor: `internal/proxy/dns.go` (HandleQuery, forwards queries, gates PopulateFromResponse on A/AAAA types)
- DNS reverse cache: `internal/proxy/dns_reverse.go` (ReverseDNSCache, PopulateFromResponse, parseDNSName)
- SNI policy check: `internal/proxy/server.go` (sniPolicyCheck, handleConnect)
- DNS constants: `internal/proxy/dns_reverse.go` (dnsTypeA, dnsTypeAAAA, dnsHeaderLen)

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- CRITICAL: every task MUST include new/updated tests
- CRITICAL: all tests must pass before starting next task

## Testing Strategy

- Unit tests for SVCB record parsing: `internal/proxy/dns_test.go`
- Unit tests for SVCB cache lookup: `internal/proxy/dns_reverse_test.go` (new file)
- Integration tests for ECH fallback flow: `internal/proxy/server_test.go`

## Solution Overview

1. Add a separate `svcbEntries` map to `ReverseDNSCache` with `StoreSVCB`/`LookupSVCB` methods
2. Extend `PopulateFromResponse` to parse HTTPS (type 65) and SVCB (type 64) records, using `parseDNSName` for the target name field (DNS name compression applies per RFC 9460)
3. Modify `HandleQuery` in `dns.go` to call `PopulateFromResponse` for HTTPS/SVCB query types (currently gated to A/AAAA only)
4. In `sniPolicyCheck`: after extracting SNI, compare it against the SVCB-cached hostname for the destination IP. If they differ, prefer the SVCB hostname (the SNI is likely a dummy ECH outer SNI)

**ECH detection approach**: no explicit ECH detection. Simply compare extracted SNI against SVCB-cached hostname for the same IP. If the SVCB cache says `149.154.167.220 -> example.com` but SNI says `cloudflare-ech.com`, prefer `example.com`. This works because SVCB hints are authoritative for the queried domain. No `HasECH` method needed.

## Progress Tracking

- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with + prefix

## Implementation Steps

### Task 1: Add SVCB cache and parse HTTPS/SVCB records

**Files:**
- Modify: `internal/proxy/dns_reverse.go`
- Modify: `internal/proxy/dns.go`
- Create: `internal/proxy/dns_reverse_test.go`

- [ ] Add constants: `dnsTypeHTTPS = 65`, `dnsTypeSVCB = 64`, `svcKeyIPv4Hint = 4`, `svcKeyIPv6Hint = 6`
- [ ] Add `svcbEntries` map to `ReverseDNSCache` (separate from existing `entries`) with same TTL/bounds
- [ ] Add `StoreSVCB(ip, hostname)` and `LookupSVCB(ip) string` methods
- [ ] In `PopulateFromResponse`, add cases for HTTPS and SVCB record types
- [ ] Parse SVCB RDATA: priority (2 bytes), target name (use `parseDNSName` for DNS compression), then SvcParam key-value pairs
- [ ] Extract `ipv4hint` (key 4, addresses are 4 bytes each) and `ipv6hint` (key 6, 16 bytes each)
- [ ] Store each hint IP -> hostname in `svcbEntries`
- [ ] In `HandleQuery` (`dns.go`): extend the `PopulateFromResponse` gate to also include HTTPS and SVCB query types
- [ ] Write tests: parse HTTPS record with ipv4hint and ipv6hint
- [ ] Write tests: parse SVCB record, verify StoreSVCB/LookupSVCB
- [ ] Write tests: malformed SVCB RDATA does not crash
- [ ] Write tests: HTTPS record with no hints is a no-op
- [ ] Run tests - must pass before next task

### Task 2: Use SVCB cache as ECH fallback in SNI policy check

**Files:**
- Modify: `internal/proxy/server.go`
- Test: `internal/proxy/server_test.go`

- [ ] In `sniPolicyCheck`: after extracting SNI, look up the destination IP in SVCB cache via `dnsInterceptor.LookupSVCB(ipStr)`
- [ ] If SVCB hostname exists AND differs from extracted SNI, prefer the SVCB hostname (ECH detected)
- [ ] Log `[SNI-ECH] <ip>:<port> SNI=<outer> SVCB=<real> (using SVCB hostname)` for observability
- [ ] Add comment block in `sniPolicyCheck` documenting the hostname recovery priority chain
- [ ] Write test: SNI differs from SVCB cache -> SVCB hostname used
- [ ] Write test: SNI matches SVCB cache -> SNI used (normal case)
- [ ] Write test: no SVCB cache entry -> SNI used as-is
- [ ] Write test: empty SNI with SVCB cache hit -> SVCB hostname used
- [ ] Run tests - must pass before next task

### Task 3: Verify acceptance criteria

- [ ] Verify HTTPS/SVCB records populate the SVCB cache
- [ ] Verify ECH connections recover hostname via SVCB cache
- [ ] Verify non-ECH connections still use SNI
- [ ] Run full test suite: `go test ./... -v -timeout 30s`
- [ ] Run linter: `golangci-lint run ./...`

### Task 4: [Final] Update documentation

- [ ] Add one-line note to CLAUDE.md DNS section about HTTPS/SVCB parsing for ECH fallback
- [ ] Move this plan to `docs/plans/completed/`

## Post-Completion

**Manual verification:**
- Deploy to knuth and verify SVCB record parsing with a Cloudflare-protected domain
- Test with an ECH-enabled server (e.g., `crypto.cloudflare.com`)
- Verify sluice logs show `[SNI-ECH]` entries for ECH connections
