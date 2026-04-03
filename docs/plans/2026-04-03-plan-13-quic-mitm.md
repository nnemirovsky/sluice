# Plan 13: QUIC / HTTP/3 MITM

## Overview

Add QUIC (HTTP/3) man-in-the-middle interception using `quic-go`. This is the final piece of the full-protocol interception story. With Plans 11 (WebSocket) and 12 (UDP), sluice can intercept and inspect all TCP and all UDP at the connection level. This plan adds content-level inspection for QUIC/HTTP/3 traffic: request/response reading, phantom token replacement, and policy enforcement per-request (not just per-connection).

**Problem:** After Plan 12, QUIC UDP packets are allowed or denied at the destination level. But sluice cannot inspect the HTTP/3 requests inside QUIC (the protocol encrypts everything, including headers). Without QUIC MITM, sluice cannot inject credentials or apply content inspection rules to HTTP/3 traffic. Most SDKs fall back to HTTP/2 over TCP when QUIC fails, but as QUIC adoption grows, this gap widens.

**Solution:** Use `quic-go` to terminate QUIC connections from the agent using sluice's CA certificate. Inspect HTTP/3 requests, replace phantom tokens, apply policy. Re-initiate QUIC to the upstream server with the real credentials. Same pattern as the goproxy HTTPS MITM but for QUIC/HTTP/3.

**Depends on:** Plan 12 (UDP interception, SOCKS5 UDP ASSOCIATE working). Plan 9 (unified rules with `quic` protocol value).

## Context

**Architecture:**
```
Agent -> tun2proxy -> SOCKS5 UDP ASSOCIATE -> sluice UDP relay
  -> destination port 443 + QUIC detection? -> QUIC MITM handler
  -> terminate QUIC with sluice CA cert
  -> read HTTP/3 request, phantom token swap, policy check
  -> re-initiate QUIC to upstream with real credentials
  -> relay HTTP/3 response (with redaction) back to agent
```

**Key challenge:** QUIC detection. Unlike TCP where port-based detection works (443 = HTTPS), UDP port 443 could be QUIC or something else. QUIC has a recognizable initial packet format (long header with version field) that can be used for detection.

**Files:**
- Create: `internal/proxy/quic.go` -- QUIC MITM proxy using quic-go
- Create: `internal/proxy/quic_test.go`
- Modify: `internal/proxy/udp.go` -- route detected QUIC to QUIC handler
- Modify: `internal/proxy/protocol.go` -- add ProtoQUIC, QUIC packet detection
- Modify: `internal/proxy/server.go` -- wire QUIC handler

**New dependencies:**
- `github.com/quic-go/quic-go` (QUIC implementation)

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- All tests must pass before starting next task

## Testing Strategy

- **Unit tests**: QUIC packet detection, HTTP/3 request parsing, phantom replacement.
- **Integration tests**: End-to-end QUIC through the proxy with credential injection.

## Implementation Steps

### Task 1: QUIC packet detection in UDP relay

Detect QUIC initial packets in the UDP relay so they can be routed to the QUIC MITM handler instead of being forwarded as generic UDP.

**Files:**
- Modify: `internal/proxy/protocol.go`
- Modify: `internal/proxy/udp.go`

QUIC initial packets have a recognizable format:
- First byte has the "Long Header" bit set (bit 7 = 1, bit 6 = 1)
- Bytes 1-4 contain the QUIC version (e.g., 0x00000001 for QUIC v1)
- This is enough to distinguish QUIC from other UDP traffic

- [ ] Add `ProtoQUIC Protocol = "quic"` to the Protocol enum
- [ ] Implement `isQUICPacket(data []byte) bool` that checks the QUIC long header format
- [ ] In the UDP relay: when a packet to port 443 (or other HTTPS ports) is detected as QUIC, route to the QUIC MITM handler instead of generic UDP relay
- [ ] If no QUIC handler is configured, fall back to connection-level allow/deny (existing behavior)
- [ ] Write tests for QUIC packet detection (valid QUIC, non-QUIC UDP, edge cases)
- [ ] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 2: QUIC termination with CA certificate

Accept QUIC connections from the agent using sluice's existing CA certificate (the same one used for TLS MITM). Generate per-host QUIC certificates the same way goproxy generates per-host TLS certificates.

**Files:**
- Create: `internal/proxy/quic.go`
- Create: `internal/proxy/quic_test.go`

- [ ] Add `github.com/quic-go/quic-go` dependency
- [ ] Implement `QUICProxy` struct holding the CA certificate, vault Provider, and BindingResolver
- [ ] Implement QUIC listener that accepts agent connections using `quic.ListenAddr` with TLS config signed by the CA
- [ ] Generate per-host QUIC TLS certificates using the same CA and logic as `internal/proxy/ca.go` (reuse `GenerateCertForHost`)
- [ ] Accept the QUIC connection, extract SNI (Server Name Indication) from the TLS ClientHello
- [ ] Write test: QUIC client connects to the proxy with a trusted CA, handshake succeeds
- [ ] Write test: SNI extraction returns correct hostname
- [ ] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 3: HTTP/3 request interception and phantom token replacement

Read HTTP/3 requests from the agent's QUIC connection. Apply phantom token replacement and policy. Forward to the upstream via a new QUIC connection.

**Files:**
- Modify: `internal/proxy/quic.go`
- Modify: `internal/proxy/quic_test.go`

- [ ] Use `quic-go/http3` to create an HTTP/3 server handler for the agent side
- [ ] For each HTTP/3 request: read headers and body (same as HTTP/1.1 and HTTP/2 in goproxy)
- [ ] Apply phantom token replacement in headers and body (reuse logic from inject.go's `injectCredentials`)
- [ ] Apply content inspection rules (deny patterns in request, redact patterns in response)
- [ ] Forward the request to the upstream using `http3.RoundTripper` (QUIC client to the real server)
- [ ] Relay the response back to the agent, applying redaction rules
- [ ] Log to audit: destination, port, protocol="quic", verdict
- [ ] Write test: HTTP/3 request through the QUIC MITM, phantom token in header is replaced
- [ ] Write test: HTTP/3 request with phantom token in body is replaced
- [ ] Write test: denied content pattern blocks the request
- [ ] Write test: redact pattern modifies the response
- [ ] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 4: Wire QUIC handler into UDP relay and server

Connect the QUIC MITM handler to the UDP relay so detected QUIC packets are intercepted.

**Files:**
- Modify: `internal/proxy/server.go`
- Modify: `internal/proxy/udp.go`
- Modify: `internal/proxy/server_test.go`

- [ ] In `server.New()`: if credential injection is enabled, create a `QUICProxy` alongside the existing `Injector`
- [ ] The QUICProxy listens on a local UDP port (like the Injector listens on a local TCP port)
- [ ] In the UDP relay: when a QUIC packet is detected, forward to the QUICProxy's local UDP port instead of the destination
- [ ] The QUICProxy handles the full QUIC lifecycle (connection, HTTP/3 requests, credential injection, upstream forwarding)
- [ ] Add `protocols = ["quic"]` matching in policy evaluation for QUIC-specific rules
- [ ] Write integration test: agent makes HTTP/3 request through the full proxy chain (tun2proxy simulated, SOCKS5 UDP ASSOCIATE, QUIC MITM)
- [ ] Write integration test: policy denies QUIC to a specific destination
- [ ] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 5: Verify acceptance criteria

- [ ] Verify QUIC packets are detected in the UDP relay
- [ ] Verify QUIC connections are terminated with sluice's CA certificate
- [ ] Verify HTTP/3 requests have phantom tokens replaced in headers and body
- [ ] Verify content deny rules block HTTP/3 requests matching patterns
- [ ] Verify content redact rules modify HTTP/3 responses
- [ ] Verify non-QUIC UDP traffic is unaffected (still handled by generic UDP relay)
- [ ] Verify `protocols = ["quic"]` in rules matches QUIC traffic specifically
- [ ] Verify audit log entries include protocol="quic"
- [ ] Verify QUIC connections to hosts WITHOUT bindings still have global phantom replacement
- [ ] Run full test suite: `go test ./... -v -timeout 60s -race`
- [ ] Run linter: `go vet ./...`

### Task 6: [Final] Update documentation

- [ ] Update CLAUDE.md: document QUIC MITM, detection, credential injection
- [ ] Update CLAUDE.md: document `quic` protocol value
- [ ] Update CLAUDE.md: update the protocol support table (HTTP/HTTPS/WS/WSS/gRPC/SSH/IMAP/SMTP/QUIC/DNS/generic)
- [ ] Update examples/config.toml: add QUIC-specific rule examples
- [ ] Update compose.yml comments: note that QUIC is now intercepted

## Technical Details

### QUIC MITM flow

```
1. Agent's HTTP client negotiates QUIC with api.anthropic.com:443
2. tun2proxy intercepts the UDP packet
3. SOCKS5 UDP ASSOCIATE sends it to sluice's UDP relay
4. UDP relay detects QUIC initial packet (long header, version field)
5. UDP relay forwards to QUICProxy's local listener
6. QUICProxy terminates QUIC with per-host certificate signed by sluice CA
7. Agent's HTTP client completes QUIC handshake (trusts sluice CA)
8. HTTP/3 request arrives (HEADERS + DATA frames)
9. QUICProxy reads request, applies phantom token replacement
10. QUICProxy opens QUIC connection to real api.anthropic.com:443
11. Forwards modified request to upstream
12. Reads response, applies redaction rules
13. Relays response to agent
```

### QUIC initial packet detection

```go
func isQUICPacket(data []byte) bool {
    if len(data) < 5 {
        return false
    }
    // Long header: first two bits are 1
    if data[0]&0xC0 != 0xC0 {
        return false
    }
    // Version field at bytes 1-4
    // QUIC v1: 0x00000001, QUIC v2: 0x6b3343cf
    version := binary.BigEndian.Uint32(data[1:5])
    return version == 0x00000001 || version == 0x6b3343cf
}
```

### quic-go integration pattern

```go
// Agent-facing QUIC listener (terminates with CA cert)
listener, _ := quic.ListenAddr("127.0.0.1:0", generateTLSConfig(caCert, sni), &quic.Config{})

// Upstream QUIC client (connects to real server)
transport := &http3.RoundTripper{
    TLSClientConfig: &tls.Config{},
}
resp, _ := transport.RoundTrip(modifiedRequest)
```

### Certificate generation

Reuse the existing `GenerateCertForHost` function from `internal/proxy/ca.go`. The same CA cert that signs TLS certificates for the HTTP MITM also signs QUIC certificates. The agent trusts this CA (mounted via the sluice-ca volume).

### Performance considerations

- QUIC connection setup is faster than TCP+TLS (0-RTT)
- The MITM adds one extra QUIC hop (agent -> sluice -> upstream)
- HTTP/3 request inspection has the same overhead as HTTP/2 inspection (read headers + body, modify, forward)
- Per-host certificate caching (same as TLS MITM) avoids repeated key generation

## Post-Completion

**Manual verification:**
- Test with a QUIC-capable HTTP client (e.g., `curl --http3`)
- Verify phantom token replacement in HTTP/3 requests
- Verify HTTP/3 fallback: if QUIC MITM fails, agent falls back to HTTP/2 over TCP (which sluice already handles)
- Performance: compare HTTP/2 vs HTTP/3 latency through the proxy

**Complete protocol support table after all plans:**

| Protocol | Transport | Detection | Credential injection | Content inspection |
|----------|-----------|-----------|---------------------|-------------------|
| `http` | TCP | Port 80, 8080 | MITM phantom swap | Full request/response |
| `https` | TCP | Port 443, 8443 | MITM phantom swap | Full request/response |
| `grpc` | TCP | Content-Type header | Header phantom swap | Request/response metadata |
| `ws` | TCP | Upgrade header | Handshake + frame inspection | Text frame content |
| `wss` | TCP | Upgrade header over TLS | Handshake + frame inspection | Text frame content |
| `ssh` | TCP | Port 22 | Jump host, key from vault | N/A |
| `imap` | TCP | Port 143, 993 | AUTH command proxy | N/A |
| `smtp` | TCP | Port 25, 587, 465 | AUTH command proxy | N/A |
| `dns` | UDP | Port 53 | N/A | Domain-level policy |
| `quic` | UDP | QUIC long header | HTTP/3 MITM phantom swap | Full HTTP/3 request/response |
| `generic` | TCP/UDP | Fallback | Connection-level only | None |
