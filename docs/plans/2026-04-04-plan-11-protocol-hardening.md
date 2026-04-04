# Plan 11: Protocol Hardening (WebSocket + UDP + QUIC)

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

## Overview

Add WebSocket frame-level inspection, UDP interception via SOCKS5 UDP ASSOCIATE, DNS query-level policy, and QUIC/HTTP/3 MITM. This is a merged plan combining WebSocket support (originally Plan 11), UDP interception (originally Plan 12), and QUIC MITM (originally Plan 13) since they all touch the same `internal/proxy/` package and build on each other sequentially.

After this plan, sluice intercepts every protocol over both TCP and UDP. Nothing leaves the agent container without sluice seeing it.

**Key changes:**
1. Add `ws`/`wss`/`grpc`/`dns`/`quic` as recognized protocol values
2. WebSocket frame parser with phantom token replacement in text frames and content inspection
3. Switch from `armon/go-socks5` to `things-go/go-socks5` for UDP ASSOCIATE support
4. UDP policy enforcement with default-deny
5. DNS query interception with domain-level policy (NXDOMAIN for denied domains)
6. QUIC packet detection and HTTP/3 MITM using `quic-go`

**Depends on:** Plan 9 (unified rules with protocols field).

## Context

**Architecture after this plan:**
```
Agent -> tun2proxy -> SOCKS5 CONNECT (TCP)       -> sluice -> internet
                   -> SOCKS5 UDP ASSOCIATE (UDP)  -> sluice -> internet (or block)

TCP protocols:  HTTP, HTTPS, gRPC, WS, WSS, SSH, IMAP, SMTP, generic
UDP protocols:  DNS (query-level policy), QUIC (HTTP/3 MITM), generic (allow/deny)
```

**Files that will change:**
- `internal/proxy/protocol.go` -- add ProtoWS, ProtoWSS, ProtoGRPC, ProtoDNS, ProtoQUIC
- `internal/proxy/ws.go` -- new: WebSocket frame parser/proxy
- `internal/proxy/udp.go` -- new: UDP relay with policy
- `internal/proxy/dns.go` -- new: DNS query parser
- `internal/proxy/quic.go` -- new: QUIC MITM proxy
- `internal/proxy/inject.go` -- intercept WebSocket upgrade
- `internal/proxy/server.go` -- wire UDP ASSOCIATE, WebSocket, QUIC handlers
- `go.mod` -- replace armon/go-socks5, add things-go/go-socks5, quic-go, coder/websocket
- `compose.yml`, `compose.dev.yml` -- configure tun2proxy for UDP routing

**New dependencies:**
- `github.com/things-go/go-socks5` (replaces `armon/go-socks5`, adds UDP ASSOCIATE)
- `github.com/quic-go/quic-go` (QUIC/HTTP/3 implementation)

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- All tests must pass before starting next task

## Testing Strategy

- **Unit tests**: Frame parsing, DNS query parsing, QUIC detection, UDP relay, policy evaluation.
- **Integration tests**: End-to-end through MITM for WebSocket, DNS, and QUIC flows.

## Implementation Steps

### Task 1: Add new protocol values and detection

**Files:**
- Modify: `internal/proxy/protocol.go`

- [x] Add `ProtoWS Protocol = "ws"`, `ProtoWSS Protocol = "wss"`, `ProtoGRPC Protocol = "grpc"`, `ProtoDNS Protocol = "dns"`, `ProtoQUIC Protocol = "quic"` to the Protocol enum
- [x] gRPC detection: in the MITM request handler, check `Content-Type: application/grpc` and tag the request context with ProtoGRPC
- [x] WebSocket detection: check for `Connection: Upgrade` + `Upgrade: websocket` headers. Tag as ProtoWS (plaintext) or ProtoWSS (over TLS).
- [x] DNS detection: UDP port 53 = ProtoDNS
- [x] QUIC detection: implement `isQUICPacket(data []byte) bool` checking QUIC long header format (first two bits = 1, version field at bytes 1-4)
- [x] Update policy evaluation to match these new protocol values in rules
- [x] Write tests for each detection method
- [x] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 2: WebSocket frame parser

RFC 6455 Section 5.2 frame format: 2-14 byte header, optional 4-byte mask, payload.

**Files:**
- Create: `internal/proxy/ws.go`
- Create: `internal/proxy/ws_test.go`

- [x] Implement `Frame` struct: `FIN bool`, `Opcode byte` (0x0=continuation, 0x1=text, 0x2=binary, 0x8=close, 0x9=ping, 0xA=pong), `Masked bool`, `MaskKey [4]byte`, `Payload []byte`
- [x] Implement `ReadFrame(r io.Reader) (*Frame, error)` that parses the wire format
- [x] Implement `WriteFrame(w io.Writer, f *Frame) error` that serializes the wire format
- [x] Implement `Frame.UnmaskedPayload() []byte` that applies the XOR mask
- [x] Implement `Frame.SetPayload(data []byte)` that updates payload and adjusts length. If frame was masked, re-masks with same key.
- [x] Handle continuation frames: track fragmented messages, reassemble for inspection, forward individual frames
- [x] Write tests for parsing text frames (masked and unmasked)
- [x] Write tests for binary frames and control frames (ping, pong, close)
- [x] Write tests for extended payload lengths (126 = 16-bit, 127 = 64-bit)
- [x] Write tests for frame round-trip (parse then serialize, verify identical)
- [x] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 3: WebSocket proxy with phantom token replacement

Bidirectional WebSocket relay that sits between agent and upstream after HTTP upgrade. Scans text frames for phantom tokens and applies content inspection rules.

**Files:**
- Modify: `internal/proxy/ws.go`
- Modify: `internal/proxy/ws_test.go`

- [x] Implement `WSProxy` struct holding vault Provider and content inspection rules
- [x] Implement `WSProxy.Relay(agentConn, upstreamConn net.Conn)` for bidirectional frame forwarding
- [x] Text frames (opcode 0x1): unmask, scan for phantom tokens, replace with real credentials, re-mask, forward. Release credential memory immediately.
- [x] Binary frames (opcode 0x2): pass through by default
- [x] Control frames (ping/pong/close): forward unchanged
- [x] Content deny rules with `protocols = ["ws", "wss"]` and `pattern` field: check text frame content, send close frame if matched
- [x] Content redact rules: replace matched patterns in text frames before forwarding to agent
- [x] Write tests for phantom token replacement in text frames
- [x] Write tests for binary frame passthrough
- [x] Write tests for content deny (pattern match closes connection)
- [x] Write tests for content redact in response frames
- [x] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 4: Wire WebSocket proxy into MITM pipeline

Intercept `101 Switching Protocols` in goproxy and switch to frame proxying.

**Files:**
- Modify: `internal/proxy/inject.go`
- Modify: `internal/proxy/server.go`
- Modify: `internal/proxy/inject_test.go`

- [x] In goproxy's response handler: detect `101 Switching Protocols` + `Upgrade: websocket`. Hijack both agent and upstream connections.
- [x] Hand off hijacked connections to `WSProxy.Relay()` for the lifetime of the WebSocket connection
- [x] HTTP-level phantom token replacement still applies to upgrade request headers (existing behavior)
- [x] Frame-level replacement applies to all subsequent text frames (new behavior)
- [x] Write integration test: HTTP client upgrades to WebSocket through MITM, sends text frame with phantom token, verify upstream receives real credential
- [x] Write integration test: upstream sends text frame with pattern-matched string, verify agent receives redacted version
- [x] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 5: Replace armon/go-socks5 with things-go/go-socks5

Drop-in replacement that adds UDP ASSOCIATE support.

**Files:**
- Modify: `go.mod`
- Modify: `internal/proxy/server.go` (update import path)
- Modify: all files importing `armon/go-socks5`

- [x] Replace `github.com/armon/go-socks5` with `github.com/things-go/go-socks5` in go.mod
- [x] Update all import paths
- [x] Verify API compatibility (things-go maintains the same interface for TCP)
- [x] Run full test suite to verify no regressions: `go test ./... -v -timeout 60s`
- [x] Write a test that verifies UDP ASSOCIATE is available in the new library
- [x] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 6: UDP relay with policy enforcement

Handle SOCKS5 UDP ASSOCIATE sessions with per-datagram policy evaluation.

**Files:**
- Create: `internal/proxy/udp.go`
- Create: `internal/proxy/udp_test.go`

- [x] Implement `UDPRelay` struct that handles SOCKS5 UDP ASSOCIATE sessions
- [x] On each UDP datagram: extract destination address, evaluate policy (same engine as TCP)
- [x] Default verdict for UDP: deny (unless explicitly allowed). Safe default since most legitimate API traffic uses TCP.
- [x] Allowed datagrams: relay to destination, relay response back
- [x] Denied datagrams: drop silently, log to audit
- [x] Ask datagrams: deny immediately (Telegram approval for individual UDP packets is not practical)
- [x] `protocols = ["udp"]` matching in policy evaluation
- [x] Write tests for UDP policy evaluation (allow, deny, ask-treated-as-deny)
- [x] Write tests for UDP relay (send datagram, receive response)
- [x] Write tests for default-deny behavior
- [x] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 7: DNS query interception

Parse DNS queries on UDP port 53. Apply policy at the domain level. Prevents DNS exfiltration.

**Files:**
- Create: `internal/proxy/dns.go`
- Create: `internal/proxy/dns_test.go`

- [x] Implement `DNSInterceptor` that parses DNS query packets (Question section only)
- [x] Extract queried domain name from the DNS Question section
- [x] Evaluate policy against the queried domain (same glob matching as network rules)
- [x] Allowed domain: forward DNS query to upstream resolver, relay response
- [x] Denied domain: return NXDOMAIN response
- [x] Log all DNS queries to audit log (destination=queried domain, port=53, protocol=dns)
- [x] Add `--dns-resolver` flag for configurable upstream resolver (default: system resolver)
- [x] Write tests for DNS query parsing (A, AAAA, CNAME)
- [x] Write tests for policy evaluation on DNS domains
- [x] Write tests for NXDOMAIN response generation
- [x] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 8: Wire UDP ASSOCIATE and DNS into SOCKS5 server

Connect UDP relay and DNS interceptor to the SOCKS5 server.

**Files:**
- Modify: `internal/proxy/server.go`
- Modify: `internal/proxy/server_test.go`

- [x] Configure `things-go/go-socks5` to handle UDP ASSOCIATE requests
- [x] On UDP ASSOCIATE: create UDP relay bound to a local port, return to client
- [x] Wire relay to use `UDPRelay` for general UDP and `DNSInterceptor` for port 53
- [x] UDP connection tracking: map client addresses to relay sessions, clean up on TCP control connection close
- [x] Update audit logging: log UDP events with protocol="udp" or protocol="dns"
- [x] Write integration test: SOCKS5 client sends UDP ASSOCIATE, sends UDP packet, receives response
- [x] Write integration test: DNS query through UDP ASSOCIATE to mock DNS server
- [x] Write integration test: blocked UDP destination dropped silently
- [x] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 9: QUIC packet detection and HTTP/3 termination

Detect QUIC initial packets in the UDP relay. Terminate QUIC with sluice's CA certificate.

**Files:**
- Create: `internal/proxy/quic.go`
- Create: `internal/proxy/quic_test.go`

- [x] Add `github.com/quic-go/quic-go` dependency
- [x] In UDP relay: when a packet to port 443 (or other HTTPS ports) is detected as QUIC, route to QUIC handler
- [x] Implement `QUICProxy` struct holding CA certificate, vault Provider, BindingResolver
- [x] QUIC listener accepts agent connections using `quic.ListenAddr` with TLS config signed by CA
- [x] Generate per-host QUIC TLS certificates using existing `GenerateCertForHost` from ca.go
- [x] Extract SNI from TLS ClientHello for per-host cert generation
- [x] If no QUIC handler configured, fall back to connection-level allow/deny (existing behavior)
- [x] Write test: QUIC client connects to proxy with trusted CA, handshake succeeds
- [x] Write test: SNI extraction returns correct hostname
- [x] Write test: QUIC packet detection (valid QUIC, non-QUIC UDP)
- [x] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 10: HTTP/3 request interception and credential injection

Read HTTP/3 requests from agent's QUIC connection. Apply phantom token replacement and policy. Forward to upstream.

**Files:**
- Modify: `internal/proxy/quic.go`
- Modify: `internal/proxy/quic_test.go`

- [x] Use `quic-go/http3` to create HTTP/3 server handler for agent side
- [x] For each HTTP/3 request: read headers and body, apply phantom token replacement (reuse inject.go logic)
- [x] Apply content inspection rules (deny patterns in request, redact patterns in response)
- [x] Forward request to upstream using `http3.RoundTripper` (QUIC client to real server)
- [x] Relay response back to agent with redaction rules applied
- [x] Log to audit: destination, port, protocol="quic", verdict
- [x] Write test: HTTP/3 request through QUIC MITM, phantom token in header replaced
- [x] Write test: denied content pattern blocks the request
- [x] Write test: redact pattern modifies the response
- [x] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 11: Wire QUIC handler into server and update Docker compose

Connect QUIC handler to UDP relay. Update Docker compose for UDP routing.

**Files:**
- Modify: `internal/proxy/server.go`
- Modify: `internal/proxy/udp.go`
- Modify: `compose.yml`, `compose.dev.yml`

- [x] In `server.New()`: if credential injection enabled, create `QUICProxy` alongside existing `Injector`
- [x] QUICProxy listens on local UDP port (like Injector listens on local TCP port)
- [x] UDP relay: when QUIC packet detected, forward to QUICProxy's local port
- [x] Update tun2proxy command in compose files to enable UDP routing
- [x] Add default UDP deny rule in examples/config.toml: `[[deny]] destination = "*" protocols = ["udp"]`
- [x] Add DNS allow rule: `[[allow]] destination = "dns.google" ports = [53] protocols = ["udp", "dns"]`
- [x] Write integration test: full chain (UDP ASSOCIATE -> QUIC detection -> HTTP/3 MITM -> credential injection)
- [x] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 12: Verify acceptance criteria

- [ ] Verify `ws`/`wss` protocols detected from upgrade headers
- [ ] Verify `grpc` protocol detected from content-type header
- [ ] Verify phantom tokens in WebSocket text frames are replaced
- [ ] Verify binary frames pass through unmodified
- [ ] Verify content deny/redact rules work on WebSocket frames
- [ ] Verify UDP packets from agent are intercepted (not bypassing)
- [ ] Verify default-deny for UDP
- [ ] Verify DNS queries logged with domain name
- [ ] Verify denied DNS domains return NXDOMAIN
- [ ] Verify QUIC packets detected in UDP relay
- [ ] Verify QUIC connections terminated with sluice's CA certificate
- [ ] Verify HTTP/3 requests have phantom tokens replaced
- [ ] Verify `protocols = ["quic"]` in rules matches QUIC traffic
- [ ] Verify tun2proxy routes both TCP and UDP through sluice
- [ ] Run full test suite: `go test ./... -v -timeout 60s -race`
- [ ] Run linter: `go vet ./...`

### Task 13: [Final] Update documentation

- [ ] Update CLAUDE.md: document all new protocol values (ws, wss, grpc, dns, quic)
- [ ] Update CLAUDE.md: document WebSocket frame inspection
- [ ] Update CLAUDE.md: document UDP interception and default-deny
- [ ] Update CLAUDE.md: document DNS query-level policy
- [ ] Update CLAUDE.md: document QUIC MITM
- [ ] Update CLAUDE.md: document SOCKS5 library change (things-go/go-socks5)
- [ ] Update CLAUDE.md: update complete protocol support table
- [ ] Update examples/config.toml: add WebSocket, UDP, DNS, QUIC rule examples

## Technical Details

### Complete protocol support table after this plan

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

### WebSocket frame inspection flow

```
Text frame from agent:
  1. ReadFrame -> UnmaskedPayload
  2. Scan for phantom tokens -> replace with real credentials
  3. Scan for deny patterns -> close connection if matched
  4. SetPayload (re-mask) -> WriteFrame to upstream

Text frame from upstream:
  1. ReadFrame
  2. Scan for redact patterns -> replace
  3. WriteFrame to agent
```

### QUIC initial packet detection

```go
func isQUICPacket(data []byte) bool {
    if len(data) < 5 { return false }
    if data[0]&0xC0 != 0xC0 { return false }  // long header check
    version := binary.BigEndian.Uint32(data[1:5])
    return version == 0x00000001 || version == 0x6b3343cf  // QUIC v1, v2
}
```

### DNS query parsing (minimal)

Only need to parse the Question section (12-byte header + length-prefixed labels + QTYPE + QCLASS). No need for answer/authority/additional sections.

### Default UDP policy in config.toml

```toml
[[deny]]
destination = "*"
protocols = ["udp"]
name = "block all UDP by default"

[[allow]]
destination = "dns.google"
ports = [53]
protocols = ["udp"]
name = "allow Google DNS"
```

## Post-Completion

**Manual verification:**
- Test WebSocket with a real echo server (wscat)
- Deploy three-container stack, verify DNS queries logged
- Verify agent cannot use QUIC (falls back to TCP unless explicitly allowed)
- Test with curl --http3 through the proxy
- Verify tun2proxy routes both TCP and UDP

**Future considerations:**
- Per-message compression (permessage-deflate) for WebSocket frames
- WebSocket subprotocol awareness (mcp subprotocol)
- QUIC 0-RTT handling
