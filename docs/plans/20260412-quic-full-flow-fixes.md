# Fix QUIC Full Flow

## Overview

Three bugs prevent QUIC/HTTP3 from working end-to-end in production. The approval flow works (Telegram prompt appears, user approves) but the actual data never completes the round trip.

## Context

- UDP dispatch loop: `internal/proxy/server.go` (handleAssociate at ~line 1459, QUIC dispatch at ~line 1590)
- QUIC proxy: `internal/proxy/quic.go` (QUICProxy, handles TLS termination and HTTP/3)
- Policy engine: `internal/policy/engine.go` (EvaluateQUICDetailed)
- QUIC packet detection: `internal/proxy/protocol.go` (IsQUICPacket)
- Response relay: `internal/proxy/server.go:relayQUICResponses`
- DNS interceptor reverse cache: `internal/proxy/dns.go` (ReverseLookup for IP -> hostname)
- TLS SNI extraction: `internal/proxy/sni.go` (`extractSNI()` parses TLS ClientHello, reuse for QUIC after decryption)
- QUIC SNI extraction: `internal/proxy/quic_sni.go` (new, decrypts QUIC Initial to get ClientHello)

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- CRITICAL: every task MUST include new/updated tests
- CRITICAL: all tests must pass before starting next task
- CRITICAL: update this plan file when scope changes during implementation
- Run tests after each change
- Uses gofumpt for Go formatting
- Deploy to knuth after each fix and test with quictest binary

## Testing Strategy

- **Unit tests**: test hostname recovery, pending session dedup, relay forwarding
- **Production test**: quictest binary on knuth (full tun2proxy -> sluice -> upstream chain)

## Solution Overview

1. **Hostname recovery via QUIC SNI extraction** (primary) with DNS reverse cache fallback. QUIC Initial packets encrypt the TLS ClientHello, but the encryption uses keys derived from the Destination Connection ID (DCID) visible in the packet header (RFC 9001 Section 5). Any observer can derive the keys and decrypt to extract SNI. This mirrors TLS SNI extraction used for HTTPS. DNS reverse cache serves as fallback when decryption fails (malformed packets, unsupported versions).

2. **Pending session dedup with bounded buffer**. Before calling `resolveQUICPolicy` (which blocks on broker), check if there's already a pending approval for this session key. Buffer up to 32 packets per session. When approval resolves, flush or discard.

3. **Response relay fix**. The QUIC proxy's `quic-go` listener reads Initial packets from `upstream` PacketConn, but sends responses through its own listener socket back to the `upstream` address. `relayQUICResponses` reads from `upstream` and should receive these responses. The issue to investigate: does `quic-go` actually send responses back to the `upstream.LocalAddr()` that forwarded the Initial? Or does it send to the original source address from the QUIC packet header?

## Technical Details

**QUIC SNI extraction flow:**
```
1. QUIC Initial packet arrives at dispatch: dest = "104.16.132.229", port = 443
2. Parse QUIC long header -> extract DCID
3. Derive Initial secret: HKDF-Extract(SHA256, DCID, salt)
4. Derive client secret: HKDF-Expand-Label("client in")
5. Derive HP key, packet key, IV
6. Remove header protection (AES-ECB on sample) -> get packet number
7. Decrypt payload with AES-128-GCM(key, IV ^ pn, payload, AAD=header)
8. Parse CRYPTO frames -> reassemble TLS ClientHello
9. extractSNI(clientHello) -> "cloudflare.com"
10. Fall back to dnsInterceptor.ReverseLookup(dest) if extraction fails
11. Fall back to raw IP if both miss
```

**QUIC v1 salt (RFC 9001):** `0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a`
**QUIC v2 salt (RFC 9369):** `0x0dede3def700a6db819381be6e269dcbf9bd2ed9`

**Pending session dedup:**
```
pendingQUICSessions map[string]*pendingQUICSession

type pendingQUICSession struct {
    mu      sync.Mutex
    packets [][]byte       // buffered payloads (max 32)
    done    chan struct{}   // closed when approval resolves
    allowed bool           // true if approved, false if denied
}
```

**Response relay architecture:**
```
Client -> tun2proxy -> SOCKS5 UDP ASSOCIATE -> bindLn
  -> dispatch loop reads from bindLn
  -> sess.upstream.WriteTo(payload, quicAddr)  // forward to QUIC proxy
  -> QUIC proxy processes, sends response
  -> relayQUICResponses reads from upstream, writes to bindLn
  -> tun2proxy receives response, forwards to client
```

## Implementation Steps

### Task 1: Extract SNI from QUIC Initial packets

**Files:**
- Create: `internal/proxy/quic_sni.go` (QUIC Initial decryption + SNI extraction)
- Create: `internal/proxy/quic_sni_test.go`
- Modify: `internal/proxy/server.go` (wire into UDP dispatch loop)

- [x] Implement `ExtractQUICSNI(packet []byte) string` in `quic_sni.go`. Parse QUIC long header to get DCID and packet type (must be Initial). Derive Initial keys from DCID via HKDF (RFC 9001 Section 5). Remove header protection (AES-ECB). Decrypt payload with AES-128-GCM. Parse CRYPTO frames to reassemble TLS ClientHello. Reuse existing `extractSNI()` for the ClientHello. Support both QUIC v1 and v2 salts. Return empty string on any failure.
- [x] In the UDP dispatch loop (`handleAssociate`), after `IsQUICPacket` returns true, call `ExtractQUICSNI(payload)`. If SNI found, use it for `sessionKey` and `resolveQUICPolicy`. If extraction fails, fall back to `dnsInterceptor.ReverseLookup(dest)`. If both miss, use raw IP.
- [x] Write tests: real QUIC Initial packet with known SNI (capture or construct), malformed packet returns empty, QUIC v2 packet, fallback to DNS reverse cache, fallback to raw IP
- [x] Run tests

### Task 2: Deduplicate broker requests with bounded buffer

**Files:**
- Modify: `internal/proxy/server.go`
- Modify: `internal/proxy/server_test.go`

- [x] Add `pendingQUICSessions` map (mutex-protected) to track in-flight approvals
- [x] Before calling `resolveQUICPolicy`, check if sessionKey is pending. If so, buffer the payload (max 32 packets, drop beyond). Skip broker call.
- [x] When approval resolves: if allowed, create session, flush buffered payloads through it, start relay goroutine. If denied, discard buffer.
- [x] Remove pending entry after resolution (both allow and deny paths)
- [x] Write tests: concurrent packets to same dest trigger one broker request, buffer overflow drops packets, denied approval discards buffer
- [x] Run tests

### Task 3: Fix response relay path

**Files:**
- Modify: `internal/proxy/server.go` (relayQUICResponses)
- Modify: `internal/proxy/quic.go` (if response routing is wrong)

- [ ] Verify that quic-go's listener sends responses to the address that forwarded the Initial packet (upstream.LocalAddr). Check quic-go's source or test empirically.
- [ ] If quic-go sends to the original client address (from QUIC packet header) instead of the forwarding address, fix by using a connected UDP socket or adjusting the relay.
- [ ] Ensure relayQUICResponses wraps response payloads in SOCKS5 UDP headers with the original destination (not the QUIC proxy address)
- [ ] Write test: forward a QUIC-like packet to a UDP echo server through the relay, verify response returns via relayQUICResponses
- [ ] Run tests

### Task 4: Fix httptest IPv6 listener failures

**Files:**
- Modify: `internal/proxy/addon_h2_test.go` (`startH2Backend` function)
- Modify: `internal/vault/provider_hashicorp_test.go` (`newMockVaultServer` function)

- [ ] Fix `startH2Backend` in `addon_h2_test.go`: use `httptest.NewUnstartedServer()`, override `Listener` with `net.Listen("tcp4", "127.0.0.1:0")`, then `StartTLS()`
- [ ] Fix `newMockVaultServer` in `provider_hashicorp_test.go`: same pattern, use IPv4-only listener
- [ ] Run `go test ./internal/proxy/ ./internal/vault/ -count=1 -timeout 60s` to verify both pass
- [ ] Run tests

### Task 5: Comprehensive e2e tests for all supported protocols

**Files:**
- Create: `e2e/websocket_test.go`
- Create: `e2e/grpc_test.go`
- Create: `e2e/quic_test.go`
- Create: `e2e/dns_test.go`
- Create: `e2e/mail_test.go`
- Modify: `e2e/helpers_test.go` (add helpers for new protocol test servers)

Current e2e coverage: HTTP/HTTPS, SSH, MCP only. Missing: WebSocket, gRPC, QUIC/HTTP3, DNS, IMAP/SMTP.

- [ ] **WebSocket e2e** (`e2e/websocket_test.go`): start a WebSocket echo server behind sluice SOCKS5. Test allow rule permits WS upgrade and message exchange. Test deny rule blocks WS handshake. Test phantom token in WS handshake headers is replaced. Test text frame phantom swap works.
- [ ] **gRPC e2e** (`e2e/grpc_test.go`): start a gRPC server behind sluice. Test allow rule permits unary RPC. Test deny rule blocks connection. Test per-stream policy (HTTP/2 streams). Test credential injection in gRPC metadata headers.
- [ ] **QUIC/HTTP3 e2e** (`e2e/quic_test.go`): start an HTTP/3 server behind sluice. Test QUIC SNI extraction shows hostname in audit. Test allow rule permits HTTP/3 request. Test deny rule blocks QUIC connection. Test per-request policy on HTTP/3.
- [ ] **DNS e2e** (`e2e/dns_test.go`): test DNS query interception. Test deny rule returns NXDOMAIN. Test allowed domain forwarded to upstream. Test reverse cache populated after DNS query.
- [ ] **IMAP/SMTP e2e** (`e2e/mail_test.go`): start mock IMAP/SMTP servers behind sluice. Test allow rule permits connection. Test deny rule blocks. Test AUTH command phantom password swap.
- [ ] Run all e2e tests: `go test -tags=e2e ./e2e/ -v -count=1 -timeout=300s`
- [ ] Run tests

### Task 6: Verify acceptance criteria

- [ ] QUIC approval shows hostname (not IP) in Telegram message
- [ ] Single broker request per destination during approval wait
- [ ] Full QUIC flow: quictest binary gets HTTP/3 response
- [ ] Run full test suite: `go test ./... -v -timeout 120s`
- [ ] Deploy to knuth and test with quictest binary
- [ ] Run tests - must pass before next task

### Task 7: [Final] Update documentation

- [ ] Update CLAUDE.md if QUIC handling details changed
- [ ] Move this plan to `docs/plans/completed/`

## Post-Completion

**Manual verification on knuth:**
```bash
# Always recreate tun2proxy + openclaw together
docker compose up -d --force-recreate sluice tun2proxy && sleep 5
docker compose up -d --force-recreate openclaw && sleep 5
docker cp /tmp/quictest openclaw:/tmp/quictest
docker compose exec openclaw /tmp/quictest https://cloudflare.com
```
- Verify Telegram shows `cloudflare.com:443`
- Verify single approval prompt
- Verify HTTP/3 response is received
