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
- Existing SNI extraction: `internal/proxy/sni.go` (works on raw TLS records, not QUIC)

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

1. **Hostname recovery via DNS reverse cache** (not QUIC packet parsing). QUIC Initial packets encrypt the TLS ClientHello (RFC 9001 Section 5.2), so extracting SNI requires decrypting with Initial keys derived from the connection ID. This is complex and fragile. Since tun2proxy resolves DNS before sending UDP, sluice's DNS interceptor already has the IP -> hostname mapping in its reverse cache. Use that as the primary strategy.

2. **Pending session dedup with bounded buffer**. Before calling `resolveQUICPolicy` (which blocks on broker), check if there's already a pending approval for this session key. Buffer up to 32 packets per session. When approval resolves, flush or discard.

3. **Response relay fix**. The QUIC proxy's `quic-go` listener reads Initial packets from `upstream` PacketConn, but sends responses through its own listener socket back to the `upstream` address. `relayQUICResponses` reads from `upstream` and should receive these responses. The issue to investigate: does `quic-go` actually send responses back to the `upstream.LocalAddr()` that forwarded the Initial? Or does it send to the original source address from the QUIC packet header?

## Technical Details

**Hostname recovery flow:**
```
1. QUIC packet arrives at dispatch: dest = "104.16.132.229", port = 443
2. Call dnsInterceptor.ReverseLookup("104.16.132.229") -> "cloudflare.com"
3. Use "cloudflare.com" for policy eval and approval message
4. Fall back to raw IP if reverse lookup misses
```

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

### Task 1: Recover hostname from DNS reverse cache

**Files:**
- Modify: `internal/proxy/server.go`
- Modify: `internal/proxy/dns.go` (if ReverseLookup doesn't exist, add it)
- Modify: `internal/proxy/server_test.go` or create `internal/proxy/dns_test.go`

- [ ] Add `ReverseLookup(ip string) (hostname string, ok bool)` to the DNS interceptor if it doesn't exist (check the reverse cache that's populated during DNS query handling)
- [ ] In the UDP dispatch loop, after `IsQUICPacket` returns true, call `dnsInterceptor.ReverseLookup(dest)`. If hostname found, replace `dest` with it for both `sessionKey` and `resolveQUICPolicy`
- [ ] Update the approval message: when hostname is recovered, the Telegram prompt shows `cloudflare.com:443` instead of `104.16.132.229:443`
- [ ] Write tests: reverse lookup hit replaces IP, reverse lookup miss keeps IP, hostname used in session key
- [ ] Run tests

### Task 2: Deduplicate broker requests with bounded buffer

**Files:**
- Modify: `internal/proxy/server.go`
- Modify: `internal/proxy/server_test.go`

- [ ] Add `pendingQUICSessions` map (mutex-protected) to track in-flight approvals
- [ ] Before calling `resolveQUICPolicy`, check if sessionKey is pending. If so, buffer the payload (max 32 packets, drop beyond). Skip broker call.
- [ ] When approval resolves: if allowed, create session, flush buffered payloads through it, start relay goroutine. If denied, discard buffer.
- [ ] Remove pending entry after resolution (both allow and deny paths)
- [ ] Write tests: concurrent packets to same dest trigger one broker request, buffer overflow drops packets, denied approval discards buffer
- [ ] Run tests

### Task 3: Fix response relay path

**Files:**
- Modify: `internal/proxy/server.go` (relayQUICResponses)
- Modify: `internal/proxy/quic.go` (if response routing is wrong)

- [ ] Verify that quic-go's listener sends responses to the address that forwarded the Initial packet (upstream.LocalAddr). Check quic-go's source or test empirically.
- [ ] If quic-go sends to the original client address (from QUIC packet header) instead of the forwarding address, fix by using a connected UDP socket or adjusting the relay.
- [ ] Ensure relayQUICResponses wraps response payloads in SOCKS5 UDP headers with the original destination (not the QUIC proxy address)
- [ ] Write test: forward a QUIC-like packet to a UDP echo server through the relay, verify response returns via relayQUICResponses
- [ ] Run tests

### Task 4: Verify acceptance criteria

- [ ] QUIC approval shows hostname (not IP) in Telegram message
- [ ] Single broker request per destination during approval wait
- [ ] Full QUIC flow: quictest binary gets HTTP/3 response
- [ ] Run full test suite: `go test ./... -v -timeout 120s`
- [ ] Deploy to knuth and test with quictest binary
- [ ] Run tests - must pass before next task

### Task 5: [Final] Update documentation

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
