# Plan 11: WebSocket Frame Inspection

## Overview

Add WebSocket (`ws`/`wss`) as recognized protocols with frame-level inspection and phantom token replacement. Currently, WebSocket connections flow through sluice's MITM as opaque TCP after the HTTP upgrade handshake. This means phantom tokens in WebSocket message frames (used by some APIs for per-message authentication) are not replaced, and content inspection/redaction rules don't apply to WebSocket traffic.

**Problem:** Some APIs (Twilio Media Streams, real-time AI model endpoints, MCP over WebSocket) send authentication tokens inside WebSocket text frames, not just in the handshake headers. Sluice currently only intercepts the HTTP upgrade handshake, missing credential injection and content inspection in the frame stream.

**Solution:** Parse WebSocket frames after the HTTP `101 Switching Protocols` response. For text frames: scan for phantom tokens and replace them. Apply content inspection (deny/redact rules with `protocols = ["ws", "wss"]`) to frame payloads. Binary frames pass through by default (optionally scannable). Add `ws`/`wss`/`grpc` as recognized protocol values.

**Depends on:** Plan 9 (unified rules with protocols field, Channel interface).

## Context

**Files that will change:**
- `internal/proxy/protocol.go` -- add ProtoWS, ProtoWSS, ProtoGRPC to Protocol enum
- `internal/proxy/inject.go` -- intercept WebSocket upgrade, switch to frame proxying
- `internal/proxy/ws.go` -- new: WebSocket frame parser/proxy with phantom replacement
- `internal/proxy/server.go` -- wire WebSocket handler into dial path
- `internal/policy/types.go` -- no change (protocols field already exists from Plan 9)

**Key pattern:** Similar to `internal/proxy/mail.go` which switches from line-based to TLS after STARTTLS. The WebSocket handler switches from HTTP request/response to frame-based proxying after the `101 Switching Protocols` response.

**No new dependencies.** WebSocket frame format is simple enough to parse without a library (2-14 byte header, optional 4-byte mask, payload).

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- All tests must pass before starting next task

## Testing Strategy

- **Unit tests**: Frame parsing/serialization, phantom replacement in frames, protocol detection.
- **Integration tests**: End-to-end WebSocket through the MITM with phantom token in a text frame.

## Implementation Steps

### Task 1: Add ws/wss/grpc to protocol enum and detection

**Files:**
- Modify: `internal/proxy/protocol.go`

- [ ] Add `ProtoWS Protocol = "ws"`, `ProtoWSS Protocol = "wss"`, `ProtoGRPC Protocol = "grpc"` to the Protocol enum
- [ ] gRPC detection: in the MITM request handler, check `Content-Type: application/grpc` and tag the request context with ProtoGRPC. Port-based detection stays as `https`. Per-request detection refines it.
- [ ] WebSocket detection: in the MITM, check for `Connection: Upgrade` + `Upgrade: websocket` headers in the request. Tag as ProtoWS (plaintext) or ProtoWSS (over TLS).
- [ ] Update policy evaluation to match these new protocol values in rules
- [ ] Write tests for gRPC content-type detection
- [ ] Write tests for WebSocket upgrade header detection
- [ ] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 2: WebSocket frame parser

Implement a WebSocket frame reader/writer. The frame format (RFC 6455 Section 5.2):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+-------------------------------+
|     Masking-key (0 or 4 bytes)                                |
+-------------------------------+-------------------------------+
|                     Payload Data                              |
+---------------------------------------------------------------+
```

**Files:**
- Create: `internal/proxy/ws.go`
- Create: `internal/proxy/ws_test.go`

- [ ] Implement `Frame` struct: `FIN bool`, `Opcode byte` (0x0=continuation, 0x1=text, 0x2=binary, 0x8=close, 0x9=ping, 0xA=pong), `Masked bool`, `MaskKey [4]byte`, `Payload []byte`
- [ ] Implement `ReadFrame(r io.Reader) (*Frame, error)` that parses the wire format
- [ ] Implement `WriteFrame(w io.Writer, f *Frame) error` that serializes the wire format
- [ ] Implement `Frame.UnmaskedPayload() []byte` that applies the XOR mask
- [ ] Implement `Frame.SetPayload(data []byte)` that updates payload and adjusts length. If frame was masked, re-masks with same key.
- [ ] Handle continuation frames: track fragmented messages, reassemble for inspection, then forward individual frames
- [ ] Write tests for parsing text frames (masked and unmasked)
- [ ] Write tests for parsing binary frames
- [ ] Write tests for control frames (ping, pong, close)
- [ ] Write tests for extended payload lengths (126 = 16-bit, 127 = 64-bit)
- [ ] Write tests for frame round-trip (parse then serialize, verify identical)
- [ ] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 3: WebSocket proxy with phantom token replacement

Implement a bidirectional WebSocket proxy that sits between agent and upstream after the HTTP upgrade. Scans text frames for phantom tokens and replaces them.

**Files:**
- Modify: `internal/proxy/ws.go`
- Modify: `internal/proxy/ws_test.go`

- [ ] Implement `WSProxy` struct holding vault Provider (for phantom token list) and optional content inspection rules
- [ ] Implement `WSProxy.Relay(agentConn, upstreamConn net.Conn)` that reads frames from both sides, inspects/modifies, and forwards
- [ ] For text frames (opcode 0x1): unmask, scan for all known phantom tokens, replace with real credentials, re-mask, forward. Release credential memory immediately.
- [ ] For binary frames (opcode 0x2): pass through by default. Optionally scan if they contain UTF-8 text.
- [ ] For control frames (ping/pong/close): forward unchanged
- [ ] Apply content inspection rules: deny rules with `protocols = ["ws", "wss"]` and a `pattern` field check text frame content. If matched, send a close frame to both sides.
- [ ] Apply redact rules: replace matched patterns in text frames before forwarding to agent
- [ ] Write tests for phantom token replacement in text frames
- [ ] Write tests for binary frame passthrough
- [ ] Write tests for content deny (pattern match closes connection)
- [ ] Write tests for content redact in response frames
- [ ] Write tests for bidirectional relay (agent sends, upstream responds)
- [ ] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 4: Wire WebSocket proxy into MITM pipeline

Intercept the `101 Switching Protocols` response in goproxy and switch from HTTP proxying to WebSocket frame proxying.

**Files:**
- Modify: `internal/proxy/inject.go`
- Modify: `internal/proxy/server.go`
- Modify: `internal/proxy/inject_test.go`

- [ ] In goproxy's response handler: detect `101 Switching Protocols` + `Upgrade: websocket`. When detected, hijack both the agent and upstream connections.
- [ ] Hand off the hijacked connections to `WSProxy.Relay()`. This runs for the lifetime of the WebSocket connection.
- [ ] The HTTP-level phantom token replacement still applies to the upgrade request headers (existing behavior)
- [ ] The frame-level replacement applies to all subsequent text frames (new behavior)
- [ ] Write integration test: HTTP client upgrades to WebSocket through the MITM, sends a text frame containing a phantom token, verify the upstream receives the real credential
- [ ] Write integration test: upstream sends a text frame containing a pattern-matched string, verify the agent receives the redacted version
- [ ] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 5: Verify acceptance criteria

- [ ] Verify `ws` and `wss` protocols are detected from upgrade headers
- [ ] Verify `grpc` protocol is detected from content-type header
- [ ] Verify phantom tokens in WebSocket text frames are replaced
- [ ] Verify binary frames pass through unmodified
- [ ] Verify content deny rules with `protocols = ["wss"]` close the WebSocket on match
- [ ] Verify content redact rules modify text frames before reaching the agent
- [ ] Verify ping/pong/close control frames are forwarded correctly
- [ ] Verify WebSocket connections without phantom tokens pass through normally (no performance regression)
- [ ] Run full test suite: `go test ./... -v -timeout 60s -race`
- [ ] Run linter: `go vet ./...`

### Task 6: [Final] Update documentation

- [ ] Update CLAUDE.md: document ws/wss/grpc protocol values
- [ ] Update CLAUDE.md: document WebSocket frame inspection behavior
- [ ] Update examples/config.toml: add WebSocket-specific rule examples

## Technical Details

### WebSocket proxy integration point

```
Agent -> SOCKS5 -> goproxy MITM -> HTTP upgrade request (phantom swap in headers)
                                -> 101 Switching Protocols response
                                -> hijack both connections
                                -> WSProxy.Relay(agentConn, upstreamConn)
                                   -> read frame from agent, inspect, forward to upstream
                                   <- read frame from upstream, inspect, forward to agent
```

### Frame inspection flow

```
Text frame from agent:
  1. ReadFrame (parse header + payload)
  2. UnmaskedPayload (apply XOR mask)
  3. Scan for phantom tokens -> replace with real credentials
  4. Scan for deny patterns -> close connection if matched
  5. SetPayload (re-mask if needed, update length)
  6. WriteFrame to upstream

Text frame from upstream:
  1. ReadFrame
  2. Scan for redact patterns -> replace matched content
  3. WriteFrame to agent
```

### Performance considerations

- Frame parsing is zero-copy where possible (read directly into the Frame's payload buffer)
- Phantom token scanning uses `bytes.Contains` (same as HTTP injection)
- Binary frames skip all inspection (just copy between connections)
- Control frames are tiny and forwarded immediately (no buffering)

## Post-Completion

**Manual verification:**
- Test with a real WebSocket echo server (e.g., `wscat`)
- Verify Twilio Media Streams work through the proxy
- Load test: sustained WebSocket connection with high frame rate

**Future considerations:**
- Per-message compression (permessage-deflate extension) -- frames would need decompression before inspection
- WebSocket subprotocol awareness (e.g., `mcp` subprotocol for MCP-over-WebSocket)
