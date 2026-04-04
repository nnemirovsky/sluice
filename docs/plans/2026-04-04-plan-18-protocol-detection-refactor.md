# Plan 18: Protocol Detection Refactor

## Overview

Refactor the Protocol type from string to integer enum and add deep packet inspection for reliable protocol detection beyond port-based guessing. Currently all protocol detection relies on destination port numbers, which fails when services run on non-standard ports (HTTPS on 8000, SSH on 2222, etc.). Since sluice has full packet access, it should peek at the first bytes of each connection to determine the actual protocol.

**Problem:** `Protocol` is a `string` type, inconsistent with other enums in the codebase (Verdict, ChannelType) which are integers. Protocol detection is port-only. An HTTPS server on port 8000 is detected as `generic`, missing credential injection. An HTTP server on port 443 would be incorrectly sent to the MITM handler.

**Solution:** Convert Protocol to `int` enum with `String()` and `ParseProtocol()` methods. Add byte-level detection that peeks at the first bytes of each TCP connection after the SOCKS5 CONNECT. Port-based detection becomes the initial guess. Byte inspection confirms or overrides.

**Depends on:** Plan 11 (protocol hardening, adds new protocol values). This plan refactors the type and adds deep detection.

## Context

**Detection signatures (first bytes of connection):**

| Protocol | Signature | Bytes |
|----------|-----------|-------|
| TLS/HTTPS | ContentType=Handshake | `0x16` + version (0x0301-0x0303) |
| SSH | Version banner | `SSH-` (ASCII) |
| HTTP | Method verb | `GET `, `POST`, `PUT `, `HEAD`, `DELE`, `PATC`, `OPTI`, `CONN` |
| SMTP | Server banner | `220 ` (server speaks first) |
| IMAP | Server banner | `* OK` (server speaks first) |
| QUIC | Long header | First two bits = 1, bytes 1-4 = version |
| DNS | Header format | Port 53 is reliable, but can validate header structure |

**Server-first protocols (SMTP, IMAP):** The server sends a banner before the client sends anything. Detection requires reading from the upstream after TCP connect, before relaying to the agent. This is already how the mail proxy works (it reads the server banner to decide STARTTLS behavior).

**Files that will change:**
- Modify: `internal/proxy/protocol.go` -- refactor type, add byte detection
- Modify: `internal/proxy/protocol_test.go`
- Modify: `internal/proxy/server.go` -- wire byte detection into dial path
- Modify: `internal/proxy/inject.go` -- update Protocol comparisons
- Modify: `internal/proxy/mail.go` -- update Protocol comparisons
- Modify: `internal/proxy/ssh.go` -- update Protocol comparisons
- Modify: `internal/store/store.go` -- serialize protocols as integers
- Modify: `internal/store/import.go` -- parse protocol strings from TOML to integers
- Modify: `internal/policy/types.go` -- if protocols stored in rules

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- All tests must pass before starting next task

## Implementation Steps

### Task 1: Convert Protocol from string to integer enum

**Files:**
- Modify: `internal/proxy/protocol.go`
- Modify: `internal/proxy/protocol_test.go`
- Modify: all files comparing Protocol values

```go
type Protocol int

const (
    ProtoGeneric Protocol = 0
    ProtoHTTP    Protocol = 1
    ProtoHTTPS   Protocol = 2
    ProtoSSH     Protocol = 3
    ProtoIMAP    Protocol = 4
    ProtoSMTP    Protocol = 5
    ProtoWS      Protocol = 6
    ProtoWSS     Protocol = 7
    ProtoGRPC    Protocol = 8
    ProtoDNS     Protocol = 9
    ProtoQUIC    Protocol = 10
    ProtoAPNS    Protocol = 11
)
```

- [x] Change `type Protocol string` to `type Protocol int` with explicit integer values
- [x] Add `String() string` method returning the display name ("http", "https", etc.)
- [x] Add `ParseProtocol(s string) (Protocol, error)` for TOML/CLI/API parsing
- [x] Update all string comparisons (`proto == "https"`) to integer comparisons (`proto == ProtoHTTPS`)
- [x] Update `DetectProtocol(port int) Protocol` return values to use integer constants
- [x] Update store serialization: protocols stored as integer arrays in JSON, parsed from string names in TOML import
- [x] Update policy evaluation to compare integer protocol values
- [x] Write tests for String() and ParseProtocol round-trip for all protocol values
- [x] Write tests verifying all existing protocol comparisons still work after refactor
- [x] Run tests: `go test ./... -v -timeout 60s`

### Task 2: Add byte-level protocol detection for client-first protocols

Detect TLS, SSH, and HTTP by peeking at the first bytes sent by the client after TCP connect.

**Files:**
- Modify: `internal/proxy/protocol.go`
- Modify: `internal/proxy/protocol_test.go`
- Modify: `internal/proxy/server.go`

- [x] Implement `DetectFromClientBytes(data []byte) Protocol` that examines the first bytes:
  - TLS: byte 0 = 0x16, bytes 1-2 in {0x0301, 0x0302, 0x0303} -> ProtoHTTPS
  - SSH: starts with "SSH-" -> ProtoSSH
  - HTTP: starts with method verb (GET, POST, PUT, HEAD, DELETE, PATCH, OPTIONS, CONNECT) -> ProtoHTTP
  - No match: return ProtoGeneric (keep port-based guess)
- [x] Wire into the SOCKS5 dial path: after TCP connect, use `net.Conn` peek (wrap with `bufio.Reader`) to read first bytes without consuming them
- [x] Two-phase detection: `portGuess := DetectProtocol(port)` then `confirmed := DetectFromClientBytes(peekedBytes)`. If confirmed != ProtoGeneric, use confirmed. Otherwise keep portGuess.
- [x] Store the confirmed protocol in the connection context (replacing the port-based guess)
- [x] Write tests: HTTPS on port 8000 detected correctly via TLS bytes
- [x] Write tests: SSH on port 2222 detected correctly via "SSH-" banner
- [x] Write tests: HTTP on port 9090 detected correctly via "GET " prefix
- [x] Write tests: unknown protocol on standard port (binary data on port 443 stays generic, not forced to HTTPS)
- [x] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 3: Add byte-level detection for server-first protocols

SMTP and IMAP servers send a banner before the client speaks. Detection requires reading from the upstream connection first.

**Files:**
- Modify: `internal/proxy/protocol.go`
- Modify: `internal/proxy/server.go`

- [x] Implement `DetectFromServerBytes(data []byte) Protocol` that examines the server's first bytes:
  - SMTP: starts with "220 " or "220-" -> ProtoSMTP
  - IMAP: starts with "* OK" -> ProtoIMAP
  - No match: return ProtoGeneric
- [x] For connections where port-based guess is SMTP or IMAP: connect to upstream first, peek server banner, confirm protocol, then relay banner to agent
- [x] For connections where port-based guess is not a server-first protocol: skip server banner detection (don't add latency to HTTP/SSH connections)
- [x] Write tests: SMTP on port 2525 detected via "220 " banner
- [x] Write tests: IMAP on port 1143 detected via "* OK" banner
- [x] Write tests: non-mail server on port 25 (doesn't send "220") falls back to generic
- [x] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 4: Verify acceptance criteria

- [x] Verify Protocol type is integer throughout the codebase (no string comparisons remain)
- [x] Verify Protocol.String() returns correct display names for all values
- [x] Verify ParseProtocol handles all known protocol names and returns error for unknown
- [x] Verify HTTPS on non-standard port (8000) is detected and gets MITM credential injection
- [x] Verify SSH on non-standard port (2222) is detected and gets jump host injection
- [x] Verify HTTP on non-standard port (9090) is detected correctly
- [x] Verify SMTP/IMAP on non-standard ports detected via server banner
- [x] Verify standard-port detection still works (no regression)
- [x] Verify store serializes protocols as integers in DB
- [x] Verify TOML import parses protocol strings ("https") into integers
- [x] Run full test suite: `go test ./... -v -timeout 60s -race`
- [x] Run linter: `go vet ./...`

### Task 5: [Final] Update documentation

- [ ] Update CLAUDE.md: document deep packet detection, explain two-phase detection (port guess + byte confirmation)
- [ ] Update CLAUDE.md: note that Protocol is integer enum, not string
- [ ] Update examples/config.toml: add comment noting protocol detection is automatic (no need to specify protocols for standard ports)

## Technical Details

### Two-phase detection flow

```
1. SOCKS5 CONNECT arrives for example.com:8000
2. Port-based guess: DetectProtocol(8000) -> ProtoGeneric
3. TCP connect to example.com:8000 succeeds
4. Peek first bytes from client: 0x16 0x03 0x03 ... (TLS ClientHello)
5. Byte detection: DetectFromClientBytes(data) -> ProtoHTTPS
6. Override: protocol = ProtoHTTPS (was ProtoGeneric)
7. Route through MITM injector (same as port 443)
```

### Peeking without consuming bytes

```go
// Wrap the connection with a buffered reader for peeking
br := bufio.NewReader(conn)
peeked, _ := br.Peek(8)  // peek first 8 bytes without consuming
confirmed := DetectFromClientBytes(peeked)

// Create a conn that replays the peeked bytes
peekConn := &bufferedConn{Reader: br, Conn: conn}
// Pass peekConn to the handler instead of raw conn
```

### Server-first protocol detection

```
1. Port-based guess for port 587: ProtoSMTP
2. TCP connect to mail.example.com:587
3. Read server banner: "220 mail.example.com ESMTP\r\n"
4. DetectFromServerBytes(banner) -> ProtoSMTP (confirmed)
5. Relay banner to agent, continue with mail proxy handler

If server sends something unexpected:
3. Read server banner: "\x16\x03\x03..." (TLS, not SMTP banner)
4. DetectFromServerBytes(banner) -> ProtoGeneric
5. Override to ProtoHTTPS (via DetectFromClientBytes on the TLS data)
6. Route through MITM instead of mail proxy
```

## Post-Completion

**Manual verification:**
- Run HTTPS server on port 8000, connect through sluice, verify MITM and credential injection work
- Run SSH server on port 2222, connect through sluice, verify jump host works
- Run SMTP on port 2525, connect through sluice, verify mail proxy handles it

**Future considerations:**
- Application-layer protocol detection inside TLS (ALPN negotiation reveals HTTP/2, gRPC, etc.)
- Heuristic detection for database protocols (PostgreSQL wire format starts with specific bytes)
