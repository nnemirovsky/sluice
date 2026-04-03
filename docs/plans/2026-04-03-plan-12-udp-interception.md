# Plan 12: UDP Interception and DNS Policy

## Overview

Add UDP interception to sluice so that ALL agent traffic (TCP and UDP) passes through policy enforcement. Currently, UDP packets bypass sluice entirely because the SOCKS5 proxy only handles TCP and tun2proxy only routes TCP to the SOCKS5 port. This means DNS queries, QUIC negotiation, WebRTC data channels, and any other UDP traffic from the agent escapes unmonitored.

**Problem:** The security model promises "nothing leaves without sluice seeing it." UDP traffic breaks this promise. An agent could exfiltrate data via DNS queries, negotiate QUIC to bypass the HTTPS MITM, or use WebRTC data channels to tunnel arbitrary data.

**Solution:** Switch from `armon/go-socks5` to `things-go/go-socks5` (which supports UDP ASSOCIATE). Implement UDP policy enforcement. Add DNS-specific interception for query-level policy. Default policy: deny all UDP except explicitly allowed destinations. Configure tun2proxy to route UDP through SOCKS5 UDP ASSOCIATE.

**Depends on:** Plan 9 (unified rules with protocols field).

## Context

**Architecture change:**
```
Current:  Agent -> tun2proxy -> SOCKS5 CONNECT (TCP only) -> sluice
          Agent -> tun2proxy -> UDP bypasses entirely

Target:   Agent -> tun2proxy -> SOCKS5 CONNECT (TCP)       -> sluice -> internet
          Agent -> tun2proxy -> SOCKS5 UDP ASSOCIATE (UDP)  -> sluice -> internet (or block)
```

**Key dependency:** `things-go/go-socks5` is a maintained fork of `armon/go-socks5` that adds UDP ASSOCIATE support. Drop-in replacement.

**Files that will change:**
- `go.mod` -- replace `armon/go-socks5` with `things-go/go-socks5`
- `internal/proxy/server.go` -- wire UDP ASSOCIATE handler, UDP policy evaluation
- `internal/proxy/udp.go` -- new: UDP relay with policy enforcement
- `internal/proxy/dns.go` -- new: DNS query parser for policy-aware DNS interception
- `internal/proxy/protocol.go` -- add ProtoDNS, update detection for UDP
- `compose.yml`, `compose.dev.yml` -- configure tun2proxy to route UDP through SOCKS5

**New dependencies:**
- `github.com/things-go/go-socks5` (replaces `armon/go-socks5`)

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- All tests must pass before starting next task

## Testing Strategy

- **Unit tests**: UDP relay, DNS parsing, policy evaluation for UDP destinations.
- **Integration tests**: End-to-end UDP through SOCKS5 with policy enforcement.

## Implementation Steps

### Task 1: Replace armon/go-socks5 with things-go/go-socks5

Drop-in replacement. Verify all existing TCP tests still pass.

**Files:**
- Modify: `go.mod`
- Modify: `internal/proxy/server.go` (update import path)
- Modify: all files importing `armon/go-socks5`

- [ ] Replace `github.com/armon/go-socks5` with `github.com/things-go/go-socks5` in go.mod
- [ ] Update all import paths from `github.com/armon/go-socks5` to `github.com/things-go/go-socks5`
- [ ] Verify API compatibility (things-go/go-socks5 maintains the same interface for TCP)
- [ ] Run full test suite to verify no regressions: `go test ./... -v -timeout 60s`
- [ ] Write a test that verifies UDP ASSOCIATE is available in the new library (basic capability check)
- [ ] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 2: Implement UDP relay with policy enforcement

Create a UDP handler that evaluates policy for each UDP datagram's destination before relaying.

**Files:**
- Create: `internal/proxy/udp.go`
- Create: `internal/proxy/udp_test.go`
- Modify: `internal/proxy/protocol.go` (add ProtoDNS)

- [ ] Add `ProtoDNS Protocol = "dns"` to the Protocol enum
- [ ] Add UDP protocol detection: port 53 = `dns`, others = `generic`
- [ ] Implement `UDPRelay` struct that handles SOCKS5 UDP ASSOCIATE sessions
- [ ] On each UDP datagram: extract destination address, evaluate policy (same engine as TCP)
- [ ] Default verdict for UDP: deny (unless explicitly allowed). This is the safe default since most legitimate API traffic uses TCP.
- [ ] For allowed datagrams: relay to destination, relay response back to agent
- [ ] For denied datagrams: drop silently, log to audit
- [ ] For ask datagrams: deny immediately (Telegram approval for individual UDP packets is not practical)
- [ ] Add `protocols = ["udp"]` matching in policy evaluation so rules can target UDP specifically
- [ ] Write tests for UDP policy evaluation (allow, deny, ask-treated-as-deny)
- [ ] Write tests for UDP relay (send datagram, receive response)
- [ ] Write tests for default-deny behavior
- [ ] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 3: DNS query interception

Intercept UDP port 53 traffic. Parse DNS queries to extract the queried domain. Apply policy at the domain level (not just destination IP). This prevents DNS exfiltration where the agent encodes data in DNS queries to a controlled domain.

**Files:**
- Create: `internal/proxy/dns.go`
- Create: `internal/proxy/dns_test.go`

- [ ] Implement `DNSInterceptor` that parses DNS query packets (Question section only, no need for full DNS library)
- [ ] Extract queried domain name from the DNS Question section
- [ ] Evaluate policy against the queried domain (same glob matching as network rules)
- [ ] If domain is allowed: forward DNS query to upstream resolver, relay response
- [ ] If domain is denied: return NXDOMAIN response (domain not found)
- [ ] Log all DNS queries to audit log (destination=queried domain, port=53, protocol=dns)
- [ ] Configure upstream DNS resolver via `--dns-resolver` flag (default: use system resolver)
- [ ] Write tests for DNS query parsing (A, AAAA, CNAME record queries)
- [ ] Write tests for policy evaluation on DNS domains
- [ ] Write tests for NXDOMAIN response generation
- [ ] Write tests for audit logging of DNS queries
- [ ] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 4: Wire UDP ASSOCIATE into SOCKS5 server

Connect the UDP relay and DNS interceptor to the SOCKS5 server's UDP ASSOCIATE handling.

**Files:**
- Modify: `internal/proxy/server.go`
- Modify: `internal/proxy/server_test.go`

- [ ] Configure `things-go/go-socks5` to handle UDP ASSOCIATE requests
- [ ] On UDP ASSOCIATE: create a UDP relay bound to a local port, return the port to the client
- [ ] Wire the relay to use `UDPRelay` for general UDP and `DNSInterceptor` for port 53
- [ ] Add UDP connection tracking: map client addresses to relay sessions, clean up on TCP control connection close
- [ ] Update audit logging: log UDP relay events with protocol="udp" or protocol="dns"
- [ ] Write integration test: SOCKS5 client sends UDP ASSOCIATE, sends a UDP packet, receives response
- [ ] Write integration test: DNS query through SOCKS5 UDP ASSOCIATE to a mock DNS server
- [ ] Write integration test: blocked UDP destination returns no response (dropped)
- [ ] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 5: Update Docker compose for UDP routing

Configure tun2proxy to route UDP traffic through SOCKS5 UDP ASSOCIATE.

**Files:**
- Modify: `compose.yml`
- Modify: `compose.dev.yml`

- [ ] Update tun2proxy command to enable UDP routing (tun2proxy supports `--dns direct` and UDP relay natively when the SOCKS5 proxy supports UDP ASSOCIATE)
- [ ] Verify tun2proxy routes both TCP and UDP through sluice
- [ ] Add a rule in the default config.toml seed that denies all UDP by default: `[[deny]] destination = "*" protocols = ["udp"]`
- [ ] Add a rule allowing DNS to specified resolvers: `[[allow]] destination = "dns.google" ports = [53] protocols = ["udp", "dns"]`
- [ ] Update compose health checks if needed
- [ ] Write compose-level documentation comments explaining UDP routing
- [ ] Run tests: `go test ./... -v -timeout 30s`

### Task 6: Verify acceptance criteria

- [ ] Verify UDP packets from agent are intercepted by sluice (not bypassing)
- [ ] Verify default-deny for UDP: agent cannot send arbitrary UDP without an explicit allow rule
- [ ] Verify DNS queries are logged in audit log with domain name
- [ ] Verify denied DNS domains return NXDOMAIN
- [ ] Verify allowed UDP destinations relay correctly (e.g., NTP, allowed DNS)
- [ ] Verify TCP functionality is not regressed after SOCKS5 library swap
- [ ] Verify tun2proxy routes both TCP and UDP through sluice
- [ ] Verify `protocols = ["udp"]` in rules matches UDP traffic specifically
- [ ] Run full test suite: `go test ./... -v -timeout 60s -race`
- [ ] Run linter: `go vet ./...`

### Task 7: [Final] Update documentation

- [ ] Update CLAUDE.md: document UDP interception, DNS policy, default-deny UDP
- [ ] Update CLAUDE.md: document SOCKS5 library change (things-go/go-socks5)
- [ ] Update CLAUDE.md: document `dns` protocol value
- [ ] Update examples/config.toml: add UDP deny-all and DNS allow rules
- [ ] Update CONTRIBUTING.md if proxy testing approach changed

## Technical Details

### SOCKS5 UDP ASSOCIATE flow

```
1. Agent wants to send UDP to dns.google:53
2. tun2proxy intercepts the UDP packet
3. tun2proxy sends SOCKS5 UDP ASSOCIATE to sluice
4. Sluice allocates a UDP relay port, returns it to tun2proxy
5. tun2proxy encapsulates the UDP datagram in SOCKS5 UDP header and sends to relay port
6. Sluice unwraps, extracts destination, evaluates policy
7. If allowed: forward to destination, relay response back
8. If denied: drop, log to audit
```

### DNS interception flow

```
UDP datagram to port 53:
  1. Parse as DNS query (extract Question section)
  2. Get queried domain name
  3. Evaluate policy against domain (glob matching)
  4. If allowed: forward to upstream resolver, relay response
  5. If denied: generate NXDOMAIN response, return to agent
  6. Log to audit: {destination: "evil.example.com", port: 53, protocol: "dns", verdict: "deny"}
```

### DNS query parsing (minimal, no full library)

```go
// DNS header: 12 bytes
// Question section starts at offset 12
// Domain name: sequence of length-prefixed labels (e.g., 03 "www" 06 "google" 03 "com" 00)
// QTYPE: 2 bytes (A=1, AAAA=28, CNAME=5)
// QCLASS: 2 bytes (IN=1)
```

Only need to parse the Question section. No need for answer/authority/additional sections.

### Default UDP policy

```toml
# In config.toml seed:
[[deny]]
destination = "*"
protocols = ["udp"]
name = "block all UDP by default"

[[allow]]
destination = "dns.google"
ports = [53]
protocols = ["udp"]
name = "allow Google DNS"

# Or use a local resolver:
[[allow]]
destination = "1.1.1.1"
ports = [53]
protocols = ["udp"]
name = "allow Cloudflare DNS"
```

## Post-Completion

**Manual verification:**
- Deploy three-container stack, verify DNS queries from agent are logged
- Verify agent cannot use QUIC (HTTP/3 negotiation fails, falls back to TCP)
- Verify DNS exfiltration is blocked (query to a disallowed domain returns NXDOMAIN)
- Verify NTP and other allowed UDP services work

**Future plans:**
- Plan 13: QUIC MITM (content inspection for HTTP/3 over UDP)
