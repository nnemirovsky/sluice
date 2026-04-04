# Plan 19: Add TCP/UDP to Protocol Enum

## Overview

Add `ProtoTCP` and `ProtoUDP` to the Protocol integer enum and replace hardcoded `"udp"` strings in the policy engine and store with proper enum constants. Currently `"udp"` is accepted as a valid protocol name in config and policy rules, and the policy engine uses it for UDP/QUIC evaluation, but there's no corresponding constant in the Protocol enum. This is inconsistent.

**Problem:** The Protocol enum in `internal/proxy/protocol.go` defines 12 protocol values (ProtoGeneric through ProtoAPNS) but `"udp"` and `"tcp"` are not among them. The policy engine hardcodes `"udp"` as a string in `EvaluateUDP` and `EvaluateQUIC`. The store import has `"udp": true` in its valid names map. Someone reading `protocol.go` would conclude `"udp"` is an invalid protocol value.

**Solution:** Add `ProtoTCP Protocol = 12` and `ProtoUDP Protocol = 13` to the enum. Replace all hardcoded `"udp"` strings with `ProtoUDP.String()` or direct enum comparisons. Update the protocol name maps, store validation, and tests.

## Context

**IMPORTANT: Do NOT create new migration files.** All schema is in a single `000001_init.up.sql`. If the schema needs changes (it shouldn't for this plan since protocols are stored as strings in JSON arrays, not as DB columns), edit `000001_init.up.sql` directly.

**Files with hardcoded "udp" strings:**
- `internal/policy/engine.go` lines 624, 627, 654, 657: `matchRulesStrictProto(rules, dest, port, "udp")`
- `internal/store/import.go` line 149: `"udp": true` in validProtocolNames

**Files that need ProtoTCP/ProtoUDP added:**
- `internal/proxy/protocol.go`: Protocol enum, String(), ParseProtocol(), protocolNames map

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Small focused refactor, single task

## Implementation Steps

### Task 1: Add ProtoTCP and ProtoUDP to enum

**Files:**
- Modify: `internal/proxy/protocol.go`
- Modify: `internal/proxy/protocol_test.go`

- [x] Add `ProtoTCP Protocol = 12` and `ProtoUDP Protocol = 13` to the Protocol enum
- [x] Add `"tcp"` and `"udp"` cases to `String()` method
- [x] Add `"tcp"` and `"udp"` entries to `protocolNames` map for `ParseProtocol()`
- [x] Write tests for `ParseProtocol("tcp")` and `ParseProtocol("udp")` round-trips
- [x] Write tests for `ProtoTCP.String() == "tcp"` and `ProtoUDP.String() == "udp"`
- [x] Run tests: `go test ./internal/proxy/ -v -timeout 30s`

### Task 2: Replace hardcoded strings in policy engine

**Files:**
- Modify: `internal/policy/engine.go`

- [x] Replace `"udp"` in `matchRulesStrictProto` calls with `proxy.ProtoUDP.String()` or use integer comparison if the compiled rules store Protocol values as integers
- [x] If the compiled rules store protocols as strings, convert to integers. If too invasive, use `proxy.ProtoUDP.String()` for now.
- [x] Verify `EvaluateUDP` and `EvaluateQUIC` still work correctly
- [x] Run tests: `go test ./internal/policy/ -v -timeout 30s`

### Task 3: Update store validation

**Files:**
- Modify: `internal/store/import.go`
- Modify: `internal/store/store.go` (if protocol validation exists)

- [x] Replace hardcoded `"udp": true` in `validProtocolNames` with reference to `proxy.protocolNames` or add `"tcp"` alongside `"udp"`
- [x] Ensure `"tcp"` is also valid in the store (not just `"udp"`)
- [x] Write test: import a TOML config with `protocols = ["tcp"]` rule, verify it's accepted
- [x] Run tests: `go test ./internal/store/ -v -timeout 30s`

### Task 4: Verify acceptance criteria

- [ ] Verify `protocols = ["udp"]` still works in policy rules
- [ ] Verify `protocols = ["tcp"]` works in policy rules
- [ ] Verify no hardcoded `"udp"` or `"tcp"` strings remain in policy engine or store (grep check)
- [ ] Verify `ParseProtocol("tcp")` and `ParseProtocol("udp")` return correct enum values
- [ ] Run full test suite: `go test ./... -v -timeout 60s -race`
- [ ] Run linter: `go vet ./...`

### Task 5: [Final] Update documentation

- [ ] Update CLAUDE.md protocol table: add TCP and UDP transport-level protocol values
- [ ] Update examples/config.toml: ensure UDP deny-all example uses the documented protocol name

## Technical Details

### Updated Protocol enum

```go
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
    ProtoTCP     Protocol = 12
    ProtoUDP     Protocol = 13
)
```

### Meta-protocol matching

When a rule has `protocols = ["udp"]`, the evaluation logic should match any UDP-based protocol (DNS, QUIC, generic UDP). When `protocols = ["tcp"]`, it should match any TCP-based protocol. The `EvaluateUDP` and `EvaluateQUIC` methods already implement this fallback logic. The refactor just replaces string literals with enum constants.
