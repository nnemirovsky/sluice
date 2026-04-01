# Sluice - CLAUDE.md

## Build and Test

```bash
go build -o sluice ./cmd/sluice/
go test ./... -v -timeout 30s
```

## Project Structure

- `cmd/sluice/main.go` - CLI entrypoint with flag parsing and signal handling
- `internal/proxy/server.go` - SOCKS5 server wrapping `armon/go-socks5` with policy enforcement
- `internal/proxy/protocol.go` - Port-based protocol detection (HTTP, HTTPS, SSH, IMAP, SMTP, generic)
- `internal/policy/engine.go` - Policy loading from TOML, compilation of glob patterns, and evaluation
- `internal/policy/glob.go` - Glob pattern to regex compilation (`*` = single label, `**` = across dots)
- `internal/policy/types.go` - Verdict enum (Allow/Deny/Ask), Rule struct, PolicyConfig
- `internal/audit/logger.go` - Thread-safe append-only JSON lines audit logger
- `testdata/` - TOML policy fixtures for tests

## Architecture

Policy engine: `LoadFromFile`/`LoadFromBytes` parses TOML and auto-compiles glob patterns into regexes. `Evaluate(dest, port)` checks deny rules first, then allow, then ask, falling back to default verdict.

Proxy integration: `policyRuleSet` implements the `socks5.RuleSet` interface. Protocol detection stores results in context for future credential injection.

Audit logger is optional. Pass nil in `Config.Audit` and the proxy handles it gracefully.

## Libraries

- `github.com/armon/go-socks5` - SOCKS5 server
- `github.com/BurntSushi/toml` - Policy file parsing
- `golang.org/x/net/proxy` - SOCKS5 client (tests only)
