# Contributing to Sluice

Thanks for your interest in contributing!

## Development Setup

```bash
# Clone and build
git clone https://github.com/nnemirovsky/sluice.git
cd sluice
make build

# Run tests
make test
```

## Before Submitting a PR

```bash
make fmt    # gofumpt formatting
make lint   # golangci-lint
make test   # all unit tests
```

## Testing

- **Unit tests** (`make test`) -- runs all tests with `-v -count=1`
- **Coverage** (`make test-coverage`) -- generates HTML coverage report

## Commit Messages

Use scoped [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(audit): blake3 hash chain for tamper-evident audit log
fix(proxy): make SIGHUP policy reload race-free
refactor(vault): consolidate credential name validation
test(mcp): add comprehensive gateway unit tests
```

## Branch Names

Prefix branches with the change type:

```
feat/hashicorp-vault-provider
fix/sighup-reload-race
refactor/approval-broker
```

## API Development

The REST API uses spec-first code generation. The OpenAPI spec is the source of truth.

```bash
# 1. Edit the OpenAPI spec
#    api/openapi.yaml

# 2. Regenerate Go types, server interface, and chi router
make generate

# 3. Implement or update handler methods in internal/api/server.go
#    The generated ServerInterface defines the method signatures

# 4. Test
go test ./internal/api/ -v

# 5. Lint the spec (optional, requires Node.js)
make lint-api
```

Do not edit `internal/api/api.gen.go` manually. It is regenerated from the spec.

## Architecture

- `internal/store/` -- SQLite-backed policy store for all runtime state
- `internal/proxy/` -- SOCKS5 server, HTTPS MITM, SSH jump host, IMAP/SMTP proxy
- `internal/policy/` -- Policy engine with glob pattern matching (compiled from SQLite store)
- `internal/vault/` -- Credential storage (age, env vars, HashiCorp Vault)
- `internal/mcp/` -- MCP gateway with tool policy enforcement
- `internal/api/` -- REST API handlers (spec-first, generated from `api/openapi.yaml` via oapi-codegen)
- `internal/channel/` -- Channel interface, ChannelType enum, and approval Broker (channel-agnostic)
- `internal/channel/http/` -- HTTP webhook channel (HMAC-signed delivery, sync/async approval)
- `internal/telegram/` -- TelegramChannel implementation of channel.Channel interface
- `internal/audit/` -- Append-only JSON lines logger with blake3 hash chaining
- `internal/docker/` -- Container lifecycle management with hot credential reload
- `cmd/sluice/` -- CLI entrypoint and subcommands (policy, mcp, cred, cert, audit, channel)

See `CLAUDE.md` for detailed architecture documentation.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
