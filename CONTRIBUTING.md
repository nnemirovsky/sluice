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

## Architecture

- `internal/proxy/` -- SOCKS5 server, HTTPS MITM, SSH jump host, IMAP/SMTP proxy
- `internal/policy/` -- TOML policy engine with glob pattern matching
- `internal/vault/` -- Credential storage (age, env vars, HashiCorp Vault)
- `internal/mcp/` -- MCP gateway with tool policy enforcement
- `internal/telegram/` -- Telegram approval bot and commands
- `internal/audit/` -- Append-only JSON lines logger with blake3 hash chaining
- `internal/docker/` -- Container lifecycle management
- `cmd/sluice/` -- CLI entrypoint and subcommands

See `CLAUDE.md` for detailed architecture documentation.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
