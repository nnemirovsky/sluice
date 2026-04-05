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

### Unit tests

- `make test` -- runs all unit tests with `-v -count=1`
- `make test-coverage` -- generates HTML coverage report in `coverage.html`
- CI enforces a minimum 75% overall coverage threshold

### End-to-end tests

E2e tests live in `e2e/` and require the `e2e` build tag. They start a real sluice binary and test the full proxy, credential injection, MCP gateway, and audit log flows.

```bash
make test-e2e          # run all e2e tests locally
make test-e2e-docker   # run Linux e2e tests via Docker Compose
make test-e2e-macos    # run macOS e2e tests (Apple Container)
```

Build tags:
- `e2e` -- required for all e2e tests
- `e2e && linux` -- Docker compose integration tests (requires Docker)
- `e2e && darwin` -- Apple Container tests (requires macOS with `container` CLI)

When writing new e2e tests, use the helpers in `e2e/helpers_test.go` (startSluice, connectSOCKS5, startEchoServer, etc.) to avoid boilerplate.

### macOS-specific tests

- Apple Container and macOS VM (tart) integration tests (`internal/container/`) use mock `CommandRunner` by default and run on all platforms
- Full integration tests requiring a real Apple Container runtime are in `e2e/apple_test.go` (see `docs/apple-container-quickstart.md`)
- macOS VM tests require `tart` CLI (`brew install cirruslabs/cli/tart`) and Apple Silicon. Unit tests use mocked `CommandRunner` and run everywhere. E2e tests with a real macOS VM require `tart` installed and a compatible OCI image.

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
- `internal/vault/` -- Credential storage and pluggable provider backends (age, env, HashiCorp Vault, 1Password, Bitwarden, KeePass, Gopass)
- `internal/mcp/` -- MCP gateway with tool policy enforcement
- `internal/api/` -- REST API handlers (spec-first, generated from `api/openapi.yaml` via oapi-codegen)
- `internal/channel/` -- Channel interface, ChannelType enum, and approval Broker (channel-agnostic)
- `internal/channel/http/` -- HTTP webhook channel (HMAC-signed delivery, sync/async approval)
- `internal/telegram/` -- TelegramChannel implementation of channel.Channel interface
- `internal/audit/` -- Append-only JSON lines logger with blake3 hash chaining
- `internal/container/` -- ContainerManager interface, Apple Container backend, macOS VM (tart) backend (CLI wrappers, pf routing, CA cert injection)
- `internal/docker/` -- Docker container backend implementing ContainerManager with hot credential reload
- `cmd/sluice/` -- CLI entrypoint and subcommands (policy, mcp, cred, cert, audit, channel) with `--runtime` flag for backend selection

See `CLAUDE.md` for detailed architecture documentation.

## Adding a Vault Provider

To add a new credential provider backend:

1. Create `internal/vault/provider_<name>.go` implementing the `Provider` interface (`Get`, `List`, `Name`).
2. Add a config struct (e.g. `FooConfig`) to `VaultConfig` in `internal/vault/provider.go`.
3. Add a `case "<name>"` to `newSingleProvider` in `internal/vault/provider.go`.
4. Add migration columns for provider-specific config to `internal/store/migrations/`.
5. Update `GetConfig`/`UpdateConfig` in `internal/store/store.go` to read/write the new columns.
6. Update TOML import in `internal/store/import.go` to parse the new `[vault.<name>]` section.
7. Write tests in `internal/vault/provider_<name>_test.go` using mocks (no live service calls).
8. Add commented examples to `examples/config.toml`.

All providers must return `SecureBytes` from `Get()` and should prefer pure Go (no CGO) for Docker compatibility.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
