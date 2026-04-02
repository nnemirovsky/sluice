# Sluice - CLAUDE.md

## Build and Test

```bash
go build -o sluice ./cmd/sluice/
go test ./... -v -timeout 30s
```

## Project Structure

- `cmd/sluice/main.go` - CLI entrypoint with flag parsing and signal handling
- `cmd/sluice/cred.go` - CLI subcommand handler for credential management (add/list/remove)
- `internal/proxy/server.go` - SOCKS5 server wrapping `armon/go-socks5` with policy enforcement
- `internal/proxy/protocol.go` - Port-based protocol detection (HTTP, HTTPS, SSH, IMAP, SMTP, generic)
- `internal/proxy/ca.go` - Self-signed CA generation and persistence for HTTPS MITM
- `internal/proxy/inject.go` - HTTPS MITM credential injector using goproxy with phantom token replacement
- `internal/proxy/ssh.go` - SSH jump host with vault key injection and bidirectional channel relay
- `internal/proxy/mail.go` - IMAP/SMTP AUTH command proxy with phantom token replacement (including base64)
- `internal/policy/engine.go` - Policy loading from TOML, compilation of glob patterns, and evaluation
- `internal/policy/glob.go` - Glob pattern to regex compilation (`*` = single label, `**` = across dots)
- `internal/policy/types.go` - Verdict enum (Allow/Deny/Ask), Rule struct, PolicyConfig, ToolRule, InspectBlockRule, InspectRedactRule
- `internal/vault/store.go` - Age-encrypted credential storage with X25519 identity key management
- `internal/vault/secure.go` - SecureBytes type with best-effort zeroizing memory release
- `internal/vault/binding.go` - Binding resolution mapping destinations to credentials via glob matching
- `internal/vault/provider.go` - Pluggable credential provider interface, VaultConfig, ChainProvider
- `internal/vault/provider_age.go` - Age file backend (Store satisfies Provider)
- `internal/vault/provider_env.go` - Environment variable credential provider
- `internal/vault/provider_hashicorp.go` - HashiCorp Vault provider stub (not yet implemented)
- `cmd/sluice/mcp.go` - CLI subcommand handler for MCP gateway mode
- `internal/mcp/gateway.go` - MCP gateway core with tool policy enforcement and upstream forwarding
- `internal/mcp/inspect.go` - Content inspection: argument blocking and response redaction using regex rules
- `internal/mcp/policy.go` - Tool-level policy evaluation using glob patterns (deny/allow/ask priority)
- `internal/mcp/transport.go` - Stdio transport for MCP gateway (JSON-RPC over stdin/stdout)
- `internal/mcp/types.go` - JSON-RPC 2.0 and MCP protocol type definitions
- `internal/mcp/upstream.go` - Upstream MCP server process management (spawn, handshake, tool discovery)
- `internal/audit/logger.go` - Thread-safe append-only JSON lines audit logger with blake3 hash chaining
- `internal/audit/verify.go` - Hash chain verification (walks log file, reports broken links)
- `internal/telegram/approval.go` - Approval broker with channel-based request/response flow
- `internal/telegram/bot.go` - Telegram bot lifecycle, inline keyboard approval messages
- `internal/telegram/commands.go` - Telegram admin commands (/policy, /cred, /status, /audit, /help)
- `internal/docker/manager.go` - Docker container manager for credential rotation (restart with updated phantom env)
- `cmd/sluice/audit.go` - CLI subcommand handler for audit log verification (`audit verify`)
- `cmd/sluice/cert.go` - CLI subcommand handler for CA certificate generation (`cert generate`)
- `Dockerfile` - Multi-stage build for Sluice container
- `docker-compose.yml` - Three-container setup (sluice + tun2proxy + openclaw)
- `scripts/docker-entrypoint.sh` - Container entrypoint with CA cert generation and copy to shared volume
- `scripts/setup-vault.sh` - Interactive credential and CA setup script
- `scripts/gen-phantom-env.sh` - Phantom token env file generator for openclaw container
- `examples/policy.toml` - Example policy for OpenClaw deployment with bindings and MCP tool rules
- `testdata/` - TOML policy fixtures for tests

## Architecture

Policy engine: `LoadFromFile`/`LoadFromBytes` parses TOML and auto-compiles glob patterns into regexes. `Evaluate(dest, port)` checks deny rules first, then allow, then ask, falling back to default verdict.

Proxy integration: `policyRuleSet` implements the `socks5.RuleSet` interface. Protocol detection stores results in context for future credential injection.

Telegram approval: `ApprovalBroker` bridges the proxy and Telegram bot via channels. When `policyRuleSet.Allow()` encounters an Ask verdict, it calls `broker.Request()` which blocks until the bot resolves the request or the timeout expires. The bot goroutine reads from `broker.Pending()`, sends an inline keyboard to Telegram, and calls `broker.Resolve()` when the user responds. "Always Allow" calls `Engine.AddDynamicAllow()` to add a runtime allow rule (not persisted to disk). The Engine uses a `sync.RWMutex` to protect concurrent reads (policy evaluation) and writes (dynamic rule addition, command handler mutations). `CouldBeAllowed(dest, includeAsk)` takes an `includeAsk` parameter: when true (broker configured), Ask-matching destinations are resolved via DNS so the approval flow can proceed; when false (no broker), Ask rules are treated as Deny at the DNS stage to prevent leaking queries.

Telegram commands: `CommandHandler` holds an `atomic.Pointer[policy.Engine]` for lock-free reads and is updated via `UpdateEngine()` on SIGHUP. Policy mutations (`/policy allow`, `/policy deny`, `/policy remove`) use `Engine.AddAllowRule()`, `AddDenyRule()`, and `RemoveRule()` which acquire write locks internally. Mutations are in-memory only and not persisted to disk.

Audit logger is optional. Pass nil in `Config.Audit` and the proxy handles it gracefully. Each JSON line includes a `prev_hash` field containing the blake3 hash of the previous line's raw JSON bytes. The first entry uses blake3("") as the genesis hash. On startup, `NewFileLogger` reads the last line from the existing file (seeking backwards from EOF) to recover the hash chain across restarts. `VerifyChain` walks the log and reports any broken links. The `sluice audit verify` CLI command wraps this for tamper detection.

Credential vault: `Store` manages age-encrypted files in `~/.sluice/credentials/` with an auto-generated X25519 identity. `SecureBytes` wraps decrypted values and zeroes memory on `Release()` (best-effort in Go due to GC and string copies). `Provider` interface abstracts credential sources (age files, env vars, HashiCorp Vault stub). `NewProviderFromConfig` reads `[vault]` from TOML config.

Binding resolution: `BindingResolver` compiles destination glob patterns (reusing `policy.CompileGlob`) and resolves `(host, port)` to a `Binding`. Bindings specify the credential name, injection header, template (`Bearer {value}`), and protocol override.

HTTPS credential injection: `Injector` wraps `goproxy` as an in-process MITM proxy. `LoadOrCreateCA` generates a self-signed ECDSA P-256 CA persisted to disk. Per-host certificates are generated at interception time. Only hosts with credential bindings are MITMed. Phantom tokens (`SLUICE_PHANTOM:<name>`) in headers and request bodies are replaced with real credential values. `SecureBytes.Release()` zeroes credentials immediately after injection.

SSH credential injection: `SSHJumpHost` accepts the agent's SSH connection with no authentication (`NoClientAuth`), decrypts the SSH private key from the vault, authenticates to the upstream server, and relays SSH channels/requests bidirectionally. `Binding.Template` holds the SSH username (defaults to "root").

Mail credential injection: `MailProxy` intercepts IMAP LOGIN and SMTP AUTH PLAIN/LOGIN commands. For base64-encoded auth data, it decodes, replaces phantom tokens, and re-encodes. Non-auth traffic is relayed unchanged.

Docker integration: Three-container architecture (sluice + tun2proxy + openclaw) with `network_mode: "service:tun2proxy"` routing all openclaw traffic through sluice's SOCKS5 proxy. `docker.Manager` wraps a `ContainerClient` interface (production implementation pending, SDK added at deployment time). On credential mutation via Telegram `/cred` commands, `credMutationComplete` regenerates phantom environment variables using `GeneratePhantomEnv` (produces SDK-format-matching phantom tokens based on credential name heuristics) and calls `Manager.RestartWithEnv` to recreate the agent container with updated env. `BotConfig.Vault` and `BotConfig.DockerMgr` wire the vault and Docker manager into Telegram command handling. The sluice entrypoint generates a CA cert and copies it to a shared volume so openclaw can trust HTTPS MITM certificates via `SSL_CERT_FILE`.

MCP gateway: `Gateway` spawns upstream MCP servers as child processes via `StartUpstream`, performs `initialize` handshake and `notifications/initialized`, discovers tools via `tools/list`, and namespaces them with `<upstream>__<tool>`. The agent connects via stdio (`RunStdio`). On `tools/call`, the gateway evaluates `ToolPolicy` (deny/allow/ask priority, same as network policy), optionally requests Telegram approval via the shared `ApprovalBroker`, runs `ContentInspector.InspectArguments` to block arguments matching regex patterns (JSON is parsed before matching to prevent unicode escape bypass), strips the namespace prefix, forwards to the upstream, runs `ContentInspector.RedactResponse` on the result, and adds governance metadata. `ToolPolicy` reuses `policy.CompileGlob` for glob matching. The `mcp` subcommand reads `[[mcp_upstream]]`, `[[tool_allow]]`, `[[tool_deny]]`, `[[tool_ask]]`, `[[inspect_block]]`, and `[[inspect_redact]]` sections from the same TOML policy file.

## Libraries

- `github.com/armon/go-socks5` - SOCKS5 server
- `github.com/BurntSushi/toml` - Policy file parsing
- `golang.org/x/net/proxy` - SOCKS5 client (tests only)
- `github.com/go-telegram-bot-api/telegram-bot-api/v5` - Telegram Bot API client
- `filippo.io/age` - Age encryption for credential vault
- `github.com/elazarl/goproxy` - In-process HTTPS MITM proxy for credential injection
- `golang.org/x/crypto/ssh` - SSH client/server for jump host credential injection
- `golang.org/x/term` - Terminal password input for `sluice cred add`
