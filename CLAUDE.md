# Sluice - CLAUDE.md

Credential-injecting approval proxy for AI agents. Two layers of governance: MCP-level (semantic tool control) and network-level (all-protocol interception). Asks for human approval via Telegram, injects credentials, and forwards.

## Problem

No existing tool combines:
1. Credential/secret isolation from the AI agent
2. Per-request human approval/deny via Telegram
3. All-protocol interception (HTTP, HTTPS, SSH, IMAP, SMTP, etc.)
4. MCP-level governance (tool names, arguments, per-action policy)
5. Audit logging of every connection and tool call

## Build and Test

```bash
go build -o sluice ./cmd/sluice/
go test ./... -v -timeout 30s
```

## Project Structure

- `cmd/sluice/main.go` - CLI entrypoint with flag parsing and signal handling
- `cmd/sluice/cred.go` - CLI subcommand handler for credential management (add/list/remove with optional policy+binding auto-creation)
- `cmd/sluice/audit.go` - CLI subcommand handler for audit log verification (`audit verify`)
- `cmd/sluice/cert.go` - CLI subcommand handler for CA certificate generation (`cert generate`)
- `cmd/sluice/mcp.go` - CLI subcommand handler for MCP gateway mode and upstream management (add/list/remove)
- `cmd/sluice/policy.go` - CLI subcommand handler for policy management (list/add/remove/import/export)
- `internal/store/store.go` - SQLite-backed policy store for all runtime state (unified rules, typed config singleton, bindings, channels, MCP upstreams)
- `internal/store/import.go` - TOML import into SQLite store with merge semantics (skip duplicates)
- `internal/store/migrate.go` - golang-migrate integration with embedded SQL files
- `internal/store/migrations/000001_init.up.sql` - Initial schema migration (rules, config, bindings, mcp_upstreams, channels)
- `internal/store/migrations/000001_init.down.sql` - Rollback for initial schema
- `internal/proxy/server.go` - SOCKS5 server wrapping `armon/go-socks5` with policy enforcement
- `internal/proxy/protocol.go` - Port-based protocol detection (HTTP, HTTPS, SSH, IMAP, SMTP, generic)
- `internal/proxy/ca.go` - Self-signed CA generation and persistence for HTTPS MITM
- `internal/proxy/inject.go` - HTTPS MITM credential injector using goproxy with global phantom token replacement in all MITMed traffic
- `internal/proxy/ssh.go` - SSH jump host with vault key injection and bidirectional channel relay
- `internal/proxy/mail.go` - IMAP/SMTP AUTH command proxy with phantom token replacement (including base64)
- `internal/policy/engine.go` - Policy compilation of glob patterns and evaluation (LoadFromBytes for backward compat)
- `internal/policy/engine_store.go` - LoadFromStore builds a read-only Engine from SQLite store
- `internal/policy/glob.go` - Glob pattern to regex compilation (`*` = single label, `**` = across dots)
- `internal/policy/types.go` - Verdict enum (Allow/Deny/Ask/Redact), Rule struct with Protocols []string, PolicyConfig
- `internal/vault/store.go` - Age-encrypted credential storage with X25519 identity key management
- `internal/vault/secure.go` - SecureBytes type with best-effort zeroizing memory release
- `internal/vault/binding.go` - Binding resolution mapping destinations to credentials via glob matching
- `internal/vault/provider.go` - Pluggable credential provider interface, VaultConfig, ChainProvider
- `internal/vault/provider_age.go` - Age file backend (Store satisfies Provider)
- `internal/vault/provider_env.go` - Environment variable credential provider
- `internal/vault/provider_hashicorp.go` - HashiCorp Vault provider with KV v2 support and AppRole auth
- `internal/mcp/gateway.go` - MCP gateway core with tool policy enforcement and upstream forwarding
- `internal/mcp/inspect.go` - Content inspection: argument blocking and response redaction using regex rules
- `internal/mcp/policy.go` - Tool-level policy evaluation using glob patterns (deny/allow/ask priority)
- `internal/mcp/transport.go` - Stdio transport for MCP gateway (JSON-RPC over stdin/stdout)
- `internal/mcp/types.go` - JSON-RPC 2.0 and MCP protocol type definitions
- `internal/mcp/upstream.go` - Upstream MCP server process management (spawn, handshake, tool discovery)
- `internal/audit/logger.go` - Thread-safe append-only JSON lines audit logger with blake3 hash chaining
- `internal/audit/verify.go` - Hash chain verification (walks log file, reports broken links)
- `internal/channel/channel.go` - Channel interface, ChannelType enum (Telegram=0, HTTP=1), ApprovalRequest/Response/Command types
- `internal/channel/broker.go` - Channel-agnostic approval broker with broadcast-and-first-wins, rate limiting, cross-channel cancellation
- `internal/telegram/approval.go` - TelegramChannel implementing channel.Channel interface
- `internal/telegram/bot.go` - Telegram bot lifecycle, inline keyboard approval messages
- `internal/telegram/commands.go` - Telegram admin commands (/policy, /cred, /status, /audit, /help) backed by SQLite store
- `internal/docker/manager.go` - Docker container manager for credential hot-reload via shared volume + docker exec, with restart fallback
- `internal/docker/socket_client.go` - Docker socket HTTP client for container lifecycle and exec operations
- `Dockerfile` - Multi-stage build for Sluice container
- `compose.yml` - Three-container setup (sluice + tun2proxy + openclaw) with shared phantom volume
- `compose.dev.yml` - Development compose with build-from-source
- `scripts/docker-entrypoint.sh` - Container entrypoint with CA cert generation and copy to shared volume
- `scripts/setup-vault.sh` - Interactive credential and CA setup script
- `scripts/gen-phantom-env.sh` - Phantom token env file generator for openclaw container
- `examples/config.toml` - Example TOML seed file for initial DB population via `sluice policy import`
- `testdata/` - TOML policy fixtures for import tests

## System Architecture

Sluice has two governance layers that work together:

### Layer 1: MCP Gateway (semantic tool governance)

Sits between the AI agent and MCP tool servers. Sees tool names, arguments, and
responses. Can approve/deny based on what the agent is trying to do, not just
where it's connecting. Catches local tools (filesystem, exec) that never hit
the network.

### Layer 2: SOCKS5 Proxy (network-level governance)

Sits between the container and the internet. Sees every TCP connection. Can
approve/deny any protocol (HTTP, SSH, IMAP, SMTP). Injects credentials at the
network level. Catches anything that bypasses MCP (direct HTTP calls, raw
sockets, etc.).

```
+---------------------------------------------------------------+
|  Docker Compose                                                |
|                                                                |
|  +----------------------------------------------------------+ |
|  |  Shared Network Namespace                                 | |
|  |  (network_mode: "service:sluice")                         | |
|  |                                                           | |
|  |  +-------------+    +---------------------+               | |
|  |  |  OpenClaw    |    |  tun2proxy          |               | |
|  |  |  (agent)     |    |  (TUN -> SOCKS5)    |               | |
|  |  |              |    |  Routes ALL TCP     |               | |
|  |  |  No real     |    |  to Sluice proxy    |               | |
|  |  |  credentials |    +---------+-----------+               | |
|  |  |              |              |                           | |
|  |  |       +------+    SOCKS5 conn                          | |
|  |  |       |MCP   |              |                           | |
|  |  |       |calls |              |                           | |
|  |  +-------+--+---+              |                           | |
|  +-------------|------------------|---------------------------+ |
|                |                  |                             |
|                v                  v                             |
|  +-------------+-----+ +--------+---------------------------+ |
|  | Sluice MCP Gateway | | Sluice SOCKS5 Proxy               | |
|  |                     | |                                    | |
|  | - Tool-level policy | | - Connection-level policy          | |
|  | - Argument inspect  | | - Allowlist/denylist/ask           | |
|  | - Per-action control| | - Built-in HTTPS MITM              | |
|  | - Response redact   | | - Credential injection (in-process)|
|  | - Local tool govnce | | - Telegram approval (inline btns)  | |
|  | - Telegram approval | | - Audit log (every connection)     | |
|  +---------------------+ +--------+--------------------------+ |
|                                    |                           |
|                  +-----------------+--------+                  |
|                  | (HTTP/HTTPS)    |(others) |                  |
|                  v                 v         |                  |
|           TLS MITM +        Direct TCP       |                  |
|           phantom swap      (after approval) |                  |
|           (goproxy)                          |                  |
|                  |                           |                  |
+-----------+------+---------------------------+------------------+
            v
        Internet
```

### Why two layers?

| Scenario | MCP Gateway | SOCKS5 Proxy |
|----------|-------------|--------------|
| Agent calls `github__delete_repository` | Sees tool name + args, can block | Sees `api.github.com:443`, can't tell read from delete |
| Agent calls `filesystem__write_file` | Sees path + content, can block | No network request. Invisible to proxy. |
| Agent makes raw `fetch("https://evil.com")` | Bypasses MCP entirely | Catches it. Blocks or asks approval. |
| Agent runs `curl` via exec tool | MCP sees exec args | Proxy also sees the outbound connection |
| Agent connects to SSH | Not an MCP tool call | Proxy sees `github.com:22`, can approve/deny |

### Components

| Component | Role | Implementation |
|-----------|------|----------------|
| **OpenClaw** | AI agent, no real credentials | Existing Docker image |
| **tun2proxy** | Routes ALL TCP through TUN to SOCKS5 | Existing `ghcr.io/tun2proxy/tun2proxy` |
| **Sluice SOCKS5 Proxy** | Network-level policy + HTTPS MITM + credential injection | Custom Go, single binary |
| **Sluice MCP Gateway** | Semantic tool governance (stdio + HTTP) | Custom Go, same binary |
| **Sluice Telegram Bot** | Approval UX + credential/config management | Same binary |
| **Vault** | Encrypted credential storage + phantom token mapping | age-encrypted files (default), pluggable providers |
| **Docker Socket** | Restart OpenClaw container with updated phantom env vars | Mounted from host |

## Core Logic

### SOCKS5 Proxy

```
on_socks5_connect(destination, port):
  rule = match_policy(destination, port)

  if rule == ALLOW:
    creds = vault.get(destination)
    conn = connect(destination, port)
    if creds and is_http(port):
      chain_through_mitmproxy(conn, creds)
    else:
      return conn

  if rule == DENY:
    audit.log("denied", destination, port)
    return reject()

  if rule == ASK:
    approval = telegram.ask_user(
      "Agent wants to connect to {destination}:{port}",
      buttons=["Allow Once", "Always Allow", "Deny"]
    )
    match approval:
      "allow_once":
        creds = vault.get(destination)
        return connect_and_inject(destination, port, creds)
      "always_allow":
        policy.add_allow(destination, port)
        creds = vault.get(destination)
        return connect_and_inject(destination, port, creds)
      "deny" | timeout:
        return reject()
```

### MCP Gateway

The MCP gateway intercepts tool calls between the agent and MCP servers.
It provides semantic governance that the SOCKS5 proxy cannot.

```
on_mcp_tool_call(tool_name, arguments, session):
  # 1. Inspect arguments for sensitive content
  findings = inspect(arguments)
  if findings.has_blockers:
    audit.log("blocked_inspection", tool_name, findings)
    return error("Content blocked: " + findings.reason)

  # 2. Check tool-level policy
  rule = match_tool_policy(tool_name, action)

  if rule == ALLOW:
    response = forward_to_upstream(tool_name, arguments)
    response = inspect_and_redact(response)
    audit.log("allowed", tool_name, arguments)
    return response

  if rule == DENY:
    audit.log("denied", tool_name, arguments)
    return error("Tool call denied by policy")

  if rule == ASK:
    # Rich context in Telegram: tool name, arguments, not just host:port
    approval = telegram.ask_user(
      "Agent wants to call: {tool_name}\nArgs: {arguments}",
      buttons=["Allow Once", "Always Allow", "Deny"]
    )
    match approval:
      "allow_once":
        response = forward_to_upstream(tool_name, arguments)
        return inspect_and_redact(response)
      "always_allow":
        tool_policy.add_allow(tool_name)
        response = forward_to_upstream(tool_name, arguments)
        return inspect_and_redact(response)
      "deny" | timeout:
        return error("Denied by user")
```

### MCP Tool Policy (unified TOML seed format, stored in SQLite at runtime)

Tool rules use the same `[[allow]]`/`[[deny]]`/`[[ask]]` sections as network rules, distinguished by the `tool` field instead of `destination`:

```toml
[[allow]]
tool = "github__list_*"
name = "Read-only GitHub operations"

[[allow]]
tool = "filesystem__read_file"
name = "File reads are safe"

[[ask]]
tool = "github__create_*"
name = "Write operations need approval"

[[ask]]
tool = "github__delete_*"

[[ask]]
tool = "filesystem__write_file"
name = "File writes need approval"

[[deny]]
tool = "exec__*"
name = "Block all exec by default"
```

### MCP Gateway Features

- **Argument inspection**: see what file the agent wants to write, what repo it
  wants to delete. SOCKS5 only sees the destination host.
- **Response redaction**: strip secrets/PII from tool responses before the agent
  sees them.
- **Local tool governance**: filesystem, exec, database tools never make network
  requests. Only the MCP gateway can govern them.
- **Upstream server management**: spawns MCP servers as child processes, handles
  initialization handshake, tool discovery, namespacing.
- **Telegram approval with rich context**: "Agent wants to call
  filesystem__write_file(/etc/passwd, ...)" is more useful than "Agent wants to
  connect to localhost:0".

## CLI Subcommands

### Policy management

```
sluice policy list [--verdict allow|deny|ask|redact] [--db sluice.db]
sluice policy add allow <destination> [--ports 443,80] [--name "reason"]
sluice policy add deny <destination> [--name "reason"]
sluice policy add ask <destination> [--ports 443] [--name "reason"]
sluice policy remove <id>
sluice policy import <path.toml>    # seed DB from TOML (merge semantics, skips duplicates)
sluice policy export                # dump current rules as TOML to stdout
```

### MCP upstream management

```
sluice mcp add <name> --command <cmd> [--args "arg1,arg2"] [--env "KEY=VAL,..."] [--timeout 120]
sluice mcp list
sluice mcp remove <name>
sluice mcp                          # start MCP gateway (reads upstreams from store)
```

### Credential management

```
sluice cred add <name> [--destination host] [--ports 443] [--header Authorization] [--template "Bearer {value}"]
sluice cred list                    # shows credentials with associated bindings from store
sluice cred remove <name>           # removes credential + associated binding + allow rule
```

When `--destination` is provided, `sluice cred add` also creates an allow rule and binding in the store.

### Other subcommands

```
sluice cert generate                # generate CA certificate for HTTPS MITM
sluice audit verify                 # verify audit log hash chain integrity
```

## Implementation Details

Policy store: `internal/store/store.go` wraps a SQLite database (via `modernc.org/sqlite`, pure Go, no CGO). Schema is managed by `golang-migrate` with embedded SQL files (`internal/store/migrations/`). All runtime state is persisted in 5 tables: `rules` (unified table for network, tool, and content inspection rules with verdict allow/deny/ask/redact), `config` (typed singleton row), `bindings` (credential-to-destination mapping), `mcp_upstreams`, and `channels` (notification/approval channel configuration). The `rules` table uses a CHECK constraint enforcing mutual exclusivity of destination/tool/pattern columns. TOML files are only used for initial seeding via `store.ImportTOML()`. Import uses merge semantics (skip duplicates based on destination+ports+verdict). The store uses WAL mode for concurrent read performance.

Policy engine: `LoadFromStore(s *store.Store)` reads all rules from SQLite and compiles glob patterns into regexes, producing a read-only Engine snapshot. `LoadFromBytes` is kept for backward compatibility (tests, import path). `Evaluate(dest, port)` checks deny rules first, then allow, then ask, falling back to default verdict. Mutations go through the store, then a new Engine is compiled and atomically swapped via `srv.StoreEngine(newEngine)`. SIGHUP also rebuilds the binding resolver from the store and atomically swaps it via `srv.StoreResolver(newResolver)`, so bindings added via CLI or Telegram take effect without a full restart.

Proxy integration: `policyRuleSet` implements the `socks5.RuleSet` interface. Protocol detection stores results in context for future credential injection. The binding resolver is stored as an `atomic.Pointer[vault.BindingResolver]` so it can be hot-swapped on SIGHUP or after Telegram/CLI credential mutations. `Server.StoreResolver()` and `Server.ResolverPtr()` provide the swap and shared-access interfaces.

Channel abstraction: `internal/channel/channel.go` defines the `Channel` interface and `ChannelType` enum (ChannelTelegram=0, ChannelHTTP=1). `Channel` has methods for non-blocking `RequestApproval`, `CancelApproval`, `Commands()`, `Notify`, and lifecycle (`Start`/`Stop`). `internal/channel/broker.go` defines the `Broker` which coordinates approval flow across multiple enabled channels. Approval requests are broadcast to all channels and the first `Resolve()` call wins. Other channels get `CancelApproval()` for cleanup. Rate limiting prevents approval queue flooding: `MaxPendingRequests` (default 50) caps concurrent pending approvals, and per-destination rate limits (5 requests/minute) prevent a single target from monopolizing the queue. Requests exceeding limits are auto-denied.

Telegram channel: `internal/telegram/approval.go` implements `TelegramChannel` satisfying the `channel.Channel` interface. When `policyRuleSet.Allow()` encounters an Ask verdict, it calls `broker.Request()` which blocks until a channel resolves the request or the timeout expires. The Telegram channel sends an inline keyboard message and calls `broker.Resolve()` when the user responds. "Always Allow" writes to the SQLite store with source="approval", then recompiles the Engine and atomically swaps it. `CouldBeAllowed(dest, includeAsk)` takes an `includeAsk` parameter: when true (broker configured), Ask-matching destinations are resolved via DNS so the approval flow can proceed; when false (no broker), Ask rules are treated as Deny at the DNS stage to prevent leaking queries. Telegram env var names are hardcoded: `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` (no config-based indirection).

Telegram commands: `CommandHandler` holds an `atomic.Pointer[policy.Engine]` for lock-free reads and is updated via `UpdateEngine()` on SIGHUP. Policy mutations (`/policy allow`, `/policy deny`, `/policy remove`) call `store.AddRule()` and `store.RemoveRule()` on the unified rules table, then recompile the Engine and swap atomically. All changes persist across restarts.

Audit logger is optional. Pass nil in `Config.Audit` and the proxy handles it gracefully. Each JSON line includes a `prev_hash` field containing the blake3 hash of the previous line's raw JSON bytes. The first entry uses blake3("") as the genesis hash. On startup, `NewFileLogger` reads the last line from the existing file (seeking backwards from EOF) to recover the hash chain across restarts. `VerifyChain` walks the log and reports any broken links. The `sluice audit verify` CLI command wraps this for tamper detection.

Credential vault: `Store` manages age-encrypted files in `~/.sluice/credentials/` with an auto-generated X25519 identity. `SecureBytes` wraps decrypted values and zeroes memory on `Release()` (best-effort in Go due to GC and string copies). `Provider` interface abstracts credential sources (age files, env vars, HashiCorp Vault). `NewProviderFromConfig` reads vault configuration from the SQLite store's typed config singleton (fields: VaultProvider, VaultDir, VaultProviders, and HashiCorp-specific fields). TOML `[vault]` and `[vault.hashicorp]` sections are imported into the config table during seed import. `HashiCorpProvider` connects to HashiCorp Vault's KV v2 secrets engine, supporting both token and AppRole authentication. `role_id` and `secret_id` support env var indirection via `role_id_env` and `secret_id_env`. For `addr` and `token`, the Vault SDK reads `VAULT_ADDR` and `VAULT_TOKEN` automatically when not set.

Binding resolution: `BindingResolver` compiles destination glob patterns (reusing `policy.CompileGlob`) and resolves `(host, port)` to a `Binding`. Bindings specify the credential name, header, template (`Bearer {value}`), and protocols (JSON array).

HTTPS credential injection: `Injector` wraps `goproxy` as an in-process MITM proxy. `LoadOrCreateCA` generates a self-signed ECDSA P-256 CA persisted to disk. Per-host certificates are generated at interception time. All authenticated HTTPS connections are MITMed (not just those with bindings) so phantom tokens can never leak to any upstream. Binding-specific header injection handles configured credential headers. A second global pass replaces ALL known phantom tokens (`SLUICE_PHANTOM:<name>`) in ALL request headers and body regardless of binding match, acting as a safety net against leaks to unexpected destinations. `SecureBytes.Release()` zeroes credentials immediately after injection.

SSH credential injection: `SSHJumpHost` accepts the agent's SSH connection with no authentication (`NoClientAuth`), decrypts the SSH private key from the vault, authenticates to the upstream server, and relays SSH channels/requests bidirectionally. `Binding.Template` holds the SSH username (defaults to "root").

Mail credential injection: `MailProxy` intercepts IMAP LOGIN and SMTP AUTH PLAIN/LOGIN commands. For base64-encoded auth data, it decodes, replaces phantom tokens, and re-encodes. Non-auth traffic is relayed unchanged.

Docker integration: Three-container architecture (sluice + tun2proxy + openclaw) with `network_mode: "service:tun2proxy"` routing all openclaw traffic through sluice's SOCKS5 proxy. `docker.Manager` wraps a `ContainerClient` interface with `ExecInContainer` for docker exec and standard container lifecycle methods. On credential mutation via Telegram `/cred` commands or CLI, `credMutationComplete` regenerates phantom environment variables using `GeneratePhantomEnv` and calls `Manager.ReloadSecrets`. Hot reload writes each phantom token as a file in a shared `sluice-phantoms` volume (e.g. `/phantoms/ANTHROPIC_API_KEY`) then runs `docker exec openclaw openclaw secrets reload`. If exec fails (agent image does not support reload), it falls back to `RestartWithEnv` which recreates the container with updated env vars. `BotConfig.Vault` and `BotConfig.DockerMgr` wire the vault and Docker manager into Telegram command handling. The sluice entrypoint generates a CA cert and copies it to a shared volume so openclaw can trust HTTPS MITM certificates via `SSL_CERT_FILE`.

Health check: A minimal HTTP server on `127.0.0.1:3000` (configurable via `--health-addr`) serves `/healthz`, returning 200 when the SOCKS5 proxy is listening. The Dockerfile includes a `HEALTHCHECK` directive using `wget` against this endpoint. compose.yml uses `service_healthy` conditions to sequence startup: tun2proxy waits for sluice, openclaw waits for tun2proxy.

Graceful shutdown: On SIGINT/SIGTERM, the proxy stops accepting new connections and drains in-flight connections up to `--shutdown-timeout` (default 10s). Pending approval requests are auto-denied via `channel.Broker.CancelAll()` with a "shutting down" reason. The audit logger is closed after all connections drain.

MCP gateway: `Gateway` spawns upstream MCP servers as child processes via `StartUpstream`, performs `initialize` handshake and `notifications/initialized`, discovers tools via `tools/list`, and namespaces them with `<upstream>__<tool>`. The agent connects via stdio (`RunStdio`). On `tools/call`, the gateway evaluates `ToolPolicy` (deny/allow/ask priority, same as network policy), optionally requests approval via the shared `channel.Broker`, runs `ContentInspector.InspectArguments` to block arguments matching regex patterns (JSON is parsed before matching to prevent unicode escape bypass), strips the namespace prefix, forwards to the upstream, runs `ContentInspector.RedactResponse` on the result, and adds governance metadata. `ToolPolicy` reuses `policy.CompileGlob` for glob matching. The `mcp` subcommand reads upstreams and rules from the unified SQLite rules table. Upstreams can be registered at runtime via `sluice mcp add` (persisted in the `mcp_upstreams` table). Per-upstream timeouts are configurable via `timeout_sec` (default 120s). `GatewayConfig.TimeoutSec` sets a global default that individual upstreams can override.

## Policy Store

All runtime policy state is stored in a SQLite database (default: `sluice.db`). TOML files are used only for initial seeding via `sluice policy import`. The CLI, Telegram commands, and approval buttons all write to the same database.

### TOML Seed File Format (config.toml)

Rules use a unified format: `[[allow]]`, `[[deny]]`, `[[ask]]`, `[[redact]]`. Each entry carries exactly one of: `destination` (network), `tool` (MCP), or `pattern` (content inspection). The section name determines the verdict. Telegram env var names (`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`) are hardcoded and not part of the config file.

```toml
[policy]
default = "ask"     # ask | deny | allow
timeout_sec = 120   # seconds to wait for approval

[vault]
provider = "age"

# -- Network rules (destination field) --

[[allow]]
destination = "api.anthropic.com"
ports = [443]

[[allow]]
destination = "api.openai.com"
ports = [443]

[[allow]]
destination = "*.telegram.org"
ports = [443]
name = "Telegram bot API passthrough"

# -- Tool rules (tool field) --

[[allow]]
tool = "github__list_*"
name = "read-only github list"

[[ask]]
tool = "github__create_*"

[[deny]]
tool = "exec__*"

# -- Content deny rules (pattern field) --

[[deny]]
pattern = "(?i)(sk-[a-zA-Z0-9_-]{20,})"
name = "api key in tool arguments"

# -- Content redact rules --

[[redact]]
pattern = "(?i)(sk-[a-zA-Z0-9_-]{20,})"
replacement = "[REDACTED_API_KEY]"
name = "api key in responses"

# -- Denylist --

[[deny]]
destination = "169.254.169.254"
name = "Block cloud metadata endpoint"

[[deny]]
destination = "100.100.100.200"
name = "Block Alibaba metadata"

# -- Credential bindings --

[[binding]]
destination = "api.anthropic.com"
ports = [443]
credential = "anthropic_api_key"
header = "x-api-key"

[[binding]]
destination = "api.openai.com"
ports = [443]
credential = "openai_api_key"
header = "Authorization"
template = "Bearer {value}"
```

## Credential Injection: Phantom Token Swap

Sluice does NOT need to know API auth schemes (which header, which format).
Instead, it uses 1:1 phantom token mapping with byte-level find-and-replace.

### How it works

1. User adds a credential via CLI (`sluice cred add anthropic_api_key`) or Telegram bot (`/cred add`)
2. For Telegram: user sends the real key (Sluice deletes the message after reading). For CLI: reads from terminal.
3. Sluice encrypts and stores the real credential in the vault
4. Sluice generates a phantom token (random string matching the key format)
5. Sluice writes phantom tokens as files in a shared volume (`/phantoms/ANTHROPIC_API_KEY`) and signals OpenClaw to reload via `docker exec openclaw openclaw secrets reload`. Falls back to full container restart if exec fails.
6. OpenClaw uses phantom tokens normally via SDKs (thinks they're real)
7. SDKs put them in the correct headers/body (they know how)
8. Sluice's built-in HTTPS MITM intercepts the request and does byte-level
   find-and-replace: phantom -> real. Credential is decrypted into zeroized
   memory and cleared immediately after injection.
9. Sluice never needs to know the API's auth format

### Hot credential reload via shared volume

Sluice delivers phantom tokens to the agent container via a shared volume
and signals a reload, avoiding full container restarts.

```
User adds cred via CLI or Telegram
    |
    v
Sluice vault (stores real + generates phantom)
    |
    v
Write phantom files to shared volume (/phantoms/ANTHROPIC_API_KEY)
    |
    v
docker exec openclaw openclaw secrets reload
    |
    v
OpenClaw hot-reloads phantom tokens from /phantoms/ directory
```

If the agent image does not support `secrets reload`, Sluice falls back to
recreating the container with updated env vars via Docker socket.

Sluice container needs `/var/run/docker.sock` mounted. This is acceptable
because Sluice already holds all real credentials. It's the most privileged
component by design.

### Built-in HTTPS MITM (replaces mitmproxy)

Sluice handles TLS interception in-process using `goproxy`
(github.com/elazarl/goproxy). Benefits over the previous mitmproxy design:

- **Single binary.** No Python runtime, no separate container, no IPC.
- **Credential never leaves process.** Decrypted into zeroized `[]byte`,
  injected into the request, zeroed immediately after. No serialization
  to another process where it could leak.
- **Simpler deployment.** One container instead of two. No addon scripts.
- **CA cert.** Sluice generates a self-signed CA on first run and stores it
  in the vault dir. The CA cert is mounted into the agent container as a
  trusted root so TLS verification works.

The injection logic is the same: byte-level find-and-replace of phantom
tokens in all request headers and body. No API knowledge needed.

### Sluice Telegram Bot (separate from OpenClaw's bot)

Two bots, two concerns:
- **OpenClaw bot**: your AI assistant (chat, commands, skills)
- **Sluice bot**: security layer (approvals, credential management, policy)

Sluice bot commands:

```
/cred add <name>           Add credential (prompts for value, deletes message)
/cred list                 List credential names (never shows values)
/cred rotate <name>        Replace credential, regenerate phantom, hot-reload agent
/cred remove <name>        Remove credential, hot-reload agent

/policy show               Show current policy rules (from SQLite store)
/policy allow <dest>       Add allow rule to store, recompile engine
/policy deny <dest>        Add deny rule to store, recompile engine
/policy remove <id>        Remove rule from store by ID

/status                    Proxy stats, pending approvals, agent health
/audit recent [N]          Show last N connections
```

### Phantom token mapping

```toml
# vault/bindings.toml
[[credential]]
name = "anthropic_api_key"
phantom = "sk-ant-phantom-abc123def456"

[[credential]]
name = "openai_api_key"
phantom = "sk-phantom-openai-xyz789"

[[credential]]
name = "github_token"
phantom = "ghp_phantom0000000000000000000000000000"

# Multiple creds per service work naturally:
[[credential]]
name = "github_org_token"
phantom = "ghp_phantom_org_1111111111111111111111"
```

The real credential values live in the age-encrypted vault. Phantom tokens
are random strings that look like real tokens (same format/length) so SDKs
don't reject them.

### In-process credential injection (the entire logic)

```go
// internal/proxy/inject.go
func injectCredentials(req *http.Request, bindings []PhantomBinding) {
    // 1. Binding-specific header injection
    for _, b := range bindings {
        real := vault.Get(b.Name) // returns SecureBytes
        // Set configured header with template formatting
        real.Release()
    }

    // 2. Global phantom replacement (ALL MITMed traffic)
    names, _ := provider.List()
    for _, name := range names {
        phantom := PhantomToken(name)
        secret, _ := provider.Get(name)
        // Replace in ALL headers and body regardless of binding match
        secret.Release() // zero credential memory immediately
    }
}
```

Two-pass injection: first sets binding-specific headers, then replaces all
known phantom tokens in all traffic as a safety net. No API knowledge needed.

### Non-HTTP protocols

| Protocol | How credentials are injected |
|----------|-------------------------------|
| **HTTP/HTTPS** | Built-in MITM, byte-level phantom swap (handles any auth scheme) |
| **SSH** | Sluice acts as SSH jump host, injects key from vault |
| **IMAP/SMTP** | Sluice proxies AUTH command, swaps phantom password for real |
| **Generic TCP** | Connection-level allow/deny only (no credential injection) |

## Docker Compose

See `compose.yml` in the repo root. Key features:
- Health checks: sluice exposes `/healthz` on `:3000`, tun2proxy checks TUN device
- Startup ordering via `condition: service_healthy`
- `restart: unless-stopped` on all services
- CA cert trust: openclaw mounts sluice-ca volume and sets `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`
- Phantom tokens: shared `sluice-phantoms` volume mounted read-write in sluice and read-only in openclaw at `/phantoms/`. Sluice writes phantom token files, openclaw reads them. Fallback `env_file: .env.phantom` for initial bootstrap.

## Libraries

- `github.com/armon/go-socks5` - SOCKS5 server
- `modernc.org/sqlite` - Pure Go SQLite driver (no CGO, works with CGO_ENABLED=0)
- `github.com/BurntSushi/toml` - TOML parsing for seed file import only (`store/import.go`)
- `golang.org/x/net/proxy` - SOCKS5 client (tests only)
- `github.com/go-telegram-bot-api/telegram-bot-api/v5` - Telegram Bot API client
- `filippo.io/age` - Age encryption for credential vault
- `github.com/elazarl/goproxy` - In-process HTTPS MITM proxy for credential injection
- `golang.org/x/crypto/ssh` - SSH client/server for jump host credential injection
- `golang.org/x/term` - Terminal password input for `sluice cred add`
- `lukechampine.com/blake3` - Blake3 hashing for tamper-evident audit chain
- `github.com/hashicorp/vault/api` - HashiCorp Vault client for external secret management (KV v2, AppRole auth)
- `github.com/golang-migrate/migrate/v4` - Schema migration framework with embedded SQL files

## Estimated Scope

| Component | Approx LOC | Notes |
|-----------|------------|-------|
| SOCKS5 proxy with policy engine | ~400 | Core connection handling |
| HTTPS MITM + credential injection | ~300 | goproxy handlers, phantom swap, CA cert gen |
| MCP gateway (stdio + HTTP) | ~500 | Tool interception, upstream management |
| Credential vault + secure memory | ~300 | age-encrypted, SecureBytes with zeroing |
| External vault providers | ~200 | HashiCorp Vault, env, provider interface |
| Telegram bot (approval UX) | ~250 | Inline keyboard, callback handling, shared by both layers |
| SQLite policy store + TOML import | ~400 | Runtime state persistence, seed import |
| Policy CLI (list/add/remove/import/export) | ~200 | Unified control plane |
| Content inspection (tool args + responses) | ~200 | Regex patterns for secrets/PII |
| Audit logger | ~200 | JSON lines, blake3 hash chains, chain verification CLI |
| **Total custom code** | **~2950** | Single Go binary |
| Docker setup + tun2proxy | Config only | compose.yml |

## Future: Apple Container Support (last-mile, requires research)

The primary deployment target is Docker (Linux containers). Apple Container
(macOS microVMs) is a stretch goal that would give native macOS isolation
without Docker Desktop.

### Why it's non-trivial

The Docker architecture relies on three features Apple Container doesn't have:

1. **Shared network namespace** (`network_mode: "service:sluice"`) forces all
   agent traffic through Sluice. Apple Container VMs have their own isolated
   network stack with no namespace sharing.

2. **tun2proxy** requires `NET_ADMIN` + `/dev/net/tun`. Apple Container's
   security model may not expose TUN devices to guest VMs.

3. **Docker socket** for credential rotation (container restart with new env
   vars). Apple Container uses a different management API (`container` CLI).

### Research options (pick one)

| Approach | All-protocol? | Complexity | Notes |
|----------|--------------|------------|-------|
| **macOS packet filter (pf)** | Yes | Medium | Redirect VM network interface traffic to Sluice SOCKS5 port via pf rules. Requires root on host. Well-documented for macOS firewalling. |
| **tun2proxy inside Apple Container VM** | Yes | Low (if TUN works) | Identical to Docker approach but running tun2proxy inside the guest VM. Need to verify TUN device availability in Apple Container guests. |
| **Virtualization.framework custom networking** | Yes | High | Create a virtual network where Sluice is the sole gateway. Most robust. Uses `VZNATNetworkDeviceAttachment` or `VZBridgedNetworkDeviceAttachment` with custom routing. |
| **`ALL_PROXY` env var only** | HTTP/HTTPS only | Low | Set `ALL_PROXY=socks5://host:1080` in the VM. Covers HTTP/HTTPS but misses SSH, IMAP, raw TCP. Breaks the all-protocol promise. Acceptable as MVP. |

### Recommended research order

1. Verify if Apple Container guests support `/dev/net/tun`. If yes, tun2proxy
   inside the VM is the simplest path and reuses the Docker architecture.
2. If not, prototype pf rules to redirect VM traffic. macOS pf is mature and
   well-documented.
3. Virtualization.framework custom networking is the nuclear option. Only if
   both above fail.

### Additional work needed

- Replace Docker socket management with `container` CLI calls for credential
  rotation (restart VM with new phantom env vars).
- CA cert injection: mount Sluice's MITM CA into the VM's trust store
  (different path than Docker volume mount).
- Sluice Telegram bot `/status` command needs to support both Docker and
  Apple Container backends for agent health checks.

### Decision: Defer until after Docker MVP is solid

Apple Container support is a last-mile feature. The Docker path covers
Linux servers, CI/CD, and macOS-with-Docker-Desktop. Apple Container adds
value for developers who want native macOS isolation without Docker, but
the user base is smaller and the engineering cost is higher.
