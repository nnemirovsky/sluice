# Sluice - CLAUDE.md

Credential-injecting approval proxy for AI agents. Two layers of governance: MCP-level (semantic tool control) and network-level (all-protocol interception). Asks for human approval via Telegram, injects credentials, and forwards.

## Problem

No existing tool combines:
1. Credential/secret isolation from the AI agent
2. Per-request human approval/deny via Telegram
3. All-protocol interception (HTTP, HTTPS, WebSocket, gRPC, SSH, IMAP, SMTP, DNS, QUIC/HTTP3)
4. MCP-level governance (tool names, arguments, per-action policy)
5. Audit logging of every connection and tool call

## Build and Test

```bash
go build -o sluice ./cmd/sluice/
go test ./... -v -timeout 30s
```

## Project Structure

- `cmd/sluice/main.go` - CLI entrypoint with flag parsing, runtime selection (--runtime docker|apple|none|auto), and signal handling
- `cmd/sluice/cred.go` - CLI subcommand handler for credential management (add/list/remove with optional policy+binding auto-creation)
- `cmd/sluice/audit.go` - CLI subcommand handler for audit log verification (`audit verify`)
- `cmd/sluice/cert.go` - CLI subcommand handler for CA certificate generation (`cert generate`)
- `cmd/sluice/mcp.go` - CLI subcommand handler for MCP gateway mode and upstream management (add/list/remove)
- `cmd/sluice/policy.go` - CLI subcommand handler for policy management (list/add/remove/import/export)
- `internal/store/store.go` - SQLite-backed policy store for all runtime state (unified rules, typed config singleton, bindings, channels, MCP upstreams)
- `internal/store/import.go` - TOML import into SQLite store with merge semantics (skip duplicates) and protocol name validation
- `internal/store/migrate.go` - golang-migrate integration with embedded SQL files
- `internal/store/migrations/000001_init.up.sql` - Initial schema migration (rules, config, bindings, mcp_upstreams, channels)
- `internal/store/migrations/000001_init.down.sql` - Rollback for initial schema
- `internal/store/migrations/000005_upstream_transport.up.sql` - Add transport column to mcp_upstreams table
- `internal/store/migrations/000005_upstream_transport.down.sql` - Rollback for transport column
- `internal/proxy/server.go` - SOCKS5 server wrapping `things-go/go-socks5` with TCP and UDP policy enforcement, two-phase protocol detection in the dial path (client byte peeking with 200ms timeout, server banner reading for SMTP/IMAP), and bufferedConn wrapper for replaying peeked bytes
- `internal/proxy/protocol.go` - Protocol type (integer enum with String/ParseProtocol) and two-phase detection: port-based guess via DetectProtocol, then byte-level confirmation via DetectFromClientBytes (TLS, SSH, HTTP) and DetectFromServerBytes (SMTP, IMAP). Supports HTTP, HTTPS, SSH, IMAP, SMTP, WebSocket (ws/wss), gRPC, DNS, QUIC, APNS, and generic.
- `internal/proxy/ca.go` - Self-signed CA generation and persistence for HTTPS MITM
- `internal/proxy/inject.go` - HTTPS MITM credential injector using goproxy with scoped phantom token replacement and unbound token stripping
- `internal/proxy/ssh.go` - SSH jump host with vault key injection and bidirectional channel relay
- `internal/proxy/mail.go` - IMAP/SMTP AUTH command proxy with phantom token replacement (including base64)
- `internal/proxy/ws.go` - WebSocket frame parser (RFC 6455) and bidirectional relay with phantom token replacement in text frames and content inspection
- `internal/proxy/udp.go` - UDP relay for SOCKS5 UDP ASSOCIATE with per-datagram policy enforcement and default-deny
- `internal/proxy/dns.go` - DNS query interceptor with domain-level policy evaluation and NXDOMAIN for denied domains
- `internal/proxy/quic.go` - QUIC/HTTP/3 MITM proxy with TLS termination, phantom token replacement, and content inspection
- `internal/policy/engine.go` - Policy compilation of glob patterns and evaluation (LoadFromBytes for backward compat)
- `internal/policy/engine_store.go` - LoadFromStore builds a read-only Engine from SQLite store
- `internal/policy/glob.go` - Glob pattern to regex compilation (`*` = single label, `**` = across dots)
- `internal/policy/types.go` - Verdict enum (Allow/Deny/Ask/Redact), Rule struct with Protocols []string, PolicyConfig. Note: Protocol in proxy is an integer enum (proxy.Protocol), while policy rules store protocol names as strings for TOML/JSON compatibility.
- `internal/vault/store.go` - Age-encrypted credential storage with X25519 identity key management
- `internal/vault/secure.go` - SecureBytes type with best-effort zeroizing memory release
- `internal/vault/binding.go` - Binding resolution mapping destinations to credentials via glob matching
- `internal/vault/provider.go` - Pluggable credential provider interface, VaultConfig, ChainProvider
- `internal/vault/provider_age.go` - Age file backend (Store satisfies Provider)
- `internal/vault/provider_env.go` - Environment variable credential provider
- `internal/vault/provider_hashicorp.go` - HashiCorp Vault provider with KV v2 support and AppRole auth
- `internal/vault/provider_1password.go` - 1Password provider via official Go SDK with Service Account token auth
- `internal/vault/provider_bitwarden.go` - Bitwarden Secrets Manager provider via bws CLI wrapper with access token auth
- `internal/vault/provider_keepass.go` - KeePass (.kdbx) file provider via gokeepasslib with auto-reload on file change
- `internal/vault/provider_gopass.go` - Gopass provider via CLI wrapper (gopass show/ls)
- `internal/mcp/gateway.go` - MCP gateway core with tool policy enforcement and upstream forwarding
- `internal/mcp/inspect.go` - Content inspection: argument blocking and response redaction using regex rules
- `internal/mcp/policy.go` - Tool-level policy evaluation using glob patterns (deny/allow/ask priority)
- `internal/mcp/transport.go` - Stdio transport for MCP gateway (JSON-RPC over stdin/stdout)
- `internal/mcp/transport_http.go` - Streamable HTTP upstream client with session management and SSE support
- `internal/mcp/transport_ws.go` - WebSocket upstream client with `mcp` subprotocol and reconnection
- `internal/mcp/server_http.go` - Streamable HTTP server endpoint (`POST /mcp`, `DELETE /mcp`) with session tracking
- `internal/mcp/types.go` - JSON-RPC 2.0 and MCP protocol type definitions
- `internal/mcp/upstream.go` - Upstream MCP server process management (spawn, handshake, tool discovery, transport routing)
- `internal/audit/logger.go` - Thread-safe append-only JSON lines audit logger with blake3 hash chaining
- `internal/audit/verify.go` - Hash chain verification (walks log file, reports broken links)
- `internal/channel/channel.go` - Channel interface, ChannelType enum (Telegram=0, HTTP=1), ApprovalRequest/Response/Command types
- `internal/channel/broker.go` - Channel-agnostic approval broker with broadcast-and-first-wins, rate limiting, cross-channel cancellation
- `internal/telegram/approval.go` - TelegramChannel implementing channel.Channel interface
- `internal/telegram/bot.go` - Telegram message formatting utilities and token sanitization
- `internal/telegram/commands.go` - Telegram admin commands (/policy, /cred, /status, /audit, /help) backed by SQLite store
- `internal/container/types.go` - ContainerManager interface shared by Docker and Apple Container backends, Runtime enum (Docker=0, Apple=1, None=2), ContainerStatus struct
- `internal/container/apple.go` - Apple Container backend: AppleCLI wrapping `container` CLI via os/exec, AppleManager implementing ContainerManager, CA cert injection
- `internal/container/apple_test.go` - Tests for AppleCLI, AppleManager, and CA cert injection with mock CommandRunner
- `internal/container/network.go` - NetworkRouter for macOS pf rules that redirect Apple Container VM traffic through tun2proxy to SOCKS5
- `internal/container/network_test.go` - Tests for pf rule generation, subnet derivation, and network routing
- `internal/docker/manager.go` - Docker container manager implementing container.ContainerManager for credential hot-reload via shared volume + docker exec, with restart fallback
- `internal/docker/socket_client.go` - Docker socket HTTP client for container lifecycle and exec operations
- `Dockerfile` - Multi-stage build for Sluice container
- `compose.yml` - Three-container setup (sluice + tun2proxy + openclaw) with shared phantom volume
- `compose.dev.yml` - Development compose with build-from-source
- `scripts/docker-entrypoint.sh` - Container entrypoint with CA cert generation and copy to shared volume
- `scripts/apple-container-setup.sh` - macOS setup script for Apple Container: pf rules, tun2proxy, IP forwarding
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

Sits between the container and the internet. Sees every TCP and UDP connection.
Can approve/deny any protocol (HTTP, HTTPS, WebSocket, gRPC, SSH, IMAP, SMTP,
DNS, QUIC/HTTP3). Injects credentials at the network level. Catches anything
that bypasses MCP (direct HTTP calls, raw sockets, etc.).

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
|  |  |              |    |  Routes ALL TCP+UDP |               | |
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
|  | - Tool-level policy | | - TCP + UDP policy                 | |
|  | - Argument inspect  | | - HTTPS + QUIC/HTTP3 MITM          | |
|  | - Per-action control| | - WebSocket frame inspection       | |
|  | - Response redact   | | - DNS query-level policy           | |
|  | - Local tool govnce | | - Credential injection (in-process)| |
|  | - Telegram approval | | - Telegram approval + audit log    | |
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
| **tun2proxy** | Routes ALL TCP + UDP through TUN to SOCKS5 | Existing `ghcr.io/tun2proxy/tun2proxy` |
| **Sluice SOCKS5 Proxy** | Network-level policy + HTTPS/QUIC MITM + WebSocket inspection + DNS interception + credential injection | Custom Go, single binary |
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
sluice mcp add <name> --command <cmd> [--transport stdio|http|websocket] [--args "arg1,arg2"] [--env "KEY=VAL,..."] [--timeout 120]
sluice mcp list
sluice mcp remove <name>
sluice mcp                          # start MCP gateway (reads upstreams from store)
```

For HTTP/WebSocket upstreams, `--command` holds the URL instead of a binary path. `--args` and `--env` are unused for remote transports. Env values prefixed with `vault:` are resolved from the credential vault at upstream spawn time.

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

Proxy integration: `policyRuleSet` implements the `socks5.RuleSet` interface for TCP CONNECT. UDP ASSOCIATE sessions are handled by `UDPRelay` with per-datagram policy, `DNSInterceptor` for port 53, and `QUICProxy` for QUIC packets on HTTPS ports. Protocol detection uses two phases: first a port-based guess via `DetectProtocol(port)`, then byte-level detection for non-standard ports. Standard ports (443, 22, 25, 587, 993, 465, etc.) are routed directly based on the port guess because protocol mismatches on well-known ports are rare and mismatched handlers fail fast without leaking credentials. When the port guess returns `ProtoGeneric` (non-standard ports), byte-level detection kicks in. For client-first protocols (TLS, SSH, HTTP), `DetectFromClientBytes` peeks at the first bytes sent by the client using a buffered connection wrapper. For server-first protocols (SMTP, IMAP), `DetectFromServerBytes` reads the server banner after upstream TCP connect. If byte detection returns a non-generic result, it overrides the port guess. This allows correct handling of services on non-standard ports (e.g. HTTPS on port 8000 gets MITM credential injection, SSH on port 2222 gets jump host handling). The detection path signals SOCKS5 CONNECT success before reading client bytes (since the client only sends data after CONNECT succeeds), so handler failures in this path surface as application-layer connection drops rather than SOCKS5 errors. The binding resolver is stored as an `atomic.Pointer[vault.BindingResolver]` so it can be hot-swapped on SIGHUP or after Telegram/CLI credential mutations. `Server.StoreResolver()` and `Server.ResolverPtr()` provide the swap and shared-access interfaces.

Channel abstraction: `internal/channel/channel.go` defines the `Channel` interface and `ChannelType` enum (ChannelTelegram=0, ChannelHTTP=1). `Channel` has methods for non-blocking `RequestApproval`, `CancelApproval`, `Commands()`, `Notify`, and lifecycle (`Start`/`Stop`). `internal/channel/broker.go` defines the `Broker` which coordinates approval flow across multiple enabled channels. Approval requests are broadcast to all channels and the first `Resolve()` call wins. Other channels get `CancelApproval()` for cleanup. Rate limiting prevents approval queue flooding: `MaxPendingRequests` (default 50) caps concurrent pending approvals, and per-destination rate limits (5 requests/minute) prevent a single target from monopolizing the queue. Requests exceeding limits are auto-denied.

Telegram channel: `internal/telegram/approval.go` implements `TelegramChannel` satisfying the `channel.Channel` interface. When `policyRuleSet.Allow()` encounters an Ask verdict, it calls `broker.Request()` which blocks until a channel resolves the request or the timeout expires. The Telegram channel sends an inline keyboard message and calls `broker.Resolve()` when the user responds. "Always Allow" writes to the SQLite store with source="approval", then recompiles the Engine and atomically swaps it. `CouldBeAllowed(dest, includeAsk)` takes an `includeAsk` parameter: when true (broker configured), Ask-matching destinations are resolved via DNS so the approval flow can proceed; when false (no broker), Ask rules are treated as Deny at the DNS stage to prevent leaking queries. Telegram env var names are hardcoded: `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` (no config-based indirection).

Telegram commands: `CommandHandler` holds an `atomic.Pointer[policy.Engine]` for lock-free reads, shared with the proxy server. Policy mutations (`/policy allow`, `/policy deny`, `/policy remove`) call `store.AddRule()` and `store.RemoveRule()` on the unified rules table, then call `recompileAndSwap()` to rebuild the Engine and atomically swap it. SIGHUP reloads go through `srv.StoreEngine()` on the same shared pointer. All changes persist across restarts.

Audit logger is optional. Pass nil in `Config.Audit` and the proxy handles it gracefully. Each JSON line includes a `prev_hash` field containing the blake3 hash of the previous line's raw JSON bytes. The first entry uses blake3("") as the genesis hash. On startup, `NewFileLogger` reads the last line from the existing file (seeking backwards from EOF) to recover the hash chain across restarts. `VerifyChain` walks the log and reports any broken links. The `sluice audit verify` CLI command wraps this for tamper detection.

Credential vault: `Store` manages age-encrypted files in `~/.sluice/credentials/` with an auto-generated X25519 identity. `SecureBytes` wraps decrypted values and zeroes memory on `Release()` (best-effort in Go due to GC and string copies). `Provider` interface abstracts credential sources. `NewProviderFromConfig` reads vault configuration from the SQLite store's typed config singleton and routes to the correct provider. TOML `[vault]` and provider-specific subsections are imported into the config table during seed import. Seven providers are supported:

- **age** (default): Local age-encrypted files in `~/.sluice/credentials/`. Auto-generates X25519 identity on first use. No external dependencies.
- **env**: Reads credentials from environment variables. Credential name maps directly to env var name (uppercased).
- **hashicorp**: HashiCorp Vault KV v2 secrets engine. Supports token auth (`VAULT_TOKEN` env var or config) and AppRole auth (`role_id_env`/`secret_id_env` for env var indirection). Config: `[vault.hashicorp]` with `addr`, `mount` (default "secret"), `prefix`.
- **1password**: 1Password via official Go SDK. Auth via `OP_SERVICE_ACCOUNT_TOKEN` env var or config. Credential name maps to item name in the configured vault. Reads the "credential" field by default (configurable via `field`). Config: `[vault.1password]` with `vault`, `field`.
- **bitwarden**: Bitwarden Secrets Manager via `bws` CLI wrapper (SDK requires CGO, so CLI is used for pure Go). Auth via `BWS_ACCESS_TOKEN` env var or config. Caches secret list for 30s to reduce API calls. Config: `[vault.bitwarden]` with `org_id`.
- **keepass**: KeePass .kdbx file via gokeepasslib (pure Go). Auth via `KEEPASS_PASSWORD` env var and optional key file. Builds in-memory index of entry titles to passwords. Auto-reloads when file modification time changes. Searches all groups recursively. Config: `[vault.keepass]` with `path`, `key_file`.
- **gopass**: Gopass via CLI wrapper (`gopass show -o` / `gopass ls --flat`). Requires `gopass` binary installed. Uses default store path unless overridden. Config: `[vault.gopass]` with `store`.

Chain provider: Set `providers = ["1password", "age"]` in `[vault]` to try multiple providers in order. First provider that has the credential wins. `ChainProvider.List()` merges names from all providers (deduped).

Binding resolution: `BindingResolver` compiles destination glob patterns (reusing `policy.CompileGlob`) and resolves `(host, port)` to a `Binding`. Bindings specify the credential name, header, template (`Bearer {value}`), and protocols (JSON array).

HTTPS credential injection: `Injector` wraps `goproxy` as an in-process MITM proxy. `LoadOrCreateCA` generates a self-signed ECDSA P-256 CA persisted to disk. Per-host certificates are generated at interception time. All authenticated HTTPS connections are MITMed (not just those with bindings) so phantom tokens can never leak to any upstream. Binding-specific header injection handles configured credential headers. Scoped phantom replacement replaces phantom tokens only for credentials bound to the destination, preventing cross-credential exfiltration to unintended destinations. Any remaining unbound phantom tokens are stripped (replaced with empty bytes) as a safety net. `SecureBytes.Release()` zeroes credentials immediately after injection.

SSH credential injection: `SSHJumpHost` accepts the agent's SSH connection with no authentication (`NoClientAuth`), decrypts the SSH private key from the vault, authenticates to the upstream server, and relays SSH channels/requests bidirectionally. `Binding.Template` holds the SSH username (defaults to "root").

Mail credential injection: `MailProxy` intercepts IMAP LOGIN and SMTP AUTH PLAIN/LOGIN commands. For base64-encoded auth data, it decodes, replaces phantom tokens, and re-encodes. Non-auth traffic is relayed unchanged.

WebSocket frame inspection: `internal/proxy/ws.go` implements RFC 6455 frame parsing (`ReadFrame`/`WriteFrame`) and a bidirectional `WSProxy.Relay()`. When the MITM detects a `101 Switching Protocols` response with `Upgrade: websocket`, it hijacks both connections and hands them to the WebSocket relay. Text frames (opcode 0x1) are unmasked, scanned for phantom tokens (replaced with real credentials), checked against content deny rules (connection closed on match), and redact rules applied. Binary frames pass through unmodified. Control frames (ping/pong/close) are forwarded unchanged. Continuation frames are reassembled for inspection and forwarded individually. Protocol is tagged as `ws` (plaintext) or `wss` (over TLS).

gRPC detection: Requests with `Content-Type: application/grpc` are tagged as `grpc` protocol in the MITM handler. This enables protocol-specific policy rules (e.g., `protocols = ["grpc"]`). gRPC credential injection uses the same HTTPS MITM phantom swap.

UDP relay and default-deny: `internal/proxy/udp.go` implements `UDPRelay` handling SOCKS5 UDP ASSOCIATE sessions. Each datagram's destination is evaluated against the policy engine. Default verdict for UDP is deny (safe default since legitimate API traffic uses TCP). Ask verdicts are treated as deny (Telegram approval for individual UDP packets is not practical). The relay maps client addresses to sessions and cleans up on TCP control connection close.

DNS query interception: `internal/proxy/dns.go` implements `DNSInterceptor` that parses DNS query packets (Question section only, extracting domain name from length-prefixed labels). Domains are evaluated against the policy engine using the same glob matching as network rules. Allowed queries are forwarded to the upstream resolver (configurable via `--dns-resolver`, default `8.8.8.8:53`). Denied domains get an NXDOMAIN response. All DNS queries are logged to audit with protocol="dns".

QUIC/HTTP3 MITM: `internal/proxy/quic.go` implements `QUICProxy` using `quic-go`. QUIC initial packets are detected in the UDP relay by checking the long header format (first byte bits 7-6 = 11, version field at bytes 1-4 for QUIC v1/v2). Detected QUIC traffic on HTTPS ports is routed to QUICProxy, which terminates TLS using per-host certificates generated from the sluice CA (reusing `GenerateCertForHost` from ca.go). SNI is extracted from the TLS ClientHello. HTTP/3 requests are intercepted using `quic-go/http3`: phantom tokens are replaced in headers and body, content deny patterns block requests, and redact patterns modify responses before forwarding to the agent. The upstream connection uses `http3.RoundTripper`.

Docker integration: Three-container architecture (sluice + tun2proxy + openclaw) with `network_mode: "service:tun2proxy"` routing all openclaw traffic through sluice's SOCKS5 proxy. `docker.Manager` wraps a `ContainerClient` interface with `ExecInContainer` for docker exec and standard container lifecycle methods. On credential mutation via Telegram `/cred` commands or CLI, `credMutationComplete` regenerates phantom environment variables using `GeneratePhantomEnv` and calls `Manager.ReloadSecrets`. Hot reload writes each phantom token as a file in a shared `sluice-phantoms` volume (e.g. `/phantoms/ANTHROPIC_API_KEY`) then runs `docker exec openclaw openclaw secrets reload`. If exec fails (agent image does not support reload), it falls back to `RestartWithEnv` which recreates the container with updated env vars. `ChannelConfig.Vault` and `ChannelConfig.ContainerMgr` wire the vault and container manager (any `container.ContainerManager` implementation) into Telegram command handling. The sluice entrypoint generates a CA cert and copies it to a shared volume so openclaw can trust HTTPS MITM certificates via `SSL_CERT_FILE`. `InjectMCPConfig` writes `mcp-servers.json` to the shared phantoms volume and signals OpenClaw to reload MCP config, enabling auto-discovery of sluice as an MCP server via Streamable HTTP.

Health check: A minimal HTTP server on `127.0.0.1:3000` (configurable via `--health-addr`) serves `/healthz`, returning 200 when the SOCKS5 proxy is listening. When MCP gateway mode is active, the same server also serves the Streamable HTTP endpoint at `/mcp` (see "MCP Streamable HTTP server" below). The Dockerfile includes a `HEALTHCHECK` directive using `wget` against this endpoint. compose.yml uses `service_healthy` conditions to sequence startup: tun2proxy waits for sluice, openclaw waits for tun2proxy.

Graceful shutdown: On SIGINT/SIGTERM, the proxy stops accepting new connections and drains in-flight connections up to `--shutdown-timeout` (default 10s). Pending approval requests are auto-denied via `channel.Broker.CancelAll()` with a "shutting down" reason. The audit logger is closed after all connections drain.

MCP gateway: `Gateway` supports three upstream transport types: stdio (child processes), Streamable HTTP (remote servers), and WebSocket (real-time servers). `StartUpstreamForTransport` routes to the correct implementation based on `UpstreamConfig.Transport` (default "stdio"). All three satisfy the `MCPUpstream` interface (`Initialize`, `DiscoverTools`, `SendRequest`, `Stop`). On startup, each upstream performs an `initialize` handshake and `notifications/initialized`, discovers tools via `tools/list`, and namespaces them with `<upstream>__<tool>`. The agent connects via stdio (`RunStdio`) or Streamable HTTP (`POST /mcp`). On `tools/call`, the gateway evaluates `ToolPolicy` (deny/allow/ask priority, same as network policy), optionally requests approval via the shared `channel.Broker`, runs `ContentInspector.InspectArguments` to block arguments matching regex patterns (JSON is parsed before matching to prevent unicode escape bypass), strips the namespace prefix, forwards to the upstream, runs `ContentInspector.RedactResponse` on the result, and adds governance metadata. `ToolPolicy` reuses `policy.CompileGlob` for glob matching. The `mcp` subcommand reads upstreams and rules from the unified SQLite rules table. Upstreams can be registered at runtime via `sluice mcp add` (persisted in the `mcp_upstreams` table). Per-upstream timeouts are configurable via `timeout_sec` (default 120s). `GatewayConfig.TimeoutSec` sets a global default that individual upstreams can override. Env values with `vault:` prefix in upstream config are resolved from the credential vault at spawn time. On credential rotation, `RestartUpstream` stops and restarts the upstream process with fresh credentials.

MCP transport details: `HTTPUpstream` (`transport_http.go`) connects to remote MCP servers via Streamable HTTP. It POSTs JSON-RPC requests to the upstream URL, tracks server sessions via the `Mcp-Session-Id` response header, and handles SSE streaming responses for long-running tool calls. `Stop` sends a DELETE request to close the server-side session. `WSUpstream` (`transport_ws.go`) connects via WebSocket with the `mcp` subprotocol. JSON-RPC messages are sent as text frames. It supports reconnection on connection drop via `Reconnect()` and reads are filtered to skip server-initiated notifications. Both transports use configurable per-upstream timeouts.

MCP Streamable HTTP server: `MCPHTTPHandler` (`server_http.go`) serves `POST /mcp` and `DELETE /mcp` on the existing port 3000 (alongside `/healthz` and `/api/*`). On `initialize`, it generates a random session ID returned via `Mcp-Session-Id` header. Sessions are tracked in a `sync.Map`. All requests are routed through the existing `Gateway.HandleToolCall` with the same policy enforcement, audit, and approval flow. Supports SSE responses when the client sends `Accept: text/event-stream`. The `/mcp` endpoint is mounted only when MCP gateway mode is active.

MCP auto-injection: When `--auto-inject-mcp` is set (defaults to true when a container runtime is active), sluice writes `/phantoms/mcp-servers.json` containing `{"sluice": {"url": "http://127.0.0.1:3000/mcp", "transport": "streamable-http"}}` to the shared phantoms volume after the gateway starts. It then signals OpenClaw to reload MCP config via `docker exec openclaw openclaw mcp reload` (best-effort). The SOCKS5 proxy auto-bypasses connections to sluice's own listener addresses (`SelfBypass` in `Config`) so the agent's MCP HTTP connection is auto-allowed without policy evaluation. Auto-injection also runs after `sluice mcp add/remove` to keep the agent's view of available tools current.

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

# -- UDP rules --

[[deny]]
destination = "*"
protocols = ["udp"]
name = "block all UDP by default"

[[allow]]
destination = "dns.google"
ports = [53]
protocols = ["udp", "dns"]
name = "allow Google DNS"

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
// internal/proxy/inject.go (simplified)
func handleRequest(req *http.Request, host string, port int, proto string) {
    // 1. Binding-specific header injection
    binding := resolver.ResolveForProtocol(host, port, proto)
    secret := vault.Get(binding.Credential)
    req.Header.Set(binding.Header, binding.FormatValue(secret.String()))
    secret.Release()

    // 2. Scoped phantom replacement (bound credentials only)
    boundCreds := resolver.CredentialsForDestination(host, port, proto)
    for _, name := range boundCreds {
        phantom := PhantomToken(name)
        secret := vault.Get(name)
        // Replace phantom with real value in headers and body
        secret.Release()
    }

    // 3. Strip unbound phantom tokens (safety net)
    // Prevents leakage without enabling cross-credential exfiltration
    stripUnboundPhantoms(headers, body)
}
```

Three-pass injection: first sets binding-specific headers, then replaces
bound phantom tokens with real values, then strips any remaining unbound
phantom tokens. Credentials are only injected into traffic destined for
their bound destinations, preventing cross-credential exfiltration.

### Protocol-specific credential injection and inspection

| Protocol | Transport | Credential injection | Content inspection |
|----------|-----------|---------------------|-------------------|
| **HTTP/HTTPS** | TCP | Built-in MITM, byte-level phantom swap | Full request/response |
| **gRPC** | TCP | Header phantom swap (detected via Content-Type: application/grpc) | Request/response metadata |
| **WebSocket (ws/wss)** | TCP | Handshake headers + text frame phantom swap | Text frame content (deny + redact rules) |
| **SSH** | TCP | Jump host, key from vault | N/A |
| **IMAP/SMTP** | TCP | AUTH command proxy, phantom password swap | N/A |
| **DNS** | UDP | N/A | Domain-level policy (NXDOMAIN for denied) |
| **QUIC/HTTP3** | UDP | HTTP/3 MITM, phantom swap via quic-go | Full HTTP/3 request/response |
| **APNS** | TCP | Connection-level allow/deny only (port 5223) | N/A |
| **Generic TCP** | TCP | Connection-level allow/deny only | None |
| **Generic UDP** | UDP | Connection-level allow/deny only (default-deny) | None |

## Docker Compose

See `compose.yml` in the repo root. Key features:
- Health checks: sluice exposes `/healthz` on `:3000`, tun2proxy checks TUN device
- Startup ordering via `condition: service_healthy`
- `restart: unless-stopped` on all services
- TCP + UDP routing: tun2proxy routes all TCP and UDP traffic through sluice's SOCKS5 proxy (UDP via SOCKS5 UDP ASSOCIATE)
- CA cert trust: openclaw mounts sluice-ca volume and sets `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`
- Phantom tokens: shared `sluice-phantoms` volume mounted read-write in sluice and read-only in openclaw at `/phantoms/`. Sluice writes phantom token files, openclaw reads them. Fallback `env_file: .env.phantom` for initial bootstrap.

## Libraries

- `github.com/things-go/go-socks5` - SOCKS5 server with UDP ASSOCIATE support (replaces armon/go-socks5)
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
- `github.com/1password/onepassword-sdk-go` - 1Password SDK for Service Account credential retrieval
- `github.com/tobischo/gokeepasslib/v3` - Pure Go KeePass .kdbx file reader/writer
- `github.com/golang-migrate/migrate/v4` - Schema migration framework with embedded SQL files
- `github.com/quic-go/quic-go` - QUIC/HTTP3 implementation for QUIC MITM proxy
- `github.com/coder/websocket` - WebSocket client for MCP WebSocket upstream transport

## Estimated Scope

| Component | Approx LOC | Notes |
|-----------|------------|-------|
| SOCKS5 proxy with policy engine | ~400 | Core connection handling |
| HTTPS MITM + credential injection | ~300 | goproxy handlers, phantom swap, CA cert gen |
| WebSocket frame inspection | ~250 | Frame parser, relay, phantom swap, content rules |
| UDP relay + DNS interception | ~300 | UDP ASSOCIATE, per-datagram policy, DNS parsing |
| QUIC/HTTP3 MITM | ~250 | quic-go TLS termination, HTTP/3 phantom swap |
| MCP gateway (stdio + HTTP) | ~500 | Tool interception, upstream management |
| Credential vault + secure memory | ~300 | age-encrypted, SecureBytes with zeroing |
| External vault providers | ~600 | HashiCorp Vault, 1Password, Bitwarden, KeePass, Gopass, env, provider interface |
| Telegram bot (approval UX) | ~250 | Inline keyboard, callback handling, shared by both layers |
| SQLite policy store + TOML import | ~400 | Runtime state persistence, seed import |
| Policy CLI (list/add/remove/import/export) | ~200 | Unified control plane |
| Content inspection (tool args + responses) | ~200 | Regex patterns for secrets/PII |
| Audit logger | ~200 | JSON lines, blake3 hash chains, chain verification CLI |
| **Total custom code** | **~3750** | Single Go binary |
| Docker setup + tun2proxy | Config only | compose.yml |

## Apple Container Support

Apple Container (macOS Virtualization.framework micro-VMs) is supported as an alternative to Docker. It gives native macOS isolation with access to Apple frameworks (EventKit, Messages, CallKit) that are unavailable in Linux containers.

### Runtime selection

The `--runtime` flag selects the container backend:

| Flag value | Description |
|-----------|-------------|
| `auto` (default) | Auto-detect: checks for `container` CLI (Apple) and Docker socket. Prefers Apple on macOS if both are available. |
| `docker` | Use Docker backend. Requires Docker socket. |
| `apple` | Use Apple Container backend. Requires macOS and `container` CLI. |
| `none` | Standalone mode. No container management. User configures `ALL_PROXY=socks5://localhost:1080` manually. |

### ContainerManager interface

Both Docker and Apple Container backends implement `container.ContainerManager` (defined in `internal/container/types.go`). Telegram commands, MCP injection, and credential management code works with any backend through this interface.

### Apple Container architecture

```
Apple Container:
  OpenClaw micro-VM (bridge100) -> pf route-to -> tun2proxy on host -> SOCKS5 -> sluice on host -> internet
```

Key differences from Docker:
- `/dev/net/tun` is not supported inside Apple Container guests. tun2proxy runs on the host.
- macOS pf rules redirect VM bridge traffic through the host TUN device.
- VM management via `container` CLI (run, exec, stop, rm, inspect, ls) wrapped by `internal/container/apple.go`.
- VirtioFS volumes (`-v` flag) for shared phantom tokens and CA certificates.

### Network routing (pf)

`NetworkRouter` in `internal/container/network.go` manages macOS pf anchor rules:

```
1. Apple Container VM gets IP on bridge100 (e.g., 192.168.64.2)
2. tun2proxy runs on host: tun2proxy --proxy socks5://127.0.0.1:1080 --tun utun3
3. pf anchor "sluice": pass in on bridge100 route-to (utun3 192.168.64.1) from 192.168.64.0/24 to any
4. All VM traffic: bridge100 -> utun3 -> tun2proxy -> SOCKS5 -> sluice -> internet
```

Setup requires root for pfctl. Use `scripts/apple-container-setup.sh` for manual setup or `NetworkRouter.SetupNetworkRouting()` for programmatic setup.

### CA cert injection (Apple Container)

`AppleManager.InjectCACert()` copies sluice's MITM CA cert to the shared volume, then tries `update-ca-certificates` (Linux guest) or `security add-trusted-cert` (macOS guest) inside the VM. Environment variables (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`) are set at VM startup as a fallback covering most HTTP libraries.

### APNS protocol detection

Port 5223 is detected as `ProtoAPNS` (Apple Push Notification Service) in `internal/proxy/protocol.go`. This enables policy rules like:

```toml
[[allow]]
destination = "*.push.apple.com"
ports = [5223]
protocols = ["apns"]
```

### Standalone mode (--runtime none)

When `--runtime none` is specified, sluice skips container manager initialization and runs as a standalone SOCKS5 proxy + MCP gateway. The user configures `ALL_PROXY=socks5://localhost:1080` in their shell. Credential injection (MITM proxy) and MCP gateway (stdio upstreams) work normally. Only container lifecycle management (hot-reload, restart) is disabled.
