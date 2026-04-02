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
- `cmd/sluice/cred.go` - CLI subcommand handler for credential management (add/list/remove)
- `cmd/sluice/audit.go` - CLI subcommand handler for audit log verification (`audit verify`)
- `cmd/sluice/cert.go` - CLI subcommand handler for CA certificate generation (`cert generate`)
- `cmd/sluice/mcp.go` - CLI subcommand handler for MCP gateway mode
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
- `internal/vault/provider_hashicorp.go` - HashiCorp Vault provider with KV v2 support and AppRole auth
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
- `Dockerfile` - Multi-stage build for Sluice container
- `compose.yml` - Three-container setup (sluice + tun2proxy + openclaw)
- `scripts/docker-entrypoint.sh` - Container entrypoint with CA cert generation and copy to shared volume
- `scripts/setup-vault.sh` - Interactive credential and CA setup script
- `scripts/gen-phantom-env.sh` - Phantom token env file generator for openclaw container
- `examples/policy.toml` - Example policy for OpenClaw deployment with bindings and MCP tool rules
- `testdata/` - TOML policy fixtures for tests

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

### MCP Tool Policy (extends the main policy file)

```toml
[[tool_allow]]
tool = "github__list_*"
note = "Read-only GitHub operations"

[[tool_allow]]
tool = "filesystem__read_file"
note = "File reads are safe"

[[tool_ask]]
tool = "github__create_*"
tool = "github__delete_*"
note = "Write operations need approval"

[[tool_ask]]
tool = "filesystem__write_file"
note = "File writes need approval"

[[tool_deny]]
tool = "exec__*"
note = "Block all exec by default"
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

## Implementation Details

Policy engine: `LoadFromFile`/`LoadFromBytes` parses TOML and auto-compiles glob patterns into regexes. `Evaluate(dest, port)` checks deny rules first, then allow, then ask, falling back to default verdict.

Proxy integration: `policyRuleSet` implements the `socks5.RuleSet` interface. Protocol detection stores results in context for future credential injection.

Telegram approval: `ApprovalBroker` bridges the proxy and Telegram bot via channels. When `policyRuleSet.Allow()` encounters an Ask verdict, it calls `broker.Request()` which blocks until the bot resolves the request or the timeout expires. The bot goroutine reads from `broker.Pending()`, sends an inline keyboard to Telegram, and calls `broker.Resolve()` when the user responds. "Always Allow" calls `Engine.AddDynamicAllow()` to add a runtime allow rule (not persisted to disk). The Engine uses a `sync.RWMutex` to protect concurrent reads (policy evaluation) and writes (dynamic rule addition, command handler mutations). `CouldBeAllowed(dest, includeAsk)` takes an `includeAsk` parameter: when true (broker configured), Ask-matching destinations are resolved via DNS so the approval flow can proceed; when false (no broker), Ask rules are treated as Deny at the DNS stage to prevent leaking queries. Rate limiting prevents approval queue flooding: `MaxPendingRequests` (default 50) caps concurrent pending approvals, and per-destination rate limits (5 requests/minute) prevent a single target from monopolizing the queue. Requests exceeding limits are auto-denied.

Telegram commands: `CommandHandler` holds an `atomic.Pointer[policy.Engine]` for lock-free reads and is updated via `UpdateEngine()` on SIGHUP. Policy mutations (`/policy allow`, `/policy deny`, `/policy remove`) use `Engine.AddAllowRule()`, `AddDenyRule()`, and `RemoveRule()` which acquire write locks internally. Mutations are in-memory only and not persisted to disk.

Audit logger is optional. Pass nil in `Config.Audit` and the proxy handles it gracefully. Each JSON line includes a `prev_hash` field containing the blake3 hash of the previous line's raw JSON bytes. The first entry uses blake3("") as the genesis hash. On startup, `NewFileLogger` reads the last line from the existing file (seeking backwards from EOF) to recover the hash chain across restarts. `VerifyChain` walks the log and reports any broken links. The `sluice audit verify` CLI command wraps this for tamper detection.

Credential vault: `Store` manages age-encrypted files in `~/.sluice/credentials/` with an auto-generated X25519 identity. `SecureBytes` wraps decrypted values and zeroes memory on `Release()` (best-effort in Go due to GC and string copies). `Provider` interface abstracts credential sources (age files, env vars, HashiCorp Vault). `NewProviderFromConfig` reads `[vault]` from TOML config. `HashiCorpProvider` connects to HashiCorp Vault's KV v2 secrets engine, supporting both token and AppRole authentication. Config fields (`addr`, `token`, `mount`, `prefix`, `role_id`, `secret_id`) are set under `[vault.hashicorp]` in the TOML config. `role_id` and `secret_id` support env var indirection via `role_id_env` and `secret_id_env`. For `addr` and `token`, the Vault SDK reads `VAULT_ADDR` and `VAULT_TOKEN` automatically when not set.

Binding resolution: `BindingResolver` compiles destination glob patterns (reusing `policy.CompileGlob`) and resolves `(host, port)` to a `Binding`. Bindings specify the credential name, injection header, template (`Bearer {value}`), and protocol override.

HTTPS credential injection: `Injector` wraps `goproxy` as an in-process MITM proxy. `LoadOrCreateCA` generates a self-signed ECDSA P-256 CA persisted to disk. Per-host certificates are generated at interception time. Only hosts with credential bindings are MITMed. Phantom tokens (`SLUICE_PHANTOM:<name>`) in headers and request bodies are replaced with real credential values. `SecureBytes.Release()` zeroes credentials immediately after injection.

SSH credential injection: `SSHJumpHost` accepts the agent's SSH connection with no authentication (`NoClientAuth`), decrypts the SSH private key from the vault, authenticates to the upstream server, and relays SSH channels/requests bidirectionally. `Binding.Template` holds the SSH username (defaults to "root").

Mail credential injection: `MailProxy` intercepts IMAP LOGIN and SMTP AUTH PLAIN/LOGIN commands. For base64-encoded auth data, it decodes, replaces phantom tokens, and re-encodes. Non-auth traffic is relayed unchanged.

Docker integration: Three-container architecture (sluice + tun2proxy + openclaw) with `network_mode: "service:tun2proxy"` routing all openclaw traffic through sluice's SOCKS5 proxy. `docker.Manager` wraps a `ContainerClient` interface (production implementation pending, SDK added at deployment time). On credential mutation via Telegram `/cred` commands, `credMutationComplete` regenerates phantom environment variables using `GeneratePhantomEnv` (produces SDK-format-matching phantom tokens based on credential name heuristics) and calls `Manager.RestartWithEnv` to recreate the agent container with updated env. `BotConfig.Vault` and `BotConfig.DockerMgr` wire the vault and Docker manager into Telegram command handling. The sluice entrypoint generates a CA cert and copies it to a shared volume so openclaw can trust HTTPS MITM certificates via `SSL_CERT_FILE`.

Health check: A minimal HTTP server on `:3000` (configurable via `--health-addr`) serves `/healthz`, returning 200 when the SOCKS5 proxy is listening. The Dockerfile includes a `HEALTHCHECK` directive using `wget` against this endpoint. compose.yml uses `service_healthy` conditions to sequence startup: tun2proxy waits for sluice, openclaw waits for tun2proxy.

Graceful shutdown: On SIGINT/SIGTERM, the proxy stops accepting new connections and drains in-flight connections up to `--shutdown-timeout` (default 10s). Pending Telegram approval requests are auto-denied with a "shutting down" reason. The audit logger is closed after all connections drain.

MCP gateway: `Gateway` spawns upstream MCP servers as child processes via `StartUpstream`, performs `initialize` handshake and `notifications/initialized`, discovers tools via `tools/list`, and namespaces them with `<upstream>__<tool>`. The agent connects via stdio (`RunStdio`). On `tools/call`, the gateway evaluates `ToolPolicy` (deny/allow/ask priority, same as network policy), optionally requests Telegram approval via the shared `ApprovalBroker`, runs `ContentInspector.InspectArguments` to block arguments matching regex patterns (JSON is parsed before matching to prevent unicode escape bypass), strips the namespace prefix, forwards to the upstream, runs `ContentInspector.RedactResponse` on the result, and adds governance metadata. `ToolPolicy` reuses `policy.CompileGlob` for glob matching. The `mcp` subcommand reads `[[mcp_upstream]]`, `[[tool_allow]]`, `[[tool_deny]]`, `[[tool_ask]]`, `[[inspect_block]]`, and `[[inspect_redact]]` sections from the same TOML policy file. Per-upstream timeouts are configurable via `timeout_sec` in `[[mcp_upstream]]` sections (default 120s). `GatewayConfig.TimeoutSec` sets a global default that individual upstreams can override.

## Policy File

```toml
[policy]
default = "ask"     # ask | deny | allow
timeout_sec = 120   # seconds to wait for Telegram approval

[telegram]
bot_token_env = "TELEGRAM_BOT_TOKEN"
chat_id_env = "TELEGRAM_CHAT_ID"

# -- Allowlist --

[[allow]]
destination = "api.anthropic.com"
ports = [443]
inject_header = "x-api-key"
credential = "anthropic_api_key"

[[allow]]
destination = "api.openai.com"
ports = [443]
inject_header = "Authorization"
credential = "openai_api_key"
template = "Bearer {value}"

[[allow]]
destination = "api.github.com"
ports = [443]
inject_header = "Authorization"
credential = "github_token"
template = "Bearer {value}"

[[allow]]
destination = "*.telegram.org"
ports = [443]
note = "Telegram bot API passthrough"

[[allow]]
destination = "github.com"
ports = [22]
protocol = "ssh"
credential = "github_ssh_key"
note = "Git SSH access"

# -- Denylist --

[[deny]]
destination = "169.254.169.254"
note = "Block cloud metadata endpoint"

[[deny]]
destination = "100.100.100.200"
note = "Block Alibaba metadata"

[[deny]]
destination = "*.crypto-mining.example"
```

## Credential Injection: Phantom Token Swap

Sluice does NOT need to know API auth schemes (which header, which format).
Instead, it uses 1:1 phantom token mapping with byte-level find-and-replace.

### How it works

1. User adds a credential via Sluice Telegram bot (`/cred add anthropic_api_key`)
2. User sends the real key in Telegram (Sluice deletes the message after reading)
3. Sluice encrypts and stores the real credential in the vault
4. Sluice generates a phantom token (random string matching the key format)
5. Sluice restarts the OpenClaw container via Docker socket with updated env vars
6. OpenClaw uses phantom tokens normally via SDKs (thinks they're real)
7. SDKs put them in the correct headers/body (they know how)
8. Sluice's built-in HTTPS MITM intercepts the request and does byte-level
   find-and-replace: phantom -> real. Credential is decrypted into zeroized
   memory and cleared immediately after injection.
9. Sluice never needs to know the API's auth format

### Docker socket for dynamic credential injection

Sluice manages the OpenClaw container's environment via Docker socket.
When credentials change, Sluice recreates the container with updated env
vars. No manual `.env` files, no restarts by hand.

```
User adds cred via Telegram
    |
    v
Sluice vault (stores real + generates phantom)
    |
    v
Docker socket --> recreate OpenClaw container with new phantom env vars
    |
    v
OpenClaw starts with updated phantom tokens
```

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
/cred rotate <name>        Replace credential, regenerate phantom, restart agent
/cred remove <name>        Remove credential, restart agent

/policy show               Show current policy rules
/policy allow <dest>       Add allow rule, hot-reload
/policy deny <dest>        Add deny rule, hot-reload

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
    for _, b := range bindings {
        // Decrypt real credential into zeroized memory
        real := vault.Get(b.Name) // returns SecureBytes

        // Replace in ALL headers
        for key, values := range req.Header {
            for i, v := range values {
                if strings.Contains(v, b.Phantom) {
                    req.Header[key][i] = strings.Replace(v, b.Phantom, real.String(), 1)
                }
            }
        }
        // Replace in request body
        if req.Body != nil {
            body, _ := io.ReadAll(req.Body)
            if bytes.Contains(body, []byte(b.Phantom)) {
                body = bytes.Replace(body, []byte(b.Phantom), real.Bytes(), 1)
            }
            req.Body = io.NopCloser(bytes.NewReader(body))
        }

        real.Release() // zero credential memory immediately
    }
}
```

No API knowledge. No header guessing. Just string replacement with
zeroized memory.

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
- Phantom tokens via `env_file: .env.phantom` (generated by `scripts/gen-phantom-env.sh`)

## Libraries

- `github.com/armon/go-socks5` - SOCKS5 server
- `github.com/BurntSushi/toml` - Policy file parsing
- `golang.org/x/net/proxy` - SOCKS5 client (tests only)
- `github.com/go-telegram-bot-api/telegram-bot-api/v5` - Telegram Bot API client
- `filippo.io/age` - Age encryption for credential vault
- `github.com/elazarl/goproxy` - In-process HTTPS MITM proxy for credential injection
- `golang.org/x/crypto/ssh` - SSH client/server for jump host credential injection
- `golang.org/x/term` - Terminal password input for `sluice cred add`
- `lukechampine.com/blake3` - Blake3 hashing for tamper-evident audit chain
- `github.com/hashicorp/vault/api` - HashiCorp Vault client for external secret management (KV v2, AppRole auth)

## Estimated Scope

| Component | Approx LOC | Notes |
|-----------|------------|-------|
| SOCKS5 proxy with policy engine | ~400 | Core connection handling |
| HTTPS MITM + credential injection | ~300 | goproxy handlers, phantom swap, CA cert gen |
| MCP gateway (stdio + HTTP) | ~500 | Tool interception, upstream management |
| Credential vault + secure memory | ~300 | age-encrypted, SecureBytes with zeroing |
| External vault providers | ~200 | HashiCorp Vault, env, provider interface |
| Telegram bot (approval UX) | ~250 | Inline keyboard, callback handling, shared by both layers |
| Policy file parser (TOML) | ~150 | Network rules + tool rules |
| Content inspection (tool args + responses) | ~200 | Regex patterns for secrets/PII |
| Audit logger | ~200 | JSON lines, blake3 hash chains, chain verification CLI |
| **Total custom code** | **~2450** | Single Go binary |
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
