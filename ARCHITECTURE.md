# Sluice

Credential-injecting approval proxy for AI agents. Two layers of governance: MCP-level (semantic tool control) and network-level (all-protocol interception). Asks for human approval via Telegram, injects credentials, and forwards.

## Problem

No existing tool combines:
1. Credential/secret isolation from the AI agent
2. Per-request human approval/deny via Telegram
3. All-protocol interception (HTTP, HTTPS, SSH, IMAP, SMTP, etc.)
4. MCP-level governance (tool names, arguments, per-action policy)
5. Audit logging of every connection and tool call

Closest existing tools only solve part of the problem:
- **nono** (phantom token proxy): credential injection only, no approval
- **Loopgate**: Telegram approval only, no credential injection
- **AgentGate**: approval via Slack/Discord/email, SDK-based (not a forward proxy)
- **OneCLI**: credential injection proxy, approval features appear aspirational
- **Bulwark** (github.com/bpolania/bulwark): HTTP proxy + MCP gateway, credential vault, content inspection, audit. No HITL approval, no non-HTTP protocols, no transparent proxying, no Telegram

## Architecture

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

## Components

| Component | Role | Implementation |
|-----------|------|----------------|
| **OpenClaw** | AI agent, no real credentials | Existing Docker image |
| **tun2proxy** | Routes ALL TCP through TUN to SOCKS5 | Existing `ghcr.io/tun2proxy/tun2proxy` |
| **Sluice SOCKS5 Proxy** | Network-level policy + HTTPS MITM + credential injection | Custom Go, single binary |
| **Sluice MCP Gateway** | Semantic tool governance (stdio + HTTP) | Custom Go, same binary |
| **Sluice Telegram Bot** | Approval UX + credential/config management | Same binary |
| **Vault** | Encrypted credential storage + phantom token mapping | age-encrypted files (default), pluggable providers |
| **Docker Socket** | Restart OpenClaw container with updated phantom env vars | Mounted from host |

## Sluice Core Logic

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

## MCP Gateway Logic

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
# Tool-level policies (MCP gateway layer)

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

```yaml
services:
  sluice:
    build: ./sluice
    environment:
      - SLUICE_TELEGRAM_BOT_TOKEN=${SLUICE_TELEGRAM_BOT_TOKEN}
      - SLUICE_TELEGRAM_CHAT_ID=${SLUICE_TELEGRAM_CHAT_ID}
      - OPENCLAW_CONTAINER_NAME=openclaw
    volumes:
      - ./policy.toml:/etc/sluice/policy.toml
      - sluice-vault:/home/sluice/.sluice
      - sluice-audit:/var/log/sluice
      - /var/run/docker.sock:/var/run/docker.sock  # manage OpenClaw container
    networks: [internal, external]
    # Exposes:
    #   - :1080  SOCKS5 proxy (internal only)
    #   - :3000  MCP gateway HTTP (internal only)

  tun2proxy:
    image: ghcr.io/tun2proxy/tun2proxy-ubuntu:latest
    cap_add: [NET_ADMIN]
    volumes: ["/dev/net/tun:/dev/net/tun"]
    command: --proxy socks5://sluice:1080
    networks: [internal]
    depends_on: [sluice]

  openclaw:
    container_name: openclaw  # fixed name so Sluice can manage it
    image: openclaw/openclaw:latest
    network_mode: "service:tun2proxy"
    environment:
      # Phantom tokens injected dynamically by Sluice via Docker socket.
      # On first run these are empty. Use Sluice Telegram bot to add creds:
      #   /cred add anthropic_api_key
      # Sluice will restart this container with phantom env vars.
      - OPENCLAW_TELEGRAM_BOT_TOKEN=${OPENCLAW_TELEGRAM_BOT_TOKEN}
    volumes:
      - openclaw-data:/root/.openclaw
      - sluice-ca:/usr/local/share/ca-certificates/sluice:ro  # trust Sluice MITM CA
    depends_on: [tun2proxy]

networks:
  internal:
    internal: true   # No direct internet access
  external: {}
```

## Tech Stack

### Go (single binary)

| Dependency | Purpose |
|------------|---------|
| `github.com/armon/go-socks5` | SOCKS5 server |
| `github.com/elazarl/goproxy` | HTTPS MITM proxy |
| `github.com/go-telegram-bot-api/telegram-bot-api/v5` | Telegram bot |
| `github.com/BurntSushi/toml` | Policy file parsing |
| `filippo.io/age` | Vault encryption (default provider) |
| `github.com/hashicorp/vault/api` | HashiCorp Vault provider (optional) |
| Standard library | Logging, HTTP, net, crypto/tls, crypto/x509 |

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
| Audit logger | ~150 | JSON lines, hash chains |
| **Total custom code** | **~2450** | Single Go binary |
| Docker setup + tun2proxy | Config only | docker-compose.yml |

## Research Sources

### Confirmed: No existing tool combines all requirements (updated 2026-04-01)

**nono** (github.com/lukehinds/nono) - Kernel-enforced sandbox + phantom tokens
- Kernel-level isolation (not just containers), capability-based security
- Phantom token credential injection proxy (same pattern as Sluice)
- Snapshot/rollback, cryptographic immutable audit chain
- Apache 2.0, Luke Hinds (ex-Red Hat security)
- Missing: Telegram approval, SOCKS5/all-protocol, MCP gateway
- Steal: audit chain design (blake3 hash chains), kernel isolation ideas

**OneCLI** (github.com/onecli/onecli) - Rust credential vault + HTTP gateway
- Phantom token swap via MITM HTTPS proxy (closest to Sluice's mitmproxy approach)
- AES-256-GCM encrypted vault, host/path pattern matching
- Multi-agent scoped permissions, web dashboard
- Bitwarden Agent Access SDK integration (alpha)
- 600+ stars, active development
- Missing: Telegram approval, SOCKS5/all-protocol, MCP gateway
- Steal: Bitwarden integration pattern, host/path matching rules, Rust MITM implementation

**Bulwark** (github.com/bpolania/bulwark) - MCP gateway + HTTP proxy governance
- Rust. Works as MCP gateway OR HTTP forward proxy (dual mode like Sluice)
- Credential injection at last mile, content inspection (secrets/PII/prompt injection)
- Tamper-evident audit (blake3 hash chains), rate limiting, YAML policy engine
- Missing: HITL approval, SOCKS5/non-HTTP, transparent proxying, Telegram
- Steal: content inspection patterns, YAML policy engine design, rate limiting

**Loopgate** (github.com/iris-networks/loopgate) - HITL approval broker
- Central broker for human-in-the-loop workflows via Telegram
- MCP + HTTP + WebSocket client support, multi-language SDKs
- Missing: credential injection, network interception, SOCKS5
- Steal: Telegram inline keyboard approval UX, MCP client integration pattern

**AgentGate** (github.com/agentkitai/agentgate) - Policy engine + multi-channel approval
- Auto-approve/deny/route-to-human policy engine
- Slack, Discord, email, web dashboard approval surfaces
- TypeScript SDK + MCP integration, webhook retry, full audit trail
- Part of AgentKit ecosystem (AgentLens for observability)
- Missing: forward proxy, credential injection, non-HTTP protocols
- Steal: policy engine design, multi-channel approval routing

**Agentgateway** (github.com/agentgateway/agentgateway) - Linux Foundation MCP/A2A proxy
- Rust. RBAC, JWT auth, TLS, CEL-based access policies
- MCP + A2A protocol support, REST-to-MCP auto-exposure
- Enterprise-focused, Linux Foundation backed
- Missing: HITL approval, credential injection, SOCKS5
- Steal: CEL-based policy expressions, A2A protocol support

### What Sluice uniquely provides (gap analysis)

No existing tool combines:
1. All-protocol interception via SOCKS5 + tun2proxy (SSH, IMAP, SMTP, not just HTTP)
2. Two-layer governance (MCP semantic + network level)
3. Telegram as single approval surface for both layers
4. Phantom token credential injection across all protocols
5. Transparent proxying (agent needs zero configuration)

Composing OneCLI + Bulwark + Loopgate would cover ~80% but with messy
integration and no all-protocol coverage.

### Key technical findings
- OpenClaw supports SOCKS5 via ALL_PROXY env var
- SOCKS5 sees destination:port before connecting (can approve/deny any TCP)
- tun2proxy transparently routes all container TCP through SOCKS5 (no app changes)
- mitmproxy in SOCKS5 mode can inspect HTTPS content with CA cert injection
- Node.js 22.21+ supports HTTP_PROXY via NODE_USE_ENV_PROXY=1
- simple-socks (Node.js) has connectionFilter API for per-connection decisions
- Docker `network_mode: "service:"` shares network namespace (enables transparent proxying)
- Docker `internal: true` network blocks direct internet access

### Community sentiment (HN discussions)
- "Human-in-the-loop doesn't scale at agent speed" (valid concern, mitigated by allowlists)
- "Capability-based authz: task-scoped permissions, cryptographically enforced" (similar concept)
- "Each tool sandboxed in its own container, the LLM can call but not edit the code"
- NanoClaw container isolation praised but "sandbox alone doesn't solve the lethal trifecta"
- Meta employee had entire inbox deleted by OpenClaw
- 21,639 exposed OpenClaw instances found leaking API keys

---

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
