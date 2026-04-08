# :shield: Sluice — Credential Governance Proxy for OpenClaw

[![Tests](https://github.com/nnemirovsky/sluice/actions/workflows/test.yml/badge.svg)](https://github.com/nnemirovsky/sluice/actions/workflows/test.yml)
[![E2E](https://github.com/nnemirovsky/sluice/actions/workflows/e2e-linux.yml/badge.svg)](https://github.com/nnemirovsky/sluice/actions/workflows/e2e-linux.yml)
[![Lint](https://github.com/nnemirovsky/sluice/actions/workflows/lint.yml/badge.svg)](https://github.com/nnemirovsky/sluice/actions/workflows/lint.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/nnemirovsky/sluice)](https://goreportcard.com/report/github.com/nnemirovsky/sluice)
[![Release](https://img.shields.io/github/v/release/nnemirovsky/sluice)](https://github.com/nnemirovsky/sluice/releases/latest)

Keeps real secrets out of the agent, enforces per-request policy on every connection and tool call, and puts a human in the loop when it matters.

## Why Sluice

AI agents need credentials to be useful. Giving them real credentials is dangerous.

**The problem:** OpenClaw makes API calls, opens network connections, and invokes MCP tools. Without governance, it can leak secrets in tool outputs, connect to unexpected endpoints, or make destructive API calls. No existing tool combines credential isolation, human approval, all-protocol interception, and MCP-level governance in one place.

**The solution:** Sluice intercepts everything at two layers and never gives OpenClaw real credentials.

| Layer | What it sees | What it governs |
|-------|-------------|-----------------|
| **MCP Gateway** | Tool names, arguments, responses | File writes, exec, deletions, any MCP tool call |
| **SOCKS5 Proxy** | Every TCP and UDP connection | HTTP, HTTPS, WebSocket, gRPC, SSH, IMAP, SMTP, DNS, QUIC/HTTP3 |

**Phantom token swap:** OpenClaw gets phantom tokens that look like real API keys, injected as environment variables via `docker exec` (no shared volume needed). Sluice's MITM proxy swaps them for real credentials in-flight. If a phantom token leaks, it is useless outside the proxy. OAuth credentials are handled bidirectionally: sluice intercepts token endpoint responses, captures real tokens, and returns phantom tokens to the agent. The entire OAuth lifecycle (initial auth, token refresh, token rotation) is transparent.

**Human approval:** Connections and tool calls matching "ask" policy rules trigger a notification via Telegram or HTTP webhook. OpenClaw blocks until a human responds with Allow or Deny.

**Credential isolation:** Real secrets live in an encrypted vault (age, HashiCorp Vault, 1Password, Bitwarden, KeePass, or gopass). They are decrypted into zeroed memory only at injection time and never exposed to the agent process.

## How It Works

```mermaid
flowchart LR
    subgraph Isolated["OpenClaw (isolated)"]
        OC[OpenClaw<br/>phantom tokens]
    end

    subgraph Sluice
        GW[MCP Gateway<br/>tool policy + inspection]
        PX[SOCKS5 Proxy<br/>network policy + MITM]
    end

    subgraph Approval["Approval Channels"]
        TG[Telegram<br/>primary]
        WH[HTTP Webhooks]
    end

    HM[Human]
    UP[Upstream<br/>MCP Servers]
    IN[Internet]

    OC -- "MCP tool calls" --> GW
    OC -- "all TCP/UDP<br/>(via tun2proxy)" --> PX
    GW -- "allowed" --> UP
    GW -. "ask verdict" .-> Approval
    PX -- "phantom -> real<br/>credential swap" --> IN
    PX -. "ask verdict" .-> Approval
    Approval -. "allow / deny" .-> HM
    HM -. "respond" .-> Approval
    Approval -. "resolve" .-> Sluice
```

**Traffic flow:** OpenClaw runs in an isolated container (Docker, Apple Container, or macOS VM). All network traffic is routed through tun2proxy to sluice's SOCKS5 proxy. MCP tool calls go through the MCP gateway. Both layers evaluate every request against policy rules.

**Policy verdicts:** Each rule resolves to allow, deny, or ask. "Ask" verdicts are broadcast to all configured approval channels. The first channel to respond wins. Credentials are managed via Telegram commands or CLI, stored encrypted, and hot-reloaded into OpenClaw via env var injection without restarts.

**Audit trail:** Every connection, tool call, approval, and denial is logged with blake3 hash chaining for tamper detection.

## Quick Start

### Docker (Linux)

The recommended setup for Linux. Three containers share a network namespace: sluice (proxy), tun2proxy (routes all traffic through SOCKS5), and OpenClaw.

```bash
# 1. Clone and configure
git clone https://github.com/nnemirovsky/sluice.git && cd sluice
cp examples/config.toml config.toml  # edit policy rules

# 2. Set Telegram credentials in compose.yml (environment section of sluice service)
#    TELEGRAM_BOT_TOKEN: "your-bot-token"
#    TELEGRAM_CHAT_ID: "your-chat-id"

# 3. Start (sluice + tun2proxy + openclaw)
docker compose up -d

# 4. Add API credentials (phantom tokens auto-generated, injected as env vars to OpenClaw)
docker exec sluice sluice cred add anthropic_api_key \
  --destination api.anthropic.com --ports 443 \
  --header x-api-key \
  --env-var ANTHROPIC_API_KEY
```

### Apple Container (macOS)

Native macOS micro-VMs via Virtualization.framework. Lightweight isolation with sub-second boot. Runs Linux guests. OpenClaw runs inside the micro-VM with all traffic routed through sluice.

```bash
# 1. Download sluice binary (see Releases page for latest version)
curl -L -o sluice https://github.com/nnemirovsky/sluice/releases/latest/download/sluice_darwin_arm64
chmod +x sluice

# 2. Generate CA certificate for HTTPS interception
./sluice cert generate

# 3. Seed policy and add credentials
./sluice policy import examples/config.toml
./sluice cred add anthropic_api_key \
  --destination api.anthropic.com --ports 443 --header x-api-key \
  --env-var ANTHROPIC_API_KEY

# 4. Start sluice with Apple Container runtime
./sluice --runtime apple --container-name openclaw

# 5. Network routing (requires root for pf rules)
sudo ./scripts/apple-container-setup.sh

# 6. Start OpenClaw in Apple Container
container run --name openclaw \
  -e SSL_CERT_FILE=/certs/sluice-ca.crt \
  -e REQUESTS_CA_BUNDLE=/certs/sluice-ca.crt \
  -e NODE_EXTRA_CA_CERTS=/certs/sluice-ca.crt \
  -v ~/.sluice/ca:/certs:ro \
  ghcr.io/openclaw/openclaw:latest
```

### macOS VM (via tart)

Full macOS guest VM with access to Apple frameworks (iMessage, EventKit, Keychain, Shortcuts). Use this when OpenClaw needs to interact with Apple ecosystem services that are unavailable in Linux containers. Sluice manages the VM lifecycle and routes all traffic through the proxy.

```bash
# 1. Install tart and download sluice binary
brew install cirruslabs/cli/tart
curl -L -o sluice https://github.com/nnemirovsky/sluice/releases/latest/download/sluice_darwin_arm64
chmod +x sluice

# 2. Start sluice with macOS VM runtime (clones and boots the VM)
./sluice --runtime macos \
  --vm-image ghcr.io/cirruslabs/macos-sequoia-base:latest \
  --container-name openclaw \
  --config examples/config.toml

# 3. Host network routing (requires root for pf rules)
sudo ./scripts/macos-vm-setup.sh
```

Requires macOS with Apple Silicon (M1+). The macOS EULA allows up to 2 additional macOS VMs per Apple-branded host.

### Standalone (binary)

Download a pre-built binary from [Releases](https://github.com/nnemirovsky/sluice/releases) and run sluice as a standalone proxy. No container runtime needed. Point OpenClaw at sluice manually.

Available binaries: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`.

```bash
# Download (replace OS_ARCH: linux_amd64, linux_arm64, darwin_amd64, darwin_arm64)
curl -L -o sluice https://github.com/nnemirovsky/sluice/releases/latest/download/sluice_OS_ARCH
chmod +x sluice

# Run standalone
./sluice --runtime none --listen 127.0.0.1:1080 --config examples/config.toml

# Point OpenClaw at the proxy
ALL_PROXY=socks5://localhost:1080 openclaw
```

Credential injection (MITM) and MCP gateway work normally. Only container lifecycle management (hot-reload, restart) is disabled.

## Policy

All policy is stored in SQLite and persists across restarts. Seed from TOML on first run, then manage via CLI or Telegram.

```toml
[policy]
default = "deny"

# Network rules
[[allow]]
destination = "api.anthropic.com"
protocols = ["http", "https"]

[[allow]]
destination = "*.github.com"   # matches the domain being queried, not the resolver
protocols = ["dns"]

[[ask]]
destination = "*.openai.com"
ports = [443]

[[deny]]
destination = "169.254.169.254"   # block cloud metadata

[[deny]]
destination = "*"
protocols = ["udp"]
name = "block all UDP by default"

# MCP tool rules
[[allow]]
tool = "github__list_*"

[[deny]]
tool = "exec__*"

# Content inspection
[[deny]]
pattern = "(?i)(sk-[a-zA-Z0-9_-]{20,})"
name = "block API keys in tool arguments"

[[redact]]
pattern = "(?i)(sk-[a-zA-Z0-9_-]{20,})"
replacement = "[REDACTED]"
name = "redact API keys in responses"
```

Glob patterns: `*` matches within a single DNS label. `**` matches across dots. Evaluation order: deny, allow, ask, default.

## Credential Providers

Sluice supports multiple credential backends. Set `provider` in `[vault]` config:

| Provider | Auth | Notes |
|----------|------|-------|
| `age` (default) | Auto-generated X25519 key | Local encrypted files, no dependencies |
| `env` | Environment variables | Credential name maps to env var |
| `hashicorp` | Token or AppRole | HashiCorp Vault KV v2 |
| `1password` | Service Account token | Via official Go SDK |
| `bitwarden` | Access token | Via `bws` CLI |
| `keepass` | Password + optional key file | Local .kdbx files, auto-reloads on change |
| `gopass` | CLI auth | Via `gopass` binary |

Chain multiple providers with `providers = ["1password", "age"]`. First provider with the credential wins.

## OAuth Token Management

Sluice handles OAuth access and refresh tokens transparently through the phantom swap system. The agent never sees real tokens at any point in the OAuth lifecycle.

**Adding OAuth credentials:**

```bash
# Tokens are read from stdin (not CLI flags) to avoid shell history exposure
sluice cred add openai_oauth \
  --type oauth \
  --token-url https://auth0.openai.com/oauth/token \
  --destination api.openai.com \
  --ports 443 \
  --env-var OPENAI_API_KEY
# Prompts for: access token, refresh token (optional)
```

**Listing credentials shows the type:**

```
$ sluice cred list
NAME             TYPE    DESTINATION
openai_oauth     oauth   api.openai.com
github_pat       static  api.github.com
```

**How it works:**

1. Sluice stores real tokens in the vault and generates deterministic phantom tokens
2. The agent receives phantom tokens and uses them normally with any SDK
3. On outbound requests, sluice swaps phantom tokens for real tokens (same as static credentials)
4. On token endpoint responses, sluice intercepts the response, captures new real tokens, and replaces them with phantoms before the response reaches the agent
5. The vault is updated asynchronously. If the write fails, the agent still sees only phantom tokens

**Token refresh and rotation:** When an access token expires and the agent (or SDK) sends a refresh request, sluice swaps the phantom refresh token for the real one, forwards the request, intercepts the response with new tokens, and returns phantoms. Concurrent refresh requests are deduplicated so only one vault update occurs per credential.

**Supported response formats:** Both `application/json` and `application/x-www-form-urlencoded` token responses per RFC 6749.

## Approval Channels

Sluice broadcasts "ask" verdicts to all configured approval channels. The first channel to respond wins. Other channels get a cancellation notice.

### Telegram (primary)

Manage sluice from your phone. Approve connections and tool calls, add credentials, update policy.

| Command | Description |
|---------|-------------|
| `/policy show` | List current rules |
| `/policy allow <dest>` | Add allow rule |
| `/policy deny <dest>` | Add deny rule |
| `/cred add <name> [--env-var VAR]` | Add credential (value sent as next message, auto-deleted) |
| `/cred rotate <name>` | Replace credential, hot-reload OpenClaw |
| `/status` | Proxy stats and pending approvals |
| `/audit recent [N]` | Last N audit entries |

### HTTP Webhooks

REST API on port 3000 for programmatic approval integration. `GET /api/approvals` lists pending requests, `POST /api/approvals/{id}/resolve` resolves them. Use this to build custom approval UIs or integrate with existing workflows.

Credential management endpoints support both static and OAuth types:

```bash
# Add static credential with env var injection
curl -X POST http://localhost:3000/api/credentials \
  -d '{"name":"github_pat","value":"ghp_xxx","destination":"api.github.com","env_var":"GITHUB_TOKEN"}'

# Add OAuth credential with env var injection
curl -X POST http://localhost:3000/api/credentials \
  -d '{"name":"openai_oauth","type":"oauth","token_url":"https://auth.example.com/token","access_token":"at-xxx","refresh_token":"rt-xxx","destination":"api.openai.com","env_var":"OPENAI_API_KEY"}'
```

## Audit Log

Tamper-evident JSON Lines log with blake3 hash chaining. Every connection, tool call, approval, and denial is recorded.

```bash
sluice audit verify   # check hash chain integrity
```

## Protocol Support

| Protocol | Credential Injection | Content Inspection |
|----------|---------------------|--------------------|
| HTTP/HTTPS | MITM phantom swap | Full request/response |
| gRPC | Header phantom swap | Metadata |
| WebSocket | Handshake + text frames | Text frame content |
| SSH | Jump host, key from vault | -- |
| IMAP/SMTP | AUTH command proxy | -- |
| DNS | -- | Deny-only (NXDOMAIN for denied domains). See note below. |
| QUIC/HTTP3 | HTTP/3 MITM | Full request/response |

**DNS policy design**: The DNS interceptor only blocks explicitly denied domains (returns NXDOMAIN). All other verdicts (allow, ask, default) are forwarded to the upstream resolver. This is intentional. Policy enforcement for "ask" destinations happens at the SOCKS5 CONNECT layer, not DNS. Blocking DNS for "ask" destinations would prevent the TCP connection from ever reaching the approval flow. The DNS interceptor populates a reverse cache (IP -> hostname) so the SOCKS5 handler can recover hostnames from IP-only CONNECT requests sent by tun2proxy. For TLS connections, SNI from the ClientHello provides an additional hostname recovery path.

## Requirements

| Runtime | Requirements |
|---------|-------------|
| Docker | Docker Engine |
| Apple Container | macOS, `container` CLI |
| macOS VM | macOS, Apple Silicon, `tart` CLI |
| All | Telegram bot token (optional, for approval flow) |

## Upgrading

**From phantom volume to env var injection:** Sluice no longer uses a shared `sluice-phantoms` volume. Credentials are injected as environment variables via `docker exec` instead. After upgrading: remove the orphaned `sluice-phantoms` volume (`docker volume rm sluice-phantoms`), recreate containers so env vars are injected fresh on startup. No credential data is lost. Vault and database contents are unchanged.

## Troubleshooting

**OpenClaw has no network access:** Check pf rules are loaded (`sudo pfctl -a sluice -sr`). Verify tun2proxy is running and sluice is listening on the SOCKS5 port.

**HTTPS certificate errors inside the container/VM:** Verify the CA cert is mounted and `SSL_CERT_FILE` points to it. Regenerate with `sluice cert generate` if needed.

**`container` CLI not found:** Install Apple Container runtime. The `container` binary must be in PATH.

**`tart` CLI not found:** Install via `brew install cirruslabs/cli/tart`.

**Permission denied on pfctl:** pf rules require root. Use the setup scripts with sudo.

## License

See [LICENSE](LICENSE).
