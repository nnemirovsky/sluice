# Sluice

Governance and credential injection proxy for [OpenClaw](https://github.com/nnemirovsky/openclaw). Sluice sits between OpenClaw and the internet, ensuring every outbound connection and MCP tool call is governed by policy, approved by a human when needed, and never exposes real credentials to the agent.

## Why Sluice

OpenClaw needs API keys, database credentials, and service tokens to do useful work. Giving it real credentials is risky. It can leak secrets in tool outputs, exfiltrate data to unexpected endpoints, or make destructive API calls without oversight.

Sluice solves this with two layers of governance:

- **MCP Gateway** -- intercepts tool calls between OpenClaw and MCP servers. Sees tool names, arguments, and responses. Blocks dangerous operations (file writes, exec, deletions) and redacts secrets from responses. Governs local tools that never touch the network.
- **SOCKS5 Proxy** -- intercepts every TCP and UDP connection from OpenClaw's container. Supports HTTP, HTTPS, WebSocket, gRPC, SSH, IMAP, SMTP, DNS, and QUIC/HTTP3. Injects real credentials at the network level via MITM so OpenClaw never sees them.

OpenClaw gets phantom tokens (random strings that look like real API keys). Sluice swaps them for real credentials in-flight. If OpenClaw leaks a phantom token, it's useless outside the proxy.

## How It Works

```
Container (Docker / Apple Container / macOS VM):
  OpenClaw                   -- uses phantom tokens, thinks they're real
  tun2proxy                  -- routes all traffic to SOCKS5

Host:
  Sluice SOCKS5 Proxy       -- policy + MITM + credential injection
  Sluice MCP Gateway        -- tool-level policy + argument inspection
  Telegram Bot              -- human approval for "ask" verdicts
```

Every connection is evaluated against policy rules (allow / deny / ask). "Ask" verdicts send a Telegram notification with inline buttons. OpenClaw blocks until the human responds. Credentials are managed via Telegram commands or CLI, stored encrypted with age, and hot-reloaded into OpenClaw without restarts.

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

# 4. Add API credentials (phantom tokens auto-generated, hot-reloaded to OpenClaw)
docker exec sluice sluice cred add anthropic_api_key \
  --destination api.anthropic.com --ports 443 \
  --header x-api-key
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
  --destination api.anthropic.com --ports 443 --header x-api-key

# 4. Start sluice with Apple Container runtime
./sluice --runtime apple --container-name openclaw \
  --phantom-dir ~/.sluice/phantoms

# 5. Network routing (requires root for pf rules)
sudo ./scripts/apple-container-setup.sh

# 6. Start OpenClaw in Apple Container
container run --name openclaw \
  -e SSL_CERT_FILE=/certs/sluice-ca.crt \
  -e REQUESTS_CA_BUNDLE=/certs/sluice-ca.crt \
  -e NODE_EXTRA_CA_CERTS=/certs/sluice-ca.crt \
  -v ~/.sluice/ca:/certs:ro \
  -v ~/.sluice/phantoms:/phantoms:ro \
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
  --phantom-dir /tmp/sluice-phantoms \
  --config examples/config.toml

# 3. Host network routing (requires root for pf rules)
sudo ./scripts/macos-vm-setup.sh
```

Requires macOS with Apple Silicon (M1+). The macOS EULA allows up to 2 additional macOS VMs per Apple-branded host.

### Standalone (binary)

Download a pre-built binary from [Releases](https://github.com/nnemirovsky/sluice/releases) and run sluice as a standalone proxy. No container runtime needed. Point OpenClaw at sluice manually.

Available binaries: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`.

```bash
# Download (replace VERSION and OS/ARCH)
curl -L -o sluice https://github.com/nnemirovsky/sluice/releases/download/vVERSION/sluice_VERSION_OS_ARCH
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
ports = [443]

[[ask]]
destination = "*.openai.com"
ports = [443]

[[deny]]
destination = "169.254.169.254"   # block cloud metadata

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

## Telegram Bot

Manage sluice from your phone. Approve connections, add credentials, update policy.

| Command | Description |
|---------|-------------|
| `/policy show` | List current rules |
| `/policy allow <dest>` | Add allow rule |
| `/policy deny <dest>` | Add deny rule |
| `/cred add <name>` | Add credential (value sent as next message, auto-deleted) |
| `/cred rotate <name>` | Replace credential, hot-reload OpenClaw |
| `/status` | Proxy stats and pending approvals |
| `/audit recent [N]` | Last N audit entries |

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
| DNS | -- | Domain-level policy |
| QUIC/HTTP3 | HTTP/3 MITM | Full request/response |

## Requirements

| Runtime | Requirements |
|---------|-------------|
| Docker | Docker Engine |
| Apple Container | macOS, `container` CLI |
| macOS VM | macOS, Apple Silicon, `tart` CLI |
| All | Telegram bot token (optional, for approval flow) |

## Troubleshooting

**OpenClaw has no network access:** Check pf rules are loaded (`sudo pfctl -a sluice -sr`). Verify tun2proxy is running and sluice is listening on the SOCKS5 port.

**HTTPS certificate errors inside the container/VM:** Verify the CA cert is mounted and `SSL_CERT_FILE` points to it. Regenerate with `sluice cert generate` if needed.

**`container` CLI not found:** Install Apple Container runtime. The `container` binary must be in PATH.

**`tart` CLI not found:** Install via `brew install cirruslabs/cli/tart`.

**Permission denied on pfctl:** pf rules require root. Use the setup scripts with sudo.

## License

See [LICENSE](LICENSE).
