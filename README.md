# Sluice

Credential-injecting approval proxy for AI agents. Two layers of governance: MCP-level (semantic tool control) and network-level (all-protocol interception). Asks for human approval via Telegram, injects credentials, and forwards.

**Status:** v0.0.1-alpha. Core proxy, policy engine, MCP gateway, and Telegram approval flow functional.

## Quick Start

```bash
go build -o sluice ./cmd/sluice/
./sluice --db sluice.db --config examples/config.toml
```

On first run with an empty database, `--config` seeds the DB from the TOML file. Subsequent runs use the SQLite store directly.

Test with curl:

```bash
curl -x socks5h://127.0.0.1:1080 https://api.anthropic.com/
```

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `127.0.0.1:1080` | SOCKS5 listen address |
| `--db` | `sluice.db` | Path to SQLite policy database |
| `--config` | (none) | TOML seed file (imported only when DB is empty) |
| `--audit` | `audit.jsonl` | Path to audit log file |
| `--telegram-token` | `$TELEGRAM_BOT_TOKEN` | Telegram bot token for approval flow |
| `--telegram-chat-id` | `$TELEGRAM_CHAT_ID` | Telegram chat ID for approvals |
| `--health-addr` | `127.0.0.1:3000` | Health check HTTP address |
| `--shutdown-timeout` | `10s` | Graceful shutdown timeout |
| `--docker-socket` | (auto-detect) | Docker socket path for container management |
| `--docker-container` | `openclaw` | Agent container name (env: `SLUICE_AGENT_CONTAINER`) |
| `--phantom-dir` | (none) | Shared volume path for phantom token files (enables hot-reload) |

## CLI Subcommands

### Policy management

```
sluice policy list [--verdict allow|deny|ask|redact] [--db sluice.db]
sluice policy add allow <destination> [--ports 443,80] [--name "reason"]
sluice policy add deny <destination> [--name "reason"]
sluice policy add ask <destination> [--ports 443] [--name "reason"]
sluice policy remove <id>
sluice policy import <path.toml>
sluice policy export
```

### MCP upstream management

```
sluice mcp add <name> --command <cmd> [--args "arg1,arg2"] [--env "KEY=VAL,..."] [--timeout 120]
sluice mcp list
sluice mcp remove <name>
sluice mcp                          # start MCP gateway
```

### Credential management

```
sluice cred add <name> [--destination host] [--ports 443] [--header Authorization] [--template "Bearer {value}"]
sluice cred list
sluice cred remove <name>
```

When `--destination` is provided, `sluice cred add` also creates an allow rule and binding in the store.

### Other subcommands

```
sluice cert generate                # generate CA certificate for HTTPS MITM
sluice audit verify                 # verify audit log hash chain integrity
```

## Policy Store

All runtime policy state is stored in a SQLite database (default: `sluice.db`). TOML files are used only for initial seeding via `sluice policy import`. The CLI, Telegram commands, and approval buttons all write to the same database. Changes persist across restarts.

### TOML Seed File Format

```toml
[policy]
default = "deny"       # "allow", "deny", or "ask"
timeout_sec = 120       # timeout for ask verdicts

[vault]
provider = "age"

# Network rules (destination field)

[[allow]]
destination = "api.anthropic.com"
ports = [443]

[[allow]]
destination = "*.github.com"    # glob: * matches within one DNS label
ports = [443, 80]

[[deny]]
destination = "169.254.169.254" # block metadata endpoint

[[ask]]
destination = "*.openai.com"
ports = [443]

# Tool rules (tool field)

[[allow]]
tool = "github__list_*"
name = "read-only github list"

[[deny]]
tool = "exec__*"
name = "block all exec"

# Content inspection rules (pattern field)

[[deny]]
pattern = "(?i)(sk-[a-zA-Z0-9_-]{20,})"
name = "api key in tool arguments"

[[redact]]
pattern = "(?i)(sk-[a-zA-Z0-9_-]{20,})"
replacement = "[REDACTED_API_KEY]"
name = "api key in responses"
```

Rules use a unified format. Each `[[allow]]`, `[[deny]]`, `[[ask]]`, or `[[redact]]` entry carries exactly one of: `destination` (network rule), `tool` (MCP tool rule), or `pattern` (content inspection rule). The section name determines the verdict.

Glob patterns: `*` matches within a single DNS label (not across dots). `**` matches across dots (any depth of subdomains). `?` matches a single non-dot character. Matching is case-insensitive (RFC 4343). An empty ports list matches all ports.

Evaluation order: deny rules first, then allow, then ask, then the default verdict.

## Telegram Approval Bot

When configured, connections matching `ask` policy rules trigger an approval request via Telegram. The bot sends an inline keyboard message to the configured chat with three options: Allow Once, Always Allow, and Deny.

The connection blocks until the user responds or the timeout expires (controlled by `timeout_sec`, default 120s). On timeout, the connection is denied.

"Always Allow" writes a persistent allow rule to the SQLite store with `source="approval"`. The rule survives restarts.

Without Telegram configured, all `ask` verdicts are treated as `deny`.

### Telegram Commands

Commands are only accepted from the configured chat ID.

| Command | Description |
|---------|-------------|
| `/policy show` | List current rules |
| `/policy allow <dest>` | Add allow rule (persisted to SQLite) |
| `/policy deny <dest>` | Add deny rule (persisted to SQLite) |
| `/policy remove <id>` | Remove rule by ID |
| `/cred add <name> <value>` | Add credential |
| `/cred list` | List credential names |
| `/cred rotate <name> <value>` | Replace credential |
| `/cred remove <name>` | Remove credential |
| `/status` | Show proxy status |
| `/audit recent [N]` | Show last N audit entries (default 10) |
| `/help` | Show available commands |

Policy changes via Telegram are persisted to the SQLite store and survive restarts.

## Hot Reload

Send SIGHUP to recompile the policy engine from the SQLite store without restarting the proxy. Existing connections are not affected. New connections use the updated policy. SIGHUP also updates the policy engine used by Telegram command handlers.

Telegram bot credentials are read from environment variables (`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`) at startup and cannot be hot-reloaded. Changing Telegram credentials requires a full restart.

```bash
kill -HUP $(pgrep sluice)
```

## Audit Log

JSON Lines format written to the audit file path. Each line includes a `prev_hash` field with the blake3 hash of the previous line for tamper detection. Verify the chain with:

```bash
sluice audit verify
```

## Docker Compose

Three-container architecture: sluice + tun2proxy + openclaw. All agent traffic is routed through sluice's SOCKS5 proxy via TUN device. Phantom tokens are delivered to the agent via a shared volume (`sluice-phantoms`). See `compose.yml` for details.

## Requirements

- Go 1.22+
- Telegram bot token (from @BotFather) for the approval flow (optional)
- Docker (optional, for container deployment)
