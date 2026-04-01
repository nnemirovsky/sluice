# Sluice

SOCKS5 proxy with policy-based connection filtering and audit logging. Evaluates connection requests against TOML policy rules (allow/deny/ask) and blocks or forwards accordingly.

**Status:** v0.0.1-alpha. Core proxy, policy engine, and Telegram approval flow functional.

## Quick Start

```bash
go build -o sluice ./cmd/sluice/
./sluice -policy testdata/policy_mixed.toml
```

Test with curl:

```bash
curl -x socks5h://127.0.0.1:1080 https://api.anthropic.com/
```

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `127.0.0.1:1080` | SOCKS5 listen address |
| `-policy` | `policy.toml` | Path to policy TOML file |
| `-audit` | `audit.jsonl` | Path to audit log file |
| `-telegram-token` | `$TELEGRAM_BOT_TOKEN` | Telegram bot token for approval flow |
| `-telegram-chat-id` | `$TELEGRAM_CHAT_ID` | Telegram chat ID for approvals |

## Policy File Format

```toml
[policy]
default = "deny"       # "allow", "deny", or "ask"
timeout_sec = 120       # timeout for ask verdicts

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
```

Glob patterns: `*` matches within a single DNS label (not across dots). `**` matches across dots (any depth of subdomains). `?` matches a single non-dot character. Matching is case-insensitive (RFC 4343). An empty ports list matches all ports.

Evaluation order: deny rules first, then allow, then ask, then the default verdict.

### Telegram Config in Policy File

The policy file can optionally specify custom environment variable names for the Telegram bot token and chat ID:

```toml
[telegram]
bot_token_env = "MY_BOT_TOKEN"   # env var name (default: TELEGRAM_BOT_TOKEN)
chat_id_env = "MY_CHAT_ID"       # env var name (default: TELEGRAM_CHAT_ID)
```

When present, these override the default environment variable names unless the corresponding CLI flag (`-telegram-token`, `-telegram-chat-id`) was explicitly provided. This is useful when running multiple Sluice instances with different bot tokens.

## Telegram Approval Bot

When configured, connections matching `ask` policy rules trigger an approval request via Telegram. The bot sends an inline keyboard message to the configured chat with three options: Allow Once, Always Allow, and Deny.

The connection blocks until the user responds or the timeout expires (controlled by `timeout_sec` in the policy file, default 120s). On timeout, the connection is denied.

"Always Allow" adds a dynamic allow rule to the running policy so subsequent connections to the same destination and port are automatically allowed without another prompt. Dynamic rules do not survive a restart.

Without Telegram configured, all `ask` verdicts are treated as `deny`.

### Telegram Commands

Commands are only accepted from the configured chat ID.

| Command | Description |
|---------|-------------|
| `/policy show` | List current rules |
| `/policy allow <dest>` | Add allow rule |
| `/policy deny <dest>` | Add deny rule |
| `/policy remove <dest>` | Remove rule |
| `/status` | Show proxy status |
| `/audit recent [N]` | Show last N audit entries (default 10) |
| `/help` | Show available commands |

Policy changes made via `/policy allow`, `/policy deny`, and `/policy remove` are applied to the running engine only. They are not persisted to the policy file and will be lost on SIGHUP reload or process restart.

## Hot Reload

Send SIGHUP to reload the policy file without restarting the proxy. Existing connections are not affected. New connections use the updated policy. SIGHUP also updates the policy engine used by Telegram command handlers.

The Telegram runtime (bot token, chat ID, approval broker) is wired once at startup and cannot be hot-reloaded. If the `[telegram]` section of the policy file changes, a full restart is required. A warning is logged when config drift is detected.

```bash
kill -HUP $(pgrep sluice)
```

## Audit Log

JSON Lines format written to the audit file path. Each line contains:

```json
{"timestamp":"2026-03-15T10:30:00Z","destination":"api.anthropic.com","port":443,"verdict":"allow"}
```

## Requirements

- Go 1.22+
- Telegram bot token (from @BotFather) for the approval flow (optional)
