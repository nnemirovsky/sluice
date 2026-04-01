# Sluice

SOCKS5 proxy with policy-based connection filtering and audit logging. Evaluates connection requests against TOML policy rules (allow/deny/ask) and blocks or forwards accordingly.

**Status:** v0.0.1-alpha. Core proxy and policy engine functional. No Telegram approval flow yet (ask = deny).

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

## Policy File Format

```toml
[policy]
default = "deny"       # "allow", "deny", or "ask"
timeout_sec = 120       # timeout for ask verdicts (future use)

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

Glob patterns: `*` matches within a single DNS label (not across dots). An empty ports list matches all ports.

Evaluation order: deny rules first, then allow, then ask, then the default verdict.

## Audit Log

JSON Lines format written to the audit file path. Each line contains:

```json
{"timestamp":"2026-03-15T10:30:00Z","destination":"api.anthropic.com","port":443,"verdict":"allow"}
```

## Requirements

- Go 1.22+
