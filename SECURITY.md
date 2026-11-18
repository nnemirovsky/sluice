# Security policy

## Reporting a vulnerability

Report privately through GitHub, not in a public issue:

**[Open a private security advisory](https://github.com/nnemirovsky/sluice/security/advisories/new)**

The report is visible only to the maintainer ([@nnemirovsky](https://github.com/nnemirovsky)) until an advisory is published, so nothing sensitive is exposed while a fix is prepared. Expect an acknowledgement within a week.

If the form is unavailable, open a normal issue that says only "I would like a private channel for a security report", with no details, and a private advisory will be opened for you.

Never attach real credentials, tokens, personal data or private files to a report. Describe the shape of the problem instead.

## Supported versions

Only the latest release gets security fixes.

## Scope

sluice holds real credentials and sits between an AI agent and everything it can reach. Its job is that the agent never sees a real secret, a real secret only goes to the destination it is bound to, and nothing passes that policy says to deny or to ask about. Any way around that is a vulnerability, for example:

- a real credential or OAuth token reaching the agent, in its env file, a response, a token-endpoint reply, an MCP tool result or an error message
- a phantom token swapped for a real credential on a request to a destination the credential is not bound to, for example through a redirect, a Host header that differs from the SNI, HTTP/2 connection reuse or an IP-only CONNECT
- agent traffic reaching a denied destination, or an "ask" destination without an approval, over any protocol sluice handles, or "Allow Once" letting through more than one request
- an MCP tool call that a deny rule or the exec inspector blocks still reaching the upstream server
- an approval, policy change or credential change accepted from anyone but the configured Telegram chat, a correctly signed webhook reply, a REST call with the API token, or the local CLI
- the age vault, the CA private key, `sluice.db` or the audit log written in plain text or readable by other users, or a credential value written to a log
- an edited audit log that `sluice audit verify` reports as intact
- a credential name, env var value or auth-reset target that runs a command inside the agent container

Out of scope:

- the limits the README and CLAUDE.md document: streamed responses (SSE and bodies over 5 MiB) skip response DLP and pool failover, DNS forwards every query that is not denied, QUIC has no OAuth response interception, and WebSocket, SSH, IMAP and SMTP are checked per connection
- a redact rule or an exec-inspector pattern that misses a variant. These are heuristics on top of policy, so open a normal issue.
- an agent using a credential on its bound destination in a way your policy allows
- traffic that never goes through sluice, such as an agent outside the tun2proxy routing or a Hermes backend on third-party infrastructure
- secrets you choose to keep in plain text: the `env` provider and MCP upstream `--env` values not given as `vault:` references
- the SOCKS5 port or the API port exposed beyond `127.0.0.1` or the container network by your own configuration
- anything that needs an attacker who already controls the host running sluice, its vault directory or its API token
