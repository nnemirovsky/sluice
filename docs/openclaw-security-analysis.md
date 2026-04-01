# OpenClaw Security Analysis vs. Sluice Mitigation

> Last updated: 2026-04-01. Based on public CVEs, security research, and
> incident reports. Assessed against the Sluice architecture (OpenClaw in
> Docker + Sluice SOCKS5/MCP proxy).

## Summary

| Category | Total Issues | Solved by Sluice | Partially Solved | Not Solved |
|----------|-------------|-----------------|-----------------|------------|
| Credential exposure | 6 | 5 | 1 | 0 |
| Remote code execution | 3 | 2 | 1 | 0 |
| Network/gateway attacks | 3 | 3 | 0 | 0 |
| Prompt injection | 2 | 0 | 1 | 1 |
| Supply chain (skills/MCP) | 2 | 1 | 1 | 0 |
| Session/authorization | 2 | 1 | 0 | 1 |
| Runaway agent behavior | 1 | 1 | 0 | 0 |
| **Total** | **19** | **13** | **4** | **2** |

---

## 1. Credential Exposure

### 1a. API keys in LLM context window
**Source:** [Snyk research](https://snyk.io/blog/openclaw-skills-credential-leaks-research/) -
283 ClawHub skills (7.1%) instruct agents to pass API keys through the LLM
context window. Keys end up in logs, conversation history, and model
provider servers.

**Sluice: SOLVED.** Agent never has real credentials. Phantom tokens in the
context window are useless to attackers. Even if the LLM provider logs
everything, they only see phantom tokens.

### 1b. 21K+ exposed instances leaking tokens
**Source:** [API Stronghold](https://www.apistronghold.com/blog/21k-exposed-openclaw-instances-why-your-ai-agent-tokens-are-leaking) -
21,639 OpenClaw instances found with exposed gateway tokens, Anthropic API
keys, Telegram bot tokens, Slack OAuth credentials.

**Sluice: SOLVED.** OpenClaw runs in a Docker container on an internal
network with no direct internet access. Even if someone exposes the
container, it only has phantom tokens.

### 1c. Telegram bot token in error messages (CVE-2026-32982)
**Source:** [RedPacket Security](https://www.redpacketsecurity.com/cve-alert-cve-2026-32982-openclaw-openclaw/) -
fetchRemoteMedia leaks Telegram bot tokens in error strings when media
downloads fail.

**Sluice: SOLVED.** OpenClaw's Telegram bot uses a phantom token. The real
token lives only in Sluice's vault. Even if leaked, the phantom token
can't be used to impersonate the bot because mitmproxy swap only happens
on outbound requests through Sluice.

### 1d. Long-lived credentials in pairing codes (CVE-2026-33575)
**Source:** [RedPacket Security](https://www.redpacketsecurity.com/cve-alert-cve-2026-33575-openclaw-openclaw/) -
/pair endpoint embeds long-lived gateway credentials in setup codes.
Leaked codes from chat history/logs/screenshots allow ongoing access.

**Sluice: SOLVED.** The gateway is only accessible on the internal Docker
network. Pairing codes, even if leaked, can't reach the gateway from
outside the Docker network.

### 1e. Environment variable exposure
**Source:** [Kaspersky](https://www.kaspersky.com/blog/openclaw-vulnerabilities-exposed/55263/) -
Agents can read environment variables containing API keys via exec tools.

**Sluice: SOLVED.** Environment variables contain phantom tokens only. Even
if the agent reads them, it gets useless phantom values.

### 1f. Credentials in skill SKILL.md instructions
**Source:** [The Register](https://www.theregister.com/2026/02/05/openclaw_skills_marketplace_leaky_security/) -
Skill authors hardcode API keys in SKILL.md prompts, which pass through
the LLM context.

**Sluice: PARTIALLY SOLVED.** Sluice prevents real keys from being in the
agent's environment, but can't stop skill authors from hardcoding
third-party keys in prompt text. Content inspection in the MCP gateway
could flag this (future feature).

---

## 2. Remote Code Execution

### 2a. One-click RCE via Control UI (CVE-2026-25253, "ClawBleed")
**Source:** [ProArch](https://www.proarch.com/blog/threats-vulnerabilities/openclaw-rce-vulnerability-cve-2026-25253),
[SonicWall](https://www.sonicwall.com/blog/openclaw-auth-token-theft-leading-to-rce-cve-2026-25253) -
Control UI trusts gatewayUrl from query string, leaks auth token to
attacker. CVSS 8.8. 40,000+ instances vulnerable.

**Sluice: SOLVED.** OpenClaw's Control UI is not exposed to the internet.
The container has no port mappings to the host. The gateway is only
reachable from the internal Docker network. Even if someone crafts a
malicious link, the victim's browser can't reach the containerized gateway.

### 2b. ClawJacked: WebSocket hijack from malicious websites
**Source:** [Oasis Security](https://www.oasis.security/blog/openclaw-vulnerability),
[The Hacker News](https://thehackernews.com/2026/02/clawjacked-flaw-lets-malicious-sites.html) -
Malicious website opens WebSocket to localhost, brute-forces gateway
password (rate limiter exempts localhost), auto-pairs as trusted device.

**Sluice: SOLVED.** OpenClaw doesn't bind to localhost on the host machine.
It runs in a container with `network_mode: "service:tun2proxy"`. No
localhost port to connect to from the host browser.

### 2c. Exec tool abuse (arbitrary command execution)
**Source:** [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/02/19/running-openclaw-safely-identity-isolation-runtime-risk/) -
Agent can execute arbitrary shell commands via exec tools, potentially
destructive.

**Sluice: PARTIALLY SOLVED.** The MCP gateway can deny exec tools by
policy. The container limits blast radius (can't damage host). But if
exec is allowed by policy, the agent can still run destructive commands
inside the container. Combine with NanoClaw's ephemeral containers for
full protection.

---

## 3. Network/Gateway Attacks

### 3a. Gateway exposed to internet (42,900 instances)
**Source:** [SecurityScorecard STRIKE](https://openclawai.io/blog/openclaw-cve-flood-nine-vulnerabilities-four-days-march-2026) -
42,900 instances exposed across 82 countries, 15,200 vulnerable to RCE.

**Sluice: SOLVED.** Gateway runs on Docker `internal: true` network. Zero
internet exposure by architecture.

### 3b. Authentication bypass on localhost
**Source:** [Oasis Security](https://www.oasis.security/blog/openclaw-vulnerability) -
Rate limiter and device pairing exemptions for localhost connections.
93.4% of exposed instances had auth bypass conditions.

**Sluice: SOLVED.** No localhost binding on the host. Container network
namespace isolation.

### 3c. Unencrypted gateway WebSocket
**Source:** [Cisco Blogs](https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare) -
Gateway WebSocket often runs without TLS, exposing tokens in transit.

**Sluice: SOLVED.** Gateway traffic stays on internal Docker network. No
external transit. Sluice's HTTPS MITM handles TLS for outbound traffic.

---

## 4. Prompt Injection

### 4a. Indirect prompt injection via processed content
**Source:** [Giskard](https://www.giskard.ai/knowledge/openclaw-security-vulnerabilities-include-data-leakage-and-prompt-injection-risks) -
Malicious content in emails, documents, web pages forces the LLM to
perform unintended actions.

**Sluice: NOT SOLVED.** Sluice operates at the network/tool level, not the
prompt level. It can't inspect or sanitize LLM prompts. The MCP gateway
can block dangerous tool calls that result from prompt injection (e.g.,
blocking `exec__rm_rf` regardless of why it was called), but can't prevent
the injection itself.

### 4b. Context window compaction drops safety instructions
**Source:** [Meta inbox incident](https://techcrunch.com/2026/02/23/a-meta-ai-security-researcher-said-an-openclaw-agent-ran-amok-on-her-inbox/) -
Large context causes compaction that silently drops user safety
instructions, leading to uncontrolled agent behavior.

**Sluice: PARTIALLY SOLVED.** Sluice's approval gates catch dangerous
actions (e.g., mass email deletion would require Telegram approval if
the tool call goes through MCP). But if the action doesn't go through a
governed tool (e.g., OpenClaw's native email integration), Sluice can't
intercept it at the MCP level. The SOCKS5 layer would still see outbound
IMAP DELETE commands and could gate them.

---

## 5. Supply Chain (Skills/MCP)

### 5a. Malicious ClawHub skills (824+ found)
**Source:** [PointGuard AI](https://www.pointguardai.com/ai-security-incidents/openclaw-clawhub-malicious-skills-supply-chain-attack) -
12% of ClawHub skills were malicious. Hidden MCP server endpoints routed
through bore.pub tunnels to attacker infrastructure. 1,184 malicious
packages across 12 publisher accounts.

**Sluice: SOLVED (network layer).** The SOCKS5 proxy blocks all outbound
connections by default. A malicious skill trying to tunnel to
`bore.pub` or any attacker C2 would be denied unless explicitly
allowlisted. The MCP gateway also sees the tool calls and can block
suspicious MCP server spawning.

### 5b. Skill code execution in agent context
**Source:** [Cisco Blogs](https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare) -
Skills run with full agent privileges. A backdoored skill can read
files, exec commands, exfiltrate data.

**Sluice: PARTIALLY SOLVED.** Network exfiltration is blocked by the
SOCKS5 proxy. File reads inside the container are limited to the
container's filesystem (not the host). But a malicious skill can still
do damage inside the container (delete agent data, corrupt memory).
Combine with NanoClaw ephemeral containers for full isolation.

---

## 6. Session/Authorization

### 6a. Session sandbox escape (CVE-2026-32918)
**Source:** [RedPacket Security](https://www.redpacketsecurity.com/cve-alert-cve-2026-32918-openclaw-openclaw/) -
Sandboxed subagents can access parent/sibling session state via arbitrary
sessionKey values in session_status tool.

**Sluice: NOT SOLVED.** This is an internal OpenClaw authorization bug.
Sluice operates outside OpenClaw's process and can't enforce session
isolation within the application. Must be patched in OpenClaw itself.

### 6b. Shared global context leaks between DM users
**Source:** [Kaspersky](https://www.kaspersky.com/blog/openclaw-vulnerabilities-exposed/55263/) -
Direct messages from different users share global context, making secrets
visible across users.

**Sluice: SOLVED (by architecture).** Each user/context runs in a separate
container with its own Sluice policy. No shared state between containers.

---

## 7. Runaway Agent Behavior

### 7a. Meta inbox deletion incident
**Source:** [TechCrunch](https://techcrunch.com/2026/02/23/a-meta-ai-security-researcher-said-an-openclaw-agent-ran-amok-on-her-inbox/),
[Tom's Hardware](https://www.tomshardware.com/tech-industry/artificial-intelligence/openclaw-wipes-inbox-of-meta-ai-alignment-director-executive-finds-out-the-hard-way-how-spectacularly-efficient-ai-tool-is-at-maintaining-her-inbox) -
Meta AI Safety Director Summer Yue's OpenClaw agent "speedrun deleted"
her entire inbox, ignoring stop commands. Three warnings were ignored.
She had to physically unplug to stop it.

**Sluice: SOLVED.** Sluice's Telegram approval gate would require explicit
human approval for destructive actions. Mass email deletion would trigger
the SOCKS5 proxy's IMAP interception (if configured as ASK). The MCP
gateway would also catch email tool calls. Even in the worst case, the
Docker container can be killed remotely via the Sluice Telegram bot
(`/status` shows agent health, Docker socket allows container stop).

---

## What Sluice Does NOT Solve

1. **Prompt injection at the LLM level.** Sluice can't prevent the LLM
   from being manipulated. It can only block the resulting dangerous
   actions at the tool/network layer.

2. **Internal OpenClaw authorization bugs** (CVE-2026-32918 session escape).
   These must be fixed in OpenClaw's code. Sluice is external.

3. **Damage inside the container.** If a policy allows exec tools, the
   agent can destroy data inside its own container. Mitigated by
   ephemeral containers (NanoClaw pattern) or read-only root filesystem.

4. **Model provider data exposure.** Even with phantom tokens, the actual
   conversation content (prompts, responses) still goes to the model
   provider. Sluice doesn't encrypt or redact prompt content (though the
   MCP gateway's response redaction could strip PII from tool responses
   before they enter the LLM context).

---

## Recommended Sluice Configuration for Maximum Security

```toml
[policy]
default = "deny"        # Block everything by default

[[allow]]
destination = "api.anthropic.com"
ports = [443]
credential = "anthropic_api_key"

[[allow]]
destination = "*.telegram.org"
ports = [443]
note = "Telegram API passthrough"

[[deny]]
destination = "169.254.169.254"
note = "Block cloud metadata"

[[deny]]
destination = "*.bore.pub"
note = "Block bore.pub tunneling (malicious skill C2)"

[[deny]]
destination = "*.ngrok.io"
note = "Block ngrok tunneling"

# Tool policies
[[tool_allow]]
tool = "github__list_*"
tool = "github__get_*"
note = "Read-only GitHub"

[[tool_ask]]
tool = "github__create_*"
tool = "github__delete_*"
tool = "filesystem__write_file"
tool = "email__delete_*"
note = "Write/delete ops need approval"

[[tool_deny]]
tool = "exec__*"
note = "Block shell execution by default"
```
