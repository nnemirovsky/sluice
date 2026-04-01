# Sluice Plan 0: OpenClaw Contributions (PRs)

> Instead of building a full standalone proxy, contribute key missing features
> directly to OpenClaw. This covers most of the Sluice use case natively.

**Goal:** Two PRs to OpenClaw that together provide credential isolation for MCP
servers and approval routing for HTTP/fetch tool calls.

---

## PR 1: SecretRef support for MCP server env vars

### Problem

MCP server credentials (`GITHUB_TOKEN`, `DATABASE_URL`, etc.) are stored as
plaintext in `openclaw.json` under `mcpServers.*.env.*`. The SecretRef system
(PR #26155, merged 2026-02-26) covers 73 credential fields but explicitly does
NOT cover MCP server env vars.

This means MCP server API keys cannot use external secret providers (Vault,
1Password, env-backed refs). They must be hardcoded or use raw `${ENV_VAR}`
expansion with no provider validation.

### Scope

The change follows the exact pattern of `skills.entries.*.apiKey` (already
supported). The SecretRef infrastructure is battle-tested with 160+ targets.

### Files to modify

1. **`extensions/acpx/src/config.ts:24`**
   - Change: `env?: Record<string, string>` to `env?: Record<string, SecretInput>`
   - Also update `AcpxMcpServer.env` array type to accept resolved strings

2. **`src/secrets/target-registry-data.ts`**
   - Add entry:
     ```typescript
     {
       id: "plugins.entries.acpx.config.mcpServers.*.env.*",
       targetType: "plugins.entries.acpx.config.mcpServers.env",
       configFile: "openclaw.json",
       pathPattern: "plugins.entries.acpx.config.mcpServers.*.env.*",
       secretShape: SECRET_INPUT_SHAPE,
       expectedResolvedValue: "string",
       includeInPlan: true,
       includeInConfigure: true,
       includeInAudit: true,
     },
     ```

3. **`extensions/acpx/src/config.ts:308-318` (`toAcpMcpServers`)**
   - Resolve SecretRef values before mapping to `{ name, value }` pairs
   - Must call `normalizeResolvedSecretInputString()` on each env value
   - Ensure resolved plaintext is NOT logged or persisted back to config

4. **`src/config/zod-schema.core.ts`** (or equivalent)
   - Update MCP server env validation to accept `SecretInput` (string | SecretRef)

5. **`docs/reference/secretref-credential-surface.md`**
   - Add `plugins.entries.acpx.config.mcpServers.*.env.*` to the supported list

6. **`docs/gateway/secrets.md`**
   - Add example showing MCP server env vars with SecretRef

7. **Tests**
   - Config parsing test: SecretRef in mcpServers env loads correctly
   - Resolution test: SecretRef values resolve before spawn
   - Audit test: resolved values appear in audit surface
   - Redaction test: resolved values NOT serialized back to config snapshots

### Example config after PR

```json
{
  "plugins": {
    "entries": {
      "acpx": {
        "config": {
          "mcpServers": {
            "github": {
              "command": "npx",
              "args": ["-y", "@modelcontextprotocol/server-github"],
              "env": {
                "GITHUB_TOKEN": {
                  "source": "exec",
                  "provider": "vault",
                  "id": "github/token"
                }
              }
            }
          }
        }
      }
    }
  }
}
```

Or with env template shorthand:

```json
{
  "env": {
    "GITHUB_TOKEN": "${GITHUB_PERSONAL_ACCESS_TOKEN}"
  }
}
```

### Estimated effort

~200 LOC changes + ~150 LOC tests. The pattern is well-established.
Biggest risk: ensuring the resolution happens at the right point in the
acpx plugin lifecycle (before server spawn, after runtime snapshot activation).

---

## PR 2: Approval routing for HTTP/fetch tool calls

### Problem

OpenClaw has exec approvals (shell commands) with Telegram inline button
routing. But HTTP/fetch tool calls have no approval mechanism. An agent can
make arbitrary HTTP requests via built-in tools without user consent.

### Approach

Extend the existing exec approval pattern to cover HTTP/fetch tools.
The infrastructure already exists:
- `exec.approval.requested` / `exec.approval.resolve` event system
- Telegram inline button routing (`channels.telegram.execApprovals`)
- Allowlist / ask-always / ask-on-miss modes
- Control UI integration

The PR would add a parallel system:
- `http.approval.requested` / `http.approval.resolve` events
- Reuse the same Telegram routing config (or add `httpApprovals` section)
- URL-based allowlist (glob patterns on destination URLs)
- Same ask modes: off / on-miss / always

### Research needed before writing PR

- [ ] Identify where HTTP/fetch tool calls are made in the codebase
- [ ] Check if `before_tool_call` hook already covers these (plugin approach vs core)
- [ ] Determine if the approval system should be core or if a plugin using
      `before_tool_call` hook is sufficient
- [ ] Check existing issues/discussions about HTTP tool approval

### Alternative: Plugin using before_tool_call hook

Instead of core PR, this could be an OpenClaw plugin:

```typescript
api.on("before_tool_call", async (event) => {
  if (isHttpTool(event.toolName)) {
    const url = extractUrl(event.params);
    if (!isAllowlisted(url)) {
      const approved = await requestTelegramApproval(event.toolName, url);
      if (!approved) return { block: true, blockReason: "HTTP request denied" };
    }
  }
  return { block: false };
});
```

This is simpler to ship (no core changes) but less integrated (no native
Telegram routing, no exec-approval-style UX).

### Recommendation

Start with the plugin approach. If it works well and the community wants it,
propose merging into core later.

---

## Revised Sluice scope

With these two PRs, the remaining Sluice scope shrinks to:

| Feature | Who builds it |
|---------|---------------|
| MCP server credential isolation | OpenClaw PR 1 (SecretRef) |
| HTTP/fetch tool approval | OpenClaw plugin or PR 2 |
| Exec command approval | Already in OpenClaw (Telegram) |
| Model/skill/channel credentials | Already in OpenClaw (SecretRef) |
| Phantom token generation | Small CLI tool or Vault workflow |
| Network-level proxy (all TCP) | Sluice v2 (hardening, optional) |
| Telegram config management bot | Sluice plugin or standalone |
