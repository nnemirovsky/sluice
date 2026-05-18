# Sluice - CLAUDE.md

Credential-injecting approval proxy for AI agents. Two layers of governance: MCP-level (semantic tool control) and network-level (all-protocol interception). Asks for human approval via Telegram, injects credentials, and forwards.

## Build and Test

```bash
go build -o sluice ./cmd/sluice/
go test ./... -v -timeout 30s
```

## E2e Tests

End-to-end tests live in `e2e/` and use build tags. They start a real sluice binary, configure policies, make connections through the proxy, and verify credential injection, MCP gateway flows, and audit log integrity. Protocol coverage: HTTP/HTTPS, SSH, MCP, WebSocket, gRPC, QUIC/HTTP3, DNS, and IMAP/SMTP.

Build tags:
- `e2e` -- required for all e2e tests
- `e2e && linux` -- Docker compose integration tests
- `e2e && darwin` -- Apple Container tests (macOS only)

```bash
make test-e2e          # run all e2e tests locally
make test-e2e-docker   # run Linux e2e tests via Docker Compose
make test-e2e-macos    # run macOS e2e tests (Apple Container)
```

Or directly:
```bash
go test -tags=e2e ./e2e/ -v -count=1 -timeout=300s
go test -tags="e2e linux" ./e2e/ -v -count=1 -timeout=300s
go test -tags="e2e darwin" ./e2e/ -v -count=1 -timeout=300s
```

CI runs e2e tests via `.github/workflows/e2e-linux.yml` and `.github/workflows/e2e-macos.yml`.

## Releases

Use the `release-tools:new` skill (`/release-tools:new`) to cut a new release. The skill handles version calculation, tag push, and description prompt.

**Naming:**
- Tag: `vX.Y.Z` (e.g. `v0.10.0`)
- Release title: same as tag (`v0.10.0`), NOT `Version X.Y.Z`

**Version selection:**
- **Minor** (`v0.9.0` -> `v0.10.0`): default for most releases. Use when a merged PR adds `feat` commits, new CLI flags, new protocol support, or user-visible behavior changes.
- **Hotfix** (`v0.10.0` -> `v0.10.1`): only when a PR contains `fix` commits exclusively (no feat, no breaking changes). Common case: CI-only regressions, test fixes shipped alongside a real bug fix, flakiness fixes.
- **Major** (`v0.10.0` -> `v1.0.0`): breaking changes to CLI flags, SQLite schema, policy TOML format, or MCP gateway API. **Always discuss with the user before a major bump.** Never pick `major` autonomously.

**Skip releases for:** `chore`, `docs`, `ci`, `test` only PRs (see `feedback_tag_policy.md` memory).

**Release workflow (goreleaser):** Pushing a `v*` tag triggers `.github/workflows/release.yml` which uses goreleaser to build Linux/darwin binaries and upload them to the release. The workflow uploads binaries even if the release was pre-created with a description, so write the description first via `gh release edit` (or let the skill do it), then push the tag.

**Cross-repo references in release notes:** Bare `#number` gets auto-linked to this repo's issue tracker, which is wrong for PRs in other repos. Use an explicit markdown link with `owner/repo#number` as the link text: `[lqqyt2423/go-mitmproxy#100](https://github.com/lqqyt2423/go-mitmproxy/pull/100)`. Don't add any prose prefix like "go-mitmproxy PR" before it.

## System Architecture

Two governance layers work together:

**Layer 1: MCP Gateway** sits between agent and MCP tool servers. Sees tool names, arguments, responses. Catches local tools (filesystem, exec) that never hit the network.

**Layer 2: SOCKS5 Proxy** sits between container and internet. Sees every TCP/UDP connection. Injects credentials at the network level. Catches anything that bypasses MCP.

| Scenario | MCP Gateway | SOCKS5 Proxy |
|----------|-------------|--------------|
| `github__delete_repository` | Sees tool name + args, can block | Sees `api.github.com:443` only |
| `filesystem__write_file` | Sees path + content, can block | Invisible (no network) |
| Raw `fetch("https://evil.com")` | Bypasses MCP entirely | Catches it |
| SSH connection | Not an MCP call | Sees `github.com:22` |

### Components

| Component | Role |
|-----------|------|
| **OpenClaw** | AI agent, no real credentials (Docker/Apple Container/tart VM) |
| **tun2proxy** | Routes ALL TCP + UDP through TUN to SOCKS5 |
| **Sluice SOCKS5 Proxy** | Network-level policy + MITM + credential injection |
| **Sluice MCP Gateway** | Semantic tool governance (stdio + HTTP + WebSocket) |
| **Sluice Telegram Bot** | Approval UX + credential/policy management |
| **Vault** | Encrypted credential storage + phantom token mapping |

## CLI Subcommands

```
sluice policy list [--verdict allow|deny|ask|redact] [--db sluice.db]
sluice policy add allow|deny|ask <destination> [--ports 443,80] [--name "reason"]
sluice policy add redact <pattern> --replacement "[REDACTED_X]" [--name "reason"]
sluice policy remove <id>
sluice policy import <path.toml>    # seed DB from TOML (merge semantics)
sluice policy export                # dump current rules as TOML

sluice mcp add <name> --command <cmd> [--transport stdio|http|websocket] [--args "a,b"] [--env "K=V"] [--header "K=V"] [--timeout 120]
sluice mcp list
sluice mcp remove <name>
sluice mcp                          # start MCP gateway

sluice cred add <name> [--type static|oauth] [--destination host] [--ports 443] [--header Authorization] [--template "Bearer {value}"] [--env-var OPENAI_API_KEY]
sluice cred add <name> --type oauth --token-url <url> --destination <host> --ports 443 [--env-var OPENAI_API_KEY]
sluice cred update <name>           # replace credential value (prompts via stdin, handles static and OAuth; OAuth refresh token is preserved if left blank)
sluice cred list
sluice cred remove <name>

sluice binding add <credential> --destination <host> [--ports 443] [--header Authorization] [--template "Bearer {value}"] [--env-var OPENAI_API_KEY]
sluice binding list [--credential <name>]
sluice binding update <id> [--destination <host>] [--ports 443] [--header Authorization] [--template "Bearer {value}"] [--protocols http,grpc] [--env-var OPENAI_API_KEY]
sluice binding remove <id>

sluice cert generate                # generate CA certificate for HTTPS MITM
sluice audit verify                 # verify audit log hash chain integrity
```

When `--destination` is provided, `sluice cred add` also creates an allow rule and binding in the store. The flag may be repeated to create multiple bindings that share the same `--ports`, `--header`, and `--template` values (use `sluice binding add` afterwards for per-destination customization). When `--env-var` is provided, the phantom token is injected into the agent container as that environment variable via `docker exec` (no shared volume needed). For HTTP/WebSocket upstreams, `--command` holds the URL. Env values prefixed with `vault:` are resolved from the credential vault at upstream spawn time.

Two credential types: `static` (default) for API keys and `oauth` for OAuth access/refresh token pairs. OAuth credentials prompt for tokens via stdin (not CLI flags) to avoid shell history exposure.

`sluice cred update` uses PATCH partial-update semantics for OAuth credentials. Pressing Enter at the refresh token prompt (or omitting the second line when piping via stdin) preserves the currently stored refresh token. To explicitly clear the refresh token, update the credential again with the desired empty value through the REST API (`PATCH /api/credentials/<name>` with `"refresh_token": ""`). This prevents an access-token rotation from silently destroying the stored refresh token.

`sluice binding update --destination` also updates the paired auto-created allow rule (tagged `binding-add:<credential>` or `cred-add:<credential>`) so the new destination is not orphaned. If no paired rule exists (e.g. because it was manually removed), the binding destination is still updated and a warning is printed. No fallback rule is created so an operator's intentional removal is not silently reverted. `--env-var` on binding update can be used to change or clear the env var name after the initial binding was created.

Runtime flags: `--mcp-base-url` sets the external URL the agent uses to reach sluice's MCP gateway (e.g. `http://sluice:3000`). This is added to `SelfBypass` so sluice does not policy-check its own MCP traffic. Defaults to deriving from `--health-addr`. `--agent <profile>` selects an agent profile (`openclaw`, `hermes`); the profile controls the env file path inside the container, the secrets-reload mechanism, and the MCP wiring command. The default is `openclaw`. May also be set via `SLUICE_AGENT_PROFILE`.

## Channel Feature Parity

Sluice exposes management surfaces over multiple channels: the **CLI**, the **HTTP/REST API** (`api/openapi.yaml`), the **Telegram bot**, and any future channel. **Every store-backed management feature must be reachable from all channels.** When you add or change a feature that reads or writes the SQLite store (policy rules, credentials, bindings, MCP upstreams, credential pools, config/default-verdict, …), implement it on **CLI and REST and Telegram**, not just one.

The mechanism for keeping them honest: put the operation logic in a **channel-agnostic package** (e.g. the `store` methods, or a small `*ops` package like `internal/poolops`) and have each channel be a thin adapter over it. Logic written inline in one channel (the historical cause of the pools-are-CLI-only gap — rotate/status lived in `cmd/sluice/pool.go`) is the anti-pattern; lift it so the channels cannot drift.

The **only** acceptable single-channel features are those with a documented rationale that makes them meaningless elsewhere — e.g. `sluice cert generate` / `sluice audit verify` are local-filesystem/operator tools with no remote-management semantics; OAuth token entry is stdin-only on the CLI specifically to keep secrets out of shell history and out of the REST/Telegram surfaces. State the rationale in the code and docs when you deliberately scope a feature to one channel; absent that rationale, parity is required and a reviewer should block the PR.

## Agent Profiles

Profiles abstract per-agent runtime conventions so sluice's container managers stay agent-agnostic. Each profile carries `EnvFileRelPath` (where to write phantom-token env vars), `ReloadCmd` (argv to exec for in-place secret reload, or nil), and `WireMCPCmd` (argv to register sluice as an MCP server in the agent's config).

| Profile | Env file | Reload | MCP wiring |
|---------|----------|--------|------------|
| `openclaw` (default) | `~/.openclaw/.env` | `node -e <gateway_rpc.js> secrets.reload` over the agent's WebSocket gateway | `node -e <gateway_rpc.js> wire-mcp <name> <url>` patches `mcp.servers.<name>` |
| `hermes` | `~/.hermes/.env` | None — Hermes has no documented in-place reload; new env values take effect on next message / restart | `sh -c '[ -f /opt/hermes/.venv/bin/activate ] && . /opt/hermes/.venv/bin/activate; exec python3 -c <script>' <name> <url>` patches `mcp_servers.<name>.url` in `~/.hermes/config.yaml` (idempotent; activates Hermes' bundled venv when present so PyYAML is importable, falls back to system python3 for native installs) |

Adding a new profile is a single edit to `internal/container/agent_profile.go`: register a struct in `builtinProfiles`. All three container backends (Docker, Apple Container, tart) consume the profile through `BuildEnvInjectionScriptForProfile`, `profile.ReloadCmd()`, and `profile.WireMCPCmd()`, so backend code does not need to know about specific agents.

Hermes-specific caveats:

- `ReloadCmd` is nil; `ReloadSecrets` logs a notice and returns nil. New phantom tokens take effect on the next Hermes message or `/reload-mcp` slash command.
- `WireMCPCmd` rewrites `~/.hermes/config.yaml` directly via a sh wrapper that activates `/opt/hermes/.venv` (so PyYAML is on the import path inside the official Hermes Docker image). For native installs without the venv the activation is a no-op and the system `python3` is used. Hermes picks up the change on its next startup or via `/reload-mcp` from the chat session — sluice cannot trigger that command remotely.
- Hermes' Modal, Daytona, and Vercel Sandbox terminal backends run code on third-party infrastructure that sluice cannot intercept. The local and Docker Hermes backends are the supported targets for sluice's network-layer governance.

### Sluice-managed env block

Sluice writes its phantom tokens into a fenced block inside the agent's env file:

```
# BEGIN sluice-managed (do not edit)
KEY1='phantom-value-1'
KEY2='phantom-value-2'
# END sluice-managed
```

Values are wrapped in single quotes so the file is safe under both shell `source` (`set -a; . file; set +a`) and dotenv parsers. Embedded single quotes inside a value are escaped via the `'\''` idiom (close current quoted run, emit a backslash-escaped literal quote, reopen the quoted run). Validation rejects newlines and NUL bytes; every other byte (`$`, backticks, spaces, glob chars) is safe because the single quoting suppresses all expansion.

Each injection rebuilds the block: existing markers are removed via an awk pre-pass that only deletes well-formed BEGIN..END pairs (an orphan BEGIN with no matching END is left intact so an operator inspecting a corrupted file sees exactly what is wrong), then a fresh block is appended. Anything outside the markers (keys written by `hermes claw migrate`, by the agent's own auth flow, or by an operator) is preserved across both incremental updates and full reconciliation runs. The `fullReplace` flag on `BuildEnvInjectionScript` is retained for API compatibility but no longer affects file behavior — every call reconciles the managed block. Removing a binding's `env_var` simply drops the key from the new block on the next injection.

## MCP Gateway Setup

OpenClaw connects to sluice's MCP gateway via Streamable HTTP. This is a one-time setup per deployment:

```bash
docker exec openclaw openclaw mcp set sluice '{"url":"http://sluice:3000/mcp"}'
```

For Hermes, the equivalent runs once at sluice startup via `WireMCPGateway` and writes `mcp_servers.sluice.url` into `~/.hermes/config.yaml`. Trigger Hermes' `/reload-mcp` slash command (or restart Hermes) once after first wire-up so it picks up the new server.

For the hostname `sluice` to resolve inside the agent container, the compose file pins sluice's IP on the internal network (172.30.0.2) and adds an `extra_hosts` entry on tun2proxy (which the agent shares). Docker's embedded DNS (127.0.0.11) is not reachable from the agent because its DNS is routed through the TUN device. The `/etc/hosts` entry bypasses DNS entirely.

MCP upstreams can be managed via `sluice mcp add|list|remove`, the REST API (`/api/mcp/upstreams`), or the Telegram bot (`/mcp add|list|remove`). All three paths write to the same SQLite store. After any addition or removal, restart sluice so the gateway re-reads the upstream set. The agent does not need to be restarted: its connection to `sluice:3000/mcp` is registered once at sluice startup (via `WireMCPGateway`) and stays valid across sluice restarts. The agent re-queries the tool list on subsequent runs.

The Telegram `/mcp add` path auto-deletes the chat message because `--env KEY=VAL` pairs may contain secrets (use `KEY=vault:name` to keep the plaintext out of the SQLite store and `/mcp list` output entirely).

## Policy Store

All runtime policy state in SQLite (default: `sluice.db`). TOML files for initial seeding only via `sluice policy import`. See `examples/config.toml` for the full seed format.

Rules use `[[allow]]`/`[[deny]]`/`[[ask]]`/`[[redact]]` sections. Each entry carries exactly one of: `destination` (network), `tool` (MCP), or `pattern` (content inspection). The `rules` table uses a CHECK constraint enforcing mutual exclusivity of these columns. Import uses merge semantics (skip duplicates). Binding entries (`[[binding]]`) support an optional `env_var` field for env var injection.

Store uses `modernc.org/sqlite` (pure Go, no CGO), WAL mode, `golang-migrate` for schema. 6 tables: `rules`, `config`, `bindings`, `mcp_upstreams`, `channels`, `credential_meta`.

## Credential Injection: Phantom Token Swap

1. User adds credential via CLI or Telegram (with `--env-var` to specify the target environment variable)
2. Sluice encrypts real credential in vault, generates phantom token (same format/length)
3. Phantom tokens injected into the agent container as environment variables via `docker exec` (written to `~/.openclaw/.env`), agent signaled to reload
4. Agent uses phantom tokens normally via SDKs
5. Sluice MITM intercepts requests, does byte-level find-and-replace: phantom -> real
6. Sluice never needs to know the API's auth format

Three-pass injection in MITM: (1) binding-specific header injection, (2) scoped phantom replacement for bound credentials only (prevents cross-credential exfiltration), (3) strip unbound phantom tokens as safety net.

All HTTPS connections are MITMed (not just those with bindings) so phantom tokens can never leak upstream. `SecureBytes.Release()` zeroes credentials immediately after injection.

### OAuth dynamic phantom swap

Extends phantom swap to handle OAuth credentials bidirectionally. Static credentials are request-only (phantom -> real). OAuth credentials add response-side interception for transparent token lifecycle management.

**Request side:** OAuth credentials produce two phantom pairs. `SLUICE_PHANTOM:cred.access` and `SLUICE_PHANTOM:cred.refresh` are swapped to real tokens in outbound requests. Works alongside static phantom pairs in the same three-pass injection.

**Response side:** When an OAuth token endpoint returns new tokens, sluice intercepts the response. Real tokens are replaced with deterministic phantoms before the response reaches the agent. Vault is updated asynchronously. If the vault write fails, the agent still receives phantom tokens (not real ones). The next refresh cycle corrects the state.

**Concurrent refresh protection:** `singleflight` keyed on credential name deduplicates async vault writes when multiple requests trigger simultaneous token refreshes. Each response is independently processed (phantom swap happens per-response), but vault persistence is deduplicated.

**Data model:** `credential_meta` table stores credential type and token_url. `OAuthIndex` maps token URLs to credential names for fast response matching. Both are hot-reloaded via `StoreResolver()`.

**Env var injection:** Credentials with an `env_var` field are injected into the agent container via `docker exec`. On startup and after credential changes, sluice reads all bindings with `env_var` set, generates phantom values, and calls `ContainerManager.InjectEnvVars()` which writes to `~/.openclaw/.env` inside the container and signals `openclaw secrets reload`.

**Key files:**
- `internal/vault/oauth.go` -- OAuthCredential struct, parse/marshal, token update
- `internal/vault/phantom.go` -- `GeneratePhantomToken` for MITM phantom strings
- `internal/proxy/oauth_index.go` -- Token URL index for response matching
- `internal/proxy/oauth_response.go` -- Response interception, phantom swap, async vault persistence
- `internal/proxy/quic_sni.go` -- `ExtractQUICSNI` decrypts QUIC Initial to extract SNI hostname
- `internal/container/docker.go` -- `InjectEnvVars` implementation for Docker backend
- `internal/container/types.go` -- `ContainerManager` interface with `InjectEnvVars`
- `internal/store/migrations/000002_credential_meta.up.sql` -- Schema for credential metadata
- `internal/store/migrations/000003_binding_env_var.up.sql` -- `env_var` column on bindings

### Credential pools and auto-failover

A **credential pool** lets one phantom identity the agent sees be backed by **N real OAuth credentials**. The agent always holds a single pool-scoped phantom pair, byte-stable across member switches: the **access** phantom is a synthetic pool-stable JWT (HS256, `sub: sluice-pool:<pool>`, `iss: sluice-phantom`, fixed far-future `exp`, built by `poolStablePhantomAccess`) — byte-identical for a given pool regardless of which member is active; the **refresh** phantom is the static string `SLUICE_PHANTOM:<pool>.refresh` (from `oauthPhantomRefresh`'s request-side strip path). Sluice maps the pair to the *currently active member's* real tokens at injection time and persists refreshed tokens back to the member that issued them. Primary use case: two OpenAI Codex OAuth accounts behind one agent so quota exhaustion on one account transparently rolls onto the other. Pool members must be `oauth` credentials — `static` members are rejected. `cred remove` errors on a credential that is a live pool member. **One credential belongs to at most one pool**: proxy attribution (`PoolResolver.PoolForMember`) maps a member back to a single pool, so a credential shared across pools would persist/audit a token response against the wrong pool's phantom and leave the agent with an unreplaceable phantom. `pool create` rejects a member that is already in another pool (enforced inside the same transaction as the member insert).

**CLI:**

```
sluice pool create <name> --members credA,credB[,credC]   # comma-separated ordered members; rejects static; namespace must not collide with a credential name
sluice pool list
sluice pool status <name>     # active member, per-member health (healthy / cooldown + cooldown-until + reason)
sluice pool rotate <name>     # operator override: advance the active member manually
sluice pool remove <name>
```

Auto-failover on 429/401 is the primary mechanism; `pool rotate` is an operator override. Pool and credential namespaces are mutually exclusive at create time.

**Data model (migration `000006_credential_pools`):** three tables — `credential_pools` (pool name, strategy reserved `failover`), `credential_pool_members` (ordered membership, pool→credential FK), `credential_health` (per-member state `healthy|cooldown`, `cooldown_until`, `last_failure_reason`) — with CHECK constraints. Store API lives in `internal/store/pools.go`. `reloadAll` loads pool + health into an atomic-pointer-swapped `PoolResolver` (`internal/vault/pool.go`), rewired into the addon via `srv.StorePool`/`SetPoolResolver` on SIGHUP and the 2s data-version watcher.

**Phase 1 — phantom indirection (pool phantom → active member):**

- **Single chokepoint (I2):** every `binding.Credential` / `OAuthIndex.Has` / `extractInjectableSecret` / persist consumer on the HTTP/HTTPS OAuth path routes through `PoolResolver.ResolveActive` (`resolveInjectionTarget` for pass-1 header + pass-2 phantom swap; `resolveOAuthResponseAttribution` for the response/persist path). `idx.Has` is always called with the resolved member name, never the pool. Plain (non-pool) credentials pass through `ResolveActive` unchanged. SSH/mail are non-OAuth and out of scope.
- **QUIC pool support covers active-member injection plus the R3 pool-stable phantom; response-side R1/failover is HTTP-only (HTTP-vs-QUIC capability boundary):** the HTTP/1.x/HTTP/2 MITM addon implements the full pool feature set (R1 refresh attribution, R3 pool-stable phantom, Phase 2 429/401 auto-failover). The HTTP/3/QUIC injection path (`QUICProxy.buildPhantomPairs` and the binding-header injection in `quic.go`) is a request-side buffered swap with **no response-side OAuth interception**. It IS pool-aware on the request side: `QUICProxy.resolvePoolTarget` (wired via `NewQUICProxy`'s `poolResolver` arg from `server.go`) classifies a pooled binding, selects the pool's current active member's real secret for the vault lookup, and routes through `buildPooledOAuthPhantomPairs` so the agent-facing **access phantom is the same pool-stable synthetic JWT** the HTTP path mints (keyed on the pool name via `poolStablePhantomAccess`, byte-identical across member switches — R3 holds over QUIC). What QUIC does **not** do, because it has no response-side OAuth interception: per-request OAuth refresh attribution (R1) and automatic 429/401 member failover (Phase 2). Over QUIC the injected member secret is whatever member the HTTP path (or an operator via `pool rotate`) last made active; a QUIC-only 429/401 does not trigger a member switch and a QUIC-only token refresh is not attributed/persisted back to its issuing member. Deployments needing R1 attribution or auto-failover must route the pooled upstream over HTTP/HTTPS rather than HTTP/3; the agent-visible phantom itself is already stable on either path.
- **Active-member selection:** healthy or expired-cooldown members first, by configured position; if all members are in cooldown, the soonest-recovering member is returned with a WARNING (degrade, never hard-fail). Recovery is lazy — evaluated in `ResolveActive`, no scheduler.
- **R1 refresh-token attribution / fail-closed:** when pass-2 swaps `SLUICE_PHANTOM:<pool>.refresh`, sluice records `realRefreshToken → member` in a short-TTL map. On the token-endpoint response it recovers the member by that real refresh token and persists to that member (`persistAddonOAuthTokens(member, ...)`, singleflight key `"persist:"+member`). The join key is the real **refresh** token sluice injected — never the access token, the client connection, or `OAuthIndex.Match` (two pooled members share `auth.openai.com`'s token URL and collide there). If the member is unrecoverable: WARNING + skip the vault write, never guess. Rotating refresh tokens are single-use, so a mis-attributed write would brick both accounts — fail-closed is mandatory. **Plain-credential disambiguation on a shared token URL:** a plain (non-pool) OAuth credential that merely shares its token URL with a pool also has its injected real refresh token tagged `realRefreshToken → <plain name>` (the plain path in `buildPhantomPairs` / `buildOAuthPhantomPairs`'s `onRefreshInject`, including the token-host expansion for split-host plain creds). On the response side, when a pool shares the token URL, `resolveOAuthResponseAttribution` recovers the tag: if it resolves to a name that is **not** a pool member (`PoolForMember == ""`), the refresh is attributed 1:1 to that plain credential (its own phantom, its own vault write) — NOT fail-closed as a pooled refresh. The pooled fail-closed path is taken only when recovery fails entirely or resolves to an actual pool member. The `poolForResponse` failover path applies the same rule: a recovered owner not in any pool only triggers the membership-raced active-member fallback when an independent `flowInjected` pool-usage tag (set post-swap only if a pool phantom was actually present) confirms pooled usage; otherwise the failure is treated as a plain credential's and no pool member is cooled.
- **R3 pool-stable phantom JWT:** Codex access tokens are JWTs and the per-real-token `resignJWT` would emit a *different* phantom after every cross-member refresh, breaking the "agent never notices" guarantee. The dedicated `poolStablePhantomAccess` (in `internal/proxy/oauth_response.go`) instead builds the phantom JWT from a deterministic synthetic payload keyed on the **pool name** (`sub: sluice-pool:<pool>`, `iss: sluice-phantom`, fixed far-future `exp`, no `iat`), HMAC-SHA256'd with the existing fixed key — byte-identical across member switches while still a structurally valid JWT. The pool name is JSON-marshaled (never concatenated) so a name with quotes/control chars cannot inject claims. Static-form fallback (`SLUICE_PHANTOM:<pool>.access`) is emitted only on the unreachable `json.Marshal` failure of the fixed struct (and is documented as the equivalent for an agent verified to treat the access token as opaque). The **refresh** phantom is unaffected — it stays the static `SLUICE_PHANTOM:<pool>.refresh`.

**Phase 2 — auto-failover on 429 / 401:**

- **Classification** (`classifyFailover` in `internal/proxy/pool_failover.go`, called from `SluiceAddon.Response` for pooled destinations): `429` or `403 + insufficient_quota` → rate-limited; `401` or token-body `invalid_grant` / `invalid_token` → auth-failure; `5xx` / other → no-op. The token-endpoint body is only trusted when the request URL matched the OAuth index.
- **Pool attribution for the response** (`poolForResponse`): a response is attributed to a pool either (a) when the flow's CONNECT host has a pooled binding (the API-host 429/403 path), **or** (b) when the request URL matches the OAuth token-URL index for a credential that is a pool member (the token-endpoint 401 / `invalid_grant` path). Case (b) is essential: an OAuth refresh hits the credential's token-URL host (e.g. `auth.openai.com`), which has no pool binding — only the API host (e.g. `api.openai.com`) does — so without the token-URL index match the token-endpoint classification would be dead code for the Codex deployment. Two pooled members share that token URL, so `OAuthIndex.Match` (deterministic-first) is **not** trusted to name the member — using it would misattribute the refresh to whichever credential sorts first. Instead `resolveOAuthResponseAttribution` consults `OAuthIndex.MatchAll`: if *any* credential sharing this token URL is a pool member, the owning member is recovered from the **real refresh token sluice injected into this request's body** (the R1 join key from `refreshAttr.Recover`, unique per member). That recovered member is what gets cooled/persisted. If the member is unrecoverable (no live tag — tag expired or consumed before a slow response), it is **fail-closed**: the vault write is skipped (the agent still gets phantoms; the next refresh re-tags and retries) — sluice never guesses the member from the shared token URL.
- **Synchronous in-memory failover (I1):** health is updated in-process *before* the response returns — `MarkCooldown` takes the resolver write lock, `ResolveActive` the read lock — so the active-member switch never waits on the 2s data-version watcher (which only reconciles). A detached `onFailover` callback also writes `SetCredentialHealth(member, 'cooldown', now+ttl, reason)` for durability. Cooldown TTLs: `vault.RateLimitCooldown` = 60s, `vault.AuthFailCooldown` = 300s. **Cooldown extension is monotonic on both layers:** a member parked for an auth failure (300s) that subsequently trips a rate-limit (60s) keeps the LATER expiry — `MarkCooldown` (in-memory) and `SetCredentialHealth`'s `cooldown` upsert (durable, via a `CASE`/comparison against the stored future `cooldown_until`) both keep `max(existing-future, new)` so a known-bad credential is never made eligible early. Only the extend path is monotonic: an explicit clear (zero/past `until` in `MarkCooldown`) and any transition to `status='healthy'` still shorten/clear (recovery intact), and lazy expiry still wins over an already-expired stored cooldown. No in-flight retry — the next request uses the new member.
- **Reload does not resurrect a cooled member:** because the durable `SetCredentialHealth` write is detached and best-effort, any reload (SIGHUP or the 2s data-version watcher firing on *any* unrelated DB write) rebuilds the resolver from store rows alone via `NewPoolResolver`. `Server.StorePool` therefore calls `PoolResolver.MergeLiveCooldowns(prev)` to carry forward still-active in-memory cooldowns from the resolver being replaced before the atomic swap. The merge is monotonic (a live cooldown is never shortened/erased by an unrelated reload) and drops cooldowns for credentials no longer in any pool.
- **Audit:** a `cred_failover` event (Verdict `failover`, Credential = the cooled-down member) with `Reason = "<pool>:<from>-><to>:<429|403|401|invalid_grant>"`, emitted synchronously in `handlePoolFailover`.
- **Telegram:** a best-effort non-blocking notice "pool <name> failed over <a> -> <b> (<reason>)" (plain text — `TelegramChannel.Notify` sends with no parse mode); the store write and every broker channel `Notify` are detached into their own goroutine so the response path never blocks.
- **Known limitation: streaming responses bypass failover.** `handlePoolFailover` runs only from the buffered `Response` addon. Server-Sent Events (`text/event-stream`) and bodies above `StreamLargeBodies` set `f.Stream=true`, which skips the `Response` callback (same path as the Response DLP streaming bypass documented above), so a 429/401 delivered on a streamed response does not trigger failover. Practical impact is low because quota/auth error bodies are tiny JSON, not streamed; the next non-streamed request to the API host still fails over normally.

**Key files:** `internal/store/migrations/000006_credential_pools.{up,down}.sql`, `internal/store/pools.go`, `internal/vault/pool.go`, `internal/proxy/pool_failover.go`, `cmd/sluice/pool.go`, plus the pool routing in `internal/proxy/addon.go` / `internal/proxy/oauth_response.go`.

### Protocol-specific handling

| Protocol | Credential injection | Content inspection | Policy granularity |
|----------|---------------------|-------------------|--------------------|
| HTTP/HTTPS | Built-in MITM, phantom swap | Full request/response | Per-request (allow-once = one HTTP request) |
| gRPC | Header phantom swap via go-mitmproxy Addon hooks (per HTTP/2 stream) | Request/response metadata | Per-request (each HTTP/2 stream is a separate policy check) |
| WebSocket | Handshake headers + text frame phantom swap | Text frame deny + redact rules | Per-connection (one upgrade = one session) |
| SSH | Jump host, key from vault | N/A | Per-connection (channels belong to one session) |
| IMAP/SMTP | AUTH command proxy, phantom password swap | N/A | Per-connection (one mailbox session) |
| DNS | N/A | Deny-only (NXDOMAIN). See DNS design note below. | Per-query deny, other verdicts resolved at SOCKS5 |
| QUIC/HTTP3 | HTTP/3 MITM via quic-go, SNI from Initial packet | Full HTTP/3 request/response | Per-request (each HTTP/3 request triggers policy check) |
| APNS | Connection-level allow/deny (port 5223) | N/A | Per-connection |

**Per-request policy evaluation** applies to HTTP/HTTPS, gRPC-over-HTTP/2, and QUIC/HTTP3. Policy is re-evaluated for every HTTP request (or HTTP/2 stream, or HTTP/3 request), so "Allow Once" permits a single request and subsequent requests on the same connection re-trigger the approval flow. When a per-request approval resolves to "Always Allow" or "Always Deny", the `RequestPolicyChecker` persists the new rule to the policy store via its `PersistRuleFunc` callback and swaps in a freshly compiled engine, so subsequent requests match via the fast path instead of re-entering the approval flow. A fast path skips per-request checks when the SOCKS5 CONNECT matched an explicit allow rule (`RuleMatch`, not default verdict) so normally allowed destinations incur no extra overhead. WebSocket, SSH, and IMAP/SMTP remain connection-level on purpose: per-message or per-command policy on those would blow past the broker's 5/min per-destination rate limit and break normal usage.

**MITM library:** HTTPS interception uses go-mitmproxy (`github.com/lqqyt2423/go-mitmproxy`). The `SluiceAddon` struct in `internal/proxy/addon.go` implements go-mitmproxy's `Addon` interface. `Requestheaders` fires per HTTP/2 stream, giving true per-request policy for gRPC and other HTTP/2 traffic. `Request` handles credential injection (three-pass phantom swap). `Response` handles OAuth token interception and response DLP scanning.

**Response DLP** (`internal/proxy/response_dlp.go`, wired via `SluiceAddon.Response` in `internal/proxy/addon.go`) scans HTTPS response bodies and header values for credential patterns using `InspectRedactRule` regexes from the policy store. Redact rules can be managed via CLI (`sluice policy add redact <pattern> --replacement "..."`), Telegram (`/policy redact <pattern> [replacement]`), or HTTP API (`POST /api/rules` with `verdict="redact"`).

* Complements phantom token stripping. Phantom stripping protects outbound requests so real credentials never leak to upstreams. Response DLP protects inbound responses so real credentials from upstream bodies (echoed auth headers in API errors, debug endpoints leaking env vars, misconfigured services returning secrets) never reach the agent.
* Header scan runs unconditionally. Headers are scanned regardless of content type and regardless of whether the body scan later succeeds. A decompression failure or a binary Content-Type cannot suppress redaction of a header-borne leak.
* Body scan skips binary content. `image/*`, `video/*`, `audio/*`, `application/octet-stream`, `application/pdf`, `application/zip`, and `font/*` responses skip the body pass.
* Hop-by-hop headers are never mutated. `Connection`, `Transfer-Encoding`, `Keep-Alive`, etc. are left alone. When the body is rewritten, `Transfer-Encoding` is stripped and `Content-Length` rewritten so the agent receives a well-framed response.
* Compressed bodies are decoded. A safe wrapper around go-mitmproxy's `ReplaceToDecodedBody` handles single-value `Content-Encoding: gzip | br | deflate | zstd` (all four have unit tests), multi-value `Content-Encoding: gzip, identity` (identity tokens are stripped then the remaining single encoding is decoded), and stacked encodings like `gzip, br` (rejected as unsupported, body scan skipped with a warning log so a still-compressed body is never scanned as plaintext). The wrapper restores the original `Content-Encoding` header values on decode failure so callers see a consistent pre-state on error.
* Oversized bodies fail-open. Bodies over `maxProxyBody` (16 MiB) skip the body scan because the data already left the upstream.
* Streamed responses are not scanned. `f.Stream=true` skips the `Response` addon callback, which go-mitmproxy sets automatically for `text/event-stream` (SSE, LLM streaming) and for bodies above `StreamLargeBodies` (default 5 MiB). `StreamResponseModifier` emits a one-shot WARNING per client connection when DLP rules are configured and the stream path fires (deduped by `dlpStreamWarned` sync.Map, keyed by client connection id). When the connection state is unavailable (`f.ConnContext` or `f.ConnContext.ClientConn` nil, rare defensive case), the warning falls back to a non-dedup log so the bypass notification is never silently suppressed. See "Known limitation: streaming bypass" below.
* Audit event. Redactions emit a `response_dlp_redact` audit action whose `Reason` field is formatted as `rule1=count1,rule2=count2` so ops can distinguish one Bearer token from fifty AWS keys. No-match scans emit a rate-limited debug log (one line per 500 scans).
* Rule loading. Rules are loaded at startup via `SluiceAddon.SetRedactRules` (all-or-nothing compile: if any rule pattern fails, the old rule set stays in place) and hot-reloaded on SIGHUP through `Server.UpdateInspectRules`, with lock-free swap via `atomic.Pointer`.

**Known limitation: streaming bypass.** Two response classes bypass Response DLP entirely:

1. **Server-Sent Events** (any response with `Content-Type: text/event-stream`). Used by SSE endpoints, LLM streaming completions, etc.
2. **Bodies larger than `StreamLargeBodies`** (default 5 MiB). Anything between 5 MiB and `maxProxyBody` (16 MiB) lands here. Bodies over 16 MiB also bypass via the oversized-body path described above.

go-mitmproxy sets `f.Stream=true` for these classes and skips the `Response` addon callback that runs DLP scanning. Sluice substitutes a `StreamResponseModifier` that handles OAuth token swapping (small token bodies are buffered) and emits one of two log lines per client connection when DLP rules are configured:

```
[ADDON-DLP] WARNING: streaming response bypasses DLP for <host> (<N> rules configured)
```

or, when `f.ConnContext` is nil and dedup cannot be applied:

```
[ADDON-DLP] WARNING: streaming response bypasses DLP for <host> (<N> rules configured; connection state unavailable, dedup disabled)
```

**Operator guidance.** Treat these warning lines as a credential-leak monitoring signal. Pipe sluice's stderr/stdout to a log aggregator (Loki, Datadog, CloudWatch, etc.) and alert on the substring `[ADDON-DLP] WARNING`. The host field tells you which upstream is hot-pathed past DLP so you can decide whether to deny the destination, route around it, or accept the risk. The rule count tells you what would have been redacted had the body been buffered. Implementing chunked stream-aware scanning is on the future-work list (see `docs/plans/completed/20260405-tool-network-dlp-hardening.md`); until then, log-based alerting is the operator's only signal that a credential pattern may have flowed to the agent through a streaming response.

**QUIC per-request:** `EvaluateQUICDetailed` returns Ask when an ask rule matches and falls back to the engine's configured default verdict (not hardcoded Deny). The UDP dispatch loop creates a `RequestPolicyChecker` and passes it to `buildHandler`, which calls `CheckAndConsume` per HTTP/3 request. When the default verdict is "allow", a per-request checker is still attached (with seed credits of 1) so long-lived QUIC sessions re-evaluate policy on subsequent requests.

**QUIC SNI extraction:** Hostname recovery uses `ExtractQUICSNI()` to decrypt the QUIC Initial packet and extract SNI from the embedded TLS ClientHello. QUIC Initial packets encrypt the ClientHello, but the encryption keys are derived from the Destination Connection ID (DCID) visible in the packet header (RFC 9001 Section 5). Supports both QUIC v1 and v2 salts. Falls back to DNS reverse cache lookup, then raw IP if extraction fails.

**QUIC broker dedup:** `pendingQUICSessions` in `server.go` prevents duplicate Telegram approval prompts when multiple UDP packets arrive for the same destination during the approval wait. Packets are buffered (max 32 per session). When approval resolves, buffered packets are flushed (if allowed) or discarded (if denied). This is QUIC's own packet-level dedup and is independent of the channel-agnostic broker-level `dest:port` coalescing (see "Channel/approval abstraction" above) — QUIC's `broker.Request` call site is deliberately left on this path and is *not* routed through the broker `dedupIndex` (it predates and subsumes it for the QUIC packet model). The broker coalescing covers the other two call sites (HTTP/HTTPS/gRPC/WS + connection-level SSH/IMAP/SMTP; MCP opted out). Both mechanisms converge on the same outcome: one prompt per target, one human tap dismisses the whole burst, and the final coalesced count is folded into the resolve/cancel edit.

See `internal/proxy/request_policy.go`, `internal/policy/engine.go` (`EvaluateDetailed`, `EvaluateQUICDetailed`), `internal/proxy/quic_sni.go` (`ExtractQUICSNI`), and `internal/proxy/addon.go` (`SluiceAddon`).

## Implementation Details

### Policy engine

`LoadFromStore` reads rules from SQLite, compiles glob patterns into regexes, produces read-only Engine snapshot. `Evaluate(dest, port)` checks deny first, then allow, then ask, falling back to default verdict. Mutations go through the store, then a new Engine is compiled and atomically swapped via `srv.StoreEngine()`. SIGHUP also rebuilds the binding resolver and swaps it via `srv.StoreResolver()`.

**Destination matching: glob and CIDR.** A rule's `destination` is interpreted as a CIDR when it contains a `/` (e.g. `192.168.0.0/16`, `2001:db8::/32`) and as a glob otherwise (e.g. `*.tailscale.com`, `api.openai.com`, `10.0.0.5`). CIDR rules use IP containment via `net.IPNet.Contains`; glob rules use the existing `[^.]*` / `(.*\.)?` matcher. A CIDR rule only matches destinations that parse as an IP, so `example.com` cannot accidentally match `0.0.0.0/0`; conversely a glob rule only matches its compiled string pattern, so `192.168.0.*` works for the 256 hosts in `192.168.0.0/24` but does not magically extend to other subnets. Compile errors are loud (invalid CIDR mask fails `compileRules` rather than silently matching nothing).

**Hostname recovery for IP-only CONNECT requests.** Two peek paths run before dial when the SOCKS5 layer received a bare IP and a hostname rule could plausibly match: `[SNI-DEFER]` for TLS ports (443, 8443, 993, 995, 465) reads the TLS ClientHello and extracts SNI; `[HTTP-HOST-DEFER]` for plain HTTP ports (80, 8080) reads the request prefix up to `\r\n\r\n` and extracts the `Host:` header. Both feed the recovered hostname back into `EvaluateDetailed` and update `ctxKeyFQDN` so the dial uses the hostname for upstream selection. The HTTP path is what makes `*.tailscale.com:80` rules match tailscale's bare-IP DERP latency probes without flooding the approval channel with one prompt per IP. Bytes consumed during the peek are prepended to the relay reader via `io.MultiReader` so the upstream sees the full request.

**Unscoped rules match all transports.** A rule without a `protocols` field (the common case for CLI-added rules like `sluice policy add allow cloudflare.com --ports 443`) matches TCP, UDP, and QUIC traffic. `EvaluateUDP` and `EvaluateQUICDetailed` first check protocol-scoped rules (`matchRulesStrictProto` with `protocols=["udp"]`/`["quic"]`) and fall back to unscoped rules (`matchRulesUnscoped`) before the engine's configured default verdict. UDP and QUIC use the same default as TCP; there is no hidden "UDP default-deny" override. `EvaluateUDP` collapses an Ask default to Deny because per-packet approval is impractical, while `EvaluateQUICDetailed` preserves Ask for the QUIC per-request approval flow. Protocol-scoped rules (`protocols=["tcp"]`, `["udp"]`, `["quic"]`, etc.) still apply only to their declared protocol. DNS has its own evaluation path via `IsDeniedDomain`, so the unscoped-rule fallback for UDP/QUIC does not affect DNS query handling.

### Protocol detection

Two-phase detection: port-based guess first, then byte-level for non-standard ports. Standard ports (443, 22, 25, etc.) route directly on port guess. When port guess returns `ProtoGeneric`, `DetectFromClientBytes` peeks first bytes (TLS, SSH, HTTP) and `DetectFromServerBytes` reads server banner (SMTP, IMAP). Detection path signals SOCKS5 CONNECT success before reading client bytes.

### Channel/approval abstraction

`Channel` interface with `Broker` coordinating across channels (Telegram, HTTP). Broadcast-and-first-wins. Rate limiting: `MaxPendingRequests` (50), per-destination (5/min). "Always Allow" writes to SQLite store, recompiles and swaps Engine.

**Broker-level approval coalescing.** The broker dedups pending approvals by their persistence-equivalent target (`dest:port`, the same key `persistApprovalRule` writes). The first request to a target opens one prompt and registers the primary waiter under `dedupIndex[dest:port]`. Concurrent requests to the same `dest:port` while that prompt is still pending do not create new prompts — they attach a buffered (cap 1) sub channel to the primary waiter (`waiter.subs`, `count++`) instead of broadcasting again. On resolve/deny/timeout/shutdown the terminal response fans out to `w.ch` plus a snapshot of every attached sub taken under the same lock that deletes `waiters[id]` and `dedupIndex[key]` (closes the late-attach race; subs use a detach-only select arm so a timed-out sub never tears down the shared waiter). One human tap therefore dismisses the whole burst, matching the granularity of the single persisted `dest:port` rule. The final coalesced `count` is folded into the *existing* resolve/cancel message edit (rendered as "… — applied to N requests at HH:MM:SS" when `count > 1`) so Phase 1 adds zero extra Telegram API calls. `WithNoCoalesce()` is the escape hatch. Of the three `broker.Request` call sites, HTTP/HTTPS/gRPC/WS and connection-level SSH/IMAP/SMTP (all share `request_policy.go`'s `resolveAsk`) coalesce uniformly; **MCP tool calls opt out** via `WithNoCoalesce()` because distinct `ToolArgs` are semantically distinct (arg-sensitive ContentInspector/exec rules) and must not collapse onto one `dest:port` key; QUIC keeps its own packet-buffering dedup (see below) and is untouched.

`CouldBeAllowed(dest, includeAsk)`: when broker configured, Ask-matching destinations resolve via DNS for approval flow. When no broker, Ask treated as Deny at DNS stage to prevent leaking queries.

**DNS approval design**: The DNS interceptor intentionally only blocks explicitly denied domains (returns NXDOMAIN). All other queries (allow, ask, default) are forwarded to the upstream resolver. This is by design. Policy enforcement for "ask" destinations happens at the SOCKS5 CONNECT layer, not at DNS. Blocking DNS for "ask" destinations would prevent the TCP connection from ever reaching the SOCKS5 handler where the approval flow triggers. The DNS layer populates the reverse DNS cache (IP -> hostname) so the SOCKS5 handler can recover hostnames from IP-only CONNECT requests. DNS uses `IsDeniedDomain`, a separate evaluation path that is independent from the unscoped-rule matching in `EvaluateUDP` / `EvaluateQUICDetailed`. Unscoped rules therefore widen TCP/UDP/QUIC policy without changing DNS behavior.

### Audit logger

Optional. JSON lines with blake3 hash chain (`prev_hash` field). Genesis hash: blake3(""). Recovers chain across restarts by reading last line. `sluice audit verify` walks log and reports broken links.

Action names operators commonly grep for: `tool_call` (MCP tool call policy verdict), `inspect_block` (ContentInspector argument block), `exec_block` (ExecInspector trampoline/dangerous-command/env-override block), `response_dlp_redact` (MITM HTTPS response body or header redacted by InspectRedactRule), `inject` (phantom token injected into outbound request), and `deny` (network connection denied at SOCKS5 or SNI layer).

### MCP gateway

Three upstream transports: stdio (child processes), Streamable HTTP, WebSocket. All satisfy `MCPUpstream` interface. Tools namespaced as `<upstream>__<tool>`. Policy evaluation: deny/allow/ask priority. `ContentInspector` blocks arguments and redacts responses using regex (JSON parsed before matching to prevent unicode escape bypass). Per-upstream timeout defaults are defined by the `mcp.DefaultTimeoutSec` constant (120s) shared across packages that need the fallback. `internal/store.AddMCPUpstream` duplicates the literal 120 because `internal/store` is imported by `internal/mcp` and cannot import it back (circular). A comment in `store.go` flags the duplicate so the two stay in sync.

`MCPHTTPHandler` serves `POST /mcp` and `DELETE /mcp` on port 3000 (alongside `/healthz`). Session tracking via `Mcp-Session-Id` header. SSE response support.

Agent connection: OpenClaw is configured once (via `openclaw mcp set`) to connect to `http://sluice:3000/mcp`. Sluice's `SelfBypass` auto-allows connections to its own MCP listener so the traffic is not policy-checked.

**ExecInspector** (`internal/mcp/exec_inspect.go`) adds structural exec-argument inspection for tools whose names match configurable globs (defaults: `*exec*`, `*shell*`, `*run_command*`, `*terminal*`). It runs in `HandleToolCall` after the ContentInspector argument check and before the Ask/approval flow (exec-block is a hard deny: a dangerous command should not be presented to a human for approval). It detects trampoline patterns (`bash -c`, `sh -c`, `zsh -c`, `python[23]? -c`, `ruby -e`, `perl -e`, `node -e`, and combined-short-flag variants like `bash -ce` / `bash -ec` / `sh -xc`), shell metacharacters (`|`, `;`, `&`, `$`, `<`, `>`, backticks) in non-shell tools, dangerous commands (`rm -rf /`, `chmod 777` including `chmod 0777` octal and the full setuid/setgid/sticky combined-bit range `[0-7]?777` which covers 1777, 2777, 3777, 4777, 5777, 6777, 7777, `curl | sh/bash/python/ruby/perl/node/php/fish`, `wget | sh`, `dd if=/dev/`, `mkfs`), and blacklisted env overrides (`GIT_SSH_COMMAND`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`) matched case-insensitively (via `strings.EqualFold`, also whitespace-trimmed before comparison so padded keys like ` GIT_SSH_COMMAND ` cannot bypass) and recursively scanned through the full arg tree under any env-style slot (`env`, `envs`, `env_vars`, `envvars`, `environment`, `environments`, `environment_variables`, `environmentvariables`, `vars`). Command-string scanning is field-scoped: preferred command slots (`command`, `cmd`, `script`, `code`, `args`, `arguments`, `argv`) are always scanned, plus known smuggle slots (`input`, `stdin`, `body`, `data`, `payload`) when any preferred slot is present. Prose fields (`description`, `notes`, `comment`, `documentation`, `summary`, `title`, `name`) are never scanned because legitimate tool metadata can mention `bash -c` or `rm -rf /` as example text and would false-positive. Top-level non-object payloads (arrays, strings) are scanned as a whole because there is no field structure to lean on. Returned command strings are sorted before inspection so the first-match category is deterministic across runs. Dedicated shell tools (matched by the anchored globs `*__shell`, `*__bash`, or literal `shell`/`bash`) skip the metacharacter check because legitimate shell invocations contain `$`, `|`, etc. (e.g. `echo $HOME`). Trampoline and dangerous-command checks still apply. Because the shell-tool globs are anchored on `__`, tools like `github__shellcheck` and `vim__bashsyntax` will still receive the metacharacter check despite the substring match on the broader ExecTool globs (`*shell*`). That is by design: shellcheck is a linter, not a shell, so it must not get the shell-tool metachar bypass.

Wired in both production entry points via `mcp.NewExecInspector(nil)` which compiles the default patterns. The two entry points are `cmd/sluice/main.go` (the `sluice` command, which runs the full proxy plus MCP gateway) and `cmd/sluice/mcp.go` (the `sluice mcp` subcommand, which runs only the MCP gateway standalone). Both need wiring so the standalone mode is not silently missing exec inspection. A block emits an `exec_block` audit event with `Reason` set to `category:match` (e.g. `trampoline:bash -c` or `env_override:GIT_SSH_COMMAND`) for forensics, then returns an error ToolResult. This is separate from ContentInspector because exec inspection needs structural understanding of command arguments rather than pattern matching on arbitrary text.

### Vault providers

Seven providers via `Provider` interface. `NewProviderFromConfig` reads from SQLite config singleton:

- **age** (default): Local age-encrypted files in `~/.sluice/credentials/`
- **env**: Environment variables (name uppercased)
- **hashicorp**: Vault KV v2, token or AppRole auth
- **1password**: Official Go SDK, Service Account token
- **bitwarden**: `bws` CLI wrapper, 30s cache
- **keepass**: gokeepasslib, auto-reload on file change
- **gopass**: CLI wrapper

Chain provider: `providers = ["1password", "age"]` tries in order, first hit wins.

### Container backends

`--runtime` flag: `auto` (default), `docker`, `apple`, `macos`, `none`.

All backends implement `ContainerManager` interface (`internal/container/types.go`).

**Docker**: Three-container compose (sluice + tun2proxy + openclaw). Hot-reload via `docker exec` env var injection into `~/.openclaw/.env` + `docker exec openclaw openclaw secrets reload`. MCP wiring is a one-time `openclaw mcp set` (see "MCP Gateway Setup" above). Fallback: container restart.

**Apple Container**: Linux micro-VMs via Virtualization.framework. tun2proxy runs on host. `NetworkRouter` manages pf anchor rules to redirect VM bridge traffic. VirtioFS for shared volumes.

**macOS VM (tart)**: macOS guests via `tart` CLI. Only backend with Apple framework access. Explicit-only (`--runtime macos`). VirtioFS mounts at `/Volumes/<name>/`. CA cert via `security add-trusted-cert`. VM lifecycle: `tart clone`, `tart run` (background), `tart stop`, `tart delete`.

**Standalone (`--runtime none`)**: No container management. User sets `ALL_PROXY=socks5://localhost:1080` manually.

### Networking (Apple/tart backends)

`NetworkRouter` in `internal/container/network.go`:
1. VM gets IP on bridge100
2. tun2proxy on host: `tun2proxy --proxy socks5://127.0.0.1:1080 --tun utun3`
3. pf anchor: `pass in on bridge100 route-to (utun3 192.168.64.1) from 192.168.64.0/24`
4. All VM traffic flows through sluice

### Health and shutdown

Health: HTTP on `127.0.0.1:3000` serves `/healthz`. compose.yml uses `service_healthy` for startup ordering.

Shutdown: SIGINT/SIGTERM drains connections up to `--shutdown-timeout` (10s). Pending approvals auto-denied via `Broker.CancelAll()`. Audit logger closed last.
