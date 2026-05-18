# Sluice - CLAUDE.md

Credential-injecting approval proxy for AI agents. Two governance layers: MCP-level (semantic tool control) and network-level (all-protocol interception). Asks for human approval via Telegram, injects credentials, forwards.

## Build and Test

```bash
go build -o sluice ./cmd/sluice/
go test ./... -v -timeout 30s
```

## E2e Tests

E2e tests in `e2e/` use build tags. They start a real sluice binary, configure policies, connect through the proxy, and verify credential injection, MCP gateway flows, and audit-log integrity across HTTP/HTTPS, SSH, MCP, WebSocket, gRPC, QUIC/HTTP3, DNS, IMAP/SMTP.

Build tags: `e2e` (all), `e2e && linux` (Docker compose integration), `e2e && darwin` (Apple Container, macOS only).

```bash
make test-e2e          # all e2e tests locally
make test-e2e-docker   # Linux e2e via Docker Compose
make test-e2e-macos    # macOS e2e (Apple Container)
```

Direct: `go test -tags=e2e ./e2e/ -v -count=1 -timeout=300s` (add `linux` or `darwin` to the tag list for the platform-specific suites).

CI runs e2e via `.github/workflows/e2e-linux.yml` and `e2e-macos.yml`.

## Releases

Use the `release-tools:new` skill; it handles version calc, tag push, description prompt. **Naming:** tag `vX.Y.Z` (e.g. `v0.10.0`); release title same as tag, NOT `Version X.Y.Z`.

**Version selection:**
- **Minor** (`v0.9.0`->`v0.10.0`): default. PR adds `feat`, new CLI flags, new protocol, or user-visible behavior change.
- **Hotfix** (`v0.10.0`->`v0.10.1`): PR has `fix` commits exclusively (no feat/breaking) — CI-only regressions, flakiness fixes, test fixes alongside a real bug fix.
- **Major** (`v0.10.0`->`v1.0.0`): breaking changes to CLI flags, SQLite schema, policy TOML, or MCP gateway API. **Always discuss with the user; never pick `major` autonomously.**

**Skip releases for** `chore`/`docs`/`ci`/`test`-only PRs (see `feedback_tag_policy.md`).

**Goreleaser workflow:** pushing a `v*` tag triggers `.github/workflows/release.yml` (goreleaser builds + uploads Linux/darwin binaries). Binaries upload even if the release was pre-created, so write the description first via `gh release edit`, then push the tag.

**Cross-repo refs in release notes:** bare `#number` auto-links to this repo's tracker (wrong for other repos' PRs). Use an explicit markdown link with `owner/repo#number` as link text: `[lqqyt2423/go-mitmproxy#100](https://github.com/lqqyt2423/go-mitmproxy/pull/100)`, no prose prefix.

## System Architecture

**Layer 1: MCP Gateway** — between agent and MCP tool servers. Sees tool names, args, responses; catches local tools (filesystem, exec) that never hit the network.

**Layer 2: SOCKS5 Proxy** — between container and internet. Sees every TCP/UDP connection, injects credentials at network level, catches anything bypassing MCP.

Complementary coverage: `filesystem__write_file` — MCP sees path+content (can block), invisible to SOCKS5; raw `fetch("https://evil.com")` — bypasses MCP, SOCKS5 catches it; `github__delete_repository` — MCP sees tool+args, SOCKS5 sees only `api.github.com:443`.

### Components

| Component | Role |
|-----------|------|
| **OpenClaw** | AI agent, no real credentials (Docker/Apple Container/tart VM) |
| **tun2proxy** | Routes ALL TCP+UDP through TUN to SOCKS5 |
| **Sluice SOCKS5 Proxy** | Network policy + MITM + credential injection |
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

`sluice cred add --destination` also creates an allow rule and binding; repeat the flag for multiple bindings sharing `--ports`/`--header`/`--template` (use `sluice binding add` for per-destination customization). `--env-var` injects the phantom into the agent container as that env var via `docker exec`. For HTTP/WebSocket upstreams `--command` holds the URL; env values prefixed `vault:` resolve from the vault at upstream spawn time. Two credential types: `static` (default, API keys), `oauth` (access/refresh pairs); OAuth tokens prompt via stdin (not flags) to avoid shell-history exposure.

`sluice cred update` is PATCH partial-update for OAuth: Enter at the refresh-token prompt (or omit the second piped line) preserves the stored refresh token (prevents an access-token rotation silently destroying it). To clear it, `PATCH /api/credentials/<name>` with `"refresh_token": ""`.

`sluice binding update --destination` also updates the paired auto-created allow rule (tagged `binding-add:<credential>` or `cred-add:<credential>`) so the new destination isn't orphaned. If no paired rule exists, the binding still updates with a warning and no fallback rule is created (don't silently revert an operator's removal). `--env-var` here changes/clears the env var name.

Runtime flags: `--mcp-base-url` sets the external URL the agent uses to reach sluice's MCP gateway (e.g. `http://sluice:3000`); added to `SelfBypass`; defaults to deriving from `--health-addr`. `--agent <profile>` selects the agent profile (`openclaw`/`hermes`) controlling env-file path, secrets-reload, MCP wiring; default `openclaw`; also `SLUICE_AGENT_PROFILE`.

## Channel Feature Parity

Management surfaces: **CLI**, **HTTP/REST API** (`api/openapi.yaml`), **Telegram bot**, future channels. **Every store-backed management feature must be reachable from all channels** (policy rules, credentials, bindings, MCP upstreams, pools, config/default-verdict — on CLI **and** REST **and** Telegram). Mechanism: put operation logic in a **channel-agnostic package** (the `store` methods, or a small `*ops` package like `internal/poolops`); each channel is a thin adapter. Logic written inline in one channel (the historical pools-CLI-only gap) is the anti-pattern.

The only acceptable single-channel features have a documented rationale making them meaningless elsewhere — `sluice cert generate` / `sluice audit verify` are local-filesystem operator tools; OAuth token entry is stdin-only to keep secrets out of shell history and the REST/Telegram surfaces. State the rationale in code and docs; absent it, parity is required and a reviewer should block the PR.

## Agent Profiles

Profiles abstract per-agent runtime conventions so container managers stay agent-agnostic. Each carries `EnvFileRelPath` (phantom env-var path), `ReloadCmd` (argv for in-place secret reload, or nil), `WireMCPCmd` (argv to register sluice as an MCP server).

| Profile | Env file | Reload | MCP wiring |
|---------|----------|--------|------------|
| `openclaw` (default) | `~/.openclaw/.env` | `node -e <gateway_rpc.js> secrets.reload` over the agent's WebSocket gateway | `node -e <gateway_rpc.js> wire-mcp <name> <url>` patches `mcp.servers.<name>` |
| `hermes` | `~/.hermes/.env` | None (see caveats) | sh wrapper patches `mcp_servers.<name>.url` in `~/.hermes/config.yaml` (see caveats) |

Adding a profile is a single edit to `internal/container/agent_profile.go` (register a struct in `builtinProfiles`); all three backends consume it via `BuildEnvInjectionScriptForProfile`, `profile.ReloadCmd()`, `profile.WireMCPCmd()`.

Hermes caveats:
- `ReloadCmd` nil; `ReloadSecrets` logs a notice, returns nil. New phantom tokens take effect on next Hermes message or `/reload-mcp`.
- `WireMCPCmd` rewrites `~/.hermes/config.yaml` via a sh wrapper activating `/opt/hermes/.venv` (PyYAML import path in the official image; no-op + system python3 for native installs). Hermes picks it up on next startup or `/reload-mcp` — sluice cannot trigger that remotely.
- Hermes' Modal/Daytona/Vercel Sandbox backends run on third-party infra sluice cannot intercept; local and Docker are the supported targets.

### Sluice-managed env block

Phantom tokens go in a fenced block in the agent's env file:

```
# BEGIN sluice-managed (do not edit)
KEY1='phantom-value-1'
# END sluice-managed
```

Values single-quoted so the file is safe under shell `source` and dotenv parsers; embedded single quotes escaped via `'\''`. Validation rejects newlines/NUL (every other byte is safe under single quoting). Each injection rebuilds the block: an awk pre-pass deletes only well-formed BEGIN..END pairs (an orphan BEGIN is left intact so a corrupted file is diagnosable), then a fresh block is appended; anything outside the markers (keys from `hermes claw migrate`, the agent's auth flow, or an operator) is preserved. `fullReplace` on `BuildEnvInjectionScript` is retained for API compat but no longer affects behavior. Removing a binding's `env_var` drops the key on the next injection.

## MCP Gateway Setup

OpenClaw connects via Streamable HTTP, one-time per deployment:

```bash
docker exec openclaw openclaw mcp set sluice '{"url":"http://sluice:3000/mcp"}'
```

For Hermes the equivalent runs once at sluice startup via `WireMCPGateway`, writing `mcp_servers.sluice.url` into `~/.hermes/config.yaml`; trigger `/reload-mcp` (or restart Hermes) once after first wire-up.

For `sluice` to resolve inside the agent container, the compose file pins sluice's IP (172.30.0.2) and adds an `extra_hosts` entry on tun2proxy (shared by the agent); Docker's embedded DNS (127.0.0.11) is unreachable from the agent (DNS routes through the TUN device), so `/etc/hosts` bypasses DNS.

MCP upstreams: manage via `sluice mcp add|list|remove`, REST (`/api/mcp/upstreams`), or Telegram (`/mcp add|list|remove`) — all write the same store. After add/remove, restart sluice so the gateway re-reads upstreams; the agent need not restart (its `sluice:3000/mcp` connection is registered once at startup, survives restarts, re-queries the tool list on subsequent runs). Telegram `/mcp add` auto-deletes the chat message because `--env KEY=VAL` may carry secrets (use `KEY=vault:name` to keep plaintext out of the store and `/mcp list`).

## Policy Store

Runtime policy state in SQLite (default `sluice.db`); TOML only for initial seeding via `sluice policy import` (see `examples/config.toml`). Rules use `[[allow]]`/`[[deny]]`/`[[ask]]`/`[[redact]]`; each entry carries exactly one of `destination` (network), `tool` (MCP), `pattern` (content), CHECK-constrained for mutual exclusivity. Import is merge (skip duplicates). `[[binding]]` entries support optional `env_var`. Store: `modernc.org/sqlite` (pure Go, no CGO), WAL, `golang-migrate`; 6 tables: `rules`, `config`, `bindings`, `mcp_upstreams`, `channels`, `credential_meta`.

## Credential Injection: Phantom Token Swap

User adds a credential (CLI/Telegram, `--env-var` sets the target env var); sluice encrypts the real value in the vault and generates a same-format/length phantom; the phantom is injected into the agent container as env vars via `docker exec` (written to `~/.openclaw/.env`, agent signaled to reload); the agent uses phantoms normally via SDKs; MITM intercepts requests and does a byte-level find-and-replace phantom->real. Sluice never needs to know the API's auth format.

Three-pass injection: (1) binding-specific header injection, (2) scoped phantom replacement for bound credentials only (prevents cross-credential exfiltration), (3) strip unbound phantom tokens as a safety net. All HTTPS is MITMed (not just bound destinations) so phantoms can't leak; `SecureBytes.Release()` zeroes credentials right after injection.

### OAuth dynamic phantom swap

Static credentials are request-only (phantom->real). OAuth adds response-side interception for transparent token lifecycle.

**Request side:** OAuth produces two phantom pairs; `SLUICE_PHANTOM:cred.access` / `SLUICE_PHANTOM:cred.refresh` swap to real tokens outbound, alongside static pairs in the same three-pass injection. **Response side:** when an OAuth token endpoint returns new tokens, sluice replaces them with deterministic phantoms before the agent sees them and updates the vault async; a vault-write failure still gives the agent phantoms (not real tokens), the next refresh corrects state. **Concurrent refresh:** `singleflight` keyed on credential name dedups async vault writes (each response is phantom-swapped independently, only persistence is deduped).

**Data model:** `credential_meta` stores type + token_url; `OAuthIndex` maps token URLs to credential names for response matching. Both hot-reloaded via `StoreResolver()`.

**Env var injection:** on startup and after credential changes, sluice reads all bindings with `env_var`, generates phantoms, and calls `ContainerManager.InjectEnvVars()` (writes `~/.openclaw/.env`, signals `openclaw secrets reload`).

**Key files:** `internal/vault/oauth.go`, `internal/vault/phantom.go` (`GeneratePhantomToken`), `internal/proxy/oauth_index.go`, `internal/proxy/oauth_response.go` (response interception/swap/async persist), `internal/proxy/quic_sni.go`, `internal/container/docker.go` (`InjectEnvVars`), `internal/container/types.go`, `internal/store/migrations/000002_credential_meta.up.sql`, `000003_binding_env_var.up.sql`.

### Credential pools and auto-failover

A **pool** backs one phantom identity with **N real OAuth credentials**. The agent always holds a single pool-scoped phantom pair, byte-stable across member switches: **access** is a synthetic pool-stable JWT (HS256, `sub: sluice-pool:<pool>`, `iss: sluice-phantom`, fixed far-future `exp`, via `poolStablePhantomAccess`); **refresh** is the static `SLUICE_PHANTOM:<pool>.refresh` (`oauthPhantomRefresh`'s request-side strip path). Sluice maps the pair to the *active member's* real tokens at injection and persists refreshed tokens back to the issuing member. Primary use: two OpenAI Codex OAuth accounts behind one agent so quota exhaustion rolls over transparently. Members must be `oauth` (static rejected); `cred remove` errors on a live member. **One credential is in at most one pool** (`PoolResolver.PoolForMember` maps a member to one pool; sharing would mis-persist/mis-audit and strand the agent); `pool create` rejects an already-pooled member in the same transaction as the member insert.

**CLI:**

```
sluice pool create <name> --members credA,credB[,credC]   # ordered; rejects static; namespace must not collide with a credential name
sluice pool list
sluice pool status <name>     # active member, per-member health (healthy / cooldown + until + reason)
sluice pool rotate <name>     # operator override: advance active member
sluice pool remove <name>
```

Auto-failover on 429/401 is primary; `pool rotate` is an override.

**Data model (migration `000006_credential_pools`):** `credential_pools` (name, strategy reserved `failover`), `credential_pool_members` (ordered, pool->credential FK), `credential_health` (`healthy|cooldown`, `cooldown_until`, `last_failure_reason`), all CHECK-constrained. Store API in `internal/store/pools.go`. `reloadAll` loads pool+health into an atomic-pointer-swapped `PoolResolver` (`internal/vault/pool.go`), rewired via `srv.StorePool`/`SetPoolResolver` on SIGHUP and the 2s data-version watcher.

**Phase 1 — phantom indirection (pool phantom -> active member):**

- **Single chokepoint (I2):** every `binding.Credential` / `OAuthIndex.Has` / `extractInjectableSecret` / persist consumer on the HTTP/HTTPS OAuth path routes through `PoolResolver.ResolveActive` (`resolveInjectionTarget` for pass-1 header + pass-2 swap; `resolveOAuthResponseAttribution` for response/persist). `idx.Has` is always called with the resolved member, never the pool. Plain credentials pass through unchanged; SSH/mail are non-OAuth, out of scope.
- **QUIC scope:** the HTTP/1.x/HTTP/2 MITM addon implements the full feature set (R1, R3, Phase 2). The HTTP/3/QUIC path (`QUICProxy.buildPhantomPairs`, binding-header injection in `quic.go`) is a request-side buffered swap with **no response-side OAuth interception**, but IS pool-aware on the request side: `QUICProxy.resolvePoolTarget` (via `NewQUICProxy`'s `poolResolver`) selects the active member's real secret and routes through `buildPooledOAuthPhantomPairs` so the access phantom is the same pool-stable JWT (R3 holds over QUIC). QUIC does **not** do R1 attribution or Phase 2 failover — the injected member is whatever the HTTP path / `pool rotate` last made active, and a QUIC-only 429/401 or refresh is not acted on. Deployments needing R1/auto-failover must route the pooled upstream over HTTP/HTTPS.
- **Active-member selection:** healthy or expired-cooldown members first, by configured position; if all are in cooldown, the soonest-recovering is returned with a WARNING (degrade, never hard-fail). Recovery is lazy (evaluated in `ResolveActive`, no scheduler).
- **R1 refresh-token attribution / fail-closed:** when pass-2 swaps `SLUICE_PHANTOM:<pool>.refresh`, sluice records `realRefreshToken -> member` in a short-TTL map; on the token-endpoint response it recovers the member by that real refresh token and persists to it (`persistAddonOAuthTokens(member, ...)`, singleflight `"persist:"+member`). The join key is the real **refresh** token — never the access token, connection, or `OAuthIndex.Match` (two pooled members share `auth.openai.com`'s token URL and collide). Unrecoverable -> WARNING + skip the write (rotating refresh tokens are single-use; a mis-attributed write bricks both accounts). **Plain-credential disambiguation:** a plain OAuth credential sharing a pool's token URL also tags its injected refresh token `realRefreshToken -> <plain name>` (plain path in `buildPhantomPairs`/`buildOAuthPhantomPairs`'s `onRefreshInject`, incl. split-host expansion); on response a recovered non-member (`PoolForMember == ""`) is attributed 1:1 to that plain credential, NOT fail-closed as pooled. The pooled fail-closed path applies only when recovery fails or resolves to an actual member; `poolForResponse` gates the same on an independent `flowInjected` tag (set post-swap only if a pool phantom was present) before cooling a member.
- **R3 pool-stable phantom JWT:** Codex access tokens are JWTs; the per-real-token `resignJWT` would emit a different phantom after each cross-member refresh, breaking "agent never notices". `poolStablePhantomAccess` (`internal/proxy/oauth_response.go`) builds the phantom JWT from a deterministic synthetic payload keyed on the **pool name** (`sub: sluice-pool:<pool>`, `iss: sluice-phantom`, fixed far-future `exp`, no `iat`), HMAC-SHA256 with the fixed key — byte-identical across switches, structurally valid. Pool name is JSON-marshaled (never concatenated) so quotes/control chars can't inject claims. Static-form fallback (`SLUICE_PHANTOM:<pool>.access`) only on the unreachable `json.Marshal` failure. Refresh phantom stays static `SLUICE_PHANTOM:<pool>.refresh`.

**Phase 2 — auto-failover on 429 / 401:**

- **Classification** (`classifyFailover`, `internal/proxy/pool_failover.go`, from `SluiceAddon.Response` for pooled destinations): `429`/`403 + insufficient_quota` -> rate-limited; `401`/token-body `invalid_grant`/`invalid_token` -> auth-failure; `5xx`/other -> no-op. Token-endpoint body trusted only when the request URL matched the OAuth index.
- **Pool attribution** (`poolForResponse`): a response is pool-attributed either (a) the flow's CONNECT host has a pooled binding (API-host 429/403), or (b) the request URL matches the OAuth token-URL index for a member (token-endpoint 401/`invalid_grant`). (b) is essential — an OAuth refresh hits `auth.openai.com` (no pool binding; only `api.openai.com` has one), so without it the token-endpoint classification is dead code for Codex. Member recovery + fail-closed are the R1 mechanism above (`OAuthIndex.MatchAll` + the refresh-token join key, never `OAuthIndex.Match`).
- **Synchronous in-memory failover (I1):** health is updated in-process before the response returns (`MarkCooldown` write lock, `ResolveActive` read lock) so the switch never waits on the 2s watcher (which only reconciles); a detached `onFailover` also writes `SetCredentialHealth(member,'cooldown',now+ttl,reason)` for durability. TTLs: `vault.RateLimitCooldown`=60s, `vault.AuthFailCooldown`=300s. **Cooldown extension is monotonic on both layers:** a member parked 300s for auth that then trips a 60s rate-limit keeps the LATER expiry — `MarkCooldown` and `SetCredentialHealth`'s `cooldown` upsert (CASE-compared against the stored future `cooldown_until`) both keep `max(existing-future, new)`. Only extend is monotonic: an explicit clear (zero/past `until`) and any transition to `healthy` still shorten/clear, and lazy expiry still wins over an expired stored cooldown. No in-flight retry — next request uses the new member.
- **Reload doesn't resurrect a cooled member:** the durable write is detached/best-effort, so any reload (SIGHUP or the 2s watcher on any unrelated DB write) rebuilds the resolver from store rows via `NewPoolResolver`; `Server.StorePool` calls `PoolResolver.MergeLiveCooldowns(prev)` to carry forward still-active in-memory cooldowns before the atomic swap (monotonic; drops cooldowns for credentials no longer in any pool).
- **Audit:** `cred_failover` (Verdict `failover`, Credential = cooled member), `Reason = "<pool>:<from>-><to>:<429|403|401|invalid_grant>"`, emitted synchronously in `handlePoolFailover`.
- **Telegram:** best-effort non-blocking notice "pool <name> failed over <a> -> <b> (<reason>)" (plain text); store write + every channel `Notify` detached into their own goroutine so the response path never blocks.
- **Known limitation:** streaming responses bypass failover (`handlePoolFailover` runs only from the buffered `Response` addon; SSE / `StreamLargeBodies`-exceeding bodies set `f.Stream=true` and skip it). Impact low (quota/auth bodies are tiny JSON); the next non-streamed request fails over normally.

**Key files:** `internal/store/migrations/000006_credential_pools.{up,down}.sql`, `internal/store/pools.go`, `internal/vault/pool.go`, `internal/proxy/pool_failover.go`, `cmd/sluice/pool.go`, plus pool routing in `internal/proxy/addon.go` / `oauth_response.go`.

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

**Per-request policy evaluation** applies to HTTP/HTTPS, gRPC-over-HTTP/2, QUIC/HTTP3: policy re-evaluated per request/stream, so "Allow Once" permits one request and the next re-triggers approval. On "Always Allow"/"Always Deny" the `RequestPolicyChecker` persists the rule via `PersistRuleFunc` and swaps in a fresh engine so subsequent requests hit the fast path (also skipped when the SOCKS5 CONNECT matched an explicit allow rule — `RuleMatch`, not default verdict). WebSocket/SSH/IMAP/SMTP stay connection-level on purpose: per-message/command policy would blow past the broker's 5/min per-destination limit.

**MITM library:** go-mitmproxy (`github.com/lqqyt2423/go-mitmproxy`); `SluiceAddon` (`internal/proxy/addon.go`) implements its `Addon` interface. `Requestheaders` fires per HTTP/2 stream (true per-request policy for gRPC/HTTP2); `Request` does credential injection (three-pass swap); `Response` does OAuth token interception + response DLP.

**Response DLP** (`internal/proxy/response_dlp.go`, via `SluiceAddon.Response`) scans HTTPS response bodies and header values for credential patterns using `InspectRedactRule` regexes. Manage redact rules via CLI (`sluice policy add redact`), Telegram (`/policy redact`), or HTTP (`POST /api/rules` `verdict="redact"`).

* Complements phantom stripping: stripping protects outbound (real creds never leak upstream); DLP protects inbound (upstream-echoed auth headers, debug endpoints, misconfigured services returning secrets never reach the agent).
* Header scan runs unconditionally — regardless of content type or body-scan success; a decompression failure or binary Content-Type can't suppress header-leak redaction.
* Body scan skips binary: `image/*`, `video/*`, `audio/*`, `application/octet-stream`, `application/pdf`, `application/zip`, `font/*`.
* Hop-by-hop headers never mutated (`Connection`, `Transfer-Encoding`, `Keep-Alive`, …). When the body is rewritten, `Transfer-Encoding` is stripped and `Content-Length` rewritten.
* Compressed bodies decoded: safe wrapper around `ReplaceToDecodedBody` handles single-value `Content-Encoding: gzip|br|deflate|zstd` (all unit-tested), multi-value `gzip, identity` (identity stripped, remaining decoded), stacked `gzip, br` (rejected unsupported, body scan skipped with a warning so it's never scanned as plaintext); restores original `Content-Encoding` on decode failure.
* Oversized bodies fail-open: over `maxProxyBody` (16 MiB) skip the body scan (data already left upstream).
* Streamed responses not scanned: `f.Stream=true` skips the `Response` callback (set for `text/event-stream` and bodies above `StreamLargeBodies`, default 5 MiB). `StreamResponseModifier` emits a one-shot WARNING per client connection when DLP rules exist (deduped by `dlpStreamWarned` sync.Map keyed by client conn id; falls back to a non-dedup log when `f.ConnContext`/`ClientConn` nil so the bypass is never silently suppressed).
* Audit: redactions emit `response_dlp_redact` with `Reason` = `rule1=count1,rule2=count2`. No-match scans emit a rate-limited debug log (1/500 scans).
* Rule loading: startup via `SluiceAddon.SetRedactRules` (all-or-nothing compile; on any pattern failure the old set stays), hot-reloaded on SIGHUP via `Server.UpdateInspectRules`, lock-free `atomic.Pointer` swap.

**Known limitation: streaming bypass.** Two classes bypass Response DLP: (1) `text/event-stream` (SSE, LLM streaming); (2) bodies > `StreamLargeBodies` (5 MiB) — 5–16 MiB here, >16 MiB via the oversized path. `StreamResponseModifier` still does OAuth token swap (small token bodies buffered) and logs `[ADDON-DLP] WARNING: streaming response bypasses DLP for <host> (<N> rules configured)`. **Operator guidance:** treat this as a credential-leak signal — alert on `[ADDON-DLP] WARNING` in a log aggregator (host = upstream hot-pathed past DLP; rule count = what would have been redacted). Chunked stream-aware scanning is future work (`docs/plans/completed/20260405-tool-network-dlp-hardening.md`).

**QUIC per-request:** `EvaluateQUICDetailed` returns Ask on an ask-rule match, else the engine's default verdict (not hardcoded Deny). The UDP dispatch loop creates a `RequestPolicyChecker` passed to `buildHandler`, which calls `CheckAndConsume` per HTTP/3 request; when default is "allow" a per-request checker (seed credits 1) is still attached so long-lived sessions re-evaluate.

**QUIC SNI extraction:** `ExtractQUICSNI()` decrypts the QUIC Initial packet (keys derive from the DCID in the packet header, RFC 9001 §5; QUIC v1+v2 salts) and extracts SNI from the embedded ClientHello. Falls back to DNS reverse-cache, then raw IP.

**QUIC broker dedup:** `pendingQUICSessions` (`server.go`) buffers UDP packets (max 32/session) for the same destination arriving during the approval wait; on resolve they flush (if allowed) or drop (if denied). This packet-level dedup is deliberately not routed through the broker `dedupIndex` (it predates and subsumes broker coalescing for the packet model) — both converge on one prompt per target.

## Implementation Details

### Policy engine

`LoadFromStore` reads rules from SQLite, compiles globs to regexes, produces a read-only Engine snapshot. `Evaluate(dest, port)` checks deny->allow->ask->default. Mutations go through the store, then a new Engine is compiled and atomically swapped via `srv.StoreEngine()`; SIGHUP also rebuilds the binding resolver (`srv.StoreResolver()`).

**Destination matching:** a rule's `destination` is a CIDR if it contains `/` (`192.168.0.0/16`, `2001:db8::/32`), else a glob (`*.tailscale.com`, `api.openai.com`). CIDR uses `net.IPNet.Contains` and only matches IP-parseable destinations (so `example.com` can't match `0.0.0.0/0`); glob uses the `[^.]*` / `(.*\.)?` matcher and only matches its compiled pattern (`192.168.0.*` covers that /24 only). Compile errors are loud (invalid CIDR fails `compileRules`).

**Hostname recovery for IP-only CONNECT.** Before dial, when the SOCKS5 layer got a bare IP and a hostname rule could match: `[SNI-DEFER]` (TLS ports 443/8443/993/995/465) reads the ClientHello SNI; `[HTTP-HOST-DEFER]` (HTTP 80/8080) reads the request prefix to `\r\n\r\n` for `Host:`. Both feed the hostname into `EvaluateDetailed` and update `ctxKeyFQDN` for upstream selection (makes `*.tailscale.com:80` rules match tailscale's bare-IP DERP probes without one prompt per IP). Peeked bytes are prepended via `io.MultiReader` so upstream sees the full request.

**Unscoped rules match all transports.** A rule without `protocols` (common for CLI-added rules) matches TCP, UDP, QUIC. `EvaluateUDP`/`EvaluateQUICDetailed` check protocol-scoped rules (`matchRulesStrictProto`) first, then unscoped (`matchRulesUnscoped`), then the default (same as TCP — no hidden UDP default-deny). `EvaluateUDP` collapses an Ask default to Deny (per-packet approval impractical); `EvaluateQUICDetailed` preserves Ask for the QUIC per-request flow. DNS has its own path (`IsDeniedDomain`), so the unscoped fallback doesn't change DNS.

### Protocol detection

Two-phase: port-based guess first (standard ports 443/22/25/… route on it), byte-level for non-standard ports. On `ProtoGeneric`, `DetectFromClientBytes` peeks first bytes (TLS, SSH, HTTP) and `DetectFromServerBytes` reads the server banner (SMTP, IMAP). Detection signals SOCKS5 CONNECT success before reading client bytes.

### Channel/approval abstraction

`Channel` interface with `Broker` coordinating across channels (Telegram, HTTP), broadcast-and-first-wins. Rate limits: `MaxPendingRequests` (50), per-destination (5/min). "Always Allow" writes the store, recompiles+swaps Engine.

**Broker-level approval coalescing.** The broker dedups pending approvals by their persistence-equivalent target (`dest:port`, the key `persistApprovalRule` writes). The first request opens one prompt and registers the primary waiter under `dedupIndex[dest:port]`; concurrent requests to the same key while pending attach a buffered (cap 1) sub channel to the primary (`waiter.subs`, `count++`). On resolve/deny/timeout/shutdown the terminal response fans out to `w.ch` plus a snapshot of every sub, under the same lock that deletes `waiters[id]`/`dedupIndex[key]` (closes the late-attach race; subs use a detach-only select arm so a timed-out sub never tears down the shared waiter). One tap dismisses the burst; the coalesced `count` is folded into the existing resolve/cancel edit ("… — applied to N requests at HH:MM:SS" when `count > 1`) so zero extra Telegram calls. `WithNoCoalesce()` is the escape hatch: HTTP/HTTPS/gRPC/WS + connection-level SSH/IMAP/SMTP (share `request_policy.go`'s `resolveAsk`) coalesce uniformly; **MCP opts out** (distinct `ToolArgs` must not collapse onto one key); QUIC keeps its own packet-buffering dedup.

`CouldBeAllowed(dest, includeAsk)`: with a broker, Ask-matching destinations resolve via DNS for the approval flow; without one, Ask is Deny at the DNS stage to avoid leaking queries.

**DNS approval design:** the interceptor only blocks explicitly denied domains (NXDOMAIN); allow/ask/default are forwarded. "ask" enforcement happens at the SOCKS5 CONNECT layer — blocking DNS for "ask" would stop the TCP connection ever reaching the SOCKS5 handler that triggers approval. DNS populates the reverse cache (IP->hostname) for IP-only CONNECT recovery and uses `IsDeniedDomain` (independent of the unscoped matching in `EvaluateUDP`/`EvaluateQUICDetailed`), so unscoped rules widen TCP/UDP/QUIC without changing DNS.

### Audit logger

Optional. JSON lines, blake3 hash chain (`prev_hash`, genesis = blake3("")); recovers across restarts by reading the last line. `sluice audit verify` walks the log and reports broken links. Common action names: `tool_call` (MCP verdict), `inspect_block` (ContentInspector arg block), `exec_block` (ExecInspector block), `response_dlp_redact` (HTTPS response/header redacted), `inject` (phantom injected outbound), `deny` (connection denied at SOCKS5/SNI).

### MCP gateway

Three upstream transports: stdio (child processes), Streamable HTTP, WebSocket — all satisfy `MCPUpstream`. Tools namespaced `<upstream>__<tool>`. Policy: deny/allow/ask priority. `ContentInspector` blocks args and redacts responses via regex (JSON parsed before matching to defeat unicode-escape bypass). Per-upstream timeout default `mcp.DefaultTimeoutSec` (120s); `internal/store.AddMCPUpstream` duplicates the literal 120 (circular import; flagged by a comment in `store.go`).

`MCPHTTPHandler` serves `POST /mcp` + `DELETE /mcp` on port 3000 (alongside `/healthz`). Session via `Mcp-Session-Id`. SSE supported. `SelfBypass` auto-allows the agent's connection to this listener (see MCP Gateway Setup).

**ExecInspector** (`internal/mcp/exec_inspect.go`) does structural exec-arg inspection for tools matching configurable globs (defaults `*exec*`, `*shell*`, `*run_command*`, `*terminal*`). Runs in `HandleToolCall` after ContentInspector and before Ask (exec-block is a hard deny — never present a dangerous command for approval). Detects:
- **Trampolines:** `bash -c`, `sh -c`, `zsh -c`, `python[23]? -c`, `ruby -e`, `perl -e`, `node -e`, plus combined-short-flag variants (`bash -ce`/`-ec`, `sh -xc`).
- **Shell metacharacters** (`| ; & $ < >`, backticks) in non-shell tools.
- **Dangerous commands:** `rm -rf /`, `chmod 777` incl. octal `0777` and the full setuid/setgid/sticky range `[0-7]?777` (1777…7777), `curl | sh/bash/python/ruby/perl/node/php/fish`, `wget | sh`, `dd if=/dev/`, `mkfs`.
- **Blacklisted env overrides** (`GIT_SSH_COMMAND`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`) matched case-insensitively (`strings.EqualFold`, whitespace-trimmed so ` GIT_SSH_COMMAND ` can't bypass), recursively through the arg tree under any env slot (`env`, `envs`, `env_vars`, `envvars`, `environment`, `environments`, `environment_variables`, `environmentvariables`, `vars`).

Command-string scanning is field-scoped: preferred slots (`command`, `cmd`, `script`, `code`, `args`, `arguments`, `argv`) always scanned, plus smuggle slots (`input`, `stdin`, `body`, `data`, `payload`) when any preferred slot is present. Prose fields (`description`, `notes`, `comment`, `documentation`, `summary`, `title`, `name`) never scanned (legit metadata may quote `bash -c`/`rm -rf /`). Top-level non-object payloads scanned whole. Returned command strings sorted before inspection so the first-match category is deterministic. Dedicated shell tools (anchored globs `*__shell`, `*__bash`, literal `shell`/`bash`) skip the metachar check (legit shell has `$`, `|`, …); trampoline + dangerous-command still apply. Because the globs are `__`-anchored, `github__shellcheck` / `vim__bashsyntax` still get the metachar check despite matching the broader `*shell*` glob — by design (a linter is not a shell).

Wired in both entry points via `mcp.NewExecInspector(nil)`: `cmd/sluice/main.go` (full proxy + gateway) and `cmd/sluice/mcp.go` (standalone gateway), so standalone isn't silently missing exec inspection. A block emits `exec_block` with `Reason = category:match` (e.g. `trampoline:bash -c`), then returns an error ToolResult. Separate from ContentInspector because it needs structural arg understanding, not text pattern matching.

### Vault providers

Seven providers via `Provider`; `NewProviderFromConfig` reads the SQLite config singleton: **age** (default, age-encrypted files in `~/.sluice/credentials/`), **env** (env vars, name uppercased), **hashicorp** (Vault KV v2, token or AppRole), **1password** (official Go SDK, Service Account token), **bitwarden** (`bws` CLI, 30s cache), **keepass** (gokeepasslib, auto-reload on file change), **gopass** (CLI wrapper). Chain provider: `providers = ["1password", "age"]` tries in order, first hit wins.

### Container backends

`--runtime`: `auto` (default), `docker`, `apple`, `macos`, `none`. All implement `ContainerManager` (`internal/container/types.go`).

- **Docker:** three-container compose (sluice + tun2proxy + openclaw). Hot-reload via `docker exec` env injection into `~/.openclaw/.env` + `openclaw secrets reload`; MCP wiring is a one-time `openclaw mcp set`; fallback container restart.
- **Apple Container:** Linux micro-VMs via Virtualization.framework. tun2proxy on host; `NetworkRouter` pf anchor redirects VM bridge traffic; VirtioFS shared volumes.
- **macOS VM (tart):** macOS guests via `tart`. Only backend with Apple framework access; explicit-only (`--runtime macos`). VirtioFS at `/Volumes/<name>/`; CA cert via `security add-trusted-cert`; lifecycle `tart clone`/`run`(bg)/`stop`/`delete`.
- **Standalone (`--runtime none`):** no container management; user sets `ALL_PROXY=socks5://localhost:1080`.

### Networking (Apple/tart backends)

`NetworkRouter` (`internal/container/network.go`): VM gets an IP on bridge100; host tun2proxy `--proxy socks5://127.0.0.1:1080 --tun utun3`; pf anchor `pass in on bridge100 route-to (utun3 192.168.64.1) from 192.168.64.0/24` routes all VM traffic through sluice.

### Health and shutdown

Health: HTTP `127.0.0.1:3000` `/healthz`; compose.yml uses `service_healthy` for startup ordering. Shutdown: SIGINT/SIGTERM drains connections up to `--shutdown-timeout` (10s); pending approvals auto-denied via `Broker.CancelAll()`; audit logger closed last.
