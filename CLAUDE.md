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

sluice mcp add <name> --command <cmd> [--transport stdio|http|websocket] [--args "a,b"] [--env "K=V"] [--timeout 120]
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

Runtime flags: `--mcp-base-url` sets the external URL the agent uses to reach sluice's MCP gateway (e.g. `http://sluice:3000`). This is added to `SelfBypass` so sluice does not policy-check its own MCP traffic. Defaults to deriving from `--health-addr`.

## MCP Gateway Setup

OpenClaw connects to sluice's MCP gateway via Streamable HTTP. This is a one-time setup per deployment:

```bash
docker exec openclaw openclaw mcp set sluice '{"url":"http://sluice:3000/mcp"}'
```

For the hostname `sluice` to resolve inside OpenClaw, the compose file pins sluice's IP on the internal network (172.30.0.2) and adds an `extra_hosts` entry on tun2proxy (which OpenClaw shares). Docker's embedded DNS (127.0.0.11) is not reachable from OpenClaw because its DNS is routed through the TUN device. The `/etc/hosts` entry bypasses DNS entirely.

When new MCP upstreams are added to sluice via `sluice mcp add`, restart sluice so the gateway picks them up. OpenClaw does not need to be restarted - its connection to sluice:3000/mcp remains valid and it re-queries the tool list on subsequent agent runs.

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

**QUIC broker dedup:** `pendingQUICSessions` in `server.go` prevents duplicate Telegram approval prompts when multiple UDP packets arrive for the same destination during the approval wait. Packets are buffered (max 32 per session). When approval resolves, buffered packets are flushed (if allowed) or discarded (if denied).

See `internal/proxy/request_policy.go`, `internal/policy/engine.go` (`EvaluateDetailed`, `EvaluateQUICDetailed`), `internal/proxy/quic_sni.go` (`ExtractQUICSNI`), and `internal/proxy/addon.go` (`SluiceAddon`).

## Implementation Details

### Policy engine

`LoadFromStore` reads rules from SQLite, compiles glob patterns into regexes, produces read-only Engine snapshot. `Evaluate(dest, port)` checks deny first, then allow, then ask, falling back to default verdict. Mutations go through the store, then a new Engine is compiled and atomically swapped via `srv.StoreEngine()`. SIGHUP also rebuilds the binding resolver and swaps it via `srv.StoreResolver()`.

**Unscoped rules match all transports.** A rule without a `protocols` field (the common case for CLI-added rules like `sluice policy add allow cloudflare.com --ports 443`) matches TCP, UDP, and QUIC traffic. `EvaluateUDP` and `EvaluateQUICDetailed` first check protocol-scoped rules (`matchRulesStrictProto` with `protocols=["udp"]`/`["quic"]`) and fall back to unscoped rules (`matchRulesUnscoped`) before the engine's configured default verdict. UDP and QUIC use the same default as TCP; there is no hidden "UDP default-deny" override. `EvaluateUDP` collapses an Ask default to Deny because per-packet approval is impractical, while `EvaluateQUICDetailed` preserves Ask for the QUIC per-request approval flow. Protocol-scoped rules (`protocols=["tcp"]`, `["udp"]`, `["quic"]`, etc.) still apply only to their declared protocol. DNS has its own evaluation path via `IsDeniedDomain`, so the unscoped-rule fallback for UDP/QUIC does not affect DNS query handling.

### Protocol detection

Two-phase detection: port-based guess first, then byte-level for non-standard ports. Standard ports (443, 22, 25, etc.) route directly on port guess. When port guess returns `ProtoGeneric`, `DetectFromClientBytes` peeks first bytes (TLS, SSH, HTTP) and `DetectFromServerBytes` reads server banner (SMTP, IMAP). Detection path signals SOCKS5 CONNECT success before reading client bytes.

### Channel/approval abstraction

`Channel` interface with `Broker` coordinating across channels (Telegram, HTTP). Broadcast-and-first-wins. Rate limiting: `MaxPendingRequests` (50), per-destination (5/min). "Always Allow" writes to SQLite store, recompiles and swaps Engine.

`CouldBeAllowed(dest, includeAsk)`: when broker configured, Ask-matching destinations resolve via DNS for approval flow. When no broker, Ask treated as Deny at DNS stage to prevent leaking queries.

**DNS approval design**: The DNS interceptor intentionally only blocks explicitly denied domains (returns NXDOMAIN). All other queries (allow, ask, default) are forwarded to the upstream resolver. This is by design. Policy enforcement for "ask" destinations happens at the SOCKS5 CONNECT layer, not at DNS. Blocking DNS for "ask" destinations would prevent the TCP connection from ever reaching the SOCKS5 handler where the approval flow triggers. The DNS layer populates the reverse DNS cache (IP -> hostname) so the SOCKS5 handler can recover hostnames from IP-only CONNECT requests. DNS uses `IsDeniedDomain`, a separate evaluation path that is independent from the unscoped-rule matching in `EvaluateUDP` / `EvaluateQUICDetailed`. Unscoped rules therefore widen TCP/UDP/QUIC policy without changing DNS behavior.

### Audit logger

Optional. JSON lines with blake3 hash chain (`prev_hash` field). Genesis hash: blake3(""). Recovers chain across restarts by reading last line. `sluice audit verify` walks log and reports broken links.

Action names operators commonly grep for: `tool_call` (MCP tool call policy verdict), `inspect_block` (ContentInspector argument block), `exec_block` (ExecInspector trampoline/dangerous-command/env-override block), `response_dlp_redact` (MITM HTTPS response body or header redacted by InspectRedactRule), `inject` (phantom token injected into outbound request), and `deny` (network connection denied at SOCKS5 or SNI layer).

### MCP gateway

Three upstream transports: stdio (child processes), Streamable HTTP, WebSocket. All satisfy `MCPUpstream` interface. Tools namespaced as `<upstream>__<tool>`. Policy evaluation: deny/allow/ask priority. `ContentInspector` blocks arguments and redacts responses using regex (JSON parsed before matching to prevent unicode escape bypass). Per-upstream timeouts (default 120s).

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
