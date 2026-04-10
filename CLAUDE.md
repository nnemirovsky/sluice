# Sluice - CLAUDE.md

Credential-injecting approval proxy for AI agents. Two layers of governance: MCP-level (semantic tool control) and network-level (all-protocol interception). Asks for human approval via Telegram, injects credentials, and forwards.

## Build and Test

```bash
go build -o sluice ./cmd/sluice/
go test ./... -v -timeout 30s
```

## E2e Tests

End-to-end tests live in `e2e/` and use build tags. They start a real sluice binary, configure policies, make connections through the proxy, and verify credential injection, MCP gateway flows, and audit log integrity.

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
- `internal/container/docker.go` -- `InjectEnvVars` implementation for Docker backend
- `internal/container/types.go` -- `ContainerManager` interface with `InjectEnvVars`
- `internal/store/migrations/000002_credential_meta.up.sql` -- Schema for credential metadata
- `internal/store/migrations/000003_binding_env_var.up.sql` -- `env_var` column on bindings

### Protocol-specific handling

| Protocol | Credential injection | Content inspection |
|----------|---------------------|-------------------|
| HTTP/HTTPS | Built-in MITM, phantom swap | Full request/response |
| gRPC | Header phantom swap (Content-Type detection) | Request/response metadata |
| WebSocket | Handshake headers + text frame phantom swap | Text frame deny + redact rules |
| SSH | Jump host, key from vault | N/A |
| IMAP/SMTP | AUTH command proxy, phantom password swap | N/A |
| DNS | N/A | Deny-only (NXDOMAIN). See DNS design note below. |
| QUIC/HTTP3 | HTTP/3 MITM via quic-go | Full HTTP/3 request/response |
| APNS | Connection-level allow/deny (port 5223) | N/A |

## Implementation Details

### Policy engine

`LoadFromStore` reads rules from SQLite, compiles glob patterns into regexes, produces read-only Engine snapshot. `Evaluate(dest, port)` checks deny first, then allow, then ask, falling back to default verdict. Mutations go through the store, then a new Engine is compiled and atomically swapped via `srv.StoreEngine()`. SIGHUP also rebuilds the binding resolver and swaps it via `srv.StoreResolver()`.

### Protocol detection

Two-phase detection: port-based guess first, then byte-level for non-standard ports. Standard ports (443, 22, 25, etc.) route directly on port guess. When port guess returns `ProtoGeneric`, `DetectFromClientBytes` peeks first bytes (TLS, SSH, HTTP) and `DetectFromServerBytes` reads server banner (SMTP, IMAP). Detection path signals SOCKS5 CONNECT success before reading client bytes.

### Channel/approval abstraction

`Channel` interface with `Broker` coordinating across channels (Telegram, HTTP). Broadcast-and-first-wins. Rate limiting: `MaxPendingRequests` (50), per-destination (5/min). "Always Allow" writes to SQLite store, recompiles and swaps Engine.

`CouldBeAllowed(dest, includeAsk)`: when broker configured, Ask-matching destinations resolve via DNS for approval flow. When no broker, Ask treated as Deny at DNS stage to prevent leaking queries.

**DNS approval design**: The DNS interceptor intentionally only blocks explicitly denied domains (returns NXDOMAIN). All other queries (allow, ask, default) are forwarded to the upstream resolver. This is by design. Policy enforcement for "ask" destinations happens at the SOCKS5 CONNECT layer, not at DNS. Blocking DNS for "ask" destinations would prevent the TCP connection from ever reaching the SOCKS5 handler where the approval flow triggers. The DNS layer populates the reverse DNS cache (IP -> hostname) so the SOCKS5 handler can recover hostnames from IP-only CONNECT requests.

### Audit logger

Optional. JSON lines with blake3 hash chain (`prev_hash` field). Genesis hash: blake3(""). Recovers chain across restarts by reading last line. `sluice audit verify` walks log and reports broken links.

### MCP gateway

Three upstream transports: stdio (child processes), Streamable HTTP, WebSocket. All satisfy `MCPUpstream` interface. Tools namespaced as `<upstream>__<tool>`. Policy evaluation: deny/allow/ask priority. `ContentInspector` blocks arguments and redacts responses using regex (JSON parsed before matching to prevent unicode escape bypass). Per-upstream timeouts (default 120s).

`MCPHTTPHandler` serves `POST /mcp` and `DELETE /mcp` on port 3000 (alongside `/healthz`). Session tracking via `Mcp-Session-Id` header. SSE response support.

Agent connection: OpenClaw is configured once (via `openclaw mcp set`) to connect to `http://sluice:3000/mcp`. Sluice's `SelfBypass` auto-allows connections to its own MCP listener so the traffic is not policy-checked.

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
