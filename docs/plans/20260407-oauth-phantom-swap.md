# OAuth Dynamic Phantom Swap

## Overview

Extend sluice's phantom token system to handle OAuth credentials bidirectionally. Currently, phantom swap is request-only (phantom -> real in outbound requests). This adds response-side interception: when an OAuth token endpoint returns new access/refresh tokens, sluice captures the real tokens, stores them in the vault, and replaces them with phantom tokens in the response body before it reaches the agent.

This enables the agent to use OAuth-based providers (OpenAI Codex subscriptions, Google OAuth, etc.) while never seeing real credentials. The entire OAuth lifecycle (initial auth, token refresh, token rotation) is handled transparently through phantom tokens.

## Context

- `internal/proxy/inject.go` -- MITM request handler with three-pass phantom injection. `injectCredentials()` (line 468) handles request-side swap. goproxy `OnResponse()` available but only used for WebSocket upgrades currently.
- `internal/vault/store.go` -- Age-encrypted credential storage. `Get()` returns `SecureBytes`, `Add()` stores encrypted.
- `internal/vault/phantom.go` -- Phantom token generation. `GeneratePhantomToken()` creates format-matching placeholders.
- `internal/vault/binding.go` -- `BindingResolver` maps (destination, port, protocol) to credentials. `CredentialsForDestination()` returns all bound credentials.
- `internal/proxy/server.go` -- `StoreResolver()` and `StoreEngine()` do atomic hot-reload of policy and bindings.
- `internal/store/store.go` -- SQLite store with `rules`, `bindings`, `config` tables. Schema in `migrations/000001_init.up.sql`.
- `internal/mcp/inspect.go` -- `ContentInspector` with `RedactResponse()` pattern for response modification.
- `internal/proxy/quic.go` -- Response body reading pattern (line 464-483): `io.ReadAll` + size limit + redact rules.

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- **CRITICAL: every task MUST include new/updated tests**
- **CRITICAL: all tests must pass before starting next task**
- Run `go test ./... -timeout 30s` after each change
- Maintain backward compatibility. Existing non-OAuth credentials must work unchanged.

## Testing Strategy

- **Unit tests**: Go tests for OAuth credential type, response interception, token parsing, vault update, phantom generation
- **Integration tests**: MITM proxy with mock OAuth server returning token responses
- **E2e tests**: Deferred to manual testing

## Progress Tracking

- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with + prefix
- Document issues/blockers with ! prefix

## Solution Overview

### Credential types

Add a `type` field to credentials. Two types:
- `static` (default, current behavior): simple phantom -> real swap in requests
- `oauth`: bidirectional swap with response interception

OAuth credentials store a JSON blob in the vault (real tokens only, no phantom values):

```json
{
  "access_token": "real-access-token",
  "refresh_token": "real-refresh-token",
  "token_url": "https://auth0.openai.com/oauth/token",
  "expires_at": "2026-04-07T12:00:00Z"
}
```

Phantom tokens are deterministic, derived at runtime from the credential name using the existing `SLUICE_PHANTOM:` prefix scheme:
- Access phantom: `SLUICE_PHANTOM:credname.access`
- Refresh phantom: `SLUICE_PHANTOM:credname.refresh`

The agent sees these deterministic phantoms. The MITM proxy resolves them to real tokens by loading the OAuth JSON from vault and extracting the corresponding field.

### Response interception flow

1. Agent sends request to token URL with phantom refresh token
2. Sluice request handler: swaps `SLUICE_PHANTOM:cred.refresh` -> real refresh token
3. Upstream returns JSON response: `{ "access_token": "new-real", "refresh_token": "new-real-refresh", "expires_in": 3600 }`
4. Sluice response handler detects this is a response from a configured `token_url`
5. Sluice extracts `access_token` and `refresh_token` from response JSON
6. Sluice replaces real tokens with deterministic phantoms in response body **first** (before any I/O)
7. Sluice returns the modified response to the agent immediately
8. Sluice **asynchronously** updates vault with new real tokens and writes phantom files to shared volume

Token replacement in the response body is independent of vault persistence. If the vault write fails, the agent still receives phantom tokens (not real ones). The vault write is retried or logged, and the next refresh cycle will correct the state.

### Concurrent refresh protection

Many OAuth providers invalidate refresh tokens on use (rotation). If two requests trigger simultaneous refresh, the second refresh would use an already-invalidated token. Solution: use `golang.org/x/sync/singleflight` keyed on credential name. Only one refresh response is processed at a time per credential. Concurrent requests reuse the first result.

### Token URL matching

The `token_url` from the OAuth credential is parsed at credential-add time. During MITM response handling, sluice checks if the response's request URL matches any configured `token_url`. Only matching responses are intercepted.

### CLI interface

```bash
# Add OAuth credential (tokens read from stdin/prompt, not CLI flags, to avoid shell history exposure)
sluice cred add openai_oauth \
  --type oauth \
  --token-url https://auth0.openai.com/oauth/token \
  --destination api.openai.com \
  --ports 443
# Prompts for: access token, refresh token (optional)

# List shows type
sluice cred list
# NAME           TYPE    DESTINATION
# openai_oauth   oauth   api.openai.com
# github_pat     static  api.github.com
```

### Data model changes

**Vault**: OAuth credentials stored as JSON blob (same `.age` file, different content format). `Get()` returns the full JSON. New `ParseOAuth()` function parses and returns structured `OAuthCredential`. Vault stores only real token data, not phantom values (phantoms are deterministic).

**Store**: New `credential_meta` table (not on `bindings` table, since one credential can have multiple bindings). One row per credential: `name` (PK), `cred_type`, `token_url`. Avoids duplication across bindings.

**Phantoms**: OAuth credentials get two phantom files written to the phantoms volume: `CRED_NAME_ACCESS` and `CRED_NAME_REFRESH`. For the MITM proxy, deterministic `SLUICE_PHANTOM:name.access` / `SLUICE_PHANTOM:name.refresh` tokens are used.

## Technical Details

### Response handler registration

```go
// In NewInjector(), add response handler alongside existing WebSocket handler
proxy.OnResponse().DoFunc(inj.interceptOAuthResponse)
```

### Response interception function

```go
func (inj *Injector) interceptOAuthResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
    // 1. Check if request URL matches any configured token_url
    // 2. If not, return resp unchanged
    // 3. Read response body (same size limit as requests)
    // 4. Parse JSON, extract access_token/refresh_token
    // 5. Update vault with new real tokens
    // 6. Generate new phantom tokens
    // 7. Replace real tokens with phantoms in response body
    // 8. Update response body and content-length
    // 9. Trigger phantom file reload
    return resp
}
```

### Token URL index

```go
// oauthIndex maps token URLs to credential names for fast lookup
type oauthIndex struct {
    entries []oauthEntry
}

type oauthEntry struct {
    tokenURL   *url.URL  // parsed token URL
    credential string    // credential name in vault
}
```

Stored in `Injector` as `*atomic.Pointer[oauthIndex]` for hot-reload. Rebuilt when credentials change.

### Phantom token mapping for OAuth

Phantom tokens are deterministic, derived from the credential name at runtime:
- Access phantom: `SLUICE_PHANTOM:credname.access`
- Refresh phantom: `SLUICE_PHANTOM:credname.refresh`

Vault JSON stores only real tokens (no phantom values):

```json
{
  "access_token": "real-access",
  "refresh_token": "real-refresh",
  "token_url": "https://auth0.openai.com/oauth/token",
  "expires_at": "2026-04-07T12:00:00Z"
}
```

For phantom files on the shared volume (what the agent loads as env vars), `GeneratePhantomToken()` produces format-matching values (e.g., `sk-phantom-xxx` for OpenAI). These are separate from the MITM deterministic tokens. The MITM proxy handles `SLUICE_PHANTOM:` tokens. The container phantoms are for the agent's SDK initialization.

### Security considerations

- Token replacement in response body happens **before** vault write (response-first, persist-async)
- If vault write fails, agent still receives phantom tokens, not real ones
- Real tokens handled via `SecureBytes` with `Release()` after vault write
- Response body modification uses same size limits as request body (16 MiB)
- Token URL matching is exact (scheme + host + path), not prefix
- Responses with status 200-299 are intercepted. Both `application/json` and `application/x-www-form-urlencoded` content types are supported (per RFC 6749).
- When replacing response body, clear `Transfer-Encoding: chunked` and set explicit `Content-Length`
- `singleflight` prevents concurrent refresh race conditions
- If refresh_token is missing from a token response, the existing refresh_token is preserved in vault

## What Goes Where

- **Implementation Steps**: vault changes, store schema, CLI, response handler, phantom generation, hot-reload
- **Post-Completion**: manual testing with real OAuth provider, OpenClaw integration testing

## Implementation Steps

### Task 1: Add OAuth credential type to vault

**Files:**
- Create: `internal/vault/oauth.go`
- Modify: `internal/vault/store.go`

- [ ] Create `internal/vault/oauth.go` with `OAuthCredential` struct (AccessToken, RefreshToken, TokenURL, ExpiresAt). No phantom values in the struct (phantoms are deterministic, derived from credential name at runtime).
- [ ] Add `ParseOAuth(data []byte) (*OAuthCredential, error)` to parse JSON blob from vault
- [ ] Add `(*OAuthCredential) Marshal() ([]byte, error)` to serialize back to JSON
- [ ] Add `(*OAuthCredential) UpdateTokens(access, refresh string, expiresIn int)` that updates real tokens and computes ExpiresAt. If refresh is empty, preserve existing refresh_token.
- [ ] Add `IsOAuth(data []byte) bool` function that checks if credential content is valid OAuth JSON (has access_token + token_url fields)
- [ ] Write tests for OAuthCredential parse/marshal round-trip
- [ ] Write tests for UpdateTokens (both tokens, access only, refresh preserved)
- [ ] Write tests for IsOAuth detection (positive, negative, malformed JSON)
- [ ] Run tests: `go test ./internal/vault/ -timeout 30s`

### Task 2: Add credential_meta table to store schema

**Files:**
- Create: `internal/store/migrations/000002_credential_meta.up.sql`
- Create: `internal/store/migrations/000002_credential_meta.down.sql`
- Modify: `internal/store/store.go`

- [ ] Create migration: new `credential_meta` table with `name TEXT PRIMARY KEY`, `cred_type TEXT NOT NULL DEFAULT 'static'`, `token_url TEXT`, `created_at DATETIME DEFAULT CURRENT_TIMESTAMP`
- [ ] Add `CredentialMeta` struct to store (Name, CredType, TokenURL, CreatedAt)
- [ ] Add `AddCredentialMeta(name, credType, tokenURL string) error`
- [ ] Add `GetCredentialMeta(name string) (*CredentialMeta, error)`
- [ ] Add `ListCredentialMeta() ([]CredentialMeta, error)`
- [ ] Add `RemoveCredentialMeta(name string) error` (cascade with credential removal)
- [ ] Write tests for migration (up and down)
- [ ] Write tests for CRUD operations on credential_meta
- [ ] Run tests: `go test ./internal/store/ -timeout 30s`

### Task 3: Extend CLI for OAuth credentials

**Files:**
- Modify: `cmd/sluice/cred.go`

- [ ] Add `--type` flag to `sluice cred add` (default: "static", options: "static", "oauth")
- [ ] Add `--token-url` flag (required when type=oauth)
- [ ] When type=oauth: prompt for access token and refresh token via stdin/terminal (not CLI flags, to avoid shell history exposure). Support stdin pipe for scripted use.
- [ ] When type=oauth: create OAuthCredential JSON, store in vault, create credential_meta row, create binding with destination
- [ ] Generate two phantom files for OAuth: `CRED_NAME_ACCESS` and `CRED_NAME_REFRESH`
- [ ] Update `sluice cred list` to show credential type column (join with credential_meta)
- [ ] Update `sluice cred remove` to also delete credential_meta row
- [ ] Write tests for CLI flag parsing and validation
- [ ] Write tests for OAuth credential creation flow
- [ ] Run tests: `go test ./cmd/sluice/ -timeout 30s`

### Task 4: Build OAuth token URL index

**Files:**
- Create: `internal/proxy/oauth_index.go`
- Modify: `internal/proxy/inject.go`

- [ ] Create `internal/proxy/oauth_index.go` with `OAuthIndex` struct: maps token URLs to credential names
- [ ] Add `NewOAuthIndex(metas []store.CredentialMeta) *OAuthIndex` that filters oauth-type entries and parses token URLs
- [ ] Add `Match(requestURL *url.URL) (credName string, ok bool)` for exact URL matching (scheme + host + path)
- [ ] Add `oauthIndex *atomic.Pointer[OAuthIndex]` field to `Injector` struct
- [ ] Build and store index during `NewInjector()` initialization
- [ ] Add `UpdateOAuthIndex(metas []store.CredentialMeta)` for hot-reload (called from StoreResolver path)
- [ ] Write tests for index building and matching (exact match, no match, multiple entries)
- [ ] Write tests for hot-reload (index swap)
- [ ] Run tests: `go test ./internal/proxy/ -timeout 30s`

### Task 5: Implement response-side OAuth token interception

**Files:**
- Create: `internal/proxy/oauth_response.go`
- Modify: `internal/proxy/inject.go`

- [ ] Add `golang.org/x/sync/singleflight` dependency: `go get golang.org/x/sync`
- [ ] Add `refreshGroup singleflight.Group` field to `Injector` struct for concurrent refresh dedup
- [ ] Register response handler in `NewInjector()`: `proxy.OnResponse().DoFunc(inj.interceptOAuthResponse)`
- [ ] Implement `interceptOAuthResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response`:
  - Check response status is 200-299
  - Match request URL against OAuth index. If no match, return unchanged.
  - Use `singleflight.Do(credName, ...)` to prevent concurrent refresh race
  - Read response body (same 16 MiB limit)
  - Parse response body: support both `application/json` and `application/x-www-form-urlencoded` (per RFC 6749)
  - Extract `access_token`, `refresh_token` (optional), `expires_in`
  - Replace real tokens with deterministic phantoms (`SLUICE_PHANTOM:cred.access`, `SLUICE_PHANTOM:cred.refresh`) in response body **first**
  - Clear `Transfer-Encoding` header, set explicit `Content-Length`
  - Update `resp.Body` with modified body
  - **Asynchronously** (goroutine): load OAuthCredential from vault, call `UpdateTokens()`, store back, write phantom files, signal agent reload
  - Use `SecureBytes` for real token handling in the async goroutine, `Release()` after vault write
- [ ] Handle edge cases: missing refresh_token in response (preserve existing), non-JSON/non-form content type (pass through), read errors (pass through unchanged)
- [ ] If vault write fails: log error. Agent already has phantom tokens. Next refresh cycle will correct.
- [ ] Write tests with mock goproxy context and httptest response (JSON format)
- [ ] Write tests for form-encoded token responses
- [ ] Write tests for partial responses (only access_token, no refresh_token)
- [ ] Write tests for concurrent refresh dedup (singleflight)
- [ ] Write tests for error cases (non-2xx, non-JSON, oversized body, vault write failure)
- [ ] Run tests: `go test ./internal/proxy/ -timeout 30s`

### Task 6: Request-side OAuth phantom swap

**Files:**
- Modify: `internal/proxy/inject.go`

- [ ] Extend `injectCredentials()` to detect OAuth credentials: check if credential name exists in OAuth index (or if vault content is OAuth JSON via `IsOAuth()`)
- [ ] For OAuth credentials: parse vault JSON via `ParseOAuth()`, extract real access_token and refresh_token, build two phantom pairs: `[{SLUICE_PHANTOM:cred.access, realAccess}, {SLUICE_PHANTOM:cred.refresh, realRefresh}]`
- [ ] Add OAuth phantom pairs to the scoped replacement list alongside static phantom pairs
- [ ] Ensure OAuth phantoms (`SLUICE_PHANTOM:*.access`, `SLUICE_PHANTOM:*.refresh`) are included in the unbound strip pass (pass 3) via extended `stripUnboundPhantoms()`
- [ ] Use `SecureBytes` for real tokens, `Release()` after replacement
- [ ] Write tests: request with OAuth phantom access token gets swapped to real
- [ ] Write tests: request with OAuth phantom refresh token gets swapped to real
- [ ] Write tests: mixed static + OAuth credentials on same request
- [ ] Write tests: unbound OAuth phantom tokens are stripped
- [ ] Run tests: `go test ./internal/proxy/ -timeout 30s`

### Task 7: Hot-reload and phantom file management

**Files:**
- Modify: `internal/proxy/server.go`
- Modify: `internal/vault/phantom.go`

- [ ] Extend `GeneratePhantomEnv()` to handle OAuth credentials: detect OAuth JSON in vault, write two files per OAuth credential (`CRED_ACCESS`, `CRED_REFRESH`) with format-matching phantom values
- [ ] Add `WriteOAuthPhantoms(dir string, cred *OAuthCredential, name string) error` to write phantom files for a single OAuth credential (called from async goroutine in response handler)
- [ ] Ensure async phantom file write in response handler (Task 5) does not block HTTP response delivery
- [ ] Rebuild OAuth index on `StoreResolver()` calls (when credential_meta changes)
- [ ] Write tests for OAuth phantom file generation (two files created, correct naming)
- [ ] Write tests for hot-reload path (credential_meta change triggers index rebuild)
- [ ] Run tests: `go test ./... -timeout 30s`

### Task 8: Verify acceptance criteria

- [ ] Verify static credentials still work unchanged (backward compatibility)
- [ ] Verify OAuth credential can be added via CLI with --type oauth
- [ ] Verify phantom files are generated for OAuth (access + refresh)
- [ ] Verify request-side swap works for OAuth access token
- [ ] Verify request-side swap works for OAuth refresh token
- [ ] Verify response interception captures new tokens from token endpoint
- [ ] Verify vault is updated with rotated tokens
- [ ] Verify new phantoms are written and agent reload signaled
- [ ] Verify unbound OAuth phantoms are stripped from requests
- [ ] Run full test suite: `go test ./... -v -timeout 30s`
- [ ] Run e2e tests: `go test -tags=e2e ./e2e/ -v -count=1 -timeout=300s`

### Task 9: [Final] Update documentation

- [ ] Update CLAUDE.md with OAuth credential type documentation
- [ ] Update README.md: add section on dynamic OAuth/JWT token management (transparent access/refresh token rotation through phantom swap, subscription-based auth support)
- [ ] Move this plan to `docs/plans/completed/`

## Post-Completion

**Manual verification:**
- Test with real OpenAI Codex OAuth flow (onboard locally, feed tokens to sluice)
- Test token refresh cycle end-to-end (let access token expire, verify transparent refresh)
- Test with OpenClaw in Docker container behind sluice MITM
- Verify phantom tokens never appear in audit log

**Future work:**
- REST API support for OAuth credential CRUD (OpenAPI spec + handlers)
- Sluice-driven proactive token refresh (refresh before expiry, not on 401)
- OAuth discovery (auto-detect token_url from .well-known/openid-configuration)
- Multiple OAuth providers per agent (OpenAI + Google + Anthropic simultaneously)
- Token usage metrics in audit log (track refresh frequency, expiry patterns)
