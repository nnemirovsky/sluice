# Binding and Credential Management

## Overview

Add full CRUD for bindings and credential value replacement via both CLI and REST API.

Current gaps:
- No standalone CLI for binding management (only implicit via `cred add --destination`)
- No way to update a binding (must delete and recreate)
- No way to replace a credential's value without deleting and re-adding (loses bindings)
- No way to create multiple bindings per credential from CLI
- API has `POST/GET/DELETE` for bindings but no `PATCH`

## Context

- `cmd/sluice/cred.go` -- credential CLI. Creates one binding per `cred add --destination`. Uses `store.AddRuleAndBinding()`.
- `internal/store/store.go` -- store has: `AddBinding()`, `RemoveBinding()`, `ListBindings()`, `ListBindingsByCredential()`, `RemoveBindingsByCredential()`. No `UpdateBinding()`.
- `internal/store/store.go:529` -- `BindingOpts` struct: Ports, Header, Template, Protocols.
- `internal/vault/store.go` -- vault `Add()` overwrites existing credential (atomic temp+rename). Can be used for replacement.
- `api/openapi.yaml` -- has `POST/GET/DELETE` for bindings, `POST/GET/DELETE` for credentials. No `PATCH` for either.
- `internal/api/server.go` -- API handlers for bindings and credentials.
- CLI pattern: `cmd/sluice/policy.go` for rules CRUD, `cmd/sluice/mcp.go` for MCP upstream CRUD.

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- **CRITICAL: every task MUST include new/updated tests**
- **CRITICAL: all tests must pass before starting next task**
- Run `go test ./... -timeout 30s` after each change
- Maintain backward compatibility. Existing single `--destination` flag on `cred add` must keep working.

## Testing Strategy

- **Unit tests**: Go tests for CLI commands, store methods, API handlers
- **E2e tests**: Deferred to manual testing

## Progress Tracking

- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with + prefix
- Document issues/blockers with ! prefix

## Solution Overview

### 1. Binding CRUD (CLI + API)

```bash
sluice binding add <credential> --destination <host> [--ports 443] [--header Authorization] [--template "Bearer {value}"]
sluice binding list [--credential <name>]
sluice binding update <id> [--destination <host>] [--ports 443] [--header Authorization] [--template "Bearer {value}"]
sluice binding remove <id>
```

API additions: `PATCH /api/bindings/{id}` for updates.

### 2. Multi-binding on `cred add`

Instead of complex flag grouping (Go's flag package does not support positional grouping of repeatable flags), use a simple repeated `--destination` flag. Each destination gets the same ports/header/template from the shared flags. For per-destination customization, use `sluice binding add` after creation.

```bash
# Multiple destinations, same options
sluice cred add github_pat \
  --destination api.github.com \
  --destination uploads.github.com \
  --ports 443 --header Authorization --template "Bearer {value}"

# Per-destination customization via binding add
sluice cred add mykey
sluice binding add mykey --destination api.example.com --ports 443 --header X-API-Key
sluice binding add mykey --destination other.example.com --ports 8080 --header Authorization
```

Each `--destination` creates both an allow rule and a binding (matching current `cred add` behavior).

### 3. Credential value replacement

```bash
# Replace credential value (prompts for new value, never shows current)
sluice cred update <name>
```

API addition: `PATCH /api/credentials/{name}` with new value in request body.

The vault's `Add()` already does atomic overwrite (temp file + rename). For OAuth credentials, `cred update` prompts for new access/refresh tokens and rebuilds the JSON blob. Bindings and rules are preserved.

### Important notes

- CLI commands write to the DB/vault only. Changes take effect in the running proxy on SIGHUP, consistent with `policy add` and `cred add`.
- `binding add` does not validate credential exists in vault (consistent with existing behavior, avoids vault I/O overhead for remote providers).
- Credential values are never displayed. `cred update` only writes, never reads.

## What Goes Where

- **Implementation Steps**: store methods, CLI commands, API endpoints, tests
- **Post-Completion**: manual testing with running proxy

## Implementation Steps

### Task 1: Add `UpdateBinding` to store

**Files:**
- Modify: `internal/store/store.go`

- [x] Add `UpdateBinding(id int64, opts BindingUpdateOpts) error` method. `BindingUpdateOpts` has optional fields (Destination, Ports, Header, Template, Protocols) using pointer-nil-means-skip pattern (same as `ChannelUpdate`).
- [x] Write tests for UpdateBinding (update single field, update multiple fields, not found)
- [x] Run tests: `go test ./internal/store/ -timeout 30s`

### Task 2: Add `sluice binding` CLI subcommand

**Files:**
- Create: `cmd/sluice/binding.go`
- Modify: `cmd/sluice/main.go`

- [x] Add `case "binding"` dispatch in `cmd/sluice/main.go`
- [x] Create `cmd/sluice/binding.go` with subcommand registration
- [x] Implement `sluice binding add <credential> --destination <host> [--ports 443] [--header Authorization] [--template "Bearer {value}"]`: calls `store.AddBinding()`, also creates allow rule for the destination
- [x] Implement `sluice binding list [--credential <name>]`: calls `store.ListBindings()` or `store.ListBindingsByCredential()`, prints formatted output (ID, credential, destination, ports, header, template)
- [x] Implement `sluice binding update <id> [--destination <host>] [--ports 443] [--header Authorization] [--template "Bearer {value}"]`: calls `store.UpdateBinding()`, only updates provided flags
- [x] Implement `sluice binding remove <id>`: calls `store.RemoveBinding()`
- [x] Write tests for add (success, missing args)
- [x] Write tests for list (all, filtered by credential)
- [x] Write tests for update (single field, multiple fields, not found)
- [x] Write tests for remove (success, not found)
- [x] Run tests: `go test ./cmd/sluice/ -timeout 30s`

### Task 3: Support multiple `--destination` on `cred add`

**Files:**
- Modify: `cmd/sluice/cred.go`

- [x] Change `--destination` from single string to repeatable string slice flag
- [x] When multiple destinations provided: create one credential in vault, then call `AddRuleAndBinding()` for each destination (each gets the same ports/header/template from shared flags)
- [x] Maintain backward compatibility: single `--destination` still works as before
- [x] Write tests for single destination (backward compat)
- [x] Write tests for multiple destinations
- [x] Write tests for error cases (no destination provided still works for credential-only add)
- [x] Run tests: `go test ./cmd/sluice/ -timeout 30s`

### Task 4: Add `sluice cred update` for value replacement

**Files:**
- Modify: `cmd/sluice/cred.go`

- [x] Implement `sluice cred update <name>`: verify credential exists via `vault.List()`, prompt for new value via stdin/terminal (never show current value), call `vault.Add()` to overwrite
- [x] For OAuth credentials (detected via `IsOAuth()`): prompt for new access token and optionally refresh token, rebuild OAuth JSON blob, overwrite in vault, regenerate phantom files
- [x] Print confirmation message after successful update
- [x] Write tests for static credential update
- [x] Write tests for OAuth credential update (access only, access + refresh)
- [x] Write tests for update of nonexistent credential
- [x] Run tests: `go test ./cmd/sluice/ -timeout 30s`

### Task 5: API endpoints for binding update and credential update

**Files:**
- Modify: `api/openapi.yaml`
- Modify: `internal/api/server.go`
- Modify: `internal/api/api.gen.go` (regenerated)

- [x] Add `PATCH /api/bindings/{id}` to OpenAPI spec (request: BindingUpdate with optional destination, ports, header, template; response: Binding)
- [x] Add `PATCH /api/credentials/{name}` to OpenAPI spec (request: new value; response: 204). For OAuth type, request body includes access_token and optional refresh_token.
- [x] Regenerate API code: `go generate ./internal/api/`
- [x] Implement `PatchApiBindingsId` handler: validate input, call `store.UpdateBinding()`
- [x] Implement `PatchApiCredentialsName` handler: validate credential exists, call `vault.Add()` to overwrite. For OAuth: rebuild JSON blob. Regenerate phantom files.
- [x] Write tests for PATCH /api/bindings/{id} (success, not found, partial update)
- [x] Write tests for PATCH /api/credentials/{name} (static, OAuth, not found)
- [x] Run tests: `go test ./internal/api/ -timeout 30s`

### Task 6: Verify acceptance criteria

- [x] Verify all binding CRUD operations work via CLI
- [x] Verify all binding CRUD operations work via API
- [x] Verify `cred add` with multiple `--destination` flags creates multiple bindings
- [x] Verify `cred update` replaces value without affecting bindings
- [x] Verify `cred update` works for OAuth credentials
- [x] Verify existing single `--destination` behavior unchanged
- [x] Run full test suite: `go test ./... -v -timeout 30s`

### Task 7: [Final] Update documentation

- [ ] Update CLAUDE.md CLI subcommands with `sluice binding` and `sluice cred update`
- [ ] Move this plan to `docs/plans/completed/`

## Post-Completion

**Manual verification:**
- Create credential with 3 destinations in one command
- Add a 4th binding via `sluice binding add`
- Update a binding's header via `sluice binding update`
- Remove one binding, verify credential and other bindings remain
- Replace credential value via `sluice cred update`, verify proxy uses new value after SIGHUP
- Test PATCH endpoints via curl
