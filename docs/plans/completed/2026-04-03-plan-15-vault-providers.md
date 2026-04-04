# Plan 15: Additional Vault Providers

## Overview

Add credential providers for 1Password, Bitwarden Secrets Manager, KeePass (.kdbx file), and Gopass (pass-compatible with age backend). These are the four providers with stable programmatic APIs that work in headless/Docker environments without CGO.

**Problem:** Sluice currently supports age-encrypted files (default), environment variables, and HashiCorp Vault. Users who manage credentials in 1Password, Bitwarden, KeePass, or Gopass must manually export and re-import credentials. There's no direct integration.

**Solution:** Implement four new providers using the existing `vault.Provider` interface. Each provider retrieves secrets on-demand from its respective backend. No credential duplication needed.

**Depends on:** Plan 9 (unified store, typed config with vault_provider field).

## Context

**Existing provider interface (`internal/vault/provider.go`):**
```go
type Provider interface {
    Get(name string) (SecureBytes, error)
    List() ([]string, error)
    Name() string
}
```

New providers implement this interface. `NewProviderFromConfig` factory function routes to the correct implementation based on `vault_provider` config value.

**Provider feasibility (researched 2026-04-03):**

| Provider | Go SDK/Library | Auth Method | Headless/Docker | CGO needed |
|----------|---------------|-------------|-----------------|------------|
| 1Password | `1password/onepassword-sdk-go` (official) | Service Account Token (`OP_SERVICE_ACCOUNT_TOKEN`) | Excellent | No |
| Bitwarden BWS | `bitwarden/sdk-go` (official) | Access Token | Excellent | No |
| KeePass (.kdbx) | `tobischo/gokeepasslib/v3` (pure Go) | Master password or key file | Excellent | No |
| Gopass | `gopasspw/gopass` or CLI wrapper | GPG key or age identity | Good (with age) | No |

**Excluded (with reasons):**
- **Apple Keychain**: Requires CGO (`Security.framework`), needs logged-in GUI session, not usable in Docker
- **Doppler**: Community SDK only, CLI-first design better suited for env injection (not programmatic retrieval)
- **AWS/GCP/Azure Secret Managers**: Good candidates but cloud-specific. HashiCorp Vault already covers the "external secret manager" use case. Could be added later.

**Files that will change:**
- Create: `internal/vault/provider_1password.go`
- Create: `internal/vault/provider_1password_test.go`
- Create: `internal/vault/provider_bitwarden.go`
- Create: `internal/vault/provider_bitwarden_test.go`
- Create: `internal/vault/provider_keepass.go`
- Create: `internal/vault/provider_keepass_test.go`
- Create: `internal/vault/provider_gopass.go`
- Create: `internal/vault/provider_gopass_test.go`
- Modify: `internal/vault/provider.go` (factory function, config types)
- Modify: `internal/store/store.go` (config columns for new providers)
- Migration: `internal/store/migrations/000004_vault_providers.up.sql`

**New dependencies:**
- `github.com/1password/onepassword-sdk-go`
- `github.com/bitwarden/sdk-go`
- `github.com/tobischo/gokeepasslib/v3`

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- All tests must pass before starting next task
- Each provider is independent and can be developed in parallel

## Testing Strategy

- **Unit tests**: Each provider tested with mock backends (mock HTTP servers for 1Password/Bitwarden, temp .kdbx files for KeePass, temp gopass store for Gopass).
- **No live service tests**: All tests use mocks. Live integration is manual post-completion verification.

## Implementation Steps

### Task 1: Add provider config columns via migration

**Files:**
- Create: `internal/store/migrations/000004_vault_providers.up.sql`
- Create: `internal/store/migrations/000004_vault_providers.down.sql`
- Modify: `internal/store/store.go` (update Config struct)

```sql
ALTER TABLE config ADD COLUMN vault_1password_token TEXT;
ALTER TABLE config ADD COLUMN vault_1password_vault TEXT;
ALTER TABLE config ADD COLUMN vault_bitwarden_token TEXT;
ALTER TABLE config ADD COLUMN vault_bitwarden_org_id TEXT;
ALTER TABLE config ADD COLUMN vault_keepass_path TEXT;
ALTER TABLE config ADD COLUMN vault_keepass_key_file TEXT;
ALTER TABLE config ADD COLUMN vault_gopass_store TEXT;
```

- [ ] Create migration 000004 adding vault provider config columns
- [ ] Update `Config` struct with new typed fields
- [ ] Update `GetConfig` and `UpdateConfig` for new columns
- [ ] Write tests for migration and config CRUD with new fields
- [ ] Run tests: `go test ./internal/store/ -v -timeout 30s`

### Task 2: 1Password provider via official Go SDK

1Password Service Accounts provide non-interactive access with granular vault-level permissions. The SDK resolves `op://vault/item/field` references.

**Files:**
- Create: `internal/vault/provider_1password.go`
- Create: `internal/vault/provider_1password_test.go`

**Auth:** `OP_SERVICE_ACCOUNT_TOKEN` env var (or from config).

**Mapping:** Sluice credential name -> 1Password item name. `Get("anthropic_api_key")` resolves to `op://<vault>/anthropic_api_key/credential` (or a configurable field).

- [ ] Add `github.com/1password/onepassword-sdk-go` dependency
- [ ] Implement `OnePasswordProvider` struct with `NewOnePasswordProvider(token, vaultName string)`
- [ ] Implement `Get(name)`: resolve `op://<vault>/<name>/credential` via SDK. Return as `SecureBytes`.
- [ ] Implement `List()`: list items in the configured vault via SDK
- [ ] Implement `Name()`: return "1password"
- [ ] Support configurable field name (default "credential", overridable for items with non-standard field names)
- [ ] Write tests with mock (the SDK supports a mock client or use httptest to mock the 1Password API)
- [ ] Write tests for error cases (item not found, auth failure, network error)
- [ ] Run tests: `go test ./internal/vault/ -v -timeout 30s`

### Task 3: Bitwarden Secrets Manager provider

Bitwarden Secrets Manager (BWS) is a dedicated machine-to-machine product with an official Go SDK and access tokens.

**Files:**
- Create: `internal/vault/provider_bitwarden.go`
- Create: `internal/vault/provider_bitwarden_test.go`

**Auth:** BWS access token (env var `BWS_ACCESS_TOKEN` or from config).

**Mapping:** Sluice credential name -> BWS secret name. Secrets are stored as key-value pairs in BWS projects.

- [ ] Add `github.com/bitwarden/sdk-go` dependency
- [ ] Implement `BitwardenProvider` struct with `NewBitwardenProvider(token, orgID string)`
- [ ] Implement `Get(name)`: list secrets, find by name, return value as `SecureBytes`
- [ ] Implement `List()`: list all secret names in the configured organization
- [ ] Implement `Name()`: return "bitwarden"
- [ ] Cache the secret list briefly (30s TTL) to avoid repeated API calls on rapid Get sequences
- [ ] Write tests with mock HTTP server simulating BWS API responses
- [ ] Write tests for error cases (secret not found, auth failure)
- [ ] Run tests: `go test ./internal/vault/ -v -timeout 30s`

### Task 4: KeePass (.kdbx) file provider

Read credentials directly from a KeePass database file. Pure Go, no external daemon needed. The .kdbx file can be mounted as a volume in Docker.

**Files:**
- Create: `internal/vault/provider_keepass.go`
- Create: `internal/vault/provider_keepass_test.go`

**Auth:** Master password (from env var `KEEPASS_PASSWORD`) and/or key file (from config path).

**Mapping:** Sluice credential name -> KeePass entry title. `Get("anthropic_api_key")` finds the entry titled "anthropic_api_key" and returns its password field.

- [ ] Add `github.com/tobischo/gokeepasslib/v3` dependency
- [ ] Implement `KeePassProvider` struct with `NewKeePassProvider(dbPath, password, keyFilePath string)`
- [ ] On creation: open and decrypt the .kdbx file, build an in-memory index of entry titles -> passwords
- [ ] Implement `Get(name)`: look up entry by title, return password as `SecureBytes`
- [ ] Implement `List()`: return all entry titles
- [ ] Implement `Name()`: return "keepass"
- [ ] Support searching in all groups (not just root)
- [ ] Re-read the file on `Get` if the file modification time changed (supports external KeePass edits)
- [ ] Write tests with temp .kdbx files created using the library
- [ ] Write tests for error cases (wrong password, missing file, entry not found)
- [ ] Run tests: `go test ./internal/vault/ -v -timeout 30s`

### Task 5: Gopass provider

Gopass is the modern Go rewrite of pass (password-store.org). Supports age encryption natively (no GPG needed). Credentials are stored as files in a directory tree.

**Files:**
- Create: `internal/vault/provider_gopass.go`
- Create: `internal/vault/provider_gopass_test.go`

**Auth:** Age identity file (same as sluice's default vault) or GPG key.

**Approach:** Shell out to `gopass show <name>` CLI. This is simpler and more maintainable than importing gopass internals. The CLI handles all decryption.

- [ ] Implement `GopassProvider` struct with `NewGopassProvider(storePath string)` (storePath optional, defaults to `~/.local/share/gopass/stores/root`)
- [ ] Implement `Get(name)`: run `gopass show -o <name>` (output only, no meta), capture stdout as `SecureBytes`
- [ ] Implement `List()`: run `gopass ls --flat`, parse output
- [ ] Implement `Name()`: return "gopass"
- [ ] Handle case where `gopass` binary is not installed (return clear error on provider creation)
- [ ] Write tests with a temp gopass store (initialize with `gopass init` in temp dir)
- [ ] Write tests for error cases (gopass not installed, entry not found)
- [ ] Run tests: `go test ./internal/vault/ -v -timeout 30s`

### Task 6: Wire providers into factory and config

Update the provider factory to support new provider types. Update config TOML import for new vault sections.

**Files:**
- Modify: `internal/vault/provider.go` (NewProviderFromConfig factory)
- Modify: `internal/store/import.go` (TOML import for new vault config)
- Modify: `internal/vault/provider_test.go`

- [ ] Add `"1password"`, `"bitwarden"`, `"keepass"`, `"gopass"` cases to `NewProviderFromConfig`
- [ ] Read provider-specific config from the typed config table
- [ ] Support chain provider: `vault_providers = ["1password", "age"]` tries 1Password first, falls back to local age vault
- [ ] Update TOML import to parse new vault config sections
- [ ] Write tests for factory with each new provider type
- [ ] Write tests for chain provider with mixed backends
- [ ] Run tests: `go test ./internal/vault/ -v -timeout 30s`

### Task 7: Verify acceptance criteria

- [ ] Verify 1Password provider retrieves secrets via Service Account token
- [ ] Verify Bitwarden BWS provider retrieves secrets via access token
- [ ] Verify KeePass provider reads credentials from .kdbx file
- [ ] Verify Gopass provider retrieves secrets via CLI
- [ ] Verify chain provider falls through (first provider that has the secret wins)
- [ ] Verify phantom token generation works with all provider backends
- [ ] Verify MITM credential injection works regardless of provider backend
- [ ] Verify `vault_provider = "1password"` in config.toml seeds correctly
- [ ] Run full test suite: `go test ./... -v -timeout 60s -race`
- [ ] Run linter: `go vet ./...`

### Task 8: [Final] Update documentation

- [ ] Update CLAUDE.md: document all vault providers (age, env, hashicorp, 1password, bitwarden, keepass, gopass)
- [ ] Update CLAUDE.md: document provider chain configuration
- [ ] Update examples/config.toml: add commented examples for each provider
- [ ] Update CONTRIBUTING.md: note how to add new vault providers (implement Provider interface)

## Technical Details

### Provider configuration in config.toml

```toml
# Single provider:
[vault]
provider = "1password"

# Or chain (try in order, first hit wins):
[vault]
providers = ["1password", "age"]

# 1Password config (Service Account):
# Auth via OP_SERVICE_ACCOUNT_TOKEN env var
[vault.1password]
vault = "sluice-credentials"     # 1Password vault name
field = "credential"             # item field to read (default: "credential")

# Bitwarden Secrets Manager:
# Auth via BWS_ACCESS_TOKEN env var
[vault.bitwarden]
org_id = "your-org-uuid"

# KeePass:
# Auth via KEEPASS_PASSWORD env var
[vault.keepass]
path = "/path/to/credentials.kdbx"
key_file = "/path/to/keyfile"    # optional

# Gopass:
[vault.gopass]
store = "~/.local/share/gopass/stores/root"  # optional, uses default
```

### Provider selection logic

```go
func NewProviderFromConfig(cfg Config) (Provider, error) {
    if len(cfg.Providers) > 0 {
        // Chain mode: try each in order
        var providers []Provider
        for _, name := range cfg.Providers {
            p, err := createProvider(name, cfg)
            if err != nil { return nil, err }
            providers = append(providers, p)
        }
        return NewChainProvider(providers), nil
    }
    // Single provider mode
    return createProvider(cfg.Provider, cfg)
}
```

### SecureBytes integration

All providers return `SecureBytes` from `Get()`. The caller calls `Release()` after use. For providers that use HTTP (1Password, Bitwarden), the response bytes are copied into `SecureBytes` and the HTTP response body is discarded. For file-based providers (KeePass, Gopass), the decrypted value is copied into `SecureBytes` and the source buffer is zeroed.

## Post-Completion

**Manual verification:**
- Test 1Password provider with a real Service Account (free tier supports this)
- Test Bitwarden BWS with a real access token
- Test KeePass with a .kdbx file from KeePassXC
- Test Gopass with an age-encrypted store
- Verify chain provider failover (1Password unavailable, falls back to age)

**Excluded providers (documented for future reference):**
- **Apple Keychain**: Requires CGO + GUI session. Not viable for Docker.
- **AWS/GCP/Azure Secret Managers**: Cloud-specific. Add if user demand materializes.
- **Doppler**: CLI-first. Better used as env injection (`doppler run -- sluice`), not as a programmatic provider.
- **Infisical**: Good candidate for future. Has Go SDK. Evaluate after initial providers ship.
