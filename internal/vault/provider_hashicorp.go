package vault

import (
	"fmt"
)

// HashiCorpConfig holds configuration for the HashiCorp Vault provider.
type HashiCorpConfig struct {
	Addr        string `toml:"addr"`
	Mount       string `toml:"mount"`
	Auth        string `toml:"auth"`
	RoleIDEnv   string `toml:"role_id_env"`
	SecretIDEnv string `toml:"secret_id_env"`
}

// HashiCorpProvider retrieves credentials from HashiCorp Vault's KV v2 engine.
// Requires VAULT_ADDR and either VAULT_TOKEN or AppRole credentials
// (VAULT_ROLE_ID + VAULT_SECRET_ID).
//
// This is a stub implementation. The full implementation will use
// github.com/hashicorp/vault/api for authentication, secret reads,
// and lease renewal for dynamic secrets.
type HashiCorpProvider struct {
	addr  string
	mount string
}

// NewHashiCorpProvider returns an error because the HashiCorp Vault provider
// is not yet implemented. This fails at construction time rather than silently
// succeeding and then failing on every credential lookup.
func NewHashiCorpProvider(cfg HashiCorpConfig) (*HashiCorpProvider, error) {
	return nil, fmt.Errorf("hashicorp vault provider is not yet implemented; use \"age\" or \"env\" provider instead")
}

func (p *HashiCorpProvider) Get(name string) (SecureBytes, error) {
	return SecureBytes{}, fmt.Errorf("hashicorp vault provider not yet implemented (would read %s/data/%s from %s)", p.mount, name, p.addr)
}

func (p *HashiCorpProvider) List() ([]string, error) { return nil, nil }
func (p *HashiCorpProvider) Name() string            { return "hashicorp" }
