package vault

import (
	"fmt"
	"os"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
)

// HashiCorpConfig holds configuration for the HashiCorp Vault provider.
type HashiCorpConfig struct {
	// Addr is the Vault server address (e.g. "https://vault.example.com:8200").
	// Falls back to VAULT_ADDR env var if empty.
	Addr string `toml:"addr"`

	// Mount is the KV v2 secrets engine mount path (default "secret").
	Mount string `toml:"mount"`

	// Prefix is an optional path prefix prepended to credential names
	// when reading from Vault (e.g. "sluice/" reads "sluice/<name>").
	Prefix string `toml:"prefix"`

	// Auth selects the authentication method: "token" (default) or "approle".
	Auth string `toml:"auth"`

	// Token is the Vault token. Falls back to VAULT_TOKEN env var if empty.
	// Used when Auth is "token" or empty.
	Token string `toml:"token"`

	// RoleID is the AppRole role_id. Falls back to env var named by
	// RoleIDEnv if empty.
	RoleID string `toml:"role_id"`

	// SecretID is the AppRole secret_id. Falls back to env var named by
	// SecretIDEnv if empty.
	SecretID string `toml:"secret_id"`

	// RoleIDEnv is the env var name holding the AppRole role_id
	// (default "VAULT_ROLE_ID").
	RoleIDEnv string `toml:"role_id_env"`

	// SecretIDEnv is the env var name holding the AppRole secret_id
	// (default "VAULT_SECRET_ID").
	SecretIDEnv string `toml:"secret_id_env"`
}

// HashiCorpProvider retrieves credentials from HashiCorp Vault's KV v2 engine.
type HashiCorpProvider struct {
	client *vaultapi.Client
	mount  string
	prefix string
}

// NewHashiCorpProvider creates a provider connected to a HashiCorp Vault server.
// It authenticates immediately using the configured auth method (token or AppRole).
func NewHashiCorpProvider(cfg HashiCorpConfig) (*HashiCorpProvider, error) {
	apiCfg := vaultapi.DefaultConfig()

	if cfg.Addr != "" {
		apiCfg.Address = cfg.Addr
	}
	// If cfg.Addr is empty, the SDK reads VAULT_ADDR automatically.

	client, err := vaultapi.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("create vault client: %w", err)
	}

	mount := cfg.Mount
	if mount == "" {
		mount = "secret"
	}

	auth := cfg.Auth
	if auth == "" {
		auth = "token"
	}

	switch auth {
	case "token":
		token := cfg.Token
		if token == "" {
			// The SDK already reads VAULT_TOKEN, but we check explicitly
			// so we can give a clear error if neither is set.
			token = os.Getenv("VAULT_TOKEN")
		}
		if token == "" {
			return nil, fmt.Errorf("hashicorp vault: no token provided (set VAULT_TOKEN or config token)")
		}
		client.SetToken(token)

	case "approle":
		roleID := cfg.RoleID
		if roleID == "" {
			envName := cfg.RoleIDEnv
			if envName == "" {
				envName = "VAULT_ROLE_ID"
			}
			roleID = os.Getenv(envName)
		}
		if roleID == "" {
			return nil, fmt.Errorf("hashicorp vault: no role_id for approle auth")
		}

		secretID := cfg.SecretID
		if secretID == "" {
			envName := cfg.SecretIDEnv
			if envName == "" {
				envName = "VAULT_SECRET_ID"
			}
			secretID = os.Getenv(envName)
		}
		if secretID == "" {
			return nil, fmt.Errorf("hashicorp vault: no secret_id for approle auth")
		}

		loginData := map[string]interface{}{
			"role_id":   roleID,
			"secret_id": secretID,
		}
		resp, err := client.Logical().Write("auth/approle/login", loginData)
		if err != nil {
			return nil, fmt.Errorf("hashicorp vault approle login: %w", err)
		}
		if resp == nil || resp.Auth == nil {
			return nil, fmt.Errorf("hashicorp vault approle login: empty auth response")
		}
		client.SetToken(resp.Auth.ClientToken)

	default:
		return nil, fmt.Errorf("hashicorp vault: unknown auth method %q (use \"token\" or \"approle\")", auth)
	}

	return &HashiCorpProvider{
		client: client,
		mount:  mount,
		prefix: cfg.Prefix,
	}, nil
}

// Get retrieves a credential from Vault KV v2 at {mount}/data/{prefix}{name}.
// The secret must contain a "value" key. The returned SecureBytes must be
// Released after use.
func (p *HashiCorpProvider) Get(name string) (SecureBytes, error) {
	path := p.prefix + name
	secret, err := p.client.Logical().Read(p.mount + "/data/" + path)
	if err != nil {
		return SecureBytes{}, fmt.Errorf("vault read %s: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return SecureBytes{}, fmt.Errorf("vault: secret %q not found", name)
	}

	// KV v2 wraps data in a nested "data" key.
	data, ok := secret.Data["data"]
	if !ok {
		return SecureBytes{}, fmt.Errorf("vault: secret %q has no data field", name)
	}
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return SecureBytes{}, fmt.Errorf("vault: secret %q data is not a map", name)
	}

	val, ok := dataMap["value"]
	if !ok {
		return SecureBytes{}, fmt.Errorf("vault: secret %q has no \"value\" key", name)
	}
	str, ok := val.(string)
	if !ok {
		return SecureBytes{}, fmt.Errorf("vault: secret %q value is not a string", name)
	}

	return NewSecureBytes(str), nil
}

// List returns available secret names under {mount}/metadata/{prefix}.
func (p *HashiCorpProvider) List() ([]string, error) {
	secret, err := p.client.Logical().List(p.mount + "/metadata/" + p.prefix)
	if err != nil {
		return nil, fmt.Errorf("vault list: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}

	keys, ok := secret.Data["keys"]
	if !ok {
		return nil, nil
	}
	keyList, ok := keys.([]interface{})
	if !ok {
		return nil, fmt.Errorf("vault list: keys is not a list")
	}

	var names []string
	for _, k := range keyList {
		s, ok := k.(string)
		if !ok {
			continue
		}
		// Skip directory entries (end with /).
		if strings.HasSuffix(s, "/") {
			continue
		}
		names = append(names, s)
	}
	return names, nil
}

// Name returns "hashicorp".
func (p *HashiCorpProvider) Name() string { return "hashicorp" }
