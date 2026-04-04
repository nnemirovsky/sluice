package vault

import (
	"fmt"
	"os"
	"path/filepath"
)

// Provider resolves credential values by name. Implementations handle
// authentication, caching, and lease renewal internally.
type Provider interface {
	// Get retrieves a credential. Returns SecureBytes that must be
	// Released after use.
	Get(name string) (SecureBytes, error)

	// List returns available credential names. Providers that don't
	// support listing return nil, nil.
	List() ([]string, error)

	// Name returns the provider identifier for logging/config.
	Name() string
}

// VaultConfig controls which credential provider is used and how it's
// configured. Populated from the SQLite store's config table.
type VaultConfig struct {
	Provider  string
	Providers []string
	Dir       string
	HashiCorp HashiCorpConfig
}

// NewProviderFromConfig creates a Provider (or ChainProvider) based on config.
// If no provider is specified, defaults to the age-encrypted file backend.
func NewProviderFromConfig(cfg VaultConfig) (Provider, error) {
	if len(cfg.Providers) > 0 {
		var providers []Provider
		for _, name := range cfg.Providers {
			p, err := newSingleProvider(name, cfg)
			if err != nil {
				return nil, fmt.Errorf("provider %q: %w", name, err)
			}
			providers = append(providers, p)
		}
		return NewChainProvider(providers...), nil
	}

	name := cfg.Provider
	if name == "" {
		name = "age"
	}
	return newSingleProvider(name, cfg)
}

func newSingleProvider(name string, cfg VaultConfig) (Provider, error) {
	switch name {
	case "age":
		dir := cfg.Dir
		if dir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("determine home dir: %w", err)
			}
			dir = filepath.Join(home, ".sluice")
		}
		return NewStore(dir)
	case "env":
		return &EnvProvider{}, nil
	case "hashicorp":
		return NewHashiCorpProvider(cfg.HashiCorp)
	default:
		return nil, fmt.Errorf("unknown provider: %q", name)
	}
}

// ChainProvider tries multiple providers in order until one succeeds.
type ChainProvider struct {
	providers []Provider
}

// NewChainProvider creates a provider that tries each provider in order.
func NewChainProvider(providers ...Provider) *ChainProvider {
	return &ChainProvider{providers: providers}
}

func (c *ChainProvider) Get(name string) (SecureBytes, error) {
	var lastErr error
	for _, p := range c.providers {
		sb, err := p.Get(name)
		if err == nil {
			return sb, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no providers configured")
	}
	return SecureBytes{}, fmt.Errorf("no provider had credential %q: %w", name, lastErr)
}

func (c *ChainProvider) List() ([]string, error) {
	seen := make(map[string]bool)
	var all []string
	for _, p := range c.providers {
		names, err := p.List()
		if err != nil {
			continue
		}
		for _, n := range names {
			if !seen[n] {
				seen[n] = true
				all = append(all, n)
			}
		}
	}
	return all, nil
}

func (c *ChainProvider) Name() string { return "chain" }

// Providers returns the inner providers for inspection (e.g. extracting
// the age Store for credential management).
func (c *ChainProvider) Providers() []Provider { return c.providers }
