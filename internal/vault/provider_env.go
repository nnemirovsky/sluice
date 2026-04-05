package vault

import (
	"fmt"
	"os"
)

// EnvProvider resolves credentials from environment variables.
// The credential name is used directly as the env var name.
type EnvProvider struct{}

// Get resolves a credential from the environment variable with the given name.
func (p *EnvProvider) Get(name string) (SecureBytes, error) {
	val, ok := os.LookupEnv(name)
	if !ok {
		return SecureBytes{}, fmt.Errorf("env var %q not set", name)
	}
	return NewSecureBytes(val), nil
}

// List returns nil since environment variable enumeration is not supported.
func (p *EnvProvider) List() ([]string, error) { return nil, nil }

// Name returns the provider identifier.
func (p *EnvProvider) Name() string { return "env" }
