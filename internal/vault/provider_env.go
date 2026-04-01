package vault

import (
	"fmt"
	"os"
)

// EnvProvider resolves credentials from environment variables.
// The credential name is used directly as the env var name.
type EnvProvider struct{}

func (p *EnvProvider) Get(name string) (SecureBytes, error) {
	val := os.Getenv(name)
	if val == "" {
		return SecureBytes{}, fmt.Errorf("env var %q not set", name)
	}
	return NewSecureBytes(val), nil
}

func (p *EnvProvider) List() ([]string, error) { return nil, nil }
func (p *EnvProvider) Name() string            { return "env" }
