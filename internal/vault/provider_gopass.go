package vault

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// GopassConfig holds configuration for the Gopass provider.
type GopassConfig struct {
	// StorePath is the path to the gopass store directory.
	// Optional: defaults to gopass's default store location.
	StorePath string
}

// gopassClient abstracts gopass CLI operations for testing.
type gopassClient interface {
	show(name string) (string, error)
	list() ([]string, error)
}

// gopassCLIClient wraps the gopass CLI.
type gopassCLIClient struct {
	storePath string
}

func (c *gopassCLIClient) show(name string) (string, error) {
	cmd := exec.Command("gopass", "show", "-o", "--", name)
	if c.storePath != "" {
		cmd.Env = append(cmd.Environ(), "GOPASS_HOMEDIR="+c.storePath)
	}
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return "", fmt.Errorf("gopass show %q: %s", name, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return "", fmt.Errorf("gopass show %q: %w", name, err)
	}
	// gopass show -o outputs the secret followed by a newline.
	return strings.TrimRight(string(out), "\n"), nil
}

func (c *gopassCLIClient) list() ([]string, error) {
	cmd := exec.Command("gopass", "ls", "--flat")
	if c.storePath != "" {
		cmd.Env = append(cmd.Environ(), "GOPASS_HOMEDIR="+c.storePath)
	}
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return nil, fmt.Errorf("gopass ls: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("gopass ls: %w", err)
	}
	text := strings.TrimSpace(string(out))
	if text == "" {
		return nil, nil
	}
	return strings.Split(text, "\n"), nil
}

// GopassProvider retrieves credentials from a gopass password store via CLI.
type GopassProvider struct {
	client gopassClient
}

// NewGopassProvider creates a provider that reads secrets using the gopass CLI.
// storePath is optional and overrides gopass's default store location.
// Returns an error if the gopass binary is not installed.
func NewGopassProvider(storePath string) (*GopassProvider, error) {
	if _, err := exec.LookPath("gopass"); err != nil {
		return nil, fmt.Errorf("gopass: binary not found in PATH (install from https://github.com/gopasspw/gopass)")
	}

	return &GopassProvider{
		client: &gopassCLIClient{storePath: storePath},
	}, nil
}

// newGopassProviderWithClient creates a provider with an injected client (for testing).
func newGopassProviderWithClient(client gopassClient) *GopassProvider {
	return &GopassProvider{client: client}
}

// Get retrieves a credential from gopass by entry name.
func (p *GopassProvider) Get(name string) (SecureBytes, error) {
	if name == "" {
		return SecureBytes{}, fmt.Errorf("credential name must not be empty")
	}

	val, err := p.client.show(name)
	if err != nil {
		return SecureBytes{}, fmt.Errorf("gopass: %w", err)
	}

	return NewSecureBytes(val), nil
}

// List returns all entry names in the gopass store.
func (p *GopassProvider) List() ([]string, error) {
	names, err := p.client.list()
	if err != nil {
		return nil, fmt.Errorf("gopass: %w", err)
	}
	return names, nil
}

// Name returns "gopass".
func (p *GopassProvider) Name() string { return "gopass" }
