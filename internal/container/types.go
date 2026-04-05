// Package container defines the ContainerManager interface shared by Docker,
// Apple Container, and tart (macOS VM) backends. Each backend implements this
// interface so that Telegram commands, MCP injection, and credential management
// code can work with any container runtime without knowing the specifics.
package container

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Runtime identifies the container backend in use.
type Runtime int

// Container runtime backends.
const (
	RuntimeDocker Runtime = 0
	RuntimeApple  Runtime = 1
	RuntimeNone   Runtime = 2
	RuntimeMacOS  Runtime = 3
)

// String returns a human-readable name for the runtime.
func (r Runtime) String() string {
	switch r {
	case RuntimeDocker:
		return "docker"
	case RuntimeApple:
		return "apple"
	case RuntimeNone:
		return "none"
	case RuntimeMacOS:
		return "macos"
	default:
		return "unknown"
	}
}

// ContainerManager abstracts container lifecycle and credential management
// across different container runtimes (Docker, Apple Container, macOS VM).
type ContainerManager interface { //nolint:revive // stuttering accepted for clarity
	// ReloadSecrets writes phantom token files to a shared volume and signals
	// the agent container to reload them. Falls back to RestartWithEnv if the
	// agent does not support hot-reload.
	ReloadSecrets(ctx context.Context, phantomDir string, phantomEnv map[string]string) error

	// RestartWithEnv recreates the container with updated environment variables.
	RestartWithEnv(ctx context.Context, env map[string]string) error

	// InjectMCPConfig writes mcp-servers.json to the shared volume and signals
	// the agent to reload MCP configuration.
	InjectMCPConfig(phantomDir, sluiceURL string) error

	// InjectCACert copies the sluice MITM CA certificate into the guest and
	// updates the system trust store so TLS interception works. hostCertPath
	// is the path to the CA cert on the host. certDir is the shared volume
	// directory where the cert is written for the guest to access.
	// Implementations should be best-effort: if trust store commands fail
	// the cert is still available via env vars (SSL_CERT_FILE, etc.).
	InjectCACert(ctx context.Context, hostCertPath, certDir string) error

	// Status returns container health information.
	Status(ctx context.Context) (ContainerStatus, error)

	// Stop stops the agent container.
	Stop(ctx context.Context) error

	// Runtime returns which backend this manager uses.
	Runtime() Runtime
}

// ContainerStatus holds container health information returned by Status.
type ContainerStatus struct { //nolint:revive // stuttering accepted for clarity
	ID      string
	Running bool
	Image   string
}

// WritePhantomFiles writes phantom token files to the shared volume directory.
// Each entry in phantomEnv maps a filename to its content. An empty value
// removes the file. This logic is shared by all container backends.
func WritePhantomFiles(phantomDir string, phantomEnv map[string]string) error {
	for name, value := range phantomEnv {
		path := filepath.Join(phantomDir, name)
		if value == "" {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove phantom file %s: %w", name, err)
			}
			continue
		}
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			return fmt.Errorf("write phantom file %s: %w", name, err)
		}
	}
	return nil
}

// WriteMCPConfig writes an mcp-servers.json file to the shared volume
// directory. This logic is shared by all container backends.
func WriteMCPConfig(phantomDir, sluiceURL string) error {
	mcpConfig := map[string]any{
		"sluice": map[string]any{
			"url":       sluiceURL,
			"transport": "streamable-http",
		},
	}

	data, err := json.Marshal(mcpConfig)
	if err != nil {
		return fmt.Errorf("marshal mcp config: %w", err)
	}

	path := filepath.Join(phantomDir, "mcp-servers.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write mcp config: %w", err)
	}
	return nil
}
