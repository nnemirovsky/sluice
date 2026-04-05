// Package container defines the ContainerManager interface shared by Docker
// and Apple Container backends. Each backend implements this interface so that
// Telegram commands, MCP injection, and credential management code can work
// with any container runtime without knowing the specifics.
package container

import "context"

// Runtime identifies the container backend in use.
type Runtime int

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
// across different container runtimes (Docker, Apple Container).
type ContainerManager interface {
	// ReloadSecrets writes phantom token files to a shared volume and signals
	// the agent container to reload them. Falls back to RestartWithEnv if the
	// agent does not support hot-reload.
	ReloadSecrets(ctx context.Context, phantomDir string, phantomEnv map[string]string) error

	// RestartWithEnv recreates the container with updated environment variables.
	RestartWithEnv(ctx context.Context, env map[string]string) error

	// InjectMCPConfig writes mcp-servers.json to the shared volume and signals
	// the agent to reload MCP configuration.
	InjectMCPConfig(phantomDir, sluiceURL string) error

	// Status returns container health information.
	Status(ctx context.Context) (ContainerStatus, error)

	// Stop stops the agent container.
	Stop(ctx context.Context) error

	// Runtime returns which backend this manager uses.
	Runtime() Runtime
}

// ContainerStatus holds container health information returned by Status.
type ContainerStatus struct {
	ID      string
	Running bool
	Image   string
}
