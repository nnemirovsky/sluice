package container

import (
	"context"
	"fmt"
	"log"
	"strings"
)

// ContainerClient abstracts Docker Engine API operations for testability.
// A production implementation wraps github.com/docker/docker/client.Client.
type ContainerClient interface { //nolint:revive // stuttering accepted for clarity
	InspectContainer(ctx context.Context, name string) (ContainerState, error)
	StopContainer(ctx context.Context, name string, timeoutSec int) error
	RemoveContainer(ctx context.Context, name string) error
	CreateContainer(ctx context.Context, spec ContainerSpec) (string, error)
	StartContainer(ctx context.Context, id string) error
	ExecInContainer(ctx context.Context, name string, cmd []string) error
}

// ContainerState holds the result of inspecting a container.
type ContainerState struct { //nolint:revive // stuttering accepted for clarity
	ID          string
	Image       string
	Env         []string
	Running     bool
	Mounts      []Mount
	Binds       []string // HostConfig.Binds preserving "source:dest:mode" format
	Networks    []string
	NetworkMode string
	Cmd         []string
	Entrypoint  []string
}

// Mount represents a container volume mount.
type Mount struct {
	Type        string
	Name        string // Volume name (for type=volume). Empty for bind mounts.
	Source      string
	Destination string
	ReadOnly    bool
}

// ContainerSpec holds parameters for creating a container.
type ContainerSpec struct { //nolint:revive // stuttering accepted for clarity
	Name        string
	Image       string
	Env         []string
	Mounts      []Mount
	Binds       []string // HostConfig.Binds preserving "source:dest:mode" format
	Networks    []string
	NetworkMode string
	Cmd         []string
	Entrypoint  []string
}

// DockerManager manages Docker container lifecycle for credential rotation.
// It implements the ContainerManager interface.
type DockerManager struct {
	client        ContainerClient
	containerName string
}

// NewDockerManager creates a new Docker container manager.
func NewDockerManager(client ContainerClient, containerName string) *DockerManager {
	return &DockerManager{
		client:        client,
		containerName: containerName,
	}
}

// InjectEnvVars writes environment variables into the agent container's env
// file (~/.openclaw/.env) via docker exec and then signals the agent to reload.
// Each key in envMap is an env var name and the value is the phantom token.
// When fullReplace is true the file is truncated before writing so stale
// entries are removed. When false, entries are merged in-place.
func (m *DockerManager) InjectEnvVars(ctx context.Context, envMap map[string]string, fullReplace bool) error {
	if len(envMap) == 0 && !fullReplace {
		return nil
	}

	script, err := BuildEnvInjectionScript(envMap, false, fullReplace)
	if err != nil {
		return fmt.Errorf("build env injection script: %w", err)
	}

	if execErr := m.client.ExecInContainer(ctx, m.containerName,
		[]string{"sh", "-c", script}); execErr != nil {
		return fmt.Errorf("inject env vars: %w", execErr)
	}

	// Signal the agent to reload secrets from the updated env file.
	if reloadErr := m.ReloadSecrets(ctx); reloadErr != nil {
		log.Printf("env vars injected but secrets reload failed: %v", reloadErr)
	}

	return nil
}

// ReloadSecrets signals the openclaw gateway to re-read secrets via WebSocket RPC.
// Uses the embedded gateway_rpc.js script to do the full device-signed
// connect handshake before invoking secrets.reload.
func (m *DockerManager) ReloadSecrets(ctx context.Context) error {
	return m.client.ExecInContainer(ctx, m.containerName,
		GatewayRPCNodeCommand("secrets.reload"))
}

// WireMCPGateway registers sluice's MCP gateway URL in the agent's
// openclaw.json config (at mcp.servers.<name>) via a gateway WebSocket
// RPC. This is a one-shot idempotent operation: if the entry already
// matches, openclaw returns a noop. Call this once at sluice startup
// after the MCP gateway is initialized.
//
// On first wire-up the config change triggers an openclaw gateway
// restart, which kills the docker exec we're running and reports
// exit code 137. The config write itself has already succeeded at
// that point, so we swallow 137 and treat it as success. Genuine
// failures surface as non-zero exit codes other than 137 or
// connect-time errors before the exec runs.
func (m *DockerManager) WireMCPGateway(ctx context.Context, name, sluiceURL string) error {
	err := m.client.ExecInContainer(ctx, m.containerName,
		GatewayRPCNodeCommand("wire-mcp", name, sluiceURL))
	if err != nil && strings.Contains(err.Error(), "exit") && strings.Contains(err.Error(), "137") {
		// The config.patch response was delivered successfully; the
		// exec was terminated by the subsequent gateway restart.
		return nil
	}
	return err
}

// RestartWithEnv recreates the container with updated environment variables.
// It inspects the current container config, stops and removes it, creates a
// new container with the same config plus updated env vars, and starts it.
func (m *DockerManager) RestartWithEnv(ctx context.Context, envUpdates map[string]string) error {
	info, err := m.client.InspectContainer(ctx, m.containerName)
	if err != nil {
		return fmt.Errorf("inspect container: %w", err)
	}

	env := mergeEnv(info.Env, envUpdates)

	if err := m.client.StopContainer(ctx, m.containerName, 10); err != nil {
		return fmt.Errorf("stop container: %w", err)
	}
	if err := m.client.RemoveContainer(ctx, m.containerName); err != nil {
		return fmt.Errorf("remove container: %w", err)
	}

	newID, err := m.client.CreateContainer(ctx, ContainerSpec{
		Name:        m.containerName,
		Image:       info.Image,
		Env:         env,
		Mounts:      info.Mounts,
		Binds:       info.Binds,
		Networks:    info.Networks,
		NetworkMode: info.NetworkMode,
		Cmd:         info.Cmd,
		Entrypoint:  info.Entrypoint,
	})
	if err != nil {
		return fmt.Errorf("create container: %w", err)
	}

	if err := m.client.StartContainer(ctx, newID); err != nil {
		return fmt.Errorf("start container: %w", err)
	}

	return nil
}

// Status returns container health information.
func (m *DockerManager) Status(ctx context.Context) (ContainerStatus, error) {
	info, err := m.client.InspectContainer(ctx, m.containerName)
	if err != nil {
		return ContainerStatus{}, err
	}
	return ContainerStatus{
		ID:      info.ID,
		Running: info.Running,
		Image:   info.Image,
	}, nil
}

// InjectCACert is a no-op for Docker. Docker handles CA trust via compose
// volumes and SSL_CERT_FILE env vars set at container creation time.
func (m *DockerManager) InjectCACert(_ context.Context, _, _ string) error {
	return nil
}

// Runtime returns RuntimeDocker.
func (m *DockerManager) Runtime() Runtime {
	return RuntimeDocker
}

// Stop stops the agent container.
func (m *DockerManager) Stop(ctx context.Context) error {
	return m.client.StopContainer(ctx, m.containerName, 10)
}

// mergeEnv merges updates into an existing environment variable list.
// Existing variables are updated in place. New variables are appended.
// Variables with an empty string value in updates are removed.
// Insertion order of existing variables is preserved.
func mergeEnv(existing []string, updates map[string]string) []string {
	envMap := make(map[string]string, len(existing))
	order := make([]string, 0, len(existing))
	for _, e := range existing {
		k, v, _ := strings.Cut(e, "=")
		if _, exists := envMap[k]; !exists {
			order = append(order, k)
		}
		envMap[k] = v
	}
	for k, v := range updates {
		if _, exists := envMap[k]; !exists {
			order = append(order, k)
		}
		envMap[k] = v
	}
	result := make([]string, 0, len(order))
	for _, k := range order {
		v := envMap[k]
		// Empty value in updates signals removal.
		if _, isUpdate := updates[k]; isUpdate && v == "" {
			continue
		}
		result = append(result, k+"="+v)
	}
	return result
}
