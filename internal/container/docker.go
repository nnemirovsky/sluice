package container

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ContainerClient abstracts Docker Engine API operations for testability.
// A production implementation wraps github.com/docker/docker/client.Client.
type ContainerClient interface {
	InspectContainer(ctx context.Context, name string) (ContainerState, error)
	StopContainer(ctx context.Context, name string, timeoutSec int) error
	RemoveContainer(ctx context.Context, name string) error
	CreateContainer(ctx context.Context, spec ContainerSpec) (string, error)
	StartContainer(ctx context.Context, id string) error
	ExecInContainer(ctx context.Context, name string, cmd []string) error
}

// ContainerState holds the result of inspecting a container.
type ContainerState struct {
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
type ContainerSpec struct {
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

// ReloadSecrets writes phantom token files to a shared volume directory and
// signals the agent container to reload them via docker exec. Each entry in
// phantomEnv is written as a separate file (key = filename, value = contents).
// If the exec command fails (e.g. the agent image does not support "secrets
// reload"), it falls back to RestartWithEnv for backward compatibility.
func (m *DockerManager) ReloadSecrets(ctx context.Context, phantomDir string, phantomEnv map[string]string) error {
	// Write each phantom token as a file in the shared volume.
	for name, value := range phantomEnv {
		path := filepath.Join(phantomDir, name)
		if value == "" {
			// Empty value means removal.
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove phantom file %s: %w", name, err)
			}
			continue
		}
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			return fmt.Errorf("write phantom file %s: %w", name, err)
		}
	}

	// Signal the agent container to reload secrets.
	err := m.client.ExecInContainer(ctx, m.containerName,
		[]string{"openclaw", "secrets", "reload"})
	if err != nil {
		// Fallback to full container restart if exec fails.
		return m.RestartWithEnv(ctx, phantomEnv)
	}
	return nil
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

// InjectMCPConfig writes an mcp-servers.json file to the shared phantoms
// volume and signals the agent container to reload MCP configuration via
// docker exec. If exec fails, the agent picks up the config on next restart.
func (m *DockerManager) InjectMCPConfig(phantomDir, sluiceURL string) error {
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
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write mcp config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if execErr := m.client.ExecInContainer(ctx, m.containerName,
		[]string{"openclaw", "mcp", "reload"}); execErr != nil {
		// Best-effort: agent picks up config on next restart.
		log.Printf("MCP config written to %s but exec reload failed: %v", path, execErr)
	}
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
