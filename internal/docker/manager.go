// Package docker manages agent containers, handling credential rotation by
// restarting containers with updated phantom environment variables.
package docker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nemirovsky/sluice/internal/container"
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

// Manager manages Docker container lifecycle for credential rotation.
// It implements the container.ContainerManager interface.
type Manager struct {
	client        ContainerClient
	containerName string
}

// NewManager creates a new Docker container manager.
func NewManager(client ContainerClient, containerName string) *Manager {
	return &Manager{
		client:        client,
		containerName: containerName,
	}
}

// ReloadSecrets writes phantom token files to a shared volume directory and
// signals the agent container to reload them via docker exec. Each entry in
// phantomEnv is written as a separate file (key = filename, value = contents).
// If the exec command fails (e.g. the agent image does not support "secrets
// reload"), it falls back to RestartWithEnv for backward compatibility.
func (m *Manager) ReloadSecrets(ctx context.Context, phantomDir string, phantomEnv map[string]string) error {
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
func (m *Manager) RestartWithEnv(ctx context.Context, envUpdates map[string]string) error {
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
func (m *Manager) Status(ctx context.Context) (container.ContainerStatus, error) {
	info, err := m.client.InspectContainer(ctx, m.containerName)
	if err != nil {
		return container.ContainerStatus{}, err
	}
	return container.ContainerStatus{
		ID:      info.ID,
		Running: info.Running,
		Image:   info.Image,
	}, nil
}

// InjectMCPConfig is a no-op for Docker. MCP configuration is handled via
// compose volumes and environment variables in the Docker deployment model.
func (m *Manager) InjectMCPConfig(_, _ string) error {
	return nil
}

// Runtime returns container.RuntimeDocker.
func (m *Manager) Runtime() container.Runtime {
	return container.RuntimeDocker
}

// Stop stops the agent container.
func (m *Manager) Stop(ctx context.Context) error {
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

// GeneratePhantomToken creates a phantom token value matching the expected
// format for the given credential name. SDKs validate token prefixes, so
// phantom tokens must pass basic format checks.
func GeneratePhantomToken(credName string) string {
	rnd := randomHex(20)
	switch {
	case strings.Contains(credName, "anthropic"):
		return "sk-ant-phantom-" + rnd
	case strings.Contains(credName, "openai"):
		return "sk-phantom-" + rnd
	case strings.Contains(credName, "github"):
		return "ghp_phantom" + rnd
	default:
		return "phantom-" + rnd
	}
}

// CredNameToEnvVar converts a credential name to an environment variable name.
// Non-alphanumeric characters (hyphens, dots, etc.) are replaced with underscores
// to produce valid shell environment variable names.
func CredNameToEnvVar(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, c := range strings.ToUpper(name) {
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// GeneratePhantomEnv generates phantom token environment variables for all
// given credential names. Returns a map of ENV_VAR_NAME to phantom value.
func GeneratePhantomEnv(credNames []string) map[string]string {
	result := make(map[string]string, len(credNames))
	for _, name := range credNames {
		envVar := CredNameToEnvVar(name)
		result[envVar] = GeneratePhantomToken(name)
	}
	return result
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
