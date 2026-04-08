package container

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CommandRunner abstracts os/exec for testability.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner runs commands via os/exec.
type ExecRunner struct{}

// Run executes a command and returns combined stdout. Returns an error
// containing stderr if the command fails.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// AppleCLI wraps the macOS `container` CLI for managing Apple Container
// micro-VMs. It provides low-level operations that AppleManager (Task 3)
// will wire into the ContainerManager interface.
type AppleCLI struct {
	bin    string // path to container binary
	runner CommandRunner
}

// NewAppleCLI creates a new AppleCLI. Returns an error if the container
// binary is not found in PATH.
func NewAppleCLI(runner CommandRunner) (*AppleCLI, error) {
	return NewAppleCLIWithBin("container", runner)
}

// NewAppleCLIWithBin creates a new AppleCLI using the specified binary path.
// Returns an error if the binary does not exist.
func NewAppleCLIWithBin(bin string, runner CommandRunner) (*AppleCLI, error) {
	if runner == nil {
		runner = ExecRunner{}
	}

	// Verify the binary exists by running --version.
	_, err := runner.Run(context.Background(), bin, "--version")
	if err != nil {
		return nil, fmt.Errorf("container binary %q not found or not working: %w", bin, err)
	}

	return &AppleCLI{bin: bin, runner: runner}, nil
}

// RunConfig holds parameters for starting a new Apple Container VM.
type RunConfig struct {
	Name    string
	Image   string
	Env     map[string]string
	Volumes []VolumeMount
}

// VolumeMount describes a host-to-guest volume mount.
type VolumeMount struct {
	HostPath  string
	GuestPath string
	ReadOnly  bool
}

// Run starts a new Apple Container VM with the given configuration.
func (c *AppleCLI) Run(ctx context.Context, cfg RunConfig) error {
	args := []string{"run", "--name", cfg.Name}
	for k, v := range cfg.Env {
		args = append(args, "-e", k+"="+v)
	}
	for _, vol := range cfg.Volumes {
		mount := vol.HostPath + ":" + vol.GuestPath
		if vol.ReadOnly {
			mount += ":ro"
		}
		args = append(args, "-v", mount)
	}
	args = append(args, cfg.Image)
	_, err := c.runner.Run(ctx, c.bin, args...)
	return err
}

// Exec runs a command inside a running VM.
func (c *AppleCLI) Exec(ctx context.Context, name string, cmd []string) ([]byte, error) {
	args := append([]string{"exec", name}, cmd...)
	return c.runner.Run(ctx, c.bin, args...)
}

// Stop stops a running VM.
func (c *AppleCLI) Stop(ctx context.Context, name string) error {
	_, err := c.runner.Run(ctx, c.bin, "stop", name)
	return err
}

// Remove removes a stopped VM.
func (c *AppleCLI) Remove(ctx context.Context, name string) error {
	_, err := c.runner.Run(ctx, c.bin, "rm", name)
	return err
}

// VMInfo holds parsed output from `container inspect`.
type VMInfo struct {
	Name    string   `json:"Name"`
	ID      string   `json:"Id"`
	Image   string   `json:"Image"`
	State   VMState  `json:"State"`
	Network VMNet    `json:"NetworkSettings"`
	Mounts  []VMBind `json:"Mounts"`
	Env     []string `json:"Env"`
}

// VMState holds VM running state.
type VMState struct {
	Status  string `json:"Status"`
	Running bool   `json:"Running"`
}

// VMNet holds VM network settings.
type VMNet struct {
	IPAddress string `json:"IPAddress"`
}

// VMBind holds a volume mount from inspect output.
type VMBind struct {
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	ReadOnly    bool   `json:"RO"`
}

// Inspect returns information about a VM by name.
func (c *AppleCLI) Inspect(ctx context.Context, name string) (VMInfo, error) {
	out, err := c.runner.Run(ctx, c.bin, "inspect", name)
	if err != nil {
		return VMInfo{}, err
	}

	// container inspect returns a JSON array with one element.
	var infos []VMInfo
	if err := json.Unmarshal(out, &infos); err != nil {
		return VMInfo{}, fmt.Errorf("parse inspect output: %w", err)
	}
	if len(infos) == 0 {
		return VMInfo{}, errors.New("inspect returned empty result")
	}
	return infos[0], nil
}

// VMListEntry holds a single entry from `container ls` output.
type VMListEntry struct {
	Name  string `json:"Name"`
	ID    string `json:"Id"`
	Image string `json:"Image"`
	State string `json:"State"`
}

// List returns all VMs visible to `container ls`.
func (c *AppleCLI) List(ctx context.Context) ([]VMListEntry, error) {
	out, err := c.runner.Run(ctx, c.bin, "ls", "--format", "json")
	if err != nil {
		return nil, err
	}

	if len(bytes.TrimSpace(out)) == 0 {
		return nil, nil
	}

	var entries []VMListEntry
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil, fmt.Errorf("parse ls output: %w", err)
	}
	return entries, nil
}

// AppleManager implements ContainerManager for Apple Container micro-VMs.
// It uses AppleCLI for VM lifecycle and credential injection via shared
// volumes and container exec.
type AppleManager struct {
	cli           *AppleCLI
	containerName string
}

// AppleManagerConfig holds configuration for creating an AppleManager.
type AppleManagerConfig struct {
	CLI           *AppleCLI
	ContainerName string
}

// NewAppleManager creates a new AppleManager from the given config.
func NewAppleManager(cfg AppleManagerConfig) *AppleManager {
	return &AppleManager{
		cli:           cfg.CLI,
		containerName: cfg.ContainerName,
	}
}

// InjectEnvVars writes environment variables into the agent VM's env file
// (~/.openclaw/.env) via container exec and signals the agent to reload.
// Each key in envMap is an env var name and the value is the phantom token.
// When fullReplace is true the file is truncated before writing so stale
// entries are removed. When false, entries are merged in-place.
func (m *AppleManager) InjectEnvVars(ctx context.Context, envMap map[string]string, fullReplace bool) error {
	if len(envMap) == 0 && !fullReplace {
		return nil
	}

	script, err := BuildEnvInjectionScript(envMap, false, fullReplace)
	if err != nil {
		return fmt.Errorf("build env injection script: %w", err)
	}

	if _, execErr := m.cli.Exec(ctx, m.containerName, []string{"sh", "-c", script}); execErr != nil {
		return fmt.Errorf("inject env vars: %w", execErr)
	}

	if reloadErr := m.ReloadSecrets(ctx); reloadErr != nil {
		log.Printf("env vars injected but secrets reload failed: %v", reloadErr)
	}

	return nil
}

// ReloadSecrets signals the openclaw gateway to re-read secrets via WebSocket RPC.
func (m *AppleManager) ReloadSecrets(ctx context.Context) error {
	_, err := m.cli.Exec(ctx, m.containerName, []string{"node", "-e", reloadSecretsScript})
	return err
}

// RestartWithEnv stops the VM, removes it, and recreates it with updated
// environment variables merged into the existing config.
func (m *AppleManager) RestartWithEnv(ctx context.Context, envUpdates map[string]string) error {
	// Inspect current state to preserve existing env.
	info, err := m.cli.Inspect(ctx, m.containerName)
	if err != nil {
		return fmt.Errorf("inspect VM: %w", err)
	}

	// Parse existing env from inspect output.
	existingEnv := make(map[string]string)
	for _, e := range info.Env {
		k, v, _ := strings.Cut(e, "=")
		existingEnv[k] = v
	}

	// Merge updates.
	for k, v := range envUpdates {
		if v == "" {
			delete(existingEnv, k)
		} else {
			existingEnv[k] = v
		}
	}

	if err := m.cli.Stop(ctx, m.containerName); err != nil {
		return fmt.Errorf("stop VM: %w", err)
	}
	if err := m.cli.Remove(ctx, m.containerName); err != nil {
		return fmt.Errorf("remove VM: %w", err)
	}

	// Reconstruct volumes from the inspect output to preserve mounts that
	// may have been added after the manager was created.
	var vols []VolumeMount
	for _, bind := range info.Mounts {
		vols = append(vols, VolumeMount{
			HostPath:  bind.Source,
			GuestPath: bind.Destination,
			ReadOnly:  bind.ReadOnly,
		})
	}

	return m.cli.Run(ctx, RunConfig{
		Name:    m.containerName,
		Image:   info.Image,
		Env:     existingEnv,
		Volumes: vols,
	})
}

// InjectMCPConfig writes an mcp-servers.json file to the shared MCP volume
// and signals the VM to reload MCP configuration via container exec.
func (m *AppleManager) InjectMCPConfig(mcpDir, sluiceURL string) error {
	if err := WriteMCPConfig(mcpDir, sluiceURL); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, execErr := m.cli.Exec(ctx, m.containerName, []string{"openclaw", "mcp", "reload"}); execErr != nil {
		path := filepath.Join(mcpDir, "mcp-servers.json")
		log.Printf("MCP config written to %s but exec reload failed: %v", path, execErr)
	}
	return nil
}

// Status returns VM health information by running container inspect.
func (m *AppleManager) Status(ctx context.Context) (ContainerStatus, error) {
	info, err := m.cli.Inspect(ctx, m.containerName)
	if err != nil {
		return ContainerStatus{}, err
	}
	return ContainerStatus{
		ID:      info.ID,
		Running: info.State.Running,
		Image:   info.Image,
	}, nil
}

// Stop stops the Apple Container VM.
func (m *AppleManager) Stop(ctx context.Context) error {
	return m.cli.Stop(ctx, m.containerName)
}

// Runtime returns RuntimeApple.
func (m *AppleManager) Runtime() Runtime {
	return RuntimeApple
}

// CACertGuestPath is the default path where the CA cert is placed inside the
// guest VM's shared volume. Agent containers read this file to trust sluice's
// MITM CA certificate.
const CACertGuestPath = "/certs/sluice-ca.crt"

// CACertEnvVars returns environment variables that configure common HTTP
// libraries to trust sluice's MITM CA certificate at the given guest path.
// These should be passed when starting the VM.
func CACertEnvVars(guestCertPath string) map[string]string {
	return map[string]string{
		"SSL_CERT_FILE":       guestCertPath,
		"REQUESTS_CA_BUNDLE":  guestCertPath,
		"NODE_EXTRA_CA_CERTS": guestCertPath,
	}
}

// InjectCACert copies the CA certificate from hostCertPath into the shared
// volume at certDir, then runs trust update commands inside the VM so the
// system trust store recognizes the cert. It tries update-ca-certificates
// (Linux guests) first, then falls back to the macOS security command.
// If both fail the cert is still available via the env vars set at VM startup.
func (m *AppleManager) InjectCACert(ctx context.Context, hostCertPath, certDir string) error {
	// Read the CA cert from the host.
	certData, err := os.ReadFile(hostCertPath)
	if err != nil {
		return fmt.Errorf("read CA cert %q: %w", hostCertPath, err)
	}

	// Write the cert to the shared volume so the guest can access it.
	destPath := filepath.Join(certDir, "sluice-ca.crt")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		return fmt.Errorf("create cert dir %q: %w", certDir, err)
	}
	if err := os.WriteFile(destPath, certData, 0o644); err != nil {
		return fmt.Errorf("write CA cert to shared volume: %w", err)
	}

	// Try to update the system trust store inside the VM.
	// Linux guests use update-ca-certificates (which scans
	// /usr/local/share/ca-certificates/). macOS guests use security.
	// If neither works, the env vars (SSL_CERT_FILE, etc.) still cover
	// most HTTP libraries.
	_, _ = m.cli.Exec(ctx, m.containerName, []string{
		"mkdir", "-p", "/usr/local/share/ca-certificates",
	})
	_, _ = m.cli.Exec(ctx, m.containerName, []string{
		"cp", CACertGuestPath, "/usr/local/share/ca-certificates/sluice-ca.crt",
	})
	_, linuxErr := m.cli.Exec(ctx, m.containerName, []string{
		"update-ca-certificates",
	})
	if linuxErr == nil {
		return nil
	}

	// Fallback: macOS guest trust store.
	_, macErr := m.cli.Exec(ctx, m.containerName, []string{
		"security", "add-trusted-cert", "-d", "-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain",
		CACertGuestPath,
	})
	if macErr == nil {
		return nil
	}

	// Both failed. The cert is still usable via env vars.
	return nil
}
