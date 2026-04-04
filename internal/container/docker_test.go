package container

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mockClient implements ContainerClient for testing.
type mockClient struct {
	state       ContainerState
	inspectErr  error
	stopErr     error
	removeErr   error
	createErr   error
	startErr    error
	execErr     error
	createdID   string
	createdSpec ContainerSpec
	stopped     bool
	removed     bool
	started     bool
	execCalled  bool
	execCmd     []string
	// Track container names passed to each method.
	inspectedName string
	stoppedName   string
	removedName   string
	startedID     string
	execName      string
}

func (m *mockClient) InspectContainer(_ context.Context, name string) (ContainerState, error) {
	m.inspectedName = name
	return m.state, m.inspectErr
}

func (m *mockClient) StopContainer(_ context.Context, name string, _ int) error {
	m.stopped = true
	m.stoppedName = name
	return m.stopErr
}

func (m *mockClient) RemoveContainer(_ context.Context, name string) error {
	m.removed = true
	m.removedName = name
	return m.removeErr
}

func (m *mockClient) CreateContainer(_ context.Context, spec ContainerSpec) (string, error) {
	m.createdSpec = spec
	return m.createdID, m.createErr
}

func (m *mockClient) StartContainer(_ context.Context, id string) error {
	m.started = true
	m.startedID = id
	return m.startErr
}

func (m *mockClient) ExecInContainer(_ context.Context, name string, cmd []string) error {
	m.execCalled = true
	m.execName = name
	m.execCmd = cmd
	return m.execErr
}

// Compile-time check that DockerManager implements ContainerManager.
var _ ContainerManager = (*DockerManager)(nil)

func TestDockerManagerImplementsContainerManager(t *testing.T) {
	mc := &mockClient{}
	mgr := NewDockerManager(mc, "test")

	// Verify Runtime() returns Docker.
	if mgr.Runtime() != RuntimeDocker {
		t.Errorf("Runtime() = %v, want %v", mgr.Runtime(), RuntimeDocker)
	}
}

func TestDockerManagerInjectMCPConfig(t *testing.T) {
	mc := &mockClient{}
	mgr := NewDockerManager(mc, "openclaw")

	tmpDir := t.TempDir()
	err := mgr.InjectMCPConfig(tmpDir, "http://sluice:3000/mcp")
	if err != nil {
		t.Fatalf("InjectMCPConfig() = %v, want nil", err)
	}

	// Verify mcp-servers.json was written.
	data, readErr := os.ReadFile(filepath.Join(tmpDir, "mcp-servers.json"))
	if readErr != nil {
		t.Fatalf("read mcp-servers.json: %v", readErr)
	}

	want := `{"sluice":{"transport":"streamable-http","url":"http://sluice:3000/mcp"}}`
	if string(data) != want {
		t.Errorf("mcp-servers.json = %s, want %s", string(data), want)
	}

	// Verify exec was called to reload MCP config.
	if !mc.execCalled {
		t.Error("expected exec call for mcp reload")
	}
	if mc.execName != "openclaw" {
		t.Errorf("exec container = %q, want %q", mc.execName, "openclaw")
	}
	wantCmd := []string{"openclaw", "mcp", "reload"}
	if len(mc.execCmd) != len(wantCmd) {
		t.Errorf("exec cmd = %v, want %v", mc.execCmd, wantCmd)
	} else {
		for i := range wantCmd {
			if mc.execCmd[i] != wantCmd[i] {
				t.Errorf("exec cmd[%d] = %q, want %q", i, mc.execCmd[i], wantCmd[i])
			}
		}
	}
}

func TestDockerManagerInjectMCPConfigExecError(t *testing.T) {
	mc := &mockClient{execErr: fmt.Errorf("exec failed")}
	mgr := NewDockerManager(mc, "openclaw")

	tmpDir := t.TempDir()
	// Exec failure should not cause InjectMCPConfig to fail.
	// The file should still be written, and the error is logged.
	err := mgr.InjectMCPConfig(tmpDir, "http://sluice:3000/mcp")
	if err != nil {
		t.Fatalf("InjectMCPConfig() = %v, want nil (exec error is best-effort)", err)
	}

	// Verify the file was still written despite exec failure.
	data, readErr := os.ReadFile(filepath.Join(tmpDir, "mcp-servers.json"))
	if readErr != nil {
		t.Fatalf("read mcp-servers.json: %v", readErr)
	}
	if !strings.Contains(string(data), "sluice") {
		t.Error("mcp-servers.json should contain sluice config")
	}
}

func TestDockerManagerInjectMCPConfigBadDir(t *testing.T) {
	mc := &mockClient{}
	mgr := NewDockerManager(mc, "openclaw")

	err := mgr.InjectMCPConfig("/nonexistent/path/xyz", "http://sluice:3000/mcp")
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
	if !strings.Contains(err.Error(), "write mcp config") {
		t.Errorf("error = %v, want to contain 'write mcp config'", err)
	}
}

func TestRestartWithEnv(t *testing.T) {
	mc := &mockClient{
		state: ContainerState{
			ID:    "abc123",
			Image: "openclaw/openclaw:latest",
			Env:   []string{"EXISTING=value", "ANTHROPIC_API_KEY=old-phantom"},
			Mounts: []Mount{
				{Type: "volume", Name: "openclaw-data", Source: "/var/lib/docker/volumes/openclaw-data/_data", Destination: "/root/.openclaw", ReadOnly: false},
				{Type: "volume", Name: "sluice-ca", Source: "/var/lib/docker/volumes/sluice-ca/_data", Destination: "/usr/local/share/ca-certificates", ReadOnly: true},
			},
			Binds:       []string{"openclaw-data:/root/.openclaw", "sluice-ca:/usr/local/share/ca-certificates:ro"},
			Networks:    []string{"internal"},
			NetworkMode: "service:tun2proxy",
			Cmd:         []string{"--model", "claude"},
			Entrypoint:  []string{"/usr/bin/openclaw"},
		},
		createdID: "def456",
	}

	mgr := NewDockerManager(mc, "openclaw")
	err := mgr.RestartWithEnv(context.Background(), map[string]string{
		"ANTHROPIC_API_KEY": "sk-ant-phantom-newvalue",
		"NEW_VAR":           "new-value",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !mc.stopped {
		t.Error("container should have been stopped")
	}
	if !mc.removed {
		t.Error("container should have been removed")
	}
	if !mc.started {
		t.Error("new container should have been started")
	}

	// Verify container name was passed correctly to all operations.
	if mc.inspectedName != "openclaw" {
		t.Errorf("inspect used wrong name: %s", mc.inspectedName)
	}
	if mc.stoppedName != "openclaw" {
		t.Errorf("stop used wrong name: %s", mc.stoppedName)
	}
	if mc.removedName != "openclaw" {
		t.Errorf("remove used wrong name: %s", mc.removedName)
	}
	if mc.startedID != "def456" {
		t.Errorf("start used wrong ID: %s", mc.startedID)
	}

	// Verify env vars.
	envMap := make(map[string]string)
	for _, e := range mc.createdSpec.Env {
		k, v, _ := strings.Cut(e, "=")
		envMap[k] = v
	}
	if envMap["EXISTING"] != "value" {
		t.Error("existing env var should be preserved")
	}
	if envMap["ANTHROPIC_API_KEY"] != "sk-ant-phantom-newvalue" {
		t.Errorf("updated env var wrong: %s", envMap["ANTHROPIC_API_KEY"])
	}
	if envMap["NEW_VAR"] != "new-value" {
		t.Error("new env var should be added")
	}
	if mc.createdSpec.Image != "openclaw/openclaw:latest" {
		t.Errorf("image should be preserved: %s", mc.createdSpec.Image)
	}

	// Verify Mounts, Networks, NetworkMode, Cmd, Entrypoint are preserved.
	if len(mc.createdSpec.Mounts) != 2 {
		t.Errorf("expected 2 mounts, got %d", len(mc.createdSpec.Mounts))
	} else {
		if mc.createdSpec.Mounts[0].Destination != "/root/.openclaw" {
			t.Errorf("first mount destination wrong: %+v", mc.createdSpec.Mounts[0])
		}
		if mc.createdSpec.Mounts[0].Name != "openclaw-data" {
			t.Errorf("first mount Name wrong: got %q, want openclaw-data", mc.createdSpec.Mounts[0].Name)
		}
		if mc.createdSpec.Mounts[1].ReadOnly != true {
			t.Error("second mount should be read-only")
		}
	}
	if len(mc.createdSpec.Networks) != 1 || mc.createdSpec.Networks[0] != "internal" {
		t.Errorf("networks not preserved: %v", mc.createdSpec.Networks)
	}
	if mc.createdSpec.NetworkMode != "service:tun2proxy" {
		t.Errorf("network mode not preserved: %s", mc.createdSpec.NetworkMode)
	}
	if len(mc.createdSpec.Cmd) != 2 || mc.createdSpec.Cmd[0] != "--model" {
		t.Errorf("cmd not preserved: %v", mc.createdSpec.Cmd)
	}
	if len(mc.createdSpec.Entrypoint) != 1 || mc.createdSpec.Entrypoint[0] != "/usr/bin/openclaw" {
		t.Errorf("entrypoint not preserved: %v", mc.createdSpec.Entrypoint)
	}
	if mc.createdSpec.Name != "openclaw" {
		t.Errorf("container name not set in spec: %s", mc.createdSpec.Name)
	}

	// Verify Binds are passed through for Docker API volume recreation.
	if len(mc.createdSpec.Binds) != 2 {
		t.Errorf("expected 2 binds, got %d", len(mc.createdSpec.Binds))
	} else {
		if mc.createdSpec.Binds[0] != "openclaw-data:/root/.openclaw" {
			t.Errorf("first bind wrong: %s", mc.createdSpec.Binds[0])
		}
		if mc.createdSpec.Binds[1] != "sluice-ca:/usr/local/share/ca-certificates:ro" {
			t.Errorf("second bind wrong: %s", mc.createdSpec.Binds[1])
		}
	}
}

func TestRestartWithEnvInspectError(t *testing.T) {
	mc := &mockClient{
		inspectErr: fmt.Errorf("container not found"),
	}
	mgr := NewDockerManager(mc, "openclaw")
	err := mgr.RestartWithEnv(context.Background(), map[string]string{"A": "1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "inspect container") {
		t.Errorf("error should mention inspect: %v", err)
	}
}

func TestRestartWithEnvStopError(t *testing.T) {
	mc := &mockClient{
		state:   ContainerState{ID: "abc", Image: "test"},
		stopErr: fmt.Errorf("timeout"),
	}
	mgr := NewDockerManager(mc, "openclaw")
	err := mgr.RestartWithEnv(context.Background(), map[string]string{"A": "1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "stop container") {
		t.Errorf("error should mention stop: %v", err)
	}
}

func TestRestartWithEnvRemoveError(t *testing.T) {
	mc := &mockClient{
		state:     ContainerState{ID: "abc", Image: "test"},
		removeErr: fmt.Errorf("in use"),
	}
	mgr := NewDockerManager(mc, "openclaw")
	err := mgr.RestartWithEnv(context.Background(), map[string]string{"A": "1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "remove container") {
		t.Errorf("error should mention remove: %v", err)
	}
}

func TestRestartWithEnvCreateError(t *testing.T) {
	mc := &mockClient{
		state:     ContainerState{ID: "abc", Image: "test"},
		createErr: fmt.Errorf("image not found"),
	}
	mgr := NewDockerManager(mc, "openclaw")
	err := mgr.RestartWithEnv(context.Background(), map[string]string{"A": "1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "create container") {
		t.Errorf("error should mention create: %v", err)
	}
}

func TestRestartWithEnvStartError(t *testing.T) {
	mc := &mockClient{
		state:     ContainerState{ID: "abc", Image: "test"},
		createdID: "new123",
		startErr:  fmt.Errorf("port conflict"),
	}
	mgr := NewDockerManager(mc, "openclaw")
	err := mgr.RestartWithEnv(context.Background(), map[string]string{"A": "1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "start container") {
		t.Errorf("error should mention start: %v", err)
	}
}

func TestDockerManagerStatus(t *testing.T) {
	mc := &mockClient{
		state: ContainerState{
			ID:      "abc123",
			Image:   "openclaw/openclaw:latest",
			Running: true,
		},
	}

	mgr := NewDockerManager(mc, "openclaw")
	status, err := mgr.Status(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.ID != "abc123" {
		t.Errorf("wrong ID: %s", status.ID)
	}
	if !status.Running {
		t.Error("should be running")
	}
	if status.Image != "openclaw/openclaw:latest" {
		t.Errorf("wrong image: %s", status.Image)
	}
}

func TestDockerManagerStop(t *testing.T) {
	mc := &mockClient{}
	mgr := NewDockerManager(mc, "openclaw")
	err := mgr.Stop(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mc.stopped {
		t.Error("container should have been stopped")
	}
}

func TestMergeEnv(t *testing.T) {
	existing := []string{"A=1", "B=2", "C=3"}
	updates := map[string]string{"B": "new2", "D": "4"}
	result := mergeEnv(existing, updates)

	envMap := make(map[string]string)
	for _, e := range result {
		k, v, _ := strings.Cut(e, "=")
		envMap[k] = v
	}

	if envMap["A"] != "1" {
		t.Error("A should be preserved")
	}
	if envMap["B"] != "new2" {
		t.Error("B should be updated")
	}
	if envMap["C"] != "3" {
		t.Error("C should be preserved")
	}
	if envMap["D"] != "4" {
		t.Error("D should be added")
	}
	if len(result) != 4 {
		t.Errorf("expected 4 entries, got %d", len(result))
	}
}

func TestMergeEnvPreservesOrder(t *testing.T) {
	existing := []string{"Z=1", "A=2", "M=3"}
	updates := map[string]string{"A": "updated"}
	result := mergeEnv(existing, updates)

	// Verify existing order is preserved.
	if result[0] != "Z=1" {
		t.Errorf("first entry should be Z=1, got %s", result[0])
	}
	if result[1] != "A=updated" {
		t.Errorf("second entry should be A=updated, got %s", result[1])
	}
	if result[2] != "M=3" {
		t.Errorf("third entry should be M=3, got %s", result[2])
	}
}

func TestMergeEnvEmpty(t *testing.T) {
	result := mergeEnv(nil, map[string]string{"A": "1"})
	if len(result) != 1 || result[0] != "A=1" {
		t.Errorf("expected [A=1], got %v", result)
	}

	result = mergeEnv([]string{"A=1"}, nil)
	if len(result) != 1 || result[0] != "A=1" {
		t.Errorf("expected [A=1], got %v", result)
	}

	result = mergeEnv(nil, nil)
	if len(result) != 0 {
		t.Errorf("expected empty, got %v", result)
	}
}

func TestMergeEnvRemoval(t *testing.T) {
	existing := []string{"A=1", "B=2", "C=3"}
	updates := map[string]string{"B": ""}
	result := mergeEnv(existing, updates)

	envMap := make(map[string]string)
	for _, e := range result {
		k, v, _ := strings.Cut(e, "=")
		envMap[k] = v
	}

	if _, ok := envMap["B"]; ok {
		t.Error("B should be removed when update value is empty")
	}
	if envMap["A"] != "1" {
		t.Error("A should be preserved")
	}
	if envMap["C"] != "3" {
		t.Error("C should be preserved")
	}
	if len(result) != 2 {
		t.Errorf("expected 2 entries, got %d: %v", len(result), result)
	}
}

func TestReloadSecretsWritesFiles(t *testing.T) {
	dir := t.TempDir()
	mc := &mockClient{}
	mgr := NewDockerManager(mc, "openclaw")

	phantomEnv := map[string]string{
		"ANTHROPIC_API_KEY": "sk-ant-phantom-abc123",
		"GITHUB_TOKEN":      "ghp_phantom0000000000",
	}

	err := mgr.ReloadSecrets(context.Background(), dir, phantomEnv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify files were written.
	for name, expected := range phantomEnv {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("failed to read phantom file %s: %v", name, err)
			continue
		}
		if string(data) != expected {
			t.Errorf("phantom file %s = %q, want %q", name, string(data), expected)
		}
	}

	// Verify file permissions are restricted.
	for name := range phantomEnv {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("stat phantom file %s: %v", name, err)
			continue
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("phantom file %s has mode %o, want 0600", name, info.Mode().Perm())
		}
	}
}

func TestReloadSecretsRemovesFiles(t *testing.T) {
	dir := t.TempDir()

	// Pre-create a file that should be removed.
	path := filepath.Join(dir, "OLD_TOKEN")
	if err := os.WriteFile(path, []byte("old-value"), 0600); err != nil {
		t.Fatal(err)
	}

	mc := &mockClient{}
	mgr := NewDockerManager(mc, "openclaw")

	err := mgr.ReloadSecrets(context.Background(), dir, map[string]string{
		"OLD_TOKEN": "", // empty = remove
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("phantom file should have been removed")
	}
}

func TestReloadSecretsCallsExec(t *testing.T) {
	dir := t.TempDir()
	mc := &mockClient{}
	mgr := NewDockerManager(mc, "openclaw")

	err := mgr.ReloadSecrets(context.Background(), dir, map[string]string{
		"API_KEY": "phantom-value",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !mc.execCalled {
		t.Error("ExecInContainer should have been called")
	}
	if mc.execName != "openclaw" {
		t.Errorf("exec container name = %q, want openclaw", mc.execName)
	}
	if len(mc.execCmd) != 3 || mc.execCmd[0] != "openclaw" || mc.execCmd[1] != "secrets" || mc.execCmd[2] != "reload" {
		t.Errorf("exec cmd = %v, want [openclaw secrets reload]", mc.execCmd)
	}
}

func TestReloadSecretsFallbackToRestart(t *testing.T) {
	dir := t.TempDir()
	mc := &mockClient{
		execErr:   fmt.Errorf("exec failed: command not found"),
		state:     ContainerState{ID: "abc", Image: "openclaw:latest"},
		createdID: "new123",
	}
	mgr := NewDockerManager(mc, "openclaw")

	err := mgr.ReloadSecrets(context.Background(), dir, map[string]string{
		"API_KEY": "phantom-value",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Exec was attempted.
	if !mc.execCalled {
		t.Error("ExecInContainer should have been called")
	}
	// Fallback to restart should have happened.
	if !mc.stopped {
		t.Error("container should have been stopped (fallback restart)")
	}
	if !mc.removed {
		t.Error("container should have been removed (fallback restart)")
	}
	if !mc.started {
		t.Error("new container should have been started (fallback restart)")
	}
}

func TestReloadSecretsFallbackRestartFails(t *testing.T) {
	dir := t.TempDir()
	mc := &mockClient{
		execErr:    fmt.Errorf("exec failed"),
		inspectErr: fmt.Errorf("container not found"),
	}
	mgr := NewDockerManager(mc, "openclaw")

	err := mgr.ReloadSecrets(context.Background(), dir, map[string]string{
		"API_KEY": "phantom-value",
	})
	if err == nil {
		t.Fatal("expected error when both exec and restart fail")
	}
	if !strings.Contains(err.Error(), "inspect container") {
		t.Errorf("error should propagate restart failure: %v", err)
	}
}
