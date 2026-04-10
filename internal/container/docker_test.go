package container

import (
	"context"
	"fmt"
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
	execErrs    []error // per-call exec errors; takes priority over execErr when non-empty
	createdID   string
	createdSpec ContainerSpec
	stopped     bool
	removed     bool
	started     bool
	execCalled  bool
	execCmd     []string
	execCalls   [][]string // all exec calls recorded
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
	m.execCalls = append(m.execCalls, cmd)

	// Use per-call error if available.
	if len(m.execErrs) > 0 {
		idx := len(m.execCalls) - 1
		if idx < len(m.execErrs) {
			return m.execErrs[idx]
		}
		return nil
	}
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

func TestInjectEnvVarsWritesEnvFile(t *testing.T) {
	mc := &mockClient{}
	mgr := NewDockerManager(mc, "openclaw")

	envMap := map[string]string{
		"ANTHROPIC_API_KEY": "sk-ant-phantom-abc123",
	}

	err := mgr.InjectEnvVars(context.Background(), envMap, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have made 2 exec calls: env file write + secrets reload.
	if len(mc.execCalls) != 2 {
		t.Fatalf("expected 2 exec calls, got %d", len(mc.execCalls))
	}

	// First call: shell script that writes to .env file.
	if mc.execCalls[0][0] != "sh" || mc.execCalls[0][1] != "-c" {
		t.Errorf("first exec should be sh -c, got %v", mc.execCalls[0])
	}
	script := mc.execCalls[0][2]
	if !strings.Contains(script, "ANTHROPIC_API_KEY") {
		t.Errorf("script should contain env var name, got %s", script)
	}
	if !strings.Contains(script, "sk-ant-phantom-abc123") {
		t.Errorf("script should contain env var value, got %s", script)
	}
	if !strings.Contains(script, ".openclaw/.env") {
		t.Errorf("script should reference .openclaw/.env, got %s", script)
	}

	// Second call: secrets reload via node WebSocket script. The new
	// script takes the RPC method as argv, so the command is
	// [node, -e, <script>, "secrets.reload"].
	if len(mc.execCalls[1]) != 4 {
		t.Errorf("reload cmd len = %d, want 4", len(mc.execCalls[1]))
	} else if mc.execCalls[1][0] != "node" || mc.execCalls[1][1] != "-e" || mc.execCalls[1][3] != "secrets.reload" {
		t.Errorf("reload cmd = %v, want [node -e <script> secrets.reload]", mc.execCalls[1][:2])
	}
}

func TestInjectEnvVarsEmptyMap(t *testing.T) {
	mc := &mockClient{}
	mgr := NewDockerManager(mc, "openclaw")

	err := mgr.InjectEnvVars(context.Background(), map[string]string{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Empty map should be a no-op.
	if mc.execCalled {
		t.Error("exec should not be called for empty envMap")
	}
}

func TestInjectEnvVarsExecError(t *testing.T) {
	mc := &mockClient{
		execErr: fmt.Errorf("container not running"),
	}
	mgr := NewDockerManager(mc, "openclaw")

	err := mgr.InjectEnvVars(context.Background(), map[string]string{
		"API_KEY": "phantom-value",
	}, false)
	if err == nil {
		t.Fatal("expected error when exec fails")
	}
	if !strings.Contains(err.Error(), "inject env vars") {
		t.Errorf("error should mention inject env vars: %v", err)
	}
}

func TestInjectEnvVarsReloadFails(t *testing.T) {
	// First exec (env file write) succeeds, second (reload) fails.
	mc := &mockClient{
		execErrs: []error{nil, fmt.Errorf("reload failed")},
	}
	mgr := NewDockerManager(mc, "openclaw")

	// Reload failure should not cause InjectEnvVars to return an error.
	// The env vars were successfully written; reload failure is logged.
	err := mgr.InjectEnvVars(context.Background(), map[string]string{
		"API_KEY": "phantom-value",
	}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v (reload failure should be best-effort)", err)
	}
}

func TestInjectEnvVarsContainerName(t *testing.T) {
	mc := &mockClient{}
	mgr := NewDockerManager(mc, "my-agent")

	err := mgr.InjectEnvVars(context.Background(), map[string]string{
		"TOKEN": "phantom-123",
	}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mc.execName != "my-agent" {
		t.Errorf("exec container = %q, want %q", mc.execName, "my-agent")
	}
}

func TestInjectEnvVarsSpecialCharacters(t *testing.T) {
	t.Run("single_quote_in_value", func(t *testing.T) {
		mc := &mockClient{}
		mgr := NewDockerManager(mc, "openclaw")

		err := mgr.InjectEnvVars(context.Background(), map[string]string{
			"KEY": "it's a test",
		}, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		script := mc.execCalls[0][2]
		if !strings.Contains(script, "'\"'\"'") {
			t.Errorf("script should contain escaped single quote, got %s", script)
		}
	})

	t.Run("pipe_in_value", func(t *testing.T) {
		mc := &mockClient{}
		mgr := NewDockerManager(mc, "openclaw")

		// Values containing | should not break the sed command. The
		// implementation uses SOH (0x01) as sed delimiter.
		err := mgr.InjectEnvVars(context.Background(), map[string]string{
			"KEY": "value|with|pipes",
		}, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		script := mc.execCalls[0][2]
		if !strings.Contains(script, "value|with|pipes") {
			t.Errorf("script should contain literal pipes in value, got %s", script)
		}
		// Must NOT use | as sed delimiter.
		if strings.Contains(script, "s|") {
			t.Errorf("script should not use | as sed delimiter, got %s", script)
		}
	})

	t.Run("invalid_key_rejected", func(t *testing.T) {
		mc := &mockClient{}
		mgr := NewDockerManager(mc, "openclaw")

		err := mgr.InjectEnvVars(context.Background(), map[string]string{
			"FOO'; rm -rf / #": "harmless",
		}, false)
		if err == nil {
			t.Fatal("expected error for invalid env var key")
		}
		if !strings.Contains(err.Error(), "invalid env var key") {
			t.Errorf("error should mention invalid key, got: %v", err)
		}
	})
}

func TestInjectEnvVarsEmptyValueDeletesLine(t *testing.T) {
	mc := &mockClient{}
	mgr := NewDockerManager(mc, "openclaw")

	// An empty value should generate a sed delete command instead of writing KEY=.
	err := mgr.InjectEnvVars(context.Background(), map[string]string{
		"OLD_KEY": "",
	}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	script := mc.execCalls[0][2]
	// Should use sed deletion (d command), not substitution.
	if !strings.Contains(script, "/^OLD_KEY=/d") {
		t.Errorf("script should contain sed deletion for empty value, got %s", script)
	}
	// Should NOT write OLD_KEY= to the file.
	if strings.Contains(script, "echo 'OLD_KEY=") {
		t.Errorf("script should not write empty env var, got %s", script)
	}
}

func TestInjectEnvVarsFullReplaceTruncatesFile(t *testing.T) {
	mc := &mockClient{}
	mgr := NewDockerManager(mc, "openclaw")

	err := mgr.InjectEnvVars(context.Background(), map[string]string{
		"NEW_KEY": "phantom-value",
	}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	script := mc.execCalls[0][2]
	// Full replace should truncate the file before writing.
	if !strings.Contains(script, ": > ") {
		t.Errorf("fullReplace script should truncate the file, got %s", script)
	}
	if strings.Contains(script, "touch") {
		t.Errorf("fullReplace script should not use touch, got %s", script)
	}
	if !strings.Contains(script, "NEW_KEY") {
		t.Errorf("script should contain env var name, got %s", script)
	}
}

func TestInjectEnvVarsMergeModeDoesNotTruncate(t *testing.T) {
	mc := &mockClient{}
	mgr := NewDockerManager(mc, "openclaw")

	err := mgr.InjectEnvVars(context.Background(), map[string]string{
		"KEY": "value",
	}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	script := mc.execCalls[0][2]
	// Merge mode should use touch, not truncate.
	if strings.Contains(script, ": > ") {
		t.Errorf("merge mode should not truncate the file, got %s", script)
	}
	if !strings.Contains(script, "touch") {
		t.Errorf("merge mode should use touch, got %s", script)
	}
}

func TestDockerManagerInjectCACertNoop(t *testing.T) {
	mc := &mockClient{}
	mgr := NewDockerManager(mc, "openclaw")

	// InjectCACert should be a no-op for Docker (returns nil, no exec calls).
	err := mgr.InjectCACert(context.Background(), "/some/cert.pem", "/some/dir")
	if err != nil {
		t.Fatalf("expected nil error for Docker no-op, got: %v", err)
	}
	if mc.execCalled {
		t.Error("Docker InjectCACert should not exec anything")
	}
}
