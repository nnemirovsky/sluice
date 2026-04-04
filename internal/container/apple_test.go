package container

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mockRunner records commands and returns canned responses.
type mockRunner struct {
	// calls records each invocation as "name arg1 arg2 ...".
	calls []string

	// responses maps a command prefix to its canned output.
	// Matched by checking if the joined command starts with the key.
	responses map[string]mockResponse
}

type mockResponse struct {
	output []byte
	err    error
}

func newMockRunner() *mockRunner {
	return &mockRunner{
		responses: make(map[string]mockResponse),
	}
}

func (m *mockRunner) onCommand(prefix string, output []byte, err error) {
	m.responses[prefix] = mockResponse{output: output, err: err}
}

func (m *mockRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := name + " " + strings.Join(args, " ")
	m.calls = append(m.calls, strings.TrimSpace(cmd))

	// Match longest prefix first.
	bestKey := ""
	for k := range m.responses {
		if strings.HasPrefix(strings.TrimSpace(cmd), k) && len(k) > len(bestKey) {
			bestKey = k
		}
	}
	if bestKey != "" {
		r := m.responses[bestKey]
		return r.output, r.err
	}

	return nil, nil
}

func (m *mockRunner) called(prefix string) bool {
	for _, c := range m.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func (m *mockRunner) callWith(prefix string) string {
	for _, c := range m.calls {
		if strings.HasPrefix(c, prefix) {
			return c
		}
	}
	return ""
}

func TestNewAppleCLI(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("container version 1.0\n"), nil)

	cli, err := NewAppleCLI(runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cli == nil {
		t.Fatal("expected non-nil CLI")
	}
	if cli.bin != "container" {
		t.Errorf("bin = %q, want container", cli.bin)
	}
}

func TestNewAppleCLIBinaryNotFound(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", nil, errors.New("exec: \"container\": executable file not found in $PATH"))

	cli, err := NewAppleCLI(runner)
	if err == nil {
		t.Fatal("expected error when binary not found")
	}
	if cli != nil {
		t.Error("expected nil CLI on error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention not found: %v", err)
	}
}

func TestNewAppleCLIWithCustomBin(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("/usr/local/bin/container --version", []byte("v1.0\n"), nil)

	cli, err := NewAppleCLIWithBin("/usr/local/bin/container", runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cli.bin != "/usr/local/bin/container" {
		t.Errorf("bin = %q, want /usr/local/bin/container", cli.bin)
	}
}

func TestRun(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)
	runner.onCommand("container run", nil, nil)

	cli, _ := NewAppleCLIWithBin("container", runner)

	err := cli.Run(context.Background(), RunConfig{
		Name:  "openclaw",
		Image: "openclaw/openclaw:latest",
		Env: map[string]string{
			"SSL_CERT_FILE": "/certs/sluice-ca.crt",
		},
		Volumes: []VolumeMount{
			{HostPath: "/tmp/certs", GuestPath: "/certs", ReadOnly: true},
			{HostPath: "/tmp/phantoms", GuestPath: "/phantoms"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmd := runner.callWith("container run")
	if cmd == "" {
		t.Fatal("container run not called")
	}
	if !strings.Contains(cmd, "--name openclaw") {
		t.Errorf("should contain --name openclaw: %s", cmd)
	}
	if !strings.Contains(cmd, "-e SSL_CERT_FILE=/certs/sluice-ca.crt") {
		t.Errorf("should contain env var: %s", cmd)
	}
	if !strings.Contains(cmd, "-v /tmp/certs:/certs:ro") {
		t.Errorf("should contain read-only volume: %s", cmd)
	}
	if !strings.Contains(cmd, "-v /tmp/phantoms:/phantoms") {
		t.Errorf("should contain writable volume: %s", cmd)
	}
	if !strings.Contains(cmd, "openclaw/openclaw:latest") {
		t.Errorf("should contain image name: %s", cmd)
	}
}

func TestRunError(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)
	runner.onCommand("container run", nil, errors.New("image not found"))

	cli, _ := NewAppleCLIWithBin("container", runner)

	err := cli.Run(context.Background(), RunConfig{
		Name:  "test",
		Image: "bad-image",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "image not found") {
		t.Errorf("error should mention image: %v", err)
	}
}

func TestExec(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)
	runner.onCommand("container exec", []byte("reload complete\n"), nil)

	cli, _ := NewAppleCLIWithBin("container", runner)

	out, err := cli.Exec(context.Background(), "openclaw", []string{"openclaw", "secrets", "reload"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != "reload complete\n" {
		t.Errorf("output = %q, want reload complete", string(out))
	}

	cmd := runner.callWith("container exec")
	if !strings.Contains(cmd, "exec openclaw openclaw secrets reload") {
		t.Errorf("wrong exec command: %s", cmd)
	}
}

func TestExecError(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)
	runner.onCommand("container exec", nil, errors.New("VM not running"))

	cli, _ := NewAppleCLIWithBin("container", runner)

	_, err := cli.Exec(context.Background(), "openclaw", []string{"ls"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "VM not running") {
		t.Errorf("error should mention VM not running: %v", err)
	}
}

func TestStop(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)
	runner.onCommand("container stop", nil, nil)

	cli, _ := NewAppleCLIWithBin("container", runner)

	err := cli.Stop(context.Background(), "openclaw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmd := runner.callWith("container stop")
	if !strings.Contains(cmd, "stop openclaw") {
		t.Errorf("wrong stop command: %s", cmd)
	}
}

func TestStopError(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)
	runner.onCommand("container stop", nil, errors.New("no such VM"))

	cli, _ := NewAppleCLIWithBin("container", runner)

	err := cli.Stop(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRemove(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)
	runner.onCommand("container rm", nil, nil)

	cli, _ := NewAppleCLIWithBin("container", runner)

	err := cli.Remove(context.Background(), "openclaw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmd := runner.callWith("container rm")
	if !strings.Contains(cmd, "rm openclaw") {
		t.Errorf("wrong rm command: %s", cmd)
	}
}

func TestRemoveError(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)
	runner.onCommand("container rm", nil, errors.New("VM is running"))

	cli, _ := NewAppleCLIWithBin("container", runner)

	err := cli.Remove(context.Background(), "openclaw")
	if err == nil {
		t.Fatal("expected error when VM is running")
	}
}

func TestInspect(t *testing.T) {
	info := []VMInfo{{
		Name:  "openclaw",
		ID:    "abc123",
		Image: "openclaw/openclaw:latest",
		State: VMState{Status: "running", Running: true},
		Network: VMNet{
			IPAddress: "192.168.64.2",
		},
		Mounts: []VMBind{
			{Source: "/tmp/certs", Destination: "/certs", ReadOnly: true},
			{Source: "/tmp/phantoms", Destination: "/phantoms", ReadOnly: false},
		},
		Env: []string{"SSL_CERT_FILE=/certs/sluice-ca.crt"},
	}}
	inspectJSON, _ := json.Marshal(info)

	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)
	runner.onCommand("container inspect", inspectJSON, nil)

	cli, _ := NewAppleCLIWithBin("container", runner)

	result, err := cli.Inspect(context.Background(), "openclaw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Name != "openclaw" {
		t.Errorf("Name = %q, want openclaw", result.Name)
	}
	if result.ID != "abc123" {
		t.Errorf("ID = %q, want abc123", result.ID)
	}
	if result.Image != "openclaw/openclaw:latest" {
		t.Errorf("Image = %q, want openclaw/openclaw:latest", result.Image)
	}
	if !result.State.Running {
		t.Error("should be running")
	}
	if result.State.Status != "running" {
		t.Errorf("Status = %q, want running", result.State.Status)
	}
	if result.Network.IPAddress != "192.168.64.2" {
		t.Errorf("IPAddress = %q, want 192.168.64.2", result.Network.IPAddress)
	}
	if len(result.Mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(result.Mounts))
	}
	if result.Mounts[0].Source != "/tmp/certs" || !result.Mounts[0].ReadOnly {
		t.Errorf("mount[0] wrong: %+v", result.Mounts[0])
	}
	if len(result.Env) != 1 || result.Env[0] != "SSL_CERT_FILE=/certs/sluice-ca.crt" {
		t.Errorf("Env wrong: %v", result.Env)
	}
}

func TestInspectVMNotFound(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)
	runner.onCommand("container inspect", nil, errors.New("no such VM: nonexistent"))

	cli, _ := NewAppleCLIWithBin("container", runner)

	_, err := cli.Inspect(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent VM")
	}
	if !strings.Contains(err.Error(), "no such VM") {
		t.Errorf("error should mention no such VM: %v", err)
	}
}

func TestInspectBadJSON(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)
	runner.onCommand("container inspect", []byte("not json"), nil)

	cli, _ := NewAppleCLIWithBin("container", runner)

	_, err := cli.Inspect(context.Background(), "openclaw")
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
	if !strings.Contains(err.Error(), "parse inspect output") {
		t.Errorf("error should mention parse: %v", err)
	}
}

func TestInspectEmptyArray(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)
	runner.onCommand("container inspect", []byte("[]"), nil)

	cli, _ := NewAppleCLIWithBin("container", runner)

	_, err := cli.Inspect(context.Background(), "openclaw")
	if err == nil {
		t.Fatal("expected error for empty result")
	}
	if !strings.Contains(err.Error(), "empty result") {
		t.Errorf("error should mention empty: %v", err)
	}
}

func TestList(t *testing.T) {
	entries := []VMListEntry{
		{Name: "openclaw", ID: "abc123", Image: "openclaw:latest", State: "running"},
		{Name: "sidecar", ID: "def456", Image: "sidecar:latest", State: "stopped"},
	}
	listJSON, _ := json.Marshal(entries)

	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)
	runner.onCommand("container ls", listJSON, nil)

	cli, _ := NewAppleCLIWithBin("container", runner)

	result, err := cli.List(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result))
	}
	if result[0].Name != "openclaw" {
		t.Errorf("first entry Name = %q, want openclaw", result[0].Name)
	}
	if result[0].State != "running" {
		t.Errorf("first entry State = %q, want running", result[0].State)
	}
	if result[1].Name != "sidecar" {
		t.Errorf("second entry Name = %q, want sidecar", result[1].Name)
	}

	cmd := runner.callWith("container ls")
	if !strings.Contains(cmd, "--format json") {
		t.Errorf("ls should use --format json: %s", cmd)
	}
}

func TestListEmpty(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)
	runner.onCommand("container ls", []byte(""), nil)

	cli, _ := NewAppleCLIWithBin("container", runner)

	result, err := cli.List(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil for empty list, got %v", result)
	}
}

func TestListError(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)
	runner.onCommand("container ls", nil, errors.New("daemon not running"))

	cli, _ := NewAppleCLIWithBin("container", runner)

	_, err := cli.List(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "daemon not running") {
		t.Errorf("error should mention daemon: %v", err)
	}
}

func TestListBadJSON(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)
	runner.onCommand("container ls", []byte("{invalid}"), nil)

	cli, _ := NewAppleCLIWithBin("container", runner)

	_, err := cli.List(context.Background())
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
	if !strings.Contains(err.Error(), "parse ls output") {
		t.Errorf("error should mention parse: %v", err)
	}
}

func TestExecRunnerIntegration(t *testing.T) {
	// Verify ExecRunner satisfies CommandRunner interface.
	var _ CommandRunner = ExecRunner{}
}

// Verify AppleManager satisfies ContainerManager at compile time.
var _ ContainerManager = (*AppleManager)(nil)

func TestRunConfigNoEnvNoVolumes(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)
	runner.onCommand("container run", nil, nil)

	cli, _ := NewAppleCLIWithBin("container", runner)

	err := cli.Run(context.Background(), RunConfig{
		Name:  "minimal",
		Image: "test:latest",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmd := runner.callWith("container run")
	if !strings.Contains(cmd, "--name minimal") {
		t.Errorf("should contain --name: %s", cmd)
	}
	if strings.Contains(cmd, "-e") {
		t.Errorf("should not contain -e with no env vars: %s", cmd)
	}
	if strings.Contains(cmd, "-v") {
		t.Errorf("should not contain -v with no volumes: %s", cmd)
	}
	if !strings.HasSuffix(cmd, "test:latest") {
		t.Errorf("should end with image name: %s", cmd)
	}
}

// newTestAppleManager creates an AppleManager with a mock runner for testing.
// Returns the manager, mock runner, and a temp dir for phantom files.
func newTestAppleManager(t *testing.T) (*AppleManager, *mockRunner, string) {
	t.Helper()
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)

	cli, err := NewAppleCLIWithBin("container", runner)
	if err != nil {
		t.Fatalf("create CLI: %v", err)
	}

	tmpDir := t.TempDir()

	mgr := NewAppleManager(AppleManagerConfig{
		CLI:           cli,
		ContainerName: "openclaw",
	})

	return mgr, runner, tmpDir
}

func TestAppleManagerReloadSecrets(t *testing.T) {
	mgr, runner, tmpDir := newTestAppleManager(t)
	runner.onCommand("container exec openclaw openclaw secrets reload", []byte("ok\n"), nil)

	env := map[string]string{
		"ANTHROPIC_API_KEY": "sk-ant-phantom-abc123",
		"OPENAI_API_KEY":    "sk-phantom-xyz789",
	}

	err := mgr.ReloadSecrets(context.Background(), tmpDir, env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify phantom files were written.
	for name, value := range env {
		data, err := os.ReadFile(filepath.Join(tmpDir, name))
		if err != nil {
			t.Errorf("phantom file %s not found: %v", name, err)
			continue
		}
		if string(data) != value {
			t.Errorf("phantom file %s = %q, want %q", name, string(data), value)
		}
	}

	// Verify exec was called.
	if !runner.called("container exec openclaw openclaw secrets reload") {
		t.Error("expected exec call for secrets reload")
	}
}

func TestAppleManagerReloadSecretsRemoveEmpty(t *testing.T) {
	mgr, runner, tmpDir := newTestAppleManager(t)
	runner.onCommand("container exec", []byte("ok\n"), nil)

	// Write a file first, then remove via empty value.
	path := filepath.Join(tmpDir, "OLD_KEY")
	if err := os.WriteFile(path, []byte("old-value"), 0600); err != nil {
		t.Fatal(err)
	}

	err := mgr.ReloadSecrets(context.Background(), tmpDir, map[string]string{
		"OLD_KEY": "",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected phantom file to be removed")
	}
}

func TestAppleManagerReloadSecretsFallback(t *testing.T) {
	mgr, runner, tmpDir := newTestAppleManager(t)

	// Exec fails, triggering RestartWithEnv fallback.
	runner.onCommand("container exec", nil, errors.New("exec not supported"))

	inspectJSON, _ := json.Marshal([]VMInfo{{
		Name:  "openclaw",
		ID:    "abc123",
		Image: "openclaw/openclaw:latest",
		State: VMState{Status: "running", Running: true},
		Env:   []string{"EXISTING=value"},
	}})
	runner.onCommand("container inspect", inspectJSON, nil)
	runner.onCommand("container stop", nil, nil)
	runner.onCommand("container rm", nil, nil)
	runner.onCommand("container run", nil, nil)

	err := mgr.ReloadSecrets(context.Background(), tmpDir, map[string]string{
		"NEW_KEY": "new-value",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify fallback called stop, rm, run.
	if !runner.called("container stop openclaw") {
		t.Error("expected stop call in fallback")
	}
	if !runner.called("container rm openclaw") {
		t.Error("expected rm call in fallback")
	}
	if !runner.called("container run") {
		t.Error("expected run call in fallback")
	}
}

func TestAppleManagerRestartWithEnv(t *testing.T) {
	mgr, runner, _ := newTestAppleManager(t)

	inspectJSON, _ := json.Marshal([]VMInfo{{
		Name:  "openclaw",
		ID:    "abc123",
		Image: "openclaw/openclaw:latest",
		State: VMState{Status: "running", Running: true},
		Env:   []string{"EXISTING=keep", "UPDATE_ME=old"},
		Mounts: []VMBind{{Source: "/host/phantoms", Destination: "/phantoms"}},
	}})
	runner.onCommand("container inspect", inspectJSON, nil)
	runner.onCommand("container stop", nil, nil)
	runner.onCommand("container rm", nil, nil)
	runner.onCommand("container run", nil, nil)

	err := mgr.RestartWithEnv(context.Background(), map[string]string{
		"UPDATE_ME": "new",
		"NEW_VAR":   "added",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the sequence: inspect, stop, rm, run.
	if !runner.called("container inspect openclaw") {
		t.Error("expected inspect call")
	}
	if !runner.called("container stop openclaw") {
		t.Error("expected stop call")
	}
	if !runner.called("container rm openclaw") {
		t.Error("expected rm call")
	}

	runCmd := runner.callWith("container run")
	if runCmd == "" {
		t.Fatal("expected run call")
	}
	if !strings.Contains(runCmd, "openclaw/openclaw:latest") {
		t.Errorf("run should use original image: %s", runCmd)
	}
	if !strings.Contains(runCmd, "-e UPDATE_ME=new") {
		t.Errorf("run should contain updated env: %s", runCmd)
	}
	if !strings.Contains(runCmd, "-e NEW_VAR=added") {
		t.Errorf("run should contain new env: %s", runCmd)
	}
	if !strings.Contains(runCmd, "-e EXISTING=keep") {
		t.Errorf("run should preserve existing env: %s", runCmd)
	}
	// Verify volumes from inspect output are preserved.
	if !strings.Contains(runCmd, "-v /host/phantoms:/phantoms") {
		t.Errorf("run should preserve inspected volumes: %s", runCmd)
	}
}

func TestAppleManagerRestartWithEnvRemoval(t *testing.T) {
	mgr, runner, _ := newTestAppleManager(t)

	inspectJSON, _ := json.Marshal([]VMInfo{{
		Name:  "openclaw",
		ID:    "abc123",
		Image: "openclaw/openclaw:latest",
		State: VMState{Status: "running", Running: true},
		Env:   []string{"KEEP=yes", "REMOVE=old"},
	}})
	runner.onCommand("container inspect", inspectJSON, nil)
	runner.onCommand("container stop", nil, nil)
	runner.onCommand("container rm", nil, nil)
	runner.onCommand("container run", nil, nil)

	err := mgr.RestartWithEnv(context.Background(), map[string]string{
		"REMOVE": "",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	runCmd := runner.callWith("container run")
	if strings.Contains(runCmd, "REMOVE") {
		t.Errorf("run should not contain removed env var: %s", runCmd)
	}
	if !strings.Contains(runCmd, "-e KEEP=yes") {
		t.Errorf("run should preserve kept env var: %s", runCmd)
	}
}

func TestAppleManagerRestartWithEnvInspectError(t *testing.T) {
	mgr, runner, _ := newTestAppleManager(t)
	runner.onCommand("container inspect", nil, errors.New("VM not found"))

	err := mgr.RestartWithEnv(context.Background(), map[string]string{"K": "V"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "inspect VM") {
		t.Errorf("error should mention inspect: %v", err)
	}
}

func TestAppleManagerRestartWithEnvStopError(t *testing.T) {
	mgr, runner, _ := newTestAppleManager(t)

	inspectJSON, _ := json.Marshal([]VMInfo{{
		Name: "openclaw", Image: "img:latest", State: VMState{Running: true},
	}})
	runner.onCommand("container inspect", inspectJSON, nil)
	runner.onCommand("container stop", nil, errors.New("stop failed"))

	err := mgr.RestartWithEnv(context.Background(), map[string]string{"K": "V"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "stop VM") {
		t.Errorf("error should mention stop: %v", err)
	}
}

func TestAppleManagerInjectMCPConfig(t *testing.T) {
	mgr, runner, tmpDir := newTestAppleManager(t)
	runner.onCommand("container exec openclaw openclaw mcp reload", []byte("ok\n"), nil)

	err := mgr.InjectMCPConfig(tmpDir, "http://localhost:3000/mcp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify mcp-servers.json was written.
	data, err := os.ReadFile(filepath.Join(tmpDir, "mcp-servers.json"))
	if err != nil {
		t.Fatalf("mcp-servers.json not found: %v", err)
	}
	if !strings.Contains(string(data), "http://localhost:3000/mcp") {
		t.Errorf("mcp config should contain sluice URL: %s", string(data))
	}
	if !strings.Contains(string(data), "sluice") {
		t.Errorf("mcp config should contain sluice key: %s", string(data))
	}

	// Verify exec was called.
	if !runner.called("container exec openclaw openclaw mcp reload") {
		t.Error("expected exec call for mcp reload")
	}
}

func TestAppleManagerInjectMCPConfigExecError(t *testing.T) {
	mgr, runner, tmpDir := newTestAppleManager(t)
	runner.onCommand("container exec", nil, errors.New("exec failed"))

	err := mgr.InjectMCPConfig(tmpDir, "http://localhost:3000/mcp")
	if err == nil {
		t.Fatal("expected error when exec fails")
	}
}

func TestAppleManagerStatus(t *testing.T) {
	mgr, runner, _ := newTestAppleManager(t)

	inspectJSON, _ := json.Marshal([]VMInfo{{
		Name:  "openclaw",
		ID:    "vm-abc123",
		Image: "openclaw/openclaw:latest",
		State: VMState{Status: "running", Running: true},
	}})
	runner.onCommand("container inspect", inspectJSON, nil)

	status, err := mgr.Status(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.ID != "vm-abc123" {
		t.Errorf("ID = %q, want vm-abc123", status.ID)
	}
	if !status.Running {
		t.Error("should be running")
	}
	if status.Image != "openclaw/openclaw:latest" {
		t.Errorf("Image = %q, want openclaw/openclaw:latest", status.Image)
	}
}

func TestAppleManagerStatusStopped(t *testing.T) {
	mgr, runner, _ := newTestAppleManager(t)

	inspectJSON, _ := json.Marshal([]VMInfo{{
		Name:  "openclaw",
		ID:    "vm-abc123",
		Image: "openclaw/openclaw:latest",
		State: VMState{Status: "stopped", Running: false},
	}})
	runner.onCommand("container inspect", inspectJSON, nil)

	status, err := mgr.Status(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Running {
		t.Error("should not be running")
	}
}

func TestAppleManagerStatusError(t *testing.T) {
	mgr, runner, _ := newTestAppleManager(t)
	runner.onCommand("container inspect", nil, errors.New("VM not found"))

	_, err := mgr.Status(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAppleManagerStop(t *testing.T) {
	mgr, runner, _ := newTestAppleManager(t)
	runner.onCommand("container stop", nil, nil)

	err := mgr.Stop(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !runner.called("container stop openclaw") {
		t.Error("expected stop call with container name")
	}
}

func TestAppleManagerStopError(t *testing.T) {
	mgr, runner, _ := newTestAppleManager(t)
	runner.onCommand("container stop", nil, errors.New("already stopped"))

	err := mgr.Stop(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAppleManagerRuntime(t *testing.T) {
	mgr, _, _ := newTestAppleManager(t)
	if mgr.Runtime() != RuntimeApple {
		t.Errorf("Runtime() = %v, want RuntimeApple", mgr.Runtime())
	}
}

func TestCACertEnvVars(t *testing.T) {
	envs := CACertEnvVars("/certs/sluice-ca.crt")

	want := map[string]string{
		"SSL_CERT_FILE":       "/certs/sluice-ca.crt",
		"REQUESTS_CA_BUNDLE":  "/certs/sluice-ca.crt",
		"NODE_EXTRA_CA_CERTS": "/certs/sluice-ca.crt",
	}
	for k, v := range want {
		if envs[k] != v {
			t.Errorf("CACertEnvVars[%q] = %q, want %q", k, envs[k], v)
		}
	}
	if len(envs) != len(want) {
		t.Errorf("CACertEnvVars returned %d entries, want %d", len(envs), len(want))
	}
}

func TestCACertGuestPath(t *testing.T) {
	if CACertGuestPath == "" {
		t.Error("CACertGuestPath should not be empty")
	}
	if !strings.HasSuffix(CACertGuestPath, ".crt") {
		t.Errorf("CACertGuestPath = %q, should end with .crt", CACertGuestPath)
	}
}

func TestInjectCACertLinuxGuest(t *testing.T) {
	mgr, runner, _ := newTestAppleManager(t)

	// update-ca-certificates succeeds (Linux guest).
	runner.onCommand("container exec openclaw update-ca-certificates", []byte("ok\n"), nil)

	// Create a fake CA cert file.
	hostCertDir := t.TempDir()
	hostCertPath := filepath.Join(hostCertDir, "ca-cert.pem")
	certContent := "-----BEGIN CERTIFICATE-----\nfake-cert-data\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(hostCertPath, []byte(certContent), 0644); err != nil {
		t.Fatal(err)
	}

	destDir := t.TempDir()
	err := mgr.InjectCACert(context.Background(), hostCertPath, destDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify cert was copied to shared volume.
	data, err := os.ReadFile(filepath.Join(destDir, "sluice-ca.crt"))
	if err != nil {
		t.Fatalf("cert file not found in shared volume: %v", err)
	}
	if string(data) != certContent {
		t.Errorf("cert content = %q, want %q", string(data), certContent)
	}

	// Verify update-ca-certificates was called.
	if !runner.called("container exec openclaw update-ca-certificates") {
		t.Error("expected update-ca-certificates exec call")
	}
}

func TestInjectCACertMacOSGuest(t *testing.T) {
	mgr, runner, _ := newTestAppleManager(t)

	// Linux update-ca-certificates fails, macOS security command succeeds.
	runner.onCommand("container exec openclaw update-ca-certificates", nil, errors.New("command not found"))
	runner.onCommand("container exec openclaw security", []byte("ok\n"), nil)

	hostCertDir := t.TempDir()
	hostCertPath := filepath.Join(hostCertDir, "ca-cert.pem")
	if err := os.WriteFile(hostCertPath, []byte("cert-data"), 0644); err != nil {
		t.Fatal(err)
	}

	destDir := t.TempDir()
	err := mgr.InjectCACert(context.Background(), hostCertPath, destDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify security command was called with correct arguments.
	cmd := runner.callWith("container exec openclaw security")
	if cmd == "" {
		t.Fatal("expected macOS security exec call")
	}
	if !strings.Contains(cmd, "add-trusted-cert") {
		t.Errorf("security command should include add-trusted-cert: %s", cmd)
	}
	if !strings.Contains(cmd, "trustRoot") {
		t.Errorf("security command should include trustRoot: %s", cmd)
	}
	if !strings.Contains(cmd, CACertGuestPath) {
		t.Errorf("security command should include guest cert path: %s", cmd)
	}
}

func TestInjectCACertBothTrustCommandsFail(t *testing.T) {
	mgr, runner, _ := newTestAppleManager(t)

	// Both trust commands fail. Should still succeed (env vars cover it).
	runner.onCommand("container exec openclaw update-ca-certificates", nil, errors.New("not found"))
	runner.onCommand("container exec openclaw security", nil, errors.New("not found"))

	hostCertDir := t.TempDir()
	hostCertPath := filepath.Join(hostCertDir, "ca-cert.pem")
	if err := os.WriteFile(hostCertPath, []byte("cert-data"), 0644); err != nil {
		t.Fatal(err)
	}

	destDir := t.TempDir()
	err := mgr.InjectCACert(context.Background(), hostCertPath, destDir)
	if err != nil {
		t.Fatalf("should not error when trust commands fail (env vars suffice): %v", err)
	}

	// Cert should still be written to shared volume.
	if _, err := os.Stat(filepath.Join(destDir, "sluice-ca.crt")); err != nil {
		t.Errorf("cert file should exist in shared volume: %v", err)
	}
}

func TestInjectCACertMissingHostCert(t *testing.T) {
	mgr, _, _ := newTestAppleManager(t)

	err := mgr.InjectCACert(context.Background(), "/nonexistent/ca-cert.pem", t.TempDir())
	if err == nil {
		t.Fatal("expected error for missing host cert")
	}
	if !strings.Contains(err.Error(), "read CA cert") {
		t.Errorf("error should mention read CA cert: %v", err)
	}
}

func TestInjectCACertWriteError(t *testing.T) {
	mgr, _, _ := newTestAppleManager(t)

	hostCertDir := t.TempDir()
	hostCertPath := filepath.Join(hostCertDir, "ca-cert.pem")
	if err := os.WriteFile(hostCertPath, []byte("cert-data"), 0644); err != nil {
		t.Fatal(err)
	}

	// Use a non-writable path as the dest dir.
	err := mgr.InjectCACert(context.Background(), hostCertPath, "/dev/null/impossible")
	if err == nil {
		t.Fatal("expected error for unwritable dest dir")
	}
}
