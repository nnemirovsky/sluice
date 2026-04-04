package container

import (
	"context"
	"encoding/json"
	"errors"
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
