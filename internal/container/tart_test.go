package container

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewTartCLI(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)

	cli, err := NewTartCLI(runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cli == nil {
		t.Fatal("expected non-nil CLI")
	}
	if cli.bin != "tart" {
		t.Errorf("bin = %q, want tart", cli.bin)
	}
}

func TestNewTartCLIBinaryNotFound(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", nil, errors.New("exec: \"tart\": executable file not found in $PATH"))

	cli, err := NewTartCLI(runner)
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

func TestNewTartCLIWithCustomBin(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("/opt/homebrew/bin/tart --version", []byte("tart 2.15.0\n"), nil)

	cli, err := NewTartCLIWithBin("/opt/homebrew/bin/tart", runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cli.bin != "/opt/homebrew/bin/tart" {
		t.Errorf("bin = %q, want /opt/homebrew/bin/tart", cli.bin)
	}
}

func TestTartClone(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart clone", nil, nil)

	cli, _ := NewTartCLIWithBin("tart", runner)

	err := cli.Clone(context.Background(), "ghcr.io/cirruslabs/macos-sequoia-base:latest", "openclaw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmd := runner.callWith("tart clone")
	if cmd == "" {
		t.Fatal("tart clone not called")
	}
	if !strings.Contains(cmd, "ghcr.io/cirruslabs/macos-sequoia-base:latest") {
		t.Errorf("should contain image: %s", cmd)
	}
	if !strings.Contains(cmd, "openclaw") {
		t.Errorf("should contain VM name: %s", cmd)
	}
}

func TestTartCloneError(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart clone", nil, errors.New("pull failed: authentication required"))

	cli, _ := NewTartCLIWithBin("tart", runner)

	err := cli.Clone(context.Background(), "private-registry/image:latest", "vm1")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "authentication required") {
		t.Errorf("error should mention auth: %v", err)
	}
}

func TestTartRunArgs(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)

	cli, _ := NewTartCLIWithBin("tart", runner)

	args := cli.RunArgs(TartRunConfig{
		Name: "openclaw",
		DirMounts: []TartDirMount{
			{Name: "phantoms", HostPath: "/tmp/phantoms"},
			{Name: "ca", HostPath: "/tmp/ca", ReadOnly: true},
		},
		NoGraphics: true,
	})

	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "run openclaw") {
		t.Errorf("should start with run <name>: %s", joined)
	}
	if !strings.Contains(joined, "--dir=phantoms:/tmp/phantoms") {
		t.Errorf("should contain phantoms dir mount: %s", joined)
	}
	if !strings.Contains(joined, "--dir=ca:/tmp/ca:ro") {
		t.Errorf("should contain read-only ca dir mount: %s", joined)
	}
	if !strings.Contains(joined, "--no-graphics") {
		t.Errorf("should contain --no-graphics: %s", joined)
	}
}

func TestTartRunArgsMinimal(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)

	cli, _ := NewTartCLIWithBin("tart", runner)

	args := cli.RunArgs(TartRunConfig{
		Name: "minimal",
	})

	joined := strings.Join(args, " ")
	if joined != "run minimal" {
		t.Errorf("minimal args = %q, want %q", joined, "run minimal")
	}
}

func TestTartRun(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart run", nil, nil)

	cli, _ := NewTartCLIWithBin("tart", runner)

	err := cli.Run(context.Background(), TartRunConfig{
		Name: "openclaw",
		DirMounts: []TartDirMount{
			{Name: "phantoms", HostPath: "/tmp/phantoms"},
		},
		NoGraphics: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmd := runner.callWith("tart run")
	if cmd == "" {
		t.Fatal("tart run not called")
	}
	if !strings.Contains(cmd, "--no-graphics") {
		t.Errorf("should contain --no-graphics: %s", cmd)
	}
	if !strings.Contains(cmd, "--dir=phantoms:/tmp/phantoms") {
		t.Errorf("should contain dir mount: %s", cmd)
	}
}

func TestTartRunError(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart run", nil, errors.New("VM not found"))

	cli, _ := NewTartCLIWithBin("tart", runner)

	err := cli.Run(context.Background(), TartRunConfig{Name: "nonexistent"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "VM not found") {
		t.Errorf("error should mention VM not found: %v", err)
	}
}

func TestTartExec(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart exec", []byte("reload complete\n"), nil)

	cli, _ := NewTartCLIWithBin("tart", runner)

	out, err := cli.Exec(context.Background(), "openclaw", []string{"openclaw", "secrets", "reload"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != "reload complete\n" {
		t.Errorf("output = %q, want reload complete", string(out))
	}

	cmd := runner.callWith("tart exec")
	if !strings.Contains(cmd, "exec openclaw -- openclaw secrets reload") {
		t.Errorf("wrong exec command: %s", cmd)
	}
}

func TestTartExecError(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart exec", nil, errors.New("VM not running"))

	cli, _ := NewTartCLIWithBin("tart", runner)

	_, err := cli.Exec(context.Background(), "openclaw", []string{"ls"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "VM not running") {
		t.Errorf("error should mention VM not running: %v", err)
	}
}

func TestTartStop(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart stop", nil, nil)

	cli, _ := NewTartCLIWithBin("tart", runner)

	err := cli.Stop(context.Background(), "openclaw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmd := runner.callWith("tart stop")
	if !strings.Contains(cmd, "stop openclaw") {
		t.Errorf("wrong stop command: %s", cmd)
	}
}

func TestTartStopError(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart stop", nil, errors.New("no such VM"))

	cli, _ := NewTartCLIWithBin("tart", runner)

	err := cli.Stop(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTartDelete(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart delete", nil, nil)

	cli, _ := NewTartCLIWithBin("tart", runner)

	err := cli.Delete(context.Background(), "openclaw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmd := runner.callWith("tart delete")
	if !strings.Contains(cmd, "delete openclaw") {
		t.Errorf("wrong delete command: %s", cmd)
	}
}

func TestTartDeleteError(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart delete", nil, errors.New("VM is running"))

	cli, _ := NewTartCLIWithBin("tart", runner)

	err := cli.Delete(context.Background(), "openclaw")
	if err == nil {
		t.Fatal("expected error when VM is running")
	}
}

func TestTartList(t *testing.T) {
	entries := []TartVMEntry{
		{Name: "openclaw", Source: "ghcr.io/cirruslabs/macos-sequoia-base:latest", State: "running", OS: "darwin"},
		{Name: "dev-vm", Source: "local", State: "stopped", OS: "darwin"},
	}
	listJSON, _ := json.Marshal(entries)

	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart list", listJSON, nil)

	cli, _ := NewTartCLIWithBin("tart", runner)

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
	if result[0].OS != "darwin" {
		t.Errorf("first entry OS = %q, want darwin", result[0].OS)
	}
	if result[1].Name != "dev-vm" {
		t.Errorf("second entry Name = %q, want dev-vm", result[1].Name)
	}

	cmd := runner.callWith("tart list")
	if !strings.Contains(cmd, "--format json") {
		t.Errorf("list should use --format json: %s", cmd)
	}
}

func TestTartListEmpty(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart list", []byte(""), nil)

	cli, _ := NewTartCLIWithBin("tart", runner)

	result, err := cli.List(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil for empty list, got %v", result)
	}
}

func TestTartListError(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart list", nil, errors.New("tart daemon not running"))

	cli, _ := NewTartCLIWithBin("tart", runner)

	_, err := cli.List(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "tart daemon not running") {
		t.Errorf("error should mention daemon: %v", err)
	}
}

func TestTartListBadJSON(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart list", []byte("{invalid}"), nil)

	cli, _ := NewTartCLIWithBin("tart", runner)

	_, err := cli.List(context.Background())
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
	if !strings.Contains(err.Error(), "parse list output") {
		t.Errorf("error should mention parse: %v", err)
	}
}

func TestTartIP(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart ip", []byte("192.168.64.5\n"), nil)

	cli, _ := NewTartCLIWithBin("tart", runner)

	ip, err := cli.IP(context.Background(), "openclaw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "192.168.64.5" {
		t.Errorf("IP = %q, want 192.168.64.5", ip)
	}

	cmd := runner.callWith("tart ip")
	if !strings.Contains(cmd, "ip openclaw") {
		t.Errorf("wrong ip command: %s", cmd)
	}
}

func TestTartIPError(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart ip", nil, errors.New("VM not running"))

	cli, _ := NewTartCLIWithBin("tart", runner)

	_, err := cli.IP(context.Background(), "openclaw")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "VM not running") {
		t.Errorf("error should mention VM not running: %v", err)
	}
}

func TestTartIPEmpty(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart ip", []byte("  \n"), nil)

	cli, _ := NewTartCLIWithBin("tart", runner)

	_, err := cli.IP(context.Background(), "openclaw")
	if err == nil {
		t.Fatal("expected error for empty IP")
	}
	if !strings.Contains(err.Error(), "empty result") {
		t.Errorf("error should mention empty: %v", err)
	}
}

func TestTartVMExists(t *testing.T) {
	entries := []TartVMEntry{
		{Name: "openclaw", State: "running"},
		{Name: "other-vm", State: "stopped"},
	}
	listJSON, _ := json.Marshal(entries)

	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart list", listJSON, nil)

	cli, _ := NewTartCLIWithBin("tart", runner)

	exists, err := cli.VMExists(context.Background(), "openclaw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected VM to exist")
	}
}

func TestTartVMExistsNotFound(t *testing.T) {
	entries := []TartVMEntry{
		{Name: "other-vm", State: "stopped"},
	}
	listJSON, _ := json.Marshal(entries)

	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart list", listJSON, nil)

	cli, _ := NewTartCLIWithBin("tart", runner)

	exists, err := cli.VMExists(context.Background(), "openclaw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Error("expected VM to not exist")
	}
}

func TestTartVMExistsListError(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart list", nil, errors.New("command failed"))

	cli, _ := NewTartCLIWithBin("tart", runner)

	_, err := cli.VMExists(context.Background(), "openclaw")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTartVMState(t *testing.T) {
	entries := []TartVMEntry{
		{Name: "openclaw", State: "running"},
	}
	listJSON, _ := json.Marshal(entries)

	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart list", listJSON, nil)

	cli, _ := NewTartCLIWithBin("tart", runner)

	state, err := cli.VMState(context.Background(), "openclaw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state != "running" {
		t.Errorf("State = %q, want running", state)
	}
}

func TestTartVMStateNotFound(t *testing.T) {
	entries := []TartVMEntry{
		{Name: "other-vm", State: "stopped"},
	}
	listJSON, _ := json.Marshal(entries)

	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart list", listJSON, nil)

	cli, _ := NewTartCLIWithBin("tart", runner)

	state, err := cli.VMState(context.Background(), "openclaw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state != "" {
		t.Errorf("State = %q, want empty for non-existent VM", state)
	}
}

// Verify TartManager satisfies ContainerManager at compile time.
var _ ContainerManager = (*TartManager)(nil)

// newTestTartManager creates a TartManager with a mock runner for testing.
// The startVM function is replaced with a mock that records the call and
// returns a nil Cmd (tests that need cmd.Wait() must override startVM).
func newTestTartManager(t *testing.T) (*TartManager, *mockRunner) {
	t.Helper()
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)

	cli, err := NewTartCLIWithBin("tart", runner)
	if err != nil {
		t.Fatalf("create CLI: %v", err)
	}

	mgr := NewTartManager(TartManagerConfig{
		CLI:    cli,
		VMName: "openclaw",
		RunConfig: TartRunConfig{
			Name: "openclaw",
			DirMounts: []TartDirMount{
				{Name: "phantoms", HostPath: "/tmp/phantoms"},
				{Name: "ca", HostPath: "/tmp/ca", ReadOnly: true},
			},
			NoGraphics: true,
		},
	})

	// Replace startVM with a mock that uses the runner (so mock command
	// matching works) and returns a completed Cmd from a no-op process.
	mgr.startVM = func(cfg TartRunConfig) (*exec.Cmd, error) {
		args := cli.RunArgs(cfg)
		_, runErr := runner.Run(context.Background(), "tart", args...)
		if runErr != nil {
			return nil, runErr
		}
		// Return a real Cmd that has already exited (true is a no-op).
		cmd := exec.Command("true")
		_ = cmd.Start()
		return cmd, nil
	}

	return mgr, runner
}

func TestTartManagerRestartWithEnv(t *testing.T) {
	mgr, runner := newTestTartManager(t)

	runner.onCommand("tart stop", nil, nil)
	runner.onCommand("tart run", nil, nil)

	err := mgr.RestartWithEnv(context.Background(), map[string]string{
		"SOME_KEY": "some-value",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify stop was called.
	if !runner.called("tart stop openclaw") {
		t.Error("expected stop call")
	}

	// Verify run was called with the stored config.
	runCmd := runner.callWith("tart run")
	if runCmd == "" {
		t.Fatal("expected run call")
	}
	if !strings.Contains(runCmd, "run openclaw") {
		t.Errorf("run should use VM name: %s", runCmd)
	}
	if !strings.Contains(runCmd, "--dir=phantoms:/tmp/phantoms") {
		t.Errorf("run should preserve dir mounts: %s", runCmd)
	}
	if !strings.Contains(runCmd, "--dir=ca:/tmp/ca:ro") {
		t.Errorf("run should preserve read-only dir mount: %s", runCmd)
	}
	if !strings.Contains(runCmd, "--no-graphics") {
		t.Errorf("run should preserve --no-graphics: %s", runCmd)
	}

	// No delete or clone should happen.
	if runner.called("tart delete") {
		t.Error("RestartWithEnv should not delete")
	}
	if runner.called("tart clone") {
		t.Error("RestartWithEnv should not clone")
	}
}

func TestTartManagerInjectEnvVars(t *testing.T) {
	mgr, runner := newTestTartManager(t)
	runner.onCommand("tart exec openclaw -- sh", []byte(""), nil)
	runner.onCommand("tart exec openclaw -- openclaw secrets reload", []byte("ok\n"), nil)

	err := mgr.InjectEnvVars(context.Background(), map[string]string{
		"OPENAI_API_KEY": "sk-phantom-xyz789",
	}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify exec was called with sh -c and the env var name.
	found := false
	for _, call := range runner.calls {
		if strings.Contains(call, "sh") && strings.Contains(call, "OPENAI_API_KEY") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected exec call with sh script containing env var name")
	}
}

func TestTartManagerInjectEnvVarsEmpty(t *testing.T) {
	mgr, runner := newTestTartManager(t)

	err := mgr.InjectEnvVars(context.Background(), map[string]string{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only the --version call from setup should exist.
	for _, call := range runner.calls {
		if strings.Contains(call, "exec") {
			t.Errorf("no exec calls expected for empty envMap, got: %s", call)
		}
	}
}

func TestTartManagerRestartWithEnvStopError(t *testing.T) {
	mgr, runner := newTestTartManager(t)
	runner.onCommand("tart stop", nil, errors.New("VM already stopped"))

	err := mgr.RestartWithEnv(context.Background(), map[string]string{"K": "V"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "stop VM") {
		t.Errorf("error should mention stop: %v", err)
	}
}

func TestTartManagerRestartWithEnvRunError(t *testing.T) {
	mgr, runner := newTestTartManager(t)
	runner.onCommand("tart stop", nil, nil)
	runner.onCommand("tart run", nil, errors.New("failed to start VM"))

	err := mgr.RestartWithEnv(context.Background(), map[string]string{"K": "V"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "restart VM") {
		t.Errorf("error should mention restart VM: %v", err)
	}
}

func TestTartManagerStatus(t *testing.T) {
	mgr, runner := newTestTartManager(t)

	entries := []TartVMEntry{
		{Name: "openclaw", Source: "ghcr.io/cirruslabs/macos-sequoia-base:latest", State: "running", OS: "darwin"},
	}
	listJSON, _ := json.Marshal(entries)
	runner.onCommand("tart list", listJSON, nil)

	status, err := mgr.Status(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.ID != "openclaw" {
		t.Errorf("ID = %q, want openclaw", status.ID)
	}
	if !status.Running {
		t.Error("should be running")
	}
	if status.Image != "ghcr.io/cirruslabs/macos-sequoia-base:latest" {
		t.Errorf("Image = %q, want ghcr.io/cirruslabs/macos-sequoia-base:latest", status.Image)
	}
}

func TestTartManagerStatusStopped(t *testing.T) {
	mgr, runner := newTestTartManager(t)

	entries := []TartVMEntry{
		{Name: "openclaw", Source: "local", State: "stopped"},
	}
	listJSON, _ := json.Marshal(entries)
	runner.onCommand("tart list", listJSON, nil)

	status, err := mgr.Status(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Running {
		t.Error("should not be running")
	}
}

func TestTartManagerStatusNotFound(t *testing.T) {
	mgr, runner := newTestTartManager(t)

	entries := []TartVMEntry{
		{Name: "other-vm", State: "running"},
	}
	listJSON, _ := json.Marshal(entries)
	runner.onCommand("tart list", listJSON, nil)

	_, err := mgr.Status(context.Background())
	if err == nil {
		t.Fatal("expected error when VM not found")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention not found: %v", err)
	}
}

func TestTartManagerStatusListError(t *testing.T) {
	mgr, runner := newTestTartManager(t)
	runner.onCommand("tart list", nil, errors.New("tart daemon not running"))

	_, err := mgr.Status(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTartManagerStop(t *testing.T) {
	mgr, runner := newTestTartManager(t)
	runner.onCommand("tart stop", nil, nil)

	err := mgr.Stop(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !runner.called("tart stop openclaw") {
		t.Error("expected stop call with VM name")
	}
}

func TestTartManagerStopError(t *testing.T) {
	mgr, runner := newTestTartManager(t)
	runner.onCommand("tart stop", nil, errors.New("already stopped"))

	err := mgr.Stop(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTartManagerRuntime(t *testing.T) {
	mgr, _ := newTestTartManager(t)
	if mgr.Runtime() != RuntimeMacOS {
		t.Errorf("Runtime() = %v, want RuntimeMacOS", mgr.Runtime())
	}
}

func TestTartManagerInjectCACert(t *testing.T) {
	mgr, runner := newTestTartManager(t)

	// security add-trusted-cert succeeds.
	runner.onCommand("tart exec openclaw -- security", []byte("ok\n"), nil)
	// launchctl setenv calls succeed.
	runner.onCommand("tart exec openclaw -- launchctl", nil, nil)

	// Create a fake CA cert file.
	hostCertDir := t.TempDir()
	hostCertPath := filepath.Join(hostCertDir, "ca-cert.pem")
	certContent := "-----BEGIN CERTIFICATE-----\nfake-cert-data\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(hostCertPath, []byte(certContent), 0o644); err != nil {
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

	// Verify security add-trusted-cert was called with correct arguments.
	cmd := runner.callWith("tart exec openclaw -- security")
	if cmd == "" {
		t.Fatal("expected security exec call")
	}
	if !strings.Contains(cmd, "add-trusted-cert") {
		t.Errorf("security command should include add-trusted-cert: %s", cmd)
	}
	if !strings.Contains(cmd, "trustRoot") {
		t.Errorf("security command should include trustRoot: %s", cmd)
	}
	if !strings.Contains(cmd, "/Library/Keychains/System.keychain") {
		t.Errorf("security command should include System.keychain: %s", cmd)
	}
	if !strings.Contains(cmd, TartCACertGuestPath) {
		t.Errorf("security command should include tart guest cert path %q: %s", TartCACertGuestPath, cmd)
	}

	// Verify launchctl setenv was called for env var fallback.
	if !runner.called("tart exec openclaw -- launchctl setenv") {
		t.Error("expected launchctl setenv exec call for env var fallback")
	}
}

func TestTartManagerInjectCACertSecurityFails(t *testing.T) {
	mgr, runner := newTestTartManager(t)

	// security add-trusted-cert fails (non-admin, guest not ready, etc.).
	runner.onCommand("tart exec openclaw -- security", nil, errors.New("errSecAuthFailed"))
	// launchctl setenv calls succeed (best-effort).
	runner.onCommand("tart exec openclaw -- launchctl", nil, nil)

	hostCertDir := t.TempDir()
	hostCertPath := filepath.Join(hostCertDir, "ca-cert.pem")
	if err := os.WriteFile(hostCertPath, []byte("cert-data"), 0o644); err != nil {
		t.Fatal(err)
	}

	destDir := t.TempDir()
	err := mgr.InjectCACert(context.Background(), hostCertPath, destDir)
	if err != nil {
		t.Fatalf("should not error when security command fails (env vars cover it): %v", err)
	}

	// Cert should still be written to shared volume.
	if _, err := os.Stat(filepath.Join(destDir, "sluice-ca.crt")); err != nil {
		t.Errorf("cert file should exist in shared volume: %v", err)
	}
}

func TestTartManagerInjectCACertMissingHostCert(t *testing.T) {
	mgr, _ := newTestTartManager(t)

	err := mgr.InjectCACert(context.Background(), "/nonexistent/ca-cert.pem", t.TempDir())
	if err == nil {
		t.Fatal("expected error for missing host cert")
	}
	if !strings.Contains(err.Error(), "read CA cert") {
		t.Errorf("error should mention read CA cert: %v", err)
	}
}

func TestTartManagerInjectCACertWriteError(t *testing.T) {
	mgr, _ := newTestTartManager(t)

	hostCertDir := t.TempDir()
	hostCertPath := filepath.Join(hostCertDir, "ca-cert.pem")
	if err := os.WriteFile(hostCertPath, []byte("cert-data"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Use a non-writable path as the dest dir.
	err := mgr.InjectCACert(context.Background(), hostCertPath, "/dev/null/impossible")
	if err == nil {
		t.Fatal("expected error for unwritable dest dir")
	}
}

func TestTartManagerInjectCACertEnvVarNames(t *testing.T) {
	mgr, runner := newTestTartManager(t)

	// Both commands succeed.
	runner.onCommand("tart exec openclaw -- security", []byte("ok\n"), nil)
	runner.onCommand("tart exec openclaw -- launchctl", nil, nil)

	hostCertDir := t.TempDir()
	hostCertPath := filepath.Join(hostCertDir, "ca-cert.pem")
	if err := os.WriteFile(hostCertPath, []byte("cert-data"), 0o644); err != nil {
		t.Fatal(err)
	}

	destDir := t.TempDir()
	if err := mgr.InjectCACert(context.Background(), hostCertPath, destDir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify that launchctl setenv was called for each expected env var.
	expectedVars := []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"}
	for _, envVar := range expectedVars {
		found := false
		for _, call := range runner.calls {
			if strings.Contains(call, "launchctl setenv "+envVar) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected launchctl setenv %s call", envVar)
		}
	}
}

func TestTartManagerVMIP(t *testing.T) {
	mgr, runner := newTestTartManager(t)
	runner.onCommand("tart ip", []byte("192.168.64.5\n"), nil)

	ip, err := mgr.VMIP(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "192.168.64.5" {
		t.Errorf("IP = %q, want 192.168.64.5", ip)
	}
}

func TestTartManagerVMIPError(t *testing.T) {
	mgr, runner := newTestTartManager(t)
	runner.onCommand("tart ip", nil, errors.New("VM not running"))

	_, err := mgr.VMIP(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "VM not running") {
		t.Errorf("error should mention VM not running: %v", err)
	}
}

func TestTartManagerSetupNetworkRouting(t *testing.T) {
	mgr, runner := newTestTartManager(t)

	// Mock tart ip response.
	runner.onCommand("tart ip", []byte("192.168.64.5\n"), nil)
	// Mock ifconfig to detect TUN interface (tun2proxy running).
	runner.onCommand("ifconfig utun3", []byte("utun3: flags=...\n"), nil)
	// Mock pfctl calls.
	pfConf := writeTempPFConf(t, "# default pf rules\n")
	runner.onCommand("pfctl -f", nil, nil)
	runner.onCommand("pfctl -a sluice -f", nil, nil)
	runner.onCommand("pfctl -e", nil, nil)

	router := NewNetworkRouter(NetworkRouterConfig{
		Runner:     runner,
		AnchorName: "sluice",
		TUNIface:   "utun3",
		PFConfPath: pfConf,
	})

	err := mgr.SetupNetworkRouting(context.Background(), router, "192.168.64.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify tart ip was called to get VM IP.
	if !runner.called("tart ip openclaw") {
		t.Error("expected tart ip call")
	}

	// Verify ifconfig was called to check TUN interface.
	if !runner.called("ifconfig utun3") {
		t.Error("expected ifconfig call to check TUN interface")
	}

	// Verify pfctl was called to load anchor rules.
	if !runner.called("pfctl -a sluice -f") {
		t.Error("expected pfctl call to load anchor rules")
	}

	// Verify anchor reference was added to pf.conf.
	data, _ := os.ReadFile(pfConf)
	if !strings.Contains(string(data), `anchor "sluice"`) {
		t.Error("pf.conf should contain anchor reference after setup")
	}
}

func TestTartManagerSetupNetworkRoutingIPError(t *testing.T) {
	mgr, runner := newTestTartManager(t)

	// tart ip fails.
	runner.onCommand("tart ip", nil, errors.New("VM not running"))
	// ifconfig check for TUN.
	runner.onCommand("ifconfig utun3", []byte("utun3: flags=...\n"), nil)

	router := NewNetworkRouter(NetworkRouterConfig{
		Runner:     runner,
		AnchorName: "sluice",
		TUNIface:   "utun3",
		PFConfPath: writeTempPFConf(t, ""),
	})

	err := mgr.SetupNetworkRouting(context.Background(), router, "192.168.64.1")
	if err == nil {
		t.Fatal("expected error when tart ip fails")
	}
	if !strings.Contains(err.Error(), "detect bridge interface") {
		t.Errorf("error should mention bridge detection: %v", err)
	}
}

func TestTartManagerSetupNetworkRoutingTun2proxyNotRunning(t *testing.T) {
	mgr, runner := newTestTartManager(t)

	// tart ip succeeds.
	runner.onCommand("tart ip", []byte("192.168.64.5\n"), nil)
	// ifconfig fails (TUN interface does not exist).
	runner.onCommand("ifconfig utun3", nil, errors.New("interface does not exist"))
	// pfctl calls succeed.
	pfConf := writeTempPFConf(t, "# default pf rules\n")
	runner.onCommand("pfctl -f", nil, nil)
	runner.onCommand("pfctl -a sluice -f", nil, nil)
	runner.onCommand("pfctl -e", nil, nil)

	router := NewNetworkRouter(NetworkRouterConfig{
		Runner:     runner,
		AnchorName: "sluice",
		TUNIface:   "utun3",
		PFConfPath: pfConf,
	})

	// Should succeed even if tun2proxy is not running (just logs a warning).
	err := mgr.SetupNetworkRouting(context.Background(), router, "192.168.64.1")
	if err != nil {
		t.Fatalf("should succeed even without tun2proxy: %v", err)
	}

	// pf rules should still be applied.
	if !runner.called("pfctl -a sluice -f") {
		t.Error("expected pfctl call even when tun2proxy is not running")
	}
}

func TestTartManagerTeardownNetworkRouting(t *testing.T) {
	mgr, runner := newTestTartManager(t)

	runner.onCommand("pfctl -a sluice -F all", nil, nil)

	pfConf := writeTempPFConf(t, "# defaults\nanchor \"sluice\"\n")
	router := NewNetworkRouter(NetworkRouterConfig{
		Runner:     runner,
		AnchorName: "sluice",
		PFConfPath: pfConf,
	})

	err := mgr.TeardownNetworkRouting(context.Background(), router)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !runner.called("pfctl -a sluice -F all") {
		t.Error("expected pfctl flush call")
	}

	// Verify anchor reference was removed from pf.conf.
	data, _ := os.ReadFile(pfConf)
	if strings.Contains(string(data), `anchor "sluice"`) {
		t.Error("pf.conf should not contain anchor reference after teardown")
	}
}

func TestTartManagerTeardownNetworkRoutingError(t *testing.T) {
	mgr, runner := newTestTartManager(t)

	runner.onCommand("pfctl", nil, errors.New("permission denied"))

	router := NewNetworkRouter(NetworkRouterConfig{
		Runner:     runner,
		AnchorName: "sluice",
	})

	err := mgr.TeardownNetworkRouting(context.Background(), router)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "flush pf anchor") {
		t.Errorf("error should mention flush: %v", err)
	}
}

func TestTartCACertGuestPath(t *testing.T) {
	// TartCACertGuestPath should use /Volumes/ca/ (VirtioFS mount point)
	// not /certs/ (Apple Container path).
	if TartCACertGuestPath != "/Volumes/ca/sluice-ca.crt" {
		t.Errorf("TartCACertGuestPath = %q, want /Volumes/ca/sluice-ca.crt", TartCACertGuestPath)
	}
	// Must differ from Apple Container path.
	if TartCACertGuestPath == CACertGuestPath {
		t.Error("TartCACertGuestPath should differ from CACertGuestPath (Apple Container uses /certs/)")
	}
}

func TestTartCLIBin(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	cli, _ := NewTartCLIWithBin("tart", runner)
	if cli.Bin() != "tart" {
		t.Errorf("Bin() = %q, want tart", cli.Bin())
	}

	runner2 := newMockRunner()
	runner2.onCommand("/opt/homebrew/bin/tart --version", []byte("tart 2.15.0\n"), nil)
	cli2, _ := NewTartCLIWithBin("/opt/homebrew/bin/tart", runner2)
	if cli2.Bin() != "/opt/homebrew/bin/tart" {
		t.Errorf("Bin() = %q, want /opt/homebrew/bin/tart", cli2.Bin())
	}
}

func TestGatewayFromIP(t *testing.T) {
	tests := []struct {
		input string
		want  string
		err   bool
	}{
		{"192.168.64.5", "192.168.64.1", false},
		{"192.168.64.1", "192.168.64.1", false},
		{"10.0.0.42", "10.0.0.1", false},
		{"invalid", "", true},
		{"::1", "", true},
	}
	for _, tt := range tests {
		got, err := GatewayFromIP(tt.input)
		if (err != nil) != tt.err {
			t.Errorf("GatewayFromIP(%q) error = %v, wantErr %v", tt.input, err, tt.err)
			continue
		}
		if got != tt.want {
			t.Errorf("GatewayFromIP(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSetupNetworkRoutingDerivesGateway(t *testing.T) {
	mgr, runner := newTestTartManager(t)

	// Mock tart ip response.
	runner.onCommand("tart ip", []byte("192.168.64.5\n"), nil)
	// Mock ifconfig to detect TUN interface.
	runner.onCommand("ifconfig utun3", []byte("utun3: flags=...\n"), nil)
	// Mock pfctl calls.
	pfConf := writeTempPFConf(t, "# default pf rules\n")
	runner.onCommand("pfctl -f", nil, nil)
	runner.onCommand("pfctl -a sluice -f", nil, nil)
	runner.onCommand("pfctl -e", nil, nil)

	router := NewNetworkRouter(NetworkRouterConfig{
		Runner:     runner,
		AnchorName: "sluice",
		TUNIface:   "utun3",
		PFConfPath: pfConf,
	})

	// Pass empty tunGateway. Should derive 192.168.64.1 from VM IP 192.168.64.5.
	err := mgr.SetupNetworkRouting(context.Background(), router, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify pfctl was called to load anchor rules.
	if !runner.called("pfctl -a sluice -f") {
		t.Error("expected pfctl call to load anchor rules")
	}
}

func TestRestartWithEnvNonBlocking(t *testing.T) {
	mgr, runner := newTestTartManager(t)

	runner.onCommand("tart stop", nil, nil)
	runner.onCommand("tart run", nil, nil)

	// RestartWithEnv should return promptly (not block on tart run).
	err := mgr.RestartWithEnv(context.Background(), map[string]string{"K": "V"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify stop and run were both called.
	if !runner.called("tart stop openclaw") {
		t.Error("expected stop call")
	}
	if !runner.called("tart run") {
		t.Error("expected run call via startVM")
	}
}

func TestRestartWithEnvStartVMError(t *testing.T) {
	mgr, runner := newTestTartManager(t)

	runner.onCommand("tart stop", nil, nil)
	// Override startVM to return an error.
	mgr.startVM = func(_ TartRunConfig) (*exec.Cmd, error) {
		return nil, errors.New("failed to start VM process")
	}

	err := mgr.RestartWithEnv(context.Background(), map[string]string{"K": "V"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "restart VM") {
		t.Errorf("error should mention restart VM: %v", err)
	}
}
