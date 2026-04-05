package container

import (
	"context"
	"encoding/json"
	"errors"
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
