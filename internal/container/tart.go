package container

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// TartCLI wraps the macOS `tart` CLI for managing macOS VMs via the
// Virtualization.framework. It provides low-level operations that TartManager
// wires into the ContainerManager interface.
type TartCLI struct {
	bin    string // path to tart binary
	runner CommandRunner
}

// NewTartCLI creates a new TartCLI using the default "tart" binary name.
// Returns an error if the tart binary is not found in PATH.
func NewTartCLI(runner CommandRunner) (*TartCLI, error) {
	return NewTartCLIWithBin("tart", runner)
}

// NewTartCLIWithBin creates a new TartCLI using the specified binary path.
// Returns an error if the binary does not exist.
func NewTartCLIWithBin(bin string, runner CommandRunner) (*TartCLI, error) {
	if runner == nil {
		runner = ExecRunner{}
	}

	// Verify the binary exists by running --version.
	_, err := runner.Run(context.Background(), bin, "--version")
	if err != nil {
		return nil, fmt.Errorf("tart binary %q not found or not working: %w", bin, err)
	}

	return &TartCLI{bin: bin, runner: runner}, nil
}

// Clone creates a VM from an OCI image. This can take minutes for macOS images.
func (c *TartCLI) Clone(ctx context.Context, image, name string) error {
	_, err := c.runner.Run(ctx, c.bin, "clone", image, name)
	return err
}

// TartRunConfig holds parameters for starting a tart VM.
type TartRunConfig struct {
	Name       string
	DirMounts  []TartDirMount // VirtioFS directory shares via --dir
	NoGraphics bool           // headless mode
}

// TartDirMount describes a VirtioFS directory share from host to guest.
type TartDirMount struct {
	Name     string // mount name (used as /Volumes/<name> in guest)
	HostPath string // absolute path on host
	ReadOnly bool
}

// RunArgs builds the argument list for `tart run` without executing it.
// This is useful for testing the argument construction.
func (c *TartCLI) RunArgs(cfg TartRunConfig) []string {
	args := []string{"run", cfg.Name}
	for _, dm := range cfg.DirMounts {
		dirArg := dm.Name + ":" + dm.HostPath
		if dm.ReadOnly {
			dirArg += ":ro"
		}
		args = append(args, "--dir="+dirArg)
	}
	if cfg.NoGraphics {
		args = append(args, "--no-graphics")
	}
	return args
}

// Run starts a tart VM. IMPORTANT: `tart run` is a BLOCKING command that
// runs until the VM shuts down. The caller must use RunArgs and launch
// the process in a background goroutine via cmd.Start(). This method is
// provided for simple/test cases where blocking is acceptable.
func (c *TartCLI) Run(ctx context.Context, cfg TartRunConfig) error {
	args := c.RunArgs(cfg)
	_, err := c.runner.Run(ctx, c.bin, args...)
	return err
}

// Exec runs a command inside a running VM. Requires the tart helper agent
// to be running inside the guest image.
func (c *TartCLI) Exec(ctx context.Context, name string, cmd []string) ([]byte, error) {
	args := []string{"exec", name, "--"}
	args = append(args, cmd...)
	return c.runner.Run(ctx, c.bin, args...)
}

// Stop stops a running VM.
func (c *TartCLI) Stop(ctx context.Context, name string) error {
	_, err := c.runner.Run(ctx, c.bin, "stop", name)
	return err
}

// Delete removes a VM.
func (c *TartCLI) Delete(ctx context.Context, name string) error {
	_, err := c.runner.Run(ctx, c.bin, "delete", name)
	return err
}

// TartVMEntry holds a single entry from `tart list --format json` output.
type TartVMEntry struct {
	Name   string `json:"Name"`
	Source string `json:"Source"`
	Disk   int64  `json:"Disk"`
	Size   int64  `json:"Size"`
	State  string `json:"State"`
	OS     string `json:"OS"`
}

// List returns all VMs visible to `tart list`.
func (c *TartCLI) List(ctx context.Context) ([]TartVMEntry, error) {
	out, err := c.runner.Run(ctx, c.bin, "list", "--format", "json")
	if err != nil {
		return nil, err
	}

	if len(bytes.TrimSpace(out)) == 0 {
		return nil, nil
	}

	var entries []TartVMEntry
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil, fmt.Errorf("parse list output: %w", err)
	}
	return entries, nil
}

// IP returns the IP address of a running VM.
func (c *TartCLI) IP(ctx context.Context, name string) (string, error) {
	out, err := c.runner.Run(ctx, c.bin, "ip", name)
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(out))
	if ip == "" {
		return "", fmt.Errorf("tart ip returned empty result for VM %q", name)
	}
	return ip, nil
}

// VMExists checks whether a VM with the given name exists by scanning the
// list output. Returns true if found regardless of running state.
func (c *TartCLI) VMExists(ctx context.Context, name string) (bool, error) {
	entries, err := c.List(ctx)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.Name == name {
			return true, nil
		}
	}
	return false, nil
}

// VMState returns the state string for a named VM from the list output.
// Returns empty string if the VM is not found.
func (c *TartCLI) VMState(ctx context.Context, name string) (string, error) {
	entries, err := c.List(ctx)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.Name == name {
			return e.State, nil
		}
	}
	return "", nil
}
