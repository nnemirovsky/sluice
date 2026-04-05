package container

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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

// Bin returns the configured path to the tart binary. This allows callers
// (such as setupMacOSVM) to use the correct binary path for exec.Command
// instead of hardcoding "tart".
func (c *TartCLI) Bin() string {
	return c.bin
}

// StartVM builds a `tart run` exec.Cmd and starts it in the background via
// cmd.Start(). This is the correct way to launch a tart VM because `tart run`
// blocks until the VM shuts down. Returns the started Cmd so the caller can
// monitor it via cmd.Wait() in a goroutine. The caller is responsible for
// calling cmd.Wait() to avoid zombie processes.
func (c *TartCLI) StartVM(cfg TartRunConfig) (*exec.Cmd, error) {
	args := c.RunArgs(cfg)
	cmd := exec.Command(c.bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start tart VM %q: %w", cfg.Name, err)
	}
	return cmd, nil
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

// TartCACertGuestPath is the path where the CA cert appears inside a tart
// macOS VM when mounted via VirtioFS with --dir=ca:<hostpath>. VirtioFS mounts
// in tart VMs appear at /Volumes/<name>/, unlike Apple Container which uses
// /certs/ as the shared volume path.
const TartCACertGuestPath = "/Volumes/ca/sluice-ca.crt"

// TartManager implements ContainerManager for macOS VMs managed by tart.
// It uses TartCLI for VM lifecycle and credential injection via VirtioFS
// shared volumes and tart exec.
type TartManager struct {
	cli    *TartCLI
	vmName string
	// runCfg holds the TartRunConfig used to (re)start the VM. This is needed
	// because tart has no inspect command. The caller sets it at creation time
	// so RestartWithEnv can re-run the VM with the same mounts.
	runCfg TartRunConfig
	// startVM launches the VM in the background. Defaults to cli.StartVM.
	// Replaceable in tests to avoid spawning real processes.
	startVM func(TartRunConfig) (*exec.Cmd, error)
}

// TartManagerConfig holds configuration for creating a TartManager.
type TartManagerConfig struct {
	CLI    *TartCLI
	VMName string
	// RunConfig is the full TartRunConfig used to start the VM. TartManager
	// stores this so it can re-run the VM on restart since tart does not have
	// an inspect command to recover the original run parameters.
	RunConfig TartRunConfig
}

// NewTartManager creates a new TartManager from the given config.
// Panics if cfg.CLI is nil because all manager operations depend on it.
func NewTartManager(cfg TartManagerConfig) *TartManager {
	if cfg.CLI == nil {
		panic("container: NewTartManager requires non-nil CLI")
	}
	m := &TartManager{
		cli:    cfg.CLI,
		vmName: cfg.VMName,
		runCfg: cfg.RunConfig,
	}
	m.startVM = cfg.CLI.StartVM
	return m
}

// ReloadSecrets writes phantom token files to the VirtioFS shared directory
// and signals the macOS VM to reload them via tart exec. Falls back to
// RestartWithEnv if the exec command fails.
func (m *TartManager) ReloadSecrets(ctx context.Context, phantomDir string, phantomEnv map[string]string) error {
	if err := WritePhantomFiles(phantomDir, phantomEnv); err != nil {
		return err
	}

	_, err := m.cli.Exec(ctx, m.vmName, []string{"openclaw", "secrets", "reload"})
	if err != nil {
		return m.RestartWithEnv(ctx, phantomEnv)
	}
	return nil
}

// RestartWithEnv stops the VM and re-runs it in the background. Unlike Apple
// Container, tart VMs persist state across stop/run cycles so we do NOT
// delete+clone (which takes minutes for macOS images). Environment variables
// are not directly supported by tart run, so this method stops and restarts
// the VM to pick up changes from the shared VirtioFS volume. The VM process
// runs in a background goroutine because `tart run` is a blocking command.
//
// Known limitation: pf routing rules are not re-applied after restart. The VM
// may receive a different IP address, making existing rules stale. During the
// restart window, network traffic from the VM could bypass sluice. This is
// acceptable because RestartWithEnv is only called as a fallback when the
// preferred hot-reload via exec fails, and credential rotation (the trigger
// for restart) is infrequent.
func (m *TartManager) RestartWithEnv(ctx context.Context, _ map[string]string) error {
	if err := m.cli.Stop(ctx, m.vmName); err != nil {
		return fmt.Errorf("stop VM: %w", err)
	}

	// Re-run with the same config in the background. tart VMs persist disk
	// state across stop/run. startVM uses cmd.Start() so this returns
	// immediately. Monitor the background process for unexpected exits.
	cmd, err := m.startVM(m.runCfg)
	if err != nil {
		return fmt.Errorf("restart VM: %w", err)
	}
	go func() {
		if waitErr := cmd.Wait(); waitErr != nil {
			log.Printf("WARNING: macOS VM %q exited after restart: %v", m.vmName, waitErr)
		}
	}()
	return nil
}

// InjectMCPConfig writes an mcp-servers.json file to the VirtioFS shared
// volume and signals the macOS VM to reload MCP configuration via tart exec.
func (m *TartManager) InjectMCPConfig(phantomDir, sluiceURL string) error {
	if err := WriteMCPConfig(phantomDir, sluiceURL); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, execErr := m.cli.Exec(ctx, m.vmName, []string{"openclaw", "mcp", "reload"}); execErr != nil {
		path := filepath.Join(phantomDir, "mcp-servers.json")
		log.Printf("MCP config written to %s but exec reload failed: %v", path, execErr)
	}
	return nil
}

// Status returns VM health information by running tart list and checking the
// VM state. tart does not have an inspect command, so we use list output.
func (m *TartManager) Status(ctx context.Context) (ContainerStatus, error) {
	entries, err := m.cli.List(ctx)
	if err != nil {
		return ContainerStatus{}, err
	}

	for _, e := range entries {
		if e.Name == m.vmName {
			return ContainerStatus{
				ID:      e.Name,
				Running: strings.EqualFold(e.State, "running"),
				Image:   e.Source,
			}, nil
		}
	}

	return ContainerStatus{}, fmt.Errorf("VM %q not found", m.vmName)
}

// Stop stops the macOS VM via tart stop.
func (m *TartManager) Stop(ctx context.Context) error {
	return m.cli.Stop(ctx, m.vmName)
}

// InjectCACert copies the CA certificate from hostCertPath into the shared
// VirtioFS volume at certDir, then runs security add-trusted-cert inside the
// macOS VM to add the cert to the System Keychain. This allows macOS-native
// tools (e.g. URLSession, curl) to trust sluice's MITM CA. If the security
// command fails, the cert is still available via env vars (SSL_CERT_FILE,
// REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS) set at VM startup.
func (m *TartManager) InjectCACert(ctx context.Context, hostCertPath, certDir string) error {
	// Read the CA cert from the host.
	certData, err := os.ReadFile(hostCertPath)
	if err != nil {
		return fmt.Errorf("read CA cert %q: %w", hostCertPath, err)
	}

	// Write the cert to the shared volume so the guest can access it via VirtioFS.
	destPath := filepath.Join(certDir, "sluice-ca.crt")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("create cert dir %q: %w", certDir, err)
	}
	if err := os.WriteFile(destPath, certData, 0644); err != nil {
		return fmt.Errorf("write CA cert to shared volume: %w", err)
	}

	// macOS guest: add cert to System Keychain via security add-trusted-cert.
	// Use TartCACertGuestPath (/Volumes/ca/sluice-ca.crt) because tart
	// VirtioFS mounts appear at /Volumes/<name>/, not at the Apple Container
	// path (/certs/).
	_, macErr := m.cli.Exec(ctx, m.vmName, []string{
		"security", "add-trusted-cert", "-d", "-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain",
		TartCACertGuestPath,
	})
	if macErr != nil {
		// Best-effort. The cert is still usable via env vars set below.
		log.Printf("security add-trusted-cert failed in macOS VM %q (will set env vars as fallback): %v", m.vmName, macErr)
	}

	// Write a launchd environment plist so SSL_CERT_FILE, REQUESTS_CA_BUNDLE,
	// and NODE_EXTRA_CA_CERTS are set for all GUI and agent processes. This
	// covers tools that do not use the macOS Keychain for TLS trust (e.g.
	// Python requests, Node.js, OpenSSL-based tools).
	envVars := CACertEnvVars(TartCACertGuestPath)
	for k, v := range envVars {
		_, _ = m.cli.Exec(ctx, m.vmName, []string{
			"launchctl", "setenv", k, v,
		})
	}

	return nil
}

// Runtime returns RuntimeMacOS.
func (m *TartManager) Runtime() Runtime {
	return RuntimeMacOS
}

// VMIP returns the IP address of the managed VM via `tart ip`. This method
// can be used as the IP getter function for DefaultBridgeInterface.
func (m *TartManager) VMIP(ctx context.Context) (string, error) {
	return m.cli.IP(ctx, m.vmName)
}

// SetupNetworkRouting gets the VM's IP address and sets up pf rules to route
// VM traffic through tun2proxy to sluice's SOCKS5 proxy. The router and
// tunGateway are provided by the caller (typically the main startup code).
// When tunGateway is empty, it is derived from the VM's IP (e.g., .1 in the
// same /24 subnet). Logs a warning if tun2proxy does not appear to be running.
func (m *TartManager) SetupNetworkRouting(ctx context.Context, router *NetworkRouter, tunGateway string) error {
	// Check if tun2proxy is running by looking for the TUN interface.
	if !IsTUN2ProxyRunning(ctx, m.cli.runner, router.tunIface) {
		log.Printf("WARNING: TUN interface %q not found. tun2proxy may not be running. "+
			"Network routing will be configured but traffic will not flow until tun2proxy starts. "+
			"Run: sudo tun2proxy --proxy socks5://127.0.0.1:1080 --tun %s", router.tunIface, router.tunIface)
	}

	getIP := func() (string, error) {
		return m.VMIP(ctx)
	}

	bridgeIface, vmIP, err := DefaultBridgeInterface(getIP)
	if err != nil {
		return fmt.Errorf("detect bridge interface: %w", err)
	}

	// When no explicit gateway is provided, derive it from the VM IP.
	// Convention: the host-side gateway is .1 in the /24 subnet.
	if tunGateway == "" {
		gw, gwErr := GatewayFromIP(vmIP)
		if gwErr != nil {
			return fmt.Errorf("derive gateway from VM IP %q: %w", vmIP, gwErr)
		}
		tunGateway = gw
	}

	return router.SetupNetworkRouting(ctx, vmIP, bridgeIface, tunGateway)
}

// TeardownNetworkRouting removes the pf anchor rules set up by
// SetupNetworkRouting. Should be called on shutdown.
func (m *TartManager) TeardownNetworkRouting(ctx context.Context, router *NetworkRouter) error {
	return router.TeardownNetworkRouting(ctx)
}
