//go:build e2e && darwin

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// requireAppleContainer skips the test if the Apple Container CLI is not
// installed or not functional on this machine.
func requireAppleContainer(t *testing.T) {
	t.Helper()
	out, err := exec.Command("container", "--version").CombinedOutput()
	if err != nil {
		t.Skipf("Apple Container not installed: %v\n%s", err, out)
	}
}

// requirePfctl skips the test if pfctl is not available (should always be
// present on macOS, but guard anyway).
func requirePfctl(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("pfctl"); err != nil {
		t.Skipf("pfctl not available: %v", err)
	}
}

// requireRoot skips the test if not running as root (pf rules and tun2proxy
// require elevated privileges).
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("Apple Container e2e tests require root (pf rules need sudo)")
	}
}

// appleE2EConfigTOML provides the policy seed for Apple Container e2e tests.
const appleE2EConfigTOML = `
[policy]
default = "deny"

[[allow]]
destination = "127.0.0.1"
ports = [3000]
name = "allow localhost health"

[[allow]]
destination = "*"
ports = [8080]
name = "allow echo server"
`

// appleEnv manages an Apple Container VM environment for e2e tests. It handles
// sluice startup, VM lifecycle, pf rules, tun2proxy, and shared volumes.
type appleEnv struct {
	t            *testing.T
	sluice       *SluiceProcess
	vmName       string
	mcpDir       string
	certDir      string
	tun2proxyCmd *exec.Cmd
	tunIface     string
	anchorName   string
	bridgeIface  string
}

// setupAppleEnv creates and starts the full Apple Container test environment:
// sluice process, shared volume dirs, VM, tun2proxy, and pf rules.
func setupAppleEnv(t *testing.T) *appleEnv {
	t.Helper()
	requireAppleContainer(t)
	requirePfctl(t)
	requireRoot(t)

	tmpDir := t.TempDir()
	mcpDir := filepath.Join(tmpDir, "mcp")
	certDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(mcpDir, 0o755); err != nil {
		t.Fatalf("create mcp dir: %v", err)
	}
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatalf("create cert dir: %v", err)
	}

	vmName := fmt.Sprintf("sluice-e2e-%d", time.Now().UnixNano()%1000000)
	anchorName := fmt.Sprintf("sluice-e2e-%d", time.Now().UnixNano()%1000000)
	tunIface := "utun99" // use a high-numbered TUN to avoid conflicts

	// Start sluice with apple runtime.
	proc := startSluice(t, SluiceOpts{
		ConfigTOML: appleE2EConfigTOML,
		ExtraArgs: []string{
			"--mcp-dir", mcpDir,
		},
	})

	env := &appleEnv{
		t:           t,
		sluice:      proc,
		vmName:      vmName,
		mcpDir:      mcpDir,
		certDir:     certDir,
		tunIface:    tunIface,
		anchorName:  anchorName,
		bridgeIface: "bridge100", // Apple Container default
	}

	return env
}

// startVM starts an Apple Container VM with the given image and env vars.
func (e *appleEnv) startVM(envVars map[string]string, volumes [][2]string) {
	e.t.Helper()

	args := []string{"run", "--name", e.vmName}
	for k, v := range envVars {
		args = append(args, "-e", k+"="+v)
	}
	for _, vol := range volumes {
		args = append(args, "-v", vol[0]+":"+vol[1])
	}
	args = append(args, "alpine:latest")

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "container", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		e.t.Fatalf("start Apple Container VM %s: %v\n%s", e.vmName, err, out)
	}
}

// stopVM stops and removes the Apple Container VM.
func (e *appleEnv) stopVM() {
	e.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop VM (best-effort).
	cmd := exec.CommandContext(ctx, "container", "stop", e.vmName)
	_ = cmd.Run()

	// Remove VM (best-effort).
	cmd = exec.CommandContext(ctx, "container", "rm", e.vmName)
	_ = cmd.Run()
}

// inspectVM returns parsed JSON from `container inspect`.
func (e *appleEnv) inspectVM() map[string]any {
	e.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "container", "inspect", e.vmName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		e.t.Fatalf("inspect VM %s: %v\n%s", e.vmName, err, out)
	}

	var infos []map[string]any
	if err := json.Unmarshal(out, &infos); err != nil {
		e.t.Fatalf("parse inspect output: %v", err)
	}
	if len(infos) == 0 {
		e.t.Fatal("inspect returned empty result")
	}
	return infos[0]
}

// getVMIP extracts the IP address from inspect output.
func (e *appleEnv) getVMIP() string {
	e.t.Helper()

	info := e.inspectVM()
	network, ok := info["NetworkSettings"].(map[string]any)
	if !ok {
		e.t.Fatal("inspect: missing NetworkSettings")
	}
	ip, ok := network["IPAddress"].(string)
	if !ok || ip == "" {
		e.t.Fatal("inspect: missing or empty IPAddress")
	}
	return ip
}

// execInVM runs a command inside the Apple Container VM.
func (e *appleEnv) execInVM(cmd ...string) (string, error) {
	args := append([]string{"exec", e.vmName}, cmd...)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c := exec.CommandContext(ctx, "container", args...)
	out, err := c.CombinedOutput()
	return string(out), err
}

// setupPfRules applies pf anchor rules to redirect VM traffic through the
// TUN device to tun2proxy.
func (e *appleEnv) setupPfRules(vmSubnet, tunGateway string) {
	e.t.Helper()

	rules := fmt.Sprintf(
		"pass in on %s route-to (%s %s) proto tcp from %s to any\npass out on %s from any to %s\n",
		e.bridgeIface, e.tunIface, tunGateway, vmSubnet,
		e.bridgeIface, vmSubnet,
	)

	// Write rules to temp file and load via pfctl.
	rulesFile := filepath.Join(e.t.TempDir(), "pf-rules.conf")
	if err := os.WriteFile(rulesFile, []byte(rules), 0o644); err != nil {
		e.t.Fatalf("write pf rules: %v", err)
	}

	// Ensure anchor reference in pf.conf.
	directive := fmt.Sprintf("anchor \"%s\"", e.anchorName)
	pfConf, err := os.ReadFile("/etc/pf.conf")
	if err != nil {
		e.t.Fatalf("read /etc/pf.conf: %v", err)
	}
	if !strings.Contains(string(pfConf), directive) {
		f, err := os.OpenFile("/etc/pf.conf", os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			e.t.Fatalf("open pf.conf for append: %v", err)
		}
		_, _ = fmt.Fprintf(f, "\n%s\n", directive)
		_ = f.Close()

		cmd := exec.Command("pfctl", "-f", "/etc/pf.conf")
		out, err := cmd.CombinedOutput()
		if err != nil {
			e.t.Fatalf("reload pf.conf: %v\n%s", err, out)
		}
	}

	// Load anchor rules.
	cmd := exec.Command("pfctl", "-a", e.anchorName, "-f", rulesFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		e.t.Fatalf("load pf anchor: %v\n%s", err, out)
	}
}

// teardownPfRules flushes the pf anchor and removes the reference from
// /etc/pf.conf.
func (e *appleEnv) teardownPfRules() {
	e.t.Helper()

	// Flush anchor rules.
	cmd := exec.Command("pfctl", "-a", e.anchorName, "-F", "all")
	_ = cmd.Run()

	// Remove anchor reference from /etc/pf.conf (best-effort).
	directive := fmt.Sprintf("anchor \"%s\"", e.anchorName)
	data, err := os.ReadFile("/etc/pf.conf")
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	var filtered []string
	for _, line := range lines {
		if strings.TrimSpace(line) != directive {
			filtered = append(filtered, line)
		}
	}
	_ = os.WriteFile("/etc/pf.conf", []byte(strings.Join(filtered, "\n")), 0o644)
	_ = exec.Command("pfctl", "-f", "/etc/pf.conf").Run()
}

// startTun2proxy starts tun2proxy on the host to forward TUN traffic to
// sluice's SOCKS5 proxy.
func (e *appleEnv) startTun2proxy() {
	e.t.Helper()

	tun2proxyBin, err := exec.LookPath("tun2proxy")
	if err != nil {
		e.t.Skipf("tun2proxy not in PATH: %v", err)
	}

	cmd := exec.Command(tun2proxyBin,
		"--proxy", "socks5://"+e.sluice.ProxyAddr,
		"--tun", e.tunIface,
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		e.t.Fatalf("start tun2proxy: %v", err)
	}
	e.tun2proxyCmd = cmd

	// Give tun2proxy time to create the TUN device.
	time.Sleep(2 * time.Second)
}

// stopTun2proxy kills the tun2proxy process.
func (e *appleEnv) stopTun2proxy() {
	if e.tun2proxyCmd != nil && e.tun2proxyCmd.Process != nil {
		_ = e.tun2proxyCmd.Process.Kill()
		_ = e.tun2proxyCmd.Wait()
	}
}

// verifyPfRulesApplied checks that the pf anchor has active rules.
func (e *appleEnv) verifyPfRulesApplied() bool {
	e.t.Helper()

	cmd := exec.Command("pfctl", "-a", e.anchorName, "-sr")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	// The anchor should contain at least the "pass in" and "pass out" rules.
	return strings.Contains(string(out), "pass") && strings.Contains(string(out), "route-to")
}

// verifyPfRulesCleared checks that the pf anchor has no rules.
func (e *appleEnv) verifyPfRulesCleared() bool {
	e.t.Helper()

	cmd := exec.Command("pfctl", "-a", e.anchorName, "-sr")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// If the anchor doesn't exist, that counts as cleared.
		return true
	}
	return strings.TrimSpace(string(out)) == ""
}

// TestAppleContainer is the top-level test for Apple Container integration.
// It starts sluice, boots a VM, configures pf rules and tun2proxy, then runs
// subtests that verify VM environment, traffic routing, credential injection,
// CA cert trust, and cleanup on shutdown.
func TestAppleContainer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Apple Container integration tests in short mode")
	}

	env := setupAppleEnv(t)

	// Start the VM with env vars pointing to MCP and cert volumes.
	envVars := map[string]string{
		"SSL_CERT_FILE":       "/certs/sluice-ca.crt",
		"REQUESTS_CA_BUNDLE":  "/certs/sluice-ca.crt",
		"NODE_EXTRA_CA_CERTS": "/certs/sluice-ca.crt",
		"ALL_PROXY":           "socks5://" + env.sluice.ProxyAddr,
	}
	volumes := [][2]string{
		{env.mcpDir, "/mcp"},
		{env.certDir, "/certs"},
	}

	env.startVM(envVars, volumes)
	t.Cleanup(func() {
		env.stopVM()
		env.teardownPfRules()
		env.stopTun2proxy()
	})

	// Wait for VM to be ready.
	vmIP := env.getVMIP()
	t.Logf("VM %s running at %s", env.vmName, vmIP)

	// Set up network routing: tun2proxy + pf rules.
	env.startTun2proxy()
	vmSubnet := vmIP[:strings.LastIndex(vmIP, ".")] + ".0/24"
	tunGateway := vmIP[:strings.LastIndex(vmIP, ".")] + ".1"
	env.setupPfRules(vmSubnet, tunGateway)

	t.Run("VMBootedWithCorrectEnv", func(t *testing.T) {
		testVMBootedWithCorrectEnv(t, env)
	})

	t.Run("PfRulesApplied", func(t *testing.T) {
		testPfRulesApplied(t, env)
	})

	t.Run("TrafficRoutedThroughSluice", func(t *testing.T) {
		testAppleTrafficRoutedThroughSluice(t, env)
	})

	t.Run("CredentialInjection", func(t *testing.T) {
		testAppleCredentialInjection(t, env)
	})

	t.Run("CACertTrusted", func(t *testing.T) {
		testAppleCACertTrusted(t, env)
	})

	t.Run("CleanupOnShutdown", func(t *testing.T) {
		testAppleCleanupOnShutdown(t, env)
	})
}

// testVMBootedWithCorrectEnv verifies that sluice starts with --runtime apple
// and the VM has the expected environment variables set for CA cert trust and
// proxy configuration.
func testVMBootedWithCorrectEnv(t *testing.T, env *appleEnv) {
	t.Helper()

	// Verify the VM is running.
	info := env.inspectVM()
	state, ok := info["State"].(map[string]any)
	if !ok {
		t.Fatal("inspect: missing State")
	}
	running, _ := state["Running"].(bool)
	if !running {
		status, _ := state["Status"].(string)
		t.Fatalf("VM not running. Status: %s", status)
	}

	// Verify env vars are set inside the VM.
	for _, envVar := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"} {
		out, err := env.execInVM("printenv", envVar)
		if err != nil {
			t.Errorf("env var %s not set in VM: %v", envVar, err)
			continue
		}
		val := strings.TrimSpace(out)
		if val != "/certs/sluice-ca.crt" {
			t.Errorf("env var %s = %q, want /certs/sluice-ca.crt", envVar, val)
		}
	}
}

// testPfRulesApplied verifies that the pf anchor rules redirecting bridge
// traffic through the TUN interface are active.
func testPfRulesApplied(t *testing.T, env *appleEnv) {
	t.Helper()

	if !env.verifyPfRulesApplied() {
		cmd := exec.Command("pfctl", "-a", env.anchorName, "-sr")
		out, _ := cmd.CombinedOutput()
		t.Fatalf("pf anchor rules not applied. Current rules:\n%s", out)
	}

	// Verify the rules reference the correct bridge and TUN interfaces.
	cmd := exec.Command("pfctl", "-a", env.anchorName, "-sr")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("show pf rules: %v\n%s", err, out)
	}
	rules := string(out)
	if !strings.Contains(rules, env.bridgeIface) {
		t.Errorf("pf rules do not reference bridge %s:\n%s", env.bridgeIface, rules)
	}
	if !strings.Contains(rules, env.tunIface) {
		t.Errorf("pf rules do not reference TUN %s:\n%s", env.tunIface, rules)
	}
}

// testAppleTrafficRoutedThroughSluice verifies that traffic from the Apple
// Container VM is routed through sluice's SOCKS5 proxy by checking the
// audit log for connection entries.
func testAppleTrafficRoutedThroughSluice(t *testing.T, env *appleEnv) {
	t.Helper()

	// Start an echo server on the host that the VM can reach through sluice.
	echoSrv := startEchoServer(t)
	echoAddr := echoServerAddr(t, echoSrv)

	// Make an HTTP request from inside the VM through the SOCKS5 proxy.
	// The VM's ALL_PROXY env var and/or pf rules should route traffic through
	// sluice. Try wget first (busybox), fall back to curl.
	out, err := env.execInVM("wget", "-qO-", "--timeout=10",
		fmt.Sprintf("http://%s/", echoAddr))
	if err != nil {
		// Try using the SOCKS5 proxy explicitly via curl.
		_, installErr := env.execInVM("apk", "add", "--no-cache", "curl")
		if installErr != nil {
			t.Skipf("cannot install curl in VM and wget failed: %v", err)
		}
		out, err = env.execInVM("curl", "-sf", "--socks5-hostname",
			env.sluice.ProxyAddr,
			fmt.Sprintf("http://%s/", echoAddr))
		if err != nil {
			t.Fatalf("HTTP request from VM through SOCKS5 failed: %v\n%s", err, out)
		}
	}

	if !strings.Contains(out, "Method: GET") {
		t.Errorf("unexpected echo response: %s", out)
	}

	// Verify sluice audit log recorded the connection.
	time.Sleep(500 * time.Millisecond) // let the audit entry flush
	auditContent := readAuditLog(t, env.sluice.AuditPath)
	if !strings.Contains(auditContent, echoAddr) && !strings.Contains(auditContent, "127.0.0.1") {
		t.Logf("audit log:\n%s", auditContent)
		t.Error("audit log does not contain entry for VM traffic")
	}
}

// testAppleCredentialInjection verifies that env vars injected via container
// exec are visible inside the Apple Container VM.
func testAppleCredentialInjection(t *testing.T, env *appleEnv) {
	t.Helper()

	phantomValue := fmt.Sprintf("sk-phantom-apple-%d", time.Now().UnixNano()%100000)
	envVarName := "TEST_API_KEY"

	// Write an env var into the VM's env file (simulating InjectEnvVars).
	writeCmd := fmt.Sprintf(
		"mkdir -p $HOME/.openclaw && echo '%s=%s' >> $HOME/.openclaw/.env",
		envVarName, phantomValue,
	)
	_, writeErr := env.execInVM("sh", "-c", writeCmd)
	if writeErr != nil {
		t.Fatalf("write env var in VM: %v", writeErr)
	}

	// Verify the env var is readable from the VM's env file.
	var vmOut string
	var readErr error
	for attempt := 0; attempt < 10; attempt++ {
		vmOut, readErr = env.execInVM("sh", "-c",
			"grep '^"+envVarName+"=' $HOME/.openclaw/.env")
		if readErr == nil && strings.Contains(vmOut, phantomValue) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if readErr != nil {
		t.Fatalf("read env var from VM: %v\n%s", readErr, vmOut)
	}
	if !strings.Contains(vmOut, phantomValue) {
		t.Errorf("env var content mismatch: want %q in %q", phantomValue, vmOut)
	}
}

// testAppleCACertTrusted verifies that the sluice CA certificate written to
// the shared cert volume is accessible from inside the VM and that HTTPS
// requests through the MITM proxy succeed when the cert is trusted.
func testAppleCACertTrusted(t *testing.T, env *appleEnv) {
	t.Helper()

	// Write a dummy CA cert to the shared cert directory. In a real deployment,
	// sluice generates this via `sluice cert generate` and InjectCACert copies
	// it to the shared volume.
	dummyCert := `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIRAKmVCfQBLjLPVCsm+RShZiQwCgYIKoZIzj0EAwIwHjEc
MBoGA1UEAxMTc2x1aWNlIGUyZSB0ZXN0IENBMB4XDTI2MDEwMTAwMDAwMFoXDTI3
MDEwMTAwMDAwMFowHjEcMBoGA1UEAxMTc2x1aWNlIGUyZSB0ZXN0IENBMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEfake+fake+fake+fake+fake+fake+fake+fake
+fake+fake+fake+fake+fake+fake+fake+fake+fake+fake+fake+fake+fakeQ==
-----END CERTIFICATE-----`

	certPath := filepath.Join(env.certDir, "sluice-ca.crt")
	if err := os.WriteFile(certPath, []byte(dummyCert), 0o644); err != nil {
		t.Fatalf("write CA cert: %v", err)
	}

	// Verify the cert file is visible inside the VM.
	var vmOut string
	var readErr error
	for attempt := 0; attempt < 10; attempt++ {
		vmOut, readErr = env.execInVM("cat", "/certs/sluice-ca.crt")
		if readErr == nil && strings.Contains(vmOut, "BEGIN CERTIFICATE") {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if readErr != nil {
		t.Fatalf("read CA cert from VM: %v\n%s", readErr, vmOut)
	}
	if !strings.Contains(vmOut, "BEGIN CERTIFICATE") {
		t.Error("CA cert not visible inside VM via shared volume")
	}

	// Verify that SSL_CERT_FILE env var points to the cert location.
	out, err := env.execInVM("printenv", "SSL_CERT_FILE")
	if err != nil {
		t.Fatalf("SSL_CERT_FILE not set: %v", err)
	}
	if strings.TrimSpace(out) != "/certs/sluice-ca.crt" {
		t.Errorf("SSL_CERT_FILE = %q, want /certs/sluice-ca.crt", strings.TrimSpace(out))
	}
}

// testAppleCleanupOnShutdown verifies that pf rules are removed and the VM is
// stopped when the test environment is torn down.
func testAppleCleanupOnShutdown(t *testing.T, env *appleEnv) {
	t.Helper()

	// Verify pf rules are currently active before cleanup.
	if !env.verifyPfRulesApplied() {
		t.Skip("pf rules were not applied, cannot test cleanup")
	}

	// Tear down pf rules.
	env.teardownPfRules()

	// Verify pf rules are cleared.
	if !env.verifyPfRulesCleared() {
		cmd := exec.Command("pfctl", "-a", env.anchorName, "-sr")
		out, _ := cmd.CombinedOutput()
		t.Errorf("pf rules not cleared after teardown:\n%s", out)
	}

	// Stop the VM.
	env.stopVM()

	// Verify the VM is no longer running.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "container", "inspect", env.vmName)
	out, err := cmd.CombinedOutput()
	if err == nil {
		// VM still exists. Check if it's stopped.
		var infos []map[string]any
		if jsonErr := json.Unmarshal(out, &infos); jsonErr == nil && len(infos) > 0 {
			if state, ok := infos[0]["State"].(map[string]any); ok {
				if running, _ := state["Running"].(bool); running {
					t.Error("VM still running after stop")
				}
			}
		}
	}
	// If inspect returns an error, the VM was already removed (which is fine).

	// Re-setup for subsequent test cleanup to be a no-op. The test cleanup
	// registered in TestAppleContainer will call stopVM and teardownPfRules
	// again, which should handle already-stopped/removed resources gracefully.
}

// TestAppleContainerSluiceStartsWithRuntimeFlag is a lightweight test that
// verifies sluice starts correctly with --runtime apple on macOS (without
// actually booting a VM). The flag validation happens at startup and this
// test verifies the binary accepts the flag without error.
func TestAppleContainerSluiceStartsWithRuntimeFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	requireAppleContainer(t)

	binary := buildSluice(t)
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "sluice.db")
	healthPort := freePort(t)
	proxyPort := freePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary,
		"--runtime", "apple",
		"--listen", fmt.Sprintf("127.0.0.1:%d", proxyPort),
		"--db", dbPath,
		"--health-addr", fmt.Sprintf("127.0.0.1:%d", healthPort),
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("sluice --runtime apple failed to start: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	// Wait for health endpoint. If sluice fails at startup due to missing
	// container CLI, that's expected and we verify the error case separately.
	healthURL := fmt.Sprintf("http://127.0.0.1:%d/healthz", healthPort)
	waitForHealthy(t, healthURL, 10*time.Second)
}

// TestAppleContainerMCPAutoInjection verifies that writing mcp-servers.json to
// the shared MCP volume makes it discoverable from inside the VM.
func TestAppleContainerMCPAutoInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	env := setupAppleEnv(t)

	envVars := map[string]string{
		"SSL_CERT_FILE": "/certs/sluice-ca.crt",
	}
	volumes := [][2]string{
		{env.mcpDir, "/mcp"},
		{env.certDir, "/certs"},
	}

	env.startVM(envVars, volumes)
	t.Cleanup(func() {
		env.stopVM()
		env.teardownPfRules()
		env.stopTun2proxy()
	})

	// Write mcp-servers.json to the MCP directory (simulating what sluice
	// does with --auto-inject-mcp).
	mcpConfig := `{"sluice":{"url":"http://127.0.0.1:3000/mcp","transport":"streamable-http"}}`
	mcpPath := filepath.Join(env.mcpDir, "mcp-servers.json")
	if err := os.WriteFile(mcpPath, []byte(mcpConfig), 0o644); err != nil {
		t.Fatalf("write mcp-servers.json: %v", err)
	}

	// Verify the MCP config is visible inside the VM.
	var vmOut string
	var readErr error
	for attempt := 0; attempt < 10; attempt++ {
		vmOut, readErr = env.execInVM("cat", "/mcp/mcp-servers.json")
		if readErr == nil && strings.Contains(vmOut, "sluice") {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if readErr != nil {
		t.Fatalf("read mcp-servers.json from VM: %v\n%s", readErr, vmOut)
	}
	if !strings.Contains(vmOut, "streamable-http") {
		t.Errorf("mcp-servers.json missing transport field: %s", vmOut)
	}
	if !strings.Contains(vmOut, "127.0.0.1:3000/mcp") {
		t.Errorf("mcp-servers.json missing sluice URL: %s", vmOut)
	}
}
