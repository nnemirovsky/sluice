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

func TestGenerateAnchorRules(t *testing.T) {
	router := NewNetworkRouter(NetworkRouterConfig{
		TUNIface: "utun3",
	})

	rules := router.GenerateAnchorRules("bridge100", "192.168.64.0/24", "192.168.64.1")

	// Verify the route-to rule redirects TCP VM traffic through TUN.
	if !strings.Contains(rules, "pass in on bridge100 route-to (utun3 192.168.64.1) proto tcp from 192.168.64.0/24 to any") {
		t.Errorf("missing route-to rule in:\n%s", rules)
	}

	// Verify return traffic is allowed.
	if !strings.Contains(rules, "pass out on bridge100 from any to 192.168.64.0/24") {
		t.Errorf("missing return traffic rule in:\n%s", rules)
	}

	// Verify bridge and TUN are mentioned in comments.
	if !strings.Contains(rules, "bridge100") {
		t.Errorf("should mention bridge interface in comments: %s", rules)
	}
	if !strings.Contains(rules, "utun3") {
		t.Errorf("should mention TUN interface in comments: %s", rules)
	}
}

func TestGenerateAnchorRulesCustomTUN(t *testing.T) {
	router := NewNetworkRouter(NetworkRouterConfig{
		TUNIface: "utun7",
	})

	rules := router.GenerateAnchorRules("bridge101", "10.0.0.0/24", "10.0.0.1")

	if !strings.Contains(rules, "pass in on bridge101 route-to (utun7 10.0.0.1) proto tcp from 10.0.0.0/24 to any") {
		t.Errorf("should use custom TUN interface:\n%s", rules)
	}
	if !strings.Contains(rules, "pass out on bridge101 from any to 10.0.0.0/24") {
		t.Errorf("should use custom bridge:\n%s", rules)
	}
}

func TestGenerateAnchorRulesDefaults(t *testing.T) {
	router := NewNetworkRouter(NetworkRouterConfig{})

	rules := router.GenerateAnchorRules("bridge100", "192.168.64.0/24", "192.168.64.1")

	// Default TUN should be utun3.
	if !strings.Contains(rules, "utun3") {
		t.Errorf("default TUN should be utun3:\n%s", rules)
	}
}

// writeTempPFConf creates a temp pf.conf for testing and returns its path.
func writeTempPFConf(t *testing.T, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "pf.conf")
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSetupNetworkRouting(t *testing.T) {
	runner := newMockRunner()
	// pfctl -f <pf.conf> reloads the main ruleset after anchor directive is added.
	runner.onCommand("pfctl -f", nil, nil)
	// pfctl -a sluice -f <tempfile> loads the anchor rules.
	runner.onCommand("pfctl -a sluice -f", nil, nil)
	// pfctl -e enables pf if not already running.
	runner.onCommand("pfctl -e", nil, nil)

	pfConf := writeTempPFConf(t, "# default pf rules\n")
	router := NewNetworkRouter(NetworkRouterConfig{
		Runner:     runner,
		AnchorName: "sluice",
		TUNIface:   "utun3",
		PFConfPath: pfConf,
	})

	err := router.SetupNetworkRouting(context.Background(), "192.168.64.2", "bridge100", "192.168.64.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !runner.called("pfctl -f") {
		t.Error("expected pfctl -f call to reload pf.conf after adding anchor")
	}
	if !runner.called("pfctl -a sluice -f") {
		t.Error("expected pfctl call to load anchor rules from file")
	}
	if !runner.called("pfctl -e") {
		t.Error("expected pfctl -e call to enable pf")
	}

	// Verify anchor reference was added to pf.conf.
	data, _ := os.ReadFile(pfConf)
	if !strings.Contains(string(data), `anchor "sluice"`) {
		t.Error("pf.conf should contain anchor reference after setup")
	}
}

func TestSetupNetworkRoutingAnchorAlreadyPresent(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("pfctl -a sluice -f", nil, nil)
	runner.onCommand("pfctl -e", nil, nil)

	pfConf := writeTempPFConf(t, "# defaults\nanchor \"sluice\"\n")
	router := NewNetworkRouter(NetworkRouterConfig{
		Runner:     runner,
		AnchorName: "sluice",
		TUNIface:   "utun3",
		PFConfPath: pfConf,
	})

	err := router.SetupNetworkRouting(context.Background(), "192.168.64.2", "bridge100", "192.168.64.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the anchor directive was not duplicated.
	data, _ := os.ReadFile(pfConf)
	count := strings.Count(string(data), `anchor "sluice"`)
	if count != 1 {
		t.Errorf("expected exactly 1 anchor reference, got %d", count)
	}

	// When anchor is already present, pf.conf should NOT be reloaded.
	if runner.called("pfctl -f") {
		t.Error("should not reload pf.conf when anchor directive already exists")
	}
}

func TestSetupNetworkRoutingCommentedAnchorNotMatched(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("pfctl -f", nil, nil)
	runner.onCommand("pfctl -a sluice -f", nil, nil)
	runner.onCommand("pfctl -e", nil, nil)

	// pf.conf has a commented-out anchor directive. Setup should still add
	// the active directive and reload.
	pfConf := writeTempPFConf(t, "# anchor \"sluice\"\n")
	router := NewNetworkRouter(NetworkRouterConfig{
		Runner:     runner,
		AnchorName: "sluice",
		TUNIface:   "utun3",
		PFConfPath: pfConf,
	})

	err := router.SetupNetworkRouting(context.Background(), "192.168.64.2", "bridge100", "192.168.64.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have reloaded pf.conf because the commented line is not active.
	if !runner.called("pfctl -f") {
		t.Error("expected pfctl -f reload when anchor was only commented out")
	}

	data, _ := os.ReadFile(pfConf)
	// Should have both the comment and the active directive.
	lines := strings.Split(string(data), "\n")
	activeCount := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == `anchor "sluice"` {
			activeCount++
		}
	}
	if activeCount != 1 {
		t.Errorf("expected exactly 1 active anchor directive, got %d in:\n%s", activeCount, data)
	}
}

func TestSetupNetworkRoutingBadIP(t *testing.T) {
	runner := newMockRunner()
	router := NewNetworkRouter(NetworkRouterConfig{Runner: runner})

	err := router.SetupNetworkRouting(context.Background(), "not-an-ip", "bridge100", "192.168.64.1")
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
	if !strings.Contains(err.Error(), "invalid IP") {
		t.Errorf("error should mention invalid IP: %v", err)
	}
}

func TestSetupNetworkRoutingIPv6(t *testing.T) {
	runner := newMockRunner()
	router := NewNetworkRouter(NetworkRouterConfig{Runner: runner})

	err := router.SetupNetworkRouting(context.Background(), "::1", "bridge100", "192.168.64.1")
	if err == nil {
		t.Fatal("expected error for IPv6 address")
	}
	if !strings.Contains(err.Error(), "not an IPv4") {
		t.Errorf("error should mention IPv4: %v", err)
	}
}

func TestSetupNetworkRoutingPfctlReloadError(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("pfctl", nil, errors.New("pfctl failed"))

	pfConf := writeTempPFConf(t, "# default pf rules\n")
	router := NewNetworkRouter(NetworkRouterConfig{
		Runner:     runner,
		AnchorName: "sluice",
		PFConfPath: pfConf,
	})

	err := router.SetupNetworkRouting(context.Background(), "192.168.64.2", "bridge100", "192.168.64.1")
	if err == nil {
		t.Fatal("expected error when pfctl reload fails")
	}
	if !strings.Contains(err.Error(), "reload pf.conf") {
		t.Errorf("error should mention pf.conf reload: %v", err)
	}
}

func TestSetupNetworkRoutingAnchorLoadError(t *testing.T) {
	runner := newMockRunner()
	// Reload succeeds, but anchor load fails.
	runner.onCommand("pfctl -f", nil, nil)
	runner.onCommand("pfctl -a sluice -f", nil, errors.New("pfctl anchor failed"))

	pfConf := writeTempPFConf(t, "# default pf rules\n")
	router := NewNetworkRouter(NetworkRouterConfig{
		Runner:     runner,
		AnchorName: "sluice",
		PFConfPath: pfConf,
	})

	err := router.SetupNetworkRouting(context.Background(), "192.168.64.2", "bridge100", "192.168.64.1")
	if err == nil {
		t.Fatal("expected error when anchor load fails")
	}
	if !strings.Contains(err.Error(), "load pf anchor") {
		t.Errorf("error should mention pf anchor: %v", err)
	}
}

func TestSetupNetworkRoutingEnablePfError(t *testing.T) {
	runner := newMockRunner()
	// Anchor ref and load succeed, but pfctl -e fails.
	runner.onCommand("pfctl -f", nil, nil)
	runner.onCommand("pfctl -a sluice -f", nil, nil)
	runner.onCommand("pfctl -e", nil, errors.New("permission denied"))

	pfConf := writeTempPFConf(t, "# default pf rules\n")
	router := NewNetworkRouter(NetworkRouterConfig{
		Runner:     runner,
		AnchorName: "sluice",
		PFConfPath: pfConf,
	})

	err := router.SetupNetworkRouting(context.Background(), "192.168.64.2", "bridge100", "192.168.64.1")
	if err == nil {
		t.Fatal("expected error when pfctl -e fails")
	}
	if !strings.Contains(err.Error(), "enable pf") {
		t.Errorf("error should mention enabling pf: %v", err)
	}
}

func TestTeardownNetworkRouting(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("pfctl -a sluice -F all", nil, nil)

	pfConf := writeTempPFConf(t, "# defaults\nanchor \"sluice\"\n")
	router := NewNetworkRouter(NetworkRouterConfig{
		Runner:     runner,
		AnchorName: "sluice",
		PFConfPath: pfConf,
	})

	err := router.TeardownNetworkRouting(context.Background())
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

func TestTeardownNetworkRoutingError(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("pfctl", nil, errors.New("permission denied"))

	router := NewNetworkRouter(NetworkRouterConfig{
		Runner:     runner,
		AnchorName: "sluice",
	})

	err := router.TeardownNetworkRouting(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "flush pf anchor") {
		t.Errorf("error should mention flush: %v", err)
	}
}

func TestTeardownCustomAnchor(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("pfctl -a my-anchor -F all", nil, nil)

	router := NewNetworkRouter(NetworkRouterConfig{
		Runner:     runner,
		AnchorName: "my-anchor",
	})

	err := router.TeardownNetworkRouting(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !runner.called("pfctl -a my-anchor -F all") {
		t.Error("expected pfctl with custom anchor name")
	}
}

func TestSubnetFromIP(t *testing.T) {
	tests := []struct {
		ip      string
		want    string
		wantErr bool
	}{
		{"192.168.64.2", "192.168.64.0/24", false},
		{"192.168.64.100", "192.168.64.0/24", false},
		{"10.0.1.55", "10.0.1.0/24", false},
		{"172.16.0.1", "172.16.0.0/24", false},
		{"not-an-ip", "", true},
		{"::1", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got, err := subnetFromIP(tt.ip)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("subnetFromIP(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestDefaultBridgeInterface(t *testing.T) {
	getIP := func() (string, error) {
		return "192.168.64.2", nil
	}

	bridge, ip, err := DefaultBridgeInterface(getIP)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bridge != "bridge100" {
		t.Errorf("bridge = %q, want bridge100", bridge)
	}
	if ip != "192.168.64.2" {
		t.Errorf("ip = %q, want 192.168.64.2", ip)
	}
}

func TestDefaultBridgeInterfaceNoIP(t *testing.T) {
	getIP := func() (string, error) {
		return "", nil
	}

	_, _, err := DefaultBridgeInterface(getIP)
	if err == nil {
		t.Fatal("expected error when VM has no IP")
	}
	if !strings.Contains(err.Error(), "no IP address") {
		t.Errorf("error should mention no IP: %v", err)
	}
}

func TestDefaultBridgeInterfaceGetIPError(t *testing.T) {
	getIP := func() (string, error) {
		return "", errors.New("VM not found")
	}

	_, _, err := DefaultBridgeInterface(getIP)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "get VM IP") {
		t.Errorf("error should mention get VM IP: %v", err)
	}
}

func TestDefaultBridgeInterfaceWithAppleCLI(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)

	inspectJSON, _ := json.Marshal([]VMInfo{{
		Name:    "openclaw",
		ID:      "abc123",
		Image:   "openclaw:latest",
		State:   VMState{Running: true},
		Network: VMNet{IPAddress: "192.168.64.2"},
	}})
	runner.onCommand("container inspect", inspectJSON, nil)

	cli, _ := NewAppleCLIWithBin("container", runner)

	// Wrap AppleCLI.Inspect as a generic IP getter.
	getIP := func() (string, error) {
		info, err := cli.Inspect(context.Background(), "openclaw")
		if err != nil {
			return "", err
		}
		return info.Network.IPAddress, nil
	}

	bridge, ip, err := DefaultBridgeInterface(getIP)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bridge != "bridge100" {
		t.Errorf("bridge = %q, want bridge100", bridge)
	}
	if ip != "192.168.64.2" {
		t.Errorf("ip = %q, want 192.168.64.2", ip)
	}
}

func TestDefaultBridgeInterfaceWithTartCLI(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("tart --version", []byte("tart 2.15.0\n"), nil)
	runner.onCommand("tart ip", []byte("192.168.64.5\n"), nil)

	cli, _ := NewTartCLIWithBin("tart", runner)

	// Wrap TartCLI.IP as a generic IP getter.
	getIP := func() (string, error) {
		return cli.IP(context.Background(), "openclaw")
	}

	bridge, ip, err := DefaultBridgeInterface(getIP)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bridge != "bridge100" {
		t.Errorf("bridge = %q, want bridge100", bridge)
	}
	if ip != "192.168.64.5" {
		t.Errorf("ip = %q, want 192.168.64.5", ip)
	}
}

func TestIsTUN2ProxyRunning(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("ifconfig utun3", []byte("utun3: flags=...\n"), nil)

	if !IsTUN2ProxyRunning(context.Background(), runner, "utun3") {
		t.Error("expected tun2proxy to be detected as running")
	}
}

func TestIsTUN2ProxyNotRunning(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("ifconfig utun3", nil, errors.New("interface does not exist"))

	if IsTUN2ProxyRunning(context.Background(), runner, "utun3") {
		t.Error("expected tun2proxy to be detected as not running")
	}
}

func TestNewNetworkRouterDefaults(t *testing.T) {
	router := NewNetworkRouter(NetworkRouterConfig{})

	if router.anchorName != "sluice" {
		t.Errorf("default anchor = %q, want sluice", router.anchorName)
	}
	if router.tunIface != "utun3" {
		t.Errorf("default TUN = %q, want utun3", router.tunIface)
	}
	if router.runner == nil {
		t.Error("default runner should not be nil")
	}
}
