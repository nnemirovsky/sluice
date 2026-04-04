package container

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestGenerateAnchorRules(t *testing.T) {
	router := NewNetworkRouter(NetworkRouterConfig{
		TUNIface: "utun3",
	})

	rules := router.GenerateAnchorRules("bridge100", "192.168.64.0/24", "192.168.64.1")

	// Verify the route-to rule redirects VM traffic through TUN.
	if !strings.Contains(rules, "pass in on bridge100 route-to (utun3 192.168.64.1) from 192.168.64.0/24 to any") {
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

	if !strings.Contains(rules, "pass in on bridge101 route-to (utun7 10.0.0.1) from 10.0.0.0/24 to any") {
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

func TestSetupNetworkRouting(t *testing.T) {
	runner := newMockRunner()
	// The first pfctl call (stdin load) succeeds.
	runner.onCommand("pfctl -a sluice -f -", nil, nil)

	router := NewNetworkRouter(NetworkRouterConfig{
		Runner:     runner,
		AnchorName: "sluice",
		TUNIface:   "utun3",
	})

	err := router.SetupNetworkRouting(context.Background(), "192.168.64.2", "bridge100", "192.168.64.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !runner.called("pfctl -a sluice -f -") {
		t.Error("expected pfctl call to load anchor rules")
	}
}

func TestSetupNetworkRoutingFallback(t *testing.T) {
	runner := newMockRunner()
	// First pfctl call fails, triggering sh -c fallback.
	runner.onCommand("pfctl -a sluice -f -", nil, errors.New("stdin not supported"))
	runner.onCommand("sh -c", nil, nil)

	router := NewNetworkRouter(NetworkRouterConfig{
		Runner:     runner,
		AnchorName: "sluice",
		TUNIface:   "utun3",
	})

	err := router.SetupNetworkRouting(context.Background(), "192.168.64.2", "bridge100", "192.168.64.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !runner.called("sh -c") {
		t.Error("expected sh -c fallback call")
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

func TestSetupNetworkRoutingPfctlError(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("pfctl", nil, errors.New("pfctl failed"))
	runner.onCommand("sh -c", nil, errors.New("sh also failed"))

	router := NewNetworkRouter(NetworkRouterConfig{
		Runner:     runner,
		AnchorName: "sluice",
	})

	err := router.SetupNetworkRouting(context.Background(), "192.168.64.2", "bridge100", "192.168.64.1")
	if err == nil {
		t.Fatal("expected error when pfctl fails")
	}
	if !strings.Contains(err.Error(), "load pf anchor") {
		t.Errorf("error should mention pf anchor: %v", err)
	}
}

func TestTeardownNetworkRouting(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("pfctl -a sluice -F all", nil, nil)

	router := NewNetworkRouter(NetworkRouterConfig{
		Runner:     runner,
		AnchorName: "sluice",
	})

	err := router.TeardownNetworkRouting(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !runner.called("pfctl -a sluice -F all") {
		t.Error("expected pfctl flush call")
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

func TestDetectBridgeInterface(t *testing.T) {
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

	bridge, ip, err := DetectBridgeInterface(context.Background(), cli, "openclaw")
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

func TestDetectBridgeInterfaceNoIP(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)

	inspectJSON, _ := json.Marshal([]VMInfo{{
		Name:    "openclaw",
		State:   VMState{Running: true},
		Network: VMNet{IPAddress: ""},
	}})
	runner.onCommand("container inspect", inspectJSON, nil)

	cli, _ := NewAppleCLIWithBin("container", runner)

	_, _, err := DetectBridgeInterface(context.Background(), cli, "openclaw")
	if err == nil {
		t.Fatal("expected error when VM has no IP")
	}
	if !strings.Contains(err.Error(), "no IP address") {
		t.Errorf("error should mention no IP: %v", err)
	}
}

func TestDetectBridgeInterfaceInspectError(t *testing.T) {
	runner := newMockRunner()
	runner.onCommand("container --version", []byte("v1.0\n"), nil)
	runner.onCommand("container inspect", nil, errors.New("VM not found"))

	cli, _ := NewAppleCLIWithBin("container", runner)

	_, _, err := DetectBridgeInterface(context.Background(), cli, "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "inspect VM") {
		t.Errorf("error should mention inspect: %v", err)
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
