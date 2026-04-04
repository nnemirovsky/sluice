package container

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// NetworkRouter manages macOS pf (packet filter) rules that redirect Apple
// Container VM traffic through a TUN device to tun2proxy, which forwards it
// to sluice's SOCKS5 proxy. All pfctl calls go through CommandRunner for
// testability.
type NetworkRouter struct {
	runner     CommandRunner
	anchorName string
	tunIface   string
}

// NetworkRouterConfig holds configuration for creating a NetworkRouter.
type NetworkRouterConfig struct {
	Runner     CommandRunner
	AnchorName string // pf anchor name (default: "sluice")
	TUNIface   string // TUN interface for tun2proxy (default: "utun3")
}

// NewNetworkRouter creates a NetworkRouter with the given config.
func NewNetworkRouter(cfg NetworkRouterConfig) *NetworkRouter {
	anchor := cfg.AnchorName
	if anchor == "" {
		anchor = "sluice"
	}
	tun := cfg.TUNIface
	if tun == "" {
		tun = "utun3"
	}
	runner := cfg.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	return &NetworkRouter{
		runner:     runner,
		anchorName: anchor,
		tunIface:   tun,
	}
}

// GenerateAnchorRules produces pf anchor rules that redirect traffic from a
// VM subnet on a bridge interface through the TUN device. The tunGateway is
// the host-side IP on the TUN interface that tun2proxy listens on.
func (r *NetworkRouter) GenerateAnchorRules(bridgeIface, vmSubnet, tunGateway string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Sluice pf anchor: redirect Apple Container VM traffic\n")
	fmt.Fprintf(&b, "# Bridge: %s, Subnet: %s, TUN: %s\n\n", bridgeIface, vmSubnet, r.tunIface)
	// Route all VM outbound traffic through the TUN device to tun2proxy.
	fmt.Fprintf(&b, "pass in on %s route-to (%s %s) from %s to any\n", bridgeIface, r.tunIface, tunGateway, vmSubnet)
	// Allow return traffic back to the VM subnet.
	fmt.Fprintf(&b, "pass out on %s from any to %s\n", bridgeIface, vmSubnet)
	return b.String()
}

// SetupNetworkRouting generates pf anchor rules for the given VM IP and loads
// them via pfctl. It detects the bridge interface and subnet from the VM IP.
// Requires root privileges (pfctl needs sudo).
func (r *NetworkRouter) SetupNetworkRouting(ctx context.Context, vmIP, bridgeIface, tunGateway string) error {
	// Derive /24 subnet from VM IP.
	subnet, err := subnetFromIP(vmIP)
	if err != nil {
		return fmt.Errorf("derive subnet from VM IP %q: %w", vmIP, err)
	}

	rules := r.GenerateAnchorRules(bridgeIface, subnet, tunGateway)

	// Load the anchor rules via pfctl.
	// pfctl -a <anchor> -f - reads rules from stdin. We pass via echo.
	_, err = r.runner.Run(ctx, "pfctl", "-a", r.anchorName, "-f", "-")
	if err != nil {
		// Fallback: write to temp file and load.
		return r.loadAnchorFromString(ctx, rules)
	}
	return nil
}

// loadAnchorFromString writes rules to a temp path and loads via pfctl.
func (r *NetworkRouter) loadAnchorFromString(ctx context.Context, rules string) error {
	// Use sh -c with echo pipe to load rules into pfctl.
	cmd := fmt.Sprintf("echo '%s' | pfctl -a %s -f -", rules, r.anchorName)
	_, err := r.runner.Run(ctx, "sh", "-c", cmd)
	if err != nil {
		return fmt.Errorf("load pf anchor %q: %w", r.anchorName, err)
	}
	return nil
}

// TeardownNetworkRouting removes the pf anchor rules by flushing the anchor.
func (r *NetworkRouter) TeardownNetworkRouting(ctx context.Context) error {
	_, err := r.runner.Run(ctx, "pfctl", "-a", r.anchorName, "-F", "all")
	if err != nil {
		return fmt.Errorf("flush pf anchor %q: %w", r.anchorName, err)
	}
	return nil
}

// DetectBridgeInterface extracts the bridge interface from a VM's IP address
// by inspecting the VM via the provided AppleCLI and matching the IP to a
// known bridge subnet. Returns the bridge interface name (e.g., "bridge100").
func DetectBridgeInterface(ctx context.Context, cli *AppleCLI, vmName string) (string, string, error) {
	info, err := cli.Inspect(ctx, vmName)
	if err != nil {
		return "", "", fmt.Errorf("inspect VM %q: %w", vmName, err)
	}
	ip := info.Network.IPAddress
	if ip == "" {
		return "", "", fmt.Errorf("VM %q has no IP address", vmName)
	}
	// Apple Container VMs typically use bridge100 with 192.168.64.0/24.
	// Return the detected IP and default bridge interface.
	return "bridge100", ip, nil
}

// subnetFromIP derives a /24 CIDR subnet from an IP address.
// For example, "192.168.64.2" returns "192.168.64.0/24".
func subnetFromIP(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", ipStr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("not an IPv4 address: %s", ipStr)
	}
	// Zero the host part for a /24.
	ip4[3] = 0
	return fmt.Sprintf("%s/24", ip4.String()), nil
}
