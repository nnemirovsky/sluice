package container

import (
	"context"
	"fmt"
	"net"
	"os"
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
	pfConfPath string
}

// NetworkRouterConfig holds configuration for creating a NetworkRouter.
type NetworkRouterConfig struct {
	Runner     CommandRunner
	AnchorName string // pf anchor name (default: "sluice")
	TUNIface   string // TUN interface for tun2proxy (default: "utun3")
	PFConfPath string // path to pf.conf (default: "/etc/pf.conf")
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
	pfConf := cfg.PFConfPath
	if pfConf == "" {
		pfConf = "/etc/pf.conf"
	}
	return &NetworkRouter{
		runner:     runner,
		anchorName: anchor,
		tunIface:   tun,
		pfConfPath: pfConf,
	}
}

// GenerateAnchorRules produces pf anchor rules that redirect traffic from a
// VM subnet on a bridge interface through the TUN device. The tunGateway is
// the host-side IP on the TUN interface that tun2proxy listens on.
func (r *NetworkRouter) GenerateAnchorRules(bridgeIface, vmSubnet, tunGateway string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Sluice pf anchor: redirect Apple Container VM traffic\n")
	fmt.Fprintf(&b, "# Bridge: %s, Subnet: %s, TUN: %s\n\n", bridgeIface, vmSubnet, r.tunIface)
	// Route TCP traffic from the VM through the TUN device to tun2proxy.
	// Only TCP is routed because SOCKS5/tun2proxy cannot handle UDP or ICMP.
	fmt.Fprintf(&b, "pass in on %s route-to (%s %s) proto tcp from %s to any\n", bridgeIface, r.tunIface, tunGateway, vmSubnet)
	// Allow return traffic back to the VM subnet.
	fmt.Fprintf(&b, "pass out on %s from any to %s\n", bridgeIface, vmSubnet)
	return b.String()
}

// SetupNetworkRouting generates pf anchor rules for the given VM IP and loads
// them via pfctl. It ensures /etc/pf.conf references the anchor (required for
// pf to evaluate anchor rules), then loads the anchor rules.
// Requires root privileges (pfctl needs sudo).
func (r *NetworkRouter) SetupNetworkRouting(ctx context.Context, vmIP, bridgeIface, tunGateway string) error {
	// Derive /24 subnet from VM IP.
	subnet, err := subnetFromIP(vmIP)
	if err != nil {
		return fmt.Errorf("derive subnet from VM IP %q: %w", vmIP, err)
	}

	// Ensure the main pf config references our anchor. Without this, the
	// anchor rules load silently but are never evaluated by pf.
	added, err := r.ensureAnchorRef()
	if err != nil {
		return fmt.Errorf("ensure pf anchor reference: %w", err)
	}
	// If we added the anchor directive, reload the main ruleset so pf
	// picks up the new anchor reference. Without this reload, the in-memory
	// pf ruleset does not include the anchor and anchor rules are ignored.
	if added {
		if _, err := r.runner.Run(ctx, "pfctl", "-f", r.pfConfPath); err != nil {
			return fmt.Errorf("reload pf.conf after adding anchor: %w", err)
		}
	}

	rules := r.GenerateAnchorRules(bridgeIface, subnet, tunGateway)

	// Write rules to a temp file and load via pfctl. This avoids shell
	// injection risks from interpolating rules into a shell command.
	return r.loadAnchorFromFile(ctx, rules)
}

// loadAnchorFromFile writes rules to a temp file and loads via pfctl -f.
func (r *NetworkRouter) loadAnchorFromFile(ctx context.Context, rules string) error {
	f, err := os.CreateTemp("", "sluice-pf-*.conf")
	if err != nil {
		return fmt.Errorf("create temp pf rules file: %w", err)
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString(rules); err != nil {
		f.Close()
		return fmt.Errorf("write pf rules: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close pf rules file: %w", err)
	}

	_, err = r.runner.Run(ctx, "pfctl", "-a", r.anchorName, "-f", f.Name())
	if err != nil {
		return fmt.Errorf("load pf anchor %q: %w", r.anchorName, err)
	}
	return nil
}

// TeardownNetworkRouting removes the pf anchor rules by flushing the anchor
// and removing the anchor reference from /etc/pf.conf.
func (r *NetworkRouter) TeardownNetworkRouting(ctx context.Context) error {
	_, err := r.runner.Run(ctx, "pfctl", "-a", r.anchorName, "-F", "all")
	if err != nil {
		return fmt.Errorf("flush pf anchor %q: %w", r.anchorName, err)
	}
	// Best-effort removal of anchor reference from /etc/pf.conf.
	_ = r.removeAnchorRef()
	return nil
}

// ensureAnchorRef adds an anchor directive to pf.conf if not already present
// as an active (non-commented) line. Returns true if the directive was added
// (meaning the caller should reload pf.conf to activate it).
// pf only evaluates anchor rules when the main ruleset references them.
func (r *NetworkRouter) ensureAnchorRef() (bool, error) {
	directive := fmt.Sprintf("anchor \"%s\"", r.anchorName)

	data, err := os.ReadFile(r.pfConfPath)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", r.pfConfPath, err)
	}

	// Check line-by-line so commented-out directives (e.g. "# anchor ...")
	// are not mistaken for active ones.
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == directive {
			return false, nil // already present as an active line
		}
	}

	f, err := os.OpenFile(r.pfConfPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return false, fmt.Errorf("open %s for append: %w", r.pfConfPath, err)
	}
	_, writeErr := fmt.Fprintf(f, "\n%s\n", directive)
	closeErr := f.Close()
	if writeErr != nil {
		return false, fmt.Errorf("write anchor directive: %w", writeErr)
	}
	if closeErr != nil {
		return false, fmt.Errorf("close %s: %w", r.pfConfPath, closeErr)
	}
	return true, nil
}

// removeAnchorRef removes the anchor directive from pf.conf.
func (r *NetworkRouter) removeAnchorRef() error {
	directive := fmt.Sprintf("anchor \"%s\"", r.anchorName)

	data, err := os.ReadFile(r.pfConfPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	var filtered []string
	for _, line := range lines {
		if strings.TrimSpace(line) != directive {
			filtered = append(filtered, line)
		}
	}

	return os.WriteFile(r.pfConfPath, []byte(strings.Join(filtered, "\n")), 0644)
}

// DefaultBridgeInterface returns the default bridge interface name and the
// VM's IP address. Apple Container VMs typically use bridge100, so this is
// used as a default. The actual bridge detection is done by the setup script
// (scripts/apple-container-setup.sh) which iterates host interfaces.
func DefaultBridgeInterface(ctx context.Context, cli *AppleCLI, vmName string) (string, string, error) {
	info, err := cli.Inspect(ctx, vmName)
	if err != nil {
		return "", "", fmt.Errorf("inspect VM %q: %w", vmName, err)
	}
	ip := info.Network.IPAddress
	if ip == "" {
		return "", "", fmt.Errorf("VM %q has no IP address", vmName)
	}
	// Default to bridge100. For accurate detection, use the setup script
	// which correlates VM IP with host interface subnets.
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
