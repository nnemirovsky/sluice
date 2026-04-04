#!/bin/bash
# apple-container-setup.sh
#
# Manual setup script for routing Apple Container VM traffic through sluice.
# This script:
#   1. Detects the bridge interface used by Apple Container VMs
#   2. Starts tun2proxy to forward TUN traffic to sluice's SOCKS5 proxy
#   3. Applies macOS pf rules to redirect VM traffic through the TUN device
#   4. Enables IP forwarding on macOS
#
# Requirements:
#   - macOS with Apple Container installed
#   - tun2proxy binary in PATH
#   - sluice running with SOCKS5 on the specified address
#   - Root privileges (pf rules require sudo)
#
# Usage:
#   sudo ./apple-container-setup.sh [options]
#
# Options:
#   --socks-addr ADDR   sluice SOCKS5 address (default: 127.0.0.1:1080)
#   --tun-iface NAME    TUN interface for tun2proxy (default: utun3)
#   --anchor NAME       pf anchor name (default: sluice)
#   --teardown          Remove pf rules and stop tun2proxy, then exit
#   --help              Show this help message

set -euo pipefail

SOCKS_ADDR="127.0.0.1:1080"
TUN_IFACE="utun3"
ANCHOR_NAME="sluice"
TEARDOWN=false
BRIDGE_IFACE=""
VM_SUBNET=""
TUN_GATEWAY=""

usage() {
    sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# //'
    sed -n '/^# Options:/,/^[^#]/p' "$0" | sed 's/^# //'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --socks-addr)
            SOCKS_ADDR="$2"
            shift 2
            ;;
        --tun-iface)
            TUN_IFACE="$2"
            shift 2
            ;;
        --anchor)
            ANCHOR_NAME="$2"
            shift 2
            ;;
        --teardown)
            TEARDOWN=true
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Check root.
if [[ $EUID -ne 0 ]]; then
    echo "Error: this script must be run as root (pf rules require sudo)."
    echo "Run: sudo $0 $*"
    exit 1
fi

# Detect bridge interface. Apple Container VMs use bridge100 by default.
detect_bridge() {
    # Look for bridge interfaces with an IP in the 192.168.64.0/24 range.
    for iface in $(ifconfig -l 2>/dev/null | tr ' ' '\n' | grep '^bridge'); do
        local ip
        ip=$(ifconfig "$iface" 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1)
        if [[ -n "$ip" ]]; then
            BRIDGE_IFACE="$iface"
            # Derive subnet: replace last octet with 0/24.
            VM_SUBNET=$(echo "$ip" | sed 's/\.[0-9]*$/.0\/24/')
            TUN_GATEWAY=$(echo "$ip" | sed 's/\.[0-9]*$/.1/')
            echo "Detected bridge interface: $BRIDGE_IFACE (subnet: $VM_SUBNET)"
            return 0
        fi
    done

    # Fallback to bridge100 with default subnet.
    echo "Warning: could not auto-detect bridge interface. Using defaults."
    BRIDGE_IFACE="bridge100"
    VM_SUBNET="192.168.64.0/24"
    TUN_GATEWAY="192.168.64.1"
    return 0
}

teardown() {
    echo "Tearing down sluice network routing..."

    # Flush pf anchor.
    if pfctl -a "$ANCHOR_NAME" -F all 2>/dev/null; then
        echo "Flushed pf anchor: $ANCHOR_NAME"
    else
        echo "Warning: could not flush pf anchor (may not exist)"
    fi

    # Kill tun2proxy if running.
    if pkill -f "tun2proxy.*--tun $TUN_IFACE" 2>/dev/null; then
        echo "Stopped tun2proxy"
    else
        echo "tun2proxy not running"
    fi

    # Disable IP forwarding (was enabled during setup).
    sysctl -w net.inet.ip.forwarding=0 >/dev/null 2>&1 || true
    echo "Disabled IP forwarding."

    echo "Teardown complete."
}

setup() {
    echo "Setting up sluice network routing for Apple Container..."
    echo "  SOCKS5 proxy: $SOCKS_ADDR"
    echo "  TUN interface: $TUN_IFACE"
    echo "  pf anchor: $ANCHOR_NAME"

    # Step 1: Detect bridge interface.
    detect_bridge
    echo "  Bridge: $BRIDGE_IFACE"
    echo "  VM subnet: $VM_SUBNET"

    # Step 2: Check prerequisites.
    if ! command -v tun2proxy >/dev/null 2>&1; then
        echo "Error: tun2proxy not found in PATH."
        echo "Install it: brew install tun2proxy"
        exit 1
    fi

    if ! command -v pfctl >/dev/null 2>&1; then
        echo "Error: pfctl not found. This script requires macOS."
        exit 1
    fi

    # Step 3: Enable IP forwarding.
    sysctl -w net.inet.ip.forwarding=1 >/dev/null
    echo "Enabled IP forwarding."

    # Step 4: Start tun2proxy in background.
    if pgrep -f "tun2proxy.*--tun $TUN_IFACE" >/dev/null 2>&1; then
        echo "tun2proxy already running on $TUN_IFACE"
    else
        echo "Starting tun2proxy..."
        tun2proxy --proxy "socks5://$SOCKS_ADDR" --tun "$TUN_IFACE" &
        TUN2PROXY_PID=$!
        sleep 1
        if ! kill -0 "$TUN2PROXY_PID" 2>/dev/null; then
            echo "Error: tun2proxy failed to start"
            exit 1
        fi
        echo "tun2proxy running (PID: $TUN2PROXY_PID)"
    fi

    # Step 5: Apply pf anchor rules.
    echo "Applying pf rules..."

    # Write anchor rules.
    cat <<EOF | pfctl -a "$ANCHOR_NAME" -f -
# Sluice pf anchor: redirect Apple Container VM traffic
# Bridge: $BRIDGE_IFACE, Subnet: $VM_SUBNET, TUN: $TUN_IFACE

pass in on $BRIDGE_IFACE route-to ($TUN_IFACE $TUN_GATEWAY) from $VM_SUBNET to any
pass out on $BRIDGE_IFACE from any to $VM_SUBNET
EOF

    echo "pf anchor loaded: $ANCHOR_NAME"

    # Ensure pf is enabled.
    pfctl -e 2>/dev/null || true
    echo "pf enabled."

    echo ""
    echo "Setup complete. All Apple Container VM traffic on $BRIDGE_IFACE"
    echo "will be routed through tun2proxy to sluice at $SOCKS_ADDR."
    echo ""
    echo "To teardown: sudo $0 --teardown"
}

if $TEARDOWN; then
    teardown
else
    setup
fi
