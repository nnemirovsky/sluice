#!/bin/bash
# macos-vm-setup.sh
#
# Manual setup script for routing macOS VM (tart) traffic through sluice.
# This script:
#   1. Starts tun2proxy to forward TUN traffic to sluice's SOCKS5 proxy
#   2. Enables IP forwarding on macOS
#   3. Documents the pf rules that sluice will apply automatically
#
# sluice applies pf rules programmatically when --runtime macos is used.
# This script only handles the prerequisites that require manual setup:
# tun2proxy and IP forwarding.
#
# Requirements:
#   - macOS with Apple Silicon (M1+)
#   - tun2proxy binary in PATH (brew install tun2proxy)
#   - sluice running with SOCKS5 on the specified address
#   - tart CLI installed (brew install cirruslabs/cli/tart)
#   - Root privileges (tun2proxy creates TUN device)
#
# Usage:
#   sudo ./macos-vm-setup.sh [options]
#
# Options:
#   --socks-addr ADDR   sluice SOCKS5 address (default: 127.0.0.1:1080)
#   --tun-iface NAME    TUN interface for tun2proxy (default: utun3)
#   --teardown          Stop tun2proxy and restore IP forwarding, then exit
#   --help              Show this help message

set -euo pipefail

SOCKS_ADDR="127.0.0.1:1080"
TUN_IFACE="utun3"
TEARDOWN=false

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
    echo "Error: this script must be run as root (tun2proxy creates TUN device)."
    echo "Run: sudo $0 $*"
    exit 1
fi

teardown() {
    echo "Tearing down tun2proxy..."

    # Kill tun2proxy if running.
    if pkill -f "tun2proxy.*--tun $TUN_IFACE" 2>/dev/null; then
        echo "Stopped tun2proxy"
    else
        echo "tun2proxy not running"
    fi

    # Restore IP forwarding to its original state (saved during setup).
    if [[ -f /tmp/sluice-macos-vm-ip-forwarding-orig ]]; then
        local orig
        orig=$(cat /tmp/sluice-macos-vm-ip-forwarding-orig)
        sysctl -w "net.inet.ip.forwarding=$orig" >/dev/null 2>&1 || true
        rm -f /tmp/sluice-macos-vm-ip-forwarding-orig
        echo "Restored IP forwarding to original state ($orig)."
    else
        echo "Warning: original IP forwarding state not found, leaving unchanged."
    fi

    echo ""
    echo "Teardown complete."
    echo "Note: pf rules are managed by sluice and cleaned up on sluice shutdown."
}

setup() {
    echo "Setting up tun2proxy for macOS VM traffic routing..."
    echo "  SOCKS5 proxy: $SOCKS_ADDR"
    echo "  TUN interface: $TUN_IFACE"

    # Check prerequisites.
    if ! command -v tun2proxy >/dev/null 2>&1; then
        echo "Error: tun2proxy not found in PATH."
        echo "Install it: brew install tun2proxy"
        exit 1
    fi

    if ! command -v tart >/dev/null 2>&1; then
        echo "Warning: tart CLI not found in PATH."
        echo "Install it: brew install cirruslabs/cli/tart"
        echo "Continuing anyway (tun2proxy can start without tart)."
    fi

    # Enable IP forwarding (save original state for teardown).
    sysctl -n net.inet.ip.forwarding > /tmp/sluice-macos-vm-ip-forwarding-orig 2>/dev/null || true
    sysctl -w net.inet.ip.forwarding=1 >/dev/null
    echo "Enabled IP forwarding."

    # Start tun2proxy in background.
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

    echo ""
    echo "Setup complete. tun2proxy is running on $TUN_IFACE."
    echo ""
    echo "Next steps:"
    echo "  1. Start sluice with: sluice --runtime macos --vm-image <image>"
    echo "     sluice will automatically apply pf rules to route VM traffic."
    echo "  2. On shutdown, sluice cleans up pf rules automatically."
    echo "  3. To stop tun2proxy: sudo $0 --teardown"
}

if $TEARDOWN; then
    teardown
else
    setup
fi
