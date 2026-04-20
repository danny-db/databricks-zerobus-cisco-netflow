#!/usr/bin/env bash
# Start fprobe to capture real network traffic as NetFlow v5
# Usage: ./start-fprobe.sh [interface]
#   interface: network interface to capture (default: auto-detect)
#   Examples:  ./start-fprobe.sh en0      # Wi-Fi
#              ./start-fprobe.sh utun4    # VPN tunnel
set -euo pipefail

command -v fprobe &>/dev/null || { echo "ERROR: fprobe not installed (brew install fprobe)"; exit 1; }

# Auto-detect interface if not specified
if [ $# -ge 1 ]; then
    IFACE="$1"
else
    # Prefer VPN tunnel (utun*) if active, otherwise use en0
    IFACE=$(ifconfig -l | tr ' ' '\n' | while read ifc; do
        if [[ "$ifc" == utun* ]] && ifconfig "$ifc" 2>/dev/null | grep -q "inet "; then
            echo "$ifc"
            break
        fi
    done)

    if [ -z "$IFACE" ]; then
        IFACE="en0"
    fi
fi

# Get interface IP for display
IFACE_IP=$(ifconfig "$IFACE" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)

# Check if fprobe is already running
if pgrep -x fprobe &>/dev/null; then
    echo "fprobe is already running. Stop it first: ./stop-fprobe.sh"
    exit 1
fi

echo "Starting fprobe..."
echo "  Interface: $IFACE (${IFACE_IP:-no IP})"
echo "  Export:    NetFlow v5 -> 127.0.0.1:2055"
echo ""

sudo fprobe -i "$IFACE" 127.0.0.1:2055

echo "fprobe started. Real traffic will appear in Databricks within ~60 seconds."
