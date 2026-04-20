#!/usr/bin/env bash
# Start the Cisco Telemetry ingestion pipeline
# Usage: ./start.sh
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Starting Cisco Telemetry Pipeline..."

# Check prerequisites
command -v telegraf &>/dev/null || { echo "ERROR: telegraf not installed (brew install telegraf)"; exit 1; }
command -v python3 &>/dev/null || { echo "ERROR: python3 not found"; exit 1; }
python3 -c "from zerobus.sdk.sync import ZerobusSdk" 2>/dev/null || { echo "ERROR: databricks-zerobus-ingest-sdk not installed"; exit 1; }

# Check env file
if grep -q '<your-' "${DIR}/telegraf/telegraf.env" 2>/dev/null; then
    echo "ERROR: Configure ${DIR}/telegraf/telegraf.env first"
    exit 1
fi

# Kill any existing instances
pkill -f "zerobus_relay.py" 2>/dev/null || true
pkill -f "telegraf --config.*cisco-telegraf-zerobus" 2>/dev/null || true
sleep 1

# 1. Start relay
echo "  [1/2] Starting Zerobus relay (port 9090)..."
cd "$DIR"
PYTHONUNBUFFERED=1 python3 relay/zerobus_relay.py > /tmp/relay.log 2>&1 &
echo $! > /tmp/zerobus_relay.pid
sleep 3

if kill -0 "$(cat /tmp/zerobus_relay.pid)" 2>/dev/null; then
    echo "        Relay running (PID $(cat /tmp/zerobus_relay.pid))"
else
    echo "        ERROR: Relay failed to start. Check /tmp/relay.log"
    exit 1
fi

# 2. Start Telegraf
echo "  [2/2] Starting Telegraf (ports 2055, 6514, 162)..."
set -a && source "${DIR}/telegraf/telegraf.env" && set +a
telegraf --config "${DIR}/telegraf/telegraf.conf" > /tmp/telegraf.log 2>&1 &
echo $! > /tmp/telegraf.pid
sleep 2

if kill -0 "$(cat /tmp/telegraf.pid)" 2>/dev/null; then
    echo "        Telegraf running (PID $(cat /tmp/telegraf.pid))"
else
    echo "        ERROR: Telegraf failed to start. Check /tmp/telegraf.log"
    exit 1
fi

echo ""
echo "Pipeline running. Listening for:"
echo "  NetFlow   UDP :2055"
echo "  Syslog    TCP :6514"
echo "  SNMP Trap UDP :162"
echo ""
echo "Logs:"
echo "  Relay:    /tmp/relay.log"
echo "  Telegraf: /tmp/telegraf.log"
echo ""
echo "Next: start a NetFlow source (./start-fprobe.sh) or point Cisco devices here"
