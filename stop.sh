#!/usr/bin/env bash
# Stop the Cisco Telemetry ingestion pipeline
# Usage: ./stop.sh
set -euo pipefail

echo "Stopping Cisco Telemetry Pipeline..."

# Stop Telegraf
if [ -f /tmp/telegraf.pid ] && kill -0 "$(cat /tmp/telegraf.pid)" 2>/dev/null; then
    kill "$(cat /tmp/telegraf.pid)" 2>/dev/null
    echo "  Telegraf stopped (PID $(cat /tmp/telegraf.pid))"
    rm -f /tmp/telegraf.pid
else
    pkill -f "telegraf --config" 2>/dev/null && echo "  Telegraf stopped" || echo "  Telegraf not running"
    rm -f /tmp/telegraf.pid
fi

# Stop relay
if [ -f /tmp/zerobus_relay.pid ] && kill -0 "$(cat /tmp/zerobus_relay.pid)" 2>/dev/null; then
    kill "$(cat /tmp/zerobus_relay.pid)" 2>/dev/null
    echo "  Relay stopped (PID $(cat /tmp/zerobus_relay.pid))"
    rm -f /tmp/zerobus_relay.pid
else
    pkill -f "zerobus_relay.py" 2>/dev/null && echo "  Relay stopped" || echo "  Relay not running"
    rm -f /tmp/zerobus_relay.pid
fi

# Stop fprobe if running
if pgrep -x fprobe &>/dev/null; then
    sudo pkill fprobe 2>/dev/null && echo "  fprobe stopped" || echo "  fprobe not running"
else
    echo "  fprobe not running"
fi

echo ""
echo "Pipeline stopped."
