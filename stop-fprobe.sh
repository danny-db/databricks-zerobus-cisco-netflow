#!/usr/bin/env bash
# Stop fprobe
# Usage: ./stop-fprobe.sh
set -euo pipefail

if pgrep -x fprobe &>/dev/null; then
    sudo pkill fprobe
    echo "fprobe stopped."
else
    echo "fprobe is not running."
fi
