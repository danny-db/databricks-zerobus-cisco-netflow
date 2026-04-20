#!/usr/bin/env bash
# =============================================================================
# Cisco Telegraf Zerobus Connector — Install Script
# Installs Telegraf, deploys config, and starts the service
# Tested on: Ubuntu 22.04/24.04, RHEL 8/9, Amazon Linux 2
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TELEGRAF_CONF="${SCRIPT_DIR}/telegraf/telegraf.conf"
TELEGRAF_ENV="${SCRIPT_DIR}/telegraf/telegraf.env"

echo "=== Cisco Telegraf Zerobus Connector — Installer ==="
echo ""

# ---- Check env file is configured ----
if grep -q '<your-' "${TELEGRAF_ENV}" 2>/dev/null; then
    echo "ERROR: Please configure ${TELEGRAF_ENV} with your Databricks credentials first."
    echo "  Required fields:"
    echo "    DATABRICKS_WORKSPACE_ID"
    echo "    DATABRICKS_SP_CLIENT_ID"
    echo "    DATABRICKS_SP_CLIENT_SECRET"
    exit 1
fi

# ---- Detect OS and install Telegraf ----
install_telegraf() {
    if command -v telegraf &>/dev/null; then
        echo "Telegraf already installed: $(telegraf --version)"
        return 0
    fi

    echo "Installing Telegraf..."

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "${ID}" in
            ubuntu|debian)
                # Add InfluxData repo
                curl -fsSL https://repos.influxdata.com/influxdata-archive_compat.key | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/influxdata.gpg
                echo "deb [signed-by=/etc/apt/trusted.gpg.d/influxdata.gpg] https://repos.influxdata.com/debian stable main" | sudo tee /etc/apt/sources.list.d/influxdata.list
                sudo apt-get update -qq
                sudo apt-get install -y telegraf
                ;;
            rhel|centos|amzn|fedora)
                cat <<'REPO' | sudo tee /etc/yum.repos.d/influxdata.repo
[influxdata]
name = InfluxData Repository
baseurl = https://repos.influxdata.com/rhel/$releasever/$basearch/stable
enabled = 1
gpgcheck = 1
gpgkey = https://repos.influxdata.com/influxdata-archive_compat.key
REPO
                sudo yum install -y telegraf
                ;;
            *)
                echo "ERROR: Unsupported OS: ${ID}. Install Telegraf manually."
                echo "  See: https://docs.influxdata.com/telegraf/v1/install/"
                exit 1
                ;;
        esac
    else
        echo "ERROR: Cannot detect OS. Install Telegraf manually."
        exit 1
    fi

    echo "Telegraf installed: $(telegraf --version)"
}

# ---- Deploy config files ----
deploy_config() {
    echo "Deploying configuration..."

    # Backup existing config if present
    if [ -f /etc/telegraf/telegraf.conf ]; then
        sudo cp /etc/telegraf/telegraf.conf /etc/telegraf/telegraf.conf.bak.$(date +%s)
        echo "  Backed up existing config"
    fi

    sudo cp "${TELEGRAF_CONF}" /etc/telegraf/telegraf.conf
    echo "  Installed telegraf.conf"

    # Deploy env file for systemd
    sudo cp "${TELEGRAF_ENV}" /etc/telegraf/telegraf.env
    sudo chmod 600 /etc/telegraf/telegraf.env
    echo "  Installed telegraf.env (permissions: 600)"

    # Create systemd override to load env file
    sudo mkdir -p /etc/systemd/system/telegraf.service.d
    cat <<'OVERRIDE' | sudo tee /etc/systemd/system/telegraf.service.d/env.conf
[Service]
EnvironmentFile=/etc/telegraf/telegraf.env
OVERRIDE
    echo "  Created systemd env override"
}

# ---- Set capabilities for privileged ports ----
set_capabilities() {
    echo "Setting capabilities for privileged ports (162, 6514)..."
    TELEGRAF_BIN=$(which telegraf)
    sudo setcap cap_net_bind_service=+ep "${TELEGRAF_BIN}" 2>/dev/null || {
        echo "  WARNING: Could not set capabilities. SNMP trap port 162 may not bind."
        echo "  Run manually: sudo setcap cap_net_bind_service=+ep ${TELEGRAF_BIN}"
    }
}

# ---- Start service ----
start_service() {
    echo "Starting Telegraf service..."
    sudo systemctl daemon-reload
    sudo systemctl enable telegraf
    sudo systemctl restart telegraf

    sleep 2
    if sudo systemctl is-active --quiet telegraf; then
        echo "Telegraf is running."
    else
        echo "ERROR: Telegraf failed to start. Check logs:"
        echo "  sudo journalctl -u telegraf --no-pager -n 30"
        exit 1
    fi
}

# ---- Validate config ----
validate_config() {
    echo "Validating Telegraf config..."
    telegraf --config "${TELEGRAF_CONF}" --test-wait 0 2>&1 | head -20 || {
        echo "WARNING: Config test returned warnings (service inputs don't support --test)."
        echo "This is expected for netflow/syslog/snmp_trap inputs."
    }
}

# ---- Main ----
install_telegraf
deploy_config
set_capabilities
validate_config
start_service

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Listening on:"
echo "  NetFlow  : UDP :2055"
echo "  Syslog   : TCP :6514"
echo "  SNMP Trap: UDP :162"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status telegraf       # Check status"
echo "  sudo journalctl -u telegraf -f       # Tail logs"
echo "  sudo systemctl restart telegraf      # Restart after config change"
echo ""
echo "Next steps:"
echo "  1. Run 01_setup_tables.sql in Databricks to create target tables"
echo "  2. Configure Cisco devices (see cisco/config_examples.txt)"
echo "  3. Run 02_validate_ingestion.sql to verify data is flowing"
