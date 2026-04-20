# Cisco Telemetry → Telegraf → Zerobus → Databricks

Ingest Cisco network telemetry (NetFlow, Syslog, SNMP Traps) into Databricks Unity Catalog using Telegraf, a Python relay, and the Zerobus SDK.

## Architecture

```
Cisco Devices              Telegraf              Relay               Databricks
┌──────────────┐      ┌──────────────┐     ┌──────────────┐     ┌──────────────────────┐
│ NetFlow v5/v9│─UDP─▶│inputs.netflow│     │              │     │ danny_catalog.        │
│ (port 2055)  │      │              │     │  zerobus     │gRPC │  cisco_telemetry.     │
├──────────────┤      ├──────────────┤HTTP │  _relay.py   │────▶│  ├─ netflow_v9        │
│ Syslog       │─TCP─▶│inputs.syslog │────▶│              │     │  ├─ event_logs        │
│ (port 6514)  │      │              │:9090│  (Zerobus    │     │  └─ snmp_traps        │
├──────────────┤      ├──────────────┤     │   SDK)       │     │                      │
│ SNMP Traps   │─UDP─▶│inputs.snmp   │     │              │     │ Unity Catalog         │
│ (port 162)   │      │  _trap       │     │              │     │ Delta Lake            │
└──────────────┘      └──────────────┘     └──────────────┘     └──────────────────────┘
```

**Why a relay?** The Zerobus REST API requires a specific OAuth2 token audience that standard HTTP clients can't mint. The relay uses the official Zerobus Python SDK which handles authentication via gRPC natively.

## Prerequisites

- **Telegraf** — `brew install telegraf` (macOS) or see [Telegraf install docs](https://docs.influxdata.com/telegraf/v1/install/)
- **Python 3.9+** with the Zerobus SDK — `pip3 install databricks-zerobus-ingest-sdk`
- **Databricks workspace** with Unity Catalog enabled
- **Service principal** with OAuth client credentials

## File Structure

```
cisco-telegraf-zerobus/
├── README.md                          # This file
├── databricks.yml                     # DAB bundle config (pipeline + targets)
├── start.sh                           # Start ingestion pipeline
├── stop.sh                            # Stop ingestion pipeline
├── start-fprobe.sh                    # Start NetFlow capture (dev/demo)
├── stop-fprobe.sh                     # Stop NetFlow capture
├── install.sh                         # Linux systemd installer (optional)
├── telegraf/
│   ├── telegraf.conf                  # Telegraf config (inputs + HTTP output to relay)
│   └── telegraf.env.example           # Databricks credentials template
├── relay/
│   └── zerobus_relay.py               # Python relay: HTTP → Zerobus SDK (gRPC)
├── databricks/
│   ├── 01_setup_tables.sql            # Create Unity Catalog tables + grants
│   ├── 02_validate_ingestion.sql      # Validation queries
│   ├── 03_netflow_to_ocsf.sql         # Batch OCSF transformation
│   ├── 04_netflow_ocsf_pipeline.py    # Lakeflow streaming OCSF pipeline
│   ├── 05_noc_soc_runbook.py          # NOC/SOC security analysis runbook
│   └── 06_lakewatch_preset_dev.py     # Lakewatch preset development notebook
├── lakewatch/
│   ├── index.yaml                     # Lakewatch preset registry
│   └── cisco/netflow/preset.yaml      # Custom NetFlow preset (to-be-tested)
├── cisco/
│   └── config_examples.txt            # IOS-XE config snippets for routers/switches
├── docs/
│   └── architecture_handdrawn.png     # Hand-drawn architecture overview
├── cisco_netflow_architecture.png     # Detailed architecture diagram
├── cisco_netflow_architecture.mmd     # Mermaid source for diagram
└── dev/
    └── netflow_generator.py           # Test NetFlow v5 packet generator
```

## Setup (One-Time)

### 1. Create tables in Databricks

Run `databricks/01_setup_tables.sql` in a Databricks SQL editor or notebook. This creates:

- `danny_catalog.cisco_telemetry.netflow_v9`
- `danny_catalog.cisco_telemetry.event_logs`
- `danny_catalog.cisco_telemetry.snmp_traps`

It also grants the service principal `SELECT` and `MODIFY` on all three tables.

### 2. Configure credentials

Edit `telegraf/telegraf.env` with your Databricks workspace details:

```bash
DATABRICKS_WORKSPACE_ID=1444828305810485
DATABRICKS_REGION=us-west-2
DATABRICKS_SP_CLIENT_ID=<your-service-principal-client-id>
DATABRICKS_SP_CLIENT_SECRET=<your-service-principal-client-secret>
DATABRICKS_WORKSPACE_URL=https://e2-demo-field-eng.cloud.databricks.com
```

### 3. Install dependencies

```bash
# Telegraf
brew install telegraf          # macOS
# or: sudo apt-get install telegraf   # Ubuntu/Debian

# Zerobus SDK (requires Rust toolchain for source build)
pip3 install databricks-zerobus-ingest-sdk
```

**Note:** If `index.crates.io` is blocked by your VPN/firewall, configure Cargo to use the GitHub mirror:

```bash
mkdir -p ~/.cargo
cat > ~/.cargo/config.toml << 'EOF'
[net]
git-fetch-with-cli = true

[source.crates-io]
registry = "https://github.com/rust-lang/crates.io-index"
EOF
```

### 4. Configure Cisco devices (production)

Apply the IOS-XE snippets from `cisco/config_examples.txt`, replacing `<TELEGRAF_IP>` with your collector's IP.

---

## Start the Pipeline

All commands assume you are in the project directory:

```bash
cd ~/Dev/cisco-telegraf-zerobus
```

### Step 1: Start the Zerobus relay

```bash
PYTHONUNBUFFERED=1 python3 relay/zerobus_relay.py &
```

You should see:
```
Relay listening on http://127.0.0.1:9090
Waiting for Telegraf metrics...
```

### Step 2: Start Telegraf

```bash
set -a && source telegraf/telegraf.env && set +a
telegraf --config telegraf/telegraf.conf &
```

You should see:
```
[inputs.netflow] Listening on udp://[::]:2055
[inputs.syslog] Listening on tcp://[::]:6514
[inputs.snmp_trap] Listening on udp://:162
```

### Step 3: Start a NetFlow source

**Option A — Real traffic with fprobe (recommended for demos):**

```bash
brew install fprobe   # one-time
sudo fprobe -i en0 127.0.0.1:2055        # Wi-Fi traffic
# or
sudo fprobe -i utun4 127.0.0.1:2055      # VPN traffic (check ifconfig for interface)
```

**Option B — Cisco devices (production):**

Configure Flexible NetFlow on your routers to export to `<telegraf-ip>:2055`. See `cisco/config_examples.txt`.

### Step 4: Verify data in Databricks

Wait ~30 seconds for Zerobus to materialize records, then run:

```sql
SELECT COUNT(*) FROM danny_catalog.cisco_telemetry.netflow_v9;

-- Top talkers
SELECT src_ip, dst_ip, dst_port, protocol_name, SUM(in_bytes) as total_bytes
FROM danny_catalog.cisco_telemetry.netflow_v9
GROUP BY src_ip, dst_ip, dst_port, protocol_name
ORDER BY total_bytes DESC
LIMIT 10;
```

Or run `databricks/02_validate_ingestion.sql` for a full set of validation queries.

---

## OCSF Transformation Pipeline (Lakeflow)

A Lakeflow Declarative Pipeline continuously transforms raw NetFlow data into OCSF (Open Cybersecurity Schema Framework) Network Activity events.

### Deploy with Databricks Asset Bundles (DAB)

```bash
cd ~/Dev/cisco-telegraf-zerobus

# Validate the bundle
databricks bundle validate

# Deploy to dev (development mode, triggered)
databricks bundle deploy -t dev

# Deploy to prod (continuous, production mode)
databricks bundle deploy -t prod
```

### Start / Stop the Pipeline

```bash
# Start
databricks bundle run netflow_to_ocsf -t prod

# Or via API
databricks api post /api/2.0/pipelines/<pipeline-id>/updates --json '{"full_refresh": false}'

# Stop
databricks api post /api/2.0/pipelines/<pipeline-id>/stop
```

### Targets

| Target | Mode | Continuous | Use Case |
|--------|------|------------|----------|
| `dev` | Development | No (triggered) | Testing, iteration |
| `prod` | Production | Yes (continuous) | Real-time OCSF transformation |

### OCSF Output Table

Query the OCSF streaming table:

```sql
SELECT
  src_endpoint.ip AS src_ip,
  dst_endpoint.ip AS dst_ip,
  dst_endpoint.port AS dst_port,
  connection_info.protocol_name AS protocol,
  connection_info.direction AS direction,
  traffic.bytes_in,
  traffic.packets_in,
  metadata.product.vendor_name AS vendor
FROM danny_catalog.cisco_telemetry.netflow_ocsf_stream
ORDER BY traffic.bytes_in DESC
LIMIT 10;
```

### Notes

- **"Refresh all" in the UI** means all tables are refreshed — streaming tables still process **incrementally** from checkpoints, not from scratch
- After stop/restart, the pipeline resumes from its last checkpoint — no data loss or reprocessing
- The batch SQL version (`databricks/03_netflow_to_ocsf.sql`) is also available for one-off transforms

---

## Lakewatch SIEM Integration (To-Be-Tested)

A custom Lakewatch preset (`lakewatch/cisco/netflow/preset.yaml`) has been developed to ingest NetFlow data into Lakewatch's SIEM platform as OCSF Network Activity events. This enables:

- Lakewatch detection rules operating on NetFlow data
- Native SIEM alerting for lateral movement, exfiltration, and C2 beaconing
- Integration with Lakewatch investigation workflows

**Status:** To-be-tested. The preset YAML and development notebook (`06_lakewatch_preset_dev.py`) are ready but require a Lakewatch-enabled workspace to validate end-to-end. The preset can coexist with the SDP pipeline — they serve different purposes (SDP for analytics/ML, Lakewatch for SOC operations).

To deploy once Lakewatch is available:
1. Copy `lakewatch/` directory to a workspace path
2. Configure Lakewatch to point at the custom presets directory
3. Run `databricks/06_lakewatch_preset_dev.py` to validate with the PreviewEngine

---

## Stop the Pipeline

Stop components in reverse order:

### Step 1: Stop the NetFlow source

```bash
# fprobe
sudo pkill fprobe

# Or if using softflowd
sudo pkill softflowd
```

### Step 2: Stop Telegraf

```bash
pkill -f "telegraf --config"
```

### Step 3: Stop the Zerobus relay

```bash
pkill -f "zerobus_relay.py"
```

### Stop everything at once

```bash
sudo pkill fprobe; pkill -f "telegraf --config"; pkill -f "zerobus_relay.py"
```

---

## Restart the Pipeline

```bash
cd ~/Dev/cisco-telegraf-zerobus

# 1. Relay
PYTHONUNBUFFERED=1 python3 relay/zerobus_relay.py &
sleep 3

# 2. Telegraf
set -a && source telegraf/telegraf.env && set +a
telegraf --config telegraf/telegraf.conf &
sleep 2

# 3. NetFlow source
sudo fprobe -i utun4 127.0.0.1:2055
```

---

## Ports

| Service       | Protocol | Port | Direction |
|---------------|----------|------|-----------|
| NetFlow v5/v9 | UDP      | 2055 | Inbound   |
| Syslog        | TCP      | 6514 | Inbound   |
| SNMP Traps    | UDP      | 162  | Inbound   |
| Relay (local) | TCP      | 9090 | Local     |
| Zerobus gRPC  | TCP      | 443  | Outbound  |

## Troubleshooting

### Check process status

```bash
ps aux | grep -E "telegraf|zerobus_relay|fprobe" | grep -v grep
```

### Check Telegraf is receiving flows

```bash
# Run with debug logging
set -a && source telegraf/telegraf.env && set +a
telegraf --config telegraf/telegraf.conf --debug
```

Look for `[inputs.netflow] received X bytes` lines.

### Check relay is forwarding

The relay prints stats every 30 seconds:
```
[stats] received=448 sent=448 errors=0
```

If `errors > 0`, check the relay output for `[error]` lines.

### Enable file debug output

Uncomment the `[[outputs.file]]` block in `telegraf/telegraf.conf` to write all metrics to `/tmp/telegraf_debug.json`:

```bash
tail -f /tmp/telegraf_debug.json
```

### fprobe not sending flows

- Check the correct network interface: `ifconfig` and look for `status: active` with an IP
- On VPN, use the tunnel interface (e.g., `utun4`) not `en0`
- fprobe exports flows after its inactive timeout (~60 seconds) — generate some traffic and wait

### Template errors with NetFlow v9

If Telegraf logs `Error template not found`, the source device hasn't sent a template yet. NetFlow v9 requires templates before data can be decoded. Either:
- Restart the NetFlow source so it re-sends templates
- Use NetFlow v5 (fprobe default) which doesn't need templates
