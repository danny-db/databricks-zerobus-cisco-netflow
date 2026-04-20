"""
Zerobus Relay: Receives JSON metrics from Telegraf HTTP output
and forwards them to Databricks via the Zerobus Python SDK (gRPC).

Architecture:
  Telegraf (outputs.http) --> HTTP POST --> This relay --> Zerobus SDK (gRPC) --> Delta Lake

Usage:
  python3 zerobus_relay.py
"""

import json
import os
import sys
import threading
import time
import gzip
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from datetime import datetime, timezone

from zerobus.sdk.sync import ZerobusSdk
from zerobus.sdk.shared import TableProperties, StreamConfigurationOptions, RecordType

# Load env file if not already set
env_file = Path(__file__).parent.parent / "telegraf" / "telegraf.env"
if env_file.exists():
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                os.environ.setdefault(key.strip(), val.strip())

# Configuration
WORKSPACE_ID = os.environ["DATABRICKS_WORKSPACE_ID"]
REGION = os.environ["DATABRICKS_REGION"]
CLIENT_ID = os.environ["DATABRICKS_SP_CLIENT_ID"]
CLIENT_SECRET = os.environ["DATABRICKS_SP_CLIENT_SECRET"]
WORKSPACE_URL = os.environ["DATABRICKS_WORKSPACE_URL"].rstrip("/")

SERVER_ENDPOINT = f"{WORKSPACE_ID}.zerobus.{REGION}.cloud.databricks.com"
RELAY_HOST = "127.0.0.1"
RELAY_PORT = 9090

# Table mapping: telemetry_type tag -> fully qualified table name
TABLE_MAP = {
    "netflow": "danny_catalog.cisco_telemetry.netflow_v9",
    "syslog": "danny_catalog.cisco_telemetry.event_logs",
    "snmp_trap": "danny_catalog.cisco_telemetry.snmp_traps",
}


class ZerobusStreamManager:
    """Manages Zerobus SDK JSON streams for each table."""

    def __init__(self):
        self.sdk = ZerobusSdk(SERVER_ENDPOINT, WORKSPACE_URL)
        self.streams = {}
        self.lock = threading.Lock()
        self._stats = {"received": 0, "sent": 0, "errors": 0}

    def get_or_create_stream(self, table_name):
        with self.lock:
            if table_name not in self.streams:
                print(f"  [stream] Creating gRPC stream for {table_name}...")
                table_props = TableProperties(table_name)
                options = StreamConfigurationOptions(record_type=RecordType.JSON)
                stream = self.sdk.create_stream(
                    client_id=CLIENT_ID,
                    client_secret=CLIENT_SECRET,
                    table_properties=table_props,
                    options=options,
                )
                self.streams[table_name] = stream
                print(f"  [stream] Ready: {table_name}")
            return self.streams[table_name]

    def ingest(self, table_name, records):
        with self.lock:
            self._stats["received"] += len(records)
        try:
            stream = self.get_or_create_stream(table_name)
            # Ingest each record as a JSON string
            for record in records:
                stream.ingest_record(json.dumps(record))
            with self.lock:
                self._stats["sent"] += len(records)
            return True
        except Exception as e:
            print(f"  [error] {table_name}: {e}")
            with self.lock:
                self._stats["errors"] += len(records)
                # Remove broken stream so it gets recreated on next attempt
                self.streams.pop(table_name, None)
            return False

    @property
    def stats(self):
        with self.lock:
            return dict(self._stats)

    def close(self):
        with self.lock:
            for name, stream in self.streams.items():
                try:
                    stream.close()
                    print(f"  [stream] Closed: {name}")
                except Exception:
                    pass
            self.streams.clear()


PROTOCOL_MAP = {
    "tcp": 6, "udp": 17, "icmp": 1, "igmp": 2, "gre": 47, "esp": 50,
}


def epoch_us_now():
    """Return current time as epoch microseconds (Delta TIMESTAMP format)."""
    return int(time.time() * 1_000_000)


def transform_netflow(metric):
    """Transform Telegraf netflow metric to table schema."""
    fields = metric.get("fields", {})
    tags = metric.get("tags", {})
    proto_name = fields.get("protocol", "")
    return {
        "src_ip": str(fields.get("src", "")),
        "dst_ip": str(fields.get("dst", "")),
        "src_port": int(fields["src_port"]) if "src_port" in fields else None,
        "dst_port": int(fields["dst_port"]) if "dst_port" in fields else None,
        "protocol": PROTOCOL_MAP.get(proto_name.lower(), fields.get("protocol_number")),
        "protocol_name": str(proto_name),
        "in_bytes": int(fields["in_bytes"]) if "in_bytes" in fields else None,
        "in_packets": int(fields["in_packets"]) if "in_packets" in fields else None,
        "agent_host": str(tags.get("source", "")),
        "ingestion_time": epoch_us_now(),
        "host": str(tags.get("host", "")),
    }


def transform_syslog(metric):
    """Transform Telegraf syslog metric to table schema."""
    fields = metric.get("fields", {})
    tags = metric.get("tags", {})
    return {
        "severity": int(fields["severity_code"]) if "severity_code" in fields else None,
        "severity_name": str(fields.get("severity", "")),
        "facility": int(fields["facility_code"]) if "facility_code" in fields else None,
        "facility_name": str(fields.get("facility", "")),
        "hostname": str(tags.get("hostname", fields.get("hostname", ""))),
        "app_name": str(fields.get("appname", "")),
        "proc_id": str(fields.get("procid", "")),
        "msg_id": str(fields.get("msgid", "")),
        "message": str(fields.get("message", "")),
        "ingestion_time": epoch_us_now(),
        "host": str(tags.get("host", "")),
        "source": str(tags.get("source", "")),
    }


def transform_snmp_trap(metric):
    """Transform Telegraf snmp_trap metric to table schema."""
    fields = metric.get("fields", {})
    tags = metric.get("tags", {})
    return {
        "trap_oid": str(tags.get("oid", fields.get("oid", ""))),
        "trap_name": str(tags.get("name", fields.get("name", ""))),
        "trap_type": str(tags.get("type", "")),
        "agent_address": str(tags.get("source", "")),
        "community": str(tags.get("community", "")),
        "version": str(tags.get("version", "")),
        "varbinds": json.dumps(
            {k: v for k, v in fields.items() if k != "ingestion_time"}
        ),
        "ingestion_time": epoch_us_now(),
        "host": str(tags.get("host", "")),
        "source": str(tags.get("source", "")),
    }


TRANSFORMERS = {
    "netflow": transform_netflow,
    "syslog": transform_syslog,
    "snmp_trap": transform_snmp_trap,
}

# Global stream manager
stream_manager = None


class RelayHandler(BaseHTTPRequestHandler):
    """HTTP handler that receives Telegraf batches and forwards to Zerobus."""

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        # Handle gzip if Telegraf sends compressed
        content_encoding = self.headers.get("Content-Encoding", "")
        if content_encoding == "gzip":
            body = gzip.decompress(body)

        try:
            data = json.loads(body)
            # Telegraf batch format sends {"metrics": [...]}
            if isinstance(data, dict) and "metrics" in data:
                metrics = data["metrics"]
            elif isinstance(data, list):
                metrics = data
            else:
                metrics = [data]
        except json.JSONDecodeError as e:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(f"Invalid JSON: {e}".encode())
            return

        # Group and transform records by target table
        batches = {}
        for metric in metrics:
            tags = metric.get("tags", {})
            telemetry_type = tags.get("telemetry_type", "unknown")
            table_name = TABLE_MAP.get(telemetry_type)
            transformer = TRANSFORMERS.get(telemetry_type)

            if table_name and transformer:
                record = transformer(metric)
                # Remove None values
                record = {k: v for k, v in record.items() if v is not None}
                batches.setdefault(table_name, []).append(record)

        if not batches:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK (no matching metrics)")
            return

        # Ingest each batch via Zerobus SDK
        errors = []
        for table_name, records in batches.items():
            if not stream_manager.ingest(table_name, records):
                errors.append(table_name)

        if errors:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Failed: {', '.join(errors)}".encode())
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

    def log_message(self, format, *args):
        pass


def print_stats_periodically():
    """Print ingestion stats every 30 seconds."""
    while True:
        time.sleep(30)
        stats = stream_manager.stats
        if stats["received"] > 0:
            print(
                f"  [stats] received={stats['received']} "
                f"sent={stats['sent']} errors={stats['errors']}"
            )


def main():
    global stream_manager

    print("=" * 60)
    print("Zerobus Relay: Telegraf -> Zerobus SDK (gRPC) -> Databricks")
    print("=" * 60)
    print(f"  Workspace:  {WORKSPACE_URL}")
    print(f"  Zerobus:    {SERVER_ENDPOINT}")
    print(f"  Relay:      http://{RELAY_HOST}:{RELAY_PORT}")
    print(f"  Tables:")
    for ttype, tname in TABLE_MAP.items():
        print(f"    {ttype:12s} -> {tname}")
    print("=" * 60)

    stream_manager = ZerobusStreamManager()

    # Start stats printer
    stats_thread = threading.Thread(target=print_stats_periodically, daemon=True)
    stats_thread.start()

    server = HTTPServer((RELAY_HOST, RELAY_PORT), RelayHandler)
    print(f"\nRelay listening on http://{RELAY_HOST}:{RELAY_PORT}")
    print("Waiting for Telegraf metrics...\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        stream_manager.close()
        server.server_close()
        print("Done.")


if __name__ == "__main__":
    main()
