# Databricks notebook source
# MAGIC %md
# MAGIC # Lakewatch Preset Development: Cisco NetFlow v9
# MAGIC
# MAGIC Tests the custom Lakewatch preset for Cisco NetFlow data using the
# MAGIC Notebook Preset Development Tool (PreviewEngine).
# MAGIC
# MAGIC **Preset:** `cisco_netflow`
# MAGIC **Source:** `danny_catalog.cisco_telemetry.netflow_v9`
# MAGIC **Target OCSF Class:** Network Activity (4001)
# MAGIC
# MAGIC **Reference:** https://docs.lakewatch.com/ingest-data/presets/preset-development/notebook-preset-development-tool

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 1: Load the preset YAML

# COMMAND ----------

preset_yaml = """
metadata:
  name: cisco_netflow
  author: danny.wong@databricks.com
  title: Cisco NetFlow v9
  description: Transforms Cisco NetFlow v9 records into OCSF Network Activity events

primaryKey:
  timeColumn: ingestion_time
  additionalColumns:
    - src_ip
    - dst_ip
    - src_port
    - dst_port
    - protocol

bronze:
  loadAsSingleVariant: false
  preTransform:
    - - "data"
      - "CAST(ingestion_time AS TIMESTAMP) AS ingestion_time"
      - "CAST(src_ip AS STRING) AS src_ip"
      - "CAST(dst_ip AS STRING) AS dst_ip"
      - "CAST(src_port AS INT) AS src_port"
      - "CAST(dst_port AS INT) AS dst_port"
      - "CAST(protocol AS INT) AS protocol_num"
      - "CAST(protocol_name AS STRING) AS protocol_name"
      - "CAST(in_bytes AS BIGINT) AS in_bytes"
      - "CAST(in_packets AS BIGINT) AS in_packets"
      - "CAST(tcp_flags AS INT) AS tcp_flags"
      - "CAST(tos AS INT) AS tos"
      - "CAST(flow_duration_ms AS BIGINT) AS flow_duration_ms"
      - "CAST(src_as AS INT) AS src_as"
      - "CAST(dst_as AS INT) AS dst_as"
      - "CAST(agent_host AS STRING) AS agent_host"
      - "CAST(host AS STRING) AS collector_host"

silver:
  transform:
    - input: cisco_netflow
      output: netflow_normalized
      fields:
        - name: src_ip
          from: src_ip
        - name: dst_ip
          from: dst_ip
        - name: src_port
          from: src_port
        - name: dst_port
          from: dst_port
        - name: protocol_num
          from: protocol_num
        - name: protocol_name
          expr: "LOWER(protocol_name)"
        - name: in_bytes
          from: in_bytes
        - name: in_packets
          from: in_packets
        - name: tcp_flags
          from: tcp_flags
        - name: tos
          from: tos
        - name: flow_duration_ms
          from: flow_duration_ms
        - name: src_as
          from: src_as
        - name: dst_as
          from: dst_as
        - name: agent_host
          from: agent_host
        - name: collector_host
          from: collector_host
        - name: ingestion_time
          from: ingestion_time
        - name: direction_id
          expr: "CASE WHEN src_ip LIKE '10.%' OR src_ip LIKE '172.16.%' OR src_ip LIKE '192.168.%' THEN 2 WHEN dst_ip LIKE '10.%' OR dst_ip LIKE '172.16.%' OR dst_ip LIKE '192.168.%' THEN 1 ELSE 0 END"
        - name: direction
          expr: "CASE WHEN src_ip LIKE '10.%' OR src_ip LIKE '172.16.%' OR src_ip LIKE '192.168.%' THEN 'Outbound' WHEN dst_ip LIKE '10.%' OR dst_ip LIKE '172.16.%' OR dst_ip LIKE '192.168.%' THEN 'Inbound' ELSE 'Unknown' END"

gold:
  - input: netflow_normalized
    output: network_activity
    fields:
      - name: activity_id
        literal: 6
      - name: activity_name
        literal: "Traffic"
      - name: category_uid
        literal: 4
      - name: category_name
        literal: "Network Activity"
      - name: class_uid
        literal: 4001
      - name: class_name
        literal: "Network Activity"
      - name: type_uid
        literal: 400106
      - name: severity_id
        literal: 1
      - name: severity
        literal: "Informational"
      - name: status_id
        literal: 1
      - name: status
        literal: "Success"
      - name: time
        expr: "UNIX_MILLIS(ingestion_time)"
      - name: duration
        from: flow_duration_ms
      - name: src_endpoint__ip
        from: src_ip
      - name: src_endpoint__port
        from: src_port
      - name: src_endpoint__autonomous_system__number
        from: src_as
      - name: dst_endpoint__ip
        from: dst_ip
      - name: dst_endpoint__port
        from: dst_port
      - name: dst_endpoint__autonomous_system__number
        from: dst_as
      - name: connection_info__protocol_num
        from: protocol_num
      - name: connection_info__protocol_name
        from: protocol_name
      - name: connection_info__direction_id
        from: direction_id
      - name: connection_info__direction
        from: direction
      - name: connection_info__tcp_flags
        from: tcp_flags
      - name: traffic__bytes_in
        from: in_bytes
      - name: traffic__packets_in
        from: in_packets
      - name: metadata__version
        literal: "1.3.0"
      - name: metadata__logged_time
        expr: "UNIX_MILLIS(ingestion_time)"
      - name: metadata__product__name
        literal: "Cisco NetFlow"
      - name: metadata__product__vendor_name
        literal: "Cisco"
      - name: metadata__product__feature__name
        literal: "Flexible NetFlow"
      - name: raw_data
        expr: "TO_JSON(NAMED_STRUCT('src_ip', src_ip, 'dst_ip', dst_ip, 'src_port', src_port, 'dst_port', dst_port, 'protocol_num', protocol_num, 'in_bytes', in_bytes, 'in_packets', in_packets))"
"""

print("Preset YAML loaded successfully")
print(f"Length: {len(preset_yaml)} characters")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2: Preview with PreviewEngine
# MAGIC
# MAGIC If Lakewatch is installed, use the PreviewEngine to test the preset.
# MAGIC Otherwise, we simulate the transformation manually.

# COMMAND ----------

# Try importing Lakewatch PreviewEngine
try:
    from lakewatch import PreviewEngine, PreviewParameters
    LAKEWATCH_AVAILABLE = True
    print("Lakewatch PreviewEngine available")
except ImportError:
    LAKEWATCH_AVAILABLE = False
    print("Lakewatch not installed on this workspace — running manual simulation")

# COMMAND ----------

if LAKEWATCH_AVAILABLE:
    # Use Lakewatch PreviewEngine with table input
    params = PreviewParameters(
        table="danny_catalog.cisco_telemetry.netflow_v9"
    )
    engine = PreviewEngine()
    engine.evaluate(
        preset_yaml=preset_yaml,
        input_params=params
    )
else:
    print("Skipping PreviewEngine — simulating transformation manually below")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 3: Manual Simulation (Silver Layer)
# MAGIC
# MAGIC Simulate the Silver transform to verify field mapping works.

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Silver layer simulation: normalize NetFlow with direction classification
# MAGIC CREATE OR REPLACE TEMP VIEW netflow_normalized AS
# MAGIC SELECT
# MAGIC   src_ip,
# MAGIC   dst_ip,
# MAGIC   src_port,
# MAGIC   dst_port,
# MAGIC   protocol AS protocol_num,
# MAGIC   LOWER(protocol_name) AS protocol_name,
# MAGIC   in_bytes,
# MAGIC   in_packets,
# MAGIC   tcp_flags,
# MAGIC   tos,
# MAGIC   flow_duration_ms,
# MAGIC   src_as,
# MAGIC   dst_as,
# MAGIC   agent_host,
# MAGIC   host AS collector_host,
# MAGIC   ingestion_time,
# MAGIC   CASE
# MAGIC     WHEN src_ip LIKE '10.%' OR src_ip LIKE '172.16.%' OR src_ip LIKE '192.168.%' THEN 2
# MAGIC     WHEN dst_ip LIKE '10.%' OR dst_ip LIKE '172.16.%' OR dst_ip LIKE '192.168.%' THEN 1
# MAGIC     ELSE 0
# MAGIC   END AS direction_id,
# MAGIC   CASE
# MAGIC     WHEN src_ip LIKE '10.%' OR src_ip LIKE '172.16.%' OR src_ip LIKE '192.168.%' THEN 'Outbound'
# MAGIC     WHEN dst_ip LIKE '10.%' OR dst_ip LIKE '172.16.%' OR dst_ip LIKE '192.168.%' THEN 'Inbound'
# MAGIC     ELSE 'Unknown'
# MAGIC   END AS direction
# MAGIC FROM danny_catalog.cisco_telemetry.netflow_v9
# MAGIC LIMIT 1000;
# MAGIC
# MAGIC SELECT * FROM netflow_normalized LIMIT 10;

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 4: Manual Simulation (Gold Layer — OCSF Network Activity 4001)

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Gold layer simulation: OCSF Network Activity output
# MAGIC -- This matches what Lakewatch would produce as the gold table
# MAGIC SELECT
# MAGIC   -- OCSF Base Event
# MAGIC   6 AS activity_id,
# MAGIC   'Traffic' AS activity_name,
# MAGIC   4 AS category_uid,
# MAGIC   'Network Activity' AS category_name,
# MAGIC   4001 AS class_uid,
# MAGIC   'Network Activity' AS class_name,
# MAGIC   CAST(400106 AS BIGINT) AS type_uid,
# MAGIC   1 AS severity_id,
# MAGIC   'Informational' AS severity,
# MAGIC   1 AS status_id,
# MAGIC   'Success' AS status,
# MAGIC
# MAGIC   -- Time
# MAGIC   UNIX_MILLIS(ingestion_time) AS time,
# MAGIC   flow_duration_ms AS duration,
# MAGIC
# MAGIC   -- Endpoints (flattened with __ separator as Lakewatch uses)
# MAGIC   src_ip AS src_endpoint__ip,
# MAGIC   src_port AS src_endpoint__port,
# MAGIC   src_as AS src_endpoint__autonomous_system__number,
# MAGIC   dst_ip AS dst_endpoint__ip,
# MAGIC   dst_port AS dst_endpoint__port,
# MAGIC   dst_as AS dst_endpoint__autonomous_system__number,
# MAGIC
# MAGIC   -- Connection Info
# MAGIC   protocol_num AS connection_info__protocol_num,
# MAGIC   protocol_name AS connection_info__protocol_name,
# MAGIC   direction_id AS connection_info__direction_id,
# MAGIC   direction AS connection_info__direction,
# MAGIC   tcp_flags AS connection_info__tcp_flags,
# MAGIC
# MAGIC   -- Traffic
# MAGIC   in_bytes AS traffic__bytes_in,
# MAGIC   in_packets AS traffic__packets_in,
# MAGIC
# MAGIC   -- Metadata
# MAGIC   '1.3.0' AS metadata__version,
# MAGIC   UNIX_MILLIS(ingestion_time) AS metadata__logged_time,
# MAGIC   'Cisco NetFlow' AS metadata__product__name,
# MAGIC   'Cisco' AS metadata__product__vendor_name,
# MAGIC   'Flexible NetFlow' AS metadata__product__feature__name
# MAGIC
# MAGIC FROM netflow_normalized
# MAGIC ORDER BY traffic__bytes_in DESC
# MAGIC LIMIT 10;

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 5: Compare with Existing SDP Pipeline Output

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Compare: Lakewatch preset output (flat with __ separators) vs SDP output (nested structs)
# MAGIC -- Both should represent the same OCSF data, just structured differently
# MAGIC
# MAGIC SELECT
# MAGIC   'SDP Pipeline (structs)' AS approach,
# MAGIC   COUNT(*) AS row_count,
# MAGIC   SUM(traffic.bytes_in) AS total_bytes,
# MAGIC   COUNT(DISTINCT src_endpoint.ip) AS unique_sources
# MAGIC FROM danny_catalog.cisco_telemetry.netflow_ocsf_stream
# MAGIC
# MAGIC UNION ALL
# MAGIC
# MAGIC SELECT
# MAGIC   'Lakewatch Preset (simulated)' AS approach,
# MAGIC   COUNT(*) AS row_count,
# MAGIC   SUM(in_bytes) AS total_bytes,
# MAGIC   COUNT(DISTINCT src_ip) AS unique_sources
# MAGIC FROM netflow_normalized;

# COMMAND ----------

# MAGIC %md
# MAGIC ## Key Differences: SDP Pipeline vs Lakewatch Preset
# MAGIC
# MAGIC | Aspect | SDP Pipeline | Lakewatch Preset |
# MAGIC |--------|-------------|------------------|
# MAGIC | **Output schema** | Nested STRUCTs (`src_endpoint.ip`) | Flat with `__` separators (`src_endpoint__ip`) |
# MAGIC | **Table management** | User-managed streaming table | Lakewatch-managed gold table |
# MAGIC | **Detection rules** | Manual SQL | Lakewatch detection engine |
# MAGIC | **Alerting** | Databricks SQL Alerts | Lakewatch native alerts |
# MAGIC | **Investigation** | NOC/SOC notebook | Lakewatch investigation UI |
# MAGIC | **Schema evolution** | Code changes required | `loadAsSingleVariant` handles drift |
# MAGIC
# MAGIC **Recommendation:** Run both. SDP for analytics/ML, Lakewatch for SOC/SIEM operations.
