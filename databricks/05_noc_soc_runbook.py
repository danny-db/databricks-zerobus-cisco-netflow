-- Databricks notebook source
-- DBTITLE 1,Introduction
-- MAGIC %md
-- MAGIC # 🛡️ NetFlow Security Analysis — NOC / SOC Runbook
-- MAGIC
-- MAGIC **Data Sources**
-- MAGIC | Table | Type | Description |
-- MAGIC |---|---|---|
-- MAGIC | `danny_catalog.cisco_telemetry.netflow_v9` | Managed | Raw Cisco NetFlow v9 records — flat schema, all fields directly accessible |
-- MAGIC | `danny_catalog.cisco_telemetry.netflow_ocsf_stream` | Streaming | OCSF-normalized Network Activity events (class 4001) — real-time streaming table |
-- MAGIC
-- MAGIC **Target Users:** Network Operations Center (NOC) & Security Operations Center (SOC) analysts  
-- MAGIC **Use Cases:** Proactive traffic monitoring, anomaly detection, threat hunting, capacity planning  
-- MAGIC **Sections:**
-- MAGIC 1. **Data Overview** — Table health, volume, schema inspection, OCSF mapping
-- MAGIC 2. **Network Traffic Analysis** — Bandwidth trends, top talkers, service breakdown
-- MAGIC 3. **Security Monitoring** — Port scanning, data exfiltration, DNS anomalies, statistical outliers
-- MAGIC 4. **AI-Powered Analysis** — Traffic forecasting (`ai_forecast`), threat narrative generation (`ai_query`), risk classification (`ai_classify`)

-- COMMAND ----------

-- DBTITLE 1,Section 1 - Data Overview
-- MAGIC %md
-- MAGIC ## 1️⃣ Data Overview
-- MAGIC Quick health check across all three tables — row counts, freshness, and schema inspection.

-- COMMAND ----------

-- DBTITLE 1,Table Health Check
-- Table health: row count, freshness, and earliest/latest timestamps
SELECT
  'netflow_v9' AS table_name,
  COUNT(*)     AS total_rows,
  MIN(ingestion_time) AS earliest_record,
  MAX(ingestion_time) AS latest_record,
  ROUND(SUM(in_bytes) / 1073741824.0, 2) AS total_gb
FROM danny_catalog.cisco_telemetry.netflow_v9

UNION ALL

SELECT
  'netflow_ocsf_stream',
  COUNT(*),
  TIMESTAMP_MILLIS(MIN(time)),
  TIMESTAMP_MILLIS(MAX(time)),
  ROUND(SUM(traffic.bytes_in) / 1073741824.0, 2)
FROM danny_catalog.cisco_telemetry.netflow_ocsf_stream

-- COMMAND ----------

-- DBTITLE 1,NetFlow v9 Sample Data
-- Raw NetFlow v9 — flat schema, easy to query
SELECT
  ingestion_time,
  src_ip,
  dst_ip,
  src_port,
  dst_port,
  protocol_name,
  in_bytes,
  in_packets,
  tcp_flags,
  next_hop,
  agent_host
FROM danny_catalog.cisco_telemetry.netflow_v9
ORDER BY ingestion_time DESC
LIMIT 20

-- COMMAND ----------

-- DBTITLE 1,OCSF Streaming Sample Data
-- OCSF streaming table — nested struct schema (src/dst endpoints, connection_info, traffic)
SELECT
  TIMESTAMP_MILLIS(time) AS event_time,
  activity_name,
  severity,
  status,
  src_endpoint.ip       AS src_ip,
  src_endpoint.port     AS src_port,
  dst_endpoint.ip       AS dst_ip,
  dst_endpoint.port     AS dst_port,
  connection_info.protocol_name AS protocol,
  connection_info.direction     AS direction,
  traffic.bytes_in,
  traffic.packets_in,
  metadata.product.vendor_name  AS vendor
FROM danny_catalog.cisco_telemetry.netflow_ocsf_stream
ORDER BY time DESC
LIMIT 20

-- COMMAND ----------

-- DBTITLE 1,OCSF Mapping Consistency Check
-- OCSF field distribution — verify consistent mapping in the streaming table
SELECT
  activity_name,
  category_name,
  class_name,
  severity,
  status,
  COUNT(*) AS cnt
FROM danny_catalog.cisco_telemetry.netflow_ocsf_stream
GROUP BY ALL
ORDER BY cnt DESC

-- COMMAND ----------

-- DBTITLE 1,Section 2 - Network Traffic Analysis
-- MAGIC %md
-- MAGIC ## 2️⃣ Network Traffic Analysis
-- MAGIC Bandwidth trends, protocol breakdown, top communicators, and service mapping. Using `netflow_v9` for flat-field queries and OCSF tables for direction-aware analysis.

-- COMMAND ----------

-- DBTITLE 1,Hourly Traffic Volume Trend
-- Hourly flow volume & bandwidth trend (NOC: capacity monitoring)
SELECT
  DATE_FORMAT(ingestion_time, 'yyyy-MM-dd HH:00') AS hour,
  COUNT(*)                                         AS flow_count,
  ROUND(SUM(in_bytes) / 1073741824.0, 2)           AS total_gb,
  SUM(in_packets)                                   AS total_packets,
  COUNT(DISTINCT src_ip)                            AS unique_src_ips,
  COUNT(DISTINCT dst_ip)                            AS unique_dst_ips
FROM danny_catalog.cisco_telemetry.netflow_v9
GROUP BY 1
ORDER BY 1

-- COMMAND ----------

-- DBTITLE 1,Protocol Distribution
-- Protocol distribution — TCP vs UDP vs ICMP
SELECT
  protocol_name,
  COUNT(*)                                AS flow_count,
  ROUND(SUM(in_bytes) / 1073741824.0, 2)  AS total_gb,
  SUM(in_packets)                          AS total_packets,
  ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) AS pct_of_flows
FROM danny_catalog.cisco_telemetry.netflow_v9
GROUP BY protocol_name
ORDER BY flow_count DESC

-- COMMAND ----------

-- DBTITLE 1,Top 20 Source IPs by Bandwidth
-- Top 20 source IPs by bandwidth (NOC: bandwidth hogs / SOC: exfil candidates)
SELECT
  src_ip,
  CASE WHEN src_ip LIKE '10.%' OR src_ip LIKE '192.168.%' THEN 'Internal' ELSE 'External' END AS ip_type,
  COUNT(*)                                AS flow_count,
  ROUND(SUM(in_bytes) / 1048576.0, 2)     AS total_mb,
  COUNT(DISTINCT dst_ip)                  AS unique_destinations,
  COUNT(DISTINCT dst_port)                AS unique_dst_ports
FROM danny_catalog.cisco_telemetry.netflow_v9
GROUP BY src_ip
ORDER BY total_mb DESC
LIMIT 20

-- COMMAND ----------

-- DBTITLE 1,Top 20 Destination IPs by Bandwidth
-- Top 20 destination IPs by bandwidth
SELECT
  dst_ip,
  CASE WHEN dst_ip LIKE '10.%' OR dst_ip LIKE '192.168.%' THEN 'Internal' ELSE 'External' END AS ip_type,
  COUNT(*)                                AS flow_count,
  ROUND(SUM(in_bytes) / 1048576.0, 2)     AS total_mb,
  COUNT(DISTINCT src_ip)                  AS unique_sources
FROM danny_catalog.cisco_telemetry.netflow_v9
GROUP BY dst_ip
ORDER BY total_mb DESC
LIMIT 20

-- COMMAND ----------

-- DBTITLE 1,Top Services by Destination Port
-- Top services by destination port (NOC: service mapping)
SELECT
  dst_port,
  CASE
    WHEN dst_port = 443  THEN 'HTTPS'
    WHEN dst_port = 80   THEN 'HTTP'
    WHEN dst_port = 53   THEN 'DNS'
    WHEN dst_port = 22   THEN 'SSH'
    WHEN dst_port = 853  THEN 'DNS-over-TLS'
    WHEN dst_port = 5353 THEN 'mDNS'
    WHEN dst_port = 123  THEN 'NTP'
    WHEN dst_port = 137 OR dst_port = 138 THEN 'NetBIOS'
    WHEN dst_port = 0    THEN 'ICMP/Other'
    ELSE 'Port ' || dst_port
  END AS service_name,
  protocol_name,
  COUNT(*)                                AS flow_count,
  ROUND(SUM(in_bytes) / 1048576.0, 2)     AS total_mb,
  SUM(in_packets)                          AS total_packets
FROM danny_catalog.cisco_telemetry.netflow_v9
GROUP BY dst_port, protocol_name
ORDER BY flow_count DESC
LIMIT 25

-- COMMAND ----------

-- DBTITLE 1,Traffic Direction Analysis (OCSF Streaming)
-- Traffic direction analysis using OCSF model (has direction field)
SELECT
  connection_info.direction AS direction,
  connection_info.protocol_name AS protocol,
  COUNT(*)                                          AS flow_count,
  ROUND(SUM(traffic.bytes_in) / 1073741824.0, 2)    AS total_gb,
  SUM(traffic.packets_in)                            AS total_packets,
  COUNT(DISTINCT src_endpoint.ip)                    AS unique_src_ips,
  COUNT(DISTINCT dst_endpoint.ip)                    AS unique_dst_ips
FROM danny_catalog.cisco_telemetry.netflow_ocsf_stream
GROUP BY 1, 2
ORDER BY total_gb DESC

-- COMMAND ----------

-- DBTITLE 1,Section 3 - Security Monitoring
-- MAGIC %md
-- MAGIC ## 3️⃣ Security Monitoring
-- MAGIC Proactive threat detection: port scanning, data exfiltration, DNS tunneling, and statistical volume anomalies. SOC analysts should investigate flagged IPs in downstream SIEM/SOAR tools.

-- COMMAND ----------

-- DBTITLE 1,Port Scan Detection
-- Port scan detection: IPs contacting many unique destination ports
-- Risk: Critical (>100 ports), High (>50), Medium (>20)
SELECT
  src_ip,
  CASE WHEN src_ip LIKE '10.%' OR src_ip LIKE '192.168.%' THEN 'Internal' ELSE 'External' END AS ip_type,
  COUNT(DISTINCT dst_port)                AS unique_dst_ports,
  COUNT(DISTINCT dst_ip)                  AS unique_dst_ips,
  COUNT(*)                                AS flow_count,
  ROUND(SUM(in_bytes) / 1048576.0, 2)     AS total_mb,
  CASE
    WHEN COUNT(DISTINCT dst_port) > 100 THEN '🔴 Critical'
    WHEN COUNT(DISTINCT dst_port) > 50  THEN '🟠 High'
    WHEN COUNT(DISTINCT dst_port) > 20  THEN '🟡 Medium'
    ELSE '🟢 Low'
  END AS scan_risk
FROM danny_catalog.cisco_telemetry.netflow_v9
GROUP BY src_ip
HAVING COUNT(DISTINCT dst_port) > 20
ORDER BY unique_dst_ports DESC
LIMIT 30

-- COMMAND ----------

-- DBTITLE 1,Data Exfiltration Candidates
-- Data exfiltration candidates: high outbound bandwidth from internal to external
SELECT
  src_ip,
  dst_ip,
  dst_port,
  protocol_name,
  COUNT(*)                                AS flow_count,
  ROUND(SUM(in_bytes) / 1048576.0, 2)     AS total_mb,
  SUM(in_packets)                          AS total_packets,
  ROUND(AVG(in_bytes) / 1024.0, 1)        AS avg_kb_per_flow
FROM danny_catalog.cisco_telemetry.netflow_v9
WHERE (src_ip LIKE '10.%' OR src_ip LIKE '192.168.%')
  AND NOT (dst_ip LIKE '10.%' OR dst_ip LIKE '192.168.%')
GROUP BY src_ip, dst_ip, dst_port, protocol_name
HAVING SUM(in_bytes) > 10000000  -- > 10 MB
ORDER BY total_mb DESC
LIMIT 30

-- COMMAND ----------

-- DBTITLE 1,DNS Anomaly Detection
-- DNS anomaly detection: heavy DNS users + tunneling indicators
-- Tunneling risk: avg query size > 200 bytes suggests encoded payloads
SELECT
  src_ip,
  COUNT(*)                                AS dns_queries,
  ROUND(SUM(in_bytes) / 1024.0, 1)        AS total_kb,
  ROUND(AVG(in_bytes), 0)                 AS avg_bytes_per_query,
  COUNT(DISTINCT dst_ip)                  AS unique_dns_servers,
  CASE
    WHEN COUNT(*) > 2000 THEN '🔴 High Volume'
    WHEN COUNT(*) > 500  THEN '🟠 Elevated'
    ELSE '🟢 Normal'
  END AS volume_risk,
  CASE
    WHEN AVG(in_bytes) > 200 THEN '⚠️ Possible Tunneling'
    ELSE '✅ Normal'
  END AS tunneling_risk
FROM danny_catalog.cisco_telemetry.netflow_v9
WHERE dst_port IN (53, 853, 5353)
GROUP BY src_ip
ORDER BY dns_queries DESC

-- COMMAND ----------

-- DBTITLE 1,Hourly Statistical Anomaly Detection
-- Hourly statistical anomaly detection (mean ± 2σ thresholds)
-- Flags hours where flow count or bandwidth exceeds 2 standard deviations
WITH hourly AS (
  SELECT
    DATE_FORMAT(ingestion_time, 'yyyy-MM-dd HH:00') AS hour,
    COUNT(*)                                         AS flow_count,
    ROUND(SUM(in_bytes) / 1073741824.0, 2)           AS total_gb,
    COUNT(DISTINCT src_ip)                            AS unique_src_ips,
    COUNT(DISTINCT dst_port)                          AS unique_dst_ports
  FROM danny_catalog.cisco_telemetry.netflow_v9
  GROUP BY 1
),
stats AS (
  SELECT
    AVG(flow_count)                          AS avg_flows,
    STDDEV(flow_count)                       AS stddev_flows,
    AVG(total_gb)                            AS avg_gb,
    STDDEV(total_gb)                         AS stddev_gb
  FROM hourly
)
SELECT
  h.hour,
  h.flow_count,
  h.total_gb,
  h.unique_src_ips,
  h.unique_dst_ports,
  ROUND(s.avg_flows, 0)                                    AS mean_flows,
  ROUND(s.avg_flows + 2 * s.stddev_flows, 0)               AS upper_threshold,
  CASE
    WHEN h.flow_count > s.avg_flows + 2 * s.stddev_flows THEN '🔴 Anomaly'
    WHEN h.flow_count > s.avg_flows + s.stddev_flows     THEN '🟠 Warning'
    ELSE '🟢 Normal'
  END AS flow_status,
  CASE
    WHEN h.total_gb > s.avg_gb + 2 * s.stddev_gb THEN '🔴 Anomaly'
    WHEN h.total_gb > s.avg_gb + s.stddev_gb     THEN '🟠 Warning'
    ELSE '🟢 Normal'
  END AS bytes_status
FROM hourly h CROSS JOIN stats s
ORDER BY h.hour

-- COMMAND ----------

-- DBTITLE 1,Suspicious Inbound External Sources (OCSF)
-- Suspicious external IPs: high-volume external sources contacting internal hosts
-- Cross-referencing OCSF direction field for inbound traffic analysis
SELECT
  src_endpoint.ip                             AS external_ip,
  COUNT(DISTINCT dst_endpoint.ip)             AS internal_targets,
  COUNT(DISTINCT dst_endpoint.port)           AS unique_ports_hit,
  COUNT(*)                                    AS flow_count,
  ROUND(SUM(traffic.bytes_in) / 1048576.0, 2) AS total_mb,
  SUM(traffic.packets_in)                      AS total_packets
FROM danny_catalog.cisco_telemetry.netflow_ocsf_stream
WHERE connection_info.direction = 'Inbound'
GROUP BY src_endpoint.ip
HAVING COUNT(*) > 50
ORDER BY flow_count DESC
LIMIT 20

-- COMMAND ----------

-- DBTITLE 1,Section 4 - AI-Powered Analysis
-- MAGIC %md
-- MAGIC ## 4️⃣ AI-Powered Analysis
-- MAGIC Leverage Databricks AI functions for proactive monitoring:
-- MAGIC - **`ai_forecast()`** — Predict future traffic volume to detect capacity issues before they happen
-- MAGIC - **`ai_query()`** — Generate natural-language threat narratives from raw security findings
-- MAGIC - **`ai_classify()`** — Automatically classify network conversations by risk level

-- COMMAND ----------

-- DBTITLE 1,Traffic Volume Forecast (Next 12 Hours)
-- ai_forecast: Predict flow volume for the next 12 hours
-- NOC use case: Capacity planning, proactive scaling
WITH hourly_traffic AS (
  SELECT
    DATE_TRUNC('hour', ingestion_time) AS ds,
    COUNT(*)                           AS flow_count,
    SUM(in_bytes) / 1073741824.0       AS total_gb
  FROM danny_catalog.cisco_telemetry.netflow_v9
  GROUP BY 1
)
SELECT * FROM ai_forecast(
  TABLE(hourly_traffic),
  horizon => (SELECT MAX(ds) + INTERVAL 12 HOURS FROM hourly_traffic),
  time_col => 'ds',
  value_col => ARRAY('flow_count', 'total_gb'),
  prediction_interval_width => 0.95,
  frequency => 'hour',
  parameters => '{"global_floor": 0}'
)

-- COMMAND ----------

-- DBTITLE 1,Protocol-Level Traffic Forecast
-- ai_forecast: Predict flow volume by protocol for next 12 hours
-- NOC use case: Protocol-level capacity planning
WITH protocol_hourly AS (
  SELECT
    DATE_TRUNC('hour', ingestion_time) AS ds,
    protocol_name,
    COUNT(*)                           AS flow_count
  FROM danny_catalog.cisco_telemetry.netflow_v9
  GROUP BY 1, 2
)
SELECT * FROM ai_forecast(
  TABLE(protocol_hourly),
  horizon => (SELECT MAX(ds) + INTERVAL 12 HOURS FROM protocol_hourly),
  time_col => 'ds',
  value_col => 'flow_count',
  group_col => 'protocol_name',
  prediction_interval_width => 0.90,
  frequency => 'hour',
  parameters => '{"global_floor": 0}'
)

-- COMMAND ----------

-- DBTITLE 1,AI Threat Narrative (SOC Shift Handoff)
-- ai_query: Generate a threat narrative from the top security findings
-- SOC use case: Auto-generate shift handoff summaries
WITH top_threats AS (
  SELECT
    src_ip,
    COUNT(DISTINCT dst_port) AS unique_ports,
    COUNT(DISTINCT dst_ip) AS unique_targets,
    COUNT(*) AS flows,
    ROUND(SUM(in_bytes) / 1048576.0, 1) AS total_mb,
    CASE WHEN src_ip LIKE '10.%' OR src_ip LIKE '192.168.%' THEN 'Internal' ELSE 'External' END AS ip_type
  FROM danny_catalog.cisco_telemetry.netflow_v9
  GROUP BY src_ip
  HAVING COUNT(DISTINCT dst_port) > 50 OR SUM(in_bytes) > 100000000
  ORDER BY unique_ports DESC
  LIMIT 10
),
threat_summary AS (
  SELECT CONCAT_WS('\n',
    COLLECT_LIST(
      CONCAT('IP: ', src_ip, ' (', ip_type, ') - ',
             unique_ports, ' unique ports, ',
             unique_targets, ' targets, ',
             total_mb, ' MB transferred, ',
             flows, ' flows')
    )
  ) AS findings
  FROM top_threats
)
SELECT ai_query(
  'databricks-meta-llama-3-3-70b-instruct',
  CONCAT(
    'You are a SOC analyst writing a shift handoff report. ',
    'Analyze these NetFlow findings and write a concise threat assessment. ',
    'Identify which IPs are likely benign (e.g., DNS resolvers like 8.8.8.8) vs genuinely suspicious. ',
    'Recommend specific investigation actions for the SOC team.\n\n',
    'FINDINGS:\n', findings
  ),
  modelParameters => named_struct('max_tokens', 1024, 'temperature', 0.3)
) AS soc_threat_narrative
FROM threat_summary

-- COMMAND ----------

-- DBTITLE 1,AI Risk Classification of Network Conversations
-- ai_classify: Classify top network conversations by risk level
-- SOC use case: Automated triage of network conversations
WITH top_conversations AS (
  SELECT
    src_ip,
    dst_ip,
    dst_port,
    protocol_name,
    COUNT(*) AS flow_count,
    ROUND(SUM(in_bytes) / 1048576.0, 2) AS total_mb,
    COUNT(DISTINCT dst_port) AS ports_used,
    CASE WHEN src_ip LIKE '10.%' OR src_ip LIKE '192.168.%' THEN 'Internal' ELSE 'External' END AS src_type,
    CASE WHEN dst_ip LIKE '10.%' OR dst_ip LIKE '192.168.%' THEN 'Internal' ELSE 'External' END AS dst_type
  FROM danny_catalog.cisco_telemetry.netflow_v9
  GROUP BY src_ip, dst_ip, dst_port, protocol_name
  HAVING SUM(in_bytes) > 5000000  -- > 5 MB
  ORDER BY total_mb DESC
  LIMIT 25
)
SELECT
  src_ip, dst_ip, dst_port, protocol_name,
  flow_count, total_mb, src_type, dst_type,
  ai_classify(
    CONCAT(
      src_type, ' IP ', src_ip, ' sent ', total_mb, ' MB to ',
      dst_type, ' IP ', dst_ip, ' on port ', dst_port, '/',  protocol_name,
      ' across ', flow_count, ' flows'
    ),
    ARRAY('Normal Traffic', 'High Volume - Investigate', 'Potential Data Exfiltration', 'Possible C2 Communication', 'DNS Anomaly')
  ) AS ai_risk_classification
FROM top_conversations
ORDER BY total_mb DESC

-- COMMAND ----------

-- DBTITLE 1,AI Network Security Posture Summary
-- ai_query: Comprehensive security posture summary
-- SOC/NOC use case: Executive-level security summary
WITH network_stats AS (
  SELECT
    COUNT(*) AS total_flows,
    ROUND(SUM(in_bytes) / 1073741824.0, 2) AS total_gb,
    COUNT(DISTINCT src_ip) AS unique_src_ips,
    COUNT(DISTINCT dst_ip) AS unique_dst_ips,
    COUNT(DISTINCT dst_port) AS unique_ports,
    SUM(CASE WHEN dst_port IN (53, 853, 5353) THEN 1 ELSE 0 END) AS dns_flows,
    SUM(CASE WHEN dst_port = 443 THEN 1 ELSE 0 END) AS https_flows,
    MIN(ingestion_time) AS first_seen,
    MAX(ingestion_time) AS last_seen
  FROM danny_catalog.cisco_telemetry.netflow_v9
),
port_scan_count AS (
  SELECT COUNT(*) AS scan_candidates
  FROM (
    SELECT src_ip FROM danny_catalog.cisco_telemetry.netflow_v9
    GROUP BY src_ip HAVING COUNT(DISTINCT dst_port) > 50
  )
),
high_volume_dns AS (
  SELECT COUNT(*) AS dns_heavy_hitters
  FROM (
    SELECT src_ip FROM danny_catalog.cisco_telemetry.netflow_v9
    WHERE dst_port IN (53, 853, 5353)
    GROUP BY src_ip HAVING COUNT(*) > 1000
  )
)
SELECT ai_query(
  'databricks-meta-llama-3-3-70b-instruct',
  CONCAT(
    'Generate a concise Network Security Posture Summary for a NOC/SOC team.\n\n',
    'TIME WINDOW: ', ns.first_seen, ' to ', ns.last_seen, '\n',
    'TOTAL FLOWS: ', ns.total_flows, '\n',
    'TOTAL BANDWIDTH: ', ns.total_gb, ' GB\n',
    'UNIQUE SOURCE IPs: ', ns.unique_src_ips, '\n',
    'UNIQUE DEST IPs: ', ns.unique_dst_ips, '\n',
    'UNIQUE DEST PORTS: ', ns.unique_ports, '\n',
    'HTTPS FLOWS: ', ns.https_flows, ' (', ROUND(100.0 * ns.https_flows / ns.total_flows, 1), '%)\n',
    'DNS FLOWS: ', ns.dns_flows, '\n',
    'PORT SCAN CANDIDATES (>50 ports): ', ps.scan_candidates, '\n',
    'DNS HEAVY HITTERS (>1000 queries): ', hd.dns_heavy_hitters, '\n\n',
    'Provide: 1) Overall risk assessment (Low/Medium/High), ',
    '2) Key findings, 3) Recommended actions for the SOC team, ',
    '4) Items to monitor in the next shift.'
  ),
  modelParameters => named_struct('max_tokens', 1024, 'temperature', 0.2)
) AS security_posture_summary
FROM network_stats ns
CROSS JOIN port_scan_count ps
CROSS JOIN high_volume_dns hd

-- COMMAND ----------

-- DBTITLE 1,Runbook Notes
-- MAGIC %md
-- MAGIC ---
-- MAGIC ### 📝 Runbook Notes
-- MAGIC - **Schedule**: Run this notebook daily or on-demand during incident investigation
-- MAGIC - **Alert Thresholds**: Customize port scan (`>20 ports`), exfiltration (`>10 MB`), and DNS (`>2000 queries`) thresholds to match your environment
-- MAGIC - **OCSF Alignment**: The `netflow_ocsf_stream` table follows the [OCSF Network Activity (4001)](https://schema.ocsf.io/1.0.0/classes/network_activity) schema for interoperability with other security tools
-- MAGIC - **Integration**: Feed flagged IPs into your SIEM/SOAR platform for automated response