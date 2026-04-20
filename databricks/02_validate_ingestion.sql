-- =============================================================================
-- Cisco Telemetry Ingestion: Validation Queries
-- Run these after starting Telegraf to confirm data is flowing
-- =============================================================================

-- 1. Row counts per table
SELECT 'netflow_v9' AS table_name, COUNT(*) AS row_count FROM danny_catalog.cisco_telemetry.netflow_v9
UNION ALL
SELECT 'event_logs', COUNT(*) FROM danny_catalog.cisco_telemetry.event_logs
UNION ALL
SELECT 'snmp_traps', COUNT(*) FROM danny_catalog.cisco_telemetry.snmp_traps;

-- 2. Latest records per table (confirms freshness)
SELECT 'netflow_v9' AS table_name, MAX(ingestion_time) AS latest_record FROM danny_catalog.cisco_telemetry.netflow_v9
UNION ALL
SELECT 'event_logs', MAX(ingestion_time) FROM danny_catalog.cisco_telemetry.event_logs
UNION ALL
SELECT 'snmp_traps', MAX(ingestion_time) FROM danny_catalog.cisco_telemetry.snmp_traps;

-- 3. NetFlow: Top 10 talkers by bytes (last hour)
SELECT
  src_ip,
  dst_ip,
  protocol_name,
  COUNT(*)            AS flow_count,
  SUM(in_bytes)       AS total_bytes,
  SUM(in_packets)     AS total_packets
FROM danny_catalog.cisco_telemetry.netflow_v9
WHERE ingestion_time > current_timestamp() - INTERVAL 1 HOUR
GROUP BY src_ip, dst_ip, protocol_name
ORDER BY total_bytes DESC
LIMIT 10;

-- 4. Syslog: Recent events by severity
SELECT
  severity_name,
  hostname,
  COUNT(*) AS event_count
FROM danny_catalog.cisco_telemetry.event_logs
WHERE ingestion_time > current_timestamp() - INTERVAL 1 HOUR
GROUP BY severity_name, hostname
ORDER BY event_count DESC;

-- 5. SNMP Traps: Recent traps by type
SELECT
  trap_name,
  agent_address,
  COUNT(*) AS trap_count,
  MAX(ingestion_time) AS latest
FROM danny_catalog.cisco_telemetry.snmp_traps
WHERE ingestion_time > current_timestamp() - INTERVAL 1 HOUR
GROUP BY trap_name, agent_address
ORDER BY trap_count DESC;

-- 6. Ingestion rate (records per minute, last 30 min)
SELECT
  date_trunc('minute', ingestion_time) AS minute,
  COUNT(*) AS records
FROM danny_catalog.cisco_telemetry.netflow_v9
WHERE ingestion_time > current_timestamp() - INTERVAL 30 MINUTES
GROUP BY 1
ORDER BY 1;
