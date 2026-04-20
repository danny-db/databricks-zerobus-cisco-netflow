-- =============================================================================
-- NetFlow to OCSF Transformation
-- Transforms raw NetFlow v9 data into OCSF Network Activity (class_uid: 4001)
-- compliant records for security data lake integration.
--
-- OCSF Reference: https://schema.ocsf.io/1.3.0/classes/network_activity
-- =============================================================================

-- =============================================================================
-- Step 1: Create OCSF-compliant Delta table with nested structs
-- =============================================================================
CREATE TABLE IF NOT EXISTS danny_catalog.cisco_telemetry.netflow_ocsf (
  -- OCSF Base Event fields
  activity_id       INT           COMMENT 'OCSF activity: 6 = Traffic',
  activity_name     STRING        COMMENT 'Activity label',
  category_uid      INT           COMMENT 'OCSF category: 4 = Network Activity',
  category_name     STRING        COMMENT 'Category label',
  class_uid         INT           COMMENT 'OCSF class: 4001 = Network Activity',
  class_name        STRING        COMMENT 'Class label',
  type_uid          BIGINT        COMMENT 'Calculated: class_uid * 100 + activity_id',
  severity_id       INT           COMMENT 'OCSF severity: 1 = Informational',
  severity          STRING        COMMENT 'Severity label',
  status_id         INT           COMMENT 'OCSF status: 1 = Success',
  status            STRING        COMMENT 'Status label',
  time              BIGINT        COMMENT 'Event time (epoch ms)',
  duration          BIGINT        COMMENT 'Flow duration in milliseconds',

  -- OCSF Network Endpoint objects
  src_endpoint      STRUCT<
    ip: STRING,
    port: INT,
    autonomous_system: STRUCT<number: INT>
  >                               COMMENT 'Source endpoint (OCSF Network Endpoint)',

  dst_endpoint      STRUCT<
    ip: STRING,
    port: INT,
    autonomous_system: STRUCT<number: INT>
  >                               COMMENT 'Destination endpoint (OCSF Network Endpoint)',

  -- OCSF Network Connection Info
  connection_info   STRUCT<
    protocol_num: INT,
    protocol_name: STRING,
    direction_id: INT,
    direction: STRING,
    tcp_flags: INT
  >                               COMMENT 'Connection details (OCSF Network Connection Info)',

  -- OCSF Network Traffic
  traffic           STRUCT<
    bytes_in: BIGINT,
    packets_in: BIGINT
  >                               COMMENT 'Traffic metrics (OCSF Network Traffic)',

  -- OCSF Metadata
  metadata          STRUCT<
    version: STRING,
    logged_time: BIGINT,
    product: STRUCT<
      name: STRING,
      vendor_name: STRING,
      feature: STRUCT<name: STRING>
    >
  >                               COMMENT 'Event metadata (OCSF Metadata)',

  -- Reference back to raw data
  raw_data          STRING        COMMENT 'Original NetFlow record as JSON'
)
USING DELTA
COMMENT 'OCSF Network Activity (4001) events transformed from Cisco NetFlow v9'
TBLPROPERTIES (
  'delta.autoOptimize.optimizeWrite' = 'true',
  'delta.autoOptimize.autoCompact' = 'true'
);

-- =============================================================================
-- Step 2: Transform and insert NetFlow data into OCSF format
-- =============================================================================
INSERT INTO danny_catalog.cisco_telemetry.netflow_ocsf
SELECT
  -- OCSF Base Event (constants for NetFlow traffic)
  6                                             AS activity_id,
  'Traffic'                                     AS activity_name,
  4                                             AS category_uid,
  'Network Activity'                            AS category_name,
  4001                                          AS class_uid,
  'Network Activity'                            AS class_name,
  CAST(400106 AS BIGINT)                        AS type_uid,
  1                                             AS severity_id,
  'Informational'                               AS severity,
  1                                             AS status_id,
  'Success'                                     AS status,

  -- Time: use ingestion_time as epoch ms, fallback to current
  COALESCE(
    CAST(unix_millis(ingestion_time) AS BIGINT),
    CAST(unix_millis(current_timestamp()) AS BIGINT)
  )                                             AS time,

  -- Duration
  flow_duration_ms                              AS duration,

  -- Source Endpoint
  named_struct(
    'ip', src_ip,
    'port', src_port,
    'autonomous_system', named_struct('number', src_as)
  )                                             AS src_endpoint,

  -- Destination Endpoint
  named_struct(
    'ip', dst_ip,
    'port', dst_port,
    'autonomous_system', named_struct('number', dst_as)
  )                                             AS dst_endpoint,

  -- Connection Info
  named_struct(
    'protocol_num', protocol,
    'protocol_name', LOWER(protocol_name),
    'direction_id', CASE
      WHEN src_ip LIKE '10.%' OR src_ip LIKE '172.16.%' OR src_ip LIKE '192.168.%'
      THEN 2  -- Outbound (internal src)
      WHEN dst_ip LIKE '10.%' OR dst_ip LIKE '172.16.%' OR dst_ip LIKE '192.168.%'
      THEN 1  -- Inbound (internal dst)
      ELSE 0  -- Unknown
    END,
    'direction', CASE
      WHEN src_ip LIKE '10.%' OR src_ip LIKE '172.16.%' OR src_ip LIKE '192.168.%'
      THEN 'Outbound'
      WHEN dst_ip LIKE '10.%' OR dst_ip LIKE '172.16.%' OR dst_ip LIKE '192.168.%'
      THEN 'Inbound'
      ELSE 'Unknown'
    END,
    'tcp_flags', tcp_flags
  )                                             AS connection_info,

  -- Traffic
  named_struct(
    'bytes_in', in_bytes,
    'packets_in', in_packets
  )                                             AS traffic,

  -- Metadata
  named_struct(
    'version', '1.3.0',
    'logged_time', COALESCE(
      CAST(unix_millis(ingestion_time) AS BIGINT),
      CAST(unix_millis(current_timestamp()) AS BIGINT)
    ),
    'product', named_struct(
      'name', 'Cisco NetFlow',
      'vendor_name', 'Cisco',
      'feature', named_struct('name', 'Flexible NetFlow')
    )
  )                                             AS metadata,

  -- Raw data reference
  to_json(named_struct(
    'src_ip', src_ip,
    'dst_ip', dst_ip,
    'src_port', src_port,
    'dst_port', dst_port,
    'protocol', protocol,
    'protocol_name', protocol_name,
    'in_bytes', in_bytes,
    'in_packets', in_packets,
    'tcp_flags', tcp_flags,
    'tos', tos,
    'agent_host', agent_host,
    'host', host
  ))                                            AS raw_data

FROM danny_catalog.cisco_telemetry.netflow_v9;

-- =============================================================================
-- Step 3: Validate the transformation
-- =============================================================================

-- Row count comparison
SELECT
  'netflow_v9 (source)' AS table_name,
  COUNT(*) AS row_count
FROM danny_catalog.cisco_telemetry.netflow_v9
UNION ALL
SELECT
  'netflow_ocsf (target)',
  COUNT(*)
FROM danny_catalog.cisco_telemetry.netflow_ocsf;

-- Sample OCSF records with struct field access
SELECT
  time,
  src_endpoint.ip AS src_ip,
  src_endpoint.port AS src_port,
  dst_endpoint.ip AS dst_ip,
  dst_endpoint.port AS dst_port,
  connection_info.protocol_name AS protocol,
  connection_info.direction AS direction,
  traffic.bytes_in,
  traffic.packets_in,
  metadata.product.vendor_name AS vendor
FROM danny_catalog.cisco_telemetry.netflow_ocsf
ORDER BY traffic.bytes_in DESC
LIMIT 10;

-- Direction breakdown
SELECT
  connection_info.direction AS direction,
  COUNT(*) AS flow_count,
  SUM(traffic.bytes_in) AS total_bytes,
  SUM(traffic.packets_in) AS total_packets
FROM danny_catalog.cisco_telemetry.netflow_ocsf
GROUP BY connection_info.direction
ORDER BY total_bytes DESC;
