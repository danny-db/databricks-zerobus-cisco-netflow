-- =============================================================================
-- Cisco Telemetry Ingestion: Table Setup
-- Workspace: e2-demo-field-eng
-- Catalog:   danny_catalog
-- Schema:    cisco_telemetry
-- =============================================================================

-- Create schema if not exists
CREATE SCHEMA IF NOT EXISTS danny_catalog.cisco_telemetry
COMMENT 'Cisco network telemetry ingested via Telegraf + Zerobus';

-- =============================================================================
-- Table 1: NetFlow v9 Records
-- =============================================================================
CREATE TABLE IF NOT EXISTS danny_catalog.cisco_telemetry.netflow_v9 (
  -- Flow identification
  src_ip            STRING        COMMENT 'Source IP address',
  dst_ip            STRING        COMMENT 'Destination IP address',
  src_port          INT           COMMENT 'Source port number',
  dst_port          INT           COMMENT 'Destination port number',
  protocol          INT           COMMENT 'IP protocol number (6=TCP, 17=UDP, 1=ICMP)',
  protocol_name     STRING        COMMENT 'Protocol name (TCP, UDP, ICMP, etc.)',

  -- Traffic metrics
  in_bytes          BIGINT        COMMENT 'Bytes transferred in the flow',
  in_packets        BIGINT        COMMENT 'Packets transferred in the flow',
  flow_duration_ms  BIGINT        COMMENT 'Flow duration in milliseconds',

  -- Routing
  src_as            INT           COMMENT 'Source autonomous system number',
  dst_as            INT           COMMENT 'Destination autonomous system number',
  input_snmp        INT           COMMENT 'Input interface SNMP index',
  output_snmp       INT           COMMENT 'Output interface SNMP index',
  next_hop          STRING        COMMENT 'Next hop IP address',

  -- TCP flags
  tcp_flags         INT           COMMENT 'Cumulative TCP flags for the flow',

  -- Type of Service
  tos               INT           COMMENT 'Type of Service byte value',

  -- Device info
  agent_host        STRING        COMMENT 'IP of the device exporting the flow',

  -- Timestamps
  flow_start_ms     BIGINT        COMMENT 'Flow start time (epoch ms)',
  flow_end_ms       BIGINT        COMMENT 'Flow end time (epoch ms)',
  ingestion_time    TIMESTAMP     COMMENT 'Time the record was ingested by Telegraf',

  -- Telegraf metadata
  host              STRING        COMMENT 'Telegraf collector hostname'
)
USING DELTA
COMMENT 'Cisco NetFlow v9 records ingested via Telegraf and Zerobus'
TBLPROPERTIES (
  'delta.autoOptimize.optimizeWrite' = 'true',
  'delta.autoOptimize.autoCompact' = 'true',
  'delta.deletedFileRetentionDuration' = 'interval 30 days',
  'delta.logRetentionDuration' = 'interval 90 days'
);

-- =============================================================================
-- Table 2: Event Logs (Syslog)
-- =============================================================================
CREATE TABLE IF NOT EXISTS danny_catalog.cisco_telemetry.event_logs (
  -- Syslog header
  severity          INT           COMMENT 'Syslog severity (0=Emergency .. 7=Debug)',
  severity_name     STRING        COMMENT 'Severity label (e.g., warning, error, info)',
  facility          INT           COMMENT 'Syslog facility code',
  facility_name     STRING        COMMENT 'Facility label (e.g., local0, kern)',

  -- Origin
  hostname          STRING        COMMENT 'Device hostname or IP',
  app_name          STRING        COMMENT 'Application or process name',
  proc_id           STRING        COMMENT 'Process ID',
  msg_id            STRING        COMMENT 'Message ID',

  -- Content
  message           STRING        COMMENT 'Syslog message body',
  structured_data   STRING        COMMENT 'RFC5424 structured data (JSON string)',

  -- Timestamps
  event_timestamp   TIMESTAMP     COMMENT 'Timestamp from the syslog message',
  ingestion_time    TIMESTAMP     COMMENT 'Time the record was ingested by Telegraf',

  -- Telegraf metadata
  host              STRING        COMMENT 'Telegraf collector hostname',
  source            STRING        COMMENT 'Source IP of the syslog sender'
)
USING DELTA
COMMENT 'Cisco device event logs (syslog) ingested via Telegraf and Zerobus'
TBLPROPERTIES (
  'delta.autoOptimize.optimizeWrite' = 'true',
  'delta.autoOptimize.autoCompact' = 'true',
  'delta.deletedFileRetentionDuration' = 'interval 30 days',
  'delta.logRetentionDuration' = 'interval 90 days'
);

-- =============================================================================
-- Table 3: SNMP Traps
-- =============================================================================
CREATE TABLE IF NOT EXISTS danny_catalog.cisco_telemetry.snmp_traps (
  -- Trap identification
  trap_oid          STRING        COMMENT 'SNMP trap OID',
  trap_name         STRING        COMMENT 'Resolved trap name from MIB',
  trap_type         STRING        COMMENT 'Trap type (e.g., linkDown, coldStart)',

  -- Source
  agent_address     STRING        COMMENT 'IP address of the SNMP agent',
  community         STRING        COMMENT 'SNMP community string',
  version           STRING        COMMENT 'SNMP version (v1, v2c, v3)',

  -- Variable bindings (key-value pairs from the trap)
  varbinds          STRING        COMMENT 'Variable bindings as JSON string',

  -- Timestamps
  trap_timestamp    BIGINT        COMMENT 'Sysuptime from the trap (timeticks)',
  ingestion_time    TIMESTAMP     COMMENT 'Time the record was ingested by Telegraf',

  -- Telegraf metadata
  host              STRING        COMMENT 'Telegraf collector hostname',
  source            STRING        COMMENT 'Source IP of the trap sender'
)
USING DELTA
COMMENT 'Cisco SNMP traps ingested via Telegraf and Zerobus'
TBLPROPERTIES (
  'delta.autoOptimize.optimizeWrite' = 'true',
  'delta.autoOptimize.autoCompact' = 'true',
  'delta.deletedFileRetentionDuration' = 'interval 30 days',
  'delta.logRetentionDuration' = 'interval 90 days'
);

-- =============================================================================
-- Grant service principal access
-- =============================================================================
GRANT USE CATALOG ON CATALOG danny_catalog TO `8ee47b1d-9016-453f-b660-05faa04b300f`;
GRANT USE SCHEMA ON SCHEMA danny_catalog.cisco_telemetry TO `8ee47b1d-9016-453f-b660-05faa04b300f`;
GRANT SELECT, MODIFY ON TABLE danny_catalog.cisco_telemetry.netflow_v9 TO `8ee47b1d-9016-453f-b660-05faa04b300f`;
GRANT SELECT, MODIFY ON TABLE danny_catalog.cisco_telemetry.event_logs TO `8ee47b1d-9016-453f-b660-05faa04b300f`;
GRANT SELECT, MODIFY ON TABLE danny_catalog.cisco_telemetry.snmp_traps TO `8ee47b1d-9016-453f-b660-05faa04b300f`;
