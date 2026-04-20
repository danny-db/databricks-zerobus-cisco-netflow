# Databricks notebook source
# MAGIC %md
# MAGIC # NetFlow → OCSF Lakeflow Declarative Pipeline
# MAGIC
# MAGIC Incrementally transforms raw Cisco NetFlow data into OCSF Network Activity (class_uid: 4001)
# MAGIC compliant records using Lakeflow Spark Declarative Pipelines.
# MAGIC
# MAGIC **Source:** `danny_catalog.cisco_telemetry.netflow_v9` (Zerobus ingested)
# MAGIC **Target:** `netflow_ocsf_stream` (OCSF compliant, streaming table)
# MAGIC
# MAGIC Run as **triggered** (batch incremental) or **continuous** (real-time).

# COMMAND ----------

from pyspark import pipelines as dp
from pyspark.sql.functions import (
    col, lit, struct, lower, when, current_timestamp,
    unix_millis, to_json
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Bronze: Stream raw NetFlow from Zerobus ingestion

# COMMAND ----------

@dp.table(
    comment="Raw NetFlow v9 records streamed from Zerobus ingestion"
)
def netflow_stream():
    return spark.readStream.table("danny_catalog.cisco_telemetry.netflow_v9")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Silver: Transform to OCSF Network Activity (4001)

# COMMAND ----------

# RFC 1918 private IP detection for direction classification
def _is_private_ip(ip_col):
    return (
        ip_col.startswith("10.")
        | ip_col.startswith("172.16.")
        | ip_col.startswith("172.17.")
        | ip_col.startswith("172.18.")
        | ip_col.startswith("172.19.")
        | ip_col.startswith("172.2")
        | ip_col.startswith("172.30.")
        | ip_col.startswith("172.31.")
        | ip_col.startswith("192.168.")
    )


@dp.table(
    comment="OCSF Network Activity (4001) events transformed from NetFlow"
)
def netflow_ocsf_stream():
    df = spark.readStream.table("netflow_stream")

    src_private = _is_private_ip(col("src_ip"))
    dst_private = _is_private_ip(col("dst_ip"))

    return df.select(
        # --- OCSF Base Event (constants for NetFlow traffic) ---
        lit(6).cast("int").alias("activity_id"),
        lit("Traffic").alias("activity_name"),
        lit(4).cast("int").alias("category_uid"),
        lit("Network Activity").alias("category_name"),
        lit(4001).cast("int").alias("class_uid"),
        lit("Network Activity").alias("class_name"),
        lit(400106).cast("long").alias("type_uid"),
        lit(1).cast("int").alias("severity_id"),
        lit("Informational").alias("severity"),
        lit(1).cast("int").alias("status_id"),
        lit("Success").alias("status"),

        # Time: epoch ms from ingestion_time
        when(
            col("ingestion_time").isNotNull(),
            unix_millis(col("ingestion_time"))
        ).otherwise(
            unix_millis(current_timestamp())
        ).cast("long").alias("time"),

        # Duration
        col("flow_duration_ms").cast("long").alias("duration"),

        # --- Source Endpoint ---
        struct(
            col("src_ip").alias("ip"),
            col("src_port").alias("port"),
            struct(
                col("src_as").alias("number")
            ).alias("autonomous_system"),
        ).alias("src_endpoint"),

        # --- Destination Endpoint ---
        struct(
            col("dst_ip").alias("ip"),
            col("dst_port").alias("port"),
            struct(
                col("dst_as").alias("number")
            ).alias("autonomous_system"),
        ).alias("dst_endpoint"),

        # --- Connection Info ---
        struct(
            col("protocol").alias("protocol_num"),
            lower(col("protocol_name")).alias("protocol_name"),
            when(src_private, lit(2))
                .when(dst_private, lit(1))
                .otherwise(lit(0))
                .alias("direction_id"),
            when(src_private, lit("Outbound"))
                .when(dst_private, lit("Inbound"))
                .otherwise(lit("Unknown"))
                .alias("direction"),
            col("tcp_flags"),
        ).alias("connection_info"),

        # --- Traffic ---
        struct(
            col("in_bytes").alias("bytes_in"),
            col("in_packets").alias("packets_in"),
        ).alias("traffic"),

        # --- Metadata ---
        struct(
            lit("1.3.0").alias("version"),
            when(
                col("ingestion_time").isNotNull(),
                unix_millis(col("ingestion_time"))
            ).otherwise(
                unix_millis(current_timestamp())
            ).cast("long").alias("logged_time"),
            struct(
                lit("Cisco NetFlow").alias("name"),
                lit("Cisco").alias("vendor_name"),
                struct(
                    lit("Flexible NetFlow").alias("name")
                ).alias("feature"),
            ).alias("product"),
        ).alias("metadata"),

        # --- Raw data reference ---
        to_json(
            struct(
                col("src_ip"), col("dst_ip"),
                col("src_port"), col("dst_port"),
                col("protocol"), col("protocol_name"),
                col("in_bytes"), col("in_packets"),
                col("tcp_flags"), col("tos"),
                col("agent_host"), col("host"),
            )
        ).alias("raw_data"),
    )
