//! The canonical flow Parquet/Arrow schema — the single source of truth.
//!
//! **29 columns.** Column order here == on-disk Parquet order == the DuckDB `flow` view's
//! SELECT order. The `schema_drift` test (CI guard) asserts all three agree. Any column
//! change MUST bump [`FLOW_PARQUET_VERSION`] and update the SQL view + `flow_columns_in_order`.
//!
//! This module is FULLY IMPLEMENTED (it is contract, not algorithm).

use std::sync::Arc;

use arrow_schema::{DataType, Field, Schema, TimeUnit};

/// On-disk flow schema version, written to the Parquet footer KV metadata
/// (`ppcap.flow_schema_version`) for forward-compatibility and external tooling. In Phase 0
/// the only flow reader is external DuckDB (`read_parquet` in `sql/schema.sql`), which does
/// not inspect this value; there is no in-engine reader that enforces it. Bump it whenever a
/// column is added/removed/reordered.
pub const FLOW_PARQUET_VERSION: u16 = 8;

/// Canonical Arrow schema for the persisted flow Parquet table.
pub fn flow_arrow_schema() -> Arc<Schema> {
    let utc = || DataType::Timestamp(TimeUnit::Nanosecond, Some("UTC".into()));
    Arc::new(Schema::new(vec![
        Field::new("flow_id", DataType::UInt64, false), // 1  monotonic id (assigned at write)
        Field::new("capture_id", DataType::UInt64, false), // 2
        Field::new("src_ip", DataType::Utf8, false), // 3  initiator (= lo endpoint), canonical string
        Field::new("dst_ip", DataType::Utf8, false), // 4  responder (= hi endpoint)
        Field::new("src_port", DataType::UInt16, false), // 5  lo_port; 0 for portless L4
        Field::new("dst_port", DataType::UInt16, false), // 6  hi_port; 0 for portless L4
        Field::new("proto", DataType::UInt8, false), // 7  IANA L4 proto (6/17/1/58/132...)
        Field::new("app_proto", DataType::Utf8, true), // 8  "dns"/"https"/...; NULL if unknown
        Field::new("bytes_c2s", DataType::UInt64, false), // 9  == bytes_fwd (lo->hi)
        Field::new("bytes_s2c", DataType::UInt64, false), // 10 == bytes_rev (hi->lo)
        Field::new("pkts", DataType::UInt64, false), // 11 pkts_fwd + pkts_rev
        Field::new("start_ts", utc(), false),        // 12 first_ts_ns (UTC ns)
        Field::new("end_ts", utc(), false),          // 13 last_ts_ns  (UTC ns)
        Field::new("tcp_flags_c2s", DataType::UInt8, false), // 14 tcp_flags_fwd
        Field::new("tcp_flags_s2c", DataType::UInt8, false), // 15 tcp_flags_rev
        Field::new("ttl_min_c2s", DataType::UInt8, false), // 16 ttl_min_fwd
        Field::new("category", DataType::Utf8, false), // 17 snake_case token; never NULL ("unknown")
        Field::new("app_proto_src", DataType::Utf8, true), // 18 derivation: "port"/"payload"; NULL when neither
        Field::new("sni", DataType::Utf8, true),           // 19 TLS SNI host; NULL if none observed
        Field::new("ja3", DataType::Utf8, true), // 20 TLS JA3 fingerprint; NULL if none observed
        Field::new("ja4", DataType::Utf8, true), // 21 TLS JA4 fingerprint; NULL if none observed
        Field::new("tls_version", DataType::Utf8, true), // 22 negotiated TLS version label; NULL if none
        Field::new("tls_cipher", DataType::Utf8, true), // 23 negotiated cipher-suite label; NULL if none
        Field::new("hassh", DataType::Utf8, true), // 24 SSH client HASSH (MD5) fingerprint; NULL if none
        Field::new("hassh_server", DataType::Utf8, true), // 25 SSH server HASSHServer (MD5); NULL if none
        Field::new("ja3s", DataType::Utf8, true), // 26 TLS JA3S server fingerprint (MD5); NULL if none
        Field::new("severity", DataType::Utf8, false),  // 27 lowercase token, never NULL ("info")
        Field::new("threat_score", DataType::UInt16, false), // 28 0..=100
        Field::new("ioc", DataType::Boolean, false),    // 29 any feed match on this flow
    ]))
}

/// CI drift guard: exact column names in canonical order.
pub fn flow_columns_in_order() -> [&'static str; 29] {
    [
        "flow_id",
        "capture_id",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "proto",
        "app_proto",
        "bytes_c2s",
        "bytes_s2c",
        "pkts",
        "start_ts",
        "end_ts",
        "tcp_flags_c2s",
        "tcp_flags_s2c",
        "ttl_min_c2s",
        "category",
        "app_proto_src",
        "sni",
        "ja3",
        "ja4",
        "tls_version",
        "tls_cipher",
        "hassh",
        "hassh_server",
        "ja3s",
        "severity",
        "threat_score",
        "ioc",
    ]
}
