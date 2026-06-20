//! WebAssembly binding for the PacketPilot analysis engine.
//!
//! Exposes a single [`analyze`] entry that runs the *same* streaming pipeline the native
//! CLI/desktop use ([`ppcap_core::run_source_visiting`]) over an in-memory capture and returns
//! the summary plus the per-flow rows as a plain JS object — so a browser can analyze a raw
//! `.pcap`/`.pcapng` with the capture never leaving the device, no server, no filesystem.
//!
//! The flow rows mirror the engine's Parquet schema column-for-column (see
//! `ppcap-core::columnar`), so the frontend normalizes them exactly like the parquet path.

use std::io::Cursor;

use ppcap_core::{run_source_visiting, FlowRecord, PipelineConfig};
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// One analyzed flow — same fields, names, and semantics as the Parquet `flows` schema.
/// Integer timestamps are nanoseconds since the Unix epoch (the frontend divides to ms).
#[derive(Serialize)]
struct FlowDto {
    flow_id: u64,
    capture_id: u64,
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    app_proto: Option<String>,
    bytes_c2s: u64,
    bytes_s2c: u64,
    pkts: u64,
    start_ts_ns: i64,
    end_ts_ns: i64,
    tcp_flags_c2s: u8,
    tcp_flags_s2c: u8,
    ttl_min_c2s: u8,
    category: String,
    app_proto_src: Option<String>,
    sni: Option<String>,
    severity: String,
    threat_score: u16,
    ioc: bool,
}

impl FlowDto {
    /// Build a row from a finalized record, mirroring `FlowParquetWriter::write` exactly:
    /// `lo`/`hi` endpoints map to `src`/`dst`, empty strings collapse to `None`.
    fn from_record(rec: &FlowRecord, flow_id: u64) -> FlowDto {
        FlowDto {
            flow_id,
            capture_id: 0,
            src_ip: rec.key.lo_ip.to_string(),
            dst_ip: rec.key.hi_ip.to_string(),
            src_port: rec.key.lo_port,
            dst_port: rec.key.hi_port,
            proto: rec.key.transport.ip_proto(),
            app_proto: if rec.app_proto.is_empty() {
                None
            } else {
                Some(rec.app_proto.clone())
            },
            bytes_c2s: rec.bytes_fwd,
            bytes_s2c: rec.bytes_rev,
            pkts: rec.total_pkts(),
            start_ts_ns: rec.first_ts_ns,
            end_ts_ns: rec.last_ts_ns,
            tcp_flags_c2s: rec.tcp_flags_fwd,
            tcp_flags_s2c: rec.tcp_flags_rev,
            ttl_min_c2s: rec.ttl_min_fwd,
            category: rec.category.as_str().to_string(),
            app_proto_src: rec.app_proto_src.map(|s| s.to_string()),
            sni: rec
                .sni
                .as_ref()
                .filter(|h| !h.is_empty())
                .map(|h| h.to_string()),
            severity: rec.severity.as_str().to_string(),
            threat_score: rec.threat_score,
            ioc: rec.ioc,
        }
    }
}

/// The full result: the capture summary (serializes to the frontend's `AnalysisOutput`) plus
/// every flow row.
#[derive(Serialize)]
struct AnalyzeResult {
    summary: ppcap_core::AnalysisOutput,
    flows: Vec<FlowDto>,
}

/// Analyze a raw capture (`.pcap`/`.pcapng`) held entirely in memory.
///
/// `bytes` is the capture file; `name` becomes the reported `source_path`. Returns a JSON
/// string `{ summary, flows }` (the caller `JSON.parse`s it), or rejects with the engine
/// error string (e.g. an unknown container magic). The provenance hash is left for the
/// caller to fill in (cheaper via WebCrypto than shipping a second hashing pass into wasm).
#[wasm_bindgen]
pub fn analyze(bytes: &[u8], name: String) -> Result<String, JsValue> {
    let len = bytes.len() as u64;

    // Build a streaming source over the owned bytes (the reader keeps only a bounded refill
    // buffer regardless of capture size — same memory discipline as the file path).
    let source = ppcap_core::reader::open_reader(Cursor::new(bytes.to_vec()), Some(len))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let cfg = PipelineConfig::default();
    let mut flows: Vec<FlowDto> = Vec::new();
    let summary = run_source_visiting(
        source,
        &name,
        len,
        &cfg,
        &mut |rec| {
            let id = flows.len() as u64;
            flows.push(FlowDto::from_record(rec, id));
        },
        |_, _, _| {},
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = AnalyzeResult { summary, flows };
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}
