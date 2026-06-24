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

// ---------------------------------------------------------------------------
// extract_packets — on-demand per-flow packet extraction
// ---------------------------------------------------------------------------

/// JS-sent query shape: IPs as strings, transport as IANA protocol number.
#[derive(serde::Deserialize)]
struct QueryDto {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    start_ns: i64,
    end_ns: i64,
}

// ---------------------------------------------------------------------------
// carve_pcap — slice/carve a subset of frames into a new pcap
// ---------------------------------------------------------------------------

/// JS-sent carve query. `host` set → Host target; else Flow (all 5-tuple fields required).
#[derive(serde::Deserialize)]
struct CarveQueryDto {
    host: Option<String>,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    proto: Option<u8>,
    start_ns: i64,
    end_ns: i64,
}

fn carve_query_from_dto(dto: CarveQueryDto) -> Result<ppcap_core::CarveQuery, String> {
    let target = if let Some(h) = dto.host {
        let ip: std::net::IpAddr = h.parse().map_err(|_| "bad host ip".to_string())?;
        ppcap_core::CarveTarget::Host { ip }
    } else {
        let src_ip = dto
            .src_ip
            .ok_or("src_ip required for flow carve")?
            .parse::<std::net::IpAddr>()
            .map_err(|_| "bad src_ip".to_string())?;
        let dst_ip = dto
            .dst_ip
            .ok_or("dst_ip required for flow carve")?
            .parse::<std::net::IpAddr>()
            .map_err(|_| "bad dst_ip".to_string())?;
        let src_port = dto.src_port.ok_or("src_port required for flow carve")?;
        let dst_port = dto.dst_port.ok_or("dst_port required for flow carve")?;
        let proto = dto.proto.ok_or("proto required for flow carve")?;
        ppcap_core::CarveTarget::Flow {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            transport: ppcap_core::Transport::from_ip_proto(proto),
        }
    };
    Ok(ppcap_core::CarveQuery {
        target,
        start_ns: dto.start_ns,
        end_ns: dto.end_ns,
    })
}

/// Re-read `bytes` (a raw `.pcap`/`.pcapng` file) and carve out frames matching `query_json`
/// (a `CarveQueryDto`). Returns raw pcap bytes (`Uint8Array` on the JS side), or rejects with
/// an error string. The capture bytes never leave the device.
#[wasm_bindgen]
pub fn carve_pcap(bytes: &[u8], query_json: &str) -> Result<Vec<u8>, JsValue> {
    let dto: CarveQueryDto =
        serde_json::from_str(query_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let q = carve_query_from_dto(dto).map_err(|e| JsValue::from_str(&e))?;
    let len = bytes.len() as u64;
    let source = ppcap_core::reader::open_reader(Cursor::new(bytes.to_vec()), Some(len))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let res = ppcap_core::carve_pcap(source, &q, &ppcap_core::PacketCaps::default())
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(res.pcap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carve_query_dto_maps_flow_and_host() {
        let flow = carve_query_from_dto(CarveQueryDto {
            host: None,
            src_ip: Some("1.1.1.1".into()),
            dst_ip: Some("2.2.2.2".into()),
            src_port: Some(1),
            dst_port: Some(2),
            proto: Some(6),
            start_ns: 0,
            end_ns: 1,
        })
        .unwrap();
        assert!(matches!(flow.target, ppcap_core::CarveTarget::Flow { .. }));

        let host = carve_query_from_dto(CarveQueryDto {
            host: Some("9.9.9.9".into()),
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            proto: None,
            start_ns: 0,
            end_ns: 1,
        })
        .unwrap();
        assert!(matches!(host.target, ppcap_core::CarveTarget::Host { .. }));
    }

    /// Build a minimal classic pcap with a TCP/443 data packet carrying "abc" in the payload.
    ///
    /// Encodes the pcap directly as raw bytes (no ppcap-core gen helpers — those are pub(crate)).
    /// Layout: pcap global header + one legacy packet record with Ethernet/IPv4/TCP frame.
    fn crafted_tcp443_pcap_with_abc() -> Vec<u8> {
        let payload: &[u8] = b"GET abc HTTP/1.1";

        // ── TCP header (20 bytes, no options) ─────────────────────────────
        // src_port=1234, dst_port=443, seq=1, ack=0, flags=PSH|ACK(0x18), window=65535
        let tcp_len = 20 + payload.len();
        let mut tcp = vec![
            0x04, 0xD2, // src port 1234
            0x01, 0xBB, // dst port 443
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, // data offset = 5 (20 bytes), reserved = 0
            0x18, // flags: PSH | ACK
            0xFF, 0xFF, // window
            0x00, 0x00, // checksum (zero — ppcap-core doesn't verify TCP checksum)
            0x00, 0x00, // urgent pointer
        ];
        tcp.extend_from_slice(payload);

        // ── IPv4 header (20 bytes, no options) ────────────────────────────
        // src=10.0.0.1, dst=93.184.216.34, proto=6 (TCP), TTL=64
        let ip_total = 20 + tcp_len as u16;
        let mut ip: Vec<u8> = vec![
            0x45, // version=4, IHL=5
            0x00, // DSCP/ECN
        ];
        ip.extend_from_slice(&ip_total.to_be_bytes()); // total length
        ip.extend_from_slice(&[0x00, 0x00]); // identification
        ip.extend_from_slice(&[0x40, 0x00]); // flags=DF, fragment offset=0
        ip.push(64); // TTL
        ip.push(6); // protocol TCP
        ip.extend_from_slice(&[0x00, 0x00]); // checksum (not verified)
        ip.extend_from_slice(&[10, 0, 0, 1]); // src 10.0.0.1
        ip.extend_from_slice(&[93, 184, 216, 34]); // dst 93.184.216.34

        // ── Ethernet header (14 bytes) ────────────────────────────────────
        let mut eth: Vec<u8> = vec![
            0x04, 0x04, 0x04, 0x04, 0x04, 0x04, // dst MAC
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, // src MAC
            0x08, 0x00, // EtherType IPv4
        ];

        let mut frame = Vec::new();
        frame.append(&mut eth);
        frame.append(&mut ip);
        frame.append(&mut tcp);

        // ── pcap global header (24 bytes, little-endian, Ethernet DLT=1) ──
        let mut buf: Vec<u8> = vec![
            0xD4, 0xC3, 0xB2, 0xA1, // magic (little-endian)
            0x02, 0x00, 0x04, 0x00, // version 2.4
            0x00, 0x00, 0x00, 0x00, // this zone
            0x00, 0x00, 0x00, 0x00, // sigfigs
            0xFF, 0xFF, 0x00, 0x00, // snaplen 65535
            0x01, 0x00, 0x00, 0x00, // DLT_EN10MB = 1
        ];

        // ── packet record header (16 bytes) ───────────────────────────────
        let ts_sec: u32 = 1;
        let ts_usec: u32 = 0;
        let cap_len = frame.len() as u32;
        buf.extend_from_slice(&ts_sec.to_le_bytes());
        buf.extend_from_slice(&ts_usec.to_le_bytes());
        buf.extend_from_slice(&cap_len.to_le_bytes());
        buf.extend_from_slice(&cap_len.to_le_bytes());
        buf.extend_from_slice(&frame);

        buf
    }

    #[test]
    fn apply_rules_folds_matches_into_output() {
        let pcap = crafted_tcp443_pcap_with_abc();

        // Get the base AnalysisOutput by analyzing the pcap, then extract the `summary` field
        // (analyze returns AnalyzeResult { summary: AnalysisOutput, flows: [...] }).
        let analyze_json = crate::analyze(&pcap, "t.pcap".into()).unwrap();
        let analyze_val: serde_json::Value = serde_json::from_str(&analyze_json).unwrap();
        let out_json = analyze_val["summary"].to_string();

        let rules = r#"alert tcp any any -> any 443 (msg:"hit"; content:"abc"; sid:7; metadata:mitre T1071;)"#;
        let res_json = crate::apply_rules(&pcap, rules, &out_json).unwrap();
        let v: serde_json::Value = serde_json::from_str(&res_json).unwrap();

        assert_eq!(v["loaded"], 1);
        assert_eq!(v["skipped"], 0);
        assert!(
            v["matches"].as_u64().unwrap() >= 1,
            "expected at least one match"
        );

        // The finding is folded into output.summary.findings
        let findings = v["output"]["summary"]["findings"].as_array().unwrap();
        assert!(
            findings.iter().any(|f| f["title"] == "hit"),
            "folded finding with title 'hit' must be present in output.summary.findings"
        );
    }

    #[test]
    fn render_report_emits_html() {
        let pcap = crafted_tcp443_pcap_with_abc();

        // Get an AnalysisOutput JSON: analyze the pcap → AnalyzeResult, extract ["summary"].
        let analyze_json = crate::analyze(&pcap, "t.pcap".into()).unwrap();
        let analyze_val: serde_json::Value = serde_json::from_str(&analyze_json).unwrap();
        let out_json = analyze_val["summary"].to_string();

        // Without AI summary: must contain doctype and "Executive summary".
        let html = crate::render_report(&out_json, 1_700_000_000, None).unwrap();
        assert!(html.contains("<!doctype html>"));
        assert!(html.contains("Executive summary"));

        // With an AI summary, the card text appears in the output.
        let html2 = crate::render_report(
            &out_json,
            1_700_000_000,
            Some("AI says: suspicious beacon".to_string()),
        )
        .unwrap();
        assert!(html2.contains("AI says: suspicious beacon"));
    }
}

/// JS-sent extraction caps (both optional; defaults to the engine's hard limits).
#[derive(serde::Deserialize)]
struct CapsDto {
    max_packets: Option<usize>,
    payload_cap: Option<usize>,
}

/// Re-read `bytes` (a raw `.pcap`/`.pcapng` file) and return the packets for the
/// single flow described by `query_json`, bounded by `caps_json`.
///
/// Returns a JSON string matching `FlowPackets` (`{ total, truncated, packets: [...] }`),
/// or rejects with an error string. The capture bytes never leave the device.
#[wasm_bindgen]
pub fn extract_packets(bytes: &[u8], query_json: &str, caps_json: &str) -> Result<String, JsValue> {
    let q: QueryDto =
        serde_json::from_str(query_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let c: CapsDto =
        serde_json::from_str(caps_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let query = ppcap_core::PacketQuery {
        src_ip: q
            .src_ip
            .parse()
            .map_err(|_| JsValue::from_str("bad src_ip"))?,
        dst_ip: q
            .dst_ip
            .parse()
            .map_err(|_| JsValue::from_str("bad dst_ip"))?,
        src_port: q.src_port,
        dst_port: q.dst_port,
        transport: ppcap_core::Transport::from_ip_proto(q.proto),
        start_ns: q.start_ns,
        end_ns: q.end_ns,
    };
    let caps = ppcap_core::PacketCaps {
        max_packets: c
            .max_packets
            .unwrap_or(ppcap_core::packets::MAX_PACKETS_PER_FLOW),
        payload_cap: c
            .payload_cap
            .unwrap_or(ppcap_core::packets::PAYLOAD_CAP_BYTES),
    };

    let len = bytes.len() as u64;
    let source = ppcap_core::reader::open_reader(Cursor::new(bytes.to_vec()), Some(len))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let fp = ppcap_core::extract_flow_packets(source, &query, &caps)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    serde_json::to_string(&fp).map_err(|e| JsValue::from_str(&e.to_string()))
}

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
    ja3: Option<String>,
    ja4: Option<String>,
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
            ja3: rec
                .ja3
                .as_ref()
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string()),
            ja4: rec
                .ja4
                .as_ref()
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string()),
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

/// The result of applying a custom ruleset to a pcap via [`apply_rules`].
#[derive(serde::Serialize)]
struct RuleApplyResult {
    output: ppcap_core::AnalysisOutput,
    loaded: usize,
    skipped: usize,
    matches: usize,
}

/// Parse a ruleset, apply it over the pcap `bytes`, and fold the matches into `output_json`.
///
/// `output_json` is the `AnalysisOutput` (the `.summary` field from `analyze`). Returns a JSON
/// `{ output, loaded, skipped, matches }` where `output` is the updated `AnalysisOutput` with
/// rule-match findings folded in. Pure + wasm-safe — no C deps, no network.
#[wasm_bindgen]
pub fn apply_rules(bytes: &[u8], rules_text: &str, output_json: &str) -> Result<String, JsValue> {
    let mut out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let parsed = ppcap_core::parse_rules(rules_text);
    let owned = bytes.to_vec();
    let len = Some(owned.len() as u64);
    let rf = ppcap_core::apply_rules(std::io::Cursor::new(owned), len, &parsed.rules);
    ppcap_core::fold_rule_findings(&mut out.summary, &rf);
    let res = RuleApplyResult {
        matches: rf.len(),
        loaded: parsed.rules.len(),
        skipped: parsed.skipped.len(),
        output: out,
    };
    serde_json::to_string(&res).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Apply reputation verdicts to a completed analysis. `output_json` is the `AnalysisOutput` from
/// `analyze`; `verdicts_json` is `{ "<ip>": [ReputationVerdict, ...], ... }` (snake_case). Returns
/// the updated `AnalysisOutput` as JSON. Pure + network-free — identical scoring to native callers.
#[wasm_bindgen]
pub fn apply_reputation(output_json: &str, verdicts_json: &str) -> Result<String, JsValue> {
    use std::collections::BTreeMap;
    let mut out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let verdicts: BTreeMap<String, Vec<ppcap_core::ReputationVerdict>> =
        serde_json::from_str(verdicts_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    ppcap_core::apply_reputation(&mut out.summary, &verdicts);
    serde_json::to_string(&out).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Apply VirusTotal domain reputation verdicts to a completed analysis. `output_json` is the
/// `AnalysisOutput`; `verdicts_json` is `{ "<host>": [ReputationVerdict, ...], ... }`. Pure +
/// network-free — identical to native callers.
#[wasm_bindgen]
pub fn apply_domain_reputation(output_json: &str, verdicts_json: &str) -> Result<String, JsValue> {
    use std::collections::BTreeMap;
    let mut out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let verdicts: BTreeMap<String, Vec<ppcap_core::ReputationVerdict>> =
        serde_json::from_str(verdicts_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    ppcap_core::apply_domain_reputation(&mut out.summary, &verdicts);
    serde_json::to_string(&out).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Export the analysis findings as RFC 4180 CSV. `output_json` is the `AnalysisOutput` from `analyze`.
#[wasm_bindgen]
pub fn export_csv(output_json: &str) -> Result<String, JsValue> {
    let out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(ppcap_core::export::findings_csv(&out))
}

/// Export the analysis findings as a STIX 2.1 bundle stamped with `generated_unix_secs`.
#[wasm_bindgen]
pub fn export_stix(output_json: &str, generated_unix_secs: i64) -> Result<String, JsValue> {
    let out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(ppcap_core::export::stix_bundle(&out, generated_unix_secs))
}

/// Export the analysis findings as a MISP event stamped with `generated_unix_secs`.
#[wasm_bindgen]
pub fn export_misp(output_json: &str, generated_unix_secs: i64) -> Result<String, JsValue> {
    let out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(ppcap_core::export::misp_event(&out, generated_unix_secs))
}

/// Export the analysis findings as CEF (Common Event Format) records.
#[wasm_bindgen]
pub fn export_cef(output_json: &str) -> Result<String, JsValue> {
    let out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(ppcap_core::export::cef_records(&out))
}

/// Export the analysis findings as Sigma detection rules (multi-document YAML).
#[wasm_bindgen]
pub fn export_sigma(output_json: &str) -> Result<String, JsValue> {
    let out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(ppcap_core::export::sigma_rules(&out))
}

/// Render the full HTML triage report for `output_json` (browser parity with the desktop `save_report`).
#[wasm_bindgen]
pub fn render_report(
    output_json: &str,
    generated_unix_secs: i64,
    ai_summary: Option<String>,
) -> Result<String, JsValue> {
    let out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(ppcap_core::render_html(
        &out,
        generated_unix_secs,
        ai_summary.as_deref(),
    ))
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
