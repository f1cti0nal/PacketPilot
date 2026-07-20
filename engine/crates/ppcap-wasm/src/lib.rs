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

    #[test]
    fn baseline_build_and_compare_across_the_json_boundary() {
        let pcap = crafted_tcp443_pcap_with_abc();
        // analyze now attaches the per-host baseline snapshot (10.0.0.1 -> 93.184.216.34:443).
        let analyze_json = crate::analyze(&pcap, "t.pcap".into()).unwrap();
        let analyze_val: serde_json::Value = serde_json::from_str(&analyze_json).unwrap();
        let out_json = analyze_val["summary"].to_string();
        assert!(
            analyze_val["summary"]["baseline"]["hosts"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false),
            "analyze must attach a baseline snapshot with hosts"
        );

        // build_baseline folds the capture into a fresh profile.
        let base_json = crate::build_baseline(&out_json, None, 1_000).unwrap();
        let bv: serde_json::Value = serde_json::from_str(&base_json).unwrap();
        assert_eq!(bv["captures_merged"], 1);
        assert!(bv["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["host"] == "10.0.0.1"));

        // Warm the baseline to the warm-up threshold, then blank its peer/service sets so the same
        // capture reads as all-new — a deterministic deviation through the wasm boundary.
        let params = ppcap_core::BaselineParams::default();
        let mut warm = base_json.clone();
        for i in 1..params.min_captures {
            warm = crate::build_baseline(&out_json, Some(warm), 1_000 + i as i64).unwrap();
        }
        let mut prof: ppcap_core::BaselineProfile = serde_json::from_str(&warm).unwrap();
        for h in &mut prof.hosts {
            h.peers.clear();
            h.services.clear();
        }
        let stale = serde_json::to_string(&prof).unwrap();

        let cmp_json = crate::compare_to_baseline(&out_json, &stale).unwrap();
        let cv: serde_json::Value = serde_json::from_str(&cmp_json).unwrap();
        let devs = cv["summary"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["kind"] == "baseline_deviation")
            .count();
        assert!(devs >= 1, "expected a baseline deviation vs the stale baseline");
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

// ---------------------------------------------------------------------------
// decrypt_tls_flow — TLS 1.3 key-log decryption for a single flow
// ---------------------------------------------------------------------------

/// Re-read `bytes` (a raw `.pcap`/`.pcapng` file) and decrypt the TLS 1.3 flow described by
/// `query_json` (a `QueryDto`) using the NSS `SSLKEYLOGFILE` text in `keylog_text`.
///
/// Returns a JSON string matching `TlsDecryptResult` (`{ supported, session_found, version,
/// cipher, cipher_name, keylog_sessions, truncated, reason, records: [...] }`), where each record
/// carries the base64 inner plaintext. Only `TLS_AES_128_GCM_SHA256` is supported this phase;
/// other suites return `supported: false` with an explaining `reason`. The capture and the
/// key-log both stay on the device — neither leaves the browser.
#[wasm_bindgen]
pub fn decrypt_tls_flow(
    bytes: &[u8],
    query_json: &str,
    keylog_text: &str,
) -> Result<String, JsValue> {
    let q: QueryDto =
        serde_json::from_str(query_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
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

    let len = bytes.len() as u64;
    let source = ppcap_core::reader::open_reader(Cursor::new(bytes.to_vec()), Some(len))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let res = ppcap_core::decrypt_tls_flow(source, &query, keylog_text)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    serde_json::to_string(&res).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ---------------------------------------------------------------------------
// sanitize — Safe Share: anonymize a capture for sharing
// ---------------------------------------------------------------------------

/// Sanitize a raw capture entirely in the browser (Safe Share).
///
/// `options_json` mirrors `ppcap_core::SanitizeOptions` (missing fields take the
/// privacy-safest defaults). `key` must be 32 bytes from `crypto.getRandomValues`
/// — wasm has no OS entropy, so the page supplies the per-run secret; it exists
/// only in memory and is never part of the output. Returns a JSON string
/// `{ manifest, pcap_b64 }`; the capture never leaves the device.
#[wasm_bindgen]
pub fn sanitize(
    bytes: &[u8],
    options_json: &str,
    key: &[u8],
    created_unix_secs: i64,
) -> Result<String, JsValue> {
    use base64::Engine as _;

    let opts: ppcap_core::SanitizeOptions =
        serde_json::from_str(options_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| JsValue::from_str("sanitize key must be exactly 32 bytes"))?;
    let (out, manifest) = ppcap_core::sanitize::sanitize_bytes(bytes, key, &opts, created_unix_secs)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    #[derive(Serialize)]
    struct SanitizeDto {
        manifest: ppcap_core::SanitizeManifest,
        pcap_b64: String,
    }
    let dto = SanitizeDto {
        manifest,
        pcap_b64: base64::engine::general_purpose::STANDARD.encode(&out),
    };
    serde_json::to_string(&dto).map_err(|e| JsValue::from_str(&e.to_string()))
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
    tls_version: Option<String>,
    tls_cipher: Option<String>,
    hassh: Option<String>,
    hassh_server: Option<String>,
    ja3s: Option<String>,
    http_host: Option<String>,
    http_ua: Option<String>,
    severity: String,
    threat_score: u16,
    ioc: bool,
}

impl FlowDto {
    /// Build a row from a finalized record, mirroring `FlowParquetWriter::write` exactly:
    /// `lo`/`hi` endpoints map to `src`/`dst`, empty strings collapse to `None`.
    fn from_record(rec: &FlowRecord, flow_id: u64) -> FlowDto {
        // Orient src/dst + c2s/s2c by the connection INITIATOR, mirroring the Parquet writer.
        let o = rec.oriented();
        FlowDto {
            flow_id,
            capture_id: 0,
            src_ip: o.src_ip.to_string(),
            dst_ip: o.dst_ip.to_string(),
            src_port: o.src_port,
            dst_port: o.dst_port,
            proto: rec.key.transport.ip_proto(),
            app_proto: if rec.app_proto.is_empty() {
                None
            } else {
                Some(rec.app_proto.clone())
            },
            bytes_c2s: o.bytes_c2s,
            bytes_s2c: o.bytes_s2c,
            pkts: rec.total_pkts(),
            start_ts_ns: rec.first_ts_ns,
            end_ts_ns: rec.last_ts_ns,
            tcp_flags_c2s: o.tcp_flags_c2s,
            tcp_flags_s2c: o.tcp_flags_s2c,
            ttl_min_c2s: o.ttl_min_c2s,
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
            tls_version: rec
                .tls_version
                .as_ref()
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string()),
            tls_cipher: rec
                .tls_cipher
                .as_ref()
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string()),
            hassh: rec
                .hassh
                .as_ref()
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string()),
            hassh_server: rec
                .hassh_server
                .as_ref()
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string()),
            ja3s: rec
                .ja3s
                .as_ref()
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string()),
            http_host: rec
                .http_host
                .as_ref()
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string()),
            http_ua: rec
                .http_ua
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

/// Behavioral Baseline: fold a completed analysis into a baseline profile (create-or-merge).
///
/// `output_json` is the `AnalysisOutput` from `analyze` (which carries the per-host egress
/// snapshot); `prior_baseline_json` is an existing baseline sidecar to merge into, or `None` to
/// start fresh; `analyzed_unix_secs` is the wall-clock analysis time (`0` if unknown). Returns the
/// updated `BaselineProfile` as JSON for the page to persist. Pure + offline — nothing leaves the
/// device; identical to the native `analyze --update-baseline`.
#[wasm_bindgen]
pub fn build_baseline(
    output_json: &str,
    prior_baseline_json: Option<String>,
    analyzed_unix_secs: i64,
) -> Result<String, JsValue> {
    let out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let prior = match prior_baseline_json {
        Some(t) => ppcap_core::BaselineProfile::from_json_str(&t)
            .map_err(|e| JsValue::from_str(&e.to_string()))?,
        None => ppcap_core::BaselineProfile::new(),
    };
    let params = ppcap_core::BaselineParams::default();
    let updated = ppcap_core::update_baseline(prior, &out, analyzed_unix_secs, &params);
    updated
        .to_json_pretty()
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Behavioral Baseline: compare a completed analysis against a saved baseline, folding the deviation
/// findings into it.
///
/// `output_json` is the `AnalysisOutput` from `analyze` (carrying the per-host snapshot);
/// `baseline_json` is the saved `BaselineProfile`. Returns the updated `AnalysisOutput` as JSON —
/// `baseline_deviation` findings appended to `summary.findings` with the per-IP threat cards
/// uplifted (via the same `fold_rule_findings` path the Suricata pass uses). Pure + offline. When
/// the output carries no snapshot (an older analysis), nothing is folded.
#[wasm_bindgen]
pub fn compare_to_baseline(output_json: &str, baseline_json: &str) -> Result<String, JsValue> {
    let mut out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let base = ppcap_core::BaselineProfile::from_json_str(baseline_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let params = ppcap_core::BaselineParams::default();
    if let Some(prof) = out.baseline.clone() {
        let devs = ppcap_core::compare_to_baseline(&base, &prof, &params).into_findings();
        ppcap_core::fold_rule_findings(&mut out.summary, &devs);
    }
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

    // Build a streaming source by BORROWING the wasm-bindgen-provided slice (no extra owned
    // copy — open_reader is lifetime-generic, so the reader keeps only its bounded refill buffer).
    // This drops one full-file copy from the linear memory: peak was ~2x the capture (the bindgen
    // copy + this clone), now ~1x. The reader still streams; memory stays bounded by file size.
    let source = ppcap_core::reader::open_reader(Cursor::new(bytes), Some(len))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Compute the per-host behavioral-baseline snapshot so the browser can learn/compare offline
    // (it rides on `AnalysisOutput.baseline`; cheap and bounded). Omitted from JSON when absent, so
    // this is additive for callers that don't use baselines.
    let cfg = PipelineConfig {
        update_baseline: true,
        ..PipelineConfig::default()
    };
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
