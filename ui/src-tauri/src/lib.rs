use std::path::{Path, PathBuf};

use base64::Engine as _;
use ppcap_core::{AnalysisOutput, PipelineConfig};
use serde::Serialize;

/// IPC payload: the summary (serializes byte-for-byte to the frontend's
/// AnalysisOutput TS type) plus the flows Parquet bytes, standard-base64 encoded.
#[derive(Serialize)]
struct AnalyzeDto {
    summary: AnalysisOutput,
    flows_b64: String,
}

/// Analyze one capture file end to end. Writes the per-flow Parquet to a unique
/// temp file (the only persistence API the engine exposes), reads it back,
/// base64-encodes it, deletes the temp file, returns it with the summary.
#[tauri::command]
fn analyze_capture(path: String) -> Result<AnalyzeDto, String> {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut tmp: PathBuf = std::env::temp_dir();
    tmp.push(format!("packetpilot-flows-{pid}-{nanos}.parquet"));

    let cfg = PipelineConfig {
        flows_parquet: Some(tmp.clone()),
        hash_source: true,
        ..Default::default()
    };

    // Progress closure is FnMut(u64, u64, Option<u64>) — three args, ignored.
    let run_result = ppcap_core::run(Path::new(&path), &cfg, |_, _, _| {});

    let summary = match run_result {
        Ok(out) => out,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.to_string());
        }
    };

    let bytes = match std::fs::read(&tmp) {
        Ok(b) => b,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("read flows parquet: {e}"));
        }
    };
    let _ = std::fs::remove_file(&tmp);

    let flows_b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    Ok(AnalyzeDto { summary, flows_b64 })
}

#[derive(serde::Deserialize)]
struct PacketQueryArg {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    start_ns: i64,
    end_ns: i64,
}

#[tauri::command]
fn extract_flow_packets(
    path: String,
    query: PacketQueryArg,
) -> Result<ppcap_core::FlowPackets, String> {
    let q = ppcap_core::PacketQuery {
        src_ip: query.src_ip.parse().map_err(|_| "bad src_ip".to_string())?,
        dst_ip: query.dst_ip.parse().map_err(|_| "bad dst_ip".to_string())?,
        src_port: query.src_port,
        dst_port: query.dst_port,
        transport: ppcap_core::Transport::from_ip_proto(query.proto),
        start_ns: query.start_ns,
        end_ns: query.end_ns,
    };
    let source =
        ppcap_core::reader::open(std::path::Path::new(&path)).map_err(|e| e.to_string())?;
    ppcap_core::extract_flow_packets(source, &q, &ppcap_core::PacketCaps::default())
        .map_err(|e| e.to_string())
}

/// Tauri-side carve query DTO. `host` set → Host target; else Flow (all 5-tuple fields required).
#[derive(serde::Deserialize)]
struct CarveQueryArg {
    host: Option<String>,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    proto: Option<u8>,
    start_ns: i64,
    end_ns: i64,
}

fn carve_query_from_arg(arg: CarveQueryArg) -> Result<ppcap_core::CarveQuery, String> {
    let target = if let Some(h) = arg.host {
        let ip: std::net::IpAddr = h.parse().map_err(|_| "bad host ip".to_string())?;
        ppcap_core::CarveTarget::Host { ip }
    } else {
        let src_ip = arg
            .src_ip
            .ok_or("src_ip required for flow carve")?
            .parse::<std::net::IpAddr>()
            .map_err(|_| "bad src_ip".to_string())?;
        let dst_ip = arg
            .dst_ip
            .ok_or("dst_ip required for flow carve")?
            .parse::<std::net::IpAddr>()
            .map_err(|_| "bad dst_ip".to_string())?;
        let src_port = arg.src_port.ok_or("src_port required for flow carve")?;
        let dst_port = arg.dst_port.ok_or("dst_port required for flow carve")?;
        let proto = arg.proto.ok_or("proto required for flow carve")?;
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
        start_ns: arg.start_ns,
        end_ns: arg.end_ns,
    })
}

/// Carve packets matching `query` from `path_in`, write a new pcap to `path_out`, and return
/// the packet count. Nothing is stored beyond the output file; the source is re-read once.
#[tauri::command]
fn carve_pcap_to(path_in: String, query: CarveQueryArg, path_out: String) -> Result<u64, String> {
    let q = carve_query_from_arg(query)?;
    let source =
        ppcap_core::reader::open(std::path::Path::new(&path_in)).map_err(|e| e.to_string())?;
    let res = ppcap_core::carve_pcap(source, &q, &ppcap_core::PacketCaps::default())
        .map_err(|e| e.to_string())?;
    std::fs::write(&path_out, &res.pcap).map_err(|e| format!("write pcap: {e}"))?;
    Ok(res.packets)
}

#[derive(serde::Serialize)]
struct RuleApplyResult {
    output: ppcap_core::AnalysisOutput,
    loaded: usize,
    skipped: usize,
    matches: usize,
}

#[tauri::command]
fn apply_rules_to(path: String, rules_text: String, output_json: String) -> Result<String, String> {
    let mut out: ppcap_core::AnalysisOutput =
        serde_json::from_str(&output_json).map_err(|e| e.to_string())?;
    let parsed = ppcap_core::parse_rules(&rules_text);
    let file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
    let len = std::fs::metadata(&path).ok().map(|m| m.len());
    let rf = ppcap_core::apply_rules(file, len, &parsed.rules);
    ppcap_core::fold_rule_findings(&mut out.summary, &rf);
    let res = RuleApplyResult {
        matches: rf.len(),
        loaded: parsed.rules.len(),
        skipped: parsed.skipped.len(),
        output: out,
    };
    serde_json::to_string(&res).map_err(|e| e.to_string())
}

const KEYRING_SERVICE: &str = "packetpilot-reputation";
const KEYRING_SERVICE_AI: &str = "packetpilot-ai";

fn key_for(provider: &str) -> Result<Option<String>, String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, provider).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(k) if !k.is_empty() => Ok(Some(k)),
        _ => Ok(None),
    }
}

#[tauri::command]
fn set_reputation_key(provider: String, key: String) -> Result<(), String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, &provider).map_err(|e| e.to_string())?;
    entry.set_password(&key).map_err(|e| e.to_string())
}

#[tauri::command]
fn reputation_key_status() -> Result<Vec<String>, String> {
    let mut active = Vec::new();
    for p in ["abuseipdb", "greynoise", "virustotal"] {
        if key_for(p)?.is_some() {
            active.push(p.to_string());
        }
    }
    Ok(active)
}

#[tauri::command]
fn reputation_lookup(ips: Vec<String>) -> Result<String, String> {
    let keys = ppcap_core::ReputationKeys {
        abuseipdb: key_for("abuseipdb")?,
        greynoise: key_for("greynoise")?,
        virustotal: key_for("virustotal")?,
    };
    if keys.is_empty() {
        return Ok("{}".to_string());
    }
    let parsed: Vec<std::net::IpAddr> = ips
        .iter()
        .filter_map(|s| s.parse().ok())
        .filter(|ip| ppcap_core::enrich::classify_ip(*ip).is_external())
        .collect();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("packetpilot");
    let verdicts = ppcap_core::lookup_reputation_native(&parsed, &keys, &cache_dir, now);
    serde_json::to_string(&verdicts).map_err(|e| e.to_string())
}

#[tauri::command]
fn domain_reputation_lookup(hosts: Vec<String>) -> Result<String, String> {
    let keys = ppcap_core::ReputationKeys {
        abuseipdb: None,
        greynoise: None,
        virustotal: key_for("virustotal")?,
    };
    if keys.virustotal.is_none() {
        return Ok("{}".to_string());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("packetpilot");
    let verdicts = ppcap_core::lookup_domain_reputation_native(&hosts, &keys, &cache_dir, now);
    serde_json::to_string(&verdicts).map_err(|e| e.to_string())
}

fn ai_key_for(name: &str) -> Result<Option<String>, String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE_AI, name).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(k) if !k.is_empty() => Ok(Some(k)),
        _ => Ok(None),
    }
}

#[tauri::command]
fn set_ai_key(provider: String, key: String) -> Result<(), String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE_AI, &provider).map_err(|e| e.to_string())?;
    entry.set_password(&key).map_err(|e| e.to_string())
}

#[tauri::command]
fn ai_key_status() -> Result<Vec<String>, String> {
    Ok(if ai_key_for("default")?.is_some() {
        vec!["default".to_string()]
    } else {
        vec![]
    })
}

/// Stream an OpenAI-compatible chat completion to the frontend. `body` is the full request JSON
/// (model + messages + stream:true) built in TS; the API key is read from the OS keychain here so it
/// never crosses into the renderer. Raw response bytes are forwarded via the Channel; the TS side
/// parses the SSE. Runs the blocking ureq read on a worker so the Tauri event loop is never blocked.
#[tauri::command]
async fn ai_chat_stream(
    url: String,
    body: String,
    on_chunk: tauri::ipc::Channel<String>,
) -> Result<(), String> {
    let key = ai_key_for("default")?;
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(180))
            .build();
        let mut req = agent.post(&url).set("content-type", "application/json");
        if let Some(k) = &key {
            req = req.set("Authorization", &format!("Bearer {k}"));
        }
        let resp = match req.send_string(&body) {
            Ok(r) => r,
            // 4xx/5xx: surface the upstream error body as the failure reason.
            Err(ureq::Error::Status(code, r)) => {
                return Err(format!(
                    "AI endpoint {code}: {}",
                    r.into_string().unwrap_or_default()
                ));
            }
            Err(e) => return Err(e.to_string()),
        };
        use std::io::Read;
        let mut reader = std::io::BufReader::new(resp.into_reader());
        let mut buf = [0u8; 4096];
        loop {
            let n = reader.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            on_chunk
                .send(String::from_utf8_lossy(&buf[..n]).to_string())
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Render the self-contained HTML triage report for `summary` and write it to `path`.
/// The "generated at" time is the current wall clock (UTC Unix seconds).
/// When `ai_summary` is `Some`, the AI analyst summary is embedded in the report.
#[tauri::command]
fn save_report(
    summary: AnalysisOutput,
    path: String,
    ai_summary: Option<String>,
) -> Result<(), String> {
    let now_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let html = ppcap_core::render_html(&summary, now_unix_secs, ai_summary.as_deref());
    std::fs::write(&path, html).map_err(|e| format!("write report: {e}"))
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Write the findings CSV for `summary` to `path`.
#[tauri::command]
fn save_csv(summary: AnalysisOutput, path: String) -> Result<(), String> {
    let csv = ppcap_core::export::findings_csv(&summary);
    std::fs::write(&path, csv).map_err(|e| format!("write csv: {e}"))
}

/// Write the STIX 2.1 bundle for `summary` to `path`.
#[tauri::command]
fn save_stix(summary: AnalysisOutput, path: String) -> Result<(), String> {
    let stix = ppcap_core::export::stix_bundle(&summary, now_unix_secs());
    std::fs::write(&path, stix).map_err(|e| format!("write stix: {e}"))
}

/// Return the findings CSV string for `summary` (used for copy-to-clipboard).
#[tauri::command]
fn export_csv(summary: AnalysisOutput) -> Result<String, String> {
    Ok(ppcap_core::export::findings_csv(&summary))
}

/// Return the STIX 2.1 bundle string for `summary` (used for copy-to-clipboard).
#[tauri::command]
fn export_stix(summary: AnalysisOutput) -> Result<String, String> {
    Ok(ppcap_core::export::stix_bundle(&summary, now_unix_secs()))
}

/// Write the MISP event for `summary` to `path`.
#[tauri::command]
fn save_misp(summary: AnalysisOutput, path: String) -> Result<(), String> {
    let s = ppcap_core::export::misp_event(&summary, now_unix_secs());
    std::fs::write(&path, s).map_err(|e| format!("write misp: {e}"))
}

/// Write the CEF records for `summary` to `path`.
#[tauri::command]
fn save_cef(summary: AnalysisOutput, path: String) -> Result<(), String> {
    let s = ppcap_core::export::cef_records(&summary);
    std::fs::write(&path, s).map_err(|e| format!("write cef: {e}"))
}

/// Return the MISP event string for `summary` (used for copy-to-clipboard).
#[tauri::command]
fn export_misp(summary: AnalysisOutput) -> Result<String, String> {
    Ok(ppcap_core::export::misp_event(&summary, now_unix_secs()))
}

/// Return the CEF records string for `summary` (used for copy-to-clipboard).
#[tauri::command]
fn export_cef(summary: AnalysisOutput) -> Result<String, String> {
    Ok(ppcap_core::export::cef_records(&summary))
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            analyze_capture,
            save_report,
            save_csv,
            save_stix,
            save_misp,
            save_cef,
            export_csv,
            export_stix,
            export_misp,
            export_cef,
            extract_flow_packets,
            carve_pcap_to,
            apply_rules_to,
            set_reputation_key,
            reputation_key_status,
            reputation_lookup,
            domain_reputation_lookup,
            set_ai_key,
            ai_key_status,
            ai_chat_stream
        ])
        .run(tauri::generate_context!())
        .expect("error while running PacketPilot");
}
