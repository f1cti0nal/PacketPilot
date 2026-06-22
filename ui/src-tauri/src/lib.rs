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
    let cache_dir = dirs::cache_dir().unwrap_or_else(std::env::temp_dir).join("packetpilot");
    let verdicts = ppcap_core::lookup_reputation_native(&parsed, &keys, &cache_dir, now);
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
    Ok(if ai_key_for("default")?.is_some() { vec!["default".to_string()] } else { vec![] })
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
                return Err(format!("AI endpoint {code}: {}", r.into_string().unwrap_or_default()));
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

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            analyze_capture,
            save_report,
            extract_flow_packets,
            set_reputation_key,
            reputation_key_status,
            reputation_lookup,
            set_ai_key,
            ai_key_status,
            ai_chat_stream
        ])
        .run(tauri::generate_context!())
        .expect("error while running PacketPilot");
}
