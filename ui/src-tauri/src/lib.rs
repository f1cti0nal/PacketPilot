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

/// Render the self-contained HTML triage report for `summary` and write it to `path`.
/// The "generated at" time is the current wall clock (UTC Unix seconds).
#[tauri::command]
fn save_report(summary: AnalysisOutput, path: String) -> Result<(), String> {
    let now_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let html = ppcap_core::render_html(&summary, now_unix_secs);
    std::fs::write(&path, html).map_err(|e| format!("write report: {e}"))
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            analyze_capture,
            save_report,
            extract_flow_packets
        ])
        .run(tauri::generate_context!())
        .expect("error while running PacketPilot");
}
