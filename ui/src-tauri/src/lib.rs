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

    let mut cfg = PipelineConfig::default();
    cfg.flows_parquet = Some(tmp.clone());
    cfg.hash_source = true;

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
        .invoke_handler(tauri::generate_handler![analyze_capture, save_report])
        .run(tauri::generate_context!())
        .expect("error while running PacketPilot");
}
