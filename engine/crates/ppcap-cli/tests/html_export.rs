//! End-to-end test for `ppcap analyze --html`.
//!
//! Generates a tiny synthetic capture, shells out to the compiled `ppcap` binary with the
//! `--html` flag (Cargo provides `CARGO_BIN_EXE_ppcap` for bin integration tests — no extra
//! dependency), and asserts a non-empty, well-formed HTML document is written.

use std::process::Command;

use ppcap_core::gen::{GenConfig, Scenario, SynthGen};

#[test]
fn analyze_writes_html_report() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cap = dir.path().join("sample.pcap");
    let html = dir.path().join("report.html");

    // Produce a small mixed capture first.
    let cfg = GenConfig {
        scenario: Scenario::Mixed,
        packets: 500,
        seed: 0x1234_5678,
        include_edge_cases: false,
        ..Default::default()
    };
    SynthGen::new(cfg)
        .write_pcap(&cap)
        .expect("generate capture");

    let output = Command::new(env!("CARGO_BIN_EXE_ppcap"))
        .args([
            "analyze",
            cap.to_str().unwrap(),
            "--quiet",
            "--json",
            "-",
            "--html",
            html.to_str().unwrap(),
        ])
        .output()
        .expect("run ppcap");

    assert!(
        output.status.success(),
        "ppcap analyze failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let doc = std::fs::read_to_string(&html).expect("read html report");
    assert!(!doc.is_empty(), "html report is empty");
    let head = doc.trim_start().to_ascii_lowercase();
    assert!(
        head.starts_with("<!doctype") || head.starts_with("<html"),
        "html report missing doctype/html prefix"
    );
    assert!(doc.contains("Capture Triage Report"), "title missing");
}
