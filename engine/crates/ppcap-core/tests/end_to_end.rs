//! Golden integration test: generate a small synthetic pcap, run the full analysis pipeline
//! (`analyze::run` — the file entry point), and assert packet/flow counts, the presence of
//! the expected traffic categories, and that the summary's internal sums reconcile.
//!
//! This complements `golden_e2e.rs`: that test exercises the edge-case capture (with a decode
//! error); this one uses a clean, no-edge capture so protocol fidelity is *exact* against the
//! generator manifest, and additionally drives the Parquet writer end to end.

use ppcap_core::analyze::{self, PipelineConfig};
use ppcap_core::gen::{GenConfig, Scenario, SynthGen};
use ppcap_core::model::category::Category;

/// Generate a small, clean (no edge cases) Mixed capture; return (path, manifest).
fn small_capture() -> (tempfile::TempPath, ppcap_core::gen::GenManifest) {
    let cfg = GenConfig {
        scenario: Scenario::Mixed,
        packets: 2_000,
        seed: 0xABCD_1234,
        include_edge_cases: false,
        host_count: 12,
        ..Default::default()
    };
    let tf = tempfile::NamedTempFile::new().expect("temp file");
    let manifest = SynthGen::new(cfg)
        .write_pcap(tf.path())
        .expect("generate capture");
    (tf.into_temp_path(), manifest)
}

#[test]
fn analyze_file_counts_categories_and_reconciles() {
    let (path, m) = small_capture();

    // Write flows to Parquet too, so the columnar path is exercised end to end.
    let dir = tempfile::tempdir().unwrap();
    let parquet_path = dir.path().join("flows.parquet");

    // Disable the scan uplift so port-based categories (Web/DNS) stand: the Mixed scenario's
    // many single-SYN probes would otherwise flag every source host as a scanner and
    // reclassify its flows to Scan, which is correct behavior but would mask the port-based
    // categories this test asserts on.
    let cfg = PipelineConfig {
        flows_parquet: Some(parquet_path.clone()),
        classify: ppcap_core::classify::ClassifyConfig {
            detect_scans: false,
            ..Default::default()
        },
        ..Default::default()
    };

    let out = analyze::run(&path, &cfg, |_, _, _| {}).expect("analyze_file");
    let s = &out.summary;

    // ---- Packet counts ------------------------------------------------------
    // No edge cases => no decode errors => every authored packet is counted.
    assert_eq!(s.decode_errors, 0, "clean capture has no decode errors");
    assert_eq!(
        s.total_packets, m.packets_written,
        "total_packets == packets_written"
    );

    // Transport aggregates are exact (no decode failures in a clean capture).
    assert_eq!(s.proto.tcp, m.counts.tcp, "tcp aggregate");
    assert_eq!(s.proto.udp, m.counts.udp, "udp aggregate");
    assert_eq!(s.non_ip_frames, m.counts.non_ipv4, "non-ip frames");
    // App-proto leaves are a lower bound on the plan. The generator's generic `other_tcp` frames
    // now target high non-service ports (never 80/443/53), so in practice the decoded leaf counts
    // equal the plan; `>=` is kept as the robust invariant (any future coincidence stays valid).
    assert!(s.proto.http >= m.counts.http, "http >= planned");
    assert!(s.proto.tls >= m.counts.tls, "tls >= planned");
    assert!(s.proto.dns >= m.counts.dns, "dns >= planned");

    // ---- Flow counts --------------------------------------------------------
    assert!(s.total_flows > 0, "some flows must be observed");
    assert!(
        s.total_flows <= s.total_packets,
        "flows cannot exceed decoded packets"
    );
    // Every observed flow lands in exactly one category slot.
    let cat_flows: u64 = s.category_breakdown.iter().map(|c| c.flows).sum();
    assert_eq!(cat_flows, s.total_flows, "Σ category.flows == total_flows");

    // ---- Expected categories present ---------------------------------------
    // A Mixed capture produces Web (http+https) and DNS traffic at minimum.
    let breakdown = |cat: Category| {
        s.category_breakdown
            .iter()
            .find(|c| c.category == cat)
            .expect("category present in fixed breakdown")
    };
    assert_eq!(
        s.category_breakdown.len(),
        12,
        "all 12 categories always listed"
    );
    assert!(breakdown(Category::Web).flows > 0, "expected Web flows");
    assert!(breakdown(Category::Dns).flows > 0, "expected DNS flows");

    // ---- Summary invariants (sums reconcile) -------------------------------
    // category packets + non-IP frames == total packets (decode_errors == 0 here).
    let cat_pkts: u64 = s.category_breakdown.iter().map(|c| c.pkts).sum();
    assert_eq!(
        cat_pkts + s.non_ip_frames,
        s.total_packets,
        "Σ category.pkts + non_ip_frames == total_packets"
    );
    // tcp + udp + non_ip == total_packets.
    assert_eq!(s.proto.tcp + s.proto.udp + s.non_ip_frames, s.total_packets);
    // time histogram conserves packets.
    let time_pkts: u64 = s.time_histogram.iter().map(|t| t.pkts).sum();
    assert_eq!(
        time_pkts, s.total_packets,
        "Σ time_histogram.pkts == total_packets"
    );
    // category byte tally reconciles with the per-direction byte sums of all flows: it must
    // not exceed total wire bytes.
    let cat_bytes: u64 = s.category_breakdown.iter().map(|c| c.bytes).sum();
    assert!(cat_bytes <= s.total_bytes, "flow bytes <= total wire bytes");

    // ---- Capture window + provenance ---------------------------------------
    assert_eq!(s.first_ts_ns, Some(m.first_ts_ns));
    assert_eq!(s.last_ts_ns, Some(m.last_ts_ns));
    assert!(s.duration_ns >= 0);
    assert_eq!(out.link_type, "EN10MB");

    // ---- Parquet was written ------------------------------------------------
    // analyze reports the path via `Path::display().to_string()`; mirror that exactly.
    assert_eq!(
        out.flows_parquet_path.as_deref(),
        Some(parquet_path.display().to_string().as_str()),
        "analysis output reports the parquet path"
    );
    let meta = std::fs::metadata(&parquet_path).expect("parquet file exists");
    assert!(meta.len() > 0, "parquet file is non-empty");
}
