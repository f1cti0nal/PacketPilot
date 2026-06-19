//! End-to-end offline threat enrichment proof: generate a clean Mixed capture, run the full
//! pipeline with the shipped sample IOC feed, and assert on both the Parquet verdict columns
//! and the `Summary` severity/ip_threats rollups. Deterministic; no network.

use arrow_array::{Array, BooleanArray, StringArray, UInt16Array};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use ppcap_core::analyze::{self, PipelineConfig};
use ppcap_core::gen::{GenConfig, Scenario, SynthGen};
use ppcap_core::Severity;

fn sample_feed_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("data/sample_iocs.json")
}

#[test]
fn threat_enrichment_end_to_end_with_sample_feed() {
    // Clean Mixed capture, host_count 16 so host_ip(5)=10.0.5.10 (auth.bank.example server)
    // appears and the SNI/IP IOCs fire.
    let cfg_gen = GenConfig {
        scenario: Scenario::Mixed,
        packets: 4_000,
        seed: 0x5EED_BEEF,
        include_edge_cases: false,
        host_count: 16,
        ..Default::default()
    };
    let tf = tempfile::NamedTempFile::new().expect("temp pcap");
    SynthGen::new(cfg_gen)
        .write_pcap(tf.path())
        .expect("generate capture");

    let dir = tempfile::tempdir().unwrap();
    let parquet_path = dir.path().join("flows.parquet");

    // Keep SNI Web flows un-uplifted (mirrors analyze_file), so the IOC floor — not scan
    // uplift — drives the demo High/Critical verdicts.
    let cfg = PipelineConfig {
        flows_parquet: Some(parquet_path.clone()),
        threat_feed: Some(sample_feed_path()),
        classify: ppcap_core::classify::ClassifyConfig {
            detect_scans: false,
            ..Default::default()
        },
        ..Default::default()
    };

    let out = analyze::run(tf.path(), &cfg, |_, _, _| {}).expect("analyze with feed");
    let s = &out.summary;

    // (2) severity_counts total reconciles with total_flows.
    assert_eq!(
        s.severity_counts.total(),
        s.total_flows,
        "every flow has a severity"
    );

    // (3) ip_threats non-empty and sorted desc by score.
    assert!(!s.ip_threats.is_empty(), "ip_threats present");
    assert!(
        s.ip_threats.windows(2).all(|w| w[0].score >= w[1].score),
        "ip_threats sorted desc by score"
    );

    // (4) at least one ioc IP-threat of rank >= High, and it includes a known synthetic IOC IP.
    let ioc_high = s
        .ip_threats
        .iter()
        .find(|t| t.ioc && t.severity.rank() >= Severity::High.rank());
    let ioc_high = ioc_high.expect("an IOC-tagged High+ ip_threat exists");
    assert!(ioc_high.tags.iter().any(|t| t == "ioc"), "tagged ioc");
    assert!(
        s.ip_threats
            .iter()
            .any(|t| (t.ip == "10.0.5.10" || t.ip == "10.0.0.10") && t.ioc),
        "a known synthetic IOC IP is flagged"
    );

    // ---- Parquet read-back: verdict columns at 19/20/21 -------------------------------
    let file = std::fs::File::open(&parquet_path).unwrap();
    let reader = ParquetRecordBatchReaderBuilder::try_new(file)
        .unwrap()
        .build()
        .unwrap();

    let mut saw_sni_auth_bank_ioc = false;
    let mut total_rows = 0usize;
    for batch in reader {
        let batch = batch.unwrap();
        let sni = batch
            .column(18)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let severity = batch
            .column(19)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let score = batch
            .column(20)
            .as_any()
            .downcast_ref::<UInt16Array>()
            .unwrap();
        let ioc = batch
            .column(21)
            .as_any()
            .downcast_ref::<BooleanArray>()
            .unwrap();

        for i in 0..batch.num_rows() {
            total_rows += 1;
            // (1) severity is a valid token, score <= 100.
            let tok = severity.value(i);
            assert!(
                Severity::from_str_opt(tok).is_some(),
                "valid severity token: {tok}"
            );
            assert!(score.value(i) <= 100, "threat_score <= 100");

            // (5) cross-check: an auth.bank.example SNI row is ioc + high/critical.
            if !sni.is_null(i) && sni.value(i) == "auth.bank.example" {
                assert!(ioc.value(i), "auth.bank.example flow is ioc");
                let sev = Severity::from_str_opt(severity.value(i)).unwrap();
                assert!(
                    sev.rank() >= Severity::High.rank(),
                    "auth.bank.example flow is High/Critical, got {tok}"
                );
                saw_sni_auth_bank_ioc = true;
            }
        }
    }
    assert!(total_rows > 0, "parquet has rows");
    assert!(
        saw_sni_auth_bank_ioc,
        "the auth.bank.example SNI flow was present and flagged"
    );
}
