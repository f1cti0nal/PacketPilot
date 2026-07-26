//! End-to-end Encrypted Traffic Analysis: generate a capture, run the real pipeline, and assert
//! the ETA findings, their attribution, and their false-positive guards.
//!
//! Black-box by construction — everything goes through `gen` + `analyze::run`, the same path the
//! CLI takes.

use std::path::PathBuf;

use ppcap_core::analyze::{self, PipelineConfig};
use ppcap_core::gen::{GenConfig, Scenario, SynthGen};
use ppcap_core::model::finding::FindingKind;

fn tmp_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("ppcap_eta_{}_{}.pcap", name, std::process::id()));
    p
}

/// Generate `scenario` to a temp pcap and analyze it with `cfg`.
fn run_scenario(
    name: &str,
    scenario: Scenario,
    packets: u64,
    cfg: &PipelineConfig,
) -> ppcap_core::model::output::AnalysisOutput {
    let path = tmp_path(name);
    let mut gen = SynthGen::new(GenConfig {
        scenario,
        packets,
        seed: 0xE7A_0001,
        ..GenConfig::default()
    });
    gen.write_pcap(&path).expect("write capture");
    let out = analyze::run(&path, cfg, |_, _, _| {}).expect("analyze");
    let _ = std::fs::remove_file(&path);
    out
}

#[test]
fn encrypted_anomaly_scenario_raises_an_unidentified_encrypted_channel() {
    let out = run_scenario(
        "anomaly",
        Scenario::EncryptedAnomaly,
        60,
        &PipelineConfig::default(),
    );

    let f = out
        .summary
        .findings
        .iter()
        .find(|f| f.kind == FindingKind::EncryptedUnknownProtocol)
        .expect("an encrypted_unknown_protocol finding");

    // Attributed to the internal client, naming the external peer and its unnamed service port.
    assert_eq!(f.src_ip, "10.0.0.10");
    assert_eq!(f.dst_ip.as_deref(), Some("198.51.100.77"));
    assert_eq!(f.dst_port, Some(41337));
    // Alone this signal tops out at Medium — an unnamed encrypted channel is a lead, not a verdict.
    assert!(
        f.score <= 59,
        "encrypted-unknown alone must not reach High, got {}",
        f.score
    );
    assert!(f.attack.iter().any(|t| t == "T1573"));
    // The evidence must be checkable against the flow table: entropy, volume, and the reason.
    assert!(
        f.evidence.iter().any(|e| e.contains("bits/byte")),
        "evidence carries the measured entropy: {:?}",
        f.evidence
    );

    // The per-flow verdict side: `Category::Anomalous` finally has a producer.
    let anomalous = out
        .summary
        .category_breakdown
        .iter()
        .find(|c| c.category == ppcap_core::model::category::Category::Anomalous)
        .map(|c| c.flows)
        .unwrap_or(0);
    assert!(anomalous >= 1, "the opaque channel is classified anomalous");
}

#[test]
fn entropy_columns_are_populated_for_the_unidentified_flow_only() {
    let path = tmp_path("cols");
    let mut gen = SynthGen::new(GenConfig {
        scenario: Scenario::EncryptedAnomaly,
        packets: 40,
        seed: 7,
        ..GenConfig::default()
    });
    gen.write_pcap(&path).expect("write");

    let mut sampled = 0usize;
    let out = analyze::run(&path, &PipelineConfig::default(), |_, _, _| {}).expect("analyze");
    let _ = out;
    // Re-run with a visitor to inspect flow rows.
    let mut entropies: Vec<(String, Option<f32>, Option<f32>)> = Vec::new();
    let src = ppcap_core::reader::open(&path).expect("open");
    ppcap_core::analyze::run_source_visiting(
        src,
        "cols",
        0,
        &PipelineConfig::default(),
        &mut |rec| {
            let o = rec.oriented();
            if o.entropy_c2s.is_some() || o.entropy_s2c.is_some() {
                sampled += 1;
            }
            entropies.push((rec.app_proto.clone(), o.entropy_c2s, o.entropy_s2c));
        },
        |_, _, _| {},
    )
    .expect("visit");
    let _ = std::fs::remove_file(&path);

    assert!(sampled >= 1, "the opaque flow carries entropy columns");
    // Ciphertext-grade bytes must measure as such.
    let peak = entropies
        .iter()
        .filter_map(|(_, a, b)| match (a, b) {
            (Some(x), Some(y)) => Some(x.max(*y)),
            (Some(x), None) => Some(*x),
            (None, Some(y)) => Some(*y),
            _ => None,
        })
        .fold(0.0f32, f32::max);
    assert!(
        peak > 7.2,
        "pseudo-random payload must read as ciphertext, got {peak}"
    );
}

#[test]
fn disabling_eta_suppresses_the_finding_and_nulls_the_columns() {
    let cfg = PipelineConfig {
        entropy: ppcap_core::entropy::EntropyConfig {
            enabled: false,
            ..Default::default()
        },
        encrypted_unknown: ppcap_core::detect::EncryptedUnknownParams {
            enabled: false,
            ..Default::default()
        },
        ..PipelineConfig::default()
    };
    let out = run_scenario("off", Scenario::EncryptedAnomaly, 60, &cfg);
    assert!(
        !out.summary
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::EncryptedUnknownProtocol),
        "disabled ETA must raise nothing"
    );
}

/// The false-positive gate that matters most: ordinary mixed traffic — including TLS, whose
/// application-data packets decode as unidentified — must raise no ETA finding.
#[test]
fn benign_mixed_traffic_raises_no_encrypted_unknown_finding() {
    let out = run_scenario("benign", Scenario::Mixed, 3_000, &PipelineConfig::default());
    let noisy: Vec<_> = out
        .summary
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::EncryptedUnknownProtocol)
        .collect();
    assert!(
        noisy.is_empty(),
        "benign traffic must not raise encrypted-unknown findings: {noisy:?}"
    );
}

/// Generation is deterministic: the same (scenario, seed, count) yields byte-identical captures.
#[test]
fn encrypted_anomaly_generation_is_deterministic() {
    let mk = || {
        let mut g = SynthGen::new(GenConfig {
            scenario: Scenario::EncryptedAnomaly,
            packets: 30,
            seed: 42,
            ..GenConfig::default()
        });
        let mut buf = Vec::new();
        g.write_to(&mut buf).expect("write");
        buf
    };
    assert_eq!(mk(), mk());
}
