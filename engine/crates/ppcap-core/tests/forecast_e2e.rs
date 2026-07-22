//! End-to-end test for Predictive Anomaly Detection.
//!
//! Generate a capture with one internal host whose egress spikes mid-capture, run the full
//! pipeline (`analyze::run`), and assert a `traffic_anomaly` finding is raised on that host, rides
//! through the summary, and uplifts its per-IP threat card — the same path every other detector
//! takes. Also assert the forecast can be switched off and that generation is deterministic.

use ppcap_core::analyze::{self, PipelineConfig};
use ppcap_core::forecast::ForecastParams;
use ppcap_core::gen::{GenConfig, Scenario, SynthGen};
use ppcap_core::model::finding::FindingKind;

/// The spiking host in [`Scenario::TrafficSpike`] is `host_ip(0)`.
const SPIKE_HOST: &str = "10.0.0.10";
/// The burst's internal receiver in [`Scenario::TrafficSpike`] is `host_ip(1)` — the same spike
/// lands on its *ingress* series, so the inbound forecaster attributes an anomaly to it.
const SPIKE_PEER: &str = "10.0.1.10";

fn spike_capture(packets: u64) -> tempfile::TempPath {
    let cfg = GenConfig {
        scenario: Scenario::TrafficSpike,
        packets,
        seed: 0x5EED_1234,
        include_edge_cases: false,
        host_count: 8,
        ..Default::default()
    };
    let tf = tempfile::NamedTempFile::new().expect("temp file");
    SynthGen::new(cfg)
        .write_pcap(tf.path())
        .expect("generate capture");
    tf.into_temp_path()
}

#[test]
fn traffic_spike_scenario_raises_a_forecast_anomaly() {
    let path = spike_capture(400);
    let out = analyze::run(&path, &PipelineConfig::default(), |_, _, _| {}).expect("analyze");
    let s = &out.summary;

    let anomalies: Vec<_> = s
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::TrafficAnomaly)
        .collect();
    assert!(
        !anomalies.is_empty(),
        "the spike scenario must raise a traffic_anomaly finding; kinds seen: {:?}",
        s.findings.iter().map(|f| f.kind).collect::<Vec<_>>()
    );
    assert!(
        anomalies.iter().any(|f| f.src_ip == SPIKE_HOST),
        "the anomaly is attributed to the spiking internal host {SPIKE_HOST}"
    );
    let a = anomalies.iter().find(|f| f.src_ip == SPIKE_HOST).unwrap();
    assert!(a.first_seen_ns.is_some() && a.last_seen_ns.is_some());
    assert!(
        !a.evidence.is_empty(),
        "the finding carries explainable evidence"
    );

    // It rode the shared finding path: `apply_findings` uplifted the host's per-IP threat card.
    assert!(
        s.ip_threats.iter().any(|t| t.ip == SPIKE_HOST),
        "the spiking host has a threat card"
    );
}

#[test]
fn traffic_spike_scenario_raises_an_inbound_anomaly_on_the_receiver() {
    let path = spike_capture(400);
    let out = analyze::run(&path, &PipelineConfig::default(), |_, _, _| {}).expect("analyze");
    let s = &out.summary;

    // The same mid-capture burst that spikes the sender's egress lands on the receiver's ingress.
    // The inbound forecaster tracks that host's receive baseline and flags the burst bin,
    // attributing the anomaly to the internal victim (`host_ip(1)`), not the sender.
    let inbound = s
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::TrafficAnomaly && f.src_ip == SPIKE_PEER)
        .find(|f| f.evidence.iter().any(|e| e.contains("inbound")));
    let a = inbound.unwrap_or_else(|| {
        panic!(
            "the burst receiver {SPIKE_PEER} must get an inbound traffic_anomaly; \
             anomalies seen: {:?}",
            s.findings
                .iter()
                .filter(|f| f.kind == FindingKind::TrafficAnomaly)
                .map(|f| f.src_ip.as_str())
                .collect::<Vec<_>>()
        )
    });
    assert!(a.first_seen_ns.is_some() && a.last_seen_ns.is_some());
    assert!(
        s.ip_threats.iter().any(|t| t.ip == SPIKE_PEER),
        "the burst receiver has a threat card"
    );
}

#[test]
fn forecast_can_be_disabled() {
    let path = spike_capture(400);
    let cfg = PipelineConfig {
        forecast: ForecastParams {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    };
    let out = analyze::run(&path, &cfg, |_, _, _| {}).expect("analyze");
    assert!(
        !out.summary
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::TrafficAnomaly),
        "no traffic anomalies when the forecast stage is disabled"
    );
}

#[test]
fn spike_scenario_generation_is_deterministic() {
    let gen = |packets: u64| -> Vec<u8> {
        let cfg = GenConfig {
            scenario: Scenario::TrafficSpike,
            packets,
            seed: 0x5EED_1234,
            host_count: 8,
            ..Default::default()
        };
        let mut buf = Vec::new();
        SynthGen::new(cfg).write_to(&mut buf).expect("generate");
        buf
    };
    assert_eq!(
        gen(300),
        gen(300),
        "same seed+count => byte-identical output"
    );
}
