//! End-to-end tests for the incident timeline: a synthetic staged attack run through
//! `analyze::run` must yield one chronological, cross-host timeline per alert whose rows each carve
//! a non-empty packet slice out of the source capture.

use ppcap_core::analyze::{self, PipelineConfig};
use ppcap_core::gen::{GenConfig, Scenario, SynthGen};
use ppcap_core::model::timeline::TimelineEventKind;
use ppcap_core::packets::{carve_pcap, CarveQuery, CarveTarget, PacketCaps};

fn capture(scenario: Scenario, packets: u64) -> tempfile::TempPath {
    let cfg = GenConfig {
        scenario,
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
fn attack_chain_capture_yields_ordered_cross_host_timelines() {
    let path = capture(Scenario::AttackChain, 4_000);
    let out = analyze::run(&path, &PipelineConfig::default(), |_, _, _| {}).expect("analyze");
    let s = &out.summary;
    assert!(!s.alerts.is_empty());
    assert_eq!(s.timelines.len(), s.alerts.len());

    // The chain alert's timeline spans more than one host and is chronological.
    let chain = s
        .alerts
        .iter()
        .find(|a| a.chain_id.is_some())
        .expect("chain alert");
    let t = s.timelines.iter().find(|t| t.alert_id == chain.id).unwrap();
    assert!(t.hosts.len() >= 2, "hosts: {:?}", t.hosts);
    assert!(t
        .events
        .iter()
        .any(|e| e.kind == TimelineEventKind::Detection));
    let timed: Vec<i64> = t.events.iter().filter_map(|e| e.ts_ns).collect();
    assert!(timed.windows(2).all(|w| w[0] <= w[1]), "not chronological");
    // Every detection row references a real finding.
    for e in &t.events {
        if let Some(i) = e.finding_index {
            assert!((i as usize) < s.findings.len());
        }
    }
    // The streaming pass recorded context for the implicated endpoints.
    assert!(!s.timeline_context.first_contacts.is_empty());
    assert!(t
        .events
        .iter()
        .any(|e| e.kind == TimelineEventKind::FirstContact));

    // A timed detection with a peer carves a non-empty slice of the source capture.
    let row = t
        .events
        .iter()
        .find(|e| {
            e.kind == TimelineEventKind::Detection
                && e.ts_ns.is_some()
                && e.packets.as_ref().is_some_and(|p| p.peer.is_some())
        })
        .expect("a timed detection with a peer");
    let p = row.packets.as_ref().unwrap();
    let q = CarveQuery {
        target: CarveTarget::Scope {
            host: p.host.parse().unwrap(),
            peer: p.peer.as_deref().map(|x| x.parse().unwrap()),
            port: p.port,
        },
        start_ns: p.start_ns,
        end_ns: p.end_ns,
    };
    let src = ppcap_core::reader::open(&path).expect("reopen");
    let res = carve_pcap(src, &q, &PacketCaps::default()).expect("carve");
    assert!(res.packets > 0, "row {:?} carved nothing", row.title);
}

#[test]
fn timelines_are_deterministic() {
    let path = capture(Scenario::AttackChain, 4_000);
    let a = analyze::run(&path, &PipelineConfig::default(), |_, _, _| {}).unwrap();
    let b = analyze::run(&path, &PipelineConfig::default(), |_, _, _| {}).unwrap();
    assert_eq!(a.summary.timelines, b.summary.timelines);
    assert_eq!(a.summary.timeline_context, b.summary.timeline_context);
}
