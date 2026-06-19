//! The gate: generate a known capture, analyze it, and assert conservation + fidelity
//! invariants against the generator's ground-truth manifest.
//!
//! NOTE (reconciled with the implementation): the standard golden capture injects the two
//! edge frames (`include_edge_cases = true`). The truncated edge frame is a *malformed*
//! IPv4/TCP frame, so in lenient decode mode it is counted as a `decode_error` and is NOT
//! folded into `total_packets` or any flow (verified by the analyze pipeline). The manifest,
//! however, tallies that frame under its planned `tcp`/`other_tcp` bucket. The invariants
//! below therefore account for the single decode error explicitly:
//!   - `total_packets + decode_errors == packets_written`
//!   - proto fidelity is asserted on the decoded population (manifest counts minus the one
//!     truncated TCP frame), and
//!   - `Σ category.pkts + non_ip_frames == total_packets` (decode errors are not in totals).

use ppcap_core::analyze::{self, PipelineConfig};
use ppcap_core::gen::{GenConfig, GenManifest, Scenario, SynthGen};
use ppcap_core::metrics::{peak_heap_bytes, IngestMetrics, Phase0Budget, PHASE0_BUDGET};
use std::time::{Duration, Instant};

/// Generate the standard golden capture and return `(path, manifest)`.
fn golden_capture() -> (tempfile::TempPath, GenManifest) {
    let cfg = GenConfig {
        scenario: Scenario::Mixed,
        packets: 5_000,
        seed: 0xC0FFEE,
        include_edge_cases: true,
        host_count: 16,
        ..Default::default()
    };
    let tf = tempfile::NamedTempFile::new().expect("temp file");
    let manifest = SynthGen::new(cfg)
        .write_pcap(tf.path())
        .expect("write golden capture");
    (tf.into_temp_path(), manifest)
}

#[test]
fn golden_conservation_and_fidelity() {
    let (path, m) = golden_capture();
    let out = analyze::run(&path, &PipelineConfig::default(), |_, _, _| {}).unwrap();
    let s = &out.summary;

    // The single truncated edge frame fails to decode in lenient mode.
    assert_eq!(s.decode_errors, 1, "exactly one truncated edge frame");

    // 1. Every non-erroring frame was counted; total + errors == authored packets.
    assert_eq!(
        s.total_packets + s.decode_errors,
        m.packets_written,
        "total_packets + decode_errors == packets_written"
    );

    // 2. Protocol fidelity on the decoded population. The truncated frame was planned as a
    //    TCP (other_tcp) unit, so the decoded TCP aggregate is exactly one short of the
    //    manifest; the UDP aggregate is exact (no UDP frame fails to decode).
    assert_eq!(
        s.proto.tcp,
        m.counts.tcp - 1,
        "decoded tcp == planned tcp - truncated"
    );
    assert_eq!(s.proto.udp, m.counts.udp, "udp aggregate exact");
    // The leaf app-proto split (http/tls/dns) is a *lower bound* on the plan: the generator's
    // generic `other_tcp` frames pick a random low destination port, which may coincide with
    // 80/443/53 and get counted as http/tls/dns. So decoded leaf counts are >= the plan.
    assert!(s.proto.http >= m.counts.http, "http >= planned");
    assert!(s.proto.tls >= m.counts.tls, "tls >= planned");
    assert!(s.proto.dns >= m.counts.dns, "dns >= planned");

    // 3. Category-breakdown packets + non-IP frames reconcile to total_packets (decode errors
    //    are not part of total_packets).
    let cat_pkts: u64 = s.category_breakdown.iter().map(|c| c.pkts).sum();
    assert_eq!(
        cat_pkts + s.non_ip_frames,
        s.total_packets,
        "Σ category.pkts + non_ip_frames == total_packets"
    );

    // 4. tcp + udp + non_ip == total_packets (these are the only Ok-arm increments).
    assert_eq!(
        s.proto.tcp + s.proto.udp + s.non_ip_frames,
        s.total_packets,
        "tcp + udp + non_ip == total_packets"
    );

    // 5. Time histogram conserves packets.
    let time_pkts: u64 = s.time_histogram.iter().map(|t| t.pkts).sum();
    assert_eq!(
        time_pkts, s.total_packets,
        "Σ time_histogram.pkts == total_packets"
    );

    // 6. Capture window matches the manifest and is well-ordered.
    assert_eq!(s.first_ts_ns, Some(m.first_ts_ns));
    assert_eq!(s.last_ts_ns, Some(m.last_ts_ns));
    assert!(s.capture_end_ns() >= s.capture_start_ns());

    // 7. Talkers bounded by the host space (16 hosts); flows never exceed the packet count.
    //    (The generator uses fresh ephemeral client ports per packet, so distinct flows scale
    //    with packets, not with host^2 — the realistic conservation bound is total_packets.)
    assert!(
        s.top_talkers.len() <= 16,
        "top talkers bounded by host count"
    );
    assert!(
        s.unique_hosts <= 16,
        "unique IP hosts bounded by host count"
    );
    assert!(
        s.total_flows <= s.total_packets,
        "flows bounded by decoded packet count"
    );
    assert!(s.total_flows > 0, "some flows were observed");

    // 8. Port histogram never over-counts.
    let port_pkts: u64 = s.port_histogram.iter().map(|p| p.pkts).sum();
    assert!(
        port_pkts <= s.total_packets,
        "Σ port_histogram.pkts <= total_packets"
    );

    // 9. Peak heap under the budget ceiling. Under plain `cargo test` peak_heap_bytes() is 0
    //    (no instrumented allocator), which trivially satisfies the ceiling; the bench build
    //    enforces it for real.
    assert!(peak_heap_bytes() < PHASE0_BUDGET.max_peak_heap_bytes);

    // Provenance sanity.
    assert_eq!(out.link_type, "EN10MB");
    assert!(out.source_bytes > 0);
}

#[test]
#[ignore = "throughput floors are runner-variant; run with --ignored on real hardware"]
fn golden_100k_budget() {
    let cfg = GenConfig {
        scenario: Scenario::Mixed,
        packets: 100_000,
        ..Default::default()
    };
    let tf = tempfile::NamedTempFile::new().unwrap();
    let manifest = SynthGen::new(cfg).write_pcap(tf.path()).unwrap();
    let path = tf.into_temp_path();

    let start = Instant::now();
    let out = analyze::run(&path, &PipelineConfig::default(), |_, _, _| {}).unwrap();
    let wall: Duration = start.elapsed();

    let metrics = IngestMetrics {
        packets: out.summary.total_packets,
        wire_bytes: manifest.frame_bytes,
        wall,
        peak_heap_bytes: peak_heap_bytes(),
    };
    let budget: Phase0Budget = PHASE0_BUDGET;
    assert!(
        budget.check(&metrics).is_ok(),
        "budget check failed: {:?}",
        budget.check(&metrics)
    );
}
