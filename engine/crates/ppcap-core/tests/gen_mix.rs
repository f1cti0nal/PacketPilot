//! Generator mix scheduler: count conservation, seed-independence, determinism, bounded mem.

use ppcap_core::gen::{GenConfig, Scenario, SynthGen};

fn cfg(packets: u64, seed: u64) -> GenConfig {
    GenConfig {
        scenario: Scenario::Mixed,
        packets,
        seed,
        host_count: 16,
        ..Default::default()
    }
}

#[test]
fn proto_counts_sum_to_packets() {
    for &packets in &[97u64, 1000, 100_000] {
        let m = SynthGen::new(cfg(packets, 1))
            .write_to(std::io::sink())
            .unwrap();
        let c = &m.counts;
        assert_eq!(c.tcp + c.udp + c.non_ipv4, packets, "packets={packets}");
        assert_eq!(
            c.http + c.tls + c.other_tcp,
            c.tcp,
            "tcp leaves, packets={packets}"
        );
        assert_eq!(c.dns + c.other_udp, c.udp, "udp leaves, packets={packets}");
        assert_eq!(m.packets_written, packets);
    }
}

#[test]
fn counts_are_seed_independent() {
    let m1 = SynthGen::new(cfg(10_000, 1))
        .write_to(std::io::sink())
        .unwrap();
    let m2 = SynthGen::new(cfg(10_000, 999_999))
        .write_to(std::io::sink())
        .unwrap();
    assert_eq!(
        m1.counts, m2.counts,
        "count plan must not depend on the seed"
    );
    assert_eq!(m1.packets_written, m2.packets_written);
}

#[test]
fn output_is_byte_identical_for_same_config() {
    let mut a = SynthGen::new(cfg(500, 42));
    let mut b = SynthGen::new(cfg(500, 42));
    let mut buf_a = Vec::new();
    let mut buf_b = Vec::new();
    a.write_to(&mut buf_a).unwrap();
    b.write_to(&mut buf_b).unwrap();
    assert_eq!(buf_a, buf_b, "same config must yield byte-identical output");
    assert!(!buf_a.is_empty());
}

#[test]
fn edge_cases_inject_exactly_one_each() {
    let n = 1000u64;
    let mut c = cfg(n, 7);
    c.include_edge_cases = true;
    let m = SynthGen::new(c).write_to(std::io::sink()).unwrap();
    assert_eq!(m.counts.truncated, 1);
    assert_eq!(m.counts.non_ipv4, 1);
    assert_eq!(m.counts.tcp + m.counts.udp + m.counts.non_ipv4, n);
}

#[test]
fn generation_is_bounded_memory() {
    // In plain `cargo test` there is no instrumented allocator (peak_alloc is bench-only), so
    // we assert the streaming contract by proxy: writing 1M packets to a sink succeeds, and the
    // generator's only accumulating structure — the distinct-flow set — stays hard-capped at
    // MAX_TRACKED_FLOWS regardless of flow cardinality. An instrumented peak check lives in the
    // bench binary.
    let m = SynthGen::new(cfg(1_000_000, 3))
        .write_to(std::io::sink())
        .unwrap();
    assert_eq!(m.packets_written, 1_000_000);
    assert!(
        (m.distinct_flows as usize) <= ppcap_core::gen::MAX_TRACKED_FLOWS,
        "distinct-flow tracking must stay bounded: {} > cap {}",
        m.distinct_flows,
        ppcap_core::gen::MAX_TRACKED_FLOWS
    );
}
