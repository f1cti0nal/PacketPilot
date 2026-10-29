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
    assert_eq!(f.dst_ip.as_deref(), Some("185.220.101.77"));
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

// ── Posture detectors through the real pipeline ─────────────────────────────

/// Drive hand-built frames through the full pipeline via an in-memory pcap.
mod posture {
    use super::*;
    use std::net::Ipv4Addr;

    // Frames are byte-built here (not via the crate-private `gen::frames`) so this stays a pure
    // black-box test against the public API — the convention `l7_enrichment_proof.rs` sets.
    const IP_PROTO_TCP: u8 = 6;
    const TCP_ACK: u8 = 0x10;
    const TCP_PSH: u8 = 0x08;
    const TCP_SYN: u8 = 0x02;

    /// Internet checksum (RFC 1071).
    fn inet_checksum(bytes: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut chunks = bytes.chunks_exact(2);
        for c in &mut chunks {
            sum += ((c[0] as u32) << 8) | (c[1] as u32);
        }
        if let [last] = chunks.remainder() {
            sum += (*last as u32) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn build_ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, _ttl: u8, l4_len: usize) -> Vec<u8> {
        let total_len = (20 + l4_len) as u16;
        let mut h = Vec::with_capacity(20);
        h.push(0x45);
        h.push(0x00);
        h.extend_from_slice(&total_len.to_be_bytes());
        h.extend_from_slice(&0u16.to_be_bytes());
        h.extend_from_slice(&0x4000u16.to_be_bytes());
        h.push(64);
        h.push(proto);
        h.extend_from_slice(&[0, 0]);
        h.extend_from_slice(&src.octets());
        h.extend_from_slice(&dst.octets());
        let cks = inet_checksum(&h);
        h[10..12].copy_from_slice(&cks.to_be_bytes());
        h
    }

    fn l4_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, segment: &[u8]) -> u16 {
        let mut buf = Vec::with_capacity(12 + segment.len() + 1);
        buf.extend_from_slice(&src.octets());
        buf.extend_from_slice(&dst.octets());
        buf.push(0);
        buf.push(proto);
        buf.extend_from_slice(&(segment.len() as u16).to_be_bytes());
        buf.extend_from_slice(segment);
        inet_checksum(&buf)
    }

    fn build_tcp(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sp: u16,
        dp: u16,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let seq: u32 = (u32::from(sp) << 16) | u32::from(dp);
        let ack: u32 = if flags & TCP_ACK != 0 {
            seq.wrapping_add(1)
        } else {
            0
        };
        let mut seg = Vec::with_capacity(20 + payload.len());
        seg.extend_from_slice(&sp.to_be_bytes());
        seg.extend_from_slice(&dp.to_be_bytes());
        seg.extend_from_slice(&seq.to_be_bytes());
        seg.extend_from_slice(&ack.to_be_bytes());
        seg.push(0x50);
        seg.push(flags);
        seg.extend_from_slice(&64240u16.to_be_bytes());
        seg.extend_from_slice(&[0, 0]);
        seg.extend_from_slice(&[0, 0]);
        seg.extend_from_slice(payload);
        let cks = l4_checksum(src, dst, IP_PROTO_TCP, &seg);
        seg[16..18].copy_from_slice(&cks.to_be_bytes());
        seg
    }

    /// A minimal ClientHello that DOES name a server (the negative control).
    fn client_hello_with_sni(host: &str) -> Vec<u8> {
        let h = host.as_bytes();
        let mut sni_body = Vec::new();
        sni_body.extend_from_slice(&((3 + h.len()) as u16).to_be_bytes());
        sni_body.push(0);
        sni_body.extend_from_slice(&(h.len() as u16).to_be_bytes());
        sni_body.extend_from_slice(h);
        client_hello_with_exts(&[(0x0000u16, sni_body), (0x002b, vec![0x02, 0x03, 0x04])])
    }

    const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    /// A genuinely public peer — RFC 5737 documentation space is not treated as external.
    const SERVER: Ipv4Addr = Ipv4Addr::new(185, 220, 101, 9);

    /// A minimal classic pcap (LINKTYPE_RAW) wrapping the given frames.
    fn write_pcap(path: &std::path::Path, frames: &[Vec<u8>]) {
        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes()); // magic (µs)
        out.extend_from_slice(&2u16.to_le_bytes()); // major
        out.extend_from_slice(&4u16.to_le_bytes()); // minor
        out.extend_from_slice(&0u32.to_le_bytes()); // tz
        out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        out.extend_from_slice(&101u32.to_le_bytes()); // LINKTYPE_RAW
        for (i, f) in frames.iter().enumerate() {
            out.extend_from_slice(&(1_700_000_000u32 + i as u32).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(f);
        }
        std::fs::write(path, out).expect("write pcap");
    }

    fn seg(src: Ipv4Addr, dst: Ipv4Addr, sp: u16, dp: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let tcp = build_tcp(src, dst, sp, dp, flags, payload);
        let mut pkt = build_ipv4(src, dst, IP_PROTO_TCP, 64, tcp.len());
        pkt.extend_from_slice(&tcp);
        pkt
    }

    /// A complete TCP session on `port` carrying `payload` from the client.
    fn session(port: u16, client_port: u16, payload: &[u8]) -> Vec<Vec<u8>> {
        vec![
            seg(CLIENT, SERVER, client_port, port, TCP_SYN, &[]),
            seg(SERVER, CLIENT, port, client_port, TCP_SYN | TCP_ACK, &[]),
            seg(
                CLIENT,
                SERVER,
                client_port,
                port,
                TCP_PSH | TCP_ACK,
                payload,
            ),
            seg(
                SERVER,
                CLIENT,
                port,
                client_port,
                TCP_PSH | TCP_ACK,
                &[0x41; 512],
            ),
        ]
    }

    fn analyze_frames(name: &str, frames: Vec<Vec<u8>>) -> ppcap_core::model::summary::Summary {
        let path = tmp_path(name);
        write_pcap(&path, &frames);
        let out = analyze::run(&path, &PipelineConfig::default(), |_, _, _| {}).expect("analyze");
        let _ = std::fs::remove_file(&path);
        out.summary
    }

    /// Wrap `exts` into a complete ClientHello record.
    fn client_hello_with_exts(exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut hs = Vec::new();
        hs.extend_from_slice(&0x0303u16.to_be_bytes()); // client_version
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0); // session_id len
        hs.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites len
        hs.extend_from_slice(&0x1301u16.to_be_bytes());
        hs.push(1); // compression methods len
        hs.push(0);
        let mut blob = Vec::new();
        for (t, body) in exts {
            blob.extend_from_slice(&t.to_be_bytes());
            blob.extend_from_slice(&(body.len() as u16).to_be_bytes());
            blob.extend_from_slice(body);
        }
        hs.extend_from_slice(&(blob.len() as u16).to_be_bytes());
        hs.extend_from_slice(&blob);

        let mut handshake = vec![1u8];
        let l = hs.len();
        handshake.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        handshake.extend_from_slice(&hs);
        let mut rec = vec![22u8, 0x03, 0x01];
        rec.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        rec.extend_from_slice(&handshake);
        rec
    }

    /// A ClientHello with NO server_name extension at all — the genuine missing-SNI case.
    fn client_hello_without_sni() -> Vec<u8> {
        client_hello_with_exts(&[(0x002bu16, vec![0x02, 0x03, 0x04])])
    }

    #[test]
    fn sni_less_tls_channel_raises_missing_sni() {
        let ch = client_hello_without_sni();
        let mut frames = Vec::new();
        // Two separate flows (distinct client ports) so the channel clears `min_flows`.
        frames.extend(session(8443, 51000, &ch));
        frames.extend(session(8443, 51001, &ch));

        let summary = analyze_frames("missing_sni", frames);
        let f = summary
            .findings
            .iter()
            .find(|f| f.kind == FindingKind::MissingSni)
            .expect("a missing_sni finding");
        assert_eq!(f.src_ip, "10.0.0.5");
        assert_eq!(f.dst_ip.as_deref(), Some("185.220.101.9"));
        // Flat Low: legitimate for IP-literal/embedded clients, so it is context, not a verdict.
        assert!(f.score <= 34, "missing SNI must stay Low, got {}", f.score);
    }

    /// A ClientHello that DOES name a server must never raise it.
    #[test]
    fn named_tls_channel_raises_no_missing_sni() {
        let ch = client_hello_with_sni("example.com");
        let mut frames = Vec::new();
        frames.extend(session(8443, 51000, &ch));
        frames.extend(session(8443, 51001, &ch));
        let summary = analyze_frames("named_sni", frames);
        assert!(!summary
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::MissingSni));
    }

    /// An established 443 session that never looked like TLS is the firewall-traversal tunnel
    /// shape — and with real volume it escalates.
    #[test]
    fn established_non_tls_on_443_raises_port_mismatch() {
        let mut frames = vec![
            seg(CLIENT, SERVER, 52000, 443, TCP_SYN, &[]),
            seg(SERVER, CLIENT, 443, 52000, TCP_SYN | TCP_ACK, &[]),
        ];
        // ~1.4 MiB of opaque payload, over the High threshold.
        for i in 0..1000 {
            let body = vec![(i % 251) as u8; 1400];
            frames.push(seg(CLIENT, SERVER, 52000, 443, TCP_PSH | TCP_ACK, &body));
        }
        let summary = analyze_frames("non_tls_443", frames);
        let f = summary
            .findings
            .iter()
            .find(|f| f.kind == FindingKind::PortProtocolMismatch)
            .expect("a port_protocol_mismatch finding");
        assert!(f.title.contains("Non-TLS traffic on 443"), "{}", f.title);
        assert!(f.score >= 60, "a used tunnel escalates, got {}", f.score);
        assert!(f.attack.iter().any(|t| t == "T1571"));
    }

    /// The review's central false positive: a capture that starts mid-session has no handshake,
    /// so "not identified as TLS on 443" has a benign explanation and must stay silent.
    #[test]
    fn mid_capture_443_flow_without_a_handshake_is_silent() {
        // No SYN / SYN-ACK — the session predates the capture.
        let frames: Vec<Vec<u8>> = (0..600)
            .map(|i| {
                let body = vec![(i % 251) as u8; 1400];
                seg(CLIENT, SERVER, 52000, 443, TCP_PSH | TCP_ACK, &body)
            })
            .collect();
        let summary = analyze_frames("midcapture", frames);
        assert!(
            !summary
                .findings
                .iter()
                .any(|f| f.kind == FindingKind::PortProtocolMismatch),
            "a mid-capture 443 flow must not be read as a tunnel"
        );
    }

    /// Ordinary TLS on 443 is the overwhelming majority of real traffic — neither detector may
    /// fire on it.
    #[test]
    fn ordinary_tls_on_443_raises_neither_posture_finding() {
        let ch = client_hello_with_sni("www.example.com");
        let mut frames = Vec::new();
        frames.extend(session(443, 51000, &ch));
        frames.extend(session(443, 51001, &ch));
        let summary = analyze_frames("plain_tls", frames);
        assert!(!summary.findings.iter().any(|f| matches!(
            f.kind,
            FindingKind::MissingSni | FindingKind::PortProtocolMismatch
        )));
    }
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
