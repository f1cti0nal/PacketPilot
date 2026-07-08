//! Safe Share integration proof: sanitize → re-parse → re-analyze.
//!
//! Uses a hand-crafted capture with *known* sensitive values (addresses, MACs,
//! DNS names, HTTP host/credentials, TLS SNI, FTP credentials) and asserts:
//! - the sanitized output is a valid capture (our reader + the independent
//!   `pcap-file` crate both parse it, packet counts preserved),
//! - no original sensitive byte sequence survives anywhere in the output,
//! - same input value → same pseudonym across packets and protocols,
//! - L3/L4 checksums in the output verify,
//! - re-analysis of the sanitized capture matches the original's totals,
//! - the manifest carries hashes + counts and never the key or original values.

use ppcap_core::sanitize::{
    sanitize_bytes, sanitize_file, PayloadMode, SanitizeFormat, SanitizeOptions,
};
use ppcap_core::PipelineConfig;

const KEY: [u8; 32] = [42u8; 32];

// ---------------------------------------------------------------------------
// Capture crafting helpers (pure bytes; no engine internals)
// ---------------------------------------------------------------------------

const MAC_A: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01];
const MAC_B: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02];
const IP_CLIENT: [u8; 4] = [192, 0, 2, 10];
const IP_SERVER: [u8; 4] = [198, 51, 100, 53];

fn eth_frame(src: [u8; 6], dst: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn ipv4_packet(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
    let total = 20 + l4.len() as u16;
    let mut p = vec![0x45, 0x00];
    p.extend_from_slice(&total.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, proto, 0, 0]);
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(l4);
    p
}

fn udp_segment(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len() as u16;
    let mut s = Vec::new();
    s.extend_from_slice(&sport.to_be_bytes());
    s.extend_from_slice(&dport.to_be_bytes());
    s.extend_from_slice(&len.to_be_bytes());
    s.extend_from_slice(&[0x12, 0x34]); // bogus checksum; sanitizer recomputes
    s.extend_from_slice(payload);
    s
}

fn tcp_segment(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&sport.to_be_bytes());
    s.extend_from_slice(&dport.to_be_bytes());
    s.extend_from_slice(&1u32.to_be_bytes()); // seq
    s.extend_from_slice(&0u32.to_be_bytes()); // ack
    s.extend_from_slice(&[0x50, 0x18, 0xFF, 0xFF, 0xAB, 0xCD, 0x00, 0x00]);
    s.extend_from_slice(payload);
    s
}

/// DNS query for the given dot-separated name.
fn dns_query(name: &str) -> Vec<u8> {
    let mut m = vec![
        0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in name.split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    m
}

/// Minimal TLS ClientHello carrying an SNI extension for `host`.
fn client_hello(host: &str) -> Vec<u8> {
    let name = host.as_bytes();
    let mut ext = Vec::new();
    ext.extend_from_slice(&0u16.to_be_bytes());
    let list_len = (name.len() + 3) as u16;
    ext.extend_from_slice(&(list_len + 2).to_be_bytes());
    ext.extend_from_slice(&list_len.to_be_bytes());
    ext.push(0);
    ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
    ext.extend_from_slice(name);

    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x11; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut hs = vec![1u8];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
    hs.extend_from_slice(&body);

    let mut rec = vec![22u8, 3, 1];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// Assemble the test capture (classic pcap, LE µs, Ethernet).
fn crafted_capture() -> Vec<u8> {
    let frames: Vec<Vec<u8>> = vec![
        // 1: DNS query with a sensitive name
        eth_frame(
            MAC_A,
            MAC_B,
            0x0800,
            &ipv4_packet(
                IP_CLIENT,
                IP_SERVER,
                17,
                &udp_segment(51000, 53, &dns_query("secret.corp.internal")),
            ),
        ),
        // 2: cleartext HTTP with host + credentials + a body
        eth_frame(
            MAC_A,
            MAC_B,
            0x0800,
            &ipv4_packet(
                IP_CLIENT,
                IP_SERVER,
                6,
                &tcp_segment(
                    51001,
                    80,
                    b"GET /users/alice/report HTTP/1.1\r\nHost: files.corp.internal\r\nAuthorization: Basic Zm9vOmJhcg==\r\n\r\nPAYLOADDATA",
                ),
            ),
        ),
        // 3: TLS ClientHello with SNI
        eth_frame(
            MAC_A,
            MAC_B,
            0x0800,
            &ipv4_packet(
                IP_CLIENT,
                IP_SERVER,
                6,
                &tcp_segment(51002, 443, &client_hello("login.corp.internal")),
            ),
        ),
        // 4: FTP credentials
        eth_frame(
            MAC_A,
            MAC_B,
            0x0800,
            &ipv4_packet(
                IP_CLIENT,
                IP_SERVER,
                6,
                &tcp_segment(51003, 21, b"USER alice\r\nPASS hunter2\r\n"),
            ),
        ),
        // 5: ARP request naming both IPs and the client MAC
        eth_frame(MAC_A, [0xFF; 6], 0x0806, &{
            let mut arp = vec![0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01];
            arp.extend_from_slice(&MAC_A);
            arp.extend_from_slice(&IP_CLIENT);
            arp.extend_from_slice(&[0u8; 6]);
            arp.extend_from_slice(&IP_SERVER);
            arp
        }),
        // 6: ICMP time-exceeded embedding the original IPv4 header
        eth_frame(MAC_B, MAC_A, 0x0800, &{
            let embedded = ipv4_packet(IP_CLIENT, IP_SERVER, 17, &udp_segment(51000, 53, b""));
            let mut icmp = vec![11u8, 0, 0, 0, 0, 0, 0, 0];
            icmp.extend_from_slice(&embedded[..28.min(embedded.len())]);
            ipv4_packet(IP_SERVER, IP_CLIENT, 1, &icmp)
        }),
    ];

    let mut buf = Vec::new();
    buf.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&4u16.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&65535u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    for (i, f) in frames.iter().enumerate() {
        let ts_sec = 1_700_000_000u32 + i as u32;
        buf.extend_from_slice(&ts_sec.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&(f.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(f.len() as u32).to_le_bytes());
        buf.extend_from_slice(f);
    }
    buf
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Parse a classic pcap byte buffer into (ts_us, frame) pairs. LE µs only —
/// exactly what the sanitizer emits.
fn parse_pcap(bytes: &[u8]) -> Vec<(u64, Vec<u8>)> {
    assert!(bytes.len() >= 24, "missing global header");
    assert_eq!(&bytes[0..4], &0xa1b2c3d4u32.to_le_bytes());
    let mut out = Vec::new();
    let mut pos = 24;
    while pos + 16 <= bytes.len() {
        let sec = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as u64;
        let usec = u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into().unwrap()) as u64;
        let caplen = u32::from_le_bytes(bytes[pos + 8..pos + 12].try_into().unwrap()) as usize;
        pos += 16;
        out.push((sec * 1_000_000 + usec, bytes[pos..pos + caplen].to_vec()));
        pos += caplen;
    }
    out
}

/// RFC 1071 sum for verification (a message including its own correct checksum
/// sums to 0xFFFF before complement, i.e. the complemented sum is 0).
fn ones_sum(parts: &[&[u8]]) -> u16 {
    let mut bytes = Vec::new();
    for p in parts {
        bytes.extend_from_slice(p);
    }
    if bytes.len() % 2 == 1 {
        bytes.push(0);
    }
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u32::from_be_bytes([0, 0, pair[0], pair[1]]);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Verify every IPv4 header + TCP/UDP checksum in an Ethernet frame.
fn assert_frame_checksums_valid(frame: &[u8]) {
    if frame.len() < 34 || u16::from_be_bytes([frame[12], frame[13]]) != 0x0800 {
        return;
    }
    let ip = &frame[14..];
    let ihl = ((ip[0] & 0x0F) as usize) * 4;
    assert_eq!(
        ones_sum(&[&ip[..ihl]]),
        0,
        "IPv4 header checksum must verify"
    );
    let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    let l4 = &ip[ihl..total.min(ip.len())];
    let src: [u8; 4] = ip[12..16].try_into().unwrap();
    let dst: [u8; 4] = ip[16..20].try_into().unwrap();
    let proto = ip[9];
    if matches!(proto, 6 | 17) && !l4.is_empty() {
        // UDP checksum 0 = "not computed" (only legal for UDP).
        if proto == 17 && l4[6] == 0 && l4[7] == 0 {
            return;
        }
        let len = (l4.len() as u16).to_be_bytes();
        let pseudo = [
            src[0], src[1], src[2], src[3], dst[0], dst[1], dst[2], dst[3], 0, proto, len[0],
            len[1],
        ];
        assert_eq!(
            ones_sum(&[&pseudo, l4]),
            0,
            "L4 checksum must verify (proto {proto})"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn scrub_mode_leaks_nothing_and_stays_loadable() {
    let capture = crafted_capture();
    let opts = SanitizeOptions::default();
    let (out, manifest) = sanitize_bytes(&capture, KEY, &opts, 1_752_000_000).unwrap();

    // Structure: same packet count, each frame same length as its input twin.
    let orig = parse_pcap(&capture);
    let got = parse_pcap(&out);
    assert_eq!(got.len(), orig.len(), "packet count preserved");
    for ((_, a), (_, b)) in orig.iter().zip(got.iter()) {
        assert_eq!(a.len(), b.len(), "frame lengths never change");
    }
    assert_eq!(manifest.counts.packets_written, orig.len() as u64);

    // Privacy: nothing sensitive survives — addresses, MACs, names, creds, payload.
    for needle in [
        &b"secret"[..],
        b"corp",
        b"internal",
        b"alice",
        b"hunter2",
        b"Zm9vOmJhcg",
        b"PAYLOADDATA",
        &IP_CLIENT,
        &IP_SERVER,
        &MAC_A,
        &MAC_B,
    ] {
        assert!(
            !contains(&out, needle),
            "sensitive bytes {:?} must not survive scrub-mode sanitize",
            String::from_utf8_lossy(needle)
        );
    }

    // Validity: checksums verify on every rewritten frame.
    for (_, frame) in &got {
        assert_frame_checksums_valid(frame);
    }

    // Consistency: the client IP appears in frames 1–4 as src — all four must
    // carry the identical pseudonym.
    let pseudo_srcs: Vec<[u8; 4]> = got[..4]
        .iter()
        .map(|(_, f)| f[26..30].try_into().unwrap())
        .collect();
    assert!(
        pseudo_srcs.windows(2).all(|w| w[0] == w[1]),
        "same input IP must map to one pseudonym"
    );

    // Manifest: hashes present, key absent, counts plausible.
    let json = manifest.to_json_pretty().unwrap();
    assert_eq!(manifest.input_sha256.len(), 64);
    assert_eq!(manifest.output_sha256.len(), 64);
    assert!(
        !json.to_lowercase().contains("key"),
        "no key material in manifest"
    );
    assert!(manifest.counts.ipv4_rewritten >= 8);
    assert!(manifest.counts.macs_rewritten >= 4);
    assert!(manifest.counts.payload_bytes_scrubbed > 0);
    assert!(manifest.counts.arp_rewritten == 1);
    assert!(manifest.counts.embedded_headers_rewritten == 1);
}

#[test]
fn keep_mode_redacts_l7_fields_but_keeps_bodies() {
    let capture = crafted_capture();
    let opts = SanitizeOptions {
        payload: PayloadMode::Keep,
        ..SanitizeOptions::default()
    };
    let (out, manifest) = sanitize_bytes(&capture, KEY, &opts, 0).unwrap();

    // Sensitive L7 fields gone even though payloads are kept.
    for needle in [
        &b"secret"[..],
        b"corp",
        b"internal",
        b"login",
        b"alice",
        b"hunter2",
        b"Zm9vOmJhcg",
    ] {
        assert!(
            !contains(&out, needle),
            "L7-sensitive bytes {:?} must be redacted in keep mode",
            String::from_utf8_lossy(needle)
        );
    }
    // The HTTP body is intentionally kept in Keep mode.
    assert!(contains(&out, b"PAYLOADDATA"));
    // Non-sensitive protocol text survives too (proof we didn't blanket-scrub).
    assert!(contains(&out, b"GET /"));
    assert!(contains(&out, b"Host: "));

    assert!(manifest.counts.dns_names_redacted >= 1);
    assert!(manifest.counts.http_fields_redacted >= 3);
    assert!(manifest.counts.tls_snis_redacted == 1);
    assert!(manifest.counts.credentials_redacted == 2);
    assert_eq!(manifest.counts.payload_bytes_scrubbed, 0);

    // Cross-protocol consistency: DNS, SNI, and Host all contained the label
    // "corp"; its token must be identical everywhere it appears. Extract the
    // token from the DNS question (frame 1: 14 eth + 20 ip + 8 udp + 12 dns hdr,
    // then len-prefixed labels: secret(6) . corp(4) . internal(8)).
    let frames = parse_pcap(&out);
    let dns = &frames[0].1;
    let q = 14 + 20 + 8 + 12;
    assert_eq!(dns[q], 6);
    let corp_token = dns[q + 8..q + 12].to_vec(); // after len byte 4
    assert_eq!(dns[q + 7], 4, "label length bytes unchanged");
    // The same 4-byte token must appear in the TLS frame (SNI) and HTTP frame (Host).
    assert!(
        contains(&frames[2].1, &corp_token),
        "SNI shares the label token"
    );
    assert!(
        contains(&frames[1].1, &corp_token),
        "HTTP Host shares the label token"
    );

    // Checksums still verify with payloads kept + redacted.
    for (_, frame) in &frames {
        assert_frame_checksums_valid(frame);
    }
}

#[test]
fn time_shift_moves_all_timestamps_uniformly() {
    let capture = crafted_capture();
    let opts = SanitizeOptions {
        time_shift_secs: -3600,
        ..SanitizeOptions::default()
    };
    let (out, _) = sanitize_bytes(&capture, KEY, &opts, 0).unwrap();
    let orig = parse_pcap(&capture);
    let got = parse_pcap(&out);
    for ((a, _), (b, _)) in orig.iter().zip(got.iter()) {
        assert_eq!(
            a - 3_600_000_000,
            *b,
            "constant shift, relative timing intact"
        );
    }
}

#[test]
fn pcapng_output_is_valid_and_counts_match() {
    let capture = crafted_capture();
    let opts = SanitizeOptions {
        format: SanitizeFormat::PcapNg,
        ..SanitizeOptions::default()
    };
    let (out, manifest) = sanitize_bytes(&capture, KEY, &opts, 0).unwrap();

    // Independent cross-validation with the pcap-file crate.
    let mut reader = pcap_file::pcapng::PcapNgReader::new(std::io::Cursor::new(out.clone()))
        .expect("pcap-file must open the sanitized pcapng");
    let mut packets = 0u64;
    while let Some(block) = reader.next_block() {
        let block = block.expect("valid block");
        if matches!(block, pcap_file::pcapng::Block::EnhancedPacket(_)) {
            packets += 1;
        }
    }
    assert_eq!(packets, manifest.counts.packets_written);

    // And our own reader re-ingests it.
    let src = ppcap_core::reader::open_reader(std::io::Cursor::new(out), None).unwrap();
    let mut n = 0u64;
    let mut src = src;
    while src.next_frame().unwrap().is_some() {
        n += 1;
    }
    assert_eq!(n, packets);
}

#[test]
fn sanitized_capture_reanalyzes_with_same_totals() {
    let capture = crafted_capture();
    let (out, _) = sanitize_bytes(&capture, KEY, &SanitizeOptions::default(), 0).unwrap();

    let cfg = PipelineConfig::default();
    let analyze = |bytes: &[u8]| {
        let src = ppcap_core::reader::open_reader(
            std::io::Cursor::new(bytes.to_vec()),
            Some(bytes.len() as u64),
        )
        .unwrap();
        ppcap_core::run_source_visiting(
            src,
            "t.pcap",
            bytes.len() as u64,
            &cfg,
            &mut |_| {},
            |_, _, _| {},
        )
        .unwrap()
    };
    let before = analyze(&capture);
    let after = analyze(&out);
    assert_eq!(
        before.summary.total_packets, after.summary.total_packets,
        "packet totals preserved through sanitize"
    );
    assert_eq!(
        before.summary.total_flows, after.summary.total_flows,
        "flow totals preserved through sanitize (bijective address mapping)"
    );
}

#[test]
fn synthetic_capture_file_roundtrip_via_sanitize_file() {
    use ppcap_core::gen::{GenConfig, Scenario, SynthGen};

    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("in.pcap");
    let output = dir.path().join("out.pcap");

    let mut g = SynthGen::new(GenConfig {
        scenario: Scenario::from_str_opt("mixed").unwrap(),
        packets: 800,
        seed: 7,
        ..Default::default()
    });
    let gen_manifest = g.write_pcap(&input).unwrap();

    let manifest = sanitize_file(
        &input,
        &output,
        None,
        &SanitizeOptions::default(),
        1_752_000_000,
        |_, _, _| {},
    )
    .unwrap();
    assert_eq!(manifest.counts.packets_read, gen_manifest.packets_written);
    assert_eq!(
        manifest.counts.packets_written,
        gen_manifest.packets_written
    );

    // The default manifest sidecar exists and parses.
    let sidecar = dir.path().join("out.pcap.manifest.json");
    let text = std::fs::read_to_string(&sidecar).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["tool"], "packetpilot");
    assert_eq!(v["counts"]["packets_written"], gen_manifest.packets_written);

    // Full pipeline re-analysis of the sanitized file succeeds with equal totals.
    let cfg = PipelineConfig::default();
    let before = ppcap_core::run(&input, &cfg, |_, _, _| {}).unwrap();
    let after = ppcap_core::run(&output, &cfg, |_, _, _| {}).unwrap();
    assert_eq!(before.summary.total_packets, after.summary.total_packets);
    assert_eq!(before.summary.total_flows, after.summary.total_flows);
}
