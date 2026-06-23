//! JA3/JA4 pipeline-parity integration test.
//!
//! Asserts the native≡pipeline contract: `fingerprint_tls_client_hello` and the
//! decode→flow path produce *identical* JA3/JA4 values for the same ClientHello payload.
//!
//! Approach: build a well-formed TLS ClientHello byte buffer, call
//! `fingerprint_tls_client_hello` on it directly, then feed the same bytes through
//! `decode::decode_frame` → `FlowRecord::observe` (exactly what the live pipeline does for
//! every TCP packet that carries a recognizable ClientHello). Assert the flow's `ja3`/`ja4`
//! fields equal the direct-fingerprint result.
//!
//! No file I/O, no `run`, no Parquet — the focus is the decode→flow seam where JA3/JA4 is
//! extracted and stored. This keeps the test fast and free of tempfile/tempdir dependencies.

use std::net::{IpAddr, Ipv4Addr};

use ppcap_core::decode::decode_frame;
use ppcap_core::fingerprint_tls_client_hello;
use ppcap_core::model::flow::{FlowKey, FlowRecord};
use ppcap_core::model::packet::Transport;
use ppcap_core::reader::{LinkType, RawFrame};

// ── ClientHello builder (mirrors ch_tests in fingerprint/mod.rs) ─────────────────────────

/// Build a TLS record wrapping a ClientHello with the given parts (all big-endian on the wire).
fn make_client_hello(
    legacy_ver: u16,
    ciphers: &[u16],
    exts: &[(u16, Vec<u8>)], // (ext_type, ext_body)
) -> Vec<u8> {
    let mut hs = Vec::new();
    hs.extend_from_slice(&legacy_ver.to_be_bytes()); // client_version
    hs.extend_from_slice(&[0u8; 32]); // random
    hs.push(0); // session_id len 0
    let cs: Vec<u8> = ciphers.iter().flat_map(|c| c.to_be_bytes()).collect();
    hs.extend_from_slice(&(cs.len() as u16).to_be_bytes());
    hs.extend_from_slice(&cs);
    hs.push(1); // compression methods len
    hs.push(0); // null compression
    let mut ext_blob = Vec::new();
    for (t, body) in exts {
        ext_blob.extend_from_slice(&t.to_be_bytes());
        ext_blob.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ext_blob.extend_from_slice(body);
    }
    hs.extend_from_slice(&(ext_blob.len() as u16).to_be_bytes());
    hs.extend_from_slice(&ext_blob);
    // Handshake header: type(1)=ClientHello + 3-byte length.
    let mut handshake = vec![1u8];
    let l = hs.len();
    handshake.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    handshake.extend_from_slice(&hs);
    // TLS record: content_type(22) version(0x0301) length(2).
    let mut rec = vec![22u8, 0x03, 0x01];
    rec.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    rec.extend_from_slice(&handshake);
    rec
}

/// SNI extension body for `host`.
fn sni_ext(host: &str) -> (u16, Vec<u8>) {
    let mut body = Vec::new();
    let entry_len = 1 + 2 + host.len();
    body.extend_from_slice(&(entry_len as u16).to_be_bytes()); // server_name_list len
    body.push(0); // name_type host_name
    body.extend_from_slice(&(host.len() as u16).to_be_bytes());
    body.extend_from_slice(host.as_bytes());
    (0x0000, body)
}

/// supported_groups / signature_algorithms extension (2-byte list-length prefix).
fn u16list_ext(t: u16, vals: &[u16]) -> (u16, Vec<u8>) {
    let inner: Vec<u8> = vals.iter().flat_map(|v| v.to_be_bytes()).collect();
    let mut body = (inner.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(&inner);
    (t, body)
}

/// supported_versions extension (1-byte list-length prefix, RFC 8446 §4.2.1).
fn supported_versions_ext(vals: &[u16]) -> (u16, Vec<u8>) {
    let inner: Vec<u8> = vals.iter().flat_map(|v| v.to_be_bytes()).collect();
    let mut body = vec![inner.len() as u8];
    body.extend_from_slice(&inner);
    (0x002b, body)
}

// ── Ethernet/IPv4/TCP frame builder ──────────────────────────────────────────────────────

/// Compute a one's-complement internet checksum per RFC 1071.
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

/// Compute the IPv4 pseudo-header checksum contribution for a TCP segment.
fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + segment.len());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.push(0);
    buf.push(6); // TCP
    buf.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    buf.extend_from_slice(segment);
    inet_checksum(&buf)
}

/// Build a complete Ethernet+IPv4+TCP frame carrying `payload` from `src`:`sport` to
/// `dst`:`dport`. Returns the raw bytes ready for `decode_frame`.
fn eth_ipv4_tcp(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, payload: &[u8]) -> Vec<u8> {
    // TCP segment (20-byte header, PSH|ACK, no options).
    let tcp_len = 20 + payload.len();
    let mut tcp = Vec::with_capacity(tcp_len);
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&dport.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes()); // seq
    tcp.extend_from_slice(&0u32.to_be_bytes()); // ack
    tcp.push(0x50); // data offset 5
    tcp.push(0x18); // PSH|ACK
    tcp.extend_from_slice(&65535u16.to_be_bytes()); // window
    tcp.extend_from_slice(&[0, 0]); // checksum placeholder
    tcp.extend_from_slice(&[0, 0]); // urgent pointer
    tcp.extend_from_slice(payload);
    let cks = tcp_checksum(src, dst, &tcp);
    tcp[16..18].copy_from_slice(&cks.to_be_bytes());

    // IPv4 header (20 bytes).
    let total_len = (20 + tcp.len()) as u16;
    let mut ip = Vec::with_capacity(20);
    ip.push(0x45); // version 4, IHL 5
    ip.push(0);
    ip.extend_from_slice(&total_len.to_be_bytes());
    ip.extend_from_slice(&[0, 1]); // id
    ip.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
    ip.push(64); // TTL
    ip.push(6); // TCP
    ip.extend_from_slice(&[0, 0]); // checksum placeholder
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let ip_cks = inet_checksum(&ip);
    ip[10..12].copy_from_slice(&ip_cks.to_be_bytes());

    // Ethernet II header (14 bytes): dst mac, src mac, ethertype 0x0800.
    let mut frame = Vec::with_capacity(14 + ip.len() + tcp.len());
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // dst mac
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // src mac
    frame.extend_from_slice(&[0x08, 0x00]); // IPv4
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    frame
}

// ── Pipeline parity tests ─────────────────────────────────────────────────────────────────

/// Core parity helper: given a ClientHello payload, assert that the decode→flow path
/// populates `ja3`/`ja4` identically to `fingerprint_tls_client_hello`.
///
/// The `ch_payload` bytes ARE the TLS record (what sits in the TCP payload after headers).
fn assert_pipeline_parity(ch_payload: &[u8], label: &str) {
    // 1. Ground-truth from the direct fingerprinting function.
    let expected = fingerprint_tls_client_hello(ch_payload)
        .unwrap_or_else(|| panic!("{label}: fingerprint_tls_client_hello returned None"));

    // 2. Wrap in Ethernet+IPv4+TCP and decode through the full frame decoder.
    let src = Ipv4Addr::new(10, 0, 0, 1);
    let dst = Ipv4Addr::new(10, 0, 0, 2);
    let sport: u16 = 51234;
    let dport: u16 = 443;
    let raw = eth_ipv4_tcp(src, sport, dst, dport, ch_payload);

    let frame = RawFrame {
        index: 0,
        ts_ns: 1_000_000_000,
        iface_id: 0,
        wire_len: raw.len() as u32,
        cap_len: raw.len() as u32,
        link_type: LinkType::Ethernet,
        data: &raw,
    };
    let meta = decode_frame(&frame).unwrap_or_else(|e| panic!("{label}: decode_frame failed: {e}"));

    // Sanity: the decode must recognise this as TCP from the right endpoints.
    assert_eq!(meta.transport, Transport::Tcp, "{label}: transport");
    assert_eq!(meta.src_ip, Some(IpAddr::V4(src)), "{label}: src_ip");
    assert_eq!(meta.dst_port, dport, "{label}: dst_port");

    // The pipeline must have extracted ja3/ja4 from the ClientHello.
    assert_eq!(
        meta.ja3.as_deref(),
        Some(expected.ja3.as_str()),
        "{label}: meta.ja3 != fingerprint result"
    );
    assert_eq!(
        meta.ja4.as_deref(),
        Some(expected.ja4.as_str()),
        "{label}: meta.ja4 != fingerprint result"
    );

    // 3. Feed into FlowRecord::observe and confirm the flow carries the same values.
    let (key, dir) = FlowKey::normalized(
        IpAddr::V4(src),
        sport,
        IpAddr::V4(dst),
        dport,
        Transport::Tcp,
    );
    let mut flow = FlowRecord::new(key, meta.ts_ns);
    flow.observe(&meta, dir);

    assert_eq!(
        flow.ja3.as_deref(),
        Some(expected.ja3.as_str()),
        "{label}: flow.ja3 != fingerprint result"
    );
    assert_eq!(
        flow.ja4.as_deref(),
        Some(expected.ja4.as_str()),
        "{label}: flow.ja4 != fingerprint result"
    );
}

// ── Test cases ────────────────────────────────────────────────────────────────────────────

#[test]
fn pipeline_emits_ja3_ja4_for_tls12_client_hello() {
    // A TLS 1.2 ClientHello with two ciphers, SNI, and supported-groups — the common shape
    // seen in most real TLS 1.2 handshakes. No supported_versions extension so the ja4_a
    // ver-code is derived from the legacy_version field (0x0303 → "12").
    let ch = make_client_hello(
        0x0303,
        &[0xc02b, 0xc02f],
        &[
            sni_ext("api.example.com"),
            u16list_ext(0x000a, &[0x001d, 0x0017]), // supported_groups
            u16list_ext(0x000d, &[0x0403, 0x0503]), // signature_algorithms
            (0x000b, vec![1, 0]),                   // ec_point_formats: len1, [0]
        ],
    );
    assert_pipeline_parity(&ch, "tls12");
}

#[test]
fn pipeline_emits_ja3_ja4_for_tls13_client_hello() {
    // A TLS 1.3 ClientHello (supported_versions extension with 0x0304). The ja4_a ver-code
    // must be derived from supported_versions, not from the TLS 1.2 legacy_version field.
    let ch = make_client_hello(
        0x0303, // legacy field always 0x0303 in TLS 1.3
        &[0x1301, 0x1302, 0xc02b],
        &[
            supported_versions_ext(&[0x0304, 0x0303]), // TLS 1.3 preferred
            sni_ext("secure.example.net"),
            u16list_ext(0x000a, &[0x001d, 0x0017, 0x0018]), // supported_groups
            u16list_ext(0x000d, &[0x0403, 0x0804, 0x0401]), // signature_algorithms
        ],
    );
    assert_pipeline_parity(&ch, "tls13");
}

#[test]
fn pipeline_emits_ja3_ja4_grease_filtered() {
    // ClientHello with GREASE values in ciphers and extensions (RFC 8701). Both JA3 and JA4
    // must strip GREASE before hashing — the parity contract covers this filtering too.
    let ch = make_client_hello(
        0x0303,
        &[0x0a0a /* GREASE */, 0xc02b, 0xc030],
        &[
            (0x1a1a, vec![]), // GREASE extension — must be stripped from JA3/JA4
            sni_ext("grease.example"),
            u16list_ext(0x000a, &[0x0a0a /* GREASE */, 0x001d, 0x0017]),
            (0x000b, vec![1, 0]),
        ],
    );
    assert_pipeline_parity(&ch, "grease_filtered");
}

#[test]
fn flow_ja3_ja4_sticky_on_subsequent_packets() {
    // After the first ClientHello populates ja3/ja4, a second packet (no ClientHello) must
    // NOT overwrite the already-stored fingerprints (first-wins / sticky contract).
    let ch = make_client_hello(0x0303, &[0xc02b], &[sni_ext("sticky.example")]);
    let expected = fingerprint_tls_client_hello(&ch).expect("valid client hello");

    let src = Ipv4Addr::new(10, 1, 0, 1);
    let dst = Ipv4Addr::new(10, 1, 0, 2);
    let sport: u16 = 40000;
    let dport: u16 = 443;

    // Frame 1: the ClientHello.
    let raw1 = eth_ipv4_tcp(src, sport, dst, dport, &ch);
    let frame1 = RawFrame {
        index: 0,
        ts_ns: 1_000,
        iface_id: 0,
        wire_len: raw1.len() as u32,
        cap_len: raw1.len() as u32,
        link_type: LinkType::Ethernet,
        data: &raw1,
    };
    let meta1 = decode_frame(&frame1).expect("frame1 decode");

    // Frame 2: a bare ACK (no payload — no ClientHello, ja3/ja4 are None on the packet).
    let raw2 = eth_ipv4_tcp(src, sport, dst, dport, &[]);
    let frame2 = RawFrame {
        index: 1,
        ts_ns: 2_000,
        iface_id: 0,
        wire_len: raw2.len() as u32,
        cap_len: raw2.len() as u32,
        link_type: LinkType::Ethernet,
        data: &raw2,
    };
    let meta2 = decode_frame(&frame2).expect("frame2 decode");
    assert!(meta2.ja3.is_none(), "bare ACK must not carry ja3");

    let (key, dir) = FlowKey::normalized(
        IpAddr::V4(src),
        sport,
        IpAddr::V4(dst),
        dport,
        Transport::Tcp,
    );
    let mut flow = FlowRecord::new(key, meta1.ts_ns);
    flow.observe(&meta1, dir);
    flow.observe(&meta2, dir);

    // After both packets, flow must still hold the first ClientHello's fingerprints.
    assert_eq!(
        flow.ja3.as_deref(),
        Some(expected.ja3.as_str()),
        "sticky: ja3 must be first-seen"
    );
    assert_eq!(
        flow.ja4.as_deref(),
        Some(expected.ja4.as_str()),
        "sticky: ja4 must be first-seen"
    );
}
