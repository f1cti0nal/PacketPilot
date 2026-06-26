//! Focused L7/SNI enrichment proofs (decode -> flow.observe -> classify, end to end).
//!
//! These complement the per-module unit tests in `decode` (frame -> hint) and `classify`
//! (hint -> category) by exercising the *full* chain on real, byte-built frames:
//!
//!  1. An HTTP request on a NON-standard port (8080 here, plus a truly unnamed 31337) is
//!     decoded, folded into a bidirectional flow, classified, and must come out
//!     `Category::Web` with `app_proto == "http"` and `app_proto_src == Some("payload")` —
//!     i.e. the payload sniff takes precedence over the (absent) well-known-port signal.
//!  2. A TLS ClientHello carrying an SNI server_name is decoded and the SNI host is captured
//!     onto the flow (`FlowRecord::sni`), with `app_proto == "tls"`, src `payload`.
//!  3. The real pipeline (`analyze::run`) over a hand-built mixed pcap (HTTP/8080, a
//!     well-formed TLS ClientHello with SNI, and a DNS query) -> Parquet read-back asserts at
//!     least one flow has a non-NULL `app_proto_src` and at least one a non-NULL `sni`, and
//!     prints a sample flow row.
//!
//! Frames are byte-built here (not via the crate-private `gen::frames`) so this stays a pure
//! black-box integration test against the public API.

use std::net::Ipv4Addr;

use arrow_array::{Array, StringArray, UInt16Array, UInt8Array};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use ppcap_core::classify::{Classifier, ClassifyConfig};
use ppcap_core::decode::decode_frame;
use ppcap_core::model::flow::{FlowKey, FlowRecord};
use ppcap_core::model::packet::AppProto;
use ppcap_core::reader::{LinkType, RawFrame};

const ETHERTYPE_IPV4: u16 = 0x0800;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;
const TCP_ACK: u8 = 0x10;
const TCP_PSH: u8 = 0x08;

const SRV: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10); // server (TEST-NET-3)
const CLI: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7); // client (TEST-NET-2)

// --------------------------------------------------------------------------------------
// Minimal, self-contained frame builders with correct checksums.
// --------------------------------------------------------------------------------------

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

fn build_ethernet(ethertype: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(14);
    v.extend_from_slice(&[0x06; 6]); // dst mac
    v.extend_from_slice(&[0x02; 6]); // src mac
    v.extend_from_slice(&ethertype.to_be_bytes());
    v
}

fn build_ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, l4_len: usize) -> Vec<u8> {
    let total_len = (20 + l4_len) as u16;
    let mut h = Vec::with_capacity(20);
    h.push(0x45); // v4, IHL 5
    h.push(0x00);
    h.extend_from_slice(&total_len.to_be_bytes());
    h.extend_from_slice(&0u16.to_be_bytes()); // id
    h.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
    h.push(64); // ttl
    h.push(proto);
    h.extend_from_slice(&[0, 0]); // checksum placeholder
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

fn build_tcp(src: Ipv4Addr, dst: Ipv4Addr, sp: u16, dp: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
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
    seg.push(0x50); // data offset 5
    seg.push(flags);
    seg.extend_from_slice(&64240u16.to_be_bytes());
    seg.extend_from_slice(&[0, 0]); // checksum placeholder
    seg.extend_from_slice(&[0, 0]); // urgent
    seg.extend_from_slice(payload);
    let cks = l4_checksum(src, dst, IP_PROTO_TCP, &seg);
    seg[16..18].copy_from_slice(&cks.to_be_bytes());
    seg
}

fn build_udp(src: Ipv4Addr, dst: Ipv4Addr, sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let len = (8 + payload.len()) as u16;
    let mut seg = Vec::with_capacity(8 + payload.len());
    seg.extend_from_slice(&sp.to_be_bytes());
    seg.extend_from_slice(&dp.to_be_bytes());
    seg.extend_from_slice(&len.to_be_bytes());
    seg.extend_from_slice(&[0, 0]); // checksum placeholder
    seg.extend_from_slice(payload);
    let mut cks = l4_checksum(src, dst, IP_PROTO_UDP, &seg);
    if cks == 0 {
        cks = 0xFFFF;
    }
    seg[6..8].copy_from_slice(&cks.to_be_bytes());
    seg
}

fn http_request_payload(host: &str, path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ppcap-proof\r\n\r\n").into_bytes()
}

fn dns_query_payload(qname: &str, txid: u16) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&txid.to_be_bytes());
    v.extend_from_slice(&0x0100u16.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    v.extend_from_slice(&[0u8; 6]); // an/ns/ar counts
    for label in qname.split('.').filter(|l| !l.is_empty()) {
        let b = label.as_bytes();
        let n = b.len().min(63);
        v.push(n as u8);
        v.extend_from_slice(&b[..n]);
    }
    v.push(0x00);
    v.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    v.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    v
}

/// A fully well-formed TLS ClientHello record carrying an SNI `host` (strict-parser path).
fn well_formed_client_hello(host: &str) -> Vec<u8> {
    let mut hs_body = Vec::new();
    hs_body.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
    hs_body.extend_from_slice(&[0u8; 32]); // random
    hs_body.push(0); // session_id length 0
    hs_body.extend_from_slice(&[0x00, 0x02]); // cipher_suites length 2
    hs_body.extend_from_slice(&[0x00, 0x2f]); // one cipher suite
    hs_body.push(1); // compression methods length 1
    hs_body.push(0); // null compression

    let hb = host.as_bytes();
    let mut entry = Vec::new();
    entry.push(0); // name_type host_name
    entry.extend_from_slice(&(hb.len() as u16).to_be_bytes());
    entry.extend_from_slice(hb);
    let mut snl = Vec::new();
    snl.extend_from_slice(&(entry.len() as u16).to_be_bytes());
    snl.extend_from_slice(&entry);
    let mut exts = Vec::new();
    exts.extend_from_slice(&[0x00, 0x00]); // extension type server_name
    exts.extend_from_slice(&(snl.len() as u16).to_be_bytes());
    exts.extend_from_slice(&snl);

    hs_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hs_body.extend_from_slice(&exts);

    let mut handshake = Vec::new();
    handshake.push(1); // ClientHello
    let len = hs_body.len();
    handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    handshake.extend_from_slice(&hs_body);

    let mut record = Vec::new();
    record.push(22); // content_type handshake
    record.extend_from_slice(&[0x03, 0x01]); // record version
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn ipv4_tcp(src: Ipv4Addr, dst: Ipv4Addr, sp: u16, dp: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let tcp = build_tcp(src, dst, sp, dp, flags, payload);
    let mut pkt = build_ipv4(src, dst, IP_PROTO_TCP, tcp.len());
    pkt.extend_from_slice(&tcp);
    pkt
}

fn ipv4_udp(src: Ipv4Addr, dst: Ipv4Addr, sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let udp = build_udp(src, dst, sp, dp, payload);
    let mut pkt = build_ipv4(src, dst, IP_PROTO_UDP, udp.len());
    pkt.extend_from_slice(&udp);
    pkt
}

fn eth_wrap(l3: &[u8]) -> Vec<u8> {
    let mut eth = build_ethernet(ETHERTYPE_IPV4);
    eth.extend_from_slice(l3);
    eth
}

/// Wrap an L3 payload in Ethernet and decode it via the public `decode_frame`.
fn decode_eth(l3: &[u8], index: u64, ts_ns: i64) -> ppcap_core::PacketMeta {
    let eth = eth_wrap(l3);
    let frame = RawFrame {
        index,
        ts_ns,
        iface_id: 0,
        wire_len: eth.len() as u32,
        cap_len: eth.len() as u32,
        link_type: LinkType::Ethernet,
        data: &eth,
    };
    decode_frame(&frame).expect("frame decodes without error")
}

fn observe_into(
    table: &mut std::collections::HashMap<FlowKey, FlowRecord>,
    p: &ppcap_core::PacketMeta,
) -> FlowKey {
    let (key, dir) = FlowKey::from_packet(p).expect("ip packet has a flow key");
    let rec = table
        .entry(key)
        .or_insert_with(|| FlowRecord::new(key, p.ts_ns));
    rec.observe(p, dir);
    key
}

// --------------------------------------------------------------------------------------
// Proof 1: HTTP on a non-standard port classifies Web via payload precedence.
// --------------------------------------------------------------------------------------

#[test]
fn http_on_nonstandard_port_8080_is_web_via_payload_full_chain() {
    let cls = Classifier::new(ClassifyConfig::default());
    let mut table = std::collections::HashMap::new();

    let req = http_request_payload("intranet.local", "/dashboard");
    let c2s = ipv4_tcp(CLI, SRV, 49152, 8080, TCP_PSH | TCP_ACK, &req);
    let m1 = decode_eth(&c2s, 0, 1_000);
    assert_eq!(m1.dst_port, 8080, "request really is to port 8080");
    assert_eq!(
        m1.app_proto,
        AppProto::Http,
        "decoder sniffed HTTP from the payload"
    );

    let s2c = ipv4_tcp(SRV, CLI, 8080, 49152, TCP_ACK, b"");
    let m2 = decode_eth(&s2c, 1, 2_000);

    let key = observe_into(&mut table, &m1);
    observe_into(&mut table, &m2);

    let rec = table.get_mut(&key).unwrap();
    assert_eq!(
        rec.observed_app_proto,
        AppProto::Http,
        "flow aggregated the HTTP hint"
    );
    cls.classify(rec);

    assert_eq!(rec.category, ppcap_core::Category::Web, "HTTP/8080 -> Web");
    assert_eq!(
        rec.app_proto, "http",
        "payload token is http (not a port token)"
    );
    assert_eq!(
        rec.app_proto_src,
        Some("payload"),
        "derivation is payload precedence, not the port table"
    );
}

/// Same proof on a truly unnamed port (31337) where the port table yields NOTHING, so the
/// ONLY way to reach Web is the payload sniff.
#[test]
fn http_on_unnamed_port_31337_is_web_only_via_payload() {
    let cls = Classifier::new(ClassifyConfig::default());
    let mut table = std::collections::HashMap::new();

    let req = http_request_payload("c2.example", "/");
    let pkt = ipv4_tcp(CLI, SRV, 50000, 31337, TCP_PSH | TCP_ACK, &req);
    let m = decode_eth(&pkt, 0, 1_000);
    assert_eq!(m.app_proto, AppProto::Http);

    let key = observe_into(&mut table, &m);
    let rec = table.get_mut(&key).unwrap();
    cls.classify(rec);

    assert_eq!(rec.category, ppcap_core::Category::Web);
    assert_eq!(rec.app_proto, "http");
    assert_eq!(rec.app_proto_src, Some("payload"));
}

// --------------------------------------------------------------------------------------
// Proof 2: TLS ClientHello captures the SNI host onto the flow.
// --------------------------------------------------------------------------------------

#[test]
fn tls_client_hello_captures_sni_host_full_chain() {
    let cls = Classifier::new(ClassifyConfig::default());
    let mut table = std::collections::HashMap::new();

    // ClientHello on a deliberately non-standard TLS port (9443) so the classification is
    // payload-driven and the SNI extraction is the load-bearing assertion.
    let ch = well_formed_client_hello("secure.intranet.example");
    let c2s = ipv4_tcp(CLI, SRV, 51000, 9443, TCP_PSH | TCP_ACK, &ch);
    let m = decode_eth(&c2s, 0, 1_000);
    assert_eq!(
        m.app_proto,
        AppProto::Tls,
        "decoder recognized the ClientHello"
    );
    assert_eq!(
        m.sni.as_deref(),
        Some("secure.intranet.example"),
        "SNI parsed at decode"
    );

    let key = observe_into(&mut table, &m);
    let rec = table.get_mut(&key).unwrap();
    cls.classify(rec);

    assert_eq!(rec.category, ppcap_core::Category::Web);
    assert_eq!(rec.app_proto, "tls", "payload token tls, not port token");
    assert_eq!(rec.app_proto_src, Some("payload"));
    assert_eq!(
        rec.sni.as_deref(),
        Some("secure.intranet.example"),
        "SNI host captured onto the flow record"
    );
}

// --------------------------------------------------------------------------------------
// Proof 3: real pipeline (analyze::run) over a hand-built mixed pcap -> Parquet read-back.
// --------------------------------------------------------------------------------------

/// Write a tiny classic pcap (Ethernet link type) containing the given frames at 1ms spacing.
fn write_pcap(path: &std::path::Path, frames: &[Vec<u8>]) {
    use std::io::Write as _;
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic (usec)
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&4u16.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&65535u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes()); // DLT_EN10MB
    for (i, f) in frames.iter().enumerate() {
        let ts_usec = (i as u32) * 1000;
        buf.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        buf.extend_from_slice(&ts_usec.to_le_bytes());
        buf.extend_from_slice(&(f.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(f.len() as u32).to_le_bytes());
        buf.extend_from_slice(f);
    }
    std::fs::File::create(path)
        .unwrap()
        .write_all(&buf)
        .unwrap();
}

#[test]
fn pipeline_parquet_has_payload_src_and_sni() {
    use ppcap_core::analyze::{self, PipelineConfig};

    let http = eth_wrap(&ipv4_tcp(
        CLI,
        SRV,
        49152,
        8080,
        TCP_PSH | TCP_ACK,
        &http_request_payload("intranet.local", "/"),
    ));
    let http_ack = eth_wrap(&ipv4_tcp(SRV, CLI, 8080, 49152, TCP_ACK, b""));
    let tls = eth_wrap(&ipv4_tcp(
        CLI,
        SRV,
        51000,
        8443,
        TCP_PSH | TCP_ACK,
        &well_formed_client_hello("login.example.net"),
    ));
    let dns = eth_wrap(&ipv4_udp(
        CLI,
        Ipv4Addr::new(8, 8, 8, 8),
        40000,
        53,
        &dns_query_payload("www.example.com", 0x1234),
    ));

    let dir = tempfile::tempdir().unwrap();
    let pcap_path = dir.path().join("mixed_edge.pcap");
    let parquet_path = dir.path().join("flows.parquet");
    write_pcap(&pcap_path, &[http, http_ack, tls, dns]);

    let cfg = PipelineConfig {
        flows_parquet: Some(parquet_path.clone()),
        classify: ClassifyConfig {
            detect_scans: false,
            ..Default::default()
        },
        ..Default::default()
    };

    let out = analyze::run(&pcap_path, &cfg, |_, _, _| {}).expect("analyze the hand-built capture");
    assert_eq!(out.summary.decode_errors, 0, "all frames decode cleanly");
    assert!(
        out.summary.total_flows >= 3,
        "http, tls, dns flows observed"
    );

    let file = std::fs::File::open(&parquet_path).unwrap();
    let reader = ParquetRecordBatchReaderBuilder::try_new(file)
        .unwrap()
        .build()
        .unwrap();

    // (category, src_port, dst_port, app_proto, endpoint, app_proto_src, sni)
    // Local one-off test tuple collecting the columns asserted below; naming it
    // would add a type alias used in exactly one place.
    #[allow(clippy::type_complexity)]
    let mut rows: Vec<(
        String,
        u16,
        u16,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
    )> = Vec::new();
    for batch in reader {
        let batch = batch.unwrap();
        let src = batch
            .column(2)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let dst = batch
            .column(3)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let sp = batch
            .column(4)
            .as_any()
            .downcast_ref::<UInt16Array>()
            .unwrap();
        let dp = batch
            .column(5)
            .as_any()
            .downcast_ref::<UInt16Array>()
            .unwrap();
        let _proto = batch
            .column(6)
            .as_any()
            .downcast_ref::<UInt8Array>()
            .unwrap();
        let app = batch
            .column(7)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let cat = batch
            .column(16)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let aps = batch
            .column(17)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let sni = batch
            .column(18)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let opt = |a: &StringArray, i: usize| {
            if a.is_null(i) {
                None
            } else {
                Some(a.value(i).to_string())
            }
        };
        for i in 0..batch.num_rows() {
            rows.push((
                cat.value(i).to_string(),
                sp.value(i),
                dp.value(i),
                opt(app, i),
                format!("{}:{}", src.value(i), dst.value(i)),
                opt(aps, i),
                opt(sni, i),
            ));
        }
    }

    let payload_rows = rows
        .iter()
        .filter(|r| r.5.as_deref() == Some("payload"))
        .count();
    let sni_rows = rows.iter().filter(|r| r.6.is_some()).count();
    assert!(
        payload_rows >= 1,
        "at least one flow has app_proto_src=payload; rows={rows:?}"
    );
    assert!(
        sni_rows >= 1,
        "at least one flow has a non-null SNI; rows={rows:?}"
    );

    if let Some(r) = rows.iter().find(|r| r.6.is_some()) {
        println!(
            "SAMPLE FLOW ROW (tls+sni): category={} endpoint={} dst_port={} app_proto={:?} app_proto_src={:?} sni={:?}",
            r.0, r.4, r.2, r.3, r.5, r.6
        );
    }
    if let Some(r) = rows.iter().find(|r| r.2 == 8080) {
        println!(
            "SAMPLE FLOW ROW (http/8080): category={} endpoint={} dst_port={} app_proto={:?} app_proto_src={:?} sni={:?}",
            r.0, r.4, r.2, r.3, r.5, r.6
        );
    }
}

#[test]
fn carves_eicar_download_hash_and_raises_malware_finding() {
    use ppcap_core::analyze::{self, PipelineConfig};
    use ppcap_core::model::finding::FindingKind;

    // A cleartext HTTP response (server -> client) delivering the EICAR test file in one segment.
    let eicar = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;
    let mut resp =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 68\r\n\r\n"
            .to_vec();
    resp.extend_from_slice(eicar);
    let frame = eth_wrap(&ipv4_tcp(SRV, CLI, 80, 49152, TCP_PSH | TCP_ACK, &resp));

    let dir = tempfile::tempdir().unwrap();
    let pcap = dir.path().join("eicar.pcap");
    write_pcap(&pcap, &[frame]);

    let cfg = PipelineConfig {
        classify: ClassifyConfig {
            detect_scans: false,
            ..Default::default()
        },
        ..Default::default()
    };
    let out = analyze::run(&pcap, &cfg, |_, _, _| {}).expect("analyze the EICAR capture");

    // The body is carved and surfaced with its SHA-256 + known-bad flag.
    let cf = out
        .summary
        .carved_files
        .iter()
        .find(|c| c.size == 68)
        .expect("the 68-byte download is carved");
    assert_eq!(
        cf.sha256,
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    );
    assert!(cf.known_bad, "EICAR's hash is in the known-bad set");
    assert_eq!(cf.client, CLI.to_string());
    assert_eq!(cf.server, SRV.to_string());

    // ...and a Critical malware-download finding is raised, attributed to the downloading client.
    assert!(
        out.summary
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::MalwareDownload && f.src_ip == CLI.to_string()),
        "a MalwareDownload finding attributed to the client"
    );
}
