//! Flow key normalization: symmetry, total ordering, and bidirectional folding.

use std::cmp::Ordering;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ppcap_core::model::flow::{Direction, FlowKey, FlowRecord};
use ppcap_core::model::packet::{PacketMeta, Protocol, Transport};

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[test]
fn normalized_is_direction_symmetric() {
    let s = v4(10, 0, 0, 1);
    let d = v4(10, 0, 0, 2);
    let (k1, dir1) = FlowKey::normalized(s, 1234, d, 80, Transport::Tcp);
    let (k2, dir2) = FlowKey::normalized(d, 80, s, 1234, Transport::Tcp);
    assert_eq!(k1, k2, "same canonical key regardless of arrival direction");
    assert_ne!(dir1, dir2, "the two directions must be opposite");
    assert!(
        matches!(
            (dir1, dir2),
            (Direction::Forward, Direction::Reverse) | (Direction::Reverse, Direction::Forward)
        ),
        "directions must be one Forward and one Reverse"
    );
}

#[test]
fn ipv4_sorts_before_ipv6_total_order() {
    let a4 = v4(255, 255, 255, 255);
    let a6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    assert_eq!(
        FlowKey::endpoint_cmp((a4, 0), (a6, 0)),
        Ordering::Less,
        "any IPv4 sorts before any IPv6"
    );
    assert_eq!(
        FlowKey::endpoint_cmp((a6, 0), (a4, 0)),
        Ordering::Greater,
        "antisymmetry"
    );

    // Reflexive equality.
    assert_eq!(FlowKey::endpoint_cmp((a4, 5), (a4, 5)), Ordering::Equal);

    // Transitivity across a small sample: x < y < z => x < z.
    let x = (v4(1, 0, 0, 1), 10);
    let y = (v4(1, 0, 0, 2), 10);
    let z = (v4(2, 0, 0, 1), 10);
    assert_eq!(FlowKey::endpoint_cmp(x, y), Ordering::Less);
    assert_eq!(FlowKey::endpoint_cmp(y, z), Ordering::Less);
    assert_eq!(FlowKey::endpoint_cmp(x, z), Ordering::Less);

    // Port is the final tiebreak when addresses are equal.
    assert_eq!(FlowKey::endpoint_cmp((a4, 1), (a4, 2)), Ordering::Less);
}

#[test]
fn ipv4_mapped_ipv6_stays_ipv6() {
    // ::ffff:1.2.3.4 is an IpAddr::V6 and must keep the IPv6 family tag (no un-mapping).
    let mapped: IpAddr = "::ffff:1.2.3.4".parse().unwrap();
    assert!(matches!(mapped, IpAddr::V6(_)));
    let genuine_v4 = v4(255, 255, 255, 255);
    assert_eq!(
        FlowKey::endpoint_cmp((genuine_v4, 0), (mapped, 0)),
        Ordering::Less,
        "IPv4-mapped IPv6 must sort AFTER all genuine IPv4 endpoints"
    );
}

#[test]
fn observe_folds_fwd_and_rev() {
    let s = v4(10, 0, 0, 1);
    let d = v4(10, 0, 0, 2);
    let (key, fwd_dir) = FlowKey::normalized(s, 1234, d, 80, Transport::Tcp);
    let rev_dir = match fwd_dir {
        Direction::Forward => Direction::Reverse,
        Direction::Reverse => Direction::Forward,
    };

    let mut rec = FlowRecord::new(key, 500);

    let fwd = PacketMeta {
        index: 0,
        ts_ns: 500,
        iface_id: 0,
        wire_len: 74,
        cap_len: 74,
        l3: Protocol::Ipv4,
        transport: Transport::Tcp,
        src_ip: Some(s),
        dst_ip: Some(d),
        src_port: 1234,
        dst_port: 80,
        tcp_flags: 0x02, // SYN
        ttl: 64,
        payload_len: 0,
        vlan: None,
        app_proto: ppcap_core::model::packet::AppProto::Unknown,
        sni: None,
        ja3: None,
        ja4: None,
        dns_qname: None,
        dns_answers: Vec::new(),
        cleartext_cred: None,
        pii: None,
        icmp_type: None,
        tls_version: None,
        tls_cipher: None,
        hassh: None,
        hassh_server: None,
        arp: None,
        ja3s: None,
        http_host: None,
        http_ua: None,
        download: None,
        download_disguised: false,
        stratum: None,
        dhcp: None,
    };
    let mut rev = fwd.clone();
    rev.ts_ns = 900;
    rev.wire_len = 60;
    rev.cap_len = 60;
    rev.src_ip = Some(d);
    rev.dst_ip = Some(s);
    rev.src_port = 80;
    rev.dst_port = 1234;
    rev.tcp_flags = 0x12; // SYN|ACK
    rev.ttl = 128;

    // Fold one packet in each canonical direction.
    rec.observe(&fwd, fwd_dir);
    rec.observe(&rev, rev_dir);

    assert_eq!(rec.pkts_fwd, 1);
    assert_eq!(rec.pkts_rev, 1);
    assert_eq!(rec.bytes_fwd, 74);
    assert_eq!(rec.bytes_rev, 60);
    // sticky-OR of flags in the forward direction; ttl_min tracks forward only.
    assert_eq!(rec.tcp_flags_fwd, 0x02);
    assert_eq!(rec.tcp_flags_rev, 0x12);
    assert_eq!(rec.ttl_min_fwd, 64);
    assert_eq!(rec.first_ts_ns, 500);
    assert_eq!(rec.last_ts_ns, 900);
    assert_eq!(rec.total_pkts(), 2);
    assert_eq!(rec.total_bytes(), 134);
}

// ---- Initiator orientation (client/server by handshake, not IP sort order) ----------------

#[allow(clippy::too_many_arguments)]
fn mk(
    src: IpAddr,
    sport: u16,
    dst: IpAddr,
    dport: u16,
    transport: Transport,
    tcp_flags: u8,
    ttl: u8,
    wire: u32,
    ts: i64,
) -> PacketMeta {
    PacketMeta {
        index: 0,
        ts_ns: ts,
        iface_id: 0,
        wire_len: wire,
        cap_len: wire,
        l3: Protocol::Ipv4,
        transport,
        src_ip: Some(src),
        dst_ip: Some(dst),
        src_port: sport,
        dst_port: dport,
        tcp_flags,
        ttl,
        payload_len: 0,
        vlan: None,
        app_proto: ppcap_core::model::packet::AppProto::Unknown,
        sni: None,
        ja3: None,
        ja4: None,
        dns_qname: None,
        dns_answers: Vec::new(),
        cleartext_cred: None,
        pii: None,
        icmp_type: None,
        tls_version: None,
        tls_cipher: None,
        hassh: None,
        hassh_server: None,
        arp: None,
        ja3s: None,
        http_host: None,
        http_ua: None,
        download: None,
        download_disguised: false,
        stratum: None,
        dhcp: None,
    }
}

/// Observe a directed packet into `rec` under the correct canonical Direction for `key`.
fn observe_directed(rec: &mut FlowRecord, key: &FlowKey, p: &PacketMeta) {
    let (k, dir) = FlowKey::normalized(
        p.src_ip.unwrap(),
        p.src_port,
        p.dst_ip.unwrap(),
        p.dst_port,
        p.transport,
    );
    assert_eq!(&k, key, "packet must belong to the same canonical flow");
    rec.observe(p, dir);
}

#[test]
fn initiator_follows_client_syn_when_client_sorts_high() {
    // Client 10.0.0.9 (sorts ABOVE server) opens to server 10.0.0.1:443. The canonical key
    // makes the server the lo endpoint, so the OLD lo->src rule would mislabel the server as
    // source. With initiator tracking the client SYN wins.
    let client = v4(10, 0, 0, 9);
    let server = v4(10, 0, 0, 1);
    let (key, _) = FlowKey::normalized(client, 50000, server, 443, Transport::Tcp);
    assert_eq!(key.lo_ip, server, "server sorts lower, so it is the lo endpoint");

    let mut rec = FlowRecord::new(key, 0);
    // Client SYN (100 bytes, ttl 64), then server SYN|ACK (200 bytes, ttl 128).
    observe_directed(&mut rec, &key, &mk(client, 50000, server, 443, Transport::Tcp, 0x02, 64, 100, 0));
    observe_directed(&mut rec, &key, &mk(server, 443, client, 50000, Transport::Tcp, 0x12, 128, 200, 10));

    let o = rec.oriented();
    assert_eq!(o.src_ip, client, "source is the SYN sender (client), not the lo endpoint");
    assert_eq!(o.dst_ip, server);
    assert_eq!(o.src_port, 50000);
    assert_eq!(o.dst_port, 443);
    assert_eq!(o.bytes_c2s, 100, "c2s = client->server bytes");
    assert_eq!(o.bytes_s2c, 200, "s2c = server->client bytes");
    assert_eq!(o.tcp_flags_c2s & 0x02, 0x02, "client side carries the SYN");
    assert_eq!(o.ttl_min_c2s, 64, "c2s TTL is the client's");
}

#[test]
fn oriented_forward_is_identity_when_client_sorts_low() {
    // Client 10.0.0.1 sorts BELOW server 10.0.0.9 → client is already the lo endpoint, so
    // orientation is the historical identity mapping.
    let client = v4(10, 0, 0, 1);
    let server = v4(10, 0, 0, 9);
    let (key, _) = FlowKey::normalized(client, 40000, server, 80, Transport::Tcp);
    assert_eq!(key.lo_ip, client);

    let mut rec = FlowRecord::new(key, 0);
    observe_directed(&mut rec, &key, &mk(client, 40000, server, 80, Transport::Tcp, 0x02, 64, 100, 0));
    observe_directed(&mut rec, &key, &mk(server, 80, client, 40000, Transport::Tcp, 0x12, 128, 200, 10));

    let o = rec.oriented();
    assert_eq!(o.src_ip, client);
    assert_eq!(o.bytes_c2s, 100);
    assert_eq!(o.ttl_min_c2s, 64);
}

#[test]
fn late_client_syn_overrides_tentative_first_packet() {
    // Capture starts on the server's SYN|ACK (client SYN missed); the tentative first-packet
    // guess is later corrected when the client's SYN-only appears.
    let client = v4(10, 0, 0, 9);
    let server = v4(10, 0, 0, 1);
    let (key, _) = FlowKey::normalized(client, 50000, server, 443, Transport::Tcp);
    let mut rec = FlowRecord::new(key, 0);
    observe_directed(&mut rec, &key, &mk(server, 443, client, 50000, Transport::Tcp, 0x12, 128, 60, 0));
    observe_directed(&mut rec, &key, &mk(client, 50000, server, 443, Transport::Tcp, 0x02, 64, 74, 5));
    assert_eq!(rec.oriented().src_ip, client, "a real client SYN corrects the guess");
}

#[test]
fn udp_initiator_is_first_packet_when_client_sorts_high() {
    // No SYN for UDP: the first packet seen is the initiator. Client (sorts high) queries DNS.
    let client = v4(10, 0, 0, 9);
    let resolver = v4(10, 0, 0, 1);
    let (key, _) = FlowKey::normalized(client, 50000, resolver, 53, Transport::Udp);
    let mut rec = FlowRecord::new(key, 0);
    observe_directed(&mut rec, &key, &mk(client, 50000, resolver, 53, Transport::Udp, 0, 64, 80, 0));
    observe_directed(&mut rec, &key, &mk(resolver, 53, client, 50000, Transport::Udp, 0, 64, 200, 5));
    assert_eq!(rec.oriented().src_ip, client, "UDP initiator = first-packet sender");
    assert_eq!(rec.oriented().bytes_c2s, 80);
}
