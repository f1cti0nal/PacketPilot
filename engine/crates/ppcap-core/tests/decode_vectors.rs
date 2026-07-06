//! Decoder vectors: hand-crafted frames -> expected PacketMeta; truncation never panics.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ppcap_core::decode::decode_frame;
use ppcap_core::model::packet::{Protocol, Transport};
use ppcap_core::reader::{LinkType, RawFrame};

/// Wrap raw bytes as a `RawFrame` with the given link type.
fn frame<'a>(link_type: LinkType, data: &'a [u8]) -> RawFrame<'a> {
    RawFrame {
        index: 0,
        ts_ns: 1_000,
        ts_known: true,
        iface_id: 0,
        wire_len: data.len() as u32,
        cap_len: data.len() as u32,
        link_type,
        data,
    }
}

fn build_ethernet(ethertype: u16) -> Vec<u8> {
    let mut v = vec![0u8; 14];
    // dst + src MAC are zero; ethertype at offset 12.
    v[12..14].copy_from_slice(&ethertype.to_be_bytes());
    v
}

fn ipv4_header(proto: u8, total_len: u16, ttl: u8) -> Vec<u8> {
    let mut h = vec![0u8; 20];
    h[0] = 0x45;
    h[2..4].copy_from_slice(&total_len.to_be_bytes());
    h[8] = ttl;
    h[9] = proto;
    h[12..16].copy_from_slice(&[10, 0, 0, 1]);
    h[16..20].copy_from_slice(&[10, 0, 0, 2]);
    h
}

fn tcp_header(sport: u16, dport: u16, flags: u8) -> Vec<u8> {
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&dport.to_be_bytes());
    t[12] = 0x50; // data offset 5 words
    t[13] = flags;
    t
}

#[test]
fn ethernet_ipv4_tcp_decodes() {
    let mut data = build_ethernet(0x0800);
    let ip = ipv4_header(6, 40, 64); // 20 ip + 20 tcp
    let tcp = tcp_header(12345, 80, 0x02); // SYN
    data.extend_from_slice(&ip);
    data.extend_from_slice(&tcp);

    let m = decode_frame(&frame(LinkType::Ethernet, &data)).unwrap();
    assert_eq!(m.l3, Protocol::Ipv4);
    assert_eq!(m.transport, Transport::Tcp);
    assert_eq!(m.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert_eq!(m.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    assert_eq!(m.src_port, 12345);
    assert_eq!(m.dst_port, 80);
    assert_eq!(m.ttl, 64);
    assert!(m.is_tcp_syn_only());
}

#[test]
fn vlan_tagged_frame_records_vlan() {
    // 14 base Ethernet (ethertype = 802.1Q) + 4 vlan tag (vlan 100, inner IPv4) + ip + udp.
    let mut data = vec![0u8; 14];
    data[12] = 0x81;
    data[13] = 0x00; // 802.1Q
    data.extend_from_slice(&[0x00, 0x64]); // TCI: vlan 100
    data.extend_from_slice(&[0x08, 0x00]); // inner ethertype IPv4

    let mut ip = ipv4_header(17, 28, 32); // 20 ip + 8 udp
    let mut udp = vec![0u8; 8];
    udp[0..2].copy_from_slice(&5353u16.to_be_bytes());
    udp[2..4].copy_from_slice(&53u16.to_be_bytes());
    udp[4..6].copy_from_slice(&8u16.to_be_bytes());
    ip.extend_from_slice(&udp);
    data.extend_from_slice(&ip);

    let m = decode_frame(&frame(LinkType::Ethernet, &data)).unwrap();
    assert_eq!(m.vlan, Some(100));
    assert_eq!(m.l3, Protocol::Ipv4);
    assert_eq!(m.transport, Transport::Udp);
    assert_eq!(m.dst_port, 53);
}

#[test]
fn ipv6_with_ext_headers_decodes() {
    // IPv6 (next_header = hop-by-hop) -> destination-options -> TCP.
    let mut data = build_ethernet(0x86DD);
    let mut ip = vec![0u8; 40];
    ip[0] = 0x60; // version 6
    ip[6] = 0; // next header: hop-by-hop
    ip[7] = 64; // hop limit
    ip[8] = 0x20;
    ip[9] = 0x01; // src 2001::1
    ip[23] = 0x01;
    ip[24] = 0x20;
    ip[25] = 0x01; // dst 2001::2
    ip[39] = 0x02;

    // Hop-by-hop ext header (8 bytes): next = destination-options (60).
    let mut hbh = vec![0u8; 8];
    hbh[0] = 60;
    hbh[1] = 0;
    // Destination-options ext header (8 bytes): next = TCP (6).
    let mut dst = vec![0u8; 8];
    dst[0] = 6;
    dst[1] = 0;

    let tcp = tcp_header(4444, 443, 0x10); // ACK

    // payload_length covers the two ext headers + tcp = 8 + 8 + 20 = 36.
    ip[4..6].copy_from_slice(&36u16.to_be_bytes());

    ip.extend_from_slice(&hbh);
    ip.extend_from_slice(&dst);
    ip.extend_from_slice(&tcp);
    data.extend_from_slice(&ip);

    let m = decode_frame(&frame(LinkType::Ethernet, &data)).unwrap();
    assert_eq!(m.l3, Protocol::Ipv6);
    assert_eq!(m.transport, Transport::Tcp);
    assert_eq!(
        m.src_ip,
        Some(IpAddr::V6("2001::1".parse::<Ipv6Addr>().unwrap()))
    );
    assert_eq!(m.src_port, 4444);
    assert_eq!(m.dst_port, 443);
}

#[test]
fn truncated_frame_errors_without_panic() {
    // Ethernet says IPv4 but only 10 bytes of L3 follow: IPv4 decode must error (no panic).
    let mut data = build_ethernet(0x0800);
    data.extend_from_slice(&[0x45u8; 10]); // 10 < 20-byte IPv4 header
    let res = std::panic::catch_unwind(|| decode_frame(&frame(LinkType::Ethernet, &data)));
    let decoded = res.expect("decode_frame must not panic on truncated input");
    assert!(decoded.is_err(), "expected an error for truncated frame");
}

#[test]
fn raw_sll_null_link_types() {
    // --- Raw (DLT_RAW): the data IS L3; sniff version nibble (IPv4). ---
    let mut ip = ipv4_header(6, 40, 16);
    ip.extend_from_slice(&tcp_header(1111, 22, 0x02));
    let m = decode_frame(&frame(LinkType::Raw, &ip)).unwrap();
    assert_eq!(m.l3, Protocol::Ipv4);
    assert_eq!(m.transport, Transport::Tcp);
    assert_eq!(m.dst_port, 22);

    // --- LinuxSll (16-byte header, ethertype at offset 14). ---
    let mut sll = vec![0u8; 16];
    sll[14] = 0x08;
    sll[15] = 0x00; // IPv4
    let mut ip2 = ipv4_header(17, 28, 10);
    let mut udp = vec![0u8; 8];
    udp[2..4].copy_from_slice(&53u16.to_be_bytes());
    udp[4..6].copy_from_slice(&8u16.to_be_bytes());
    ip2.extend_from_slice(&udp);
    sll.extend_from_slice(&ip2);
    let m = decode_frame(&frame(LinkType::LinuxSll, &sll)).unwrap();
    assert_eq!(m.l3, Protocol::Ipv4);
    assert_eq!(m.transport, Transport::Udp);
    assert_eq!(m.dst_port, 53);

    // --- Null (BSD loopback: 4-byte AF word; AF_INET=2 => IPv4). ---
    let mut null = vec![2u8, 0, 0, 0];
    let mut ip3 = ipv4_header(6, 40, 5);
    ip3.extend_from_slice(&tcp_header(2222, 80, 0x02));
    null.extend_from_slice(&ip3);
    let m = decode_frame(&frame(LinkType::Null, &null)).unwrap();
    assert_eq!(m.l3, Protocol::Ipv4);
    assert_eq!(m.transport, Transport::Tcp);
}
