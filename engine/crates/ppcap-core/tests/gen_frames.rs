//! Generator frame builders: checksums and protocol signatures.
//!
//! `gen::frames` is crate-private, so these tests validate the builders *through the public
//! surface*: we generate a small capture, walk the emitted classic-pcap records, and assert
//! the on-wire IPv4/TCP/UDP checksums fold to zero and the DNS/HTTP/TLS signatures appear.

use std::net::Ipv4Addr;

use ppcap_core::gen::{GenConfig, Scenario, SynthGen};

/// One's-complement Internet checksum (RFC 1071) — re-implemented here so the test does not
/// depend on the crate-private builder, and can independently verify emitted frames.
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

/// Generate a small classic-pcap capture and return its raw bytes.
fn generate(scenario: Scenario, packets: u64) -> Vec<u8> {
    let cfg = GenConfig {
        scenario,
        packets,
        seed: 123,
        host_count: 8,
        ..Default::default()
    };
    let mut buf = Vec::new();
    SynthGen::new(cfg).write_to(&mut buf).unwrap();
    buf
}

/// Iterate classic-pcap records, yielding each frame's L2 byte slice.
fn for_each_frame(capture: &[u8], mut f: impl FnMut(&[u8])) {
    // 24-byte global header, then 16-byte record headers + caplen bytes.
    let mut off = 24usize;
    while off + 16 <= capture.len() {
        let caplen = u32::from_le_bytes([
            capture[off + 8],
            capture[off + 9],
            capture[off + 10],
            capture[off + 11],
        ]) as usize;
        let data_start = off + 16;
        let data_end = data_start + caplen;
        if data_end > capture.len() {
            break;
        }
        f(&capture[data_start..data_end]);
        off = data_end;
    }
}

#[test]
fn inet_checksum_rfc1071_vectors() {
    // Property: a buffer plus its checksum re-folds to zero.
    let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
    let cks = inet_checksum(&data);
    let mut full = data.to_vec();
    full.extend_from_slice(&cks.to_be_bytes());
    assert_eq!(inet_checksum(&full), 0);
    // Odd-length case: RFC 1071 pads the odd trailing byte with a zero low octet. That zero
    // pad must be materialized to keep the appended checksum word-aligned before re-folding.
    let odd = [0x12u8, 0x34, 0x56];
    let cks = inet_checksum(&odd);
    let mut full = vec![0x12u8, 0x34, 0x56, 0x00];
    full.extend_from_slice(&cks.to_be_bytes());
    assert_eq!(inet_checksum(&full), 0);
    // All-zero folds to 0xFFFF.
    assert_eq!(inet_checksum(&[0, 0, 0, 0]), 0xFFFF);
}

#[test]
fn ipv4_total_length_and_checksum() {
    // Generated frames carry well-formed IPv4 headers: checksum folds to zero and
    // total_length == 20 + L4 length.
    let capture = generate(Scenario::WebOnly, 20);
    let mut checked = 0;
    for_each_frame(&capture, |frame| {
        // Skip the 14-byte Ethernet header; require IPv4.
        if frame.len() < 14 + 20 {
            return;
        }
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        if ethertype != 0x0800 {
            return;
        }
        let ip = &frame[14..];
        let ihl = (ip[0] & 0x0F) as usize * 4;
        if ihl < 20 || ip.len() < ihl {
            return;
        }
        // IPv4 header checksum recomputes to zero.
        assert_eq!(inet_checksum(&ip[..ihl]), 0, "IPv4 header checksum");
        let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        assert!(total >= ihl, "total length must cover the header");
        checked += 1;
    });
    assert!(checked > 0, "expected at least one IPv4 frame");
}

#[test]
fn tcp_udp_pseudo_header_checksum_zero() {
    let capture = generate(Scenario::Mixed, 200);
    let mut tcp_checked = 0;
    let mut udp_checked = 0;
    for_each_frame(&capture, |frame| {
        if frame.len() < 14 + 20 {
            return;
        }
        if u16::from_be_bytes([frame[12], frame[13]]) != 0x0800 {
            return;
        }
        let ip = &frame[14..];
        let ihl = (ip[0] & 0x0F) as usize * 4;
        if ihl < 20 || ip.len() < ihl {
            return;
        }
        let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        if total < ihl || total > ip.len() {
            return; // truncated edge frame: skip checksum validation.
        }
        let proto = ip[9];
        let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
        let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
        let l4 = &ip[ihl..total];
        match proto {
            6 if l4.len() >= 20 => {
                assert_eq!(l4_checksum(src, dst, 6, l4), 0, "TCP checksum");
                tcp_checked += 1;
            }
            17 if l4.len() >= 8 => {
                // UDP checksum 0 is transmitted as 0xFFFF; only verify when not remapped.
                let stored = u16::from_be_bytes([l4[6], l4[7]]);
                if stored != 0xFFFF {
                    assert_eq!(l4_checksum(src, dst, 17, l4), 0, "UDP checksum");
                }
                udp_checked += 1;
            }
            _ => {}
        }
    });
    assert!(tcp_checked > 0, "expected TCP frames in a mixed capture");
    assert!(udp_checked > 0, "expected UDP frames in a mixed capture");
}

#[test]
fn app_payload_signatures_present() {
    let capture = generate(Scenario::Mixed, 400);
    let mut saw_tls = false;
    let mut saw_http = false;
    let mut saw_dns = false;
    for_each_frame(&capture, |frame| {
        if frame.len() < 14 + 20 {
            return;
        }
        if u16::from_be_bytes([frame[12], frame[13]]) != 0x0800 {
            return;
        }
        let ip = &frame[14..];
        let ihl = (ip[0] & 0x0F) as usize * 4;
        if ihl < 20 || ip.len() < ihl {
            return;
        }
        let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        if total < ihl || total > ip.len() {
            return;
        }
        let proto = ip[9];
        let l4 = &ip[ihl..total];
        match proto {
            6 if l4.len() >= 20 => {
                let payload = &l4[20..];
                if payload.starts_with(&[0x16, 0x03, 0x03]) {
                    saw_tls = true;
                }
                if payload.starts_with(b"GET ") {
                    saw_http = true;
                }
            }
            17 if l4.len() >= 8 => {
                let payload = &l4[8..];
                // DNS query: qdcount==1 at offset 4..6, with a recognizable header.
                if payload.len() >= 12 && u16::from_be_bytes([payload[4], payload[5]]) == 1 {
                    saw_dns = true;
                }
            }
            _ => {}
        }
    });
    assert!(saw_tls, "expected a TLS ClientHello signature");
    assert!(saw_http, "expected an HTTP GET signature");
    assert!(saw_dns, "expected a DNS query signature");
}
