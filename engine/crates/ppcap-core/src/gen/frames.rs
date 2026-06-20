//! L2..L7 frame builders for the generator, with correct checksums.
//!
//! Each builder appends to a `Vec<u8>` and returns it, producing well-formed
//! Ethernet/IPv4/TCP/UDP frames carrying recognizable DNS/HTTP/TLS payload signatures so
//! the decoder + classifier can be exercised end-to-end.

use std::net::Ipv4Addr;

/// IP protocol numbers used by the generator.
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;

/// Ethertypes.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;

// Common TCP flag bits. Some are part of the builder vocabulary but not used by every
// scenario, so unused ones are explicitly allowed.
#[allow(dead_code)]
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
#[allow(dead_code)]
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

/// Internet checksum (RFC 1071): one's-complement sum of 16-bit big-endian words.
///
/// Pure function. An odd trailing byte is treated as the high byte of a final 16-bit word
/// (i.e. padded with a zero low byte), per RFC 1071.
pub fn inet_checksum(bytes: &[u8]) -> u16 {
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

/// Build an Ethernet II header for the given ethertype. Returns 14 bytes.
pub fn build_ethernet(src_mac: [u8; 6], dst_mac: [u8; 6], ethertype: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(14);
    v.extend_from_slice(&dst_mac);
    v.extend_from_slice(&src_mac);
    v.extend_from_slice(&ethertype.to_be_bytes());
    v
}

/// Build a 20-byte IPv4 header (IHL=5, no options) over an `l4_len`-byte payload.
///
/// Sets total length, TTL, protocol, a deterministic identification, the Don't-Fragment
/// flag, and a correct header checksum.
pub fn build_ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, ttl: u8, l4_len: usize) -> Vec<u8> {
    build_ipv4_id(src, dst, proto, ttl, l4_len, 0)
}

/// Like [`build_ipv4`] but with a caller-chosen identification field (kept deterministic).
pub fn build_ipv4_id(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    ttl: u8,
    l4_len: usize,
    id: u16,
) -> Vec<u8> {
    let total_len = (20 + l4_len) as u16;
    let mut h = Vec::with_capacity(20);
    h.push(0x45); // version 4, IHL 5
    h.push(0x00); // DSCP/ECN
    h.extend_from_slice(&total_len.to_be_bytes());
    h.extend_from_slice(&id.to_be_bytes());
    h.extend_from_slice(&0x4000u16.to_be_bytes()); // flags=DF, frag offset 0
    h.push(ttl);
    h.push(proto);
    h.extend_from_slice(&[0, 0]); // checksum placeholder
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    let cks = inet_checksum(&h);
    h[10..12].copy_from_slice(&cks.to_be_bytes());
    h
}

/// Build a 24-byte IPv4 header (IHL=6) with a single NOP+EOL option word, over `l4_len`
/// bytes of payload. Used to exercise the option-skipping decode path.
#[allow(dead_code)] // exercised by this module's tests; kept as the IPv4-options builder
pub fn build_ipv4_with_options(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    ttl: u8,
    l4_len: usize,
) -> Vec<u8> {
    let total_len = (24 + l4_len) as u16;
    let mut h = Vec::with_capacity(24);
    h.push(0x46); // version 4, IHL 6 (one 32-bit option word)
    h.push(0x00);
    h.extend_from_slice(&total_len.to_be_bytes());
    h.extend_from_slice(&0u16.to_be_bytes()); // id
    h.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
    h.push(ttl);
    h.push(proto);
    h.extend_from_slice(&[0, 0]); // checksum placeholder
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    // One option word: NOP (0x01), NOP (0x01), NOP (0x01), End-of-Options (0x00).
    h.extend_from_slice(&[0x01, 0x01, 0x01, 0x00]);
    let cks = inet_checksum(&h);
    h[10..12].copy_from_slice(&cks.to_be_bytes());
    h
}

/// Compute the IPv4 pseudo-header checksum contribution for a TCP/UDP segment and return
/// the finished one's-complement checksum over `(pseudo-header || segment)`.
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

/// Build a TCP segment (20-byte header + payload) with a correct pseudo-header checksum.
///
/// `seq`/`ack` are derived deterministically from the ports so output stays reproducible.
pub fn build_tcp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let seq: u32 = (u32::from(src_port) << 16) | u32::from(dst_port);
    let ack: u32 = if flags & TCP_ACK != 0 {
        seq.wrapping_add(1)
    } else {
        0
    };
    let mut seg = Vec::with_capacity(20 + payload.len());
    seg.extend_from_slice(&src_port.to_be_bytes());
    seg.extend_from_slice(&dst_port.to_be_bytes());
    seg.extend_from_slice(&seq.to_be_bytes());
    seg.extend_from_slice(&ack.to_be_bytes());
    seg.push(0x50); // data offset 5 (<<4), reserved 0
    seg.push(flags);
    seg.extend_from_slice(&64240u16.to_be_bytes()); // window
    seg.extend_from_slice(&[0, 0]); // checksum placeholder
    seg.extend_from_slice(&[0, 0]); // urgent pointer
    seg.extend_from_slice(payload);
    let cks = l4_checksum(src, dst, IP_PROTO_TCP, &seg);
    seg[16..18].copy_from_slice(&cks.to_be_bytes());
    seg
}

/// Build a UDP datagram (8-byte header + payload) with a correct pseudo-header checksum.
pub fn build_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let len = (8 + payload.len()) as u16;
    let mut seg = Vec::with_capacity(8 + payload.len());
    seg.extend_from_slice(&src_port.to_be_bytes());
    seg.extend_from_slice(&dst_port.to_be_bytes());
    seg.extend_from_slice(&len.to_be_bytes());
    seg.extend_from_slice(&[0, 0]); // checksum placeholder
    seg.extend_from_slice(payload);
    let mut cks = l4_checksum(src, dst, IP_PROTO_UDP, &seg);
    // Per RFC 768 a computed checksum of zero is transmitted as 0xFFFF.
    if cks == 0 {
        cks = 0xFFFF;
    }
    seg[6..8].copy_from_slice(&cks.to_be_bytes());
    seg
}

/// Build an ARP request frame body (28 bytes, Ethernet/IPv4). Carried over ethertype
/// 0x0806; used as the deterministic non-IPv4 edge frame.
pub fn arp_request_payload(
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    sender_mac: [u8; 6],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(28);
    v.extend_from_slice(&1u16.to_be_bytes()); // htype: Ethernet
    v.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes()); // ptype: IPv4
    v.push(6); // hlen
    v.push(4); // plen
    v.extend_from_slice(&1u16.to_be_bytes()); // opcode: request
    v.extend_from_slice(&sender_mac);
    v.extend_from_slice(&sender_ip.octets());
    v.extend_from_slice(&[0u8; 6]); // target mac (unknown)
    v.extend_from_slice(&target_ip.octets());
    v
}

/// A minimal DNS query payload (recognizable header + one A question).
pub fn dns_query_payload(qname: &str, txid: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(12 + qname.len() + 6);
    v.extend_from_slice(&txid.to_be_bytes());
    v.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, RD set
    v.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    v.extend_from_slice(&0u16.to_be_bytes()); // ancount
    v.extend_from_slice(&0u16.to_be_bytes()); // nscount
    v.extend_from_slice(&0u16.to_be_bytes()); // arcount
                                              // QNAME: length-prefixed labels, terminated by a zero byte.
    for label in qname.split('.') {
        if label.is_empty() {
            continue;
        }
        // Labels are limited to 63 bytes on the wire.
        let bytes = label.as_bytes();
        let len = bytes.len().min(63);
        v.push(len as u8);
        v.extend_from_slice(&bytes[..len]);
    }
    v.push(0x00); // root label terminator
    v.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    v.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    v
}

/// A minimal HTTP request payload (`GET ... HTTP/1.1` signature).
pub fn http_request_payload(host: &str, path: &str) -> Vec<u8> {
    let s = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ppcap-gen\r\n\r\n");
    s.into_bytes()
}

/// An HTTP GET request carrying an `Authorization: Basic` header (the base64 of `user:pass`) — a
/// cleartext credential exposure for the sniffer to flag. The token is opaque to the sniffer,
/// which only recognizes the scheme, never the credential.
pub fn http_basic_auth_payload(host: &str, path: &str, basic_token: &str) -> Vec<u8> {
    let s = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Basic {basic_token}\r\nUser-Agent: ppcap-gen\r\n\r\n"
    );
    s.into_bytes()
}

/// An FTP control command line (e.g. `"USER bob"`, `"PASS hunter2"`) as a CRLF-terminated payload.
pub fn ftp_command_payload(line: &str) -> Vec<u8> {
    format!("{line}\r\n").into_bytes()
}

/// An HTTP POST request with a form-encoded body — used to carry plaintext PII (e.g. a card
/// number) in the clear for the PII sniffer to flag.
pub fn http_post_payload(host: &str, path: &str, body: &str) -> Vec<u8> {
    let s = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.into_bytes()
}

/// A well-formed TLS ClientHello record carrying a real SNI `server_name` extension.
///
/// Emits a complete (if minimal) ClientHello — client_version, 32-byte random, empty
/// session id, one cipher suite, null compression, and a single server_name (type 0)
/// extension — structured exactly as `decode::sniff_tls_client_hello` walks it, so the
/// engine recovers the SNI host. The `16 03 03` record prefix still satisfies the
/// structural TLS recognizer.
pub fn tls_client_hello_payload(sni: &str) -> Vec<u8> {
    let host = sni.as_bytes();
    let host_len = host.len();

    // server_name (SNI) extension sizing.
    let list_len = 3 + host_len; // name_type(1) + name_length(2) + host
    let ext_data_len = 2 + list_len; // server_name_list length(2) + list
    let ext_total = 4 + ext_data_len; // ext_type(2) + ext_len(2) + data

    // ClientHello body (everything after the 4-byte handshake header).
    let mut body = Vec::with_capacity(40 + 8 + ext_total);
    body.extend_from_slice(&[0x03, 0x03]); // client_version = TLS 1.2
    body.extend_from_slice(&[0u8; 32]); // random (deterministic zeros)
    body.push(0x00); // session_id length = 0
    body.extend_from_slice(&[0x00, 0x02]); // cipher_suites length = 2
    body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    body.push(0x01); // compression_methods length = 1
    body.push(0x00); // null compression
    body.extend_from_slice(&(ext_total as u16).to_be_bytes()); // extensions length
    body.extend_from_slice(&[0x00, 0x00]); // ext_type = server_name (0)
    body.extend_from_slice(&(ext_data_len as u16).to_be_bytes()); // ext length
    body.extend_from_slice(&(list_len as u16).to_be_bytes()); // server_name_list length
    body.push(0x00); // name_type = host_name (0)
    body.extend_from_slice(&(host_len as u16).to_be_bytes()); // name length
    body.extend_from_slice(host); // host bytes

    // Handshake header: msg_type(1)=ClientHello, length(3).
    let body_len = body.len() as u32;
    let mut handshake = Vec::with_capacity(4 + body.len());
    handshake.push(0x01);
    handshake.push(((body_len >> 16) & 0xFF) as u8);
    handshake.push(((body_len >> 8) & 0xFF) as u8);
    handshake.push((body_len & 0xFF) as u8);
    handshake.extend_from_slice(&body);

    // TLS record header: content_type=22(handshake), version=TLS 1.2, length(2).
    let mut rec = Vec::with_capacity(5 + handshake.len());
    rec.push(0x16);
    rec.extend_from_slice(&0x0303u16.to_be_bytes());
    rec.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    rec.extend_from_slice(&handshake);
    rec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_rfc1071_example() {
        // Classic RFC 1071 worked example block.
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let cks = inet_checksum(&data);
        // Verify the defining property: sum of all words plus checksum folds to 0xFFFF.
        let mut full = data.to_vec();
        full.extend_from_slice(&cks.to_be_bytes());
        assert_eq!(inet_checksum(&full), 0);
    }

    #[test]
    fn checksum_odd_length() {
        // RFC 1071: an odd trailing byte is treated as the high byte of the final 16-bit
        // word (padded with a zero low octet). To re-fold and verify the sum-incl-checksum
        // property, that zero pad must be materialized so the appended checksum stays
        // word-aligned — appending it at the odd offset would misalign every following word.
        let data = [0x12u8, 0x34, 0x56];
        let cks = inet_checksum(&data);
        let mut full = vec![0x12u8, 0x34, 0x56, 0x00]; // even-aligned: data + zero pad
        full.extend_from_slice(&cks.to_be_bytes());
        assert_eq!(inet_checksum(&full), 0);
    }

    #[test]
    fn checksum_all_zero_is_ffff() {
        assert_eq!(inet_checksum(&[0, 0, 0, 0]), 0xFFFF);
    }

    #[test]
    fn ethernet_layout() {
        let f = build_ethernet([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12], ETHERTYPE_IPV4);
        assert_eq!(f.len(), 14);
        assert_eq!(&f[0..6], &[7, 8, 9, 10, 11, 12]); // dst first
        assert_eq!(&f[6..12], &[1, 2, 3, 4, 5, 6]); // then src
        assert_eq!(&f[12..14], &[0x08, 0x00]);
    }

    #[test]
    fn ipv4_total_length_and_self_checksum() {
        let h = build_ipv4(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            IP_PROTO_TCP,
            64,
            100,
        );
        assert_eq!(h.len(), 20);
        assert_eq!(h[0] >> 4, 4); // version
        assert_eq!(h[0] & 0x0F, 5); // IHL
        let total = u16::from_be_bytes([h[2], h[3]]);
        assert_eq!(total, 120); // 20 + 100
                                // Recomputing the checksum over the full header yields 0 when correct.
        assert_eq!(inet_checksum(&h), 0);
    }

    #[test]
    fn ipv4_options_path_is_ihl6() {
        let h = build_ipv4_with_options(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            IP_PROTO_UDP,
            64,
            8,
        );
        assert_eq!(h.len(), 24);
        assert_eq!(h[0] & 0x0F, 6); // IHL == 6
        let total = u16::from_be_bytes([h[2], h[3]]);
        assert_eq!(total, 32); // 24 + 8
        assert_eq!(inet_checksum(&h), 0);
    }

    #[test]
    fn tcp_pseudo_header_checksum_folds_to_zero() {
        let src = Ipv4Addr::new(10, 1, 1, 1);
        let dst = Ipv4Addr::new(10, 2, 2, 2);
        let seg = build_tcp(src, dst, 12345, 80, TCP_SYN | TCP_ACK, b"hello world");
        // Recompute over pseudo-header || segment: must be 0.
        assert_eq!(l4_checksum(src, dst, IP_PROTO_TCP, &seg), 0);
    }

    #[test]
    fn udp_pseudo_header_checksum_folds_to_zero() {
        let src = Ipv4Addr::new(172, 16, 0, 1);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let payload = dns_query_payload("example.com", 0x1234);
        let seg = build_udp(src, dst, 5353, 53, &payload);
        // The stored checksum may have been remapped 0->0xFFFF; only verify when it wasn't.
        let stored = u16::from_be_bytes([seg[6], seg[7]]);
        if stored != 0xFFFF {
            assert_eq!(l4_checksum(src, dst, IP_PROTO_UDP, &seg), 0);
        }
        let len = u16::from_be_bytes([seg[4], seg[5]]);
        assert_eq!(len as usize, seg.len());
    }

    #[test]
    fn app_signatures_present() {
        let tls = tls_client_hello_payload("example.com");
        assert_eq!(&tls[0..3], &[0x16, 0x03, 0x03]);

        let http = http_request_payload("example.com", "/index.html");
        let s = String::from_utf8(http).unwrap();
        assert!(s.starts_with("GET "));
        assert!(s.contains("HTTP/"));
        assert!(s.contains("Host: example.com"));

        let dns = dns_query_payload("www.example.com", 0xBEEF);
        assert_eq!(&dns[0..2], &[0xBE, 0xEF]); // txid
        assert_eq!(u16::from_be_bytes([dns[4], dns[5]]), 1); // qdcount
                                                             // Encoded QNAME contains the label lengths and bytes.
        assert!(dns.windows(3).any(|w| w == b"www"));
        assert_eq!(dns[dns.len() - 4], 0x00); // root label before QTYPE/QCLASS
    }

    #[test]
    fn arp_payload_is_28_bytes() {
        let a = arp_request_payload(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            [0xAA; 6],
        );
        assert_eq!(a.len(), 28);
        assert_eq!(u16::from_be_bytes([a[6], a[7]]), 1); // opcode request
    }
}
