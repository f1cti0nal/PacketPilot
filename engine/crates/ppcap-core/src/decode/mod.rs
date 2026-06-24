//! Frame decoder: a borrowed [`RawFrame`] -> a fixed-size [`PacketMeta`].
//!
//! Backed by hand-rolled, fully bounds-checked framing for Ethernet/VLAN/SLL/Null/Raw link
//! types and IPv4/IPv6/TCP/UDP/SCTP, plus lightweight L7 sniffing helpers (DNS by port,
//! HTTP request-method, TLS ClientHello SNI). No payload is retained — only metadata.
//!
//! ## Contract
//! - Never panics on malformed input: every access is bounds-checked
//!   (`get`/`split_at_checked`), never raw indexing of attacker-controlled offsets.
//! - Returns [`PpError::Truncated`] / [`PpError::MalformedHeader`] for per-packet
//!   problems; the pipeline counts these as `decode_errors` and continues (unless strict).
//! - VLAN-tagged frames: record the 802.1Q id and decode the inner ethertype.
//! - IPv6 extension-header chains: walk a bounded number of headers (≤ 8) to find L4.
//! - IP fragments: ports are 0 for non-first fragments; still counted.
//! - ARP / non-IP: produce a `PacketMeta` with `l3 = Arp|NonIp`, no IPs, no ports.
//!
//! ## NOTE TO INTEGRATOR (etherparse vs hand-rolled)
//! The task brief asked for an `etherparse`-backed implementation. The IMPL comments
//! committed in these files (mod.rs / l2.rs / l3.rs / l4.rs) instead specify exact byte
//! offsets and a hand-rolled, allocation-free, bounds-checked parse, and `PacketMeta`
//! exposes only fixed metadata fields. This implementation follows the committed IMPL
//! contract (hand-rolled) because it is what the documented data-flow and the existing
//! `model::packet` flag masks require, and it is trivially panic-safe. `etherparse 0.20.2`
//! is still a dependency and may be swapped in behind these same function signatures with
//! no change to callers if desired.
//!
//! ## L7 hints
//! The freeze is lifted: `decode_l3` now stores the sniffed L7 hint on
//! [`PacketMeta::app_proto`] and the SNI host on [`PacketMeta::sni`], and
//! `FlowRecord::observe` unions those onto the flow (most-specific hint, first SNI). The
//! pure sniffing helpers ([`l7_hint`], [`sniff_http_method`], [`sniff_tls_client_hello`],
//! [`looks_like_tls_client_hello`], [`is_dns_port`]) remain the building blocks and are
//! exercised by this module's unit tests.

use crate::error::PpError;
use crate::model::packet::{AppProto, CredScheme, PacketMeta, PiiKind, Protocol, Transport};
use crate::reader::{LinkType, RawFrame};
use crate::Result;

use l2::{ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6};

/// Decode a full L2 (or raw-L3) frame into packet metadata.
pub fn decode_frame(frame: &RawFrame<'_>) -> Result<PacketMeta> {
    // 1. Seed a PacketMeta from the borrowed frame's fixed fields.
    let mut meta = PacketMeta {
        index: frame.index,
        ts_ns: frame.ts_ns,
        iface_id: frame.iface_id,
        wire_len: frame.wire_len,
        cap_len: frame.cap_len,
        l3: Protocol::NonIp,
        transport: Transport::Other(0),
        src_ip: None,
        dst_ip: None,
        src_port: 0,
        dst_port: 0,
        tcp_flags: 0,
        ttl: 0,
        payload_len: 0,
        vlan: None,
        app_proto: AppProto::Unknown,
        sni: None,
        ja3: None,
        ja4: None,
        dns_qname: None,
        cleartext_cred: None,
        pii: None,
        icmp_type: None,
        tls_version: None,
        tls_cipher: None,
    };

    // 2. Branch on the link type to obtain (ethertype-or-equivalent, L3 slice).
    //    For raw-IP link types there is no ethertype, so we dispatch straight to L3.
    match frame.link_type {
        LinkType::Ethernet => {
            let (ethertype, l3) = l2::strip_l2(frame.data, &mut meta)?;
            dispatch_ethertype(ethertype, l3, &mut meta)?;
        }
        LinkType::LinuxSll => {
            let (ethertype, l3) = strip_linux_sll(frame.data, &mut meta)?;
            dispatch_ethertype(ethertype, l3, &mut meta)?;
        }
        LinkType::LinuxSll2 => {
            let (ethertype, l3) = strip_linux_sll2(frame.data, &mut meta)?;
            dispatch_ethertype(ethertype, l3, &mut meta)?;
        }
        LinkType::Null => {
            let (family_is_ipv6, l3) = strip_null(frame.data, &mut meta)?;
            // BSD loopback only ever carries IP; sniff version but trust the family word.
            if family_is_ipv6 {
                dispatch_ethertype(ETHERTYPE_IPV6, l3, &mut meta)?;
            } else {
                dispatch_ethertype(ETHERTYPE_IPV4, l3, &mut meta)?;
            }
        }
        LinkType::RawIpv4 => {
            decode_l3(frame.data, &mut meta)?;
        }
        LinkType::RawIpv6 => {
            decode_l3(frame.data, &mut meta)?;
        }
        LinkType::Raw => {
            // DLT_RAW: the data IS L3; sniff the IP version nibble.
            decode_l3(frame.data, &mut meta)?;
        }
        LinkType::Unsupported(dlt) => {
            return Err(PpError::UnsupportedLinkType("UNSUPPORTED", dlt));
        }
    }

    Ok(meta)
}

/// Map an ethertype to L3 handling, mutating `meta`. ARP/unknown are recorded but not
/// parsed further (counted, never flowed).
fn dispatch_ethertype(ethertype: u16, l3: &[u8], meta: &mut PacketMeta) -> Result<()> {
    match ethertype {
        ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => decode_l3(l3, meta),
        ETHERTYPE_ARP => {
            meta.l3 = Protocol::Arp;
            Ok(())
        }
        _ => {
            // Unknown ethertype: counted as non-IP.
            meta.l3 = Protocol::NonIp;
            Ok(())
        }
    }
}

/// Decode an L3 slice (for raw-IP link types, or after L2 stripping) into `meta`,
/// including the L4 dispatch.
pub fn decode_l3(bytes: &[u8], meta: &mut PacketMeta) -> Result<()> {
    // Peek the version nibble. An empty slice is non-IP, not an error.
    let first = match bytes.first() {
        Some(&b) => b,
        None => {
            meta.l3 = Protocol::NonIp;
            return Ok(());
        }
    };

    let (proto, l4) = match first >> 4 {
        4 => l3::decode_ipv4(bytes, meta)?,
        6 => l3::decode_ipv6(bytes, meta)?,
        _ => {
            meta.l3 = Protocol::NonIp;
            return Ok(());
        }
    };

    meta.transport = Transport::from_ip_proto(proto);

    match meta.transport {
        Transport::Tcp => l4::decode_tcp(l4, meta)?,
        Transport::Udp => l4::decode_udp(l4, meta)?,
        Transport::Sctp => l4::decode_sctp(l4, meta)?,
        // ICMP / ICMPv6: no ports; payload_len already seeded from L3 total length. Capture the
        // message type (first byte) so the covert-channel detector can isolate echo request/reply.
        Transport::Icmp | Transport::Icmpv6 => meta.icmp_type = l4.first().copied(),
        Transport::Other(_) => {}
    }

    // L7 enrichment: peek at the L4 payload (NO retention). The payload begins after the
    // transport header; `payload_len` was set by the L4 decoder, so the payload offset within
    // the captured L4 slice is `l4.len() - payload_len`. Only TCP/UDP carry sniffable L7;
    // the DNS-by-port case still fires when `payload_len == 0`. Non-first fragments have an
    // empty `l4` slice -> empty payload -> no match (correct: fragment data must not sniff).
    if meta.transport.has_ports() {
        let consumed = l4.len().saturating_sub(meta.payload_len as usize);
        let payload = l4.get(consumed..).unwrap_or(&[]);
        if let Some(hint) = l7_hint(meta.transport, meta.src_port, meta.dst_port, payload) {
            match hint {
                L7Hint::Dns { qname } => {
                    meta.app_proto = AppProto::Dns;
                    meta.dns_qname = qname;
                }
                L7Hint::Http { .. } => meta.app_proto = AppProto::Http, // method token dropped
                L7Hint::Tls { sni, ja3, ja4 } => {
                    meta.app_proto = AppProto::Tls;
                    meta.sni = sni; // Some only when ClientHello carried server_name
                    meta.ja3 = ja3;
                    meta.ja4 = ja4;
                }
            }
        }
        // Cleartext credential exposure: a second, payload-free sniff over the same peek. Sets
        // only the derived scheme (never the credential), so the no-retention contract holds.
        meta.cleartext_cred =
            sniff_cleartext_cred(meta.transport, meta.src_port, meta.dst_port, payload);
        // Plaintext PII exposure: derive only the PII *kind* (credit card / SSN), never the value.
        meta.pii = sniff_pii(meta.transport, payload);
        // TLS server posture: the negotiated version + cipher from a ServerHello (server-side
        // counterpart to the ClientHello's sni/ja3/ja4). Payload-free; only set when the payload
        // begins a ServerHello.
        if let Some((version, cipher)) = crate::tls::sniff_server_hello(payload) {
            meta.app_proto = AppProto::Tls;
            meta.tls_version = Some(version.to_string());
            meta.tls_cipher = Some(cipher);
        }
    }

    Ok(())
}

/// The L4 seq/ack (TCP only) plus the L4 payload slice for a raw frame.
///
/// Returned by [`l4_payload`]; the borrow lives as long as the frame's `data`. `seq`/`ack`
/// are `Some` only for TCP; `payload` is the bytes after the transport header (empty when the
/// segment is header-only, undecodable, or a transport without an extractable payload here).
pub(crate) struct L4Info<'a> {
    pub seq: Option<u32>,
    pub ack: Option<u32>,
    pub payload: &'a [u8],
}

/// Derive the L4 seq/ack (TCP) and payload slice for a raw frame; `None` when the frame is
/// undecodable down to L3 (too short / ARP / non-IP / unsupported DLT / non-first fragment).
///
/// Reuses the existing strip walk: [`l2::strip_to_l3`] handles the per-link-type L2 header
/// (Ethernet/VLAN, SLL/SLL2, Null, raw-IP), and [`l3::strip_to_l4`] handles the IPv4 IHL /
/// IPv6 extension-header chain — the same offset arithmetic `decode_frame`/`decode_l3` use, so
/// no offsets are duplicated here. `PacketMeta` (from `decode_frame`) does not expose TCP
/// seq/ack or the payload bytes, so this is where the UI's hexdump bytes come from.
pub(crate) fn l4_payload<'a>(frame: &crate::reader::RawFrame<'a>) -> Option<L4Info<'a>> {
    let l3 = l2::strip_to_l3(frame.link_type, frame.data)?;
    let (l4, transport) = l3::strip_to_l4(l3)?;
    match transport {
        Transport::Tcp if l4.len() >= 20 => {
            let data_off = ((l4[12] >> 4) as usize) * 4;
            let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
            let ack = u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]);
            let payload = if l4.len() > data_off {
                &l4[data_off..]
            } else {
                &[][..]
            };
            Some(L4Info {
                seq: Some(seq),
                ack: Some(ack),
                payload,
            })
        }
        Transport::Udp if l4.len() >= 8 => Some(L4Info {
            seq: None,
            ack: None,
            payload: &l4[8..],
        }),
        _ => Some(L4Info {
            seq: None,
            ack: None,
            payload: &[][..],
        }),
    }
}

// ---------------------------------------------------------------------------------------
// Link-type framing helpers for the non-Ethernet DLTs (hand-rolled, bounds-checked).
// ---------------------------------------------------------------------------------------

/// Strip a Linux "cooked" v1 (SLL, DLT 113) header: 16 bytes, the L3 protocol type is the
/// big-endian ethertype at offset 14. Returns `(ethertype, l3_slice)`.
fn strip_linux_sll<'a>(data: &'a [u8], meta: &mut PacketMeta) -> Result<(u16, &'a [u8])> {
    const SLL_HDR: usize = 16;
    if data.len() < SLL_HDR {
        return Err(PpError::Truncated {
            needed: SLL_HDR,
            had: data.len(),
            offset: meta.index,
        });
    }
    let ethertype = u16::from_be_bytes([data[14], data[15]]);
    match data.split_at_checked(SLL_HDR) {
        Some((_, l3)) => Ok((ethertype, l3)),
        None => Err(PpError::Truncated {
            needed: SLL_HDR,
            had: data.len(),
            offset: meta.index,
        }),
    }
}

/// Strip a Linux "cooked" v2 (SLL2, DLT 276) header: 20 bytes, the protocol type is the
/// big-endian ethertype at offset 0. Returns `(ethertype, l3_slice)`.
fn strip_linux_sll2<'a>(data: &'a [u8], meta: &mut PacketMeta) -> Result<(u16, &'a [u8])> {
    const SLL2_HDR: usize = 20;
    if data.len() < SLL2_HDR {
        return Err(PpError::Truncated {
            needed: SLL2_HDR,
            had: data.len(),
            offset: meta.index,
        });
    }
    let ethertype = u16::from_be_bytes([data[0], data[1]]);
    match data.split_at_checked(SLL2_HDR) {
        Some((_, l3)) => Ok((ethertype, l3)),
        None => Err(PpError::Truncated {
            needed: SLL2_HDR,
            had: data.len(),
            offset: meta.index,
        }),
    }
}

/// Strip a BSD loopback / null (DLT 0) header: a 4-byte host-endian address family word.
/// Returns `(is_ipv6, l3_slice)`. AF_INET == 2 means IPv4; the various AF_INET6 values
/// (24/28/30 across BSDs, plus Linux's 10) mean IPv6. We accept both endiannesses and fall
/// back to sniffing the IP version nibble if the family word is unrecognized.
fn strip_null<'a>(data: &'a [u8], meta: &mut PacketMeta) -> Result<(bool, &'a [u8])> {
    const NULL_HDR: usize = 4;
    if data.len() < NULL_HDR {
        return Err(PpError::Truncated {
            needed: NULL_HDR,
            had: data.len(),
            offset: meta.index,
        });
    }
    let le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

    let l3 = match data.split_at_checked(NULL_HDR) {
        Some((_, rest)) => rest,
        None => {
            return Err(PpError::Truncated {
                needed: NULL_HDR,
                had: data.len(),
                offset: meta.index,
            })
        }
    };

    let is_ipv6 = |fam: u32| matches!(fam, 10 | 24 | 28 | 30);
    let is_ipv4 = |fam: u32| fam == 2;

    if is_ipv4(le) || is_ipv4(be) {
        Ok((false, l3))
    } else if is_ipv6(le) || is_ipv6(be) {
        Ok((true, l3))
    } else {
        // Unrecognized family word: fall back to the IP version nibble of the payload.
        let v6 = l3.first().map(|b| (b >> 4) == 6).unwrap_or(false);
        Ok((v6, l3))
    }
}

// ---------------------------------------------------------------------------------------
// L7 sniffing helpers (pure; see "NOTE TO INTEGRATOR" above — not stored on PacketMeta).
// ---------------------------------------------------------------------------------------

/// A lightweight, best-effort application-layer hint derived from L4 ports + a peek at the
/// (uncaptured-by-`PacketMeta`) payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L7Hint {
    /// Likely DNS (matched on port 53); `qname` is the first question name if parseable.
    Dns { qname: Option<String> },
    /// An HTTP request with the sniffed method (e.g. `GET`, `POST`).
    Http { method: String },
    /// A TLS ClientHello; `sni` is the Server Name Indication host if present.
    Tls {
        sni: Option<String>,
        ja3: Option<String>,
        ja4: Option<String>,
    },
}

/// True if either endpoint is the well-known DNS port (53).
#[inline]
pub fn is_dns_port(src_port: u16, dst_port: u16) -> bool {
    src_port == 53 || dst_port == 53
}

/// Extract the first question's QNAME from a DNS message payload, or `None` if it is not a
/// parseable query name. Parses defensively — every index is bounds-checked, labels are capped,
/// and a compression pointer (which a question QNAME never legitimately uses) or any malformed
/// byte aborts cleanly — so it never panics on adversarial input. Label bytes map 1:1 to chars
/// (so the caller can measure length/entropy); the registered domain is not separated out here.
pub fn sniff_dns_qname(payload: &[u8]) -> Option<String> {
    // Need the 12-byte header plus at least one name byte.
    if payload.len() < 13 {
        return None;
    }
    // QDCOUNT (questions) must be non-zero for a query name to exist.
    if u16::from_be_bytes([payload[4], payload[5]]) == 0 {
        return None;
    }

    let mut off = 12usize; // first question begins right after the header
    let mut name = String::new();
    // A valid QNAME has at most 127 labels (255-byte cap, >=2 bytes each); cap to bound the loop.
    for _ in 0..128 {
        let len = *payload.get(off)? as usize;
        if len == 0 {
            // Root label: end of the name.
            return if name.is_empty() { None } else { Some(name) };
        }
        // Top two bits set => compression pointer (or reserved); a question QNAME never uses
        // these, so any malformed pointer aborts cleanly rather than chasing offsets.
        if len & 0xC0 != 0 {
            return if name.is_empty() { None } else { Some(name) };
        }
        let start = off + 1;
        let end = start.checked_add(len)?;
        let label = payload.get(start..end)?;
        if !name.is_empty() {
            name.push('.');
        }
        for &b in label {
            name.push(b as char);
        }
        if name.len() > 255 {
            return None;
        }
        off = end;
    }
    None // exceeded the label cap without a root terminator => malformed
}

/// Top-level L7 sniff: combine port heuristics with a payload peek. `payload` is the L4
/// payload (may be empty or truncated). Returns `None` when nothing is recognized.
pub fn l7_hint(
    transport: Transport,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<L7Hint> {
    // TLS ClientHello (typically TCP/443 but detected structurally, so port-agnostic).
    if transport == Transport::Tcp {
        if let Some(fp) = crate::fingerprint::fingerprint_tls_client_hello(
            payload,
            crate::fingerprint::Ja4Transport::Tcp,
        ) {
            return Some(L7Hint::Tls {
                sni: fp.sni,
                ja3: Some(fp.ja3),
                ja4: Some(fp.ja4),
            });
        }
        if let Some(sni) = sniff_tls_client_hello(payload) {
            return Some(L7Hint::Tls {
                sni,
                ja3: None,
                ja4: None,
            });
        }
        if looks_like_tls_client_hello(payload) {
            return Some(L7Hint::Tls {
                sni: None,
                ja3: None,
                ja4: None,
            });
        }
        if let Some(method) = sniff_http_method(payload) {
            return Some(L7Hint::Http { method });
        }
    }
    // QUIC Initial (UDP long header): form-bit precheck before any crypto.
    // A QUIC long header has both 0x80 (long) and 0x40 (fixed bit) set.
    if transport == Transport::Udp && payload.first().is_some_and(|b| b & 0xC0 == 0xC0) {
        if let Some(ch) = crate::quic::extract_initial_client_hello(payload) {
            // `extract_initial_client_hello` returns raw handshake bytes (first byte 0x01).
            // Both `fingerprint_tls_client_hello` and `sniff_tls_client_hello` expect a
            // TLS record (first byte 0x16), so wrap the handshake in a minimal record header.
            let mut record = Vec::with_capacity(5 + ch.len());
            record.push(22u8); // content_type = handshake
            record.extend_from_slice(&[0x03, 0x03]); // record version TLS 1.2
            record.extend_from_slice(&(ch.len() as u16).to_be_bytes());
            record.extend_from_slice(&ch);
            if let Some(fp) = crate::fingerprint::fingerprint_tls_client_hello(
                &record,
                crate::fingerprint::Ja4Transport::Quic,
            ) {
                return Some(L7Hint::Tls {
                    sni: fp.sni,
                    ja3: Some(fp.ja3),
                    ja4: Some(fp.ja4),
                });
            }
            // Fallback: plain SNI extraction (no fingerprints).
            if let Some(sni) = sniff_tls_client_hello(&record) {
                return Some(L7Hint::Tls {
                    sni,
                    ja3: None,
                    ja4: None,
                });
            }
            // At minimum we know this was a QUIC Initial -> TLS.
            return Some(L7Hint::Tls {
                sni: None,
                ja3: None,
                ja4: None,
            });
        }
    }
    // DNS is matched on port for both UDP and TCP.
    if (transport == Transport::Udp || transport == Transport::Tcp)
        && is_dns_port(src_port, dst_port)
    {
        return Some(L7Hint::Dns {
            qname: sniff_dns_qname(payload),
        });
    }
    None
}

/// Lightweight TLS-record recognizer: a handshake record (content type 22), record version
/// major 3, whose first handshake-message byte is 1 (ClientHello). Recognizes a ClientHello
/// *structurally* even when the body is too short for full SNI parsing (e.g. the synthetic
/// generator's stub `gen::frames::tls_client_hello_payload`), so payload-derived TLS
/// classification still fires. Strict SNI parsing still wins when the payload is well-formed.
#[inline]
pub fn looks_like_tls_client_hello(payload: &[u8]) -> bool {
    matches!(payload, [22, 3, _, _, _, 1, ..])
}

/// Sniff an HTTP request method from the start of a TCP payload. Returns the method token
/// (e.g. `"GET"`) when the payload begins with a known method followed by a space.
pub fn sniff_http_method(payload: &[u8]) -> Option<String> {
    const METHODS: &[&str] = &[
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT ",
    ];
    for m in METHODS {
        let mb = m.as_bytes();
        if payload.len() >= mb.len() && &payload[..mb.len()] == mb {
            // Strip the trailing space we matched on.
            return Some(m.trim_end().to_string());
        }
    }
    None
}

/// ASCII case-insensitive prefix test (`haystack` starts with `needle`).
fn starts_with_ci(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len()
        && haystack[..needle.len()]
            .iter()
            .zip(needle)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// First index in `haystack` where `needle` matches, ASCII case-insensitively; `None` if absent.
/// O(n·m) but `n` is the bounded header peek and `m` is a short literal.
fn find_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| starts_with_ci(&haystack[i..], needle))
}

/// If an HTTP request's header block carries an `Authorization` / `Proxy-Authorization` header
/// with a Basic or Digest scheme, return the scheme. The credential itself is neither parsed nor
/// kept. The match is anchored to the **start of a header line** and the **request body is never
/// scanned** (truncated at the first blank line), so the literal `authorization:` appearing in a
/// request URI/query or body does not false-positive.
fn http_auth_scheme(buf: &[u8]) -> Option<CredScheme> {
    // Headers end at the first blank line (`\r\n\r\n`); if it is not in the bounded peek, the
    // payload is all headers (truncated), so scan what we have.
    let headers = match find_ci(buf, b"\r\n\r\n") {
        Some(end) => &buf[..end],
        None => buf,
    };
    // Each header sits on its own CRLF-delimited line; the first line is the request line, which
    // never starts with the header name, so it is naturally skipped.
    for raw in headers.split(|&b| b == b'\n') {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        let value = if starts_with_ci(line, b"authorization:") {
            &line[b"authorization:".len()..]
        } else if starts_with_ci(line, b"proxy-authorization:") {
            &line[b"proxy-authorization:".len()..]
        } else {
            continue;
        };
        // Skip optional leading whitespace, then match the scheme token.
        let start = value
            .iter()
            .position(|&b| b != b' ' && b != b'\t')
            .unwrap_or(value.len());
        let token = &value[start..];
        if starts_with_ci(token, b"basic") {
            return Some(CredScheme::HttpBasic);
        } else if starts_with_ci(token, b"digest") {
            return Some(CredScheme::HttpDigest);
        }
    }
    None
}

/// Sniff a *cleartext* credential exposure from a bounded TCP-payload peek — HTTP Basic/Digest
/// auth (the request is plaintext, so an HTTPS request would be TLS-wrapped and never match) or
/// FTP `USER`/`PASS` control commands. Returns only the derived [`CredScheme`]; the credential is
/// never extracted or retained. Pure, bounds-checked, and never panics on malformed input.
pub fn sniff_cleartext_cred(
    transport: Transport,
    _src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<CredScheme> {
    if transport != Transport::Tcp || payload.is_empty() {
        return None;
    }
    // Credentials live in the request line / header block near the start; bound the scan.
    let scan = &payload[..payload.len().min(1024)];

    // FTP control commands to the server (port 21): USER/PASS carry the credential verbatim.
    if dst_port == 21 && (starts_with_ci(scan, b"USER ") || starts_with_ci(scan, b"PASS ")) {
        return Some(CredScheme::Ftp);
    }

    // HTTP Authorization header — only on an actual request, to avoid matching response bodies.
    if sniff_http_method(payload).is_some() {
        return http_auth_scheme(scan);
    }
    None
}

/// Luhn (mod-10) checksum over ASCII digits; `true` if the sequence is Luhn-valid. The slice must
/// contain only ASCII digits (the caller guarantees this).
fn luhn_valid(digits: &[u8]) -> bool {
    if digits.len() < 12 {
        return false;
    }
    let mut sum = 0u32;
    // Double every second digit counting from the right.
    for (i, &d) in digits.iter().rev().enumerate() {
        let mut v = (d - b'0') as u32;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum % 10 == 0
}

/// Whether a digit string has a recognized payment-card issuer prefix and length. Gating on real
/// issuer ranges (with the Luhn check) keeps a random Luhn-valid digit run from false-positiving.
fn has_card_prefix(d: &[u8]) -> bool {
    let n = d.len();
    if !(13..=19).contains(&n) {
        return false;
    }
    let digit = |i: usize| (d[i] - b'0') as usize;
    let p2 = digit(0) * 10 + digit(1);
    let p4 = digit(0) * 1000 + digit(1) * 100 + digit(2) * 10 + digit(3);
    match d[0] {
        b'4' => n == 13 || n == 16 || n == 19,          // Visa
        b'3' => n == 15 && (p2 == 34 || p2 == 37),      // Amex
        b'5' => n == 16 && (51..=55).contains(&p2),     // Mastercard (legacy BIN)
        b'2' => n == 16 && (2221..=2720).contains(&p4), // Mastercard (2-series)
        b'6' => n == 16 && (p4 == 6011 || p2 == 65),    // Discover
        _ => false,
    }
}

/// Whether any of `keywords` (lowercase ASCII) appears, case-insensitively, within the `window`
/// bytes of `buf` immediately preceding `pos`. Used to require a field-name hint (`card`, `ssn`,
/// …) near a candidate, so a bare numeric run that merely passes Luhn / the dashed shape is not
/// reported — the dominant false-positive source.
fn keyword_before(buf: &[u8], pos: usize, window: usize, keywords: &[&[u8]]) -> bool {
    let start = pos.saturating_sub(window);
    let ctx = &buf[start..pos];
    keywords.iter().any(|kw| find_ci(ctx, kw).is_some())
}

/// Field-name hints that must precede a card-number run for it to be reported.
const CARD_KEYWORDS: &[&[u8]] = &[b"card", b"pan", b"credit"];
/// Field-name hints that must precede an SSN-shaped run for it to be reported.
const SSN_KEYWORDS: &[&[u8]] = &[b"ssn", b"social"];

/// Scan `buf` for a payment-card number: a run of 13–19 digits (single space/dash separators
/// allowed, as cards are often grouped) with a recognized issuer prefix, a valid Luhn checksum,
/// **and** a card-ish field-name keyword within the preceding bytes. The keyword corroboration is
/// what keeps a benign Luhn-valid numeric id (which Visa's `4`-anything range would otherwise
/// admit ~10% of the time) from being mislabeled as a card.
fn contains_credit_card(buf: &[u8]) -> bool {
    let mut i = 0;
    while i < buf.len() {
        if !buf[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        // Collect the (separator-tolerant) digit group starting here.
        let start = i;
        let mut digits = [0u8; 19];
        let mut len = 0usize;
        let mut j = i;
        while j < buf.len() && len < 19 {
            let b = buf[j];
            if b.is_ascii_digit() {
                digits[len] = b;
                len += 1;
                j += 1;
            } else if (b == b' ' || b == b'-') && j + 1 < buf.len() && buf[j + 1].is_ascii_digit() {
                // A single separator inside the run.
                j += 1;
            } else {
                break;
            }
        }
        if has_card_prefix(&digits[..len])
            && luhn_valid(&digits[..len])
            && keyword_before(buf, start, 40, CARD_KEYWORDS)
        {
            return true;
        }
        // Skip past the run we just consumed (j advanced past at least one digit), avoiding
        // O(n^2) rescanning.
        i = j;
    }
    false
}

/// Scan `buf` for a US SSN in the dashed `NNN-NN-NNNN` form: a structurally-valid run (area not
/// 000/666/900–999, group not 00, serial not 0000), not embedded in a longer digit string, **and**
/// preceded by an `ssn`/`social` field-name keyword. Both the structure and the keyword are needed
/// because a bare dashed 3-2-4 number is also a common product/serial-code shape.
fn contains_ssn(buf: &[u8]) -> bool {
    let d = |b: u8| b.is_ascii_digit();
    let n = buf.len();
    if n < 11 {
        return false;
    }
    let mut i = 0;
    while i + 11 <= n {
        let w = &buf[i..i + 11];
        let shaped = d(w[0])
            && d(w[1])
            && d(w[2])
            && w[3] == b'-'
            && d(w[4])
            && d(w[5])
            && w[6] == b'-'
            && d(w[7])
            && d(w[8])
            && d(w[9])
            && d(w[10]);
        if shaped {
            // Not embedded in a longer formatted number on either side.
            let prev_ok = i == 0 || !buf[i - 1].is_ascii_digit();
            let next_ok = i + 11 >= n || !buf[i + 11].is_ascii_digit();
            let area =
                (w[0] - b'0') as u16 * 100 + (w[1] - b'0') as u16 * 10 + (w[2] - b'0') as u16;
            let group_ok = w[4] != b'0' || w[5] != b'0'; // group 00 is never a valid SSN
            let serial_ok = w[7] != b'0' || w[8] != b'0' || w[9] != b'0' || w[10] != b'0'; // serial 0000
            if prev_ok
                && next_ok
                && area != 0
                && area != 666
                && area < 900
                && group_ok
                && serial_ok
                && keyword_before(buf, i, 40, SSN_KEYWORDS)
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// True if the first up-to-64 payload bytes look like text (so the PII scan skips binary / TLS /
/// compressed payloads cheaply). Gates on *control-byte* density rather than ASCII-printable
/// density, so UTF-8 text with high bytes (≥ 0x80) is still admitted while NUL/control-heavy
/// binary is rejected. Tab/CR/LF do not count as control.
fn looks_like_text(buf: &[u8]) -> bool {
    let sample = &buf[..buf.len().min(64)];
    if sample.is_empty() {
        return false;
    }
    let control = sample
        .iter()
        .filter(|&&b| b < 0x20 && b != b'\t' && b != b'\r' && b != b'\n')
        .count();
    control * 10 <= sample.len() // ≤ 10% control bytes
}

/// Sniff plaintext PII (a credit-card number or a US SSN) from a bounded TCP-payload peek.
/// Returns only the derived [`PiiKind`] — never the value. Gated on a cheap printable-text check
/// so binary / TLS payloads skip the digit scan. Pure, bounds-checked, never panics.
pub fn sniff_pii(transport: Transport, payload: &[u8]) -> Option<PiiKind> {
    if transport != Transport::Tcp || payload.is_empty() {
        return None;
    }
    let scan = &payload[..payload.len().min(1024)];
    if !looks_like_text(scan) {
        return None;
    }
    if contains_credit_card(scan) {
        return Some(PiiKind::CreditCard);
    }
    if contains_ssn(scan) {
        return Some(PiiKind::Ssn);
    }
    None
}

/// Sniff a TLS ClientHello and, if present, the SNI host. Returns:
/// - `Some(Some(host))` — ClientHello with an SNI extension,
/// - `Some(None)` — ClientHello but no SNI,
/// - `None` — not a (recognizable) ClientHello.
pub fn sniff_tls_client_hello(payload: &[u8]) -> Option<Option<String>> {
    // TLS record header: content_type(1) version(2) length(2).
    // ClientHello content type is 22 (handshake); handshake type 1 is ClientHello.
    let ct = *payload.first()?;
    if ct != 22 {
        return None;
    }
    // payload[1..3] = record version (ignored). payload[3..5] = record length.
    let rec_len = u16::from_be_bytes([*payload.get(3)?, *payload.get(4)?]) as usize;
    let rec_end = 5usize.checked_add(rec_len)?.min(payload.len());
    let body = payload.get(5..rec_end)?;

    // Handshake header: msg_type(1) length(3).
    if *body.first()? != 1 {
        return None; // not ClientHello
    }
    // Skip handshake header (4) + client_version(2) + random(32) = 38.
    let mut pos = 4 + 2 + 32;
    // session_id: len(1) + bytes.
    let sid_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(sid_len)?;
    // cipher_suites: len(2) + bytes.
    let cs_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
    pos = pos.checked_add(2)?.checked_add(cs_len)?;
    // compression_methods: len(1) + bytes.
    let cm_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(cm_len)?;
    // extensions: len(2) + bytes.
    let ext_total = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
    pos = pos.checked_add(2)?;
    let ext_end = pos.checked_add(ext_total)?.min(body.len());
    let extensions = body.get(pos..ext_end)?;

    // Walk extensions looking for type 0x0000 (server_name).
    let mut i = 0usize;
    while i + 4 <= extensions.len() {
        let ext_type = u16::from_be_bytes([extensions[i], extensions[i + 1]]);
        let ext_len = u16::from_be_bytes([extensions[i + 2], extensions[i + 3]]) as usize;
        let data_start = i + 4;
        let data_end = data_start.checked_add(ext_len)?;
        if data_end > extensions.len() {
            break;
        }
        if ext_type == 0x0000 {
            // server_name extension:
            //   server_name_list length(2), then entries of:
            //     name_type(1) + name_length(2) + name(name_length).
            let snl = extensions.get(data_start..data_end)?;
            // server_name_list length.
            if snl.len() < 2 {
                return Some(None);
            }
            let mut j = 2usize; // skip list length
            while j + 3 <= snl.len() {
                let name_type = snl[j];
                let name_len = u16::from_be_bytes([snl[j + 1], snl[j + 2]]) as usize;
                let name_start = j + 3;
                let name_end = name_start.checked_add(name_len)?;
                if name_end > snl.len() {
                    break;
                }
                if name_type == 0 {
                    // host_name
                    if let Ok(host) = std::str::from_utf8(&snl[name_start..name_end]) {
                        return Some(Some(host.to_string()));
                    }
                    return Some(None);
                }
                j = name_end;
            }
            return Some(None);
        }
        i = data_end;
    }

    // It was a ClientHello but carried no SNI.
    Some(None)
}

/// Convenience wrapper returning just the SNI host (`None` if not a ClientHello or no SNI).
pub fn sniff_tls_sni(payload: &[u8]) -> Option<String> {
    sniff_tls_client_hello(payload).flatten()
}

pub(crate) mod l2;
pub(crate) mod l3;
pub(crate) mod l4;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn blank_meta() -> PacketMeta {
        PacketMeta {
            index: 0,
            ts_ns: 0,
            iface_id: 0,
            wire_len: 0,
            cap_len: 0,
            l3: Protocol::NonIp,
            transport: Transport::Other(0),
            src_ip: None,
            dst_ip: None,
            src_port: 0,
            dst_port: 0,
            tcp_flags: 0,
            ttl: 0,
            payload_len: 0,
            vlan: None,
            app_proto: AppProto::Unknown,
            sni: None,
            ja3: None,
            ja4: None,
            dns_qname: None,
            cleartext_cred: None,
            pii: None,
            icmp_type: None,
            tls_version: None,
            tls_cipher: None,
        }
    }

    #[test]
    fn icmp_echo_sets_type_and_payload_len() {
        // IPv4 + ICMP echo request (type 8) with an 8-byte ICMP header + 56 data bytes.
        let mut icmp = vec![8u8, 0, 0, 0, 0x12, 0x34, 0, 1];
        icmp.extend(std::iter::repeat_n(0xABu8, 56));
        let mut bytes = crate::gen::frames::build_ipv4(
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(10, 0, 0, 6),
            1, // IPPROTO_ICMP
            64,
            icmp.len(),
        );
        bytes.extend_from_slice(&icmp);

        let mut meta = blank_meta();
        decode_l3(&bytes, &mut meta).unwrap();
        assert_eq!(meta.transport, Transport::Icmp);
        assert_eq!(meta.icmp_type, Some(8));
        assert_eq!(meta.payload_len, 64); // 8-byte ICMP header + 56 data bytes
    }

    #[test]
    fn serverhello_sets_tls_version_and_cipher_but_clienthello_does_not() {
        use crate::gen::frames::{build_ipv4, build_tcp, IP_PROTO_TCP, TCP_ACK, TCP_PSH};
        let server = Ipv4Addr::new(203, 0, 113, 9);
        let client = Ipv4Addr::new(10, 0, 0, 5);

        // A server ServerHello (TLS 1.2 + ECDHE_RSA_AES128_GCM 0xC02F) sets the server-side fields.
        let sh = crate::tls::testcert::server_hello(0x0303, 0xC02F, None);
        let tcp = build_tcp(server, client, 443, 51000, TCP_PSH | TCP_ACK, &sh);
        let mut l3 = build_ipv4(server, client, IP_PROTO_TCP, 64, tcp.len());
        l3.extend_from_slice(&tcp);
        let mut sm = blank_meta();
        decode_l3(&l3, &mut sm).unwrap();
        assert_eq!(sm.app_proto, AppProto::Tls);
        assert_eq!(sm.tls_version.as_deref(), Some("TLS 1.2"));
        assert_eq!(
            sm.tls_cipher.as_deref(),
            Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        );
        assert!(sm.ja3.is_none()); // server side, no client fingerprint

        // A ClientHello fingerprints (ja3/ja4) but must NOT set the server-side fields.
        let ch = crate::gen::frames::tls_client_hello_payload("example.com");
        let tcp2 = build_tcp(client, server, 51000, 443, TCP_PSH | TCP_ACK, &ch);
        let mut l3b = build_ipv4(client, server, IP_PROTO_TCP, 64, tcp2.len());
        l3b.extend_from_slice(&tcp2);
        let mut cm = blank_meta();
        decode_l3(&l3b, &mut cm).unwrap();
        assert_eq!(cm.app_proto, AppProto::Tls);
        assert!(cm.ja3.is_some());
        assert_eq!(cm.tls_version, None);
        assert_eq!(cm.tls_cipher, None);
    }

    fn frame<'a>(link_type: LinkType, data: &'a [u8]) -> RawFrame<'a> {
        RawFrame {
            index: 7,
            ts_ns: 1_234,
            iface_id: 0,
            wire_len: data.len() as u32,
            cap_len: data.len() as u32,
            link_type,
            data,
        }
    }

    // --- L2 ---------------------------------------------------------------------------

    #[test]
    fn ethernet_too_short_is_truncated() {
        let data = [0u8; 10];
        let mut m = blank_meta();
        let err = l2::strip_l2(&data, &mut m).unwrap_err();
        assert!(matches!(err, PpError::Truncated { needed: 14, .. }));
    }

    #[test]
    fn ethernet_ipv4_ethertype_no_vlan() {
        let mut data = vec![0u8; 14];
        data[12] = 0x08;
        data[13] = 0x00; // IPv4
        let mut m = blank_meta();
        let (et, l3) = l2::strip_l2(&data, &mut m).unwrap();
        assert_eq!(et, ETHERTYPE_IPV4);
        assert_eq!(l3.len(), 0);
        assert_eq!(m.vlan, None);
    }

    #[test]
    fn ethernet_single_vlan_records_id_and_inner_ethertype() {
        // 14 base + 4 vlan; TCI = 0x0064 (vlan id 100), inner = IPv4.
        let mut data = vec![0u8; 18];
        data[12] = 0x81;
        data[13] = 0x00; // 802.1Q
        data[14] = 0x00;
        data[15] = 0x64; // TCI: vlan 100
        data[16] = 0x08;
        data[17] = 0x00; // inner = IPv4
        let mut m = blank_meta();
        let (et, l3) = l2::strip_l2(&data, &mut m).unwrap();
        assert_eq!(et, ETHERTYPE_IPV4);
        assert_eq!(m.vlan, Some(100));
        assert_eq!(l3.len(), 0);
    }

    #[test]
    fn ethernet_qinq_double_vlan_bounded() {
        // Two stacked tags; outer vlan 1, inner vlan 2, then IPv6.
        let mut data = vec![0u8; 22];
        data[12] = 0x88;
        data[13] = 0xA8; // QinQ
        data[14] = 0x00;
        data[15] = 0x01; // outer vlan 1
        data[16] = 0x81;
        data[17] = 0x00; // 802.1Q
        data[18] = 0x00;
        data[19] = 0x02; // inner vlan 2
        data[20] = 0x86;
        data[21] = 0xDD; // IPv6
        let mut m = blank_meta();
        let (et, _l3) = l2::strip_l2(&data, &mut m).unwrap();
        assert_eq!(et, ETHERTYPE_IPV6);
        // Only the outermost vlan id is recorded.
        assert_eq!(m.vlan, Some(1));
    }

    #[test]
    fn arp_frame_sets_l3_arp_and_no_ip() {
        let mut data = vec![0u8; 14];
        data[12] = 0x08;
        data[13] = 0x06; // ARP
        let f = frame(LinkType::Ethernet, &data);
        let m = decode_frame(&f).unwrap();
        assert_eq!(m.l3, Protocol::Arp);
        assert_eq!(m.src_ip, None);
        assert_eq!(m.dst_ip, None);
    }

    #[test]
    fn unknown_ethertype_is_nonip() {
        let mut data = vec![0u8; 14];
        data[12] = 0x12;
        data[13] = 0x34;
        let f = frame(LinkType::Ethernet, &data);
        let m = decode_frame(&f).unwrap();
        assert_eq!(m.l3, Protocol::NonIp);
    }

    // --- L3 IPv4 ----------------------------------------------------------------------

    /// Build a minimal IPv4 header (20 bytes, IHL=5).
    fn ipv4_header(proto: u8, total_len: u16, frag_field: u16, ttl: u8) -> Vec<u8> {
        let mut h = vec![0u8; 20];
        h[0] = 0x45; // version 4, IHL 5
        h[2..4].copy_from_slice(&total_len.to_be_bytes());
        h[6..8].copy_from_slice(&frag_field.to_be_bytes());
        h[8] = ttl;
        h[9] = proto;
        h[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
        h[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst
        h
    }

    #[test]
    fn ipv4_tcp_full_decode() {
        let mut pkt = ipv4_header(6, 40, 0, 64); // 20 ip + 20 tcp
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[12] = 0x50; // data offset 5 words = 20 bytes
        tcp[13] = 0x02; // SYN
        pkt.extend_from_slice(&tcp);

        let mut m = blank_meta();
        decode_l3(&pkt, &mut m).unwrap();
        assert_eq!(m.l3, Protocol::Ipv4);
        assert_eq!(m.transport, Transport::Tcp);
        assert_eq!(m.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(m.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
        assert_eq!(m.src_port, 12345);
        assert_eq!(m.dst_port, 80);
        assert_eq!(m.ttl, 64);
        assert!(m.is_tcp_syn_only());
        assert_eq!(m.payload_len, 0);
    }

    #[test]
    fn ipv4_options_shift_l4_offset() {
        // IHL = 6 (24-byte header, 4 bytes of options).
        let mut pkt = vec![0u8; 24];
        pkt[0] = 0x46; // version 4, IHL 6
        pkt[2..4].copy_from_slice(&32u16.to_be_bytes()); // total 24 + 8 udp
        pkt[8] = 50;
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[1, 1, 1, 1]);
        pkt[16..20].copy_from_slice(&[2, 2, 2, 2]);
        // UDP header at offset 24.
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&5353u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        udp[4..6].copy_from_slice(&8u16.to_be_bytes()); // udp length 8 (header only)
        pkt.extend_from_slice(&udp);

        let mut m = blank_meta();
        decode_l3(&pkt, &mut m).unwrap();
        assert_eq!(m.transport, Transport::Udp);
        assert_eq!(m.src_port, 5353);
        assert_eq!(m.dst_port, 53);
    }

    #[test]
    fn ipv4_non_first_fragment_has_zero_ports() {
        // frag offset != 0 (offset field nonzero) marks a non-first fragment.
        let mut pkt = ipv4_header(6, 1400, 185, 64);
        // append some "tcp-looking" bytes that must be ignored.
        pkt.extend_from_slice(&[0xff; 20]);
        let mut m = blank_meta();
        decode_l3(&pkt, &mut m).unwrap();
        assert_eq!(m.transport, Transport::Tcp);
        assert_eq!(m.src_port, 0);
        assert_eq!(m.dst_port, 0);
        assert_eq!(m.tcp_flags, 0);
    }

    #[test]
    fn ipv4_bad_ihl_is_malformed() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x43; // IHL 3 -> header_len 12 < 20
        let mut m = blank_meta();
        let err = l3::decode_ipv4(&pkt, &mut m).unwrap_err();
        assert!(matches!(
            err,
            PpError::MalformedHeader { layer: "ipv4", .. }
        ));
    }

    #[test]
    fn ipv4_truncated_header() {
        let pkt = [0x45u8; 10];
        let mut m = blank_meta();
        let err = l3::decode_ipv4(&pkt, &mut m).unwrap_err();
        assert!(matches!(err, PpError::Truncated { needed: 20, .. }));
    }

    // --- L3 IPv6 ----------------------------------------------------------------------

    fn ipv6_header(next_header: u8, payload_len: u16, hop: u8) -> Vec<u8> {
        let mut h = vec![0u8; 40];
        h[0] = 0x60; // version 6
        h[4..6].copy_from_slice(&payload_len.to_be_bytes());
        h[6] = next_header;
        h[7] = hop;
        h[8] = 0x20;
        h[9] = 0x01; // src 2001::1
        h[23] = 0x01;
        h[24] = 0x20;
        h[25] = 0x01; // dst 2001::2
        h[39] = 0x02;
        h
    }

    #[test]
    fn ipv6_udp_direct() {
        let mut pkt = ipv6_header(17, 8, 64);
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&1000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        udp[4..6].copy_from_slice(&8u16.to_be_bytes());
        pkt.extend_from_slice(&udp);
        let mut m = blank_meta();
        decode_l3(&pkt, &mut m).unwrap();
        assert_eq!(m.l3, Protocol::Ipv6);
        assert_eq!(m.transport, Transport::Udp);
        assert_eq!(m.dst_port, 53);
        assert_eq!(m.ttl, 64);
        assert_eq!(
            m.src_ip,
            Some(IpAddr::V6("2001::1".parse::<Ipv6Addr>().unwrap()))
        );
        assert_eq!(
            m.dst_ip,
            Some(IpAddr::V6("2001::2".parse::<Ipv6Addr>().unwrap()))
        );
    }

    #[test]
    fn ipv6_hop_by_hop_then_tcp() {
        // next_header 0 (hop-by-hop), one 8-byte ext header pointing to TCP (6).
        let mut pkt = ipv6_header(0, 28, 64);
        let mut ext = vec![0u8; 8];
        ext[0] = 6; // next = TCP
        ext[1] = 0; // hdr_ext_len 0 -> total 8 bytes
        pkt.extend_from_slice(&ext);
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&4444u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x10; // ACK
        pkt.extend_from_slice(&tcp);
        let mut m = blank_meta();
        decode_l3(&pkt, &mut m).unwrap();
        assert_eq!(m.transport, Transport::Tcp);
        assert_eq!(m.src_port, 4444);
        assert_eq!(m.dst_port, 443);
    }

    #[test]
    fn ipv6_fragment_non_first_zero_ports() {
        // Fragment ext header with nonzero offset -> non-first fragment.
        let mut pkt = ipv6_header(44, 28, 64);
        let mut frag = vec![0u8; 8];
        frag[0] = 6; // next TCP
                     // fragment offset (top 13 bits) nonzero: set offset 1 (value 0x0008).
        frag[2..4].copy_from_slice(&0x0008u16.to_be_bytes());
        pkt.extend_from_slice(&frag);
        pkt.extend_from_slice(&[0xee; 20]); // garbage that must be ignored
        let mut m = blank_meta();
        decode_l3(&pkt, &mut m).unwrap();
        assert_eq!(m.transport, Transport::Tcp);
        assert_eq!(m.src_port, 0);
        assert_eq!(m.dst_port, 0);
    }

    #[test]
    fn ipv6_ext_header_chain_overflow_is_malformed() {
        // Chain of 9 hop-by-hop headers each pointing to another hop-by-hop (0).
        let mut pkt = ipv6_header(0, 0, 64);
        for _ in 0..9 {
            let mut ext = vec![0u8; 8];
            ext[0] = 0; // next = hop-by-hop again
            ext[1] = 0;
            pkt.extend_from_slice(&ext);
        }
        let mut m = blank_meta();
        let err = decode_l3(&pkt, &mut m).unwrap_err();
        assert!(matches!(
            err,
            PpError::MalformedHeader {
                layer: "ipv6-ext",
                ..
            }
        ));
    }

    // --- L4 ---------------------------------------------------------------------------

    #[test]
    fn tcp_flag_union_full_byte() {
        let mut tcp = vec![0u8; 20];
        tcp[12] = 0x50;
        tcp[13] = 0b0001_1111; // FIN|SYN|RST|PSH|ACK
        let mut m = blank_meta();
        l4::decode_tcp(&tcp, &mut m).unwrap();
        assert_eq!(m.tcp_flags, 0b0001_1111);
    }

    #[test]
    fn tcp_payload_len_after_options() {
        let mut tcp = vec![0u8; 24 + 5]; // 24-byte header (data offset 6) + 5 payload
        tcp[12] = 0x60; // data offset 6 words = 24 bytes
        let mut m = blank_meta();
        l4::decode_tcp(&tcp, &mut m).unwrap();
        assert_eq!(m.payload_len, 5);
    }

    #[test]
    fn tcp_bad_data_offset_is_malformed() {
        let mut tcp = vec![0u8; 20];
        tcp[12] = 0x40; // data offset 4 words = 16 < 20
        let mut m = blank_meta();
        let err = l4::decode_tcp(&tcp, &mut m).unwrap_err();
        assert!(matches!(err, PpError::MalformedHeader { layer: "tcp", .. }));
    }

    #[test]
    fn empty_l4_slice_is_ok_no_ports() {
        let mut m = blank_meta();
        l4::decode_tcp(&[], &mut m).unwrap();
        l4::decode_udp(&[], &mut m).unwrap();
        l4::decode_sctp(&[], &mut m).unwrap();
        assert_eq!(m.src_port, 0);
        assert_eq!(m.dst_port, 0);
    }

    #[test]
    fn udp_payload_len_clamped_to_capture() {
        let mut udp = vec![0u8; 8 + 2]; // only 2 payload bytes captured
        udp[4..6].copy_from_slice(&100u16.to_be_bytes()); // claims 92 payload
        let mut m = blank_meta();
        l4::decode_udp(&udp, &mut m).unwrap();
        assert_eq!(m.payload_len, 2);
    }

    #[test]
    fn sctp_ports() {
        let mut sctp = vec![0u8; 12];
        sctp[0..2].copy_from_slice(&2905u16.to_be_bytes());
        sctp[2..4].copy_from_slice(&9899u16.to_be_bytes());
        let mut m = blank_meta();
        l4::decode_sctp(&sctp, &mut m).unwrap();
        assert_eq!(m.src_port, 2905);
        assert_eq!(m.dst_port, 9899);
    }

    // --- Link types -------------------------------------------------------------------

    #[test]
    fn raw_ipv4_link_type_decodes_l3_directly() {
        let mut pkt = ipv4_header(17, 28, 0, 32);
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&99u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        udp[4..6].copy_from_slice(&8u16.to_be_bytes());
        pkt.extend_from_slice(&udp);
        let f = frame(LinkType::RawIpv4, &pkt);
        let m = decode_frame(&f).unwrap();
        assert_eq!(m.l3, Protocol::Ipv4);
        assert_eq!(m.dst_port, 53);
    }

    #[test]
    fn linux_sll_strips_16_bytes() {
        let mut data = vec![0u8; 16];
        data[14] = 0x08;
        data[15] = 0x00; // IPv4
                         // append a minimal ipv4+udp.
        let mut pkt = ipv4_header(17, 28, 0, 10);
        let mut udp = vec![0u8; 8];
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        udp[4..6].copy_from_slice(&8u16.to_be_bytes());
        pkt.extend_from_slice(&udp);
        data.extend_from_slice(&pkt);
        let f = frame(LinkType::LinuxSll, &data);
        let m = decode_frame(&f).unwrap();
        assert_eq!(m.l3, Protocol::Ipv4);
        assert_eq!(m.dst_port, 53);
    }

    #[test]
    fn null_loopback_af_inet() {
        let mut data = vec![2u8, 0, 0, 0]; // AF_INET little-endian
        let pkt = ipv4_header(6, 20, 0, 5);
        data.extend_from_slice(&pkt);
        // add tcp
        let mut tcp = vec![0u8; 20];
        tcp[12] = 0x50;
        data.extend_from_slice(&tcp);
        let f = frame(LinkType::Null, &data);
        let m = decode_frame(&f).unwrap();
        assert_eq!(m.l3, Protocol::Ipv4);
        assert_eq!(m.transport, Transport::Tcp);
    }

    #[test]
    fn unsupported_link_type_is_fatal_err() {
        let data = [0u8; 4];
        let f = frame(LinkType::Unsupported(99), &data);
        let err = decode_frame(&f).unwrap_err();
        assert!(matches!(err, PpError::UnsupportedLinkType(_, 99)));
        assert!(err.is_fatal());
    }

    #[test]
    fn never_panics_on_random_garbage() {
        // Fuzz-lite: a spread of malformed inputs must all return without panicking.
        let cases: &[(LinkType, &[u8])] = &[
            (LinkType::Ethernet, &[]),
            (LinkType::Ethernet, &[0xff; 3]),
            (LinkType::Ethernet, &[0x45; 14]),
            (LinkType::RawIpv4, &[0x40]),
            (LinkType::RawIpv6, &[0x60; 39]),
            (LinkType::Raw, &[0x99; 7]),
            (LinkType::LinuxSll, &[0x00; 5]),
            (LinkType::Null, &[0xde, 0xad, 0xbe, 0xef, 0x45]),
        ];
        for (lt, data) in cases {
            let f = frame(*lt, data);
            // Either Ok or Err — just must not panic.
            let _ = decode_frame(&f);
        }
    }

    // --- L7 hints ---------------------------------------------------------------------

    #[test]
    fn http_method_sniff() {
        assert_eq!(
            sniff_http_method(b"GET / HTTP/1.1\r\n"),
            Some("GET".to_string())
        );
        assert_eq!(
            sniff_http_method(b"POST /api HTTP/1.1"),
            Some("POST".to_string())
        );
        assert_eq!(sniff_http_method(b"NOTAVERB / HTTP"), None);
        assert_eq!(sniff_http_method(b"GE"), None);
        assert_eq!(sniff_http_method(b""), None);
    }

    #[test]
    fn cleartext_cred_sniff_http_basic_and_digest() {
        let tcp = Transport::Tcp;
        // HTTP Basic auth over cleartext -> HttpBasic (case-insensitive header match).
        let basic = b"GET /p HTTP/1.1\r\nHost: x\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n";
        assert_eq!(
            sniff_cleartext_cred(tcp, 50000, 80, basic),
            Some(CredScheme::HttpBasic)
        );
        // Lowercased header + no space after the colon still matches.
        let basic2 = b"POST /login HTTP/1.1\r\nauthorization:Basic QQ==\r\n\r\n";
        assert_eq!(
            sniff_cleartext_cred(tcp, 50000, 8080, basic2),
            Some(CredScheme::HttpBasic)
        );
        // Digest scheme.
        let digest = b"GET / HTTP/1.1\r\nAuthorization: Digest username=\"bob\"\r\n\r\n";
        assert_eq!(
            sniff_cleartext_cred(tcp, 50000, 80, digest),
            Some(CredScheme::HttpDigest)
        );
        // Proxy-Authorization is also covered (contains "authorization:").
        let proxy = b"GET / HTTP/1.1\r\nProxy-Authorization: Basic QQ==\r\n\r\n";
        assert_eq!(
            sniff_cleartext_cred(tcp, 50000, 80, proxy),
            Some(CredScheme::HttpBasic)
        );
    }

    #[test]
    fn cleartext_cred_sniff_ftp() {
        let tcp = Transport::Tcp;
        assert_eq!(
            sniff_cleartext_cred(tcp, 40000, 21, b"USER alice\r\n"),
            Some(CredScheme::Ftp)
        );
        assert_eq!(
            sniff_cleartext_cred(tcp, 40000, 21, b"pass s3cret\r\n"),
            Some(CredScheme::Ftp)
        );
        // FTP commands only count when addressed to the control port (21).
        assert_eq!(
            sniff_cleartext_cred(tcp, 40000, 8021, b"USER alice\r\n"),
            None
        );
    }

    #[test]
    fn cleartext_cred_sniff_negatives() {
        let tcp = Transport::Tcp;
        // A plain HTTP request with no auth header.
        assert_eq!(
            sniff_cleartext_cred(tcp, 50000, 80, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
            None
        );
        // "Authorization:" in a non-request body must not match (we require an HTTP request).
        assert_eq!(
            sniff_cleartext_cred(tcp, 50000, 80, b"random bytes Authorization: Basic xx"),
            None
        );
        // UDP and empty payloads never match.
        assert_eq!(
            sniff_cleartext_cred(Transport::Udp, 0, 80, b"Authorization: Basic x"),
            None
        );
        assert_eq!(sniff_cleartext_cred(tcp, 50000, 80, b""), None);

        // The literal in a request URI/query must NOT match (anchored to header lines).
        assert_eq!(
            sniff_cleartext_cred(
                tcp,
                50000,
                80,
                b"GET /r?h=authorization:basic%20x HTTP/1.1\r\nHost: x\r\n\r\n"
            ),
            None
        );
        // The literal echoed in a request BODY must NOT match (body is never scanned).
        assert_eq!(
            sniff_cleartext_cred(
                tcp,
                50000,
                80,
                b"POST /log HTTP/1.1\r\nHost: x\r\n\r\n{\"h\":\"Authorization: Basic QQ==\"}"
            ),
            None
        );
        // ...but a real header line after a body-less request still fires.
        assert_eq!(
            sniff_cleartext_cred(
                tcp,
                50000,
                80,
                b"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic QQ==\r\n\r\n"
            ),
            Some(CredScheme::HttpBasic)
        );
    }

    #[test]
    fn pii_sniff_detects_credit_cards() {
        let tcp = Transport::Tcp;
        // Visa / Amex / Mastercard test numbers (all Luhn-valid), each near a card field name.
        let visa = b"POST /pay HTTP/1.1\r\n\r\ncard=4111111111111111&cvv=123";
        assert_eq!(sniff_pii(tcp, visa), Some(PiiKind::CreditCard));
        let amex = b"card number: 378282246310005";
        assert_eq!(sniff_pii(tcp, amex), Some(PiiKind::CreditCard));
        // Grouped with spaces (as cards are often written).
        let grouped = b"pan=5555 5555 5555 4444 exp=12/30";
        assert_eq!(sniff_pii(tcp, grouped), Some(PiiKind::CreditCard));
        let dashed = b"credit card: 4012-8888-8888-1881"; // Visa test number, dash-grouped
        assert_eq!(sniff_pii(tcp, dashed), Some(PiiKind::CreditCard));
        // UTF-8 text with high bytes is still scanned (control-byte text gate, not ASCII-only).
        let utf8 = "café — card=4111111111111111".as_bytes();
        assert_eq!(sniff_pii(tcp, utf8), Some(PiiKind::CreditCard));
    }

    #[test]
    fn pii_sniff_detects_ssn() {
        assert_eq!(
            sniff_pii(Transport::Tcp, b"ssn=123-45-6789 dob=..."),
            Some(PiiKind::Ssn)
        );
        assert_eq!(
            sniff_pii(Transport::Tcp, b"Social Security: 078-05-1120"),
            Some(PiiKind::Ssn)
        );
    }

    #[test]
    fn pii_sniff_negatives() {
        let tcp = Transport::Tcp;
        // A Luhn-valid Visa-shaped run with NO card keyword nearby is NOT reported (the dominant
        // false-positive: a benign 4-prefixed numeric id).
        assert_eq!(sniff_pii(tcp, b"orderId=4111111111111111 ok"), None);
        // A card keyword but a Luhn-FAILING number must not match.
        assert_eq!(sniff_pii(tcp, b"card=4111111111111112"), None);
        // Luhn-valid but no recognized issuer prefix / length (an 8-digit order id), with keyword.
        assert_eq!(sniff_pii(tcp, b"card=00000000"), None);
        // A bare 9-digit number is NOT an SSN (requires the dashed shape).
        assert_eq!(sniff_pii(tcp, b"ssn 123456789 ok"), None);
        // An SSN-shaped run embedded in a longer digit string is rejected.
        assert_eq!(sniff_pii(tcp, b"ssn=9123-45-67890"), None);
        // SSN-shaped with a keyword but an invalid group (00) or all-zero serial is rejected.
        assert_eq!(sniff_pii(tcp, b"ssn=123-00-6789"), None);
        assert_eq!(sniff_pii(tcp, b"ssn=123-45-0000"), None);
        // A dashed 3-2-4 code with NO ssn keyword (a benign product code) is NOT reported.
        assert_eq!(sniff_pii(tcp, b"part 123-45-6789 qty 2"), None);
        // Binary / non-text payload skips the scan even if digits line up.
        let mut bin = vec![0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        bin.extend_from_slice(b"card=4111111111111111");
        assert_eq!(sniff_pii(tcp, &bin), None);
        // UDP and empty never match.
        assert_eq!(sniff_pii(Transport::Udp, b"card=4111111111111111"), None);
        assert_eq!(sniff_pii(tcp, b""), None);
    }

    #[test]
    fn dns_port_hint() {
        assert!(is_dns_port(53, 12345));
        assert!(is_dns_port(40000, 53));
        assert!(!is_dns_port(80, 443));
        assert_eq!(
            l7_hint(Transport::Udp, 40000, 53, &[]),
            Some(L7Hint::Dns { qname: None })
        );
    }

    #[test]
    fn tls_client_hello_sni_extraction() {
        let payload = build_client_hello(Some("example.com"));
        assert_eq!(sniff_tls_sni(&payload), Some("example.com".to_string()));
        match l7_hint(Transport::Tcp, 50000, 443, &payload) {
            Some(L7Hint::Tls { sni, .. }) => assert_eq!(sni, Some("example.com".to_string())),
            other => panic!("expected TLS hint, got {other:?}"),
        }
    }

    #[test]
    fn tls_client_hello_without_sni() {
        let payload = build_client_hello(None);
        assert_eq!(sniff_tls_sni(&payload), None);
        // Still recognized as a ClientHello (Some(None)).
        assert_eq!(sniff_tls_client_hello(&payload), Some(None));
    }

    #[test]
    fn tls_sniffer_rejects_non_tls() {
        assert_eq!(sniff_tls_client_hello(b"GET / HTTP/1.1"), None);
        assert_eq!(sniff_tls_client_hello(&[]), None);
        // Truncated TLS record must not panic.
        assert_eq!(sniff_tls_client_hello(&[22, 3, 1, 0]), None);
    }

    // --- L7 decode integration --------------------------------------------------------

    #[test]
    fn decode_sets_tls_hint_and_sni_wellformed() {
        // IPv4/TCP :443 carrying a well-formed ClientHello (strict parser path).
        let ch = build_client_hello(Some("decode.example"));
        let total = (20 + 20 + ch.len()) as u16;
        let mut pkt = ipv4_header(6, total, 0, 64);
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&50000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 0x50; // data offset 5
        tcp[13] = 0x18; // PSH|ACK
        pkt.extend_from_slice(&tcp);
        pkt.extend_from_slice(&ch);
        let m = decode_frame(&frame(LinkType::RawIpv4, &pkt)).unwrap();
        assert_eq!(m.app_proto, AppProto::Tls);
        assert_eq!(m.sni.as_deref(), Some("decode.example"));
        // TCP TLS JA4 must be present and start with 't' (mirrors the QUIC 'q' assertion).
        let ja4 = m.ja4.as_deref().expect("TCP TLS JA4 present");
        assert!(
            ja4.starts_with('t'),
            "TCP TLS JA4 must start with 't', got: {ja4}"
        );
    }

    #[test]
    fn decode_sets_tls_hint_via_signature_fallback_no_sni() {
        // A structurally-recognizable ClientHello (16 03 03 .. 01) too short for the strict
        // SNI parser: the signature fallback fires (app_proto=Tls) with no SNI extracted.
        let ch: &[u8] = &[22, 3, 3, 0, 2, 1, 0];
        let total = (20 + 20 + ch.len()) as u16;
        let mut pkt = ipv4_header(6, total, 0, 64);
        let mut tcp = vec![0u8; 20];
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x18;
        pkt.extend_from_slice(&tcp);
        pkt.extend_from_slice(ch);
        let m = decode_frame(&frame(LinkType::RawIpv4, &pkt)).unwrap();
        assert_eq!(m.app_proto, AppProto::Tls);
        assert_eq!(m.sni, None); // recognized structurally, no SNI extracted
    }

    #[test]
    fn decode_generator_clienthello_yields_sni() {
        // The generator now emits a full ClientHello with a real SNI extension; the strict
        // parser must recover the host end to end.
        let ch = crate::gen::frames::tls_client_hello_payload("gen.example.net");
        let total = (20 + 20 + ch.len()) as u16;
        let mut pkt = ipv4_header(6, total, 0, 64);
        let mut tcp = vec![0u8; 20];
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x18;
        pkt.extend_from_slice(&tcp);
        pkt.extend_from_slice(&ch);
        let m = decode_frame(&frame(LinkType::RawIpv4, &pkt)).unwrap();
        assert_eq!(m.app_proto, AppProto::Tls);
        assert_eq!(m.sni.as_deref(), Some("gen.example.net"));
    }

    #[test]
    fn decode_sets_http_hint_no_sni_nonstandard_port() {
        let body = b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n";
        let total = (20 + 20 + body.len()) as u16;
        let mut pkt = ipv4_header(6, total, 0, 64);
        let mut tcp = vec![0u8; 20];
        tcp[2..4].copy_from_slice(&8080u16.to_be_bytes()); // non-standard HTTP port
        tcp[12] = 0x50;
        tcp[13] = 0x18;
        pkt.extend_from_slice(&tcp);
        pkt.extend_from_slice(body);
        let m = decode_frame(&frame(LinkType::RawIpv4, &pkt)).unwrap();
        assert_eq!(m.app_proto, AppProto::Http);
        assert_eq!(m.sni, None);
    }

    // ── QUIC Initial → SNI integration ──────────────────────────────────────────

    /// Helper: the RFC 9001 §A.2 protected Initial packet (1200 bytes).
    /// Shared with decode tests so the decode path can be exercised end-to-end
    /// without duplicating the byte literal here.
    fn rfc9001_a2_udp_payload() -> Vec<u8> {
        fn hex(s: &str) -> Vec<u8> {
            let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        let pkt = hex("c000000001088394c8f03e5157080000\
             449e7b9aec34d1b1c98dd7689fb8ec11\
             d242b123dc9bd8bab936b47d92ec356c\
             0bab7df5976d27cd449f63300099f399\
             1c260ec4c60d17b31f8429157bb35a12\
             82a643a8d2262cad67500cadb8e7378c\
             8eb7539ec4d4905fed1bee1fc8aafba1\
             7c750e2c7ace01e6005f80fcb7df6212\
             30c83711b39343fa028cea7f7fb5ff89\
             eac2308249a02252155e2347b63d58c5\
             457afd84d05dfffdb20392844ae81215\
             4682e9cf012f9021a6f0be17ddd0c208\
             4dce25ff9b06cde535d0f920a2db1bf3\
             62c23e596d11a4f5a6cf3948838a3aec\
             4e15daf8500a6ef69ec4e3feb6b1d98e\
             610ac8b7ec3faf6ad760b7bad1db4ba3\
             485e8a94dc250ae3fdb41ed15fb6a8e5\
             eba0fc3dd60bc8e30c5c4287e53805db\
             059ae0648db2f64264ed5e39be2e20d8\
             2df566da8dd5998ccabdae053060ae6c\
             7b4378e846d29f37ed7b4ea9ec5d82e7\
             961b7f25a9323851f681d582363aa5f8\
             9937f5a67258bf63ad6f1a0b1d96dbd4\
             faddfcefc5266ba6611722395c906556\
             be52afe3f565636ad1b17d508b73d874\
             3eeb524be22b3dcbc2c7468d54119c74\
             68449a13d8e3b95811a198f3491de3e7\
             fe942b330407abf82a4ed7c1b311663a\
             c69890f4157015853d91e923037c227a\
             33cdd5ec281ca3f79c44546b9d90ca00\
             f064c99e3dd97911d39fe9c5d0b23a22\
             9a234cb36186c4819e8b9c5927726632\
             291d6a418211cc2962e20fe47feb3edf\
             330f2c603a9d48c0fcb5699dbfe58964\
             25c5bac4aee82e57a85aaf4e2513e4f0\
             5796b07ba2ee47d80506f8d2c25e50fd\
             14de71e6c418559302f939b0e1abd576\
             f279c4b2e0feb85c1f28ff18f58891ff\
             ef132eef2fa09346aee33c28eb130ff2\
             8f5b766953334113211996d20011a198\
             e3fc433f9f2541010ae17c1bf202580f\
             6047472fb36857fe843b19f5984009dd\
             c324044e847a4f4a0ab34f719595de37\
             252d6235365e9b84392b061085349d73\
             203a4a13e96f5432ec0fd4a1ee65accd\
             d5e3904df54c1da510b0ff20dcc0c77f\
             cb2c0e0eb605cb0504db87632cf3d8b4\
             dae6e705769d1de354270123cb11450e\
             fc60ac47683d7b8d0f811365565fd98c\
             4c8eb936bcab8d069fc33bd801b03ade\
             a2e1fbc5aa463d08ca19896d2bf59a07\
             1b851e6c239052172f296bfb5e724047\
             90a2181014f3b94a4e97d117b4381303\
             68cc39dbb2d198065ae3986547926cd2\
             162f40a29f0c3c8745c0f50fba3852e5\
             66d44575c29d39a03f0cda721984b6f4\
             40591f355e12d439ff150aab7613499d\
             bd49adabc8676eef023b15b65bfc5ca0\
             6948109f23f350db82123535eb8a7433\
             bdabcb909271a6ecbcb58b936a88cd4e\
             8f2e6ff5800175f113253d8fa9ca8885\
             c2f552e657dc603f252e1a8e308f76f0\
             be79e2fb8f5d5fbbe2e30ecadd220723\
             c8c0aea8078cdfcb3868263ff8f09400\
             54da48781893a7e49ad5aff4af300cd8\
             04a6b6279ab3ff3afb64491c85194aab\
             760d58a606654f9f4400e8b38591356f\
             bf6425aca26dc85244259ff2b19c41b9\
             f96f3ca9ec1dde434da7d2d392b905dd\
             f3d1f9af93d1af5950bd493f5aa731b4\
             056df31bd267b6b90a079831aaf579be\
             0a39013137aac6d404f518cfd4684064\
             7e78bfe706ca4cf5e9c5453e9f7cfd2b\
             8b4c8d169a44e55c88d4a9a7f9474241\
             e221af44860018ab0856972e194cd934");
        assert_eq!(pkt.len(), 1200, "A.2 packet must be 1200 bytes");
        pkt
    }

    /// Build a minimal IPv4/UDP frame carrying `udp_payload`.
    fn ipv4_udp_frame(src_port: u16, dst_port: u16, udp_payload: &[u8]) -> Vec<u8> {
        let udp_len = (8 + udp_payload.len()) as u16;
        let total_len = 20u16 + udp_len;
        let mut ip = ipv4_header(17, total_len, 0, 64);
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&src_port.to_be_bytes());
        udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
        ip.extend_from_slice(&udp);
        ip.extend_from_slice(udp_payload);
        ip
    }

    /// QUIC Initial on UDP :443 → decode extracts SNI "example.com" (RFC 9001 §A.2 golden vector).
    #[test]
    fn decode_quic_initial_udp_sets_sni() {
        let quic_payload = rfc9001_a2_udp_payload();
        let pkt = ipv4_udp_frame(12345, 443, &quic_payload);
        let m = decode_frame(&frame(LinkType::RawIpv4, &pkt)).unwrap();
        assert_eq!(m.app_proto, AppProto::Tls);
        assert_eq!(
            m.sni.as_deref(),
            Some("example.com"),
            "QUIC Initial must yield SNI example.com"
        );
        // JA3 and JA4 must also be populated (the fingerprint parser succeeds on this ClientHello).
        assert!(
            m.ja3.is_some(),
            "JA3 must be set for QUIC Initial ClientHello"
        );
        assert!(
            m.ja4.is_some(),
            "JA4 must be set for QUIC Initial ClientHello"
        );
        // JA4 must start with 'q' for QUIC (FoxIO spec protocol letter).
        assert!(
            m.ja4.as_deref().unwrap().starts_with('q'),
            "QUIC JA4 must start with 'q', got: {:?}",
            m.ja4
        );
    }

    /// Non-QUIC UDP payload (a DNS query) on :443 → sni unchanged (None), no panic.
    /// The form-bit precheck (0xC0) must reject ordinary UDP before any crypto.
    #[test]
    fn decode_non_quic_udp_no_sni_no_panic() {
        // A minimal DNS query payload (does not start with 0xC0).
        let dns = crate::gen::frames::dns_query_payload("example.com", 1);
        // Use port 443 to confirm the QUIC branch doesn't misfire on non-QUIC bytes.
        let pkt = ipv4_udp_frame(54321, 443, &dns);
        let m = decode_frame(&frame(LinkType::RawIpv4, &pkt)).unwrap();
        // Not a QUIC packet → sni/ja3/ja4 all None; app_proto is not Tls.
        assert_eq!(m.sni, None, "non-QUIC UDP must not set SNI");
        assert_eq!(m.ja3, None);
        assert_eq!(m.ja4, None);
        // DNS query on port 443 won't be detected as DNS (not port 53) so Unknown.
        assert_eq!(m.app_proto, AppProto::Unknown);
    }

    #[test]
    fn decode_sets_dns_hint_by_port_empty_payload() {
        let mut pkt = ipv4_header(17, 28, 0, 64); // 20 ip + 8 udp, no payload
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&53u16.to_be_bytes());
        udp[2..4].copy_from_slice(&40000u16.to_be_bytes());
        udp[4..6].copy_from_slice(&8u16.to_be_bytes());
        pkt.extend_from_slice(&udp);
        let m = decode_frame(&frame(LinkType::RawIpv4, &pkt)).unwrap();
        assert_eq!(m.app_proto, AppProto::Dns);
        assert_eq!(m.sni, None);
    }

    #[test]
    fn decode_common_path_leaves_hint_unknown_no_alloc() {
        let mut pkt = ipv4_header(6, 40, 0, 64);
        let mut tcp = vec![0u8; 20];
        tcp[2..4].copy_from_slice(&31337u16.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x02; // bare SYN, no payload
        pkt.extend_from_slice(&tcp);
        let m = decode_frame(&frame(LinkType::RawIpv4, &pkt)).unwrap();
        assert_eq!(m.app_proto, AppProto::Unknown);
        assert_eq!(m.sni, None);
    }

    /// Build a minimal-but-well-formed TLS ClientHello record, optionally with an SNI
    /// extension carrying `host`.
    fn build_client_hello(host: Option<&str>) -> Vec<u8> {
        // Handshake body (after the 4-byte handshake header).
        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
        hs_body.extend_from_slice(&[0u8; 32]); // random
        hs_body.push(0); // session_id length 0
        hs_body.extend_from_slice(&[0x00, 0x02]); // cipher_suites length 2
        hs_body.extend_from_slice(&[0x00, 0x2f]); // one cipher suite
        hs_body.push(1); // compression methods length 1
        hs_body.push(0); // null compression

        // Extensions.
        let mut exts = Vec::new();
        if let Some(h) = host {
            let hb = h.as_bytes();
            // server_name entry: name_type(0) + name_len(2) + name.
            let mut entry = Vec::new();
            entry.push(0);
            entry.extend_from_slice(&(hb.len() as u16).to_be_bytes());
            entry.extend_from_slice(hb);
            // server_name_list = list_len(2) + entry.
            let mut snl = Vec::new();
            snl.extend_from_slice(&(entry.len() as u16).to_be_bytes());
            snl.extend_from_slice(&entry);
            // extension = type(0x0000) + len(2) + snl.
            exts.extend_from_slice(&[0x00, 0x00]);
            exts.extend_from_slice(&(snl.len() as u16).to_be_bytes());
            exts.extend_from_slice(&snl);
        }
        hs_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs_body.extend_from_slice(&exts);

        // Handshake header: msg_type(1=ClientHello) + length(3).
        let mut handshake = Vec::new();
        handshake.push(1);
        let len = hs_body.len();
        handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        handshake.extend_from_slice(&hs_body);

        // TLS record header: content_type(22) + version(2) + length(2).
        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&[0x03, 0x01]); // record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn sniff_dns_qname_parses_a_generated_query() {
        let payload = crate::gen::frames::dns_query_payload("abc.example.com", 0x1234);
        assert_eq!(
            sniff_dns_qname(&payload).as_deref(),
            Some("abc.example.com")
        );
    }

    #[test]
    fn sniff_dns_qname_parses_a_long_tunnel_label() {
        let qname = "k7f9q2x8b3z1a5w0.tunnel.evil.example";
        let payload = crate::gen::frames::dns_query_payload(qname, 1);
        assert_eq!(sniff_dns_qname(&payload).as_deref(), Some(qname));
    }

    #[test]
    fn sniff_dns_qname_rejects_short_or_empty_payload() {
        assert_eq!(sniff_dns_qname(&[]), None);
        assert_eq!(sniff_dns_qname(&[0u8; 8]), None);
    }

    #[test]
    fn sniff_dns_qname_rejects_zero_question_count() {
        // 12-byte header with QDCOUNT = 0, then a stray byte.
        let mut p = vec![0u8; 12];
        p[4] = 0;
        p[5] = 0; // qdcount
        p.push(0x00);
        assert_eq!(sniff_dns_qname(&p), None);
    }

    #[test]
    fn sniff_dns_qname_handles_truncated_label_without_panic() {
        // Header (qdcount=1) then a label claiming 40 bytes with only 3 present.
        let mut p = vec![0u8; 12];
        p[5] = 1; // qdcount = 1
        p.push(40); // label length 40
        p.extend_from_slice(b"abc"); // only 3 bytes follow
        assert_eq!(sniff_dns_qname(&p), None);
    }

    #[test]
    fn sniff_dns_qname_aborts_on_compression_pointer() {
        // Header (qdcount=1) then a compression pointer (0xC0 0x0C) as the first label.
        let mut p = vec![0u8; 12];
        p[5] = 1;
        p.push(0xC0);
        p.push(0x0C);
        // A pointer at the very start yields no label -> None; must not panic or loop.
        assert_eq!(sniff_dns_qname(&p), None);
    }

    #[test]
    fn sniff_dns_qname_never_panics_on_arbitrary_bytes() {
        // Adversarial / fuzzy inputs: the parser must always return, never panic.
        for seed in 0u16..2000 {
            let mut p = vec![0u8; 12];
            p[5] = 1;
            // Fill a pseudo-random tail.
            let mut x = seed as u32;
            for _ in 0..(seed % 80) as usize {
                x = x.wrapping_mul(1103515245).wrapping_add(12345);
                p.push((x >> 16) as u8);
            }
            let _ = sniff_dns_qname(&p); // just must not panic
        }
    }
}
