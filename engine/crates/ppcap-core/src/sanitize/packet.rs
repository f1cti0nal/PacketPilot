//! Per-frame sanitization: parse L2/L3/L4 by offset, pseudonymize addresses,
//! scrub or redact payloads, and recompute checksums — all in place, never
//! changing a single length, so flow structure, sequence numbers, and container
//! bookkeeping survive untouched.
//!
//! Parsing here is deliberately independent of the analysis decoder: the
//! sanitizer needs *byte offsets to mutate*, not semantic metadata, and it must
//! stay conservative — anything it cannot confidently parse is handled by the
//! opaque-payload policy (scrubbed in `Scrub` mode, counted either way) rather
//! than guessed at. No code path can panic on hostile input.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::anon::Anonymizer;
use super::checksum;
use super::l7::{self, RedactionCounts};
use super::{PayloadMode, SanitizeCounts, SanitizeOptions};
use crate::reader::LinkType;

/// Sanitize one captured frame in place. `wire_len` is the original (untruncated)
/// length from the container record; `buf` holds the `cap_len` captured bytes.
pub(crate) fn sanitize_frame(
    buf: &mut [u8],
    link: LinkType,
    wire_len: u32,
    anon: &mut Anonymizer,
    opts: &SanitizeOptions,
    counts: &mut SanitizeCounts,
) {
    let mut red = RedactionCounts::default();
    match link {
        LinkType::Ethernet => sanitize_ethernet(buf, 0, wire_len, anon, opts, counts, &mut red),
        LinkType::LinuxSll => {
            // pkttype(2) arphrd(2) halen(2) addr(8) proto(2) → L3 at 16.
            if buf.len() >= 16 {
                let halen = u16::from_be_bytes([buf[4], buf[5]]);
                if halen == 6 {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&buf[6..12]);
                    let out = anon.mac(mac);
                    if out != mac {
                        counts.macs_rewritten += 1;
                    }
                    buf[6..12].copy_from_slice(&out);
                }
                let ethertype = u16::from_be_bytes([buf[14], buf[15]]);
                dispatch_l3(buf, 16, ethertype, wire_len, anon, opts, counts, &mut red);
            } else {
                counts.passthrough_frames += 1;
            }
        }
        LinkType::LinuxSll2 => {
            // proto(2) mbz(2) ifindex(4) arphrd(2) pkttype(1) halen(1) addr(8) → L3 at 20.
            if buf.len() >= 20 {
                if buf[11] == 6 {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&buf[12..18]);
                    let out = anon.mac(mac);
                    if out != mac {
                        counts.macs_rewritten += 1;
                    }
                    buf[12..18].copy_from_slice(&out);
                }
                let ethertype = u16::from_be_bytes([buf[0], buf[1]]);
                dispatch_l3(buf, 20, ethertype, wire_len, anon, opts, counts, &mut red);
            } else {
                counts.passthrough_frames += 1;
            }
        }
        LinkType::Null => {
            // 4-byte host-order family; 2 = INET, {24,28,30} = INET6 (BSD variants).
            if buf.len() >= 4 {
                let fam_le = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                let fam_be = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                let fam = if fam_le <= 255 { fam_le } else { fam_be };
                match fam {
                    2 => sanitize_ipv4(buf, 4, wire_len, anon, opts, counts, &mut red),
                    24 | 28 | 30 => sanitize_ipv6(buf, 4, wire_len, anon, opts, counts, &mut red),
                    _ => counts.passthrough_frames += 1,
                }
            } else {
                counts.passthrough_frames += 1;
            }
        }
        LinkType::RawIpv4 => sanitize_ipv4(buf, 0, wire_len, anon, opts, counts, &mut red),
        LinkType::RawIpv6 => sanitize_ipv6(buf, 0, wire_len, anon, opts, counts, &mut red),
        LinkType::Raw => match buf.first().map(|b| b >> 4) {
            Some(4) => sanitize_ipv4(buf, 0, wire_len, anon, opts, counts, &mut red),
            Some(6) => sanitize_ipv6(buf, 0, wire_len, anon, opts, counts, &mut red),
            _ => counts.passthrough_frames += 1,
        },
        LinkType::Unsupported(_) => counts.passthrough_frames += 1,
    }
    counts.dns_names_redacted += red.dns_names;
    counts.http_fields_redacted += red.http_fields;
    counts.tls_snis_redacted += red.tls_snis;
    counts.credentials_redacted += red.credentials;
    counts.rdata_addrs_rewritten += red.rdata_addrs;
}

#[allow(clippy::too_many_arguments)]
fn sanitize_ethernet(
    buf: &mut [u8],
    off: usize,
    wire_len: u32,
    anon: &mut Anonymizer,
    opts: &SanitizeOptions,
    counts: &mut SanitizeCounts,
    red: &mut RedactionCounts,
) {
    if buf.len() < off + 14 {
        counts.passthrough_frames += 1;
        return;
    }
    for range in [off..off + 6, off + 6..off + 12] {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&buf[range.clone()]);
        let out = anon.mac(mac);
        if out != mac {
            counts.macs_rewritten += 1;
        }
        buf[range].copy_from_slice(&out);
    }
    let mut pos = off + 12;
    let mut ethertype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;
    // Peel up to three stacked VLAN tags (802.1Q / 802.1ad / legacy QinQ).
    let mut vlan_depth = 0;
    while matches!(ethertype, 0x8100 | 0x88A8 | 0x9100) && vlan_depth < 3 {
        if buf.len() < pos + 4 {
            counts.passthrough_frames += 1;
            return;
        }
        ethertype = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        pos += 4;
        vlan_depth += 1;
    }
    dispatch_l3(buf, pos, ethertype, wire_len, anon, opts, counts, red);
}

/// Route an L3 payload by ethertype. Unknown ethertypes (LLDP, MPLS, …) fall
/// under the opaque policy: scrubbed after the link header in `Scrub` mode so
/// they cannot leak hostnames or inner addresses, left intact in `Keep` mode.
#[allow(clippy::too_many_arguments)]
fn dispatch_l3(
    buf: &mut [u8],
    off: usize,
    ethertype: u16,
    wire_len: u32,
    anon: &mut Anonymizer,
    opts: &SanitizeOptions,
    counts: &mut SanitizeCounts,
    red: &mut RedactionCounts,
) {
    match ethertype {
        0x0800 => sanitize_ipv4(buf, off, wire_len, anon, opts, counts, red),
        0x86DD => sanitize_ipv6(buf, off, wire_len, anon, opts, counts, red),
        0x0806 => sanitize_arp(buf, off, anon, counts),
        _ => {
            if opts.payload == PayloadMode::Scrub && off < buf.len() {
                counts.payload_bytes_scrubbed += scrub_range(buf, off, buf.len(), opts.keep_first);
                counts.opaque_l3_scrubbed += 1;
            } else {
                counts.passthrough_frames += 1;
            }
        }
    }
}

/// ARP (Ethernet/IPv4 flavor): pseudonymize sender/target hardware and protocol
/// addresses with the same mappings as everything else, keeping the structure.
fn sanitize_arp(buf: &mut [u8], off: usize, anon: &mut Anonymizer, counts: &mut SanitizeCounts) {
    if buf.len() < off + 8 {
        counts.passthrough_frames += 1;
        return;
    }
    let hlen = buf[off + 4] as usize;
    let plen = buf[off + 5] as usize;
    let need = off + 8 + 2 * (hlen + plen);
    if buf.len() < need {
        counts.passthrough_frames += 1;
        return;
    }
    let mut pos = off + 8;
    for _ in 0..2 {
        if hlen == 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&buf[pos..pos + 6]);
            let out = anon.mac(mac);
            if out != mac {
                counts.macs_rewritten += 1;
            }
            buf[pos..pos + 6].copy_from_slice(&out);
        }
        pos += hlen;
        if plen == 4 {
            let ip = Ipv4Addr::new(buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]);
            let out = anon.ipv4(ip);
            if out != ip {
                counts.ipv4_rewritten += 1;
            }
            buf[pos..pos + 4].copy_from_slice(&out.octets());
        }
        pos += plen;
    }
    counts.arp_rewritten += 1;
}

#[allow(clippy::too_many_arguments)]
fn sanitize_ipv4(
    buf: &mut [u8],
    off: usize,
    wire_len: u32,
    anon: &mut Anonymizer,
    opts: &SanitizeOptions,
    counts: &mut SanitizeCounts,
    red: &mut RedactionCounts,
) {
    if buf.len() < off + 20 || buf[off] >> 4 != 4 {
        counts.passthrough_frames += 1;
        return;
    }
    let ihl = ((buf[off] & 0x0F) as usize) * 4;
    if ihl < 20 || buf.len() < off + ihl {
        counts.passthrough_frames += 1;
        return;
    }
    let total_len = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
    let proto = buf[off + 9];
    let frag = u16::from_be_bytes([buf[off + 6], buf[off + 7]]);
    let frag_offset = frag & 0x1FFF;

    // Pseudonymize addresses.
    let src = Ipv4Addr::new(buf[off + 12], buf[off + 13], buf[off + 14], buf[off + 15]);
    let dst = Ipv4Addr::new(buf[off + 16], buf[off + 17], buf[off + 18], buf[off + 19]);
    let (nsrc, ndst) = (anon.ipv4(src), anon.ipv4(dst));
    if nsrc != src {
        counts.ipv4_rewritten += 1;
    }
    if ndst != dst {
        counts.ipv4_rewritten += 1;
    }
    buf[off + 12..off + 16].copy_from_slice(&nsrc.octets());
    buf[off + 16..off + 20].copy_from_slice(&ndst.octets());

    // Zero any Ethernet trailer padding beyond the IP datagram (it can carry
    // stale memory — the classic "etherleak").
    let l3_end = (off + total_len).min(buf.len());
    if total_len >= 20 && l3_end < buf.len() {
        counts.payload_bytes_scrubbed += scrub_range(buf, l3_end, buf.len(), 0);
    }

    let l4_off = off + ihl;
    if frag_offset > 0 {
        // Non-first fragment: no L4 header present — payload is opaque.
        scrub_payload_policy(buf, l4_off, l3_end, opts, counts);
    } else if l4_off <= l3_end {
        sanitize_l4(
            buf,
            l4_off,
            l3_end,
            L3::V4 {
                src: nsrc.octets(),
                dst: ndst.octets(),
                proto,
            },
            proto,
            wire_len,
            total_len.saturating_sub(ihl),
            anon,
            opts,
            counts,
            red,
        );
    }

    // Header checksum last, over the final header bytes.
    let c = checksum::ipv4_header(&buf[off..off + ihl]).to_be_bytes();
    buf[off + 10] = c[0];
    buf[off + 11] = c[1];
    counts.l3_checksums_recomputed += 1;
}

#[allow(clippy::too_many_arguments)]
fn sanitize_ipv6(
    buf: &mut [u8],
    off: usize,
    wire_len: u32,
    anon: &mut Anonymizer,
    opts: &SanitizeOptions,
    counts: &mut SanitizeCounts,
    red: &mut RedactionCounts,
) {
    if buf.len() < off + 40 || buf[off] >> 4 != 6 {
        counts.passthrough_frames += 1;
        return;
    }
    let payload_len = u16::from_be_bytes([buf[off + 4], buf[off + 5]]) as usize;

    let mut s = [0u8; 16];
    s.copy_from_slice(&buf[off + 8..off + 24]);
    let mut d = [0u8; 16];
    d.copy_from_slice(&buf[off + 24..off + 40]);
    let (src, dst) = (Ipv6Addr::from(s), Ipv6Addr::from(d));
    let (nsrc, ndst) = (anon.ipv6(src), anon.ipv6(dst));
    if nsrc != src {
        counts.ipv6_rewritten += 1;
    }
    if ndst != dst {
        counts.ipv6_rewritten += 1;
    }
    buf[off + 8..off + 24].copy_from_slice(&nsrc.octets());
    buf[off + 24..off + 40].copy_from_slice(&ndst.octets());

    // Trailer padding beyond the declared datagram (jumbograms declare 0 — skip).
    let l3_end = if payload_len > 0 {
        let end = (off + 40 + payload_len).min(buf.len());
        if end < buf.len() {
            counts.payload_bytes_scrubbed += scrub_range(buf, end, buf.len(), 0);
        }
        end
    } else {
        buf.len()
    };

    // Walk the extension-header chain to the upper-layer protocol.
    let mut next = buf[off + 6];
    let mut pos = off + 40;
    let mut hops = 0;
    loop {
        match next {
            0 | 43 | 60 => {
                // Hop-by-hop / routing / destination options: (ext_len + 1) * 8.
                if pos + 2 > l3_end {
                    return;
                }
                next = buf[pos];
                pos += (buf[pos + 1] as usize + 1) * 8;
            }
            44 => {
                // Fragment header: fixed 8 bytes. Non-zero offset → opaque payload.
                if pos + 8 > l3_end {
                    return;
                }
                let frag_off = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) >> 3;
                next = buf[pos];
                pos += 8;
                if frag_off > 0 {
                    scrub_payload_policy(buf, pos, l3_end, opts, counts);
                    return;
                }
            }
            51 => {
                // Authentication header: (len + 2) * 4.
                if pos + 2 > l3_end {
                    return;
                }
                next = buf[pos];
                pos += (buf[pos + 1] as usize + 2) * 4;
            }
            _ => break,
        }
        hops += 1;
        if hops > 8 || pos > l3_end {
            return; // hostile chain — leave the rest to the container copy
        }
    }
    if pos <= l3_end {
        sanitize_l4(
            buf,
            pos,
            l3_end,
            L3::V6 {
                src: nsrc.octets(),
                dst: ndst.octets(),
                next,
            },
            next,
            wire_len,
            l3_end.saturating_sub(pos),
            anon,
            opts,
            counts,
            red,
        );
    }
}

/// The L3 context an L4 checksum needs.
enum L3 {
    V4 {
        src: [u8; 4],
        dst: [u8; 4],
        proto: u8,
    },
    V6 {
        src: [u8; 16],
        dst: [u8; 16],
        next: u8,
    },
}

/// Sanitize the transport layer starting at `l4_off` (bounded by `l3_end`), then
/// recompute or zero its checksum. `l4_decl_len` is the L4 length the IP header
/// declares — when the capture holds fewer bytes (snaplen truncation) the
/// checksum cannot be recomputed and is zeroed instead.
#[allow(clippy::too_many_arguments)]
fn sanitize_l4(
    buf: &mut [u8],
    l4_off: usize,
    l3_end: usize,
    l3: L3,
    proto: u8,
    wire_len: u32,
    l4_decl_len: usize,
    anon: &mut Anonymizer,
    opts: &SanitizeOptions,
    counts: &mut SanitizeCounts,
    red: &mut RedactionCounts,
) {
    let avail = l3_end.saturating_sub(l4_off);
    // Full L4 data present (no snaplen truncation, no IP fragmentation spillover)?
    let complete = avail >= l4_decl_len && (wire_len as usize) <= buf.len();

    match proto {
        6 => {
            // TCP
            if avail < 20 {
                scrub_payload_policy(buf, l4_off, l3_end, opts, counts);
                return;
            }
            let hdr_len = ((buf[l4_off + 12] >> 4) as usize) * 4;
            if hdr_len < 20 || l4_off + hdr_len > l3_end {
                scrub_payload_policy(buf, l4_off, l3_end, opts, counts);
                return;
            }
            let src_port = u16::from_be_bytes([buf[l4_off], buf[l4_off + 1]]);
            let dst_port = u16::from_be_bytes([buf[l4_off + 2], buf[l4_off + 3]]);
            let pstart = l4_off + hdr_len;
            handle_app_payload(
                buf, pstart, l3_end, src_port, dst_port, true, anon, opts, counts, red,
            );
            finish_l4_checksum(buf, l4_off, l3_end, &l3, l4_off + 16, complete, counts);
        }
        17 => {
            // UDP
            if avail < 8 {
                scrub_payload_policy(buf, l4_off, l3_end, opts, counts);
                return;
            }
            let src_port = u16::from_be_bytes([buf[l4_off], buf[l4_off + 1]]);
            let dst_port = u16::from_be_bytes([buf[l4_off + 2], buf[l4_off + 3]]);
            let had_checksum = buf[l4_off + 6] != 0 || buf[l4_off + 7] != 0;
            handle_app_payload(
                buf,
                l4_off + 8,
                l3_end,
                src_port,
                dst_port,
                false,
                anon,
                opts,
                counts,
                red,
            );
            if matches!(l3, L3::V4 { .. }) && !had_checksum {
                // UDP/IPv4 checksum 0 = "not computed"; keep that, it's valid.
            } else {
                finish_l4_checksum(buf, l4_off, l3_end, &l3, l4_off + 6, complete, counts);
            }
        }
        1 => {
            // ICMPv4: 8-byte header. Error messages embed the offending IP header —
            // anonymize it so the inner addresses can't leak.
            if avail < 8 {
                scrub_payload_policy(buf, l4_off, l3_end, opts, counts);
                return;
            }
            let icmp_type = buf[l4_off];
            let body = l4_off + 8;
            if matches!(icmp_type, 3 | 5 | 11 | 12) {
                anonymize_embedded_ipv4(buf, body, l3_end, anon, counts);
            } else {
                scrub_payload_policy(buf, body, l3_end, opts, counts);
            }
            if complete {
                buf[l4_off + 2] = 0;
                buf[l4_off + 3] = 0;
                let c = checksum::icmp_v4(&buf[l4_off..l3_end]).to_be_bytes();
                buf[l4_off + 2] = c[0];
                buf[l4_off + 3] = c[1];
                counts.l4_checksums_recomputed += 1;
            } else {
                buf[l4_off + 2] = 0;
                buf[l4_off + 3] = 0;
                counts.l4_checksums_zeroed += 1;
            }
        }
        58 => {
            // ICMPv6. NDP (133–137) carries addresses/options that matter for
            // structure — anonymize the target address and any link-layer options;
            // everything else follows the payload policy after the 4-byte header.
            if avail < 4 {
                scrub_payload_policy(buf, l4_off, l3_end, opts, counts);
                return;
            }
            let t = buf[l4_off];
            if matches!(t, 133..=137) {
                sanitize_ndp(buf, l4_off, l3_end, t, anon, counts);
            } else if matches!(t, 1..=4) {
                // Error messages embed the offending IPv6 header.
                anonymize_embedded_ipv6(buf, l4_off + 8, l3_end, anon, counts);
            } else {
                scrub_payload_policy(buf, l4_off + 8.min(avail), l3_end, opts, counts);
            }
            finish_l4_checksum(buf, l4_off, l3_end, &l3, l4_off + 2, complete, counts);
        }
        132 => {
            // SCTP: common header 12 bytes, CRC-32C at offset 8.
            if avail < 12 {
                scrub_payload_policy(buf, l4_off, l3_end, opts, counts);
                return;
            }
            scrub_payload_policy(buf, l4_off + 12, l3_end, opts, counts);
            if complete {
                buf[l4_off + 8..l4_off + 12].fill(0);
                let crc = checksum::crc32c(&buf[l4_off..l3_end]).to_le_bytes();
                buf[l4_off + 8..l4_off + 12].copy_from_slice(&crc);
                counts.l4_checksums_recomputed += 1;
            } else {
                buf[l4_off + 8..l4_off + 12].fill(0);
                counts.l4_checksums_zeroed += 1;
            }
        }
        _ => {
            // Unknown transport (GRE, ESP, …): opaque. Scrub mode wipes it — GRE
            // could tunnel un-pseudonymized inner packets.
            scrub_payload_policy(buf, l4_off, l3_end, opts, counts);
        }
    }
}

/// Zero the L4 checksum field, then recompute it over the (possibly rewritten)
/// segment when the capture is complete, or leave it zeroed (and counted) when not.
fn finish_l4_checksum(
    buf: &mut [u8],
    l4_off: usize,
    l3_end: usize,
    l3: &L3,
    ck_off: usize,
    complete: bool,
    counts: &mut SanitizeCounts,
) {
    if ck_off + 2 > l3_end {
        return;
    }
    buf[ck_off] = 0;
    buf[ck_off + 1] = 0;
    if !complete {
        counts.l4_checksums_zeroed += 1;
        return;
    }
    let seg = &buf[l4_off..l3_end];
    let c = match l3 {
        L3::V4 { src, dst, proto } => checksum::l4_v4(*src, *dst, *proto, seg),
        L3::V6 { src, dst, next } => checksum::l4_v6(*src, *dst, *next, seg),
    };
    let c = c.to_be_bytes();
    buf[ck_off] = c[0];
    buf[ck_off + 1] = c[1];
    counts.l4_checksums_recomputed += 1;
}

/// Apply the payload policy + L7 redaction to an application payload.
#[allow(clippy::too_many_arguments)]
fn handle_app_payload(
    buf: &mut [u8],
    pstart: usize,
    pend: usize,
    src_port: u16,
    dst_port: u16,
    is_tcp: bool,
    anon: &mut Anonymizer,
    opts: &SanitizeOptions,
    counts: &mut SanitizeCounts,
    red: &mut RedactionCounts,
) {
    if pstart >= pend || pstart >= buf.len() {
        return;
    }
    let pend = pend.min(buf.len());

    // In Keep mode (or over the retained head in Scrub mode) run the L7 redactors.
    let redact_end = match opts.payload {
        PayloadMode::Keep => pend,
        PayloadMode::Scrub => (pstart + opts.keep_first).min(pend),
    };
    if opts.redact_l7 && redact_end > pstart {
        let dns_port = src_port == 53 || dst_port == 53 || src_port == 5353 || dst_port == 5353;
        let seg = &mut buf[pstart..redact_end];
        if dns_port {
            if is_tcp {
                // TCP DNS: 2-byte length prefix, then the message.
                if seg.len() > 2 {
                    let (_, msg) = seg.split_at_mut(2);
                    let _ = l7::redact_dns(anon, msg, red);
                }
            } else {
                let _ = l7::redact_dns(anon, seg, red);
            }
        } else if is_tcp {
            let redacted = l7::redact_tls_sni(anon, seg, red) || l7::redact_http(anon, seg, red);
            if !redacted && l7::is_cred_port(src_port.min(dst_port)) {
                l7::redact_cleartext_creds(anon, seg, red);
            }
        }
    }

    if opts.payload == PayloadMode::Scrub {
        counts.payload_bytes_scrubbed += scrub_range(buf, pstart, pend, opts.keep_first);
    }
}

/// The opaque-payload policy: scrub (respecting keep_first) in Scrub mode, leave
/// alone in Keep mode.
fn scrub_payload_policy(
    buf: &mut [u8],
    start: usize,
    end: usize,
    opts: &SanitizeOptions,
    counts: &mut SanitizeCounts,
) {
    if opts.payload == PayloadMode::Scrub {
        counts.payload_bytes_scrubbed += scrub_range(buf, start, end, opts.keep_first);
    }
}

/// Zero `buf[start+keep .. end]`; returns bytes zeroed. Bounds-safe.
fn scrub_range(buf: &mut [u8], start: usize, end: usize, keep: usize) -> u64 {
    let end = end.min(buf.len());
    let from = (start + keep).min(end);
    if from >= end {
        return 0;
    }
    buf[from..end].fill(0);
    (end - from) as u64
}

/// Anonymize an IPv4 header embedded in an ICMP error body (plus the first 8
/// bytes of its transport header, which only contain ports/seq — kept).
fn anonymize_embedded_ipv4(
    buf: &mut [u8],
    off: usize,
    end: usize,
    anon: &mut Anonymizer,
    counts: &mut SanitizeCounts,
) {
    if off + 20 > end || off + 20 > buf.len() || buf[off] >> 4 != 4 {
        return;
    }
    let ihl = ((buf[off] & 0x0F) as usize) * 4;
    if ihl < 20 || off + ihl > end.min(buf.len()) {
        return;
    }
    let src = Ipv4Addr::new(buf[off + 12], buf[off + 13], buf[off + 14], buf[off + 15]);
    let dst = Ipv4Addr::new(buf[off + 16], buf[off + 17], buf[off + 18], buf[off + 19]);
    buf[off + 12..off + 16].copy_from_slice(&anon.ipv4(src).octets());
    buf[off + 16..off + 20].copy_from_slice(&anon.ipv4(dst).octets());
    let c = checksum::ipv4_header(&buf[off..off + ihl]).to_be_bytes();
    buf[off + 10] = c[0];
    buf[off + 11] = c[1];
    counts.embedded_headers_rewritten += 1;
}

/// Anonymize an IPv6 header embedded in an ICMPv6 error body.
fn anonymize_embedded_ipv6(
    buf: &mut [u8],
    off: usize,
    end: usize,
    anon: &mut Anonymizer,
    counts: &mut SanitizeCounts,
) {
    if off + 40 > end || off + 40 > buf.len() || buf[off] >> 4 != 6 {
        return;
    }
    let mut s = [0u8; 16];
    s.copy_from_slice(&buf[off + 8..off + 24]);
    let mut d = [0u8; 16];
    d.copy_from_slice(&buf[off + 24..off + 40]);
    let ns = anon.ipv6(Ipv6Addr::from(s));
    let nd = anon.ipv6(Ipv6Addr::from(d));
    buf[off + 8..off + 24].copy_from_slice(&ns.octets());
    buf[off + 24..off + 40].copy_from_slice(&nd.octets());
    counts.embedded_headers_rewritten += 1;
}

/// NDP (ICMPv6 133–137): anonymize the target/destination addresses and any
/// source/target link-layer address options (they carry real MACs).
fn sanitize_ndp(
    buf: &mut [u8],
    l4_off: usize,
    end: usize,
    icmp_type: u8,
    anon: &mut Anonymizer,
    counts: &mut SanitizeCounts,
) {
    // Options start after the fixed part; NS/NA/redirect carry a 16-byte target
    // address at offset 8 (redirect has a second, the destination, at 24).
    let mut opt_off = match icmp_type {
        133 => l4_off + 8,  // RS
        134 => l4_off + 16, // RA
        135 | 136 => {
            if l4_off + 24 <= end && l4_off + 24 <= buf.len() {
                let mut t = [0u8; 16];
                t.copy_from_slice(&buf[l4_off + 8..l4_off + 24]);
                let out = anon.ipv6(Ipv6Addr::from(t));
                buf[l4_off + 8..l4_off + 24].copy_from_slice(&out.octets());
            }
            l4_off + 24
        }
        137 => {
            for base in [l4_off + 8, l4_off + 24] {
                if base + 16 <= end && base + 16 <= buf.len() {
                    let mut t = [0u8; 16];
                    t.copy_from_slice(&buf[base..base + 16]);
                    let out = anon.ipv6(Ipv6Addr::from(t));
                    buf[base..base + 16].copy_from_slice(&out.octets());
                }
            }
            l4_off + 40
        }
        _ => return,
    };
    // Options: type(1) len(1, in units of 8) …; types 1/2 = link-layer address.
    let end = end.min(buf.len());
    let mut hops = 0;
    while opt_off + 8 <= end && hops < 16 {
        let olen = (buf[opt_off + 1] as usize) * 8;
        if olen == 0 || opt_off + olen > end {
            break;
        }
        if matches!(buf[opt_off], 1 | 2) && olen >= 8 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&buf[opt_off + 2..opt_off + 8]);
            let out = anon.mac(mac);
            if out != mac {
                counts.macs_rewritten += 1;
            }
            buf[opt_off + 2..opt_off + 8].copy_from_slice(&out);
        }
        opt_off += olen;
        hops += 1;
    }
}
