//! L3 (network) decoding: IPv4 and IPv6 (with bounded extension-header walking).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::PpError;
use crate::model::packet::PacketMeta;
use crate::Result;

/// Maximum number of IPv6 extension headers we will walk before giving up. A legitimate
/// packet never stacks this many; the bound exists purely to defang pathological / hostile
/// chains so the walk can never loop unboundedly.
const MAX_IPV6_EXT_HEADERS: usize = 8;

// IPv6 extension-header / "next header" values that are NOT transport protocols and so are
// walked over to reach L4.
const NH_HOPOPT: u8 = 0; // Hop-by-Hop Options
const NH_ROUTING: u8 = 43; // Routing
const NH_FRAGMENT: u8 = 44; // Fragment
const NH_AH: u8 = 51; // Authentication Header
const NH_DESTOPTS: u8 = 60; // Destination Options
const NH_NO_NEXT: u8 = 59; // No Next Header

#[inline]
fn be_u16(buf: &[u8], off: usize) -> Option<u16> {
    let hi = *buf.get(off)?;
    let lo = *buf.get(off + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

/// Decode an IPv4 header into `meta`, returning `(l4_proto, l4_slice)`.
///
/// An **empty** returned `l4_slice` is the agreed marker for "no first-fragment L4 here"
/// (non-first fragment, or the header consumed the whole captured slice); the L4 decoders
/// treat it as "leave ports/flags at 0".
pub fn decode_ipv4<'a>(bytes: &'a [u8], meta: &mut PacketMeta) -> Result<(u8, &'a [u8])> {
    if bytes.len() < 20 {
        return Err(PpError::Truncated {
            needed: 20,
            had: bytes.len(),
            offset: meta.index,
        });
    }

    let ver_ihl = bytes[0];
    let version = ver_ihl >> 4;
    let ihl_words = (ver_ihl & 0x0F) as usize;
    let header_len = ihl_words * 4;

    if version != 4 || header_len < 20 {
        return Err(PpError::MalformedHeader {
            layer: "ipv4",
            packet_index: meta.index,
            detail: format!("bad version/IHL byte 0x{ver_ihl:02x} (header_len={header_len})"),
        });
    }
    if header_len > bytes.len() {
        return Err(PpError::Truncated {
            needed: header_len,
            had: bytes.len(),
            offset: meta.index,
        });
    }

    meta.l3 = crate::model::packet::Protocol::Ipv4;
    meta.ttl = bytes[8];
    let proto = bytes[9];

    // Addresses (bounds guaranteed: header_len >= 20 <= bytes.len()).
    let src = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let dst = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    meta.src_ip = Some(IpAddr::V4(src));
    meta.dst_ip = Some(IpAddr::V4(dst));

    // total_length and fragmentation.
    let total_length = be_u16(bytes, 2).unwrap_or(0) as usize;
    let flags_frag = be_u16(bytes, 6).unwrap_or(0);
    let frag_offset = flags_frag & 0x1FFF;

    // Seed payload_len for non-port protocols from the IP total length. If total_length is
    // bogus (0 or < header_len) fall back to captured bytes.
    let ip_payload = total_length.saturating_sub(header_len);
    meta.payload_len = ip_payload as u32;

    // Non-first fragment: the L4 header lives in fragment #0, not here. Signal via an
    // empty L4 slice so the transport decoders leave ports/flags at 0.
    if frag_offset != 0 {
        return Ok((proto, &bytes[bytes.len()..]));
    }

    match bytes.split_at_checked(header_len) {
        Some((_, l4)) => Ok((proto, l4)),
        None => Err(PpError::Truncated {
            needed: header_len,
            had: bytes.len(),
            offset: meta.index,
        }),
    }
}

/// Decode an IPv6 header (walking the extension-header chain) into `meta`, returning
/// `(l4_proto, l4_slice)`.
///
/// As with IPv4, an empty returned slice marks "non-first fragment / no L4 here".
pub fn decode_ipv6<'a>(bytes: &'a [u8], meta: &mut PacketMeta) -> Result<(u8, &'a [u8])> {
    if bytes.len() < 40 {
        return Err(PpError::Truncated {
            needed: 40,
            had: bytes.len(),
            offset: meta.index,
        });
    }

    let version = bytes[0] >> 4;
    if version != 6 {
        return Err(PpError::MalformedHeader {
            layer: "ipv6",
            packet_index: meta.index,
            detail: format!("bad version nibble {version}"),
        });
    }

    meta.l3 = crate::model::packet::Protocol::Ipv6;
    meta.ttl = bytes[7]; // hop limit
    let mut next_header = bytes[6];

    let payload_length = be_u16(bytes, 4).unwrap_or(0) as u32;
    meta.payload_len = payload_length;

    let mut src_octets = [0u8; 16];
    let mut dst_octets = [0u8; 16];
    src_octets.copy_from_slice(&bytes[8..24]);
    dst_octets.copy_from_slice(&bytes[24..40]);
    meta.src_ip = Some(IpAddr::V6(Ipv6Addr::from(src_octets)));
    meta.dst_ip = Some(IpAddr::V6(Ipv6Addr::from(dst_octets)));

    let mut offset = 40usize;
    let mut is_non_first_fragment = false;

    for _ in 0..MAX_IPV6_EXT_HEADERS {
        match next_header {
            NH_HOPOPT | NH_ROUTING | NH_DESTOPTS => {
                // Generic extension header: [next_header, hdr_ext_len, ...].
                let nh = match bytes.get(offset) {
                    Some(&v) => v,
                    None => {
                        return Err(PpError::Truncated {
                            needed: offset + 1,
                            had: bytes.len(),
                            offset: meta.index,
                        })
                    }
                };
                let hdr_ext_len = match bytes.get(offset + 1) {
                    Some(&v) => v as usize,
                    None => {
                        return Err(PpError::Truncated {
                            needed: offset + 2,
                            had: bytes.len(),
                            offset: meta.index,
                        })
                    }
                };
                let ext_len = hdr_ext_len.saturating_add(1).saturating_mul(8);
                next_header = nh;
                offset = offset.saturating_add(ext_len);
            }
            NH_AH => {
                // Authentication Header length is in 4-byte units, value = (len+2)*4.
                let nh = match bytes.get(offset) {
                    Some(&v) => v,
                    None => {
                        return Err(PpError::Truncated {
                            needed: offset + 1,
                            had: bytes.len(),
                            offset: meta.index,
                        })
                    }
                };
                let ah_len = match bytes.get(offset + 1) {
                    Some(&v) => v as usize,
                    None => {
                        return Err(PpError::Truncated {
                            needed: offset + 2,
                            had: bytes.len(),
                            offset: meta.index,
                        })
                    }
                };
                let ext_len = ah_len.saturating_add(2).saturating_mul(4);
                next_header = nh;
                offset = offset.saturating_add(ext_len);
            }
            NH_FRAGMENT => {
                // Fixed 8-byte fragment header: [next_header, reserved, frag_off+flags(2),
                // identification(4)].
                let nh = match bytes.get(offset) {
                    Some(&v) => v,
                    None => {
                        return Err(PpError::Truncated {
                            needed: offset + 1,
                            had: bytes.len(),
                            offset: meta.index,
                        })
                    }
                };
                let frag_field = be_u16(bytes, offset + 2).ok_or_else(|| PpError::Truncated {
                    needed: offset + 4,
                    had: bytes.len(),
                    offset: meta.index,
                })?;
                // Fragment offset is the top 13 bits.
                if (frag_field >> 3) != 0 {
                    is_non_first_fragment = true;
                }
                next_header = nh;
                offset = offset.saturating_add(8);
            }
            NH_NO_NEXT => {
                // No upper-layer payload.
                return Ok((NH_NO_NEXT, &bytes[bytes.len()..]));
            }
            _ => {
                // A transport protocol (TCP/UDP/SCTP/ICMPv6/...) — stop walking.
                // RFC 8200's payload_length includes every extension header we just walked;
                // subtract the consumed ext-header bytes (offset - 40) so payload_len reports
                // L4-and-beyond, matching the IPv4 path (total_length - header_len).
                meta.payload_len =
                    payload_length.saturating_sub((offset.saturating_sub(40)) as u32);
                if is_non_first_fragment {
                    return Ok((next_header, &bytes[bytes.len()..]));
                }
                return match bytes.split_at_checked(offset.min(bytes.len())) {
                    Some((_, l4)) => Ok((next_header, l4)),
                    None => Err(PpError::Truncated {
                        needed: offset,
                        had: bytes.len(),
                        offset: meta.index,
                    }),
                };
            }
        }
    }

    // Walked too many headers: treat as malformed rather than risk an unbounded loop.
    Err(PpError::MalformedHeader {
        layer: "ipv6-ext",
        packet_index: meta.index,
        detail: format!("extension-header chain exceeded {MAX_IPV6_EXT_HEADERS} headers"),
    })
}
