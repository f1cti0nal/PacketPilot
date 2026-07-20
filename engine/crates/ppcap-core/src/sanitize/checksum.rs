//! Checksum recomputation for sanitized packets.
//!
//! After addresses are pseudonymized and payloads scrubbed, the original L3/L4
//! checksums are wrong (and would also leak a 16-bit residue of the original
//! bytes), so every checksum the sanitizer can recompute is recomputed and every
//! one it cannot (truncated capture) is zeroed. Pure functions over byte slices;
//! callers own all offset math.

/// RFC 1071 internet checksum over a list of byte slices (16-bit one's complement
/// sum). Odd-length slices are only valid as the *last* slice — internally the sum
/// is carried across slices byte-aligned, so callers pass logical segments
/// (pseudo-header, then L4 bytes).
fn ones_complement_sum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut carry_byte: Option<u8> = None;
    for part in parts {
        let mut bytes = part.iter();
        // If the previous slice ended on an odd byte, pair it with our first byte.
        if let Some(hi) = carry_byte.take() {
            match bytes.next() {
                Some(&lo) => sum += u32::from_be_bytes([0, 0, hi, lo]),
                None => {
                    carry_byte = Some(hi);
                    continue;
                }
            }
        }
        loop {
            match (bytes.next(), bytes.next()) {
                (Some(&hi), Some(&lo)) => sum += u32::from_be_bytes([0, 0, hi, lo]),
                (Some(&hi), None) => {
                    carry_byte = Some(hi);
                    break;
                }
                _ => break,
            }
        }
    }
    if let Some(hi) = carry_byte {
        sum += (hi as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// IPv4 header checksum over `hdr` (the full IHL-length header). The checksum
/// field (bytes 10..12) must be zeroed by the caller before computing — this
/// helper does that itself on a scratch basis by summing around it.
pub(crate) fn ipv4_header(hdr: &[u8]) -> u16 {
    // Sum with the checksum field treated as zero.
    let before = &hdr[..10];
    let after = &hdr[12..];
    ones_complement_sum(&[before, &[0, 0], after])
}

/// TCP/UDP checksum for IPv4: pseudo-header (src, dst, zero, proto, l4_len) plus
/// the L4 segment with its checksum field zeroed by the caller.
pub(crate) fn l4_v4(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> u16 {
    let len = (l4.len() as u16).to_be_bytes();
    let pseudo = [
        src[0], src[1], src[2], src[3], dst[0], dst[1], dst[2], dst[3], 0, proto, len[0], len[1],
    ];
    ones_complement_sum(&[&pseudo, l4])
}

/// TCP/UDP/ICMPv6 checksum for IPv6: pseudo-header (src, dst, u32 length, zeros,
/// next-header) plus the L4 segment with its checksum field zeroed by the caller.
pub(crate) fn l4_v6(src: [u8; 16], dst: [u8; 16], next: u8, l4: &[u8]) -> u16 {
    let len = (l4.len() as u32).to_be_bytes();
    let mut pseudo = [0u8; 40];
    pseudo[..16].copy_from_slice(&src);
    pseudo[16..32].copy_from_slice(&dst);
    pseudo[32..36].copy_from_slice(&len);
    pseudo[39] = next;
    ones_complement_sum(&[&pseudo, l4])
}

/// ICMPv4 checksum: plain internet checksum over the ICMP message (no
/// pseudo-header). Caller zeroes the checksum field first.
pub(crate) fn icmp_v4(icmp: &[u8]) -> u16 {
    ones_complement_sum(&[icmp])
}

/// CRC-32C (Castagnoli) as used by SCTP. Bitwise (no table) — packets are small
/// and sanitize is IO-bound, so simplicity wins over a 1 KiB table.
pub(crate) fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82F6_3B78 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_header_checksum_matches_reference() {
        // Classic worked example (RFC 1071 style): header from Wikipedia's IPv4
        // checksum article; expected checksum 0xB861.
        let hdr: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(ipv4_header(&hdr), 0xB861);
    }

    #[test]
    fn verifying_a_correct_ipv4_header_yields_zero_sum() {
        let mut hdr: [u8; 20] = [
            0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0a, 0x00,
            0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
        ];
        let c = ipv4_header(&hdr).to_be_bytes();
        hdr[10] = c[0];
        hdr[11] = c[1];
        // Re-summing a header containing its own correct checksum gives 0.
        assert_eq!(ones_complement_sum(&[&hdr]), 0);
    }

    #[test]
    fn udp_v4_checksum_verifies() {
        // src 10.0.0.1 -> dst 10.0.0.2, UDP 8-byte header + "hi".
        let mut udp = vec![0x04, 0xD2, 0x00, 0x35, 0x00, 0x0A, 0x00, 0x00];
        udp.extend_from_slice(b"hi");
        let c = l4_v4([10, 0, 0, 1], [10, 0, 0, 2], 17, &udp).to_be_bytes();
        udp[6] = c[0];
        udp[7] = c[1];
        // Verification: checksum over the message including its checksum == 0.
        let pseudo_ok = l4_v4([10, 0, 0, 1], [10, 0, 0, 2], 17, &udp);
        assert_eq!(pseudo_ok, 0);
    }

    #[test]
    fn odd_length_payload_roundtrips() {
        // 9-byte (odd) UDP message: the final byte must be virtually zero-padded.
        let mut udp = vec![0x00u8, 0x01, 0x00, 0x02, 0x00, 0x09, 0x00, 0x00, 0xAB];
        let c = l4_v4([1, 1, 1, 1], [2, 2, 2, 2], 17, &udp).to_be_bytes();
        udp[6] = c[0];
        udp[7] = c[1];
        // A message containing its own correct checksum sums to zero.
        assert_eq!(l4_v4([1, 1, 1, 1], [2, 2, 2, 2], 17, &udp), 0);
    }

    #[test]
    fn crc32c_known_vectors() {
        // RFC 3720 / common test vectors for CRC-32C.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
    }

    #[test]
    fn icmp_v4_roundtrip() {
        let mut msg = vec![8u8, 0, 0, 0, 0, 1, 0, 1]; // echo request header
        msg.extend_from_slice(b"payload");
        let c = icmp_v4(&msg).to_be_bytes();
        msg[2] = c[0];
        msg[3] = c[1];
        assert_eq!(icmp_v4(&msg), 0, "message including its checksum sums to 0");
    }
}
