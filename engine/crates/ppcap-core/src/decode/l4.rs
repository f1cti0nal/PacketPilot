//! L4 (transport) decoding: TCP, UDP, SCTP port/flag extraction.

use crate::error::PpError;
use crate::model::packet::PacketMeta;
use crate::Result;

#[inline]
fn be_u16(buf: &[u8], off: usize) -> Option<u16> {
    let hi = *buf.get(off)?;
    let lo = *buf.get(off + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

/// Decode a TCP header into `meta` (ports, flags, payload_len).
///
/// An empty `bytes` is the L3 "non-first fragment / no L4" marker: ports and flags are
/// left at 0 and we return `Ok(())`.
pub fn decode_tcp(bytes: &[u8], meta: &mut PacketMeta) -> Result<()> {
    if bytes.is_empty() {
        // Non-first fragment marker: nothing to extract, not an error.
        return Ok(());
    }
    if bytes.len() < 20 {
        return Err(PpError::Truncated {
            needed: 20,
            had: bytes.len(),
            offset: meta.index,
        });
    }

    meta.src_port = be_u16(bytes, 0).unwrap_or(0);
    meta.dst_port = be_u16(bytes, 2).unwrap_or(0);

    // Data offset (header length) lives in the high nibble of byte 12, in 32-bit words.
    let data_offset = ((bytes[12] >> 4) as usize) * 4;
    if data_offset < 20 {
        return Err(PpError::MalformedHeader {
            layer: "tcp",
            packet_index: meta.index,
            detail: format!("data offset {data_offset} < 20"),
        });
    }

    // Full 8-bit flags byte (CWR ECE URG ACK PSH RST SYN FIN). This matches the on-wire
    // TCP flags byte, which is what model::packet's flag masks expect.
    meta.tcp_flags = bytes[13];

    // Payload is whatever follows the (possibly option-extended) header within the
    // captured slice. Clamp to available bytes so truncation never underflows.
    let effective_header = data_offset.min(bytes.len());
    meta.payload_len = (bytes.len() - effective_header) as u32;

    Ok(())
}

/// Decode a UDP header into `meta` (ports, payload_len).
pub fn decode_udp(bytes: &[u8], meta: &mut PacketMeta) -> Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    if bytes.len() < 8 {
        return Err(PpError::Truncated {
            needed: 8,
            had: bytes.len(),
            offset: meta.index,
        });
    }

    meta.src_port = be_u16(bytes, 0).unwrap_or(0);
    meta.dst_port = be_u16(bytes, 2).unwrap_or(0);

    let udp_len = be_u16(bytes, 4).unwrap_or(0) as usize;
    // Declared payload = udp_len - 8; clamp to what was actually captured.
    let declared_payload = udp_len.saturating_sub(8);
    let available_payload = bytes.len() - 8;
    meta.payload_len = declared_payload.min(available_payload) as u32;

    Ok(())
}

/// Decode an SCTP common header into `meta` (ports only in Phase 0).
pub fn decode_sctp(bytes: &[u8], meta: &mut PacketMeta) -> Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    // src 2 + dst 2 + verification tag 4 + checksum 4 = 12 bytes.
    if bytes.len() < 12 {
        return Err(PpError::Truncated {
            needed: 12,
            had: bytes.len(),
            offset: meta.index,
        });
    }

    meta.src_port = be_u16(bytes, 0).unwrap_or(0);
    meta.dst_port = be_u16(bytes, 2).unwrap_or(0);
    // Chunks are not parsed in Phase 0; payload_len left as seeded by L3.
    Ok(())
}
