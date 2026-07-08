//! QUIC protocol support.
//!
//! This module provides cryptographic primitives and protocol dissection
//! for QUIC (RFC 9000) and QUIC-TLS (RFC 9001), enabling SNI extraction
//! from QUIC Initial packets without a full TLS stack.
//!
//! ## Sub-modules
//!
//! - [`crypto`] — vendored HMAC-SHA256, HKDF-Extract, HKDF-Expand, and
//!   HKDF-Expand-Label (RFC 8446 §7.1). Pure compute; wasm-safe (no std::{fs,net,time}).
//!
//! ## This module
//!
//! [`extract_initial_client_hello`] takes the UDP payload of a QUIC Initial
//! packet (long header, version 1), derives the client Initial keys from the
//! Destination Connection ID (RFC 9001 §5.2), removes header protection
//! (RFC 9001 §5.4), AEAD-decrypts the packet payload (RFC 9001 §5.3), then
//! reassembles CRYPTO frames (RFC 9000 §19.6) into the contiguous TLS
//! handshake bytes (a ClientHello). Nothing is stored; the function is pure
//! and wasm-safe, and never panics — every slice goes through `get` and every
//! arithmetic step through `checked_*`. Any failure (truncation, unknown
//! version, non-Initial, bad tag) yields `None`.

pub(crate) mod crypto;

use crypto::{aes128_gcm_open, hkdf_expand_label, hkdf_extract, Aes128};

/// A recognized QUIC version, parsed from the 4-byte long-header version field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicVersion {
    /// RFC 9000 / RFC 9001 (`0x00000001`).
    V1,
    /// RFC 9369 (`0x6b3343cf`).
    V2,
    /// An `draft-ietf-quic-transport-NN` version (`0xff0000NN`).
    Draft(u8),
    /// A Version Negotiation packet (version field `0x00000000`).
    Negotiation,
    /// Any other (forced-negotiation / experimental / future) version.
    Other(u32),
}

impl QuicVersion {
    fn from_u32(v: u32) -> QuicVersion {
        match v {
            0x0000_0000 => QuicVersion::Negotiation,
            VERSION_1 => QuicVersion::V1,
            VERSION_2 => QuicVersion::V2,
            v if v & 0xffff_ff00 == 0xff00_0000 => QuicVersion::Draft((v & 0xff) as u8),
            other => QuicVersion::Other(other),
        }
    }
}

/// The long-header packet type, normalized across version-specific codepoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicLongKind {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

/// The result of structurally identifying a QUIC packet from a UDP payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicInfo {
    pub version: QuicVersion,
    /// The long-header packet kind, or `None` for a Version Negotiation packet
    /// (which carries no packet type).
    pub kind: Option<QuicLongKind>,
}

/// Map a v1-style 2-bit long packet type codepoint (RFC 9000 §17.2).
fn v1_long_kind(bits: u8) -> QuicLongKind {
    match bits & 0x03 {
        0b00 => QuicLongKind::Initial,
        0b01 => QuicLongKind::ZeroRtt,
        0b10 => QuicLongKind::Handshake,
        _ => QuicLongKind::Retry,
    }
}

/// Map a v2 2-bit long packet type codepoint (RFC 9369 §3.2 remapping).
fn v2_long_kind(bits: u8) -> QuicLongKind {
    match bits & 0x03 {
        0b01 => QuicLongKind::Initial,
        0b10 => QuicLongKind::ZeroRtt,
        0b11 => QuicLongKind::Handshake,
        _ => QuicLongKind::Retry,
    }
}

/// Structurally identify a QUIC packet from the UDP payload, keylessly.
///
/// Recognizes **long-header** packets (Initial / 0-RTT / Handshake / Retry) of a
/// known version (v1, v2, or an `0xff0000NN` draft), and Version Negotiation
/// packets. Short-header (1-RTT) packets cannot be identified from a single
/// datagram without connection state, so they return `None` here — a flow that
/// only ever shows 1-RTT packets is instead recognized once its handshake was
/// seen, or falls back to the UDP/443 port heuristic.
///
/// Only accepts *recognized* versions so arbitrary UDP payloads whose first byte
/// happens to have the high bit set are not misread as QUIC. Pure, bounded, and
/// panic-free.
pub(crate) fn identify_quic(udp_payload: &[u8]) -> Option<QuicInfo> {
    let first = *udp_payload.first()?;
    // Long header form: high bit set (RFC 9000 §17.2).
    if first & 0x80 == 0 {
        return None;
    }
    let vb = udp_payload.get(1..5)?;
    let raw = u32::from_be_bytes([vb[0], vb[1], vb[2], vb[3]]);
    let version = QuicVersion::from_u32(raw);

    // Version Negotiation: version field is zero; no packet type, fixed bit may
    // be unset. (RFC 9000 §17.2.1.)
    if version == QuicVersion::Negotiation {
        return Some(QuicInfo {
            version,
            kind: None,
        });
    }

    let type_bits = (first >> 4) & 0x03;
    let kind = match version {
        QuicVersion::V1 | QuicVersion::Draft(_) => v1_long_kind(type_bits),
        QuicVersion::V2 => v2_long_kind(type_bits),
        // Unknown version: too risky to claim QUIC from a lone byte pattern.
        QuicVersion::Other(_) | QuicVersion::Negotiation => return None,
    };

    // Real v1/v2 packets set the fixed bit (0x40); require it to keep the false
    // positive rate near zero for unrecognized UDP traffic.
    if first & 0x40 == 0 {
        return None;
    }
    Some(QuicInfo {
        version,
        kind: Some(kind),
    })
}

/// QUIC version 1 (RFC 9000 / RFC 9001).
const VERSION_1: u32 = 0x0000_0001;
/// QUIC version 2 (RFC 9369).
const VERSION_2: u32 = 0x6b33_43cf;

/// RFC 9001 §5.2 initial salt for QUIC v1.
const V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// RFC 9369 §3.3.1 initial salt for QUIC v2.
const V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// Per-version derivation parameters: (initial salt, client-secret label,
/// key label, iv label). The client-secret label (`"client in"`) is unchanged
/// in v2; only the salt and the packet-protection labels differ (RFC 9369 §3.3).
///
/// v1 (`0x00000001`, RFC 9001) and v2 (`0x6b3343cf`, RFC 9369) are supported.
/// NOTE: the v2 constants are transcribed from RFC 9369 §3.3 and verified by a
/// round-trip test here; they were not pinned against the RFC 9369 Appendix A
/// golden vector because this build environment's network policy blocks
/// rfc-editor.org. Any mismatch degrades gracefully to `None` (no SNI), never a
/// panic — see `extract_initial_client_hello`.
fn version_params(
    version: u32,
) -> Option<(&'static [u8], &'static str, &'static str, &'static str)> {
    match version {
        VERSION_1 => Some((&V1_SALT, "client in", "quic key", "quic iv")),
        VERSION_2 => Some((&V2_SALT, "client in", "quicv2 key", "quicv2 iv")),
        _ => None,
    }
}

/// The header-protection label for a version (kept separate only for clarity;
/// gated by [`version_params`] returning `Some` first).
fn hp_label(version: u32) -> Option<&'static str> {
    match version {
        VERSION_1 => Some("quic hp"),
        VERSION_2 => Some("quicv2 hp"),
        _ => None,
    }
}

/// Read a QUIC variable-length integer (RFC 9000 §16).
///
/// The two most-significant bits of the first byte encode the length:
/// `00` → 1 byte, `01` → 2 bytes, `10` → 4 bytes, `11` → 8 bytes. The
/// remaining bits are the high bits of the value. Advances `*pos` past the
/// encoded integer. Returns `None` if the buffer is too short.
fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *buf.get(*pos)?;
    let len = 1usize << (first >> 6); // 1, 2, 4, or 8
    let mut value = u64::from(first & 0x3f);
    let mut i = 1usize;
    while i < len {
        let b = *buf.get(pos.checked_add(i)?)?;
        value = (value << 8) | u64::from(b);
        i += 1;
    }
    *pos = pos.checked_add(len)?;
    Some(value)
}

/// Derive the client Initial `(key, iv, hp)` from the Destination Connection
/// ID, per RFC 9001 §5.2.
///
/// `initial_secret = HKDF-Extract(salt, DCID)`,
/// `client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)`,
/// then the AEAD `key` (16), `iv` (12), and header-protection `hp` (16) keys.
///
/// Returns `None` for unsupported versions.
fn derive_client_initial_keys(version: u32, dcid: &[u8]) -> Option<([u8; 16], [u8; 12], [u8; 16])> {
    let (salt, client_label, key_label, iv_label) = version_params(version)?;
    let hp_lbl = hp_label(version)?;

    let initial_secret = hkdf_extract(salt, dcid);
    let client_secret_vec = hkdf_expand_label(&initial_secret, client_label, 32);
    let client_secret: [u8; 32] = client_secret_vec.as_slice().try_into().ok()?;

    let key_vec = hkdf_expand_label(&client_secret, key_label, 16);
    let iv_vec = hkdf_expand_label(&client_secret, iv_label, 12);
    let hp_vec = hkdf_expand_label(&client_secret, hp_lbl, 16);

    let key: [u8; 16] = key_vec.as_slice().try_into().ok()?;
    let iv: [u8; 12] = iv_vec.as_slice().try_into().ok()?;
    let hp: [u8; 16] = hp_vec.as_slice().try_into().ok()?;
    Some((key, iv, hp))
}

/// Reassemble CRYPTO frames (RFC 9000 §19.6) from a decrypted Initial payload
/// into the contiguous handshake bytes starting at offset 0.
///
/// Walks the frame sequence: `0x00` PADDING (any run of zero bytes), `0x01`
/// PING (no body), `0x06` CRYPTO (`offset` varint, `length` varint, `length`
/// data bytes). Any other frame type stops the walk. CRYPTO fragments are
/// placed at their stated offset in a buffer; the function returns the
/// longest contiguous prefix from offset 0. Returns `None` if no CRYPTO data
/// is recovered or the bytes from offset 0 are not contiguous.
fn reassemble_crypto(plaintext: &[u8]) -> Option<Vec<u8>> {
    // (offset, data) fragments, collected then stitched.
    let mut fragments: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut pos = 0usize;

    while pos < plaintext.len() {
        let frame_type = *plaintext.get(pos)?;
        match frame_type {
            0x00 => {
                // PADDING: consume the contiguous run of zero bytes.
                while pos < plaintext.len() && plaintext.get(pos) == Some(&0x00) {
                    pos += 1;
                }
            }
            0x01 => {
                // PING: a single byte, no body.
                pos = pos.checked_add(1)?;
            }
            0x06 => {
                // CRYPTO: type(1) offset(varint) length(varint) data(length).
                let mut p = pos.checked_add(1)?;
                let offset = read_varint(plaintext, &mut p)?;
                let length = read_varint(plaintext, &mut p)? as usize;
                let data_end = p.checked_add(length)?;
                let data = plaintext.get(p..data_end)?.to_vec();
                fragments.push((offset, data));
                pos = data_end;
            }
            _ => break,
        }
    }

    if fragments.is_empty() {
        return None;
    }

    // Stitch fragments in offset order, requiring contiguity from 0.
    fragments.sort_by_key(|(off, _)| *off);
    let mut out: Vec<u8> = Vec::new();
    let mut next: u64 = 0;
    for (off, data) in &fragments {
        if *off > next {
            // Gap before this fragment: not contiguous from 0.
            break;
        }
        // Overlap-safe append: skip any bytes already covered.
        let skip = (next - *off) as usize;
        if let Some(tail) = data.get(skip..) {
            out.extend_from_slice(tail);
            next = next.checked_add((data.len() - skip) as u64)?;
        }
    }

    if out.is_empty() || next == 0 {
        return None;
    }
    Some(out)
}

/// Extract the TLS handshake (ClientHello) bytes from a QUIC Initial packet's
/// UDP payload.
///
/// Parses the long header (RFC 9000 §17.2), derives the client Initial keys
/// from the DCID (RFC 9001 §5.2), removes header protection (RFC 9001 §5.4),
/// AEAD-decrypts the packet (RFC 9001 §5.3), and reassembles CRYPTO frames
/// (RFC 9000 §19.6). Returns the contiguous handshake bytes (a raw TLS
/// ClientHello, not wrapped in a record), or `None` on any failure
/// (truncation, unknown/unsupported version, non-Initial, short header,
/// authentication failure, or no contiguous CRYPTO from offset 0).
///
/// Pure and wasm-safe; never panics.
pub(crate) fn extract_initial_client_hello(udp_payload: &[u8]) -> Option<Vec<u8>> {
    let first = *udp_payload.first()?;

    // Long header (0x80) with fixed bit set (0x40). RFC 9000 §17.2.
    if first & 0x80 == 0 || first & 0x40 == 0 {
        return None;
    }

    // Version: 4 bytes, big-endian.
    let version_bytes = udp_payload.get(1..5)?;
    let version = u32::from_be_bytes([
        version_bytes[0],
        version_bytes[1],
        version_bytes[2],
        version_bytes[3],
    ]);

    // Long packet type must be Initial. The 2-bit type codepoint is version-
    // specific: v1 (RFC 9000 §17.2) uses Initial == 0b00; v2 (RFC 9369 §3.2)
    // remaps Initial to 0b01. Reject other long-header packet types.
    let type_bits = (first >> 4) & 0x03;
    let initial_type = match version {
        VERSION_1 => 0b00,
        VERSION_2 => 0b01,
        _ => return None, // unsupported version — no keys anyway
    };
    if type_bits != initial_type {
        return None;
    }

    let mut pos = 5usize; // past first byte + version

    // DCID: len(1) + bytes.
    let dcid_len = *udp_payload.get(pos)? as usize;
    pos = pos.checked_add(1)?;
    let dcid_end = pos.checked_add(dcid_len)?;
    let dcid = udp_payload.get(pos..dcid_end)?.to_vec();
    pos = dcid_end;

    // SCID: len(1) + bytes.
    let scid_len = *udp_payload.get(pos)? as usize;
    pos = pos.checked_add(1)?;
    pos = pos.checked_add(scid_len)?;

    // Token: len(varint) + bytes (Initial packets only).
    let token_len = read_varint(udp_payload, &mut pos)? as usize;
    pos = pos.checked_add(token_len)?;

    // Length: varint covering packet number + protected payload + tag.
    let length = read_varint(udp_payload, &mut pos)? as usize;
    let pn_offset = pos;

    // Bound the packet so `length` cannot reach past the buffer.
    let packet_end = pn_offset.checked_add(length)?;
    if packet_end > udp_payload.len() {
        return None;
    }

    // Derive keys (rejects unsupported versions).
    let (key, iv, hp) = derive_client_initial_keys(version, &dcid)?;

    // Header protection (RFC 9001 §5.4): sample 16 bytes starting 4 bytes into
    // where the packet number would be (the largest possible PN is 4 bytes).
    let sample_start = pn_offset.checked_add(4)?;
    let sample_end = sample_start.checked_add(16)?;
    let sample: [u8; 16] = udp_payload.get(sample_start..sample_end)?.try_into().ok()?;
    let mask = Aes128::new(&hp).encrypt_block(&sample);

    // Unmask the first byte: low 4 bits for a long header.
    let first_unmasked = first ^ (mask[0] & 0x0f);
    let pn_len = ((first_unmasked & 0x03) as usize).checked_add(1)?;

    // Build the AAD (RFC 9001 §5.3): the header bytes with the unmasked first
    // byte and the unmasked packet number written in. We unmask the packet
    // number with mask[1..1+pn_len] directly into the header copy and
    // accumulate the decoded packet-number integer as we go.
    let header_len = pn_offset.checked_add(pn_len)?;
    let mut header = udp_payload.get(..header_len)?.to_vec();
    *header.get_mut(0)? = first_unmasked;
    let mut pn_value: u64 = 0;
    for (i, mask_byte) in mask.iter().skip(1).take(pn_len).enumerate() {
        let idx = pn_offset.checked_add(i)?;
        let b = *header.get(idx)? ^ mask_byte;
        *header.get_mut(idx)? = b;
        pn_value = (pn_value << 8) | u64::from(b);
    }

    // Nonce = iv XOR left-padded big-endian packet number (RFC 9001 §5.3):
    // right-align the 8-byte big-endian PN into the 12-byte nonce (offset 4).
    let mut nonce = iv;
    for (n, pn) in nonce.iter_mut().skip(4).zip(pn_value.to_be_bytes()) {
        *n ^= pn;
    }

    // Ciphertext+tag spans from the end of the packet number to packet_end.
    let ct_and_tag = udp_payload.get(header_len..packet_end)?;

    // AEAD open: returns None on authentication failure.
    let plaintext = aes128_gcm_open(&key, &nonce, &header, ct_and_tag)?;

    // Reassemble CRYPTO frames into the handshake (ClientHello) bytes.
    reassemble_crypto(&plaintext)
}

/// Test-only builders for synthetic QUIC Initial packets, shared by the QUIC and
/// decode test suites (round-trips through the real protection/derivation code).
#[cfg(test)]
pub(crate) mod testkit {
    use super::*;
    use crate::quic::crypto::aes128_gcm_seal;

    /// Build a raw TLS 1.3 ClientHello (handshake bytes, first byte 0x01) with the
    /// given SNI and ALPN list.
    pub(crate) fn client_hello(sni: &str, alpns: &[&str]) -> Vec<u8> {
        // SNI extension (0x0000).
        let mut sni_ext_body = Vec::new();
        let name = sni.as_bytes();
        let list_len = (name.len() + 3) as u16;
        sni_ext_body.extend_from_slice(&list_len.to_be_bytes());
        sni_ext_body.push(0); // host_name
        sni_ext_body.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext_body.extend_from_slice(name);

        // ALPN extension (0x0010).
        let mut alpn_protos = Vec::new();
        for a in alpns {
            alpn_protos.push(a.len() as u8);
            alpn_protos.extend_from_slice(a.as_bytes());
        }
        let mut alpn_ext_body = Vec::new();
        alpn_ext_body.extend_from_slice(&(alpn_protos.len() as u16).to_be_bytes());
        alpn_ext_body.extend_from_slice(&alpn_protos);

        // supported_versions (0x002b) advertising TLS 1.3.
        let sv_body = [0x02u8, 0x03, 0x04];

        let mut exts = Vec::new();
        let push_ext = |exts: &mut Vec<u8>, ty: u16, body: &[u8]| {
            exts.extend_from_slice(&ty.to_be_bytes());
            exts.extend_from_slice(&(body.len() as u16).to_be_bytes());
            exts.extend_from_slice(body);
        };
        push_ext(&mut exts, 0x0000, &sni_ext_body);
        push_ext(&mut exts, 0x0010, &alpn_ext_body);
        push_ext(&mut exts, 0x002b, &sv_body);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(0); // session_id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites len
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(1); // compression methods len
        body.push(0); // null
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![0x01u8]; // ClientHello
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        hs.extend_from_slice(&body);
        hs
    }

    /// Build a protected QUIC Initial packet carrying `handshake`, under `version`,
    /// keyed from `dcid`. This is the exact inverse of `extract_initial_client_hello`:
    /// derive keys → CRYPTO-frame + PADDING → seal → apply header protection.
    pub(crate) fn protected_initial(version: u32, dcid: &[u8], handshake: &[u8]) -> Vec<u8> {
        let (key, iv, hp) =
            derive_client_initial_keys(version, dcid).expect("keys for supported version");

        // Plaintext: one CRYPTO frame (type 0x06, offset 0, len varint, data) then
        // PADDING (zero bytes) so the packet is comfortably longer than the sample.
        let mut plaintext = vec![0x06u8, 0x00];
        // 2-byte varint length (valid for < 16384).
        plaintext.push(0x40 | ((handshake.len() >> 8) as u8));
        plaintext.push((handshake.len() & 0xff) as u8);
        plaintext.extend_from_slice(handshake);
        while plaintext.len() < 64 {
            plaintext.push(0x00);
        }

        let pn_len = 1usize;
        let type_bits: u8 = if version == VERSION_2 { 0b01 } else { 0b00 };
        let first = 0x80 | 0x40 | (type_bits << 4) | ((pn_len as u8) - 1);

        let mut hdr = vec![first];
        hdr.extend_from_slice(&version.to_be_bytes());
        hdr.push(dcid.len() as u8);
        hdr.extend_from_slice(dcid);
        hdr.push(0); // scid len 0
        hdr.push(0x00); // token len varint 0
        let length = pn_len + plaintext.len() + 16; // pn + ciphertext + tag
        hdr.push(0x40 | ((length >> 8) as u8));
        hdr.push((length & 0xff) as u8);
        let pn_offset = hdr.len();
        hdr.push(0x00); // packet number = 0 (1 byte)

        // AAD is the header with unprotected first byte + PN; nonce = iv (PN=0).
        let ct_and_tag = aes128_gcm_seal(&key, &iv, &hdr, &plaintext);

        let mut pkt = hdr;
        pkt.extend_from_slice(&ct_and_tag);

        // Apply header protection: sample at pn_offset+4.
        let sample_start = pn_offset + 4;
        let sample: [u8; 16] = pkt[sample_start..sample_start + 16].try_into().unwrap();
        let mask = Aes128::new(&hp).encrypt_block(&sample);
        pkt[0] ^= mask[0] & 0x0f;
        for i in 0..pn_len {
            pkt[pn_offset + i] ^= mask[1 + i];
        }
        pkt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// RFC 9001 §A.1: the client Initial key/iv/hp derived from the sample
    /// DCID 0x8394c8f03e515708 under the v1 salt. These are the published
    /// golden values; the helper must reproduce them exactly.
    #[test]
    fn derive_client_initial_keys_rfc9001_a1() {
        let dcid = hex("8394c8f03e515708");
        let (key, iv, hp) =
            derive_client_initial_keys(VERSION_1, &dcid).expect("v1 derivation must succeed");
        assert_eq!(to_hex(&key), "1f369613dd76d5467730efcbe3b1a22d", "key");
        assert_eq!(to_hex(&iv), "fa044b2f42a3fd3b46fb255c", "iv");
        assert_eq!(to_hex(&hp), "9f50449e04a0e810283a1e9933adedd2", "hp");
    }

    /// Unsupported versions (Version Negotiation, a draft, an experimental value)
    /// yield no keys. v1 and v2 are the supported versions.
    #[test]
    fn derive_client_initial_keys_rejects_unknown_version() {
        let dcid = hex("8394c8f03e515708");
        assert_eq!(derive_client_initial_keys(0x0000_0000, &dcid), None);
        assert_eq!(derive_client_initial_keys(0xff00_001d, &dcid), None);
        assert_eq!(derive_client_initial_keys(0xdead_beef, &dcid), None);
        // v2 is now supported (derivation succeeds).
        assert!(derive_client_initial_keys(VERSION_2, &dcid).is_some());
    }

    /// QUIC varint decoding across all four length prefixes (RFC 9000 §16).
    #[test]
    fn read_varint_all_lengths() {
        // 1-byte: 0x25 -> 37.
        let mut p = 0;
        assert_eq!(read_varint(&hex("25"), &mut p), Some(37));
        assert_eq!(p, 1);
        // 2-byte: 0x7bbd -> 15293.
        let mut p = 0;
        assert_eq!(read_varint(&hex("7bbd"), &mut p), Some(15293));
        assert_eq!(p, 2);
        // 4-byte: 0x9d7f3e7d -> 494878333.
        let mut p = 0;
        assert_eq!(read_varint(&hex("9d7f3e7d"), &mut p), Some(494_878_333));
        assert_eq!(p, 4);
        // 8-byte: 0xc2197c5eff14e88c -> 151288809941952652.
        let mut p = 0;
        assert_eq!(
            read_varint(&hex("c2197c5eff14e88c"), &mut p),
            Some(151_288_809_941_952_652)
        );
        assert_eq!(p, 8);
        // The A.2 length field 0x449e decodes to 1182.
        let mut p = 0;
        assert_eq!(read_varint(&hex("449e"), &mut p), Some(1182));
        // Truncated multi-byte varint -> None.
        let mut p = 0;
        assert_eq!(read_varint(&hex("44"), &mut p), None);
    }

    /// The full RFC 9001 §A.2 protected client Initial packet (1200 bytes),
    /// transcribed verbatim from the RFC.
    fn rfc9001_a2_protected() -> Vec<u8> {
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

    /// The 241-byte ClientHello carried by the §A.2 CRYPTO frame, transcribed
    /// from the unprotected payload listing in the RFC. This is the golden
    /// decrypted handshake the end-to-end path must reproduce.
    fn rfc9001_a2_clienthello() -> Vec<u8> {
        // Bytes [4..245] of the §A.2 unprotected payload (after the CRYPTO
        // frame header 06 00 40f1): the 241-byte ClientHello, verbatim.
        let ch = hex(
            "010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47\
             f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c\
             652e636f6dff01000100000a00080006001d0017001800100007000504616c70\
             6e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559f\
             edba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d001000\
             0e0403050306030203080408050806002d00020101001c000240010039003204\
             08ffffffffffffffff05048000ffff07048000ffff0801100104800075300901\
             100f088394c8f03e51570806048000ffff",
        );
        assert_eq!(ch.len(), 241, "A.2 ClientHello must be 241 bytes");
        ch
    }

    /// End-to-end golden vector: decrypt the §A.2 packet and recover exactly
    /// the §A.2 ClientHello. Pins header-unprotect + AEAD + reassembly against
    /// the RFC's published plaintext.
    #[test]
    fn extract_initial_client_hello_rfc9001_a2_golden() {
        let pkt = rfc9001_a2_protected();
        let handshake = extract_initial_client_hello(&pkt).expect("must decrypt A.2");
        let expected = rfc9001_a2_clienthello();
        assert_eq!(
            to_hex(&handshake),
            to_hex(&expected),
            "recovered handshake must equal the A.2 ClientHello"
        );
    }

    /// The recovered handshake is a TLS 1.3 ClientHello carrying the
    /// server_name "example.com"; wrapping it in a TLS record and feeding it
    /// to the existing SNI sniffer recovers that host.
    #[test]
    fn extract_initial_client_hello_carries_sni() {
        let pkt = rfc9001_a2_protected();
        let handshake = extract_initial_client_hello(&pkt).expect("must decrypt A.2");

        // Wrap the raw handshake in a TLS record header so the record-oriented
        // sniffer can parse it: content_type=22(handshake), version 0x0303,
        // length(2).
        let mut record = Vec::with_capacity(5 + handshake.len());
        record.push(22u8);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        assert_eq!(
            crate::decode::sniff_tls_sni(&record),
            Some("example.com".to_string()),
            "ClientHello must carry SNI example.com"
        );
    }

    /// Truncated input (first 20 bytes only) yields None — the AEAD/sample
    /// region is missing.
    #[test]
    fn extract_initial_truncated_is_none() {
        let pkt = rfc9001_a2_protected();
        assert_eq!(extract_initial_client_hello(&pkt[..20]), None);
        assert_eq!(extract_initial_client_hello(&[]), None);
        assert_eq!(extract_initial_client_hello(&[0xc0]), None);
    }

    /// Unknown version (mutate the version bytes to v2) yields None: key
    /// derivation is unsupported.
    #[test]
    fn extract_initial_unknown_version_is_none() {
        let mut pkt = rfc9001_a2_protected();
        // Version is bytes [1..5]; set to QUIC v2 0x6b3343cf.
        pkt[1] = 0x6b;
        pkt[2] = 0x33;
        pkt[3] = 0x43;
        pkt[4] = 0xcf;
        assert_eq!(extract_initial_client_hello(&pkt), None);
    }

    /// A short-header packet (high bit clear) is rejected.
    #[test]
    fn extract_initial_short_header_is_none() {
        let mut pkt = rfc9001_a2_protected();
        pkt[0] &= 0x7f; // clear the long-header bit
        assert_eq!(extract_initial_client_hello(&pkt), None);
    }

    /// A long-header packet that is not Initial (type bits != 0) is rejected.
    #[test]
    fn extract_initial_non_initial_type_is_none() {
        let mut pkt = rfc9001_a2_protected();
        // Set long-packet-type bits (bits 4-5) to Handshake (0b10).
        pkt[0] = (pkt[0] & 0xcf) | 0x20;
        assert_eq!(extract_initial_client_hello(&pkt), None);
    }

    /// A tampered ciphertext byte fails AEAD authentication -> None.
    #[test]
    fn extract_initial_tampered_tag_is_none() {
        let mut pkt = rfc9001_a2_protected();
        // Flip a byte deep in the protected payload (well past the header).
        let last = pkt.len() - 1;
        pkt[last] ^= 0x01;
        assert_eq!(extract_initial_client_hello(&pkt), None);
    }

    // ── Structural identification (identify_quic) ────────────────────────────

    #[test]
    fn identify_quic_recognizes_versions_and_types() {
        // v1 Initial (0xC0 = long+fixed, type 0b00), version 1.
        let v1_initial = [0xc0, 0x00, 0x00, 0x00, 0x01, 0x00];
        assert_eq!(
            identify_quic(&v1_initial),
            Some(QuicInfo {
                version: QuicVersion::V1,
                kind: Some(QuicLongKind::Initial),
            })
        );
        // v2 Initial: type codepoint 0b01 (RFC 9369), first byte 0xD0.
        let v2_initial = [0xd0, 0x6b, 0x33, 0x43, 0xcf, 0x00];
        assert_eq!(
            identify_quic(&v2_initial),
            Some(QuicInfo {
                version: QuicVersion::V2,
                kind: Some(QuicLongKind::Initial),
            })
        );
        // v1 Handshake (type 0b10 → 0xE0).
        let v1_hs = [0xe0, 0x00, 0x00, 0x00, 0x01, 0x00];
        assert_eq!(
            identify_quic(&v1_hs).unwrap().kind,
            Some(QuicLongKind::Handshake)
        );
        // Version Negotiation (version 0): kind None, still QUIC.
        let vneg = [0xc0, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            identify_quic(&vneg),
            Some(QuicInfo {
                version: QuicVersion::Negotiation,
                kind: None,
            })
        );
        // A draft version (0xff00001d) maps with v1-style types.
        let draft = [0xc0, 0xff, 0x00, 0x00, 0x1d, 0x00];
        assert_eq!(
            identify_quic(&draft).unwrap().version,
            QuicVersion::Draft(0x1d)
        );
    }

    #[test]
    fn identify_quic_rejects_non_quic() {
        // Short header (high bit clear) — not identifiable from one datagram.
        assert_eq!(identify_quic(&[0x40, 0x00, 0x00, 0x00, 0x01]), None);
        // Long header but unknown version → not claimed as QUIC.
        assert_eq!(identify_quic(&[0xc0, 0xde, 0xad, 0xbe, 0xef, 0x00]), None);
        // Long header, known version, but fixed bit clear → rejected.
        assert_eq!(identify_quic(&[0x80, 0x00, 0x00, 0x00, 0x01, 0x00]), None);
        // A DNS-looking UDP payload (first byte 0x00) → not QUIC.
        assert_eq!(identify_quic(&[0x00, 0x01, 0x02, 0x03, 0x04]), None);
        assert_eq!(identify_quic(&[]), None);
    }

    // ── v1/v2 Initial round-trip (build → protect → extract) ─────────────────

    fn roundtrip_recovers_sni_alpn(version: u32) {
        let dcid = hex("8394c8f03e515708");
        let ch = testkit::client_hello("quic.example.net", &["h3", "h3-29"]);
        let pkt = testkit::protected_initial(version, &dcid, &ch);

        // identify_quic must classify it as an Initial of the right version.
        let info = identify_quic(&pkt).expect("must identify as QUIC");
        assert_eq!(info.kind, Some(QuicLongKind::Initial));

        // Extraction recovers the exact handshake bytes.
        let recovered = extract_initial_client_hello(&pkt).expect("must decrypt Initial");
        assert_eq!(recovered, ch, "recovered handshake must match the input");

        // Wrapped in a record, the fingerprint parser recovers SNI + ALPN.
        let mut record = vec![22u8, 0x03, 0x03];
        record.extend_from_slice(&(recovered.len() as u16).to_be_bytes());
        record.extend_from_slice(&recovered);
        let fp = crate::fingerprint::fingerprint_tls_client_hello(
            &record,
            crate::fingerprint::Ja4Transport::Quic,
        )
        .expect("fingerprint must parse the recovered ClientHello");
        assert_eq!(fp.sni.as_deref(), Some("quic.example.net"));
        assert!(fp.alpn.iter().any(|a| a == "h3"), "ALPN must include h3");
        assert!(fp.ja4.starts_with('q'), "QUIC JA4 must start with 'q'");
    }

    #[test]
    fn v1_initial_roundtrip() {
        roundtrip_recovers_sni_alpn(VERSION_1);
    }

    /// QUIC v2 (RFC 9369) keyless Initial: build → protect → extract round-trips,
    /// recovering SNI + ALPN. This exercises the v2 salt/labels and the v2 Initial
    /// packet-type codepoint. (Round-trip self-consistency; see the version_params
    /// note re: the Appendix A golden vector being unreachable in this sandbox.)
    #[test]
    fn v2_initial_roundtrip() {
        roundtrip_recovers_sni_alpn(VERSION_2);
    }

    /// v2 keys must differ from v1 keys for the same DCID (proves the salt/labels
    /// actually changed rather than silently reusing v1).
    #[test]
    fn v2_keys_differ_from_v1() {
        let dcid = hex("8394c8f03e515708");
        let v1 = derive_client_initial_keys(VERSION_1, &dcid).unwrap();
        let v2 = derive_client_initial_keys(VERSION_2, &dcid).unwrap();
        assert_ne!(v1.0, v2.0, "v2 key must differ from v1");
        assert_ne!(v1.1, v2.1, "v2 iv must differ from v1");
        assert_ne!(v1.2, v2.2, "v2 hp must differ from v1");
    }
}
