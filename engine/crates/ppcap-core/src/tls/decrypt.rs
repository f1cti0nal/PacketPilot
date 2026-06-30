//! TLS 1.3 record decryption from key-log secrets.
//!
//! Phase 1: the `TLS_AES_128_GCM_SHA256` suite, which reuses the engine's existing RFC-tested
//! crypto (HKDF / `hkdf_expand_label` / AES-128-GCM, vendored for QUIC). Given a per-direction
//! traffic secret (from the key-log, e.g. `CLIENT_TRAFFIC_SECRET_0`), derive the AEAD key + iv via
//! HKDF-Expand-Label (RFC 8446 §7.3), then decrypt each `application_data` record:
//!   * per-record nonce = `iv XOR left-pad(seq)`  (RFC 8446 §5.3),
//!   * additional data = the 5-byte record header (RFC 8446 §5.2),
//!   * AES-128-GCM open,
//!   * strip the TLS 1.3 inner content-type + zero padding (RFC 8446 §5.4).
//!
//! Verified against the RFC 8448 §3 published handshake trace. Pure compute, wasm-safe. Higher
//! suites (AES-256-GCM, ChaCha20-Poly1305), TLS 1.2, and the pcap/flow integration are later phases.
#![allow(dead_code)] // Phase 1 foundation; wired into a wasm `tls_decrypt` entry + UI in Phase 2.

use crate::quic::crypto::{aes128_gcm_open, hkdf_expand_label};

/// AEAD state for one direction of a TLS 1.3 connection (TLS_AES_128_GCM_SHA256).
pub(crate) struct Tls13Keys {
    key: [u8; 16],
    iv: [u8; 12],
    /// Record sequence number for this direction; starts at 0, increments per decrypted record.
    seq: u64,
}

impl Tls13Keys {
    /// Derive the AES-128-GCM key + iv from a 32-byte TLS 1.3 traffic secret (RFC 8446 §7.3).
    /// Returns None if the secret isn't the SHA-256 length (32 bytes).
    pub(crate) fn aes128_gcm(secret: &[u8]) -> Option<Self> {
        let secret: &[u8; 32] = secret.try_into().ok()?;
        let key: [u8; 16] = hkdf_expand_label(secret, "key", 16).try_into().ok()?;
        let iv: [u8; 12] = hkdf_expand_label(secret, "iv", 12).try_into().ok()?;
        Some(Tls13Keys { key, iv, seq: 0 })
    }

    /// Per-record nonce: the write_iv XOR the 64-bit sequence number, left-padded with zeros to the
    /// 12-byte iv length (RFC 8446 §5.3).
    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        let seq = self.seq.to_be_bytes(); // 8 bytes → the rightmost 8 of the 12-byte nonce
        for i in 0..8 {
            n[4 + i] ^= seq[i];
        }
        n
    }

    /// Decrypt the next `application_data` record IN ORDER. `record` is the full TLS record,
    /// including its 5-byte header (which is the AEAD additional data). On success advances the
    /// sequence number and returns the inner plaintext with TLS 1.3 padding stripped, as
    /// `(content, inner_content_type)`. Returns None on a malformed record or auth failure.
    pub(crate) fn open_next(&mut self, record: &[u8]) -> Option<(Vec<u8>, u8)> {
        if record.len() < 5 {
            return None;
        }
        let (header, body) = record.split_at(5);
        // header = opaque_type(1) || legacy_record_version(2) || length(2); length must cover body.
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if len != body.len() || body.len() < 16 {
            return None;
        }
        let inner = aes128_gcm_open(&self.key, &self.nonce(), header, body)?;
        self.seq += 1;
        // TLSInnerPlaintext = content || ContentType(1) || zeros*. The last non-zero byte is the
        // real content type; everything before it is the content.
        let last = inner.iter().rposition(|&b| b != 0)?;
        let content_type = inner[last];
        let mut content = inner;
        content.truncate(last);
        Some((content, content_type))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8448 §3 ("Simple 1-RTT Handshake"), the client's `application_data` record. Cross-checks
    /// key derivation, iv derivation, AND the full decrypt against the published trace.
    #[test]
    fn rfc8448_client_application_data() {
        // "tls13 c ap traffic" secret (RFC 8448 §3).
        let secret = hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5");
        let mut keys = Tls13Keys::aes128_gcm(&secret).expect("derive keys");

        // The published "key expanded" / "iv expanded" for the client app-data write keys.
        assert_eq!(
            keys.key.to_vec(),
            hex("17422dda596ed5d9acd890e3c63f5051"),
            "key derivation"
        );
        assert_eq!(
            keys.iv.to_vec(),
            hex("5b78923dee08579033e523d9"),
            "iv derivation"
        );

        // The full 72-octet record: 5-byte header (17 03 03 00 43) + 67-byte ciphertext+tag.
        let record = hex(
            "1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f2b\
             9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae63aee\
             bb21694915e4",
        );
        let (content, ctype) = keys.open_next(&record).expect("decrypt must succeed");
        assert_eq!(ctype, 0x17, "inner content type = application_data");
        let expected: Vec<u8> = (0u8..=0x31).collect(); // plaintext = bytes 0x00..0x31 (50 octets)
        assert_eq!(content, expected, "decrypted plaintext mismatch");
        assert_eq!(keys.seq, 1, "sequence number advanced");
    }

    /// A tampered record (one flipped tag byte) must fail authentication and not advance the seq.
    #[test]
    fn tampered_record_is_rejected() {
        let secret = hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5");
        let mut keys = Tls13Keys::aes128_gcm(&secret).unwrap();
        let mut record = hex(
            "1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f2b\
             9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae63aee\
             bb21694915e4",
        );
        *record.last_mut().unwrap() ^= 0x01; // flip the last tag byte
        assert!(keys.open_next(&record).is_none());
        assert_eq!(keys.seq, 0, "rejected record must not advance the sequence");
    }

    #[test]
    fn rejects_wrong_length_secret() {
        assert!(Tls13Keys::aes128_gcm(&[0u8; 16]).is_none());
    }
}
