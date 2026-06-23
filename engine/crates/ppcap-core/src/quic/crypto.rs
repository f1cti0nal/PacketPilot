//! Vendored HMAC-SHA256, HKDF-Extract, HKDF-Expand, and HKDF-Expand-Label.
//!
//! Builds on the existing vendored SHA-256 in `analyze::sha256`. Pure compute;
//! wasm-safe (no std::{fs, net, time}).
//!
//! ## References
//! - RFC 2104 — HMAC
//! - RFC 5869 — HKDF
//! - RFC 8446 §7.1 — TLS 1.3 HKDF-Expand-Label
//! - RFC 9001 §5 — QUIC-TLS key derivation

use crate::analyze::sha256;

const BLOCK: usize = 64;

/// HMAC-SHA256 per RFC 2104.
pub(crate) fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Vec::with_capacity(BLOCK + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner_hash = sha256(&inner);
    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/// HKDF-Extract per RFC 5869 §2.2.
pub(crate) fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

/// HKDF-Expand per RFC 5869 §2.3.
pub(crate) fn hkdf_expand(prk: &[u8; 32], info: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < out_len {
        let mut data = Vec::with_capacity(t.len() + info.len() + 1);
        data.extend_from_slice(&t);
        data.extend_from_slice(info);
        data.push(counter);
        t = hmac_sha256(prk, &data).to_vec();
        out.extend_from_slice(&t);
        counter = counter.wrapping_add(1);
    }
    out.truncate(out_len);
    out
}

/// TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1), empty context.
pub(crate) fn hkdf_expand_label(secret: &[u8; 32], label: &str, out_len: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + full.len() + 1);
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0u8); // empty context
    hkdf_expand(secret, &info, out_len)
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

    /// RFC 4231 Test Case 2:
    /// Key  = "Jefe"
    /// Data = "what do ya want for nothing?"
    /// HMAC = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    #[test]
    fn hmac_sha256_rfc4231_tc2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        let got = hmac_sha256(key, data);
        assert_eq!(got.as_ref(), expected.as_slice());
    }

    /// RFC 5869 Test Case 1:
    /// Hash  = SHA-256
    /// IKM   = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
    /// salt  = 0x000102030405060708090a0b0c (13 octets)
    /// info  = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
    /// L     = 42
    /// PRK   = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
    /// OKM   = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
    #[test]
    fn hkdf_rfc5869_tc1() {
        let ikm: Vec<u8> = vec![0x0bu8; 22];
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let l = 42;

        let expected_prk = hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let expected_okm = hex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );

        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(prk.as_ref(), expected_prk.as_slice(), "PRK mismatch");

        let okm = hkdf_expand(&prk, &info, l);
        assert_eq!(okm, expected_okm, "OKM mismatch");
    }

    /// hkdf_expand_label shape test: output length must match requested length.
    /// Uses RFC 9001 §A.1 QUIC initial secret derivation as a spot-check.
    ///
    /// From RFC 9001 Appendix A.1:
    ///   initial_salt = 38762cf7f55934b34d179ae6a4c80cadccbb7f0a
    ///   DCID         = 8394c8f03e515708
    ///   initial_secret = HKDF-Extract(initial_salt, DCID)
    ///                  = 7db5df06e7a69e432496adedb0085192...
    ///   client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    ///                         = c00cf151ca5be075ed0ebfb5c80323c4...
    #[test]
    fn hkdf_expand_label_quic_rfc9001_a1() {
        let initial_salt = hex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
        let dcid = hex("8394c8f03e515708");

        let initial_secret = hkdf_extract(&initial_salt, &dcid);
        // RFC 9001 Appendix A.1: initial_secret
        assert_eq!(
            initial_secret.as_ref(),
            hex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44").as_slice(),
            "initial_secret mismatch"
        );

        let client_in = hkdf_expand_label(&initial_secret, "client in", 32);
        assert_eq!(client_in.len(), 32, "output length must be 32");
        // RFC 9001 Appendix A.1: client_initial_secret
        assert_eq!(
            client_in,
            hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"),
            "client_initial_secret mismatch"
        );
    }
}
