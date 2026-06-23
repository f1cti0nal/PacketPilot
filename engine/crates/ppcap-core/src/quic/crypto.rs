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

// ---------------------------------------------------------------------------
// Vendored AES-128 + AES-128-GCM (open / decrypt-and-verify).
//
// Pure compute; wasm-safe. Used for QUIC Initial packet header/payload
// protection (RFC 9001 uses AEAD_AES_128_GCM for the Initial keys).
//
// References:
//   - FIPS-197              — AES block cipher (S-box, Rcon, KeyExpansion)
//   - NIST SP 800-38D       — GCM mode / GHASH over GF(2^128)
//   - McGrew & Viega (GCM)  — original spec + test vectors
// ---------------------------------------------------------------------------

/// Canonical AES S-box (FIPS-197 Figure 7 / §5.1.1).
#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// AES round constants (FIPS-197 §5.2): 01,02,04,08,10,20,40,80,1b,36.
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// AES-128 cipher with a precomputed key schedule (11 round keys = 44 words).
pub(crate) struct Aes128 {
    rk: [[u8; 4]; 44],
}

impl Aes128 {
    /// KeyExpansion (FIPS-197 §5.2) from a 16-byte key.
    pub(crate) fn new(key: &[u8; 16]) -> Self {
        let mut rk = [[0u8; 4]; 44];
        for i in 0..4 {
            rk[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
        }
        for i in 4..44 {
            let mut temp = rk[i - 1];
            if i % 4 == 0 {
                // RotWord, then SubWord, then XOR Rcon on the first byte.
                temp = [temp[1], temp[2], temp[3], temp[0]];
                for b in temp.iter_mut() {
                    *b = SBOX[*b as usize];
                }
                temp[0] ^= RCON[i / 4 - 1];
            }
            for j in 0..4 {
                rk[i][j] = rk[i - 4][j] ^ temp[j];
            }
        }
        Aes128 { rk }
    }

    /// Encrypt one 16-byte block (FIPS-197 §5.1).
    pub(crate) fn encrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut state = *input;
        self.add_round_key(&mut state, 0);
        for round in 1..10 {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            self.add_round_key(&mut state, round);
        }
        sub_bytes(&mut state);
        shift_rows(&mut state);
        self.add_round_key(&mut state, 10);
        state
    }

    /// AddRoundKey: XOR the state (column-major) with round-key words.
    fn add_round_key(&self, state: &mut [u8; 16], round: usize) {
        for c in 0..4 {
            let w = self.rk[round * 4 + c];
            for r in 0..4 {
                state[4 * c + r] ^= w[r];
            }
        }
    }
}

/// SubBytes: apply the S-box to every byte.
fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

/// ShiftRows: cyclically shift row `r` left by `r` (state is column-major,
/// so byte at column `c`, row `r` is `state[4*c + r]`).
fn shift_rows(state: &mut [u8; 16]) {
    let s = *state;
    for r in 1..4 {
        for c in 0..4 {
            state[4 * c + r] = s[4 * ((c + r) % 4) + r];
        }
    }
}

/// GF(2^8) multiply-by-x (xtime): left shift, conditional reduction by 0x1b.
fn xtime(a: u8) -> u8 {
    let hi = a & 0x80;
    let mut r = a << 1;
    if hi != 0 {
        r ^= 0x1b;
    }
    r
}

/// MixColumns (FIPS-197 §5.1.3): per-column matrix multiply in GF(2^8).
fn mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let i = 4 * c;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];
        state[i] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
        state[i + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        state[i + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        state[i + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    }
}

/// One GF(2^128) multiplication `x · y` per SP 800-38D §6.3.
///
/// Bit convention is MSB-first: bit 0 of the field element is the most
/// significant bit of byte 0. The reduction polynomial is
/// R = 11100001 || 0^120, i.e. byte 0 = 0xe1. We iterate the bits of `y`
/// from the MSB of byte 0 to the LSB of byte 15; whenever we shift `v`
/// right and a 1 falls off the low end, we XOR the high byte with 0xe1.
fn gf_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *x;
    for i in 0..128 {
        let bit = (y[i / 8] >> (7 - (i % 8))) & 1;
        if bit == 1 {
            for j in 0..16 {
                z[j] ^= v[j];
            }
        }
        // v >>= 1 across the whole 128-bit register (MSB-first), with
        // reduction if the bit shifted out of the LSB was set.
        let lsb = v[15] & 1;
        let mut carry = 0u8;
        for j in 0..16 {
            let new_carry = v[j] & 1;
            v[j] = (v[j] >> 1) | (carry << 7);
            carry = new_carry;
        }
        if lsb == 1 {
            v[0] ^= 0xe1;
        }
    }
    z
}

/// GHASH (SP 800-38D §6.4): authenticate AAD then ciphertext under H.
///
/// Blocks: each 16-byte block of `aad` (zero-padded to a block boundary),
/// then each 16-byte block of `ct` (zero-padded), then a final length block
/// `u64be(aad_bits) || u64be(ct_bits)`. `X = (X ^ block) · H`, X starts at 0.
fn ghash(h: &[u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut x = [0u8; 16];

    let absorb = |data: &[u8], x: &mut [u8; 16]| {
        for chunk in data.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            for j in 0..16 {
                x[j] ^= block[j];
            }
            *x = gf_mul(x, h);
        }
    };

    absorb(aad, &mut x);
    absorb(ct, &mut x);

    // Length block: bit lengths of AAD and ciphertext, big-endian u64 each.
    let mut len_block = [0u8; 16];
    let aad_bits = (aad.len() as u64) * 8;
    let ct_bits = (ct.len() as u64) * 8;
    len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..].copy_from_slice(&ct_bits.to_be_bytes());
    for j in 0..16 {
        x[j] ^= len_block[j];
    }
    x = gf_mul(&x, h);

    x
}

/// Increment the low 32 bits (big-endian) of a 16-byte counter block (inc32).
fn incr32(block: &mut [u8; 16]) {
    let mut ctr = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);
    ctr = ctr.wrapping_add(1);
    block[12..].copy_from_slice(&ctr.to_be_bytes());
}

/// AES-128-GCM authenticated decryption (SP 800-38D §7.2 / RFC 5116).
///
/// `ct_and_tag` is ciphertext followed by the 16-byte tag. Returns the
/// plaintext only if the tag verifies; otherwise `None`.
pub(crate) fn aes128_gcm_open(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ct_and_tag: &[u8],
) -> Option<Vec<u8>> {
    if ct_and_tag.len() < 16 {
        return None;
    }
    let (ct, tag) = ct_and_tag.split_at(ct_and_tag.len() - 16);

    let aes = Aes128::new(key);
    let h = aes.encrypt_block(&[0u8; 16]);

    // J0 = nonce(12) || 0x00000001  (only valid for 96-bit nonces).
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    // Expected tag = GHASH(aad, ct) XOR E(K, J0).
    let s = ghash(&h, aad, ct);
    let ej0 = aes.encrypt_block(&j0);
    let mut expected = [0u8; 16];
    for i in 0..16 {
        expected[i] = s[i] ^ ej0[i];
    }
    if expected != tag[..16] {
        return None;
    }

    // CTR decrypt from inc32(J0).
    let mut counter = j0;
    incr32(&mut counter);
    let mut out = Vec::with_capacity(ct.len());
    for chunk in ct.chunks(16) {
        let ks = aes.encrypt_block(&counter);
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
        incr32(&mut counter);
    }
    Some(out)
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

    /// Encode bytes as a lowercase hex string (inverse of `hex`).
    fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
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

    /// AES-128 single-block encryption, FIPS-197 Appendix C.1.
    ///   key = 000102030405060708090a0b0c0d0e0f
    ///   pt  = 00112233445566778899aabbccddeeff
    ///   ct  = 69c4e0d86a7b0430d8cdb78070b4c55a
    #[test]
    fn aes128_fips197_c1() {
        let key = hex("000102030405060708090a0b0c0d0e0f");
        let pt = hex("00112233445566778899aabbccddeeff");
        let ct = Aes128::new(key[..].try_into().unwrap()).encrypt_block(pt[..].try_into().unwrap());
        assert_eq!(to_hex(&ct), "69c4e0d86a7b0430d8cdb78070b4c55a");
    }

    /// AES-128-GCM decrypt/verify, McGrew–Viega "The Galois/Counter Mode of
    /// Operation (GCM)" Test Case 4 (non-empty AAD). Also matches NIST
    /// SP 800-38D and is reproduced in CAVP gcmDecrypt128 vectors.
    ///   K = feffe9928665731c6d6a8f9467308308
    ///   IV = cafebabefacedbaddecaf888 (12 bytes)
    ///   A  = feedfacedeadbeeffeedfacedeadbeefabaddad2 (20 bytes)
    ///   C  = 42831ec2...ba637b39
    ///   T  = 5bc94fbc3221a5db94fae95ae7121a47
    ///   P  = d9313225...ba637b39
    #[test]
    fn aes128_gcm_open_gcm_tc4() {
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let iv = hex("cafebabefacedbaddecaf888");
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let ct = hex(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        );
        let tag = hex("5bc94fbc3221a5db94fae95ae7121a47");
        let expected_pt = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );

        let mut ct_and_tag = ct.clone();
        ct_and_tag.extend_from_slice(&tag);

        let got = aes128_gcm_open(
            key[..].try_into().unwrap(),
            iv[..].try_into().unwrap(),
            &aad,
            &ct_and_tag,
        );
        assert_eq!(got, Some(expected_pt), "GCM open must recover plaintext");

        // Flipping one byte of the tag must reject (None).
        let mut tampered = ct.clone();
        let mut bad_tag = tag.clone();
        bad_tag[0] ^= 0x01;
        tampered.extend_from_slice(&bad_tag);
        let bad = aes128_gcm_open(
            key[..].try_into().unwrap(),
            iv[..].try_into().unwrap(),
            &aad,
            &tampered,
        );
        assert_eq!(bad, None, "tampered tag must fail authentication");
    }

    /// Independent NIST CAVP gcmDecrypt128 PASS vector
    /// (Keylen=128, IVlen=96, PTlen=128, AADlen=128, Taglen=128, Count 0,
    /// from gcmDecrypt128.rsp), as a second authentic AES-128-GCM open case.
    ///   Key = cf063a34d4a9a76c2c86787d3f96db71
    ///   IV  = 113b9785971864c83b01c787
    ///   CT  = (empty)
    ///   AAD = (empty)
    ///   Tag = 72ac8493e3a5228b5d130a69d2510e42
    ///   PT  = (empty)  -> PASS
    #[test]
    fn aes128_gcm_open_cavp_empty() {
        let key = hex("cf063a34d4a9a76c2c86787d3f96db71");
        let iv = hex("113b9785971864c83b01c787");
        let aad: Vec<u8> = Vec::new();
        let tag = hex("72ac8493e3a5228b5d130a69d2510e42");

        // ct_and_tag is just the tag (empty ciphertext).
        let got = aes128_gcm_open(
            key[..].try_into().unwrap(),
            iv[..].try_into().unwrap(),
            &aad,
            &tag,
        );
        assert_eq!(got, Some(Vec::new()), "CAVP empty PASS vector");

        // Tamper -> None.
        let mut bad_tag = tag.clone();
        bad_tag[15] ^= 0x80;
        let bad = aes128_gcm_open(
            key[..].try_into().unwrap(),
            iv[..].try_into().unwrap(),
            &aad,
            &bad_tag,
        );
        assert_eq!(bad, None, "tampered empty-ct tag must fail");
    }
}
