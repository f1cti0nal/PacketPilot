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
        add_round_key(state, &self.rk, round);
    }
}

/// AES-256 cipher with a precomputed key schedule (15 round keys = 60 words).
/// Used for TLS 1.3 `TLS_AES_256_GCM_SHA384` key-log decryption.
pub(crate) struct Aes256 {
    rk: [[u8; 4]; 60],
}

impl Aes256 {
    /// KeyExpansion (FIPS-197 §5.2) from a 32-byte key (Nk = 8, Nr = 14). Differs from AES-128 by
    /// the extra SubWord applied every fourth word within an 8-word run (`i % 8 == 4`).
    pub(crate) fn new(key: &[u8; 32]) -> Self {
        let mut rk = [[0u8; 4]; 60];
        for i in 0..8 {
            rk[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
        }
        for i in 8..60 {
            let mut temp = rk[i - 1];
            if i % 8 == 0 {
                temp = [temp[1], temp[2], temp[3], temp[0]]; // RotWord
                for b in temp.iter_mut() {
                    *b = SBOX[*b as usize]; // SubWord
                }
                temp[0] ^= RCON[i / 8 - 1];
            } else if i % 8 == 4 {
                for b in temp.iter_mut() {
                    *b = SBOX[*b as usize]; // SubWord only (AES-256 extra step)
                }
            }
            for j in 0..4 {
                rk[i][j] = rk[i - 8][j] ^ temp[j];
            }
        }
        Aes256 { rk }
    }

    /// Encrypt one 16-byte block (FIPS-197 §5.1, 14 rounds).
    pub(crate) fn encrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut state = *input;
        add_round_key(&mut state, &self.rk, 0);
        for round in 1..14 {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &self.rk, round);
        }
        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &self.rk, 14);
        state
    }
}

/// AddRoundKey over an explicit round-key schedule: XOR the column-major state with the four
/// round-key words for `round`. Shared by [`Aes128`] and [`Aes256`].
fn add_round_key(state: &mut [u8; 16], rk: &[[u8; 4]], round: usize) {
    for c in 0..4 {
        let w = rk[round * 4 + c];
        for r in 0..4 {
            state[4 * c + r] ^= w[r];
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
            for (zb, vb) in z.iter_mut().zip(v.iter()) {
                *zb ^= *vb;
            }
        }
        // v >>= 1 across the whole 128-bit register (MSB-first), with
        // reduction if the bit shifted out of the LSB was set.
        let lsb = v[15] & 1;
        let mut carry = 0u8;
        for vb in v.iter_mut() {
            let new_carry = *vb & 1;
            *vb = (*vb >> 1) | (carry << 7);
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

/// AES-GCM authenticated decryption core, generic over the block cipher (SP 800-38D §7.2 /
/// RFC 5116). `encrypt_block` is the AES block function for the chosen key size; `ct_and_tag` is
/// the ciphertext followed by the 16-byte tag. Returns the plaintext only if the tag verifies.
fn gcm_open(
    encrypt_block: impl Fn(&[u8; 16]) -> [u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ct_and_tag: &[u8],
) -> Option<Vec<u8>> {
    if ct_and_tag.len() < 16 {
        return None;
    }
    let (ct, tag) = ct_and_tag.split_at(ct_and_tag.len() - 16);

    let h = encrypt_block(&[0u8; 16]);

    // J0 = nonce(12) || 0x00000001  (only valid for 96-bit nonces).
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    // Expected tag = GHASH(aad, ct) XOR E(K, J0).
    let s = ghash(&h, aad, ct);
    let ej0 = encrypt_block(&j0);
    let mut expected = [0u8; 16];
    for i in 0..16 {
        expected[i] = s[i] ^ ej0[i];
    }
    if !tags_eq(&expected, tag) {
        return None;
    }

    // CTR decrypt from inc32(J0).
    let mut counter = j0;
    incr32(&mut counter);
    let mut out = Vec::with_capacity(ct.len());
    for chunk in ct.chunks(16) {
        let ks = encrypt_block(&counter);
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
        incr32(&mut counter);
    }
    Some(out)
}

/// AES-128-GCM authenticated decryption. `ct_and_tag` is ciphertext + the 16-byte tag; returns the
/// plaintext only if the tag verifies, else `None`.
pub(crate) fn aes128_gcm_open(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ct_and_tag: &[u8],
) -> Option<Vec<u8>> {
    let aes = Aes128::new(key);
    gcm_open(|b| aes.encrypt_block(b), nonce, aad, ct_and_tag)
}

/// AES-256-GCM authenticated decryption (TLS 1.3 `TLS_AES_256_GCM_SHA384`).
pub(crate) fn aes256_gcm_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ct_and_tag: &[u8],
) -> Option<Vec<u8>> {
    let aes = Aes256::new(key);
    gcm_open(|b| aes.encrypt_block(b), nonce, aad, ct_and_tag)
}

// ---------------------------------------------------------------------------
// AES decryption (inverse cipher) + AES-CBC, for the TLS 1.2 CBC suites.
//
// References: FIPS-197 §5.3 (InvCipher), NIST SP 800-38A §6.2 (CBC).
// ---------------------------------------------------------------------------

/// Inverse AES S-box, derived from [`SBOX`] at compile time (`INV_SBOX[SBOX[i]] == i`), so there is
/// no second 256-byte table to mistranscribe.
const INV_SBOX: [u8; 256] = {
    let mut inv = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        inv[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    inv
};

/// GF(2^8) multiply (Russian-peasant), reduction polynomial 0x1b — for InvMixColumns coefficients.
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

/// InvSubBytes: apply the inverse S-box to every byte.
fn inv_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = INV_SBOX[*b as usize];
    }
}

/// InvShiftRows: cyclically shift row `r` RIGHT by `r` (inverse of [`shift_rows`]).
fn inv_shift_rows(state: &mut [u8; 16]) {
    let s = *state;
    for r in 1..4 {
        for c in 0..4 {
            state[4 * c + r] = s[4 * ((c + 4 - r) % 4) + r];
        }
    }
}

/// InvMixColumns (FIPS-197 §5.3.3): per-column multiply by the inverse matrix (0e,0b,0d,09).
fn inv_mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let i = 4 * c;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];
        state[i] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
        state[i + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
        state[i + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
        state[i + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
    }
}

/// Decrypt one 16-byte block under the round-key schedule `rk` with `nr` rounds (FIPS-197 §5.3,
/// the straightforward inverse cipher).
fn aes_decrypt_block(input: &[u8; 16], rk: &[[u8; 4]], nr: usize) -> [u8; 16] {
    let mut state = *input;
    add_round_key(&mut state, rk, nr);
    for round in (1..nr).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, rk, round);
        inv_mix_columns(&mut state);
    }
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    add_round_key(&mut state, rk, 0);
    state
}

impl Aes128 {
    /// Decrypt one 16-byte block (FIPS-197 §5.3).
    pub(crate) fn decrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        aes_decrypt_block(input, &self.rk, 10)
    }
}

impl Aes256 {
    /// Decrypt one 16-byte block (FIPS-197 §5.3, 14 rounds).
    pub(crate) fn decrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        aes_decrypt_block(input, &self.rk, 14)
    }
}

/// AES-CBC decryption (SP 800-38A §6.2), generic over the block-decrypt function. `ct` length must
/// be a non-zero multiple of 16. Returns `None` otherwise (no unpadding here — TLS strips its own).
fn cbc_decrypt(
    decrypt_block: impl Fn(&[u8; 16]) -> [u8; 16],
    iv: &[u8; 16],
    ct: &[u8],
) -> Option<Vec<u8>> {
    if ct.is_empty() || ct.len() % 16 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(ct.len());
    let mut prev = *iv;
    for chunk in ct.chunks_exact(16) {
        let block: [u8; 16] = chunk.try_into().unwrap();
        let dec = decrypt_block(&block);
        for i in 0..16 {
            out.push(dec[i] ^ prev[i]);
        }
        prev = block;
    }
    Some(out)
}

/// AES-128-CBC decryption.
pub(crate) fn aes128_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], ct: &[u8]) -> Option<Vec<u8>> {
    let aes = Aes128::new(key);
    cbc_decrypt(|b| aes.decrypt_block(b), iv, ct)
}

/// AES-256-CBC decryption.
pub(crate) fn aes256_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], ct: &[u8]) -> Option<Vec<u8>> {
    let aes = Aes256::new(key);
    cbc_decrypt(|b| aes.decrypt_block(b), iv, ct)
}

// ---------------------------------------------------------------------------
// Vendored SHA-384 + HMAC-SHA384 + HKDF-Expand-Label-SHA384.
//
// TLS 1.3 `TLS_AES_256_GCM_SHA384` runs its key schedule over SHA-384, so the AEAD key/iv come
// from HKDF-Expand-Label with SHA-384 (the SHA-256 path above is wrong for this suite). SHA-384 is
// SHA-512 with different initial values, truncated to 48 bytes.
//
// References: FIPS 180-4 (SHA-384/512), RFC 2104 (HMAC), RFC 5869 (HKDF), RFC 8446 §7.1.
// ---------------------------------------------------------------------------

/// SHA-512 round constants (FIPS 180-4 §4.2.3): first 64 bits of the fractional parts of the cube
/// roots of the first 80 primes.
#[rustfmt::skip]
const SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// SHA-384 initial hash values (FIPS 180-4 §5.3.4).
#[rustfmt::skip]
const SHA384_H0: [u64; 8] = [
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
];

const BLOCK384: usize = 128;

/// One SHA-512 compression over a 128-byte block (FIPS 180-4 §6.4).
fn sha512_compress(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 80];
    for i in 0..16 {
        w[i] = u64::from_be_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
    }
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA512_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// SHA-384 digest (FIPS 180-4): SHA-512 with the SHA-384 IV, truncated to 48 bytes. The padding
/// length field is 128-bit; capture inputs are far below 2^64 bytes so the high half is always 0.
pub(crate) fn sha384(msg: &[u8]) -> [u8; 48] {
    let mut state = SHA384_H0;
    let bitlen = (msg.len() as u128) * 8;
    let mut data = msg.to_vec();
    data.push(0x80);
    while data.len() % BLOCK384 != BLOCK384 - 16 {
        data.push(0);
    }
    data.extend_from_slice(&bitlen.to_be_bytes()); // 16-byte big-endian length
    for chunk in data.chunks_exact(BLOCK384) {
        sha512_compress(&mut state, chunk.try_into().unwrap());
    }
    let mut out = [0u8; 48];
    for i in 0..6 {
        out[i * 8..i * 8 + 8].copy_from_slice(&state[i].to_be_bytes());
    }
    out
}

/// HMAC-SHA384 per RFC 2104 (block size 128, digest 48).
pub(crate) fn hmac_sha384(key: &[u8], msg: &[u8]) -> [u8; 48] {
    let mut k = [0u8; BLOCK384];
    if key.len() > BLOCK384 {
        k[..48].copy_from_slice(&sha384(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK384];
    let mut opad = [0x5cu8; BLOCK384];
    for i in 0..BLOCK384 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Vec::with_capacity(BLOCK384 + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner_hash = sha384(&inner);
    let mut outer = Vec::with_capacity(BLOCK384 + 48);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha384(&outer)
}

/// HKDF-Expand (RFC 5869 §2.3) with SHA-384 (48-byte PRK / `T(n)` blocks).
fn hkdf_expand384(prk: &[u8; 48], info: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < out_len {
        let mut data = Vec::with_capacity(t.len() + info.len() + 1);
        data.extend_from_slice(&t);
        data.extend_from_slice(info);
        data.push(counter);
        t = hmac_sha384(prk, &data).to_vec();
        out.extend_from_slice(&t);
        counter = counter.wrapping_add(1);
    }
    out.truncate(out_len);
    out
}

/// TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1) with SHA-384, empty context. The traffic `secret` is
/// the 48-byte SHA-384-length secret from the key-log.
pub(crate) fn hkdf_expand_label_sha384(secret: &[u8; 48], label: &str, out_len: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + full.len() + 1);
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0u8); // empty context
    hkdf_expand384(secret, &info, out_len)
}

// ---------------------------------------------------------------------------
// Vendored SHA-1 + HMAC-SHA1 (FIPS 180-4 / RFC 2104).
//
// Needed for the TLS 1.2 CBC suites with an HMAC-SHA1 record MAC (`*_CBC_SHA`), the most common
// legacy AES-CBC suites. SHA-1 is used here ONLY to verify record integrity while decrypting a
// capture the analyst already holds the keys for — never to produce a new signature.
// ---------------------------------------------------------------------------

/// SHA-1 digest (FIPS 180-4 §6.1).
pub(crate) fn sha1(msg: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let bitlen = (msg.len() as u64) * 8;
    let mut data = msg.to_vec();
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bitlen.to_be_bytes());
    for block in data.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for i in 0..5 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

/// HMAC-SHA1 per RFC 2104 (block size 64, digest 20).
pub(crate) fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..20].copy_from_slice(&sha1(key));
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
    let inner_hash = sha1(&inner);
    let mut outer = Vec::with_capacity(BLOCK + 20);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

// ---------------------------------------------------------------------------
// TLS 1.2 PRF (RFC 5246 §5).
//
// `PRF(secret, label, seed) = P_hash(secret, label || seed)`, where
// `P_hash(secret, seed) = HMAC(secret, A(1)||seed) || HMAC(secret, A(2)||seed) || …`,
// `A(0) = seed`, `A(i) = HMAC(secret, A(i-1))`. The hash is the cipher suite's PRF hash
// (SHA-256 for most TLS 1.2 AEAD suites; SHA-384 for the `_SHA384` suites). Used to expand the
// key-log master secret into the per-direction key block for TLS 1.2 key-log decryption.
// ---------------------------------------------------------------------------

/// TLS 1.2 PRF with SHA-256 (RFC 5246 §5).
pub(crate) fn tls12_prf_sha256(
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    out_len: usize,
) -> Vec<u8> {
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);
    let mut out = Vec::with_capacity(out_len);
    let mut a = hmac_sha256(secret, &label_seed).to_vec(); // A(1)
    while out.len() < out_len {
        let mut input = Vec::with_capacity(a.len() + label_seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(&label_seed);
        out.extend_from_slice(&hmac_sha256(secret, &input));
        a = hmac_sha256(secret, &a).to_vec(); // A(i+1)
    }
    out.truncate(out_len);
    out
}

/// TLS 1.2 PRF with SHA-384 (for the `_SHA384` cipher suites).
pub(crate) fn tls12_prf_sha384(
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    out_len: usize,
) -> Vec<u8> {
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);
    let mut out = Vec::with_capacity(out_len);
    let mut a = hmac_sha384(secret, &label_seed).to_vec();
    while out.len() < out_len {
        let mut input = Vec::with_capacity(a.len() + label_seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(&label_seed);
        out.extend_from_slice(&hmac_sha384(secret, &input));
        a = hmac_sha384(secret, &a).to_vec();
    }
    out.truncate(out_len);
    out
}

// ---------------------------------------------------------------------------
// Vendored ChaCha20-Poly1305 AEAD (RFC 8439).
//
// TLS 1.3 `TLS_CHACHA20_POLY1305_SHA256`. Stream cipher + one-time Poly1305 MAC, both from scratch
// (no GCM/GF(2^128) reuse). Pure compute; wasm-safe.
// ---------------------------------------------------------------------------

/// ChaCha20 quarter-round (RFC 8439 §2.1) over four state words.
fn chacha_qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// The ChaCha20 block function (RFC 8439 §2.3): 64-byte keystream block for `counter`/`nonce`.
fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
    }
    let mut w = state;
    for _ in 0..10 {
        // Column rounds, then diagonal rounds (RFC 8439 §2.3.1).
        chacha_qr(&mut w, 0, 4, 8, 12);
        chacha_qr(&mut w, 1, 5, 9, 13);
        chacha_qr(&mut w, 2, 6, 10, 14);
        chacha_qr(&mut w, 3, 7, 11, 15);
        chacha_qr(&mut w, 0, 5, 10, 15);
        chacha_qr(&mut w, 1, 6, 11, 12);
        chacha_qr(&mut w, 2, 7, 8, 13);
        chacha_qr(&mut w, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        let v = w[i].wrapping_add(state[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

/// ChaCha20 keystream XOR (RFC 8439 §2.4) starting from block counter `counter0`.
fn chacha20_xor(key: &[u8; 32], counter0: u32, nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut counter = counter0;
    for chunk in data.chunks(64) {
        let ks = chacha20_block(key, counter, nonce);
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
        counter = counter.wrapping_add(1);
    }
    out
}

/// Poly1305 one-time authenticator (RFC 8439 §2.5) over `msg` with a 32-byte one-time key.
/// Radix-2^26 (5 limbs), the classic "donna32" arithmetic mod 2^130 − 5.
fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    // Clamp r and split into 26-bit limbs.
    let t0 = u32::from_le_bytes(key[0..4].try_into().unwrap());
    let t1 = u32::from_le_bytes(key[4..8].try_into().unwrap());
    let t2 = u32::from_le_bytes(key[8..12].try_into().unwrap());
    let t3 = u32::from_le_bytes(key[12..16].try_into().unwrap());
    let r0 = (t0) & 0x3ff_ffff;
    let r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ff_ff03;
    let r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ff_c0ff;
    let r3 = ((t2 >> 14) | (t3 << 18)) & 0x3f0_3fff;
    let r4 = (t3 >> 8) & 0x00f_ffff;
    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    let mut h = [0u32; 5];
    let mut chunks = msg.chunks(16).peekable();
    while let Some(chunk) = chunks.next() {
        // Load the block as a 17-byte little-endian number: the bytes, then a 1 bit at position
        // 8*len (a full 16-byte block sets bit 128 via `hibit`; a short final block embeds the
        // 0x01 byte directly).
        let mut blk = [0u8; 16];
        blk[..chunk.len()].copy_from_slice(chunk);
        let last = chunks.peek().is_none() && chunk.len() < 16;
        if last {
            blk[chunk.len()] = 1;
        }
        let hibit: u32 = if last { 0 } else { 1 << 24 };
        let b0 = u32::from_le_bytes(blk[0..4].try_into().unwrap());
        let b1 = u32::from_le_bytes(blk[4..8].try_into().unwrap());
        let b2 = u32::from_le_bytes(blk[8..12].try_into().unwrap());
        let b3 = u32::from_le_bytes(blk[12..16].try_into().unwrap());
        h[0] = h[0].wrapping_add(b0 & 0x3ff_ffff);
        h[1] = h[1].wrapping_add(((b0 >> 26) | (b1 << 6)) & 0x3ff_ffff);
        h[2] = h[2].wrapping_add(((b1 >> 20) | (b2 << 12)) & 0x3ff_ffff);
        h[3] = h[3].wrapping_add(((b2 >> 14) | (b3 << 18)) & 0x3ff_ffff);
        h[4] = h[4].wrapping_add((b3 >> 8) | hibit);

        // h = (h * r) mod (2^130 - 5)
        let d0 = (h[0] as u64) * (r0 as u64)
            + (h[1] as u64) * (s4 as u64)
            + (h[2] as u64) * (s3 as u64)
            + (h[3] as u64) * (s2 as u64)
            + (h[4] as u64) * (s1 as u64);
        let d1 = (h[0] as u64) * (r1 as u64)
            + (h[1] as u64) * (r0 as u64)
            + (h[2] as u64) * (s4 as u64)
            + (h[3] as u64) * (s3 as u64)
            + (h[4] as u64) * (s2 as u64);
        let d2 = (h[0] as u64) * (r2 as u64)
            + (h[1] as u64) * (r1 as u64)
            + (h[2] as u64) * (r0 as u64)
            + (h[3] as u64) * (s4 as u64)
            + (h[4] as u64) * (s3 as u64);
        let d3 = (h[0] as u64) * (r3 as u64)
            + (h[1] as u64) * (r2 as u64)
            + (h[2] as u64) * (r1 as u64)
            + (h[3] as u64) * (r0 as u64)
            + (h[4] as u64) * (s4 as u64);
        let d4 = (h[0] as u64) * (r4 as u64)
            + (h[1] as u64) * (r3 as u64)
            + (h[2] as u64) * (r2 as u64)
            + (h[3] as u64) * (r1 as u64)
            + (h[4] as u64) * (r0 as u64);

        let mut c = (d0 >> 26) as u32;
        h[0] = (d0 as u32) & 0x3ff_ffff;
        let d1 = d1 + c as u64;
        c = (d1 >> 26) as u32;
        h[1] = (d1 as u32) & 0x3ff_ffff;
        let d2 = d2 + c as u64;
        c = (d2 >> 26) as u32;
        h[2] = (d2 as u32) & 0x3ff_ffff;
        let d3 = d3 + c as u64;
        c = (d3 >> 26) as u32;
        h[3] = (d3 as u32) & 0x3ff_ffff;
        let d4 = d4 + c as u64;
        c = (d4 >> 26) as u32;
        h[4] = (d4 as u32) & 0x3ff_ffff;
        h[0] = h[0].wrapping_add(c * 5);
        c = h[0] >> 26;
        h[0] &= 0x3ff_ffff;
        h[1] = h[1].wrapping_add(c);
    }

    // Final reduction: fully carry, then conditionally subtract p = 2^130 - 5.
    let mut c = h[1] >> 26;
    h[1] &= 0x3ff_ffff;
    h[2] = h[2].wrapping_add(c);
    c = h[2] >> 26;
    h[2] &= 0x3ff_ffff;
    h[3] = h[3].wrapping_add(c);
    c = h[3] >> 26;
    h[3] &= 0x3ff_ffff;
    h[4] = h[4].wrapping_add(c);
    c = h[4] >> 26;
    h[4] &= 0x3ff_ffff;
    h[0] = h[0].wrapping_add(c * 5);
    c = h[0] >> 26;
    h[0] &= 0x3ff_ffff;
    h[1] = h[1].wrapping_add(c);

    // g = h - p (p = 2^130 - 5): add 5, then test the carry out of bit 130.
    let mut g = [0u32; 5];
    let mut gc = 5u32;
    for i in 0..5 {
        g[i] = h[i].wrapping_add(gc);
        gc = g[i] >> 26;
        g[i] &= 0x3ff_ffff;
    }
    g[4] = g[4].wrapping_sub(1 << 26);
    // If g[4] did NOT borrow (top bit clear), h >= p, so use g; else keep h.
    let mask = (g[4] >> 31).wrapping_sub(1); // 0xffffffff when g is valid (no borrow), else 0
    for i in 0..5 {
        h[i] = (h[i] & !mask) | (g[i] & mask);
    }

    // Serialize h to a 128-bit little-endian number, then add s (the high 16 key bytes).
    let h0 = h[0] | (h[1] << 26);
    let h1 = (h[1] >> 6) | (h[2] << 20);
    let h2 = (h[2] >> 12) | (h[3] << 14);
    let h3 = (h[3] >> 18) | (h[4] << 8);
    let mut acc = [h0, h1, h2, h3];
    let mut carry = 0u64;
    for (i, a) in acc.iter_mut().enumerate() {
        let s = u32::from_le_bytes(key[16 + i * 4..16 + i * 4 + 4].try_into().unwrap());
        let sum = (*a as u64) + (s as u64) + carry;
        *a = sum as u32;
        carry = sum >> 32;
    }
    let mut tag = [0u8; 16];
    for i in 0..4 {
        tag[i * 4..i * 4 + 4].copy_from_slice(&acc[i].to_le_bytes());
    }
    tag
}

/// Constant-time equality for MAC/tag comparison (length-checked, no early exit).
pub(crate) fn tags_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// AEAD_CHACHA20_POLY1305 authenticated decryption (RFC 8439 §2.8). `ct_and_tag` is ciphertext +
/// the 16-byte Poly1305 tag. Returns the plaintext only if the tag verifies, else `None`.
pub(crate) fn chacha20_poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ct_and_tag: &[u8],
) -> Option<Vec<u8>> {
    if ct_and_tag.len() < 16 {
        return None;
    }
    let (ct, tag) = ct_and_tag.split_at(ct_and_tag.len() - 16);

    // One-time Poly1305 key = first 32 bytes of ChaCha20 block 0.
    let block0 = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&block0[..32]);

    // MAC input: AAD || pad16 || ciphertext || pad16 || le64(aad_len) || le64(ct_len).
    let mut mac = Vec::with_capacity(aad.len() + ct.len() + 64);
    mac.extend_from_slice(aad);
    while mac.len() % 16 != 0 {
        mac.push(0);
    }
    mac.extend_from_slice(ct);
    while mac.len() % 16 != 0 {
        mac.push(0);
    }
    mac.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac.extend_from_slice(&(ct.len() as u64).to_le_bytes());

    if !tags_eq(&poly1305(&poly_key, &mac), tag) {
        return None;
    }
    // Payload encryption uses counter 1 onward (block 0 made the Poly key).
    Some(chacha20_xor(key, 1, nonce, ct))
}

// ---------------------------------------------------------------------------
// Test-only AEAD seal helpers (inverse of the `*_open` functions). Not compiled into the wasm.
// Used to build synthetic encrypted TLS records for round-trip integration tests.
// ---------------------------------------------------------------------------

/// AES-GCM authenticated encryption core (inverse of [`gcm_open`]); returns ciphertext || tag.
#[cfg(test)]
fn gcm_seal(
    encrypt_block: impl Fn(&[u8; 16]) -> [u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    pt: &[u8],
) -> Vec<u8> {
    let h = encrypt_block(&[0u8; 16]);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;
    let mut counter = j0;
    incr32(&mut counter);
    let mut ct = Vec::with_capacity(pt.len() + 16);
    for chunk in pt.chunks(16) {
        let ks = encrypt_block(&counter);
        for (i, &b) in chunk.iter().enumerate() {
            ct.push(b ^ ks[i]);
        }
        incr32(&mut counter);
    }
    let s = ghash(&h, aad, &ct);
    let ej0 = encrypt_block(&j0);
    for i in 0..16 {
        ct.push(s[i] ^ ej0[i]);
    }
    ct
}

#[cfg(test)]
pub(crate) fn aes128_gcm_seal(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let aes = Aes128::new(key);
    gcm_seal(|b| aes.encrypt_block(b), nonce, aad, pt)
}

#[cfg(test)]
pub(crate) fn aes256_gcm_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let aes = Aes256::new(key);
    gcm_seal(|b| aes.encrypt_block(b), nonce, aad, pt)
}

/// AES-CBC encryption (inverse of [`cbc_decrypt`]); `pt` length must be a multiple of 16.
#[cfg(test)]
fn cbc_encrypt(encrypt_block: impl Fn(&[u8; 16]) -> [u8; 16], iv: &[u8; 16], pt: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(pt.len());
    let mut prev = *iv;
    for chunk in pt.chunks_exact(16) {
        let mut x = [0u8; 16];
        for i in 0..16 {
            x[i] = chunk[i] ^ prev[i];
        }
        let enc = encrypt_block(&x);
        out.extend_from_slice(&enc);
        prev = enc;
    }
    out
}

#[cfg(test)]
pub(crate) fn aes128_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], pt: &[u8]) -> Vec<u8> {
    let aes = Aes128::new(key);
    cbc_encrypt(|b| aes.encrypt_block(b), iv, pt)
}

#[cfg(test)]
pub(crate) fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], pt: &[u8]) -> Vec<u8> {
    let aes = Aes256::new(key);
    cbc_encrypt(|b| aes.encrypt_block(b), iv, pt)
}

#[cfg(test)]
pub(crate) fn chacha20_poly1305_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    pt: &[u8],
) -> Vec<u8> {
    let block0 = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&block0[..32]);
    let ct = chacha20_xor(key, 1, nonce, pt);
    let mut mac = Vec::with_capacity(aad.len() + ct.len() + 64);
    mac.extend_from_slice(aad);
    while mac.len() % 16 != 0 {
        mac.push(0);
    }
    mac.extend_from_slice(&ct);
    while mac.len() % 16 != 0 {
        mac.push(0);
    }
    mac.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    let tag = poly1305(&poly_key, &mac);
    let mut out = ct;
    out.extend_from_slice(&tag);
    out
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

    // ── SHA-384 / HMAC-SHA384 (for TLS_AES_256_GCM_SHA384 HKDF) ──────────────────

    /// SHA-384("abc") — FIPS 180-4 / NIST CAVP known answer.
    #[test]
    fn sha384_fips180_abc() {
        assert_eq!(
            to_hex(&sha384(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
        // A two-block message (>112 bytes) exercises multi-block padding; FIPS 180-4 §appendix.
        let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        assert_eq!(
            to_hex(&sha384(msg)),
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712\
             fcc7c71a557e2db966c3e9fa91746039"
        );
    }

    /// RFC 4231 Test Case 2: HMAC-SHA-384(key="Jefe", "what do ya want for nothing?").
    #[test]
    fn hmac_sha384_rfc4231_tc2() {
        let got = hmac_sha384(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            to_hex(&got),
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
             8e2240ca5e69e2c78b3239ecfab21649"
        );
    }

    /// hkdf_expand_label_sha384 must return exactly the requested length (the AES-256 key/iv sizes).
    #[test]
    fn hkdf_expand_label_sha384_lengths() {
        let secret = [0x42u8; 48];
        assert_eq!(hkdf_expand_label_sha384(&secret, "key", 32).len(), 32);
        assert_eq!(hkdf_expand_label_sha384(&secret, "iv", 12).len(), 12);
    }

    // ── AES-256 / AES-256-GCM ────────────────────────────────────────────────────

    /// AES-256 single-block encryption, FIPS-197 Appendix C.3.
    #[test]
    fn aes256_fips197_c3() {
        let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let pt = hex("00112233445566778899aabbccddeeff");
        let ct = Aes256::new(key[..].try_into().unwrap()).encrypt_block(pt[..].try_into().unwrap());
        assert_eq!(to_hex(&ct), "8ea2b7ca516745bfeafc49904b496089");
    }

    /// AES-256-GCM decrypt/verify, McGrew–Viega GCM Test Case 15 (AES-256, 64-byte P, empty AAD).
    ///   K  = feffe9928665731c6d6a8f9467308308 feffe9928665731c6d6a8f9467308308
    ///   IV = cafebabefacedbaddecaf888
    ///   T  = b094dac5d93471bdec1a502270e3cc6c
    #[test]
    fn aes256_gcm_open_gcm_tc15() {
        let key = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let iv = hex("cafebabefacedbaddecaf888");
        let aad: Vec<u8> = Vec::new();
        let ct = hex(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        );
        let tag = hex("b094dac5d93471bdec1a502270e3cc6c");
        let expected_pt = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        );

        let mut ct_and_tag = ct.clone();
        ct_and_tag.extend_from_slice(&tag);
        let got = aes256_gcm_open(
            key[..].try_into().unwrap(),
            iv[..].try_into().unwrap(),
            &aad,
            &ct_and_tag,
        );
        assert_eq!(
            got,
            Some(expected_pt),
            "AES-256-GCM open recovers plaintext"
        );

        // Tamper one tag byte -> reject.
        let mut tampered = ct.clone();
        let mut bad_tag = tag.clone();
        bad_tag[0] ^= 0x01;
        tampered.extend_from_slice(&bad_tag);
        assert_eq!(
            aes256_gcm_open(
                key[..].try_into().unwrap(),
                iv[..].try_into().unwrap(),
                &aad,
                &tampered,
            ),
            None,
            "tampered AES-256-GCM tag must fail"
        );
    }

    // ── ChaCha20 / Poly1305 / AEAD ───────────────────────────────────────────────

    /// ChaCha20 block function, RFC 8439 §2.3.2 (key 00..1f, counter 1, nonce 00000009...).
    #[test]
    fn chacha20_block_rfc8439_232() {
        let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = hex("000000090000004a00000000");
        let block = chacha20_block(
            key[..].try_into().unwrap(),
            1,
            nonce[..].try_into().unwrap(),
        );
        assert_eq!(
            to_hex(&block),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c0680304\
             22aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        );
    }

    /// Poly1305, RFC 8439 §2.5.2 ("Cryptographic Forum Research Group").
    #[test]
    fn poly1305_rfc8439_252() {
        let key = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        let tag = poly1305(
            key[..].try_into().unwrap(),
            b"Cryptographic Forum Research Group",
        );
        assert_eq!(to_hex(&tag), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    /// AEAD_CHACHA20_POLY1305 decrypt, RFC 8439 §2.8.2 (recovers the sunscreen plaintext).
    #[test]
    fn chacha20_poly1305_open_rfc8439_282() {
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = hex("070000004041424344454647");
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let ct = hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116",
        );
        let tag = hex("1ae10b594f09e26a7e902ecbd0600691");
        let expected = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let mut ct_and_tag = ct.clone();
        ct_and_tag.extend_from_slice(&tag);
        let got = chacha20_poly1305_open(
            key[..].try_into().unwrap(),
            nonce[..].try_into().unwrap(),
            &aad,
            &ct_and_tag,
        );
        assert_eq!(
            got.as_deref(),
            Some(&expected[..]),
            "ChaCha20-Poly1305 open"
        );

        // Tamper one ciphertext byte -> reject.
        let mut tampered = ct.clone();
        tampered[0] ^= 0x01;
        tampered.extend_from_slice(&tag);
        assert_eq!(
            chacha20_poly1305_open(
                key[..].try_into().unwrap(),
                nonce[..].try_into().unwrap(),
                &aad,
                &tampered,
            ),
            None,
            "tampered ChaCha20-Poly1305 must fail"
        );
    }

    /// The 32-bit GCM CTR counter wraps (NIST SP 800-38D §7.1) rather than panicking; the upper
    /// 96 bits of the counter block are untouched.
    #[test]
    fn incr32_wraps_at_u32_max() {
        let mut block = [0u8; 16];
        block[..12].copy_from_slice(&[0xaa; 12]);
        block[12..].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
        incr32(&mut block);
        assert_eq!(u32::from_be_bytes(block[12..16].try_into().unwrap()), 0);
        assert!(
            block[..12].iter().all(|&b| b == 0xaa),
            "high 96 bits unchanged"
        );
    }

    /// Poly1305 over an empty message: no blocks are absorbed, so the tag is exactly `s`
    /// (the high 16 key bytes). Exercises the zero-block path the RFC vectors don't.
    #[test]
    fn poly1305_empty_message_is_s() {
        let key = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        let tag = poly1305(key[..].try_into().unwrap(), b"");
        assert_eq!(tag.to_vec(), key[16..32].to_vec());
    }

    /// The test-only AEAD seal helpers are exact inverses of the RFC-verified `*_open` functions.
    #[test]
    fn aead_seal_open_roundtrips() {
        let pt = b"the quick brown fox jumps over the lazy dog (and then some more bytes)";
        let nonce = [0x07u8; 12];
        let aad = b"record-header-aad";
        let k16 = [0x11u8; 16];
        let k32 = [0x22u8; 32];

        let s = aes128_gcm_seal(&k16, &nonce, aad, pt);
        assert_eq!(
            aes128_gcm_open(&k16, &nonce, aad, &s).as_deref(),
            Some(&pt[..])
        );
        let s = aes256_gcm_seal(&k32, &nonce, aad, pt);
        assert_eq!(
            aes256_gcm_open(&k32, &nonce, aad, &s).as_deref(),
            Some(&pt[..])
        );
        let s = chacha20_poly1305_seal(&k32, &nonce, aad, pt);
        assert_eq!(
            chacha20_poly1305_open(&k32, &nonce, aad, &s).as_deref(),
            Some(&pt[..])
        );

        // A flipped ciphertext byte must fail authentication.
        let mut bad = aes256_gcm_seal(&k32, &nonce, aad, pt);
        bad[0] ^= 0x01;
        assert!(aes256_gcm_open(&k32, &nonce, aad, &bad).is_none());
    }

    // ── SHA-1 / HMAC-SHA1 (TLS 1.2 *_CBC_SHA suites) ─────────────────────────────

    /// SHA-1("abc") — FIPS 180-4 known answer; plus the empty-string KAT.
    #[test]
    fn sha1_fips180_kats() {
        assert_eq!(
            to_hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            to_hex(&sha1(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        // A two-block message (>56 bytes) exercises the multi-block padding.
        assert_eq!(
            to_hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    /// HMAC-SHA1, RFC 2202 Test Case 2 (key="Jefe").
    #[test]
    fn hmac_sha1_rfc2202_tc2() {
        let got = hmac_sha1(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(to_hex(&got), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    }

    // ── AES decryption + AES-CBC ─────────────────────────────────────────────────

    /// AES-128/256 single-block decryption: the inverse of the FIPS-197 C.1/C.3 encrypt vectors.
    #[test]
    fn aes_decrypt_fips197_inverse() {
        let key128 = hex("000102030405060708090a0b0c0d0e0f");
        let pt = hex("00112233445566778899aabbccddeeff");
        let ct128 = hex("69c4e0d86a7b0430d8cdb78070b4c55a");
        assert_eq!(
            Aes128::new(key128[..].try_into().unwrap())
                .decrypt_block(ct128[..].try_into().unwrap())
                .to_vec(),
            pt
        );
        let key256 = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let ct256 = hex("8ea2b7ca516745bfeafc49904b496089");
        assert_eq!(
            Aes256::new(key256[..].try_into().unwrap())
                .decrypt_block(ct256[..].try_into().unwrap())
                .to_vec(),
            pt
        );
    }

    /// AES-128-CBC decryption, NIST SP 800-38A §F.2.2 (two blocks).
    #[test]
    fn aes128_cbc_decrypt_sp80038a() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        let ct = hex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2");
        let expected = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        assert_eq!(
            aes128_cbc_decrypt(key[..].try_into().unwrap(), iv[..].try_into().unwrap(), &ct),
            Some(expected)
        );
    }

    /// AES-CBC encrypt↔decrypt round-trip (the test-only encrypt helper inverts decrypt).
    #[test]
    fn aes_cbc_roundtrips() {
        let iv = [0x24u8; 16];
        let pt: Vec<u8> = (0u8..48).collect(); // 3 blocks
        let k16 = [0x11u8; 16];
        let ct = aes128_cbc_encrypt(&k16, &iv, &pt);
        assert_eq!(aes128_cbc_decrypt(&k16, &iv, &ct), Some(pt.clone()));
        let k32 = [0x22u8; 32];
        let ct = aes256_cbc_encrypt(&k32, &iv, &pt);
        assert_eq!(aes256_cbc_decrypt(&k32, &iv, &ct), Some(pt));
    }

    /// TLS 1.2 PRF-SHA256, the canonical IETF TLS WG test vector (secret/seed = 16 bytes,
    /// label = "test label", first 100 output octets).
    #[test]
    fn tls12_prf_sha256_ietf_vector() {
        let secret = hex("9bbe436ba940f017b17652849a71db35");
        let seed = hex("a0ba9f936cda311827a6f796ffd5198c");
        let out = tls12_prf_sha256(&secret, b"test label", &seed, 100);
        assert_eq!(
            to_hex(&out),
            "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a\
             6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4\
             fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff7018\
             7347b66"
        );
    }
}
