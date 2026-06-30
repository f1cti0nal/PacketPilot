//! TLS record decryption from key-log secrets — TLS 1.3 and TLS 1.2.
//!
//! All three TLS 1.3 AEAD suites (`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
//! `TLS_CHACHA20_POLY1305_SHA256`) and the common TLS 1.2 AEAD + AES-CBC suites (ECDHE/DHE/RSA) over
//! the engine's vendored crypto (HKDF-SHA256/384, the TLS 1.2 PRF, AES-128/256-GCM/CBC,
//! ChaCha20-Poly1305, SHA-1/256/384 + HMACs; see [`crate::quic::crypto`], each RFC-vector-tested).
//!
//! * **TLS 1.3** ([`decrypt_flow_tls13`]): derive the AEAD key + iv from each direction's traffic
//!   secret via HKDF-Expand-Label (RFC 8446 §7.3), then decrypt `application_data` records — nonce =
//!   `iv XOR left-pad(seq)` (§5.3), AAD = the 5-byte record header (§5.2), then strip the inner
//!   content-type + zero padding (§5.4). A handshake→application epoch machine handles the key
//!   change. AES-128-GCM is cross-checked against the RFC 8448 §3 published trace end-to-end.
//! * **TLS 1.2** ([`decrypt_flow_tls12`]): expand the 48-byte master secret (key-log `CLIENT_RANDOM`)
//!   into the per-direction key block via the TLS 1.2 PRF (RFC 5246 §6.3), then decrypt records after
//!   the ChangeCipherSpec, sequence number per record. AEAD: nonce + AAD per RFC 5288 (GCM) /
//!   RFC 7905 (ChaCha20). AES-CBC (RFC 5246 §6.2.3.2): explicit IV, CBC-decrypt, strip the padding,
//!   and verify the MAC-then-encrypt HMAC.
//!
//! Pure compute, wasm-safe. [`decrypt_flow`] is the flow-level entry the wasm `decrypt_tls_flow`
//! export drives: it orients client/server from the ClientHello, then dispatches on the negotiated
//! version. TLS 1.0/1.1 and non-AEAD/non-CBC suites (CCM, RC4, NULL, …) return an unsupported
//! `reason`.

use base64::Engine as _;
use serde::Serialize;

use super::keylog::KeyLog;
use crate::quic::crypto::{
    aes128_cbc_decrypt, aes128_gcm_open, aes256_cbc_decrypt, aes256_gcm_open,
    chacha20_poly1305_open, hkdf_expand_label, hkdf_expand_label_sha384, hmac_sha1, hmac_sha256,
    hmac_sha384, tags_eq, tls12_prf_sha256, tls12_prf_sha384,
};

/// The TLS 1.3 cipher suites this build decrypts, all over vendored RFC-tested crypto.
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
/// TLS 1.3 wire version word (`supported_versions`-unmasked).
const TLS13_VERSION: u16 = 0x0304;
/// TLS 1.2 wire version word.
const TLS12_VERSION: u16 = 0x0303;
/// TLS `ContentType` values (RFC 8446 §5.1). The same registry tags both the outer record's
/// `opaque_type` and — once decrypted — the TLS 1.3 `TLSInnerPlaintext.type`, so `CT_HANDSHAKE`
/// is the correct constant for an inner handshake payload as well as an outer handshake record.
const CT_CHANGE_CIPHER_SPEC: u8 = 20;
const CT_HANDSHAKE: u8 = 22;
const CT_APPLICATION_DATA: u8 = 23;
/// Inner (TLSInnerPlaintext) handshake message type for `Finished` (RFC 8446 §4.4.4).
const HS_FINISHED: u8 = 20;
/// Cap on decrypted records returned per flow (the UI paginates).
const MAX_DECRYPTED_RECORDS: usize = 2000;
/// Cap on reassembled handshake-message bytes per direction while locating the `Finished` boundary.
/// A real TLS 1.3 flight (even with a large certificate chain) is well under this; the bound stops
/// a malicious peer from growing the reassembly buffer with an endless run of non-`Finished`
/// handshake records (defense in depth — the caller already caps the input at 4 MiB/direction).
const MAX_HANDSHAKE_BYTES: usize = 512 * 1024;

/// The negotiated AEAD + its derived per-direction key.
enum Tls13Aead {
    Aes128Gcm([u8; 16]),
    Aes256Gcm([u8; 32]),
    ChaCha20Poly1305([u8; 32]),
}

/// AEAD state for one direction of a TLS 1.3 connection.
pub(crate) struct Tls13Keys {
    aead: Tls13Aead,
    iv: [u8; 12],
    /// Record sequence number for this direction; starts at 0, increments per decrypted record.
    seq: u64,
}

impl Tls13Keys {
    /// Derive the per-direction AEAD key + iv for `cipher` from a TLS 1.3 traffic secret
    /// (RFC 8446 §7.3): 32-byte secret + HKDF-SHA256 for the SHA-256 suites, 48-byte secret +
    /// HKDF-SHA384 for `TLS_AES_256_GCM_SHA384`. Returns None on an unsupported suite or a secret
    /// whose length doesn't match the suite's hash.
    pub(crate) fn for_cipher(cipher: u16, secret: &[u8]) -> Option<Self> {
        let (aead, iv) = match cipher {
            TLS_AES_128_GCM_SHA256 => {
                let s: &[u8; 32] = secret.try_into().ok()?;
                let key: [u8; 16] = hkdf_expand_label(s, "key", 16).try_into().ok()?;
                let iv: [u8; 12] = hkdf_expand_label(s, "iv", 12).try_into().ok()?;
                (Tls13Aead::Aes128Gcm(key), iv)
            }
            TLS_CHACHA20_POLY1305_SHA256 => {
                let s: &[u8; 32] = secret.try_into().ok()?;
                let key: [u8; 32] = hkdf_expand_label(s, "key", 32).try_into().ok()?;
                let iv: [u8; 12] = hkdf_expand_label(s, "iv", 12).try_into().ok()?;
                (Tls13Aead::ChaCha20Poly1305(key), iv)
            }
            TLS_AES_256_GCM_SHA384 => {
                let s: &[u8; 48] = secret.try_into().ok()?;
                let key: [u8; 32] = hkdf_expand_label_sha384(s, "key", 32).try_into().ok()?;
                let iv: [u8; 12] = hkdf_expand_label_sha384(s, "iv", 12).try_into().ok()?;
                (Tls13Aead::Aes256Gcm(key), iv)
            }
            _ => return None,
        };
        Some(Tls13Keys { aead, iv, seq: 0 })
    }

    /// Back-compat convenience for the AES-128-GCM suite (used by the RFC 8448 trace test).
    #[cfg(test)]
    pub(crate) fn aes128_gcm(secret: &[u8]) -> Option<Self> {
        Self::for_cipher(TLS_AES_128_GCM_SHA256, secret)
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
        let nonce = self.nonce();
        let inner = match &self.aead {
            Tls13Aead::Aes128Gcm(k) => aes128_gcm_open(k, &nonce, header, body)?,
            Tls13Aead::Aes256Gcm(k) => aes256_gcm_open(k, &nonce, header, body)?,
            Tls13Aead::ChaCha20Poly1305(k) => chacha20_poly1305_open(k, &nonce, header, body)?,
        };
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

// ---------------------------------------------------------------------------------------------
// Flow-level decryption
// ---------------------------------------------------------------------------------------------

/// One decrypted TLS record surfaced to the UI.
#[derive(Debug, Clone, Serialize)]
pub struct TlsDecryptRecord {
    /// `"c2s"` (client→server, requests) or `"s2c"` (server→client, responses).
    pub direction: &'static str,
    /// The AEAD sequence number within the application epoch (starts at 0 per direction).
    pub seq: u64,
    /// TLS 1.3 inner content type (RFC 8446 §5.4): 23 application_data, 22 handshake, 21 alert.
    pub inner_type: u8,
    pub plaintext_len: usize,
    /// Base64 of the decrypted inner plaintext (may be binary — HTTP/2 frames, gzip, …).
    pub plaintext_b64: String,
}

/// The outcome of decrypting one TLS flow with a key-log.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TlsDecryptResult {
    /// True when the flow negotiated a suite this build can decrypt (TLS 1.3 + AES-128-GCM).
    pub supported: bool,
    /// True when the key-log carried traffic secrets for this session's ClientHello random.
    pub session_found: bool,
    /// Negotiated version word (`0x0304` = TLS 1.3), when a ServerHello was seen.
    pub version: Option<u16>,
    /// Negotiated cipher-suite word, when a ServerHello was seen.
    pub cipher: Option<u16>,
    /// Human cipher-suite name for the UI (e.g. `TLS_AES_128_GCM_SHA256`).
    pub cipher_name: Option<String>,
    /// Distinct TLS sessions in the supplied key-log (for the upload summary).
    pub keylog_sessions: usize,
    /// True when the record list hit [`MAX_DECRYPTED_RECORDS`] and was capped.
    pub truncated: bool,
    /// Why nothing decrypted, when `records` is empty (unsupported suite, no secret, …).
    pub reason: Option<String>,
    pub records: Vec<TlsDecryptRecord>,
}

impl TlsDecryptResult {
    fn unsupported(
        version: Option<u16>,
        cipher: Option<u16>,
        reason: &str,
        sessions: usize,
    ) -> Self {
        TlsDecryptResult {
            supported: false,
            version,
            cipher,
            cipher_name: cipher.map(super::cipher_label),
            keylog_sessions: sessions,
            reason: Some(reason.to_string()),
            ..Default::default()
        }
    }
}

/// Decrypt a single TLS flow from its two cleartext byte streams (`fwd` = query src→dst, `rev` =
/// the reverse) and a parsed key-log. Orients client/server from whichever stream carries the
/// ClientHello, so the result's `c2s`/`s2c` labels are always client-relative regardless of the
/// query's direction, then dispatches on the negotiated version to the TLS 1.3 or TLS 1.2 path
/// (both AEAD suites only). Unsupported versions/suites return `supported = false` with an
/// explaining `reason`. Pure compute, wasm-safe.
pub(crate) fn decrypt_flow(fwd: &[u8], rev: &[u8], keylog: &KeyLog) -> TlsDecryptResult {
    let sessions = keylog.session_count();
    if keylog.is_empty() {
        return TlsDecryptResult {
            supported: true,
            reason: Some("no key-log secrets loaded".to_string()),
            ..Default::default()
        };
    }

    // The client is whichever direction sent the ClientHello.
    let (client_buf, server_buf) = match find_client_random(fwd) {
        Some(_) => (fwd, rev),
        None if find_client_random(rev).is_some() => (rev, fwd),
        None => {
            return TlsDecryptResult {
                supported: true,
                keylog_sessions: sessions,
                reason: Some("no TLS ClientHello found in this flow".to_string()),
                ..Default::default()
            };
        }
    };
    let client_random = find_client_random(client_buf).expect("ClientHello present");

    let (version, cipher) = match super::negotiated_version_cipher(server_buf) {
        Some(vc) => vc,
        None => {
            return TlsDecryptResult {
                supported: true,
                keylog_sessions: sessions,
                reason: Some("no TLS ServerHello found in this flow".to_string()),
                ..Default::default()
            };
        }
    };
    match version {
        TLS13_VERSION => decrypt_flow_tls13(
            client_buf,
            server_buf,
            &client_random,
            cipher,
            keylog,
            sessions,
        ),
        TLS12_VERSION => decrypt_flow_tls12(
            client_buf,
            server_buf,
            &client_random,
            cipher,
            keylog,
            sessions,
        ),
        _ => TlsDecryptResult::unsupported(
            Some(version),
            Some(cipher),
            "key-log decryption supports TLS 1.2 and 1.3 only",
            sessions,
        ),
    }
}

/// TLS 1.3 branch of [`decrypt_flow`]: derive per-direction traffic keys from the key-log and run
/// the handshake→application epoch state machine over each direction.
fn decrypt_flow_tls13(
    client_buf: &[u8],
    server_buf: &[u8],
    client_random: &[u8; 32],
    cipher: u16,
    keylog: &KeyLog,
    sessions: usize,
) -> TlsDecryptResult {
    let version = TLS13_VERSION;
    if !matches!(
        cipher,
        TLS_AES_128_GCM_SHA256 | TLS_AES_256_GCM_SHA384 | TLS_CHACHA20_POLY1305_SHA256
    ) {
        return TlsDecryptResult::unsupported(
            Some(version),
            Some(cipher),
            &format!(
                "cipher suite {} not supported (TLS 1.3 AES-128-GCM / AES-256-GCM / \
                 ChaCha20-Poly1305 only)",
                super::cipher_label(cipher)
            ),
            sessions,
        );
    }

    let client_app = keylog.secret(client_random, "CLIENT_TRAFFIC_SECRET_0");
    let server_app = keylog.secret(client_random, "SERVER_TRAFFIC_SECRET_0");
    if client_app.is_none() && server_app.is_none() {
        return TlsDecryptResult {
            supported: true,
            session_found: false,
            version: Some(version),
            cipher: Some(cipher),
            cipher_name: Some(super::cipher_label(cipher)),
            keylog_sessions: sessions,
            reason: Some("key-log has no traffic secrets for this TLS session".to_string()),
            ..Default::default()
        };
    }

    let mut records: Vec<TlsDecryptRecord> = Vec::new();
    let mut truncated = false;
    decrypt_direction(
        client_buf,
        keylog.secret(client_random, "CLIENT_HANDSHAKE_TRAFFIC_SECRET"),
        client_app,
        cipher,
        "c2s",
        &mut records,
        &mut truncated,
    );
    decrypt_direction(
        server_buf,
        keylog.secret(client_random, "SERVER_HANDSHAKE_TRAFFIC_SECRET"),
        server_app,
        cipher,
        "s2c",
        &mut records,
        &mut truncated,
    );

    TlsDecryptResult {
        supported: true,
        session_found: true,
        version: Some(version),
        cipher: Some(cipher),
        cipher_name: Some(super::cipher_label(cipher)),
        keylog_sessions: sessions,
        truncated,
        reason: None,
        records,
    }
}

/// The record MAC hash of a TLS 1.2 CBC suite. The MAC key and digest are the same length.
#[derive(Clone, Copy)]
enum Tls12Mac {
    Sha1,
    Sha256,
    Sha384,
}

impl Tls12Mac {
    /// MAC key / digest length (RFC 2104): SHA-1 = 20, SHA-256 = 32, SHA-384 = 48.
    fn len(self) -> usize {
        match self {
            Tls12Mac::Sha1 => 20,
            Tls12Mac::Sha256 => 32,
            Tls12Mac::Sha384 => 48,
        }
    }

    /// HMAC under this hash.
    fn hmac(self, key: &[u8], msg: &[u8]) -> Vec<u8> {
        match self {
            Tls12Mac::Sha1 => hmac_sha1(key, msg).to_vec(),
            Tls12Mac::Sha256 => hmac_sha256(key, msg).to_vec(),
            Tls12Mac::Sha384 => hmac_sha384(key, msg).to_vec(),
        }
    }
}

/// The record-protection mode of a supported TLS 1.2 suite.
#[derive(Clone, Copy)]
enum Tls12Mode {
    AesGcm,
    ChaCha20Poly1305,
    /// AES-CBC with an HMAC record MAC (MAC-then-encrypt).
    Cbc(Tls12Mac),
}

/// Parameters for a supported TLS 1.2 cipher suite.
struct Tls12Params {
    mode: Tls12Mode,
    /// AES key length (16 / 32) or the ChaCha20 key length (32).
    enc_key_len: usize,
    /// "Implicit" write-IV length from the key block: 4 (GCM salt), 12 (ChaCha20 base), 0 (CBC —
    /// the IV is explicit per record).
    fixed_iv_len: usize,
    /// The suite's PRF hash is SHA-384 (the `_SHA384` suites), else SHA-256.
    sha384_prf: bool,
}

impl Tls12Params {
    /// MAC key length from the key block (0 for AEAD suites — they have no separate MAC key).
    fn mac_key_len(&self) -> usize {
        match self.mode {
            Tls12Mode::Cbc(mac) => mac.len(),
            _ => 0,
        }
    }
}

/// Map a TLS 1.2 cipher suite to its parameters, or `None` for an unsupported suite (CCM, RC4,
/// NULL, …). Covers the common ECDHE/DHE/RSA AES-GCM, ChaCha20-Poly1305, and AES-CBC suites.
fn tls12_params(cipher: u16) -> Option<Tls12Params> {
    use Tls12Mac::{Sha1, Sha256, Sha384};
    use Tls12Mode::{AesGcm, Cbc, ChaCha20Poly1305};
    let p = match cipher {
        // ── AEAD ──────────────────────────────────────────────────────────────
        // AES-128-GCM-SHA256: ECDHE-ECDSA / ECDHE-RSA / RSA / DHE-RSA.
        0xC02B | 0xC02F | 0x009C | 0x009E => mk(AesGcm, 16, 4, false),
        // AES-256-GCM-SHA384.
        0xC02C | 0xC030 | 0x009D | 0x009F => mk(AesGcm, 32, 4, true),
        // ChaCha20-Poly1305-SHA256 (RFC 7905): ECDHE-RSA / ECDHE-ECDSA / DHE-RSA.
        0xCCA8..=0xCCAA => mk(ChaCha20Poly1305, 32, 12, false),
        // ── AES-CBC (MAC-then-encrypt) ────────────────────────────────────────
        // AES-128-CBC + HMAC-SHA1: RSA / DHE-RSA / ECDHE-RSA / ECDHE-ECDSA.
        0x002F | 0x0033 | 0xC013 | 0xC009 => mk(Cbc(Sha1), 16, 0, false),
        // AES-256-CBC + HMAC-SHA1.
        0x0035 | 0x0039 | 0xC014 | 0xC00A => mk(Cbc(Sha1), 32, 0, false),
        // AES-128-CBC + HMAC-SHA256.
        0x003C | 0x0067 | 0xC027 | 0xC023 => mk(Cbc(Sha256), 16, 0, false),
        // AES-256-CBC + HMAC-SHA256.
        0x003D | 0x006B => mk(Cbc(Sha256), 32, 0, false),
        // AES-256-CBC + HMAC-SHA384 (PRF is SHA-384 too).
        0xC028 | 0xC024 => mk(Cbc(Sha384), 32, 0, true),
        _ => return None,
    };
    Some(p)
}

/// Small constructor to keep [`tls12_params`] readable.
fn mk(mode: Tls12Mode, enc_key_len: usize, fixed_iv_len: usize, sha384_prf: bool) -> Tls12Params {
    Tls12Params {
        mode,
        enc_key_len,
        fixed_iv_len,
        sha384_prf,
    }
}

/// TLS 1.2 branch of [`decrypt_flow`]: expand the key-log master secret into the per-direction key
/// block (RFC 5246 §6.3), then decrypt each direction's post-ChangeCipherSpec records. Unlike
/// TLS 1.3 there is no handshake/application key change — a single key per direction with the
/// sequence number incrementing per record.
fn decrypt_flow_tls12(
    client_buf: &[u8],
    server_buf: &[u8],
    client_random: &[u8; 32],
    cipher: u16,
    keylog: &KeyLog,
    sessions: usize,
) -> TlsDecryptResult {
    let version = TLS12_VERSION;
    let params = match tls12_params(cipher) {
        Some(p) => p,
        None => {
            return TlsDecryptResult::unsupported(
                Some(version),
                Some(cipher),
                &format!(
                    "cipher suite {} not supported (TLS 1.2 AES-GCM / AES-CBC / \
                     ChaCha20-Poly1305 only)",
                    super::cipher_label(cipher)
                ),
                sessions,
            );
        }
    };

    // TLS 1.2 derives everything from the 48-byte master secret (key-log `CLIENT_RANDOM` label).
    let master = match keylog.secret(client_random, "CLIENT_RANDOM") {
        Some(m) if m.len() == 48 => m,
        _ => {
            return TlsDecryptResult {
                supported: true,
                session_found: false,
                version: Some(version),
                cipher: Some(cipher),
                cipher_name: Some(super::cipher_label(cipher)),
                keylog_sessions: sessions,
                reason: Some(
                    "key-log has no master secret (CLIENT_RANDOM) for this TLS session".to_string(),
                ),
                ..Default::default()
            };
        }
    };
    let server_random = match find_server_random(server_buf) {
        Some(r) => r,
        None => {
            return TlsDecryptResult {
                supported: true,
                version: Some(version),
                cipher: Some(cipher),
                cipher_name: Some(super::cipher_label(cipher)),
                keylog_sessions: sessions,
                reason: Some("no TLS ServerHello random found in this flow".to_string()),
                ..Default::default()
            };
        }
    };

    // key_block = PRF(master, "key expansion", server_random || client_random). Layout (RFC 5246
    // §6.3): client/server MAC keys (CBC only — AEAD has none), then client/server write keys, then
    // client/server write IVs (the GCM salt / ChaCha20 base; CBC's IV is explicit per record).
    let mk_len = params.mac_key_len();
    let ek = params.enc_key_len;
    let iv = params.fixed_iv_len;
    let total = 2 * mk_len + 2 * ek + 2 * iv;
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(&server_random);
    seed[32..].copy_from_slice(client_random);
    let kb = if params.sha384_prf {
        tls12_prf_sha384(master, b"key expansion", &seed, total)
    } else {
        tls12_prf_sha256(master, b"key expansion", &seed, total)
    };
    let c_mac = &kb[0..mk_len];
    let s_mac = &kb[mk_len..2 * mk_len];
    let k0 = 2 * mk_len;
    let c_key = &kb[k0..k0 + ek];
    let s_key = &kb[k0 + ek..k0 + 2 * ek];
    let iv0 = k0 + 2 * ek;
    let c_iv = &kb[iv0..iv0 + iv];
    let s_iv = &kb[iv0 + iv..iv0 + 2 * iv];

    let mut records: Vec<TlsDecryptRecord> = Vec::new();
    let mut truncated = false;
    decrypt_direction_tls12(
        client_buf,
        &DirKeys {
            enc_key: c_key,
            mac_key: c_mac,
            write_iv: c_iv,
        },
        &params,
        "c2s",
        &mut records,
        &mut truncated,
    );
    decrypt_direction_tls12(
        server_buf,
        &DirKeys {
            enc_key: s_key,
            mac_key: s_mac,
            write_iv: s_iv,
        },
        &params,
        "s2c",
        &mut records,
        &mut truncated,
    );

    TlsDecryptResult {
        supported: true,
        session_found: true,
        version: Some(version),
        cipher: Some(cipher),
        cipher_name: Some(super::cipher_label(cipher)),
        keylog_sessions: sessions,
        truncated,
        reason: None,
        records,
    }
}

/// One direction's TLS 1.2 keys from the key block.
struct DirKeys<'a> {
    enc_key: &'a [u8],
    /// HMAC key (CBC suites only; empty for AEAD).
    mac_key: &'a [u8],
    /// Implicit write IV (GCM salt / ChaCha20 base; empty for CBC).
    write_iv: &'a [u8],
}

/// Decrypt one TLS 1.2 direction. Records are cleartext until the ChangeCipherSpec; every record
/// after it is protected under this direction's keys, with the record sequence number starting at 0
/// (the encrypted Finished) and incrementing per record. Only decrypted `application_data` (type
/// 23) is surfaced; the Finished/alerts advance the sequence but are not shown.
fn decrypt_direction_tls12(
    buf: &[u8],
    keys: &DirKeys,
    params: &Tls12Params,
    dir: &'static str,
    out: &mut Vec<TlsDecryptRecord>,
    truncated: &mut bool,
) {
    let mut seq: u64 = 0;
    let mut encrypted = false;
    for rec in tls_records(buf) {
        let ctype = rec[0];
        if !encrypted {
            if ctype == CT_CHANGE_CIPHER_SPEC {
                encrypted = true; // subsequent records use the negotiated keys, seq from 0
            }
            continue;
        }
        let version = [rec[1], rec[2]];
        let body = &rec[5..];
        let this_seq = seq;
        seq = seq.wrapping_add(1); // every received record advances the sequence number
        let decrypted = match params.mode {
            Tls12Mode::Cbc(mac) => tls12_open_cbc_record(
                keys.enc_key,
                keys.mac_key,
                mac,
                params.enc_key_len,
                this_seq,
                ctype,
                version,
                body,
            ),
            _ => tls12_open_record(
                keys.enc_key,
                keys.write_iv,
                params,
                this_seq,
                ctype,
                version,
                body,
            ),
        };
        let pt = match decrypted {
            Some(p) => p,
            None => continue,
        };
        if ctype == CT_APPLICATION_DATA {
            if out.len() >= MAX_DECRYPTED_RECORDS {
                *truncated = true;
                break;
            }
            out.push(TlsDecryptRecord {
                direction: dir,
                seq: this_seq,
                inner_type: ctype,
                plaintext_len: pt.len(),
                plaintext_b64: base64::engine::general_purpose::STANDARD.encode(&pt),
            });
        }
    }
}

/// Decrypt one TLS 1.2 AEAD record `body` (the bytes after the 5-byte header). Builds the
/// per-record nonce and the AEAD additional-data per RFC 5246 §6.2.3.3 / RFC 5288 / RFC 7905:
/// `additional_data = seq_num(8) || type(1) || version(2) || plaintext_len(2)`.
fn tls12_open_record(
    key: &[u8],
    write_iv: &[u8],
    params: &Tls12Params,
    seq: u64,
    ctype: u8,
    version: [u8; 2],
    body: &[u8],
) -> Option<Vec<u8>> {
    let mut nonce = [0u8; 12];
    let ct_and_tag: &[u8] = match params.mode {
        Tls12Mode::AesGcm => {
            // GenericAEADCipher: explicit_nonce(8) || ciphertext || tag(16). The 12-byte nonce is
            // the 4-byte implicit salt (write_iv) followed by the wire explicit nonce.
            if body.len() < 8 + 16 || write_iv.len() != 4 {
                return None;
            }
            nonce[..4].copy_from_slice(write_iv);
            nonce[4..].copy_from_slice(&body[..8]);
            &body[8..]
        }
        Tls12Mode::ChaCha20Poly1305 => {
            // RFC 7905: no explicit nonce on the wire; nonce = write_iv XOR left-padded seq_num.
            if body.len() < 16 || write_iv.len() != 12 {
                return None;
            }
            nonce.copy_from_slice(write_iv);
            let s = seq.to_be_bytes();
            for i in 0..8 {
                nonce[4 + i] ^= s[i];
            }
            body
        }
        Tls12Mode::Cbc(_) => return None, // handled by tls12_open_cbc_record
    };

    let pt_len = ct_and_tag.len() - 16;
    let mut aad = Vec::with_capacity(13);
    aad.extend_from_slice(&seq.to_be_bytes());
    aad.push(ctype);
    aad.extend_from_slice(&version);
    aad.extend_from_slice(&(pt_len as u16).to_be_bytes());

    match params.mode {
        Tls12Mode::AesGcm if params.enc_key_len == 16 => {
            aes128_gcm_open(key.try_into().ok()?, &nonce, &aad, ct_and_tag)
        }
        Tls12Mode::AesGcm => aes256_gcm_open(key.try_into().ok()?, &nonce, &aad, ct_and_tag),
        Tls12Mode::ChaCha20Poly1305 => {
            chacha20_poly1305_open(key.try_into().ok()?, &nonce, &aad, ct_and_tag)
        }
        Tls12Mode::Cbc(_) => None,
    }
}

/// Decrypt one TLS 1.2 AES-CBC record `body` (MAC-then-encrypt, RFC 5246 §6.2.3.2). The record is
/// `explicit_IV(16) || AES-CBC(content || MAC || padding)`. After CBC decryption we strip the
/// padding (each byte = `padding_length`), split off the trailing `mac_len`-byte HMAC, verify it
/// over `seq || type || version || u16(content_len) || content`, and return the content. Any
/// padding or MAC failure returns `None` (the caller still advances the sequence number).
#[allow(clippy::too_many_arguments)]
fn tls12_open_cbc_record(
    enc_key: &[u8],
    mac_key: &[u8],
    mac: Tls12Mac,
    enc_key_len: usize,
    seq: u64,
    ctype: u8,
    version: [u8; 2],
    body: &[u8],
) -> Option<Vec<u8>> {
    // body = explicit_IV(16) || ciphertext (a non-zero multiple of the 16-byte AES block).
    if body.len() < 32 || (body.len() - 16) % 16 != 0 {
        return None;
    }
    let iv: &[u8; 16] = body[..16].try_into().ok()?;
    let ct = &body[16..];
    let plain = if enc_key_len == 16 {
        aes128_cbc_decrypt(enc_key.try_into().ok()?, iv, ct)?
    } else {
        aes256_cbc_decrypt(enc_key.try_into().ok()?, iv, ct)?
    };

    // Strip padding: the last byte is padding_length, and the trailing padding_length+1 bytes must
    // all equal it (RFC 5246 §6.2.3.2).
    let pad_len = *plain.last()? as usize;
    if pad_len + 1 > plain.len() {
        return None;
    }
    let unpadded = plain.len() - (pad_len + 1);
    if plain[unpadded..].iter().any(|&b| b as usize != pad_len) {
        return None;
    }

    // Split content || MAC, then verify the MAC over the TLS 1.2 MAC input.
    let mac_len = mac.len();
    if unpadded < mac_len {
        return None;
    }
    let content_len = unpadded - mac_len;
    let content = &plain[..content_len];
    let mac_recv = &plain[content_len..unpadded];
    let mut mac_input = Vec::with_capacity(13 + content_len);
    mac_input.extend_from_slice(&seq.to_be_bytes());
    mac_input.push(ctype);
    mac_input.extend_from_slice(&version);
    mac_input.extend_from_slice(&(content_len as u16).to_be_bytes());
    mac_input.extend_from_slice(content);
    if !tags_eq(&mac.hmac(mac_key, &mac_input), mac_recv) {
        return None;
    }
    Some(content.to_vec())
}

/// Decrypt one direction's record stream. TLS 1.3 sends the post-ServerHello handshake (and the
/// client's Finished) under the *handshake* traffic secret, then application data under the
/// *application* traffic secret with the AEAD sequence reset to 0 — so we must walk the handshake
/// epoch first to find the boundary. We decrypt handshake records with `hs_secret`, reassemble the
/// inner handshake messages, and the moment a `Finished` appears the *next* `application_data`
/// record switches to `app_secret` at seq 0. If `hs_secret` is absent, we start in the application
/// epoch and rely on AEAD authentication to skip the (undecryptable) handshake records without
/// advancing the application sequence — `open_next` only advances on success.
fn decrypt_direction(
    buf: &[u8],
    hs_secret: Option<&[u8]>,
    app_secret: Option<&[u8]>,
    cipher: u16,
    dir: &'static str,
    out: &mut Vec<TlsDecryptRecord>,
    truncated: &mut bool,
) {
    let mut hs_keys = hs_secret.and_then(|s| Tls13Keys::for_cipher(cipher, s));
    let mut app_keys = app_secret.and_then(|s| Tls13Keys::for_cipher(cipher, s));
    let mut in_app = hs_keys.is_none();
    let mut hs_msgs: Vec<u8> = Vec::new();
    let mut hs_scan = 0usize; // offset of the next unparsed handshake message in `hs_msgs`
    let mut switch_next = false;

    for rec in tls_records(buf) {
        // Only application_data records are AEAD-protected; the plaintext ServerHello/ClientHello
        // (22), ChangeCipherSpec (20), and any cleartext alert are skipped and never counted.
        if rec[0] != CT_APPLICATION_DATA {
            debug_assert!(
                rec[0] == CT_HANDSHAKE || rec[0] == CT_CHANGE_CIPHER_SPEC || rec[0] == 21
            );
            continue;
        }
        if switch_next {
            in_app = true;
            switch_next = false;
        }

        if !in_app {
            if let Some(keys) = hs_keys.as_mut() {
                if let Some((content, inner)) = keys.open_next(rec) {
                    if inner == CT_HANDSHAKE {
                        if hs_msgs.len().saturating_add(content.len()) > MAX_HANDSHAKE_BYTES {
                            break; // runaway handshake with no Finished — give up on this direction
                        }
                        hs_msgs.extend_from_slice(&content);
                        if scan_for_finished(&hs_msgs, &mut hs_scan) {
                            switch_next = true; // next application_data record is the app epoch
                        }
                    }
                }
            }
            continue;
        }

        if out.len() >= MAX_DECRYPTED_RECORDS {
            *truncated = true;
            break;
        }
        if let Some(keys) = app_keys.as_mut() {
            let seq = keys.seq;
            if let Some((content, inner)) = keys.open_next(rec) {
                out.push(TlsDecryptRecord {
                    direction: dir,
                    seq,
                    inner_type: inner,
                    plaintext_len: content.len(),
                    plaintext_b64: base64::engine::general_purpose::STANDARD.encode(&content),
                });
            }
        }
    }
}

/// Split a cleartext byte stream into whole TLS records (`type(1) version(2) length(2) body`),
/// stopping at the first truncated record. Each returned slice includes its 5-byte header.
fn tls_records(buf: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 5 <= buf.len() {
        let len = ((buf[pos + 3] as usize) << 8) | buf[pos + 4] as usize;
        let end = match (pos + 5).checked_add(len) {
            Some(e) => e,
            None => break,
        };
        if end > buf.len() {
            break;
        }
        out.push(&buf[pos..end]);
        pos = end;
    }
    out
}

/// The 32-byte random from the first handshake message of type `want` in `buf`, if any. Both
/// ClientHello (type 1) and ServerHello (type 2) place the random right after the 4-byte handshake
/// header + 2-byte legacy_version. Layout: record-hdr(5) handshake-hdr(4) version(2) random(32) —
/// random at byte 11 of the record (offset 6 within the handshake message).
fn find_hs_random(buf: &[u8], want: u8) -> Option<[u8; 32]> {
    for rec in tls_records(buf) {
        if rec[0] != CT_HANDSHAKE {
            continue;
        }
        let hs = &rec[5..];
        if hs.first() == Some(&want) && hs.len() >= 38 {
            return hs[6..38].try_into().ok();
        }
    }
    None
}

/// The ClientHello random (key-log lookup key).
fn find_client_random(buf: &[u8]) -> Option<[u8; 32]> {
    find_hs_random(buf, 1)
}

/// The ServerHello random (TLS 1.2 key-block derivation seed).
fn find_server_random(buf: &[u8]) -> Option<[u8; 32]> {
    find_hs_random(buf, 2)
}

/// Advance `*pos` over complete handshake messages in the reassembled stream `msgs`, returning
/// true once a `Finished` (type 20) header is reached — the last message of a TLS 1.3 flight,
/// marking the handshake→application key change. Earlier messages (EncryptedExtensions / Certificate
/// / CertificateVerify) are skipped; a partially-arrived trailing message leaves `*pos` at its start
/// so the next call resumes there. Incremental (scans only new bytes), so repeated calls over a
/// growing buffer stay O(total) rather than O(total²).
fn scan_for_finished(msgs: &[u8], pos: &mut usize) -> bool {
    while *pos + 4 <= msgs.len() {
        if msgs[*pos] == HS_FINISHED {
            return true;
        }
        let mlen = ((msgs[*pos + 1] as usize) << 16)
            | ((msgs[*pos + 2] as usize) << 8)
            | msgs[*pos + 3] as usize;
        match (*pos + 4).checked_add(mlen) {
            Some(end) if end <= msgs.len() => *pos = end,
            _ => break, // message not fully arrived yet — resume here next time
        }
    }
    false
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
        let key = match &keys.aead {
            Tls13Aead::Aes128Gcm(k) => k.to_vec(),
            _ => panic!("expected AES-128-GCM AEAD"),
        };
        assert_eq!(
            key,
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

    // ── flow-level decryption ────────────────────────────────────────────────────

    /// The RFC 8448 §3 client app-data secret + record (also used by the open_next test above).
    fn rfc_client_secret() -> Vec<u8> {
        hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
    }
    fn rfc_app_record() -> Vec<u8> {
        hex(
            "1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f2b\
             9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae63aee\
             bb21694915e4",
        )
    }

    /// A minimal cleartext ClientHello record carrying `random` (one cipher suite, no extensions).
    fn client_hello_record(random: &[u8; 32]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03]; // client_version (legacy TLS 1.2)
        body.extend_from_slice(random);
        body.push(0x00); // session_id length
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites: len 2 + TLS_AES_128_GCM
        body.extend_from_slice(&[0x01, 0x00]); // compression_methods: len 1 + null
        body.extend_from_slice(&[0x00, 0x00]); // extensions: length 0
        let hs_len = body.len();
        let mut hs = vec![1u8, (hs_len >> 16) as u8, (hs_len >> 8) as u8, hs_len as u8];
        hs.extend_from_slice(&body);
        let mut rec = vec![22u8, 0x03, 0x03, (hs.len() >> 8) as u8, hs.len() as u8];
        rec.extend_from_slice(&hs);
        rec
    }

    /// A TLS 1.3 ServerHello record (legacy 0x0303 + supported_versions 0x0304 + the given cipher).
    fn server_hello_record(cipher: u16) -> Vec<u8> {
        crate::tls::testcert::server_hello(0x0303, cipher, Some(0x0304))
    }

    fn keylog_for(client_random: &[u8; 32], label: &str, secret: &[u8]) -> KeyLog {
        let cr: String = client_random.iter().map(|b| format!("{b:02x}")).collect();
        let sec: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        KeyLog::parse(&format!("{label} {cr} {sec}\n"))
    }

    #[test]
    fn tls_records_splits_and_stops_at_truncation() {
        let mut buf = vec![23, 3, 3, 0, 2, 0xaa, 0xbb]; // one 2-byte record
        buf.extend_from_slice(&[23, 3, 3, 0, 4, 1, 2, 3]); // truncated (claims 4, has 3) → dropped
        let recs = tls_records(&buf);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0], &[23, 3, 3, 0, 2, 0xaa, 0xbb]);
    }

    #[test]
    fn find_client_random_extracts_from_clienthello() {
        let r = [0x5a; 32];
        let rec = client_hello_record(&r);
        assert_eq!(find_client_random(&rec), Some(r));
        // A ServerHello (handshake type 2) is not a ClientHello.
        assert_eq!(find_client_random(&server_hello_record(0x1301)), None);
    }

    #[test]
    fn scan_for_finished_walks_messages_incrementally() {
        // EncryptedExtensions (8, len 2) then Finished (20, len 32).
        let mut msgs = vec![8u8, 0, 0, 2, 0xaa, 0xbb];
        msgs.extend_from_slice(&[20u8, 0, 0, 32]);
        msgs.extend_from_slice(&[0u8; 32]);
        let mut pos = 0usize;
        assert!(scan_for_finished(&msgs, &mut pos));
        // Only EncryptedExtensions so far → not yet, and `pos` advances past it (no re-walk).
        let mut p2 = 0usize;
        assert!(!scan_for_finished(&[8u8, 0, 0, 2, 0xaa, 0xbb], &mut p2));
        assert_eq!(p2, 6, "scan position advances past the complete message");
    }

    /// End-to-end through `decrypt_flow` using the RFC 8448 vector: a client stream of
    /// [ClientHello][app-data record], a TLS 1.3 ServerHello, and a key-log carrying only the
    /// client application secret (no handshake secret → the app epoch starts immediately).
    #[test]
    fn decrypt_flow_decrypts_rfc8448_app_record() {
        let random = [0xab; 32];
        let mut client_buf = client_hello_record(&random);
        client_buf.extend_from_slice(&rfc_app_record());
        let server_buf = server_hello_record(0x1301);
        let keylog = keylog_for(&random, "CLIENT_TRAFFIC_SECRET_0", &rfc_client_secret());

        let res = decrypt_flow(&client_buf, &server_buf, &keylog);
        assert!(res.supported && res.session_found, "{res:?}");
        assert_eq!(res.cipher, Some(0x1301));
        assert_eq!(res.records.len(), 1);
        let rec = &res.records[0];
        assert_eq!(rec.direction, "c2s");
        assert_eq!(rec.seq, 0);
        assert_eq!(rec.inner_type, 0x17); // application_data
        assert_eq!(rec.plaintext_len, 50);
        let pt = base64::engine::general_purpose::STANDARD
            .decode(&rec.plaintext_b64)
            .unwrap();
        assert_eq!(pt, (0u8..=0x31).collect::<Vec<u8>>());
    }

    /// Orientation is client-relative: swapping the two streams still labels the request `c2s`.
    #[test]
    fn decrypt_flow_orients_regardless_of_query_direction() {
        let random = [0xab; 32];
        let mut client_buf = client_hello_record(&random);
        client_buf.extend_from_slice(&rfc_app_record());
        let server_buf = server_hello_record(0x1301);
        let keylog = keylog_for(&random, "CLIENT_TRAFFIC_SECRET_0", &rfc_client_secret());

        // Pass server stream as `fwd`, client as `rev` — result must be identical.
        let res = decrypt_flow(&server_buf, &client_buf, &keylog);
        assert_eq!(res.records.len(), 1);
        assert_eq!(res.records[0].direction, "c2s");
    }

    #[test]
    fn decrypt_flow_reports_unsupported_cipher() {
        let random = [0x11; 32];
        let client_buf = client_hello_record(&random);
        let server_buf = server_hello_record(0x1304); // TLS_AES_128_CCM_SHA256 (not supported)
        let keylog = keylog_for(&random, "CLIENT_TRAFFIC_SECRET_0", &[0u8; 32]);

        let res = decrypt_flow(&client_buf, &server_buf, &keylog);
        assert!(!res.supported);
        assert_eq!(res.cipher, Some(0x1304));
        assert!(res.records.is_empty());
        assert!(res.reason.unwrap().contains("not supported"));
    }

    /// The AES-256-GCM (SHA-384) and ChaCha20-Poly1305 suites now pass the gate: a flow that
    /// negotiates them is `supported` (only the per-session secret is missing here).
    #[test]
    fn decrypt_flow_accepts_aes256_and_chacha20_suites() {
        for cipher in [0x1302u16, 0x1303u16] {
            let random = [0x33; 32];
            let client_buf = client_hello_record(&random);
            let server_buf = server_hello_record(cipher);
            // No secret for this session → supported, but session_found = false (not "unsupported").
            let keylog = keylog_for(&[0x99; 32], "CLIENT_TRAFFIC_SECRET_0", &[0u8; 32]);
            let res = decrypt_flow(&client_buf, &server_buf, &keylog);
            assert!(res.supported, "cipher {cipher:#06x} must be supported");
            assert!(!res.session_found);
            assert_eq!(res.cipher, Some(cipher));
        }
    }

    /// `Tls13Keys::for_cipher` builds the right AEAD and enforces the suite's secret length.
    #[test]
    fn for_cipher_dispatch_and_secret_length() {
        assert!(Tls13Keys::for_cipher(0x1301, &[0u8; 32]).is_some()); // AES-128-GCM-SHA256
        assert!(Tls13Keys::for_cipher(0x1303, &[0u8; 32]).is_some()); // ChaCha20-Poly1305-SHA256
        assert!(Tls13Keys::for_cipher(0x1302, &[0u8; 48]).is_some()); // AES-256-GCM-SHA384 (48 B)
        assert!(Tls13Keys::for_cipher(0x1302, &[0u8; 32]).is_none()); // wrong length for SHA-384
        assert!(Tls13Keys::for_cipher(0x1301, &[0u8; 48]).is_none()); // wrong length for SHA-256
        assert!(Tls13Keys::for_cipher(0x1304, &[0u8; 32]).is_none()); // unsupported suite
    }

    #[test]
    fn decrypt_flow_no_secret_for_session() {
        let random = [0x22; 32];
        let client_buf = client_hello_record(&random);
        let server_buf = server_hello_record(0x1301);
        // Key-log has a secret for a *different* ClientHello random.
        let keylog = keylog_for(&[0x99; 32], "CLIENT_TRAFFIC_SECRET_0", &[0u8; 32]);

        let res = decrypt_flow(&client_buf, &server_buf, &keylog);
        assert!(res.supported && !res.session_found);
        assert!(res.records.is_empty());
        assert!(res.reason.unwrap().contains("no traffic secrets"));
    }

    #[test]
    fn decrypt_flow_empty_keylog() {
        let res = decrypt_flow(&[], &[], &KeyLog::parse(""));
        assert!(res.supported && !res.session_found);
        assert!(res.reason.unwrap().contains("no key-log"));
    }

    // ── TLS 1.2 ──────────────────────────────────────────────────────────────────

    use crate::quic::crypto::{
        aes128_gcm_seal, aes256_gcm_seal, chacha20_poly1305_seal, tls12_prf_sha256,
        tls12_prf_sha384,
    };

    /// A TLS 1.2 ServerHello record carrying `server_random` and negotiating `cipher` (legacy
    /// version 0x0303, no extensions — so the parser reports TLS 1.2).
    fn tls12_server_hello(server_random: &[u8; 32], cipher: u16) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(server_random);
        body.push(0x00); // session_id length
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(0x00); // compression
        let mut hs = vec![
            2u8,
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ];
        hs.extend_from_slice(&body);
        let mut rec = vec![22u8, 0x03, 0x03, (hs.len() >> 8) as u8, hs.len() as u8];
        rec.extend_from_slice(&hs);
        rec
    }

    fn ccs_record() -> Vec<u8> {
        vec![20, 0x03, 0x03, 0, 1, 1] // ChangeCipherSpec
    }

    fn tls12_aad(seq: u64, ctype: u8, pt_len: usize) -> Vec<u8> {
        let mut aad = Vec::with_capacity(13);
        aad.extend_from_slice(&seq.to_be_bytes());
        aad.push(ctype);
        aad.extend_from_slice(&[0x03, 0x03]);
        aad.extend_from_slice(&(pt_len as u16).to_be_bytes());
        aad
    }

    /// Build a sealed TLS 1.2 GCM record (`explicit_nonce(8) || ct || tag`).
    fn tls12_gcm_record(ctype: u8, seq: u64, key: &[u8], iv4: &[u8], pt: &[u8]) -> Vec<u8> {
        let explicit = seq.to_be_bytes();
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(iv4);
        nonce[4..].copy_from_slice(&explicit);
        let aad = tls12_aad(seq, ctype, pt.len());
        let sealed = if key.len() == 16 {
            aes128_gcm_seal(key.try_into().unwrap(), &nonce, &aad, pt)
        } else {
            aes256_gcm_seal(key.try_into().unwrap(), &nonce, &aad, pt)
        };
        let mut frag = explicit.to_vec();
        frag.extend_from_slice(&sealed);
        let mut rec = vec![ctype, 0x03, 0x03, (frag.len() >> 8) as u8, frag.len() as u8];
        rec.extend_from_slice(&frag);
        rec
    }

    /// Build a sealed TLS 1.2 ChaCha20-Poly1305 record (RFC 7905: `ct || tag`, no explicit nonce).
    fn tls12_chacha_record(ctype: u8, seq: u64, key: &[u8; 32], iv12: &[u8], pt: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(iv12);
        let s = seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= s[i];
        }
        let aad = tls12_aad(seq, ctype, pt.len());
        let sealed = chacha20_poly1305_seal(key, &nonce, &aad, pt);
        let mut rec = vec![
            ctype,
            0x03,
            0x03,
            (sealed.len() >> 8) as u8,
            sealed.len() as u8,
        ];
        rec.extend_from_slice(&sealed);
        rec
    }

    /// AES-128-GCM-SHA256 (cipher 0xC02F): the PRF-SHA256 key block + per-record GCM nonce/AAD/seq
    /// path, end-to-end through `decrypt_flow`. The encrypted Finished (seq 0) advances the
    /// sequence; the application_data (seq 1) is surfaced.
    #[test]
    fn decrypt_flow_tls12_aes128_gcm() {
        let client_random = [0x11u8; 32];
        let server_random = [0x22u8; 32];
        let master = [0x33u8; 48];
        let cipher = 0xC02Fu16;

        let mut seed = Vec::new();
        seed.extend_from_slice(&server_random);
        seed.extend_from_slice(&client_random);
        let kb = tls12_prf_sha256(&master, b"key expansion", &seed, 40); // 2*16 key + 2*4 iv
        let (c_key, s_key) = (&kb[0..16], &kb[16..32]);
        let (c_iv, s_iv) = (&kb[32..36], &kb[36..40]);

        let mut client_buf = client_hello_record(&client_random);
        client_buf.extend_from_slice(&ccs_record());
        client_buf.extend_from_slice(&tls12_gcm_record(
            22,
            0,
            c_key,
            c_iv,
            b"\x14\x00\x00\x0cFINISHEDxx",
        ));
        client_buf.extend_from_slice(&tls12_gcm_record(
            23,
            1,
            c_key,
            c_iv,
            b"GET /secret HTTP/1.1\r\n",
        ));

        let mut server_buf = tls12_server_hello(&server_random, cipher);
        server_buf.extend_from_slice(&ccs_record());
        server_buf.extend_from_slice(&tls12_gcm_record(
            22,
            0,
            s_key,
            s_iv,
            b"\x14\x00\x00\x0cFINISHEDxx",
        ));
        server_buf.extend_from_slice(&tls12_gcm_record(
            23,
            1,
            s_key,
            s_iv,
            b"HTTP/1.1 200 OK\r\nsecret",
        ));

        let keylog = keylog_for(&client_random, "CLIENT_RANDOM", &master);
        let res = decrypt_flow(&client_buf, &server_buf, &keylog);
        assert!(res.supported && res.session_found, "{res:?}");
        assert_eq!(res.version, Some(0x0303));
        assert_eq!(res.records.len(), 2, "{:?}", res.records);

        let c2s = res.records.iter().find(|r| r.direction == "c2s").unwrap();
        assert_eq!(c2s.seq, 1, "app data is the 2nd encrypted record");
        let c2s_pt = base64::engine::general_purpose::STANDARD
            .decode(&c2s.plaintext_b64)
            .unwrap();
        assert_eq!(c2s_pt, b"GET /secret HTTP/1.1\r\n");
        let s2c = res.records.iter().find(|r| r.direction == "s2c").unwrap();
        let s2c_pt = base64::engine::general_purpose::STANDARD
            .decode(&s2c.plaintext_b64)
            .unwrap();
        assert_eq!(s2c_pt, b"HTTP/1.1 200 OK\r\nsecret");
    }

    /// AES-256-GCM-SHA384 (cipher 0xC030): exercises the PRF-SHA384 key-block path + AES-256-GCM.
    #[test]
    fn decrypt_flow_tls12_aes256_gcm_sha384() {
        let client_random = [0x44u8; 32];
        let server_random = [0x55u8; 32];
        let master = [0x66u8; 48];
        let cipher = 0xC030u16;

        let mut seed = Vec::new();
        seed.extend_from_slice(&server_random);
        seed.extend_from_slice(&client_random);
        let kb = tls12_prf_sha384(&master, b"key expansion", &seed, 72); // 2*32 key + 2*4 iv
        let (c_key, s_key) = (&kb[0..32], &kb[32..64]);
        let (c_iv, s_iv) = (&kb[64..68], &kb[68..72]);

        // Exercise both directions (each uses its own write key/IV from the key block).
        let mut client_buf = client_hello_record(&client_random);
        client_buf.extend_from_slice(&ccs_record());
        client_buf.extend_from_slice(&tls12_gcm_record(
            23,
            0,
            c_key,
            c_iv,
            b"client AES-256 request",
        ));

        let mut server_buf = tls12_server_hello(&server_random, cipher);
        server_buf.extend_from_slice(&ccs_record());
        server_buf.extend_from_slice(&tls12_gcm_record(
            23,
            0,
            s_key,
            s_iv,
            b"server AES-256 response",
        ));

        let keylog = keylog_for(&client_random, "CLIENT_RANDOM", &master);
        let res = decrypt_flow(&client_buf, &server_buf, &keylog);
        assert!(res.supported && res.session_found, "{res:?}");
        assert_eq!(res.records.len(), 2, "{:?}", res.records);
        let c2s = res.records.iter().find(|r| r.direction == "c2s").unwrap();
        let s2c = res.records.iter().find(|r| r.direction == "s2c").unwrap();
        let dec = |r: &TlsDecryptRecord| {
            base64::engine::general_purpose::STANDARD
                .decode(&r.plaintext_b64)
                .unwrap()
        };
        assert_eq!(dec(c2s), b"client AES-256 request");
        assert_eq!(dec(s2c), b"server AES-256 response");
    }

    /// ChaCha20-Poly1305-SHA256 (cipher 0xCCA8, RFC 7905): nonce = write_iv XOR seq, no explicit
    /// nonce on the wire.
    #[test]
    fn decrypt_flow_tls12_chacha20() {
        let client_random = [0x77u8; 32];
        let server_random = [0x88u8; 32];
        let master = [0x99u8; 48];
        let cipher = 0xCCA8u16;

        let mut seed = Vec::new();
        seed.extend_from_slice(&server_random);
        seed.extend_from_slice(&client_random);
        let kb = tls12_prf_sha256(&master, b"key expansion", &seed, 88); // 2*32 key + 2*12 iv
        let s_key: &[u8; 32] = kb[32..64].try_into().unwrap();
        let s_iv = &kb[64 + 12..88];

        let mut server_buf = tls12_server_hello(&server_random, cipher);
        server_buf.extend_from_slice(&ccs_record());
        server_buf.extend_from_slice(&tls12_chacha_record(
            23,
            0,
            s_key,
            s_iv,
            b"chacha20 secret response",
        ));

        let client_buf = client_hello_record(&client_random);
        let keylog = keylog_for(&client_random, "CLIENT_RANDOM", &master);
        let res = decrypt_flow(&client_buf, &server_buf, &keylog);
        assert!(res.supported && res.session_found, "{res:?}");
        assert_eq!(res.records.len(), 1);
        let pt = base64::engine::general_purpose::STANDARD
            .decode(&res.records[0].plaintext_b64)
            .unwrap();
        assert_eq!(pt, b"chacha20 secret response");
    }

    use crate::quic::crypto::{aes128_cbc_encrypt, aes256_cbc_encrypt};

    /// Build a sealed TLS 1.2 AES-CBC record (`explicit_IV(16) || AES-CBC(content || MAC ||
    /// padding)`, MAC-then-encrypt). The inverse of `tls12_open_cbc_record`.
    fn tls12_cbc_record(
        ctype: u8,
        seq: u64,
        enc_key: &[u8],
        mac_key: &[u8],
        mac: Tls12Mac,
        content: &[u8],
    ) -> Vec<u8> {
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&seq.to_be_bytes());
        mac_input.push(ctype);
        mac_input.extend_from_slice(&[0x03, 0x03]);
        mac_input.extend_from_slice(&(content.len() as u16).to_be_bytes());
        mac_input.extend_from_slice(content);
        let tag = mac.hmac(mac_key, &mac_input);

        let mut plain = content.to_vec();
        plain.extend_from_slice(&tag);
        // Pad to a 16-byte boundary: pad_total bytes each holding (pad_total - 1).
        let pad_total = 16 - (plain.len() % 16);
        let pad_len = (pad_total - 1) as u8;
        plain.extend(std::iter::repeat(pad_len).take(pad_total));

        let iv = [0x5au8; 16];
        let ct = if enc_key.len() == 16 {
            aes128_cbc_encrypt(enc_key.try_into().unwrap(), &iv, &plain)
        } else {
            aes256_cbc_encrypt(enc_key.try_into().unwrap(), &iv, &plain)
        };
        let mut frag = iv.to_vec();
        frag.extend_from_slice(&ct);
        let mut rec = vec![ctype, 0x03, 0x03, (frag.len() >> 8) as u8, frag.len() as u8];
        rec.extend_from_slice(&frag);
        rec
    }

    /// AES-128-CBC + HMAC-SHA1 (cipher 0xC013): the key block now carries MAC keys, and each record
    /// is CBC-decrypted, unpadded, and MAC-verified. Exercises both directions.
    #[test]
    fn decrypt_flow_tls12_aes128_cbc_sha1() {
        let client_random = [0xa1u8; 32];
        let server_random = [0xa2u8; 32];
        let master = [0xa3u8; 48];
        let cipher = 0xC013u16;

        let mut seed = Vec::new();
        seed.extend_from_slice(&server_random);
        seed.extend_from_slice(&client_random);
        // CBC-SHA1: mac_len 20, enc 16 → total = 2*20 + 2*16 = 72. Layout: c_mac, s_mac, c_key, s_key.
        let kb = tls12_prf_sha256(&master, b"key expansion", &seed, 72);
        let (c_mac, s_mac) = (&kb[0..20], &kb[20..40]);
        let (c_key, s_key) = (&kb[40..56], &kb[56..72]);

        let mut client_buf = client_hello_record(&client_random);
        client_buf.extend_from_slice(&ccs_record());
        client_buf.extend_from_slice(&tls12_cbc_record(
            22,
            0,
            c_key,
            c_mac,
            Tls12Mac::Sha1,
            b"FIN",
        ));
        client_buf.extend_from_slice(&tls12_cbc_record(
            23,
            1,
            c_key,
            c_mac,
            Tls12Mac::Sha1,
            b"GET /cbc HTTP/1.1\r\n",
        ));

        let mut server_buf = tls12_server_hello(&server_random, cipher);
        server_buf.extend_from_slice(&ccs_record());
        server_buf.extend_from_slice(&tls12_cbc_record(
            22,
            0,
            s_key,
            s_mac,
            Tls12Mac::Sha1,
            b"FIN",
        ));
        server_buf.extend_from_slice(&tls12_cbc_record(
            23,
            1,
            s_key,
            s_mac,
            Tls12Mac::Sha1,
            b"HTTP/1.1 200 OK CBC body",
        ));

        let keylog = keylog_for(&client_random, "CLIENT_RANDOM", &master);
        let res = decrypt_flow(&client_buf, &server_buf, &keylog);
        assert!(res.supported && res.session_found, "{res:?}");
        assert_eq!(res.records.len(), 2, "{:?}", res.records);
        let dec = |d: &str| {
            let r = res.records.iter().find(|r| r.direction == d).unwrap();
            base64::engine::general_purpose::STANDARD
                .decode(&r.plaintext_b64)
                .unwrap()
        };
        assert_eq!(dec("c2s"), b"GET /cbc HTTP/1.1\r\n");
        assert_eq!(dec("s2c"), b"HTTP/1.1 200 OK CBC body");
    }

    /// AES-256-CBC + HMAC-SHA384 (cipher 0xC028): exercises the SHA-384 PRF *and* SHA-384 MAC paths.
    #[test]
    fn decrypt_flow_tls12_aes256_cbc_sha384() {
        let client_random = [0xb1u8; 32];
        let server_random = [0xb2u8; 32];
        let master = [0xb3u8; 48];
        let cipher = 0xC028u16;

        let mut seed = Vec::new();
        seed.extend_from_slice(&server_random);
        seed.extend_from_slice(&client_random);
        // CBC-SHA384: mac_len 48, enc 32 → total = 2*48 + 2*32 = 160.
        let kb = tls12_prf_sha384(&master, b"key expansion", &seed, 160);
        let s_mac = &kb[48..96];
        let s_key = &kb[96 + 32..160];

        let mut server_buf = tls12_server_hello(&server_random, cipher);
        server_buf.extend_from_slice(&ccs_record());
        server_buf.extend_from_slice(&tls12_cbc_record(
            23,
            0,
            s_key,
            s_mac,
            Tls12Mac::Sha384,
            b"AES-256-CBC-SHA384 ok",
        ));

        let client_buf = client_hello_record(&client_random);
        let keylog = keylog_for(&client_random, "CLIENT_RANDOM", &master);
        let res = decrypt_flow(&client_buf, &server_buf, &keylog);
        assert!(res.supported && res.session_found, "{res:?}");
        assert_eq!(res.records.len(), 1);
        let pt = base64::engine::general_purpose::STANDARD
            .decode(&res.records[0].plaintext_b64)
            .unwrap();
        assert_eq!(pt, b"AES-256-CBC-SHA384 ok");
    }

    /// A CBC record whose MAC fails verification is dropped (not surfaced), but still advances seq.
    #[test]
    fn decrypt_flow_tls12_cbc_bad_mac_dropped() {
        let client_random = [0xc1u8; 32];
        let server_random = [0xc2u8; 32];
        let master = [0xc3u8; 48];
        let cipher = 0xC013u16;
        let mut seed = Vec::new();
        seed.extend_from_slice(&server_random);
        seed.extend_from_slice(&client_random);
        let kb = tls12_prf_sha256(&master, b"key expansion", &seed, 72);
        let (s_mac, s_key) = (&kb[20..40], &kb[56..72]);

        // Seal with the WRONG MAC key → the MAC won't verify under the real key.
        let wrong_mac = &kb[0..20]; // client MAC key, not the server's
        let mut server_buf = tls12_server_hello(&server_random, cipher);
        server_buf.extend_from_slice(&ccs_record());
        server_buf.extend_from_slice(&tls12_cbc_record(
            23,
            0,
            s_key,
            wrong_mac,
            Tls12Mac::Sha1,
            b"tampered",
        ));

        let client_buf = client_hello_record(&client_random);
        let keylog = keylog_for(&client_random, "CLIENT_RANDOM", &master);
        let res = decrypt_flow(&client_buf, &server_buf, &keylog);
        assert!(res.supported && res.session_found);
        assert!(
            res.records.is_empty(),
            "bad-MAC record must not be surfaced"
        );
    }

    #[test]
    fn decrypt_flow_tls12_unsupported_cipher() {
        let client_random = [0x12u8; 32];
        let server_random = [0x34u8; 32];
        // 0xC09C = TLS_RSA_WITH_AES_128_CCM (CCM mode — not supported).
        let server_buf = tls12_server_hello(&server_random, 0xC09C);
        let client_buf = client_hello_record(&client_random);
        let keylog = keylog_for(&client_random, "CLIENT_RANDOM", &[0u8; 48]);
        let res = decrypt_flow(&client_buf, &server_buf, &keylog);
        assert!(!res.supported);
        assert_eq!(res.version, Some(0x0303));
        assert!(res.reason.unwrap().contains("not supported"));
    }

    #[test]
    fn decrypt_flow_tls12_no_master_secret() {
        let client_random = [0xaau8; 32];
        let server_random = [0xbbu8; 32];
        let server_buf = tls12_server_hello(&server_random, 0xC02F);
        let client_buf = client_hello_record(&client_random);
        // Key-log has a master secret for a different session.
        let keylog = keylog_for(&[0xcc; 32], "CLIENT_RANDOM", &[0u8; 48]);
        let res = decrypt_flow(&client_buf, &server_buf, &keylog);
        assert!(res.supported && !res.session_found);
        assert!(res.reason.unwrap().contains("no master secret"));
    }
}
