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
//! suites (AES-256-GCM, ChaCha20-Poly1305) and TLS 1.2 are later phases.
//!
//! [`decrypt_flow`] is the flow-level entry the wasm `decrypt_tls_flow` export drives: given a
//! TLS connection's two cleartext byte streams (each direction's reassembled TCP payload) and a
//! parsed [`KeyLog`], it orients client/server from the ClientHello, gates on a supported suite,
//! then runs the per-direction epoch state machine below.

use base64::Engine as _;
use serde::Serialize;

use super::keylog::KeyLog;
use crate::quic::crypto::{aes128_gcm_open, hkdf_expand_label};

/// The only TLS 1.3 suite this phase decrypts (HKDF-SHA256 + AES-128-GCM). The crypto for it is
/// already RFC-verified; AES-256-GCM / ChaCha20-Poly1305 are later phases.
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
/// TLS 1.3 wire version word (`supported_versions`-unmasked).
const TLS13_VERSION: u16 = 0x0304;
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

/// Decrypt a single TLS 1.3 flow from its two cleartext byte streams (`fwd` = query src→dst,
/// `rev` = the reverse) and a parsed key-log. Orients client/server from whichever stream carries
/// the ClientHello, so the result's `c2s`/`s2c` labels are always client-relative regardless of
/// the query's direction. Only `TLS_AES_128_GCM_SHA256` is decrypted this phase; other suites and
/// TLS 1.2 return `supported = false` with an explaining `reason`. Pure compute, wasm-safe.
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
    if version != TLS13_VERSION {
        return TlsDecryptResult::unsupported(
            Some(version),
            Some(cipher),
            "key-log decryption supports TLS 1.3 only in this build",
            sessions,
        );
    }
    if cipher != TLS_AES_128_GCM_SHA256 {
        return TlsDecryptResult::unsupported(
            Some(version),
            Some(cipher),
            &format!(
                "cipher suite {} not yet supported (only TLS_AES_128_GCM_SHA256)",
                super::cipher_label(cipher)
            ),
            sessions,
        );
    }

    let client_app = keylog.secret(&client_random, "CLIENT_TRAFFIC_SECRET_0");
    let server_app = keylog.secret(&client_random, "SERVER_TRAFFIC_SECRET_0");
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
        keylog.secret(&client_random, "CLIENT_HANDSHAKE_TRAFFIC_SECRET"),
        client_app,
        "c2s",
        &mut records,
        &mut truncated,
    );
    decrypt_direction(
        server_buf,
        keylog.secret(&client_random, "SERVER_HANDSHAKE_TRAFFIC_SECRET"),
        server_app,
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
    dir: &'static str,
    out: &mut Vec<TlsDecryptRecord>,
    truncated: &mut bool,
) {
    let mut hs_keys = hs_secret.and_then(Tls13Keys::aes128_gcm);
    let mut app_keys = app_secret.and_then(Tls13Keys::aes128_gcm);
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

/// The 32-byte ClientHello random from the first ClientHello record in `buf`, if any.
/// Layout: record-hdr(5) handshake-hdr(4) client_version(2) random(32) — random at byte 11.
fn find_client_random(buf: &[u8]) -> Option<[u8; 32]> {
    for rec in tls_records(buf) {
        if rec[0] != CT_HANDSHAKE {
            continue;
        }
        let hs = &rec[5..];
        if hs.first() == Some(&1) && hs.len() >= 38 {
            return hs[6..38].try_into().ok();
        }
    }
    None
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
        let server_buf = server_hello_record(0x1302); // TLS_AES_256_GCM_SHA384 (not yet supported)
        let keylog = keylog_for(&random, "CLIENT_TRAFFIC_SECRET_0", &[0u8; 32]);

        let res = decrypt_flow(&client_buf, &server_buf, &keylog);
        assert!(!res.supported);
        assert_eq!(res.cipher, Some(0x1302));
        assert!(res.records.is_empty());
        assert!(res.reason.unwrap().contains("not yet supported"));
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
}
