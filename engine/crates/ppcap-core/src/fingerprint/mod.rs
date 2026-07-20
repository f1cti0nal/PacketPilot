//! TLS client fingerprinting (JA3/JA4) + the vendored MD5 JA3 requires.
//! No hashing crate (mirrors the vendored SHA-256 in `analyze`): the C-free / minimal-deps
//! invariant forbids adding `md-5`/`sha2`.

/// Minimal MD5 (RFC 1321), lowercase hex. JA3 is defined as the MD5 of its string.
pub(crate) fn md5_hex(data: &[u8]) -> String {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let (mut a0, mut b0, mut c0, mut d0) =
        (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, w) in chunk.chunks_exact(4).enumerate() {
            m[i] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = String::with_capacity(32);
    for v in [a0, b0, c0, d0] {
        for byte in v.to_le_bytes() {
            out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
            out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
        }
    }
    out
}

// ── TLS fingerprint types ─────────────────────────────────────────────────────

/// Transport the ClientHello was carried over — sets the JA4 protocol letter (FoxIO spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ja4Transport {
    Tcp,
    Quic,
}

impl Ja4Transport {
    fn marker(self) -> char {
        match self {
            Ja4Transport::Tcp => 't',
            Ja4Transport::Quic => 'q',
        }
    }
}

/// JA3 + JA4 fingerprints extracted from a TLS ClientHello.
pub struct TlsFingerprints {
    /// JA3 fingerprint: MD5 hex of `"ver,ciphers,exts,curves,ecpf"`.
    pub ja3: String,
    /// JA4 fingerprint: `ja4_a_ja4_b_ja4_c` (FoxIO spec).
    /// Shape: `<t|q><ver><sni><nc><ne><alpn>_<12-hex>_<12-hex>`  (2 underscores).
    /// The first character is `t` for TCP and `q` for QUIC (FoxIO spec protocol letter).
    /// Reference: <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md>
    pub ja4: String,
    /// Server Name Indication extracted from the ClientHello (if present).
    pub sni: Option<String>,
    /// ALPN protocol IDs offered by the client, in wire order (e.g. `["h3"]` for
    /// HTTP/3 over QUIC, `["h2","http/1.1"]` for TLS-over-TCP). Empty when absent.
    pub alpn: Vec<String>,
}

// ── GREASE filter ─────────────────────────────────────────────────────────────

/// Returns `true` for GREASE values (RFC 8701 / draft-davidben-tls-grease).
/// GREASE values have the pattern `{0,1,..f}A{0,1,..f}A` in hex — the high byte equals
/// the low byte and both nibbles end in `0xA` (i.e. 0x0A0A, 0x1A1A … 0xFAFA).
#[inline]
pub(crate) fn is_grease(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    hi == lo && (lo & 0x0f) == 0x0a
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Parse a TLS ClientHello record and compute its JA3 + JA4 fingerprints.
///
/// `transport` sets the JA4 protocol letter: `t` for TCP, `q` for QUIC (FoxIO spec).
/// JA3 is transport-agnostic and is identical for both transports.
///
/// Returns `None` if `payload` is not a parseable ClientHello (wrong content type, truncated,
/// or structurally malformed). Bounded + panic-free: every offset is bounds-checked via
/// `.get()` / `checked_add` (same style as `decode::sniff_tls_client_hello`).
pub fn fingerprint_tls_client_hello(
    payload: &[u8],
    transport: Ja4Transport,
) -> Option<TlsFingerprints> {
    // TLS record: content_type(1) version(2) length(2).
    if *payload.first()? != 22 {
        return None;
    }
    let rec_len = u16::from_be_bytes([*payload.get(3)?, *payload.get(4)?]) as usize;
    let rec_end = 5usize.checked_add(rec_len)?.min(payload.len());
    let body = payload.get(5..rec_end)?;

    // Handshake header: msg_type(1) length(3) — then ClientHello body.
    if *body.first()? != 1 {
        return None; // not ClientHello
    }
    // Skip: handshake-hdr(4) + client_version(2) + random(32) = 38.
    let legacy_ver = u16::from_be_bytes([*body.get(4)?, *body.get(5)?]);
    let mut pos = 4 + 2 + 32;

    // session_id: len(1) + data.
    let sid_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(sid_len)?;

    // cipher_suites: len(2) + u16 pairs.
    let cs_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos.checked_add(1)?)?]) as usize;
    let cs_start = pos.checked_add(2)?;
    let cs_end = cs_start.checked_add(cs_len)?;
    let cs_bytes = body.get(cs_start..cs_end)?;
    let ciphers: Vec<u16> = cs_bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|v| !is_grease(*v))
        .collect();
    pos = cs_end;

    // compression_methods: len(1) + data.
    let cm_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(cm_len)?;

    // extensions: len(2) + extension list.
    let ext_total = u16::from_be_bytes([*body.get(pos)?, *body.get(pos.checked_add(1)?)?]) as usize;
    pos = pos.checked_add(2)?;
    let ext_end = pos.checked_add(ext_total)?.min(body.len());
    let extensions = body.get(pos..ext_end)?;

    // Walk extension list — collect what we need for JA3 and JA4.
    let mut ext_types: Vec<u16> = Vec::new(); // wire order, GREASE removed
    let mut sni: Option<String> = None;
    let mut curves: Vec<u16> = Vec::new();
    let mut ec_point_formats: Vec<u8> = Vec::new();
    let mut alpn_first: Option<String> = None;
    let mut alpn_list: Vec<String> = Vec::new();
    let mut sig_algs: Vec<u16> = Vec::new();
    let mut supported_versions: Vec<u16> = Vec::new();

    let mut i = 0usize;
    while i + 4 <= extensions.len() {
        let et = u16::from_be_bytes([extensions[i], extensions[i + 1]]);
        let el = u16::from_be_bytes([extensions[i + 2], extensions[i + 3]]) as usize;
        let ds = i + 4;
        let de = match ds.checked_add(el) {
            Some(v) => v,
            None => break,
        };
        if de > extensions.len() {
            break;
        }
        let data = &extensions[ds..de];

        if !is_grease(et) {
            ext_types.push(et);
        }
        match et {
            0x0000 => sni = parse_sni(data),
            0x000a => {
                curves = parse_u16_list(data)
                    .into_iter()
                    .filter(|v| !is_grease(*v))
                    .collect()
            }
            0x000b => ec_point_formats = parse_u8_list(data),
            0x0010 => {
                alpn_list = parse_alpn_list(data);
                alpn_first = alpn_list.first().cloned();
            }
            0x000d => sig_algs = parse_u16_list(data),
            // supported_versions (0x002b): RFC 8446 §4.2.1 — the ClientHello body uses a
            // 1-byte length prefix (versions<2..254>) followed by u16 version pairs.
            // This differs from 0x000a/0x000d which use a 2-byte prefix; use the dedicated
            // 1-byte-prefix parser so real TLS 1.3 ClientHellos parse correctly.
            0x002b => supported_versions = parse_u8_prefixed_u16_list(data),
            _ => {}
        }
        i = de;
    }

    let ja3 = compute_ja3(legacy_ver, &ciphers, &ext_types, &curves, &ec_point_formats);
    let ja4 = compute_ja4(
        transport,
        legacy_ver,
        &supported_versions,
        &ciphers,
        &ext_types,
        &sig_algs,
        sni.is_some(),
        alpn_first.as_deref(),
    );
    Some(TlsFingerprints {
        ja3,
        ja4,
        sni,
        alpn: alpn_list,
    })
}

// ── JA3 builder ───────────────────────────────────────────────────────────────

fn join_dec(vals: &[u16]) -> String {
    vals.iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// Build the JA3 fingerprint.
///
/// JA3 = MD5(`"version,ciphers,exts,curves,ecpf"`) where every list is decimal,
/// dash-joined, and GREASE values have already been removed by the caller.
fn compute_ja3(ver: u16, ciphers: &[u16], exts: &[u16], curves: &[u16], ecpf: &[u8]) -> String {
    let ecpf_dec = ecpf
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let s = format!(
        "{},{},{},{},{}",
        ver,
        join_dec(ciphers),
        join_dec(exts),
        join_dec(curves),
        ecpf_dec
    );
    md5_hex(s.as_bytes())
}

// ── JA4 builder ───────────────────────────────────────────────────────────────

/// Build the JA4 fingerprint per the FoxIO spec.
///
/// # Canonical shape
/// `<t|q><ver><sni><nc><ne><alpn>_<sha256_12(sorted ciphers)>_<sha256_12(sorted_exts_sigalgs)>`
///
/// That is **two underscores** and **three components** (`ja4_a`, `ja4_b`, `ja4_c`).
/// The first character of `ja4_a` is `t` for TCP and `q` for QUIC (FoxIO spec).
///
/// `ja4_c` is the first 12 characters of SHA-256 over
/// `"<sorted-ext-hex>,…_<sig-alg-hex>,…"` (extensions sorted ascending excluding
/// SNI 0x0000 and ALPN 0x0010; signature_algorithms in original wire order).
///
/// Reference: <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md>
/// Canonical cross-check example: `t13d1516h2_8daaf6152771_e5627efa2ab1`
// 8 args (transport added for JA4-Q): a private, single-use builder — a params struct
// would add boilerplate without legibility, and all args are consumed building ja4_a.
#[allow(clippy::too_many_arguments)]
fn compute_ja4(
    transport: Ja4Transport,
    legacy_ver: u16,
    supported_versions: &[u16],
    ciphers: &[u16],
    exts: &[u16],
    sig_algs: &[u16],
    sni_present: bool,
    alpn_first: Option<&str>,
) -> String {
    // ── ja4_a ─────────────────────────────────────────────────────────────────
    // TLS version: use the maximum non-GREASE value from supported_versions (0x002b),
    // falling back to the ClientHello legacy_version field.
    let ver = supported_versions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .max()
        .unwrap_or(legacy_ver);
    let ver_code = match ver {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    };
    let sni_flag = if sni_present { "d" } else { "i" };
    // Cipher + extension counts: GREASE already removed; cap at 99, zero-padded to 2 digits.
    let nc = ciphers.len().min(99);
    let ne = exts.len().min(99);
    // ALPN: first and last ASCII character of the first protocol string; "00" if absent/empty.
    let alpn = match alpn_first {
        Some(a) if !a.is_empty() => {
            let bytes = a.as_bytes();
            let first = bytes[0] as char;
            let last = bytes[bytes.len() - 1] as char;
            format!("{first}{last}")
        }
        _ => "00".to_string(),
    };
    let ja4_a = format!(
        "{}{ver_code}{sni_flag}{nc:02}{ne:02}{alpn}",
        transport.marker()
    );

    // ── ja4_b ─────────────────────────────────────────────────────────────────
    // SHA-256[:12] of sorted cipher suite values, 4-hex lowercase, comma-joined.
    // Empty → "000000000000".
    let ja4_b = if ciphers.is_empty() {
        "000000000000".to_string()
    } else {
        let mut cs = ciphers.to_vec();
        cs.sort_unstable();
        let cs_hex = cs
            .iter()
            .map(|c| format!("{c:04x}"))
            .collect::<Vec<_>>()
            .join(",");
        crate::analyze::sha256_hex(cs_hex.as_bytes())[..12].to_string()
    };

    // ── ja4_c ─────────────────────────────────────────────────────────────────
    // SHA-256[:12] of `"<sorted_exts>_<sig_algs_in_order>"` where:
    //   - sorted_exts = extensions sorted ascending, excluding SNI (0x0000) and ALPN (0x0010),
    //     4-hex lowercase, comma-joined.
    //   - sig_algs_in_order = signature_algorithms in original wire order, 4-hex, comma-joined.
    //   - Empty extension list AND empty sig_algs → "000000000000" (whole ja4_c constant).
    //   - Extensions present but no sig_algs → SHA-256[:12](ex_hex) (no underscore, no sig part).
    //   - Both present → SHA-256[:12]("<ex_hex>_<sig_hex>").
    // Note: `ne` (extension count in ja4_a) counts SNI + ALPN too (per FoxIO spec — the count
    // includes all non-GREASE extensions), even though ja4_c excludes them from the hash input.
    let mut ex: Vec<u16> = exts
        .iter()
        .copied()
        .filter(|e| *e != 0x0000 && *e != 0x0010)
        .collect();
    ex.sort_unstable();
    let ex_hex = ex
        .iter()
        .map(|e| format!("{e:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let ja4_c = if ex.is_empty() {
        "000000000000".to_string()
    } else if sig_algs.is_empty() {
        // Extensions present but no signature_algorithms: hash only the ext list (no trailing underscore).
        crate::analyze::sha256_hex(ex_hex.as_bytes())[..12].to_string()
    } else {
        let sig_hex = sig_algs
            .iter()
            .map(|s| format!("{s:04x}"))
            .collect::<Vec<_>>()
            .join(",");
        let combined = format!("{ex_hex}_{sig_hex}");
        crate::analyze::sha256_hex(combined.as_bytes())[..12].to_string()
    };

    format!("{ja4_a}_{ja4_b}_{ja4_c}")
}

// ── Extension sub-parsers ─────────────────────────────────────────────────────

/// Parse the SNI extension body → hostname (or `None` on malformed / non-host entry).
/// Mirrors the walk in `decode::sniff_tls_client_hello`.
fn parse_sni(data: &[u8]) -> Option<String> {
    // server_name_list length (2 bytes), then entries.
    if data.len() < 2 {
        return None;
    }
    let mut j = 2usize; // skip list-length
    while j + 3 <= data.len() {
        let name_type = data[j];
        let name_len = u16::from_be_bytes([data[j + 1], data[j + 2]]) as usize;
        let name_start = j + 3;
        let name_end = name_start.checked_add(name_len)?;
        if name_end > data.len() {
            break;
        }
        if name_type == 0 {
            // host_name
            return std::str::from_utf8(&data[name_start..name_end])
                .ok()
                .map(|s| s.to_string());
        }
        j = name_end;
    }
    None
}

/// Parse a length-prefixed (2-byte) list of u16 values.
/// Used for extensions with a 2-byte list-length prefix: supported_groups (0x000a)
/// and signature_algorithms (0x000d). Returns empty `Vec` on malformed input.
fn parse_u16_list(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let end = 2usize.saturating_add(list_len).min(data.len());
    data.get(2..end)
        .unwrap_or(&[])
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

/// Parse a length-prefixed (1-byte) list of u16 values.
/// Used for supported_versions (0x002b): RFC 8446 §4.2.1 uses a 1-byte length prefix
/// followed by big-endian u16 version pairs. Returns empty `Vec` on malformed input.
fn parse_u8_prefixed_u16_list(data: &[u8]) -> Vec<u16> {
    if data.is_empty() {
        return Vec::new();
    }
    let list_len = data[0] as usize;
    let end = 1usize.saturating_add(list_len).min(data.len());
    data.get(1..end)
        .unwrap_or(&[])
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

/// Parse a length-prefixed (1-byte) list of u8 values (ec_point_formats).
fn parse_u8_list(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let list_len = data[0] as usize;
    let end = 1usize.saturating_add(list_len).min(data.len());
    data.get(1..end).unwrap_or(&[]).to_vec()
}

/// Parse the ALPN extension (0x0010) and return the first protocol string.
/// Wire format: u16 total-list-length, then entries of u8-length + bytes.
/// Parse every ALPN protocol ID from an ALPN extension body (RFC 7301): a 2-byte
/// outer list length, then a sequence of `len(1) + bytes` entries. Non-UTF-8
/// entries are skipped. Bounded + panic-free.
fn parse_alpn_list(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    // Skip the 2-byte outer ProtocolNameList length; entries start at offset 2.
    let mut pos = 2usize;
    while pos < data.len() {
        let proto_len = data[pos] as usize;
        let start = pos + 1;
        let end = match start.checked_add(proto_len) {
            Some(e) if e <= data.len() => e,
            _ => break,
        };
        if let Ok(s) = std::str::from_utf8(&data[start..end]) {
            out.push(s.to_string());
        }
        pos = end;
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_rfc1321_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_hex(b"message digest"),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            md5_hex(b"abcdefghijklmnopqrstuvwxyz"),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
    }

    #[test]
    fn sha256_helper_matches_known_vector() {
        assert_eq!(
            crate::analyze::sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

#[cfg(test)]
mod ch_tests {
    use super::*;

    // Build a TLS record wrapping a ClientHello with the given parts (all big-endian on the wire).
    fn client_hello(
        legacy_ver: u16,
        ciphers: &[u16],
        exts: &[(u16, Vec<u8>)], // (ext_type, ext_body)
    ) -> Vec<u8> {
        let mut hs = Vec::new();
        hs.extend_from_slice(&legacy_ver.to_be_bytes()); // client_version
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0); // session_id len 0
        let cs: Vec<u8> = ciphers.iter().flat_map(|c| c.to_be_bytes()).collect();
        hs.extend_from_slice(&(cs.len() as u16).to_be_bytes());
        hs.extend_from_slice(&cs);
        hs.push(1); // compression methods len
        hs.push(0); // null compression
        let mut ext_blob = Vec::new();
        for (t, body) in exts {
            ext_blob.extend_from_slice(&t.to_be_bytes());
            ext_blob.extend_from_slice(&(body.len() as u16).to_be_bytes());
            ext_blob.extend_from_slice(body);
        }
        hs.extend_from_slice(&(ext_blob.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext_blob);
        // handshake header: type(1)=ClientHello + 3-byte length
        let mut handshake = vec![1u8];
        let l = hs.len();
        handshake.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        handshake.extend_from_slice(&hs);
        // TLS record: content_type(22) version(0x0301) length(2)
        let mut rec = vec![22u8, 0x03, 0x01];
        rec.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        rec.extend_from_slice(&handshake);
        rec
    }

    fn sni_ext(host: &str) -> (u16, Vec<u8>) {
        let mut body = Vec::new();
        let entry_len = 1 + 2 + host.len();
        body.extend_from_slice(&(entry_len as u16).to_be_bytes()); // server_name_list len
        body.push(0); // name_type host_name
        body.extend_from_slice(&(host.len() as u16).to_be_bytes());
        body.extend_from_slice(host.as_bytes());
        (0x0000, body)
    }
    fn alpn_ext(proto: &str) -> (u16, Vec<u8>) {
        let mut list = vec![proto.len() as u8];
        list.extend_from_slice(proto.as_bytes());
        let mut body = (list.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(&list);
        (0x0010, body)
    }
    /// Build an extension with a **2-byte** list-length prefix.
    /// Correct for supported_groups (0x000a) and signature_algorithms (0x000d).
    /// Do NOT use for supported_versions (0x002b) — use `supported_versions_ext` instead.
    fn u16list_ext(t: u16, vals: &[u16]) -> (u16, Vec<u8>) {
        let inner: Vec<u8> = vals.iter().flat_map(|v| v.to_be_bytes()).collect();
        let mut body = (inner.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(&inner);
        (t, body)
    }

    /// Build a supported_versions (0x002b) extension with the correct **1-byte** list-length
    /// prefix as mandated by RFC 8446 §4.2.1 (`versions<2..254>`).
    fn supported_versions_ext(vals: &[u16]) -> (u16, Vec<u8>) {
        let inner: Vec<u8> = vals.iter().flat_map(|v| v.to_be_bytes()).collect();
        let mut body = vec![inner.len() as u8]; // 1-byte prefix
        body.extend_from_slice(&inner);
        (0x002b, body)
    }

    #[test]
    fn ja3_grease_filtered_and_md5_matches_string() {
        // legacy 0x0303 (771); ciphers incl. a GREASE 0x0a0a; exts incl. GREASE 0x1a1a, sni, groups, ec_point_formats.
        let ch = client_hello(
            0x0303,
            &[0x0a0a, 0xc02b, 0xc02f],
            &[
                (0x1a1a, vec![]),
                sni_ext("example.com"),
                u16list_ext(0x000a, &[0x0a0a, 0x001d, 0x0017]), // supported_groups (with GREASE)
                (0x000b, vec![1, 0]),                           // ec_point_formats: len1, [0]
            ],
        );
        let fp = fingerprint_tls_client_hello(&ch, Ja4Transport::Tcp).expect("client hello");
        // Recompute the expected JA3 string by hand (GREASE removed):
        //   version=771, ciphers=49195-49199, exts=0-10-11, curves=29-23, ec_point_formats=0
        let expected = "771,49195-49199,0-10-11,29-23,0";
        assert_eq!(fp.ja3, md5_hex(expected.as_bytes()));
        assert_eq!(fp.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn ja4_parts_are_self_consistent() {
        // JA4 canonical shape: `ja4_a_ja4_b_ja4_c` — 2 underscores, 3 parts.
        // ja4_c = SHA-256[:12] of "<sorted_exts_hex>_<sig_algs_in_order_hex>".
        // Reference: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
        // Cross-check example (FoxIO repo): t13d1516h2_8daaf6152771_e5627efa2ab1
        let ch = client_hello(
            0x0303,
            &[0xc030, 0xc02b], // 2 ciphers, no GREASE
            &[
                supported_versions_ext(&[0x0304]), // supported_versions -> TLS 1.3 (1-byte prefix)
                sni_ext("a.test"),
                alpn_ext("h2"),
                u16list_ext(0x000d, &[0x0403, 0x0804]), // signature_algorithms (2-byte prefix)
            ],
        );
        let fp = fingerprint_tls_client_hello(&ch, Ja4Transport::Tcp).unwrap();
        let parts: Vec<&str> = fp.ja4.split('_').collect();
        assert_eq!(parts.len(), 3);
        // ja4_a: t (TCP) + 13 (supported_versions 0x0304) + d (SNI present) + 02 ciphers + 04 exts + h2 alpn
        assert_eq!(parts[0], "t13d0204h2");
        // ja4_b = sha256_12 of sorted cipher hex (lowercase, 4-hex, comma-joined)
        assert_eq!(parts[1], &crate::analyze::sha256_hex(b"c02b,c030")[..12]);
        // ja4_c = sha256_12 of "<sorted_exts_minus_sni_alpn>_<sig_algs_in_order>"
        // exts in wire order: 0x002b, 0x0000(sni), 0x0010(alpn), 0x000d → exclude sni+alpn → [0x002b, 0x000d]
        // sorted: 0x000d, 0x002b → "000d,002b"
        // sig_algs in order: 0x0403, 0x0804 → "0403,0804"
        // combined: "000d,002b_0403,0804"
        let combined = "000d,002b_0403,0804";
        let want_c = &crate::analyze::sha256_hex(combined.as_bytes())[..12];
        assert_eq!(parts[2], want_c);
    }

    /// Verify the ja4_c fallback when extensions ARE present but signature_algorithms (0x000d)
    /// is absent. Per the FoxIO JA4 spec, ja4_c must be SHA-256[:12](ex_hex) with no trailing
    /// underscore and no sig_algs part — NOT the constant "000000000000".
    #[test]
    fn ja4_c_no_sig_algs_but_has_extensions() {
        // Build a ClientHello with: supported_versions (0x002b) + SNI (0x0000) + supported_groups
        // (0x000a) — but NO signature_algorithms (0x000d).
        let ch = client_hello(
            0x0303,
            &[0xc02b],
            &[
                supported_versions_ext(&[0x0304]),      // 0x002b — 1-byte prefix
                sni_ext("test.example"),                // 0x0000 — excluded from ja4_c hash
                u16list_ext(0x000a, &[0x001d, 0x0017]), // 0x000a — included in ja4_c
            ],
        );
        let fp = fingerprint_tls_client_hello(&ch, Ja4Transport::Tcp).expect("valid client hello");
        let parts: Vec<&str> = fp.ja4.split('_').collect();
        assert_eq!(
            parts.len(),
            3,
            "ja4 must have exactly 3 underscore-separated parts"
        );

        // Recompute ja4_c manually:
        // exts in wire order (GREASE removed): [0x002b, 0x0000, 0x000a]
        // exclude SNI (0x0000) and ALPN (0x0010) → [0x002b, 0x000a]
        // sorted ascending → [0x000a, 0x002b]
        // ex_hex = "000a,002b"
        // no sig_algs → ja4_c = sha256_hex("000a,002b")[..12]
        let ex_hex = "000a,002b";
        let want_c = &crate::analyze::sha256_hex(ex_hex.as_bytes())[..12];
        assert_eq!(
            parts[2], want_c,
            "ja4_c must be sha256[:12](ex_hex) when sig_algs absent but extensions present"
        );
        // Also sanity-check it is NOT the zero constant.
        assert_ne!(parts[2], "000000000000");
    }

    #[test]
    fn truncated_client_hello_is_none() {
        assert!(
            fingerprint_tls_client_hello(&[22, 3, 1, 0, 5, 1, 0, 0], Ja4Transport::Tcp).is_none()
        );
    }

    #[test]
    fn ja4_quic_marker_differs_only_in_protocol_letter() {
        // Reuse the same fixture as ja4_parts_are_self_consistent.
        let ch = client_hello(
            0x0303,
            &[0xc030, 0xc02b],
            &[
                supported_versions_ext(&[0x0304]),
                sni_ext("a.test"),
                alpn_ext("h2"),
                u16list_ext(0x000d, &[0x0403, 0x0804]),
            ],
        );
        let t = fingerprint_tls_client_hello(&ch, Ja4Transport::Tcp).expect("tcp");
        let q = fingerprint_tls_client_hello(&ch, Ja4Transport::Quic).expect("quic");
        assert!(t.ja4.starts_with('t') && q.ja4.starts_with('q'));
        // identical apart from the leading letter:
        assert_eq!(&t.ja4[1..], &q.ja4[1..]);
        // JA3 is transport-agnostic:
        assert_eq!(t.ja3, q.ja3);
    }
}
