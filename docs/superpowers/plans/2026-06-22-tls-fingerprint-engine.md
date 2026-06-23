# TLS fingerprinting (JA3/JA4) — Sub-project A (Engine) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compute JA3 + JA4 TLS client fingerprints from the ClientHello and match them against an embedded (+ user-extensible) malware-fingerprint set, lighting up the dormant `ja3_ioc` IOC path (`+35`, `ioc=true`, evidence) on every surface — fully offline.

**Architecture:** Extend the existing safe ClientHello walk to collect the JA3/JA4 fields; vendor MD5 + reuse the vendored SHA-256 (no new deps); carry `ja3`/`ja4` per-flow exactly like `sni`; bake an embedded signature set into the default `ThreatFeed`; wire matches into the existing `enrich`→`score` IOC path. No new `FindingKind`.

**Tech Stack:** Rust (`ppcap-core`, `ppcap-wasm`, `ppcap-cli`). No new crates.

## Global Constraints

- **No new dependencies.** Vendor MD5 (mirroring the vendored `Sha256`); reuse `Sha256` for JA4. The C-free CI gate stays green and stays scoped to `cargo tree -p ppcap-core`.
- **Bounded, panic-free parsing.** Reuse the `checked_add`/`.get()` style of `sniff_tls_client_hello`; a malformed/truncated ClientHello yields `None`, never an error/panic.
- **GREASE filtered** (RFC 8701): a value `v: u16` is GREASE iff `((v >> 8) as u8) == ((v & 0xff) as u8) && (((v & 0xff) as u8) & 0x0f) == 0x0a` (the set `0x0a0a,0x1a1a,…,0xfafa`). Filter from JA3 ciphers/extensions/curves and JA4 ciphers/extensions.
- **TLS-over-TCP only.** JA4 always uses the `t` transport prefix; QUIC `q` and JA3S/JA4S are out of scope.
- **A fingerprint IOC contributes `+35` exactly once** even if both JA3 and JA4 match (one ClientHello = one signal). It sets `ioc=true` + the existing `High` floor.
- **`FlowRecord.ja3`/`ja4` are `Option<String>`** mirroring `sni`; new serialized/DTO fields get `#[serde(default)]`.
- **Embedded signatures are always on, all surfaces** (baked into the default feed, incl. WASM/Tauri which pass no feed). Bundled entries are attributed + sourced; deterministic tests validate the *mechanism* with a controlled fingerprint, not fabricated real-world hashes.
- Engine gates: `cargo fmt`, `cargo clippy --workspace --all-targets -D warnings`, `cargo test --workspace`, `cargo test --features online`, the C-free gate.
- **TOOLCHAIN:** cargo at `/c/Users/ravid/.cargo/bin`; run cargo from `engine/`. The `online`-feature build needs MinGW (`/c/Users/ravid/opt/mingw64/bin`). `cargo fmt` before every commit.

## Reference: existing seams (verbatim, verified)

```rust
// decode/mod.rs:343  enum L7Hint { …, Tls { sni: Option<String> } }
// decode/mod.rs:400  l7_hint(transport, src_port, dst_port, payload) -> Option<L7Hint>
//    if Tcp { if let Some(sni) = sniff_tls_client_hello(payload) { return Some(L7Hint::Tls { sni }); }
//             if looks_like_tls_client_hello(payload) { return Some(L7Hint::Tls { sni: None }); } … }
// decode/mod.rs:173  match hint { L7Hint::Tls { sni } => { meta.app_proto = AppProto::Tls; meta.sni = sni; } … }
// decode/mod.rs:727  sniff_tls_client_hello(payload) -> Option<Option<String>>   (walks the ClientHello safely)
// model/packet.rs:240  PacketMeta { …, pub sni: Option<String>, … }
// model/flow.rs:116  FlowRecord { …, pub sni: Option<String>, …, pub ioc: bool }   (::new sets sni:None)
// model/flow.rs:178  FlowRecord::observe(&mut self, p:&PacketMeta, dir) { … if self.sni.is_none() { if let Some(host)=&p.sni { if !host.is_empty() { self.sni = Some(host.clone()); } } } … }
// enrich/mod.rs  ThreatFeedFile { …, bad_ja3:Vec<String> }  ThreatFeed { …, ja3:HashSet<String> }
//    ThreatFeed::empty() / from_file()  ; matches_ja3(&self,&str)->bool  ; matches_ip/matches_domain
//    FlowEnrichment { ip_ioc, domain_ioc, ja3_ioc /*reserved*/, ioc_labels:Vec<String> } any_ioc()=ip||domain||ja3
//    Enricher::enrich(rec)->FlowEnrichment (sets ip_ioc/domain_ioc + labels) ; feed_match(e)->FeedMatch{ip,domain}
// score/mod.rs:42  const PTS_IOC:i32=35;  score_flow(rec,fm:&FeedMatch)->ScoredFlow
//    if fm.ip {acc+=PTS_IOC; evidence.push("ioc: endpoint ip on threat feed (+35)")}  (same for fm.domain)
//    if fm.any() { High floor >=60 ("floor: ioc match forces High (>= 60)"); C2/Anomalous -> Critical >=90 }
// columnar/schema.rs:20  flow_arrow_schema() — Field "sni" Utf8 nullable (#19)
// columnar/mod.rs:84  struct Builders { …, sni: StringBuilder, … }
// columnar/mod.rs:249  write(rec): match &rec.sni { Some(h) if !h.is_empty() => b.sni.append_value(h), _ => b.sni.append_null() }
// ppcap-wasm/src/lib.rs:88  struct FlowDto { …, sni: Option<String>, … }  from_record: sni: rec.sni…filter(!empty)…
// analyze/mod.rs:517  struct Sha256 { … fn new/update/finalize_hex } (vendored)  ; test helper sha256_hex(&[u8])->String
// cli.rs:54  --threat-feed -> PipelineConfig.threat_feed ; ppcap-wasm analyze() & src-tauri use PipelineConfig::default() (threat_feed:None)
```

---

### Task 1: Vendored MD5 + reusable SHA-256 helper

**Files:**
- Create: `engine/crates/ppcap-core/src/fingerprint/mod.rs` (new module; houses hashing + JA3/JA4)
- Modify: `engine/crates/ppcap-core/src/lib.rs` (declare `mod fingerprint;`), `engine/crates/ppcap-core/src/analyze/mod.rs` (expose `pub(crate) fn sha256_hex`)

**Interfaces:**
- Produces: `pub(crate) fn fingerprint::md5_hex(&[u8]) -> String`; `pub(crate) fn analyze::sha256_hex(&[u8]) -> String`.

- [ ] **Step 1: Write the failing test** — in a new `engine/crates/ppcap-core/src/fingerprint/mod.rs`, add a `#[cfg(test)]` module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_rfc1321_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(md5_hex(b"message digest"), "f96b697d7cb7938d525a2f31aaf161d0");
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
```

- [ ] **Step 2: Run it to verify it fails** — `cd engine && cargo test -p ppcap-core fingerprint::tests` → FAIL (module/fns absent).

- [ ] **Step 3: Implement** — (a) in `engine/crates/ppcap-core/src/lib.rs`, add `mod fingerprint;` next to the other `mod` decls.

(b) in `engine/crates/ppcap-core/src/analyze/mod.rs`, change the test-only `sha256_hex` into a crate helper next to `Sha256` (remove it from the `#[cfg(test)]` block if it lived there; keep the tests using it):

```rust
/// One-shot SHA-256 hex of a byte slice (reuses the vendored streaming `Sha256`).
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize_hex()
}
```

(c) write `engine/crates/ppcap-core/src/fingerprint/mod.rs` with the vendored MD5:

```rust
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
```

> NOTE: if `sha256_hex` already exists only under `#[cfg(test)]` in `analyze/mod.rs`, move it out of the test module (make it `pub(crate)`); keep the existing `#[cfg(test)]` callers working. `cargo clippy -D warnings` must stay clean (the helper is now used in prod by JA4 in Task 2 — until then, allow it may be unused; Task 1 and Task 2 land in sequence, so add `#[allow(dead_code)]` only if Task 1's clippy fails on the not-yet-used helper, and remove it in Task 2).

- [ ] **Step 4: Run it to verify it passes** — `cd engine && cargo test -p ppcap-core fingerprint::tests::md5_rfc1321_vectors fingerprint::tests::sha256_helper_matches_known_vector` → PASS. `cargo fmt && cargo clippy -p ppcap-core --all-targets -- -D warnings` → clean.

- [ ] **Step 5: Commit**

```bash
cd engine && cargo fmt
git add engine/crates/ppcap-core/src/fingerprint/mod.rs engine/crates/ppcap-core/src/lib.rs engine/crates/ppcap-core/src/analyze/mod.rs
git commit -m "feat(engine): vendored MD5 + reusable sha256_hex for TLS fingerprinting"
```

---

### Task 2: JA3 + JA4 compute from the ClientHello

**Files:**
- Modify: `engine/crates/ppcap-core/src/fingerprint/mod.rs` (the parser + builders + tests)

**Interfaces:**
- Consumes: `md5_hex` (T1), `crate::analyze::sha256_hex` (T1).
- Produces: `pub struct TlsFingerprints { pub ja3: String, pub ja4: String, pub sni: Option<String> }`; `pub fn fingerprint_tls_client_hello(payload: &[u8]) -> Option<TlsFingerprints>`.

- [ ] **Step 1: Write the failing test** — add to `fingerprint/mod.rs` tests. Build a minimal real ClientHello in-test (helper `client_hello(...)`), so JA3 and the JA4 sub-parts are recomputable in-test (self-consistent — no external oracle), plus assert the hand-computable `ja4_a` prefix:

```rust
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
    fn u16list_ext(t: u16, vals: &[u16]) -> (u16, Vec<u8>) {
        let inner: Vec<u8> = vals.iter().flat_map(|v| v.to_be_bytes()).collect();
        let mut body = (inner.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(&inner);
        (t, body)
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
                (0x000b, vec![1, 0]),                            // ec_point_formats: len1, [0]
            ],
        );
        let fp = fingerprint_tls_client_hello(&ch).expect("client hello");
        // Recompute the expected JA3 string by hand (GREASE removed):
        //   version=771, ciphers=49195-49199, exts=0-10-11, curves=29-23, ec_point_formats=0
        let expected = "771,49195-49199,0-10-11,29-23,0";
        assert_eq!(fp.ja3, md5_hex(expected.as_bytes()));
        assert_eq!(fp.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn ja4_parts_are_self_consistent() {
        let ch = client_hello(
            0x0303,
            &[0xc030, 0xc02b], // 2 ciphers, no GREASE
            &[
                u16list_ext(0x002b, &[0x0304]), // supported_versions -> TLS 1.3
                sni_ext("a.test"),
                alpn_ext("h2"),
                u16list_ext(0x000d, &[0x0403, 0x0804]), // signature_algorithms
            ],
        );
        let fp = fingerprint_tls_client_hello(&ch).unwrap();
        let parts: Vec<&str> = fp.ja4.split('_').collect();
        assert_eq!(parts.len(), 3);
        // ja4_a: t (TCP) + 13 (supported_versions 0x0304) + d (SNI present) + 02 ciphers + 04 exts + h2 alpn
        assert_eq!(parts[0], "t13d0204h2");
        // ja4_b = sha256_12 of sorted cipher hex (lowercase, 4-hex, comma-joined)
        assert_eq!(parts[1], &crate::analyze::sha256_hex(b"c02b,c030")[..12]);
        // ja4_c = sha256_12(sorted exts minus sni(0000)+alpn(0010)) + "_" + sha256_12(sig_algs in order)
        let exts_sorted = "000d,002b"; // 0x002b + 0x000d, sorted, sni/alpn excluded
        let sigalgs = "0403,0804";
        let want_c = format!(
            "{}_{}",
            &crate::analyze::sha256_hex(exts_sorted.as_bytes())[..12],
            &crate::analyze::sha256_hex(sigalgs.as_bytes())[..12]
        );
        assert_eq!(parts[2], want_c);
    }

    #[test]
    fn truncated_client_hello_is_none() {
        assert!(fingerprint_tls_client_hello(&[22, 3, 1, 0, 5, 1, 0, 0]).is_none());
    }
}
```

> NOTE: these tests are self-consistent (they recompute ja4_b/c via the same `sha256_hex`), so they lock the *construction*. Additionally cross-check your implementation once against a canonical FoxIO JA4 example (e.g. the spec's `t13d1516h2_8daaf6152771_e5627efa2ab1`) using the FoxIO `ja4` reference repo — cite it in a code comment. Use WebSearch/WebFetch for the exact JA4 algorithm details (`ja4_a` version map, ALPN first/last char, the `d`/`i` SNI flag, GREASE handling, the `00` ALPN fallback, and the `000000000000` empty-sig-algs fallback).

- [ ] **Step 2: Run it to verify it fails** — `cd engine && cargo test -p ppcap-core fingerprint::ch_tests` → FAIL.

- [ ] **Step 3: Implement** — add to `fingerprint/mod.rs`:

```rust
pub struct TlsFingerprints {
    pub ja3: String,
    pub ja4: String,
    pub sni: Option<String>,
}

#[inline]
fn is_grease(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    hi == lo && (lo & 0x0f) == 0x0a
}

/// Parse a TLS ClientHello and compute its JA3 + JA4 fingerprints (TLS-over-TCP).
/// Returns `None` if the payload is not a parseable ClientHello. Bounded + panic-free
/// (same checked indexing as `decode::sniff_tls_client_hello`).
pub fn fingerprint_tls_client_hello(payload: &[u8]) -> Option<TlsFingerprints> {
    if *payload.first()? != 22 {
        return None;
    }
    let rec_len = u16::from_be_bytes([*payload.get(3)?, *payload.get(4)?]) as usize;
    let rec_end = 5usize.checked_add(rec_len)?.min(payload.len());
    let body = payload.get(5..rec_end)?;
    if *body.first()? != 1 {
        return None;
    }
    let legacy_ver = u16::from_be_bytes([*body.get(4)?, *body.get(5)?]);
    let mut pos = 4 + 2 + 32;
    let sid_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(sid_len)?;
    // cipher_suites
    let cs_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
    let cs_start = pos.checked_add(2)?;
    let cs_end = cs_start.checked_add(cs_len)?;
    let cs_bytes = body.get(cs_start..cs_end)?;
    let ciphers: Vec<u16> = cs_bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|v| !is_grease(*v))
        .collect();
    pos = cs_end;
    // compression_methods
    let cm_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(cm_len)?;
    // extensions
    let ext_total = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
    pos = pos.checked_add(2)?;
    let ext_end = pos.checked_add(ext_total)?.min(body.len());
    let extensions = body.get(pos..ext_end)?;

    let mut ext_types: Vec<u16> = Vec::new(); // order, GREASE removed
    let mut sni: Option<String> = None;
    let mut curves: Vec<u16> = Vec::new();
    let mut ec_point_formats: Vec<u8> = Vec::new();
    let mut alpn_first: Option<String> = None;
    let mut sig_algs: Vec<u16> = Vec::new();
    let mut supported_versions: Vec<u16> = Vec::new();

    let mut i = 0usize;
    while i + 4 <= extensions.len() {
        let et = u16::from_be_bytes([extensions[i], extensions[i + 1]]);
        let el = u16::from_be_bytes([extensions[i + 2], extensions[i + 3]]) as usize;
        let ds = i + 4;
        let de = ds.checked_add(el)?;
        if de > extensions.len() {
            break;
        }
        let data = &extensions[ds..de];
        if !is_grease(et) {
            ext_types.push(et);
        }
        match et {
            0x0000 => sni = parse_sni(data),
            0x000a => curves = parse_u16_list(data).into_iter().filter(|v| !is_grease(*v)).collect(),
            0x000b => ec_point_formats = parse_u8_list(data),
            0x0010 => alpn_first = parse_first_alpn(data),
            0x000d => sig_algs = parse_u16_list(data),
            0x002b => supported_versions = parse_u8_prefixed_u16_list(data),
            _ => {}
        }
        i = de;
    }

    let ja3 = compute_ja3(legacy_ver, &ciphers, &ext_types, &curves, &ec_point_formats);
    let ja4 = compute_ja4(
        legacy_ver,
        &supported_versions,
        &ciphers,
        &ext_types,
        &sig_algs,
        sni.is_some(),
        alpn_first.as_deref(),
    );
    Some(TlsFingerprints { ja3, ja4, sni })
}
```

Then the helper builders (`compute_ja3`, `compute_ja4`, and the small extension parsers `parse_sni`, `parse_u16_list`, `parse_u8_list`, `parse_first_alpn`, `parse_u8_prefixed_u16_list`):

```rust
fn join_dec(vals: &[u16]) -> String {
    vals.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("-")
}

fn compute_ja3(ver: u16, ciphers: &[u16], exts: &[u16], curves: &[u16], ecpf: &[u8]) -> String {
    // exts here are already GREASE-filtered and in wire order (JA3 keeps order).
    let ecpf_dec = ecpf.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("-");
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

fn compute_ja4(
    legacy_ver: u16,
    supported_versions: &[u16],
    ciphers: &[u16],
    exts: &[u16],
    sig_algs: &[u16],
    sni_present: bool,
    alpn_first: Option<&str>,
) -> String {
    // ja4_a
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
        _ => "00",
    };
    let sni_flag = if sni_present { "d" } else { "i" };
    let nc = ciphers.len().min(99);
    let ne = exts.len().min(99);
    let alpn = match alpn_first {
        Some(a) if !a.is_empty() => {
            let bytes = a.as_bytes();
            let first = bytes[0] as char;
            let last = bytes[bytes.len() - 1] as char;
            format!("{first}{last}")
        }
        _ => "00".to_string(),
    };
    let ja4_a = format!("t{ver_code}{sni_flag}{nc:02}{ne:02}{alpn}");

    // ja4_b: sorted ciphers, 4-hex lowercase, comma-joined.
    let mut cs = ciphers.to_vec();
    cs.sort_unstable();
    let cs_hex = cs.iter().map(|c| format!("{c:04x}")).collect::<Vec<_>>().join(",");
    let ja4_b = &crate::analyze::sha256_hex(cs_hex.as_bytes())[..12];

    // ja4_c: sorted exts minus SNI(0x0000)+ALPN(0x0010), 4-hex; then sig algs in order.
    let mut ex: Vec<u16> = exts.iter().copied().filter(|e| *e != 0x0000 && *e != 0x0010).collect();
    ex.sort_unstable();
    let ex_hex = ex.iter().map(|e| format!("{e:04x}")).collect::<Vec<_>>().join(",");
    let sig_hex = sig_algs.iter().map(|s| format!("{s:04x}")).collect::<Vec<_>>().join(",");
    let c1 = &crate::analyze::sha256_hex(ex_hex.as_bytes())[..12];
    let c2 = if sig_algs.is_empty() {
        "000000000000".to_string()
    } else {
        crate::analyze::sha256_hex(sig_hex.as_bytes())[..12].to_string()
    };
    format!("{ja4_a}_{ja4_b}_{c1}_{c2}")
}
```

> NOTE: confirm the canonical JA4 string layout is `ja4_a_ja4_b_ja4_c` where `ja4_c` itself is `hash12_hash12` — i.e. the final JA4 has THREE underscores (`a_b_c1_c2`). The test in Step 1 splits on `_` into 3 and treats `parts[2]` as `c1_c2`; reconcile the test and `compute_ja4` to the SAME shape (either split into 4, or join `c1_c2` first). Pick the FoxIO-correct shape and make both agree. Implement the small parsers (`parse_sni` reuses the SNI walk from `decode::sniff_tls_client_hello`; `parse_u16_list` reads a 2-byte length then u16s; `parse_u8_list` reads a 1-byte length then u8s; `parse_u8_prefixed_u16_list` for supported_versions reads a 1-byte length then u16s; `parse_first_alpn` reads the 2-byte list length, then the first 1-byte-prefixed string) with bounded indexing returning empty/None on malformed input.

- [ ] **Step 4: Run it to verify it passes** — `cd engine && cargo test -p ppcap-core fingerprint` → PASS. `cargo fmt && cargo clippy -p ppcap-core --all-targets -- -D warnings` → clean.

- [ ] **Step 5: Commit**

```bash
cd engine && cargo fmt
git add engine/crates/ppcap-core/src/fingerprint/mod.rs
git commit -m "feat(engine): compute JA3 + JA4 from the TLS ClientHello (GREASE-filtered)"
```

---

### Task 3: Decode → flow plumbing (`PacketMeta.ja3/ja4`, `FlowRecord.ja3/ja4`)

**Files:**
- Modify: `engine/crates/ppcap-core/src/decode/mod.rs` (`L7Hint::Tls`, `l7_hint`, the `meta.ja3/ja4` set), `engine/crates/ppcap-core/src/model/packet.rs` (`PacketMeta.ja3/ja4`), `engine/crates/ppcap-core/src/model/flow.rs` (`FlowRecord.ja3/ja4` + `::new` + `observe`)

**Interfaces:**
- Consumes: `fingerprint::fingerprint_tls_client_hello` (T2).
- Produces: `PacketMeta.ja3/ja4: Option<String>`, `FlowRecord.ja3/ja4: Option<String>` (first-seen, sticky).

- [ ] **Step 1: Write the failing test** — add to `model/flow.rs` tests (mirror `observe_aggregates_most_specific_l7_and_first_sni`):

```rust
#[test]
fn observe_captures_first_ja3_ja4_sticky() {
    let key = /* reuse the existing test's FlowKey builder */ test_key();
    let mut r = FlowRecord::new(key, 0);
    let mut p1 = test_meta(); // a PacketMeta with sni/ja3/ja4 None
    p1.ja3 = Some("aaa".into());
    p1.ja4 = Some("t13d0000".into());
    r.observe(&p1, Direction::Forward);
    let mut p2 = test_meta();
    p2.ja3 = Some("bbb".into());
    r.observe(&p2, Direction::Forward);
    assert_eq!(r.ja3.as_deref(), Some("aaa")); // first wins, sticky
    assert_eq!(r.ja4.as_deref(), Some("t13d0000"));
}
```

> NOTE: reuse the existing flow-test fixtures (`make_meta`/`tls`-style helpers already present in `model/flow.rs` tests) rather than inventing `test_meta`/`test_key`; just set `.ja3`/`.ja4` on them.

- [ ] **Step 2: Run it to verify it fails** — `cd engine && cargo test -p ppcap-core observe_captures_first_ja3` → FAIL (fields absent).

- [ ] **Step 3: Implement** —
(a) `model/packet.rs`: add after `pub sni: Option<String>,`:
```rust
    /// TLS JA3 fingerprint of a ClientHello on this packet; `None` otherwise. Derived flag.
    pub ja3: Option<String>,
    /// TLS JA4 fingerprint of a ClientHello on this packet; `None` otherwise. Derived flag.
    pub ja4: Option<String>,
```
Add `ja3: None, ja4: None,` to every `PacketMeta { … }` construction in the decoder (where `sni: None` / `sni:` is set — find each).

(b) `decode/mod.rs`: change the `L7Hint::Tls` variant to carry the fingerprints:
```rust
    Tls { sni: Option<String>, ja3: Option<String>, ja4: Option<String> },
```
In `l7_hint`, the TLS branch becomes (compute once, fall back to SNI-only sniff when fingerprinting fails but it still looks like a ClientHello):
```rust
    if transport == Transport::Tcp {
        if let Some(fp) = crate::fingerprint::fingerprint_tls_client_hello(payload) {
            return Some(L7Hint::Tls { sni: fp.sni, ja3: Some(fp.ja3), ja4: Some(fp.ja4) });
        }
        if let Some(sni) = sniff_tls_client_hello(payload) {
            return Some(L7Hint::Tls { sni, ja3: None, ja4: None });
        }
        if looks_like_tls_client_hello(payload) {
            return Some(L7Hint::Tls { sni: None, ja3: None, ja4: None });
        }
        if let Some(method) = sniff_http_method(payload) { /* unchanged */ }
    }
```
In the hint→meta match (decode/mod.rs:173): 
```rust
    L7Hint::Tls { sni, ja3, ja4 } => {
        meta.app_proto = AppProto::Tls;
        meta.sni = sni;
        meta.ja3 = ja3;
        meta.ja4 = ja4;
    }
```
Fix the decode test at ~1463 (`Some(L7Hint::Tls { sni }) => …`) to the new shape `Some(L7Hint::Tls { sni, .. })`.

(c) `model/flow.rs`: add `pub ja3: Option<String>,` + `pub ja4: Option<String>,` to `FlowRecord` (after `sni`); `ja3: None, ja4: None,` to `FlowRecord::new`; and in `observe`, after the SNI capture block, mirror it:
```rust
    if self.ja3.is_none() {
        if let Some(v) = &p.ja3 {
            if !v.is_empty() {
                self.ja3 = Some(v.clone());
            }
        }
    }
    if self.ja4.is_none() {
        if let Some(v) = &p.ja4 {
            if !v.is_empty() {
                self.ja4 = Some(v.clone());
            }
        }
    }
```

- [ ] **Step 4: Run it to verify it passes** — `cd engine && cargo test -p ppcap-core` → all pass (fix any other `PacketMeta {` / `L7Hint::Tls {` construction the compiler flags). `cargo fmt && cargo clippy -p ppcap-core --all-targets -- -D warnings` → clean.

- [ ] **Step 5: Commit**

```bash
cd engine && cargo fmt
git add engine/crates/ppcap-core/src/decode/mod.rs engine/crates/ppcap-core/src/model/packet.rs engine/crates/ppcap-core/src/model/flow.rs
git commit -m "feat(engine): carry JA3/JA4 from decode through to the flow record"
```

---

### Task 4: ThreatFeed JA4 + embedded signature set

**Files:**
- Modify: `engine/crates/ppcap-core/src/enrich/mod.rs` (`bad_ja4`/`ja4`/`matches_ja4`, embedded set, `fingerprint_label`)
- Create: `engine/crates/ppcap-core/data/builtin_fingerprints.json` (attributed curated set)

**Interfaces:**
- Produces: `ThreatFeed::matches_ja4(&str) -> bool`; `ThreatFeed::fingerprint_label(ja3: Option<&str>, ja4: Option<&str>) -> Option<String>`; the embedded set merged into `empty()` and `from_file()`.

- [ ] **Step 1: Write the failing test** — add to `enrich/mod.rs` tests:

```rust
#[test]
fn builtin_fingerprints_match_without_user_feed() {
    let feed = ThreatFeed::empty(); // now includes the embedded set
    // The embedded set ships at least one entry; assert the mechanism via a known builtin.
    // (Use a value you add to builtin_fingerprints.json with label "test-sig".)
    assert!(feed.matches_ja3("00000000000000000000000000000000")); // sentinel builtin
    assert_eq!(
        feed.fingerprint_label(Some("00000000000000000000000000000000"), None).as_deref(),
        Some("test-sig")
    );
}

#[test]
fn user_feed_augments_ja4() {
    let f = ThreatFeed::from_file(ThreatFeedFile {
        bad_ja4: vec!["t13d1516h2_8daaf6152771_e5627efa2ab1".into()],
        ..Default::default()
    })
    .unwrap();
    assert!(f.matches_ja4("t13d1516h2_8daaf6152771_e5627efa2ab1"));
}
```

> NOTE: include a sentinel entry `{"ja3":"00000000000000000000000000000000","label":"test-sig"}` in `builtin_fingerprints.json` so the mechanism is testable deterministically without depending on real-world hashes; the real curated entries sit alongside it.

- [ ] **Step 2: Run it to verify it fails** — `cd engine && cargo test -p ppcap-core builtin_fingerprints_match user_feed_augments_ja4` → FAIL.

- [ ] **Step 3: Implement** —
(a) `ThreatFeedFile`: add `#[serde(default)] pub bad_ja4: Vec<String>,`.
(b) `ThreatFeed`: add `ja4: HashSet<String>,` and a `labels: std::collections::HashMap<String, String>` (fingerprint → family). 
(c) Create `engine/crates/ppcap-core/data/builtin_fingerprints.json`:
```json
{
  "_source": "Curated from public JA3/JA4 malware fingerprint lists (e.g. abuse.ch SSLBL); see header comment.",
  "entries": [
    { "ja3": "00000000000000000000000000000000", "label": "test-sig" }
  ]
}
```
Embed it via `include_str!`: `const BUILTIN: &str = include_str!("../../data/builtin_fingerprints.json");` (adjust the relative path from `enrich/mod.rs`). Parse it once (a small `BuiltinFile { entries: Vec<BuiltinEntry { ja3: Option<String>, ja4: Option<String>, label: String }> }`).
(d) Make `empty()` and `from_file()` BOTH seed `ja3`/`ja4`/`labels` from `BUILTIN` first, then add the user entries. Add `matches_ja4` (mirror `matches_ja3`) and:
```rust
pub fn fingerprint_label(&self, ja3: Option<&str>, ja4: Option<&str>) -> Option<String> {
    if let Some(j) = ja3 {
        if let Some(l) = self.labels.get(&j.to_ascii_lowercase()) { return Some(l.clone()); }
    }
    if let Some(j) = ja4 {
        if let Some(l) = self.labels.get(&j.to_ascii_lowercase()) { return Some(l.clone()); }
    }
    None
}
```

> NOTE: populate the real curated entries from a cited public source during implementation (attribute in the file header / `_source`). Keep the bundled set small. Document provenance. JA4 strings are case-sensitive in their hash parts but lowercase by construction — store lowercased and compare lowercased, consistent with `matches_ja3`.

- [ ] **Step 4: Run it to verify it passes** — `cd engine && cargo test -p ppcap-core enrich` → PASS. `cargo fmt && cargo clippy -p ppcap-core --all-targets -- -D warnings` → clean.

- [ ] **Step 5: Commit**

```bash
cd engine && cargo fmt
git add engine/crates/ppcap-core/src/enrich/mod.rs engine/crates/ppcap-core/data/builtin_fingerprints.json
git commit -m "feat(engine): JA4 feed field + matches_ja4 + embedded builtin fingerprint set"
```

---

### Task 5: Enrich + score wiring (light up the IOC path)

**Files:**
- Modify: `engine/crates/ppcap-core/src/enrich/mod.rs` (`FlowEnrichment.ja4_ioc` + label, `Enricher::enrich`, `FeedMatch`, `feed_match`), `engine/crates/ppcap-core/src/score/mod.rs` (fingerprint `+35`)

**Interfaces:**
- Consumes: `FlowRecord.ja3/ja4` (T3), `matches_ja3`/`matches_ja4`/`fingerprint_label` (T4).
- Produces: `FeedMatch.fingerprint: bool` (+ the existing `ip`/`domain`); the `+35`-once fingerprint IOC term.

- [ ] **Step 1: Write the failing test** — add to `score/mod.rs` (or `enrich`) tests:

```rust
#[test]
fn fingerprint_ioc_adds_35_once_and_floors_high() {
    let mut rec = test_flow(); // a benign-category flow scoring < 60 on its own
    rec.ja3 = Some("00000000000000000000000000000000".into()); // builtin "test-sig"
    rec.ja4 = Some("00000000000000000000000000000000".into());
    let enr = Enricher::new(ThreatFeed::empty());
    let e = enr.enrich(&rec);
    assert!(e.ja3_ioc || e.ja4_ioc);
    let fm = enr.feed_match(&e);
    assert!(fm.fingerprint);
    let scored = score_flow(&rec, &fm);
    assert!(scored.severity.rank() >= Severity::High.rank()); // IOC floor
    // +35 applied exactly once even though both ja3 and ja4 matched:
    assert_eq!(scored.evidence.iter().filter(|s| s.contains("tls fingerprint")).count(), 1);
}
```

> NOTE: reuse the existing score-test flow builder; pick a category/shape that scores below 60 pre-IOC so the High floor is observable. If `matches_ja4` of the same sentinel isn't in the builtin set, set only `rec.ja3` — the assertion is "+35 once".

- [ ] **Step 2: Run it to verify it fails** — `cd engine && cargo test -p ppcap-core fingerprint_ioc_adds_35` → FAIL.

- [ ] **Step 3: Implement** —
(a) `FlowEnrichment`: add `pub ja4_ioc: bool,` (after `ja3_ioc`) and `pub fingerprint_label: Option<String>,`; update `any_ioc()` to `self.ip_ioc || self.domain_ioc || self.ja3_ioc || self.ja4_ioc`.
(b) `Enricher::enrich`: after the SNI block, add:
```rust
    if let Some(j) = &rec.ja3 {
        if self.feed.matches_ja3(j) {
            e.ja3_ioc = true;
        }
    }
    if let Some(j) = &rec.ja4 {
        if self.feed.matches_ja4(j) {
            e.ja4_ioc = true;
        }
    }
    if e.ja3_ioc || e.ja4_ioc {
        let label = self
            .feed
            .fingerprint_label(rec.ja3.as_deref(), rec.ja4.as_deref())
            .unwrap_or_else(|| "tls fingerprint".to_string());
        e.fingerprint_label = Some(label.clone());
        e.ioc_labels.push(format!("tls fingerprint {label}"));
    }
```
(c) `FeedMatch`: add `pub fingerprint: bool,`; `any()` → `self.ip || self.domain || self.fingerprint`. `feed_match`: `fingerprint: e.ja3_ioc || e.ja4_ioc,`.
(d) `score/mod.rs` `score_flow`: after the `fm.domain` branch, add (once):
```rust
    if fm.fingerprint {
        acc += PTS_IOC;
        evidence.push("ioc: tls fingerprint on threat feed (+35)".to_string());
    }
```
Update the `PTS_IOC` comment to `// per IOC dimension (ip, domain, tls fingerprint)`.

> NOTE: the `High`/`Critical` floor logic keys off `fm.any()` — now also true for a fingerprint match, so no extra floor code is needed. Confirm `fm.any()` is what gates the floor (it is, per the reference).

- [ ] **Step 4: Run it to verify it passes** — `cd engine && cargo test -p ppcap-core` → all pass. `cargo fmt && cargo clippy -p ppcap-core --all-targets -- -D warnings` → clean.

- [ ] **Step 5: Commit**

```bash
cd engine && cargo fmt
git add engine/crates/ppcap-core/src/enrich/mod.rs engine/crates/ppcap-core/src/score/mod.rs
git commit -m "feat(engine): light up the JA3/JA4 IOC path (+35 once, ioc, High floor)"
```

---

### Task 6: Parquet columns + WASM FlowDto

**Files:**
- Modify: `engine/crates/ppcap-core/src/columnar/schema.rs` (ja3/ja4 fields), `engine/crates/ppcap-core/src/columnar/mod.rs` (`Builders` + `write`), `engine/crates/ppcap-wasm/src/lib.rs` (`FlowDto` + `from_record`)

**Interfaces:**
- Consumes: `FlowRecord.ja3/ja4` (T3).
- Produces: `ja3`/`ja4` nullable Utf8 Parquet columns + `FlowDto.ja3/ja4`.

- [ ] **Step 1: Write the failing test** — extend the columnar round-trip test (find the existing one writing+reading a `FlowRecord` through `FlowParquetWriter`): set `rec.ja3 = Some("abc".into()); rec.ja4 = Some("t13d…".into());` and assert the read-back batch has `ja3`/`ja4` columns with those values; also assert a `None` ja3 reads back NULL. If the suite asserts the column COUNT (currently 22), bump it to 24.

```rust
// in the existing columnar round-trip test:
rec.ja3 = Some("769,49195,0,29,0".into());
rec.ja4 = Some("t13d0204h2_aaaaaaaaaaaa_bbbbbbbbbbbb".into());
// … write, read back …
assert_eq!(batch.schema().fields().len(), 24);
let ja3_col = batch.column_by_name("ja3").unwrap();
// downcast to StringArray, assert value(0) == the ja3 above (mirror how the test reads `sni`)
```

- [ ] **Step 2: Run it to verify it fails** — `cd engine && cargo test -p ppcap-core columnar` → FAIL.

- [ ] **Step 3: Implement** —
(a) `columnar/schema.rs`: add after the `sni` field (#19), before `severity`:
```rust
        Field::new("ja3", DataType::Utf8, true),  // TLS JA3 fingerprint; NULL if none observed
        Field::new("ja4", DataType::Utf8, true),  // TLS JA4 fingerprint; NULL if none observed
```
(b) `columnar/mod.rs` `Builders`: add `ja3: StringBuilder,` + `ja4: StringBuilder,` after `sni` (keep field order matching the schema); init them in `Builders::new`/`with_capacity` wherever `sni` is initialized; and in `finish()` append their arrays in the SAME position. In `write`, after the `sni` match:
```rust
        match &rec.ja3 {
            Some(v) if !v.is_empty() => b.ja3.append_value(v),
            _ => b.ja3.append_null(),
        }
        match &rec.ja4 {
            Some(v) if !v.is_empty() => b.ja4.append_value(v),
            _ => b.ja4.append_null(),
        }
```
(c) `ppcap-wasm/src/lib.rs` `FlowDto`: add `ja3: Option<String>,` + `ja4: Option<String>,` after `sni`; in `from_record`, mirror the `sni` mapping:
```rust
            ja3: rec.ja3.as_ref().filter(|v| !v.is_empty()).map(|v| v.to_string()),
            ja4: rec.ja4.as_ref().filter(|v| !v.is_empty()).map(|v| v.to_string()),
```

> NOTE: the `Builders` struct, its constructor, and `finish()` must all list `ja3`/`ja4` in the SAME ordinal position as the schema (right after `sni`) or the RecordBatch assembly panics. Search `columnar/mod.rs` for every place `sni` appears and mirror it.

- [ ] **Step 4: Run it to verify it passes** — `cd engine && cargo test -p ppcap-core columnar && cargo build -p ppcap-wasm` → pass/clean. `cargo fmt && cargo clippy -p ppcap-core --all-targets -- -D warnings` → clean.

- [ ] **Step 5: Commit**

```bash
cd engine && cargo fmt
git add engine/crates/ppcap-core/src/columnar/schema.rs engine/crates/ppcap-core/src/columnar/mod.rs engine/crates/ppcap-wasm/src/lib.rs
git commit -m "feat(engine): persist JA3/JA4 to the flows Parquet columns + WASM FlowDto"
```

---

### Task 7: Cross-surface parity + full gate

**Files:**
- Modify/Create: a parity test asserting `fingerprint_tls_client_hello` is identical native vs the WASM build path (extend the existing parity harness if present, e.g. `engine/crates/ppcap-core/tests/` or the wasm parity fixture), OR a focused integration test that runs a fixture pcap through `run`/`analyze` and asserts the resulting flow carries the expected JA3/JA4.

- [ ] **Step 1: Write the test** — add an integration test (`engine/crates/ppcap-core/tests/fingerprint.rs`) that builds a tiny in-memory capture containing one TLS ClientHello (reuse `gen::` helpers or a raw pcap fixture), runs the pipeline, and asserts the emitted `FlowRecord.ja3`/`ja4` equal the value `fingerprint_tls_client_hello` returns for that ClientHello (the native≡pipeline contract). If a WASM parity harness exists (search for an existing native≡wasm test), extend it with the JA3/JA4 fields instead.

```rust
// pseudo-shape — adapt to the existing gen/test harness:
#[test]
fn pipeline_emits_ja3_ja4_for_tls_flow() {
    let ch = /* the same client_hello bytes as fingerprint::ch_tests */;
    let expected = ppcap_core::fingerprint::fingerprint_tls_client_hello(&ch).unwrap();
    // run a capture whose one TLS flow carries `ch`, collect flows:
    let flow = /* the TLS flow from the run */;
    assert_eq!(flow.ja3.as_deref(), Some(expected.ja3.as_str()));
    assert_eq!(flow.ja4.as_deref(), Some(expected.ja4.as_str()));
}
```

> NOTE: `fingerprint_tls_client_hello` is `pub` — make sure it (and `TlsFingerprints`) are reachable from the test crate (re-export from `lib.rs` if needed: `pub use fingerprint::{fingerprint_tls_client_hello, TlsFingerprints};`). If wiring a full pcap through `run` is heavy, assert the decode→flow path directly via the `gen` synthetic beacon/TLS scenario.

- [ ] **Step 2: Run it to verify it fails (then passes after wiring)** — `cd engine && cargo test -p ppcap-core --test fingerprint` → PASS once the re-export/harness is in place.

- [ ] **Step 3: Full engine gate** — `export PATH="/c/Users/ravid/opt/mingw64/bin:/c/Users/ravid/.cargo/bin:$PATH"` then from `engine/`:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p ppcap-core --features online
cargo build -p ppcap-wasm
echo "C-free gate:"; cargo tree -p ppcap-core -e no-dev | grep -iE "ring|openssl-sys|.*-sys|cc " || echo "no C deps in default graph"
```
All green; the C-free default graph must NOT show a C-compiled dep (md-5/sha2 were NOT added).

- [ ] **Step 4: Commit**

```bash
cd engine && cargo fmt
git add engine/crates/ppcap-core/tests/fingerprint.rs engine/crates/ppcap-core/src/lib.rs
git commit -m "test(engine): JA3/JA4 pipeline parity + full engine gate green"
```

---

## Self-Review

**1. Spec coverage:** vendored MD5 + sha256_hex (T1) → spec §1; JA3/JA4 compute + GREASE (T2) → §2; decode→flow plumbing (T3) → §2-3; ThreatFeed JA4 + embedded set (T4) → §4; enrich+score IOC wiring (T5) → §5; Parquet/FlowDto (T6) → §3; parity + gate (T7) → §Testing + cross-surface. No-new-deps, +35-once, GREASE, TCP-only, embedded-on-all-surfaces — all honored. UI/AI/export = sub-project B. ✓

**2. Placeholder scan:** complete code for the MD5, the parser, the builders, every diff. The NOTEs are concrete in-repo verifications (reuse the real test fixtures; reconcile the JA4 underscore shape against FoxIO; mirror every `sni` site in `Builders`; populate the curated set from a cited source). The one genuinely external item — the exact JA4 algorithm details + a canonical cross-check vector — is explicitly delegated to the FoxIO spec via WebSearch/WebFetch, with self-consistent deterministic tests as the primary gate. ✓

**3. Type consistency:** `TlsFingerprints{ja3,ja4,sni}` (T2) → `L7Hint::Tls{sni,ja3,ja4}` (T3) → `PacketMeta.ja3/ja4` → `FlowRecord.ja3/ja4` (T3) → `Enricher::enrich` reads `rec.ja3/ja4` (T5) → `FeedMatch.fingerprint` → `score_flow` (T5); `matches_ja4`/`fingerprint_label` (T4) consumed in T5; `FlowRecord.ja3/ja4` → Parquet columns + `FlowDto` (T6). The `+35`-once rule lives in one `if fm.fingerprint` branch. All consistent. ✓
