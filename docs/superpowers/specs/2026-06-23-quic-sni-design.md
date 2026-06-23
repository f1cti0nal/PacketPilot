# QUIC / HTTP3 SNI (phase A) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-23
**Branch:** `feat/quic-sni`

## Goal

Extract the SNI (server name) from QUIC **Initial** packets (UDP, commonly :443) so HTTP/3 traffic feeds the existing domain/SNI pipeline. Today QUIC is invisible to SNI/domains/fingerprints — the TLS sniff in `decode` is TCP-only. A QUIC ClientHello is a normal TLS 1.3 ClientHello carried inside encrypted QUIC CRYPTO frames; phase A decrypts the Initial and reuses the existing ClientHello parser.

## Architecture

A new `quic` module in `ppcap-core`:
1. Detect a QUIC long-header **Initial** packet in a UDP payload.
2. Derive the client initial keys from the (public) Destination Connection ID + the version's published salt — vendored HMAC-SHA256 + HKDF over the **existing vendored SHA-256** (`analyze::sha256`).
3. Remove header protection (vendored AES-128-ECB sample mask) and AEAD-decrypt the payload (vendored AES-128-GCM).
4. Parse QUIC frames, reassemble CRYPTO frames into the TLS handshake bytes (the ClientHello).
5. Feed the reassembled ClientHello to the **existing** `fingerprint_tls_client_hello` / `sniff_tls_client_hello` and set `meta.sni` — exactly as the TCP TLS path does, so `columnar.sni` + `domain_threats` light up with **no downstream change**.

**Why vendor (decided):** ppcap-core has an explicit "no crypto crate" philosophy and already vendors SHA-256 (`analyze`) and MD5 (`fingerprint`). QUIC Initial keys are **public** (RFC 9001 §5.2 — derived from the on-wire DCID + a published salt; no secret material), so a hand-rolled AEAD here is a *correctness* concern, not a security one, and the RFC 9001 Appendix A golden vector pins correctness end-to-end. Vendoring keeps the C-free / minimal-deps / wasm-safe invariants trivially.

**Tech stack:** Rust (ppcap-core, pure compute — wasm-safe). No new deps.

## Global Constraints

- **No new dependencies** in ppcap-core; vendor the crypto. C-free gate (`cargo tree -p ppcap-core -e no-dev | grep -Ei "zstd-sys|lz4-sys|cc |cmake|bzip2-sys|openssl-sys|zlib-sys"` empty) and **wasm-safe** (the `quic` module is pure compute — no `std::{fs,net,time}`; the separate `ppcap-wasm` workspace must still build for `wasm32`).
- **Never panics, never allocates unboundedly** — every parse step uses `get`/`checked_add`/varint-with-bounds (mirroring `decode`/`fingerprint`), returns `Option`/`None` on short/malformed/unsupported input. The only allocation is the decrypted plaintext + the reassembled ClientHello.
- **The GCM tag MUST verify** before using any plaintext — wrong keys / wrong version / tampered packet → `None`, never a garbage SNI.
- **Reuse, don't reimplement** — the ClientHello → SNI (+ JA3/JA4) parser already exists; QUIC only produces the ClientHello bytes and hands them over.

## Reference: the seams (verified)

```
// engine/crates/ppcap-core/src/analyze/mod.rs:518  pub(crate) fn sha256_hex(data: &[u8]) -> String
//   — there is a vendored Sha256 (the comment at :496 names it). Phase A needs the RAW 32-byte digest:
//     add `pub(crate) fn sha256(data: &[u8]) -> [u8; 32]` next to sha256_hex (sha256_hex becomes hex(sha256(..))).
// engine/crates/ppcap-core/src/fingerprint/mod.rs:104 pub fn fingerprint_tls_client_hello(payload: &[u8]) -> Option<TlsFingerprints { ja3, ja4, sni }>
// engine/crates/ppcap-core/src/decode/mod.rs:414-423  the TCP branch: `if transport == Transport::Tcp { fingerprint_tls_client_hello(payload); if let Some(sni)=sniff_tls_client_hello(payload) {…} }`  → meta.sni set at :177
//   :830 pub fn sniff_tls_sni(payload) ; :750 sniff_tls_client_hello(payload) -> Option<Option<String>>
//   ⚠️ CONFIRM in impl whether these expect a TLS RECORD wrapper (content_type 22 + ver + len) or the handshake directly.
//     QUIC CRYPTO data is the HANDSHAKE directly (no record layer). If the parser needs a record, wrap:
//     [0x16, 0x03, 0x01, len_hi, len_lo] ++ handshake_bytes before calling.
// engine/crates/ppcap-core/src/model/packet.rs:11 enum Transport (Udp variant) ; decode l4 UDP branch ~:154/:232
```

## Components

### 1. `engine/crates/ppcap-core/src/quic/crypto.rs` (vendored, pure Rust)
- `fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32]` — standard HMAC over `analyze::sha256` (block size 64).
- `fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32]` = `hmac_sha256(salt, ikm)`.
- `fn hkdf_expand(prk: &[u8; 32], info: &[u8], out_len: usize) -> Vec<u8>` — RFC 5869 T(i) loop.
- `fn hkdf_expand_label(secret: &[u8; 32], label: &str, out_len: usize) -> Vec<u8>` — TLS 1.3 HkdfLabel (RFC 8446 §7.1): `info = u16(out_len) ++ u8(len("tls13 "+label)) ++ "tls13 "+label ++ u8(0) /*empty context*/`.
- `struct Aes128 { round_keys }` with `fn new(key: &[u8;16])` (key schedule) + `fn encrypt_block(&self, &[u8;16]) -> [u8;16]` (FIPS-197).
- `fn aes128_gcm_open(key: &[u8;16], nonce: &[u8;12], aad: &[u8], ct_and_tag: &[u8]) -> Option<Vec<u8>>` — AES-128-CTR over the ciphertext (counter starts at GCM J0+1) + GHASH(aad, ct) → tag compare (constant-time-ish `==` is fine; non-secret) → `Some(plaintext)` only if the tag matches.
- **Tests:** HKDF (RFC 5869 test case 1), AES-128 single block (FIPS-197 Appendix B / C.1), AES-128-GCM (a NIST GCM KAT — known nonce/aad/ct/tag), HMAC-SHA256 (RFC 4231).

### 2. `engine/crates/ppcap-core/src/quic/mod.rs`
- Version table:
  - **v1** `0x00000001` — salt `0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a` (RFC 9001 §5.2); labels `"quic key"`, `"quic iv"`, `"quic hp"`, client secret label `"client in"`.
  - **v2** `0x6b3343cf` — salt + labels per **RFC 9369 §3.3** (`"quicv2 key"/"quicv2 iv"/"quicv2 hp"`); the implementer MUST source the exact v2 salt from RFC 9369 and verify it against the RFC 9369 Appendix A vector. **If a v2 vector cannot be verified, ship v1-only and defer v2** (note it in the report) — v1 is the firm, golden-vector-tested scope.
- `pub(crate) fn extract_initial_client_hello(udp_payload: &[u8]) -> Option<Vec<u8>>`:
  1. First byte: header form (`0x80`) + fixed bit (`0x40`) + long-packet-type bits = Initial (v1: `0b00`). Bail if not a long-header Initial.
  2. Version (4 bytes) → look up salt/labels; unknown version → `None`.
  3. DCID len (1) + DCID; SCID len (1) + SCID; Token length (varint) + token; Length (varint) = remaining (pn + payload). Compute `pn_offset` = current offset.
  4. Keys: `is = hkdf_extract(salt, dcid)`; `cis = hkdf_expand_label(&is, "client in", 32)`; `key = hkdf_expand_label(cis32, key_label, 16)`; `iv = …(iv_label,12)`; `hp = …(hp_label,16)`.
  5. Header unprotect: `sample = payload[pn_offset+4 .. pn_offset+20]`; `mask = Aes128::new(hp).encrypt_block(sample)`; `first ^= mask[0] & 0x0f`; `pn_len = (first & 0x03)+1`; unmask `pn_len` packet-number bytes with `mask[1..]`; decode the packet number integer.
  6. AEAD: `nonce = iv XOR left_pad(pn, 12)`; `aad = payload[0 .. pn_offset+pn_len]` (with the unprotected first byte + pn written back); `ct_and_tag = payload[pn_offset+pn_len .. pn_offset+length]`; `plaintext = aes128_gcm_open(key, nonce, aad, ct_and_tag)?`.
  7. Frames: iterate `plaintext` — `0x00` PADDING (skip run), `0x01` PING (skip), `0x06` CRYPTO (offset varint, length varint, data) → collect into a map/Vec by offset; any other frame type → stop iterating (return what CRYPTO is reassembled so far). Reassemble CRYPTO from offset 0 contiguously; if offset 0 missing → `None`.
  8. Return the contiguous CRYPTO bytes (the TLS handshake / ClientHello).
- Varint decode (RFC 9000 §16): 2-bit length prefix → 1/2/4/8-byte big-endian, bounds-checked.

### 3. `engine/crates/ppcap-core/src/decode/mod.rs` (integration)
- A UDP sibling to the TCP TLS branch: when `transport == Transport::Udp` and the payload looks like a QUIC long-header Initial (first byte `& 0xC0 == 0xC0`), call `quic::extract_initial_client_hello(payload)`. On `Some(ch)`: feed `ch` (wrapped in a synthetic TLS record iff the parser requires one) to `fingerprint_tls_client_hello`/`sniff_tls_client_hello` and set `meta.sni` (+ JA3/JA4 if produced).
- Gate by the structural long-header form, not solely by port (QUIC is usually :443 but not required). Keep it cheap: the form-bit + version check rejects non-QUIC UDP fast.

## Data flow & error handling

UDP payload → (form/version check) → key derivation → header unprotect → AEAD-open (**tag must verify**) → frame parse → CRYPTO reassembly → ClientHello → existing SNI/JA3/JA4 parser → `meta.sni`/fingerprint → `columnar.sni` + `domain_threats` (unchanged). Any failure at any step (short packet, unknown version, bad tag, no CRYPTO at offset 0, unparseable ClientHello) → `None`/no SNI; never a panic, never a wrong SNI. Decryption uses only public inputs.

## Testing

- **crypto.rs:** RFC 5869 HKDF, RFC 4231 HMAC-SHA256, FIPS-197 AES-128 block, NIST AES-128-GCM KAT.
- **quic/mod.rs (golden):** the **RFC 9001 Appendix A** client Initial packet → `extract_initial_client_hello` → assert the recovered handshake parses to the expected SNI (the RFC vector's ClientHello). Negatives: truncated header, unknown version, non-Initial long header, short-header packet, tampered tag → all `None`.
- **decode integration:** a UDP/:443 frame carrying the RFC 9001 Initial → `decode` sets `meta.sni` to the expected name; a non-QUIC UDP payload → no SNI, no panic.
- **Gates:** `cargo test -p ppcap-core` green; C-free gate empty; `cd engine/crates/ppcap-wasm && cargo build --target x86_64-pc-windows-gnu` (or the wasm32 target) still builds (quic is wasm-safe). Commit BOTH `engine/Cargo.lock` and `engine/crates/ppcap-wasm/Cargo.lock` if anything changes (no new deps expected → likely unchanged).

## Out of scope (phase B)

Multi-datagram CRYPTO reassembly across packets; coalesced packets beyond the first; 0-RTT; Retry; Version Negotiation; server-side ServerHello; the dedicated **JA4-Q** QUIC transport transform; a QUIC indicator in the UI (SNI already flows to the existing surfaces — a tiny badge is a possible later follow-up). No WASM-export/Tauri/CLI/UI change in phase A.

## File manifest

**Engine — create:** `engine/crates/ppcap-core/src/quic/mod.rs`, `engine/crates/ppcap-core/src/quic/crypto.rs` (+ unit tests inline).
**Engine — modify:** `engine/crates/ppcap-core/src/analyze/mod.rs` (expose `pub(crate) fn sha256(&[u8]) -> [u8;32]`), `engine/crates/ppcap-core/src/lib.rs` (`mod quic;`), `engine/crates/ppcap-core/src/decode/mod.rs` (the UDP→QUIC SNI branch).
**No new deps; no WASM-export/Tauri/CLI/UI change.**
