# TLS fingerprinting (JA3/JA4) — Sub-project A (Engine) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-22
**Branch:** `feat/tls-fingerprint-engine`
**Parent feature:** "TLS fingerprinting everywhere" — split into **A (engine, this spec)** → B (UI + AI context + export). A emits the fingerprint + IOC contract that B surfaces.

## Goal

Compute **JA3 and JA4** TLS client fingerprints from the ClientHello the decoder already sees, and match them against a **bundled (and user-extensible) malware-fingerprint set** — so a known-malware TLS fingerprint becomes hard evidence on every surface (CLI, desktop, browser), fully offline, with zero configuration.

## Architecture

Extends the existing TLS ClientHello path (`decode/`) and rides the **already-present-but-dormant** IOC machinery: `ThreatFeedFile.bad_ja3`, `ThreatFeed.ja3`/`matches_ja3`, and `FlowEnrichment.ja3_ioc` already exist (the last is commented *"Reserved; always false in Phase 2 (no JA3 on `FlowRecord` yet)"*). This sub-project supplies the missing `FlowRecord.ja3`/`ja4`, the JA4 mirror of the JA3 feed plumbing, an embedded signature set, and the enrich/score wiring. A fingerprint match flows into the **same `+35 IOC / ioc=true / evidence` path** that IP and domain IOCs use today (`score/mod.rs`) — so detection surfaces on threat cards, AI context, and exports with **no new `FindingKind`**.

**Hashing (no new deps):** ppcap-core vendors its crypto — a hand-rolled `Sha256` lives in `analyze/mod.rs:517` and there is no `sha2`/`md5`/`rand` dependency. JA4 (SHA-256, truncated) reuses that vendored SHA-256 (promoted to a reusable `sha256_hex(&[u8]) -> String`); JA3 (MD5) gets a **small vendored pure-Rust MD5** module, matching the project's vendored-SHA-256 / deterministic-no-rand convention. The dependency graph and the C-free gate are untouched.

**Tech stack:** Rust (`ppcap-core`, `ppcap-wasm`, `ppcap-cli`). No new crates.

## Global Constraints

- **No new dependencies.** Reuse the vendored `Sha256`; vendor a small MD5. The C-compiler-free CI gate stays green and stays scoped to `cargo tree -p ppcap-core` (the offline default graph).
- **Bounded, panic-free parsing.** The fingerprint parser uses the same safe bounded indexing as `sniff_tls_client_hello` (no panics on truncated/malformed ClientHello); a parse failure yields `None`, never an error.
- **JA3 and JA4 are computed for TLS-over-TCP ClientHello only.** JA4's QUIC (`q`) variant and JA3S/JA4S (server side) are out of scope (JA4 always uses the `t` transport prefix here).
- **GREASE values are filtered** (RFC 8701: cipher/extension/group values `0x0a0a,0x1a1a,…,0xfafa`) from JA3 and JA4 per their specs, so fingerprints are stable across browsers that send GREASE.
- **Embedded signatures are always on, all surfaces.** The curated set is baked into the *default* `ThreatFeed`, so WASM and Tauri (which pass no user feed today) still match. The user `--threat-feed` augments it on CLI. Bundled entries are a small, **attributed, public** curated set; provenance documented in the data file.
- **A fingerprint IOC contributes `+35` exactly once** (`PTS_IOC`), even if both JA3 and JA4 match — it is one signal (the same ClientHello). It sets `ioc = true` and a `High` severity floor, exactly like an IP/domain IOC.
- **`FlowRecord.ja3`/`ja4` are `Option<String>`** mirroring `sni` (first ClientHello's value per flow), persisted to the Parquet flows columns + the WASM `FlowDto` (the sni-parallel path). `#[serde(default)]` where a summary/DTO field is added, so old cached parquet/JSON still loads.
- **Cross-surface parity:** a native≡WASM test asserts identical JA3/JA4 for a fixture ClientHello.
- Engine CI gates pass: `cargo fmt`, `cargo clippy --workspace --all-targets -D warnings`, `cargo test --workspace`, `cargo test --features online`.

## Reference: existing structures (verified)

```rust
// decode/mod.rs:435  looks_like_tls_client_hello(payload) -> bool   (matches [22,3,_,_,_,1,..])
// decode/mod.rs:727  sniff_tls_client_hello(payload) -> Option<Option<String>>   (walks record→handshake→
//                    session_id→cipher_suites(skipped)→compression→extensions; stops at ext 0x0000 for SNI)
// decode/mod.rs:807  sniff_tls_sni(payload) -> Option<String>
// model/packet.rs:240  PacketMeta.sni: Option<String>   ; decode/mod.rs:175  meta.sni = sni
// model/flow.rs:115  FlowRecord { …, sni: Option<String>, …, ioc: bool }   (no ja3/ja4 yet)
// enrich/mod.rs ThreatFeedFile { …, bad_ja3: Vec<String> }   ThreatFeed { …, ja3: HashSet<String> }
// enrich/mod.rs matches_ja3(&self, ja3: &str) -> bool
// enrich/mod.rs:445  FlowEnrichment { ip_ioc, domain_ioc, ja3_ioc /*reserved, always false*/ } ; any_ioc()=ip||domain||ja3
// enrich/mod.rs:505  Enricher::enrich(rec) sets ip_ioc/domain_ioc + ioc_labels ; feed_match(e) -> FeedMatch{ip,domain}
// score/mod.rs:67  score_flow(rec, fm: &FeedMatch) -> ScoredFlow   (fm.ip/fm.domain each +35 PTS_IOC, evidence, High floor)
// analyze/mod.rs:517  struct Sha256 (vendored)  ; cli.rs --threat-feed -> PipelineConfig.threat_feed
// ppcap-wasm/src/lib.rs:212 analyze() uses PipelineConfig::default() (threat_feed:None) ; FlowDto::from_record
```

## Components

### 1. Vendored hashing — `enrich/fingerprint/` (new module) or `hash.rs`
- Promote/expose `sha256_hex(bytes: &[u8]) -> String` from the vendored `Sha256` (reuse for JA4).
- Vendor `md5_hex(bytes: &[u8]) -> String` — a small, self-contained, pure-Rust MD5 (RFC 1321), tested against canonical vectors. (Matches the vendored-SHA-256 pattern; no `md-5` crate.)

### 2. Fingerprint compute — `decode/` (`fingerprint_tls_client_hello`)
A new `pub fn fingerprint_tls_client_hello(payload: &[u8]) -> Option<TlsFingerprints>` reusing the existing safe framing/extension walk, but collecting the fields JA3/JA4 need instead of stopping at SNI:

```rust
pub struct TlsFingerprints { pub ja3: String, pub ja4: String, pub sni: Option<String> }
```
Collected from the ClientHello (GREASE-filtered): `legacy_version`; `cipher_suites[]`; extension types (in order); `supported_groups` (0x000a) curve ids; `ec_point_formats` (0x000b); `application_layer_protocol_negotiation` (0x0010) first ALPN; `supported_versions` (0x002b, for the real TLS version JA4 needs); `signature_algorithms` (0x000d).

- **JA3** = `md5_hex` of `"{version},{ciphers '-'},{exts '-'},{curves '-'},{ecpf '-'}"` (decimal fields, GREASE removed), per the Salesforce JA3 spec.
- **JA4** = `ja4_a + "_" + ja4_b + "_" + ja4_c` per the FoxIO JA4 spec: `ja4_a = t + tls_ver(2) + (d|i for SNI) + cipher_count(2) + ext_count(2) + alpn_first_last(2)`; `ja4_b = sha256_hex(sorted ciphers hex, GREASE removed)[..12]`; `ja4_c = sha256_hex(sorted exts hex minus SNI/ALPN, GREASE removed)[..12] + "_" + sha256_hex(sig_algs hex, in order)[..12]`.
- SNI extraction stays available (the existing `sniff_tls_sni`/`sniff_tls_client_hello` are unchanged; `fingerprint_*` may return the SNI too so the flow path computes both in one pass, but the existing functions remain for callers that only want SNI).

### 3. Flow model — `model/flow.rs` + columnar
`FlowRecord.ja3: Option<String>` + `ja4: Option<String>` (first ClientHello's values, captured exactly where `sni` is). Add `ja3`/`ja4` columns to the Parquet flows schema + writer (mirroring `sni`) and to the WASM `FlowDto`. `PacketMeta` carries the computed fingerprints from decode to flow aggregation (mirroring `meta.sni`).

### 4. Signature feed — `enrich/mod.rs` + a bundled data file
- Add `bad_ja4: Vec<String>` to `ThreatFeedFile`; `ja4: HashSet<String>` to `ThreatFeed`; `matches_ja4(&self, ja4: &str) -> bool` (mirror `matches_ja3`; lowercased).
- A bundled, attributed curated set (`engine/crates/ppcap-core/data/builtin_fingerprints.json` or a `const`) of `{ja3|ja4 → family}` from public sources, **always merged into the default `ThreatFeed`** (in `ThreatFeed::empty`/the default constructor), so every surface matches with no user feed. The user `--threat-feed` `bad_ja3`/`bad_ja4` augment it.
- A `fingerprint_label(ja3, ja4) -> Option<String>` lookup returns the matched family for evidence.

### 5. Enrich + score — `enrich/mod.rs` + `score/mod.rs`
- `FlowEnrichment`: populate the reserved `ja3_ioc` and add `ja4_ioc: bool` + a `fingerprint_label: Option<String>`. In `Enricher::enrich`, when `rec.ja3`/`rec.ja4` matches the feed, set the flag(s) + push an `ioc_label` like `ja3 <family>`.
- `FeedMatch`: add a single `fingerprint: bool` (true if ja3 or ja4 matched) + carry the label.
- `score_flow`: if `fm.fingerprint`, add `+35` **once** (`PTS_IOC`) with evidence `ioc: tls fingerprint <family> (+35)` and set `ioc = true` (the existing `High` floor applies).

### 6. CLI / WASM / Tauri
- CLI: `--threat-feed` already loads `bad_ja3`/`bad_ja4`; the embedded set is always on. (Optional `--no-builtin-fingerprints` opt-out — deferred unless trivial.)
- WASM (`analyze`) + Tauri (`analyze_capture`): unchanged call sites — the embedded fingerprints flow automatically because they're baked into the default feed.

## Data flow & error handling

Decode → `fingerprint_tls_client_hello` → `PacketMeta.{ja3,ja4}` → `FlowRecord.{ja3,ja4}` (first seen) → `Enricher::enrich` matches (embedded ∪ user feed) → `ja3_ioc`/`ja4_ioc` + label → `score_flow` `+35` IOC + `ioc=true` + evidence → summary/threat cards. A non-TLS flow, a truncated ClientHello, or no match → `ja3`/`ja4` `None` / no IOC; never panics. Old captures without the new fields deserialize via `#[serde(default)]`.

## Testing

- **Hashing:** vendored `md5_hex` + `sha256_hex` against canonical RFC test vectors.
- **JA3/JA4 compute:** a fixture ClientHello (raw bytes) → asserts the exact JA3 MD5 and JA4 string from the published spec test vectors; GREASE values are excluded; a ClientHello with no SNI still fingerprints (JA4 `i`); a truncated ClientHello → `None`.
- **Feed:** `matches_ja4` parity with `matches_ja3`; an embedded-signature ClientHello → `ja3_ioc`/`ja4_ioc` set + family label; `+35` applied once when both JA3 and JA4 match; `ioc=true`, severity floored `High`.
- **Flow/columnar:** `FlowRecord.ja3`/`ja4` populated from a TLS flow; Parquet round-trip of the new columns.
- **Parity:** native `fingerprint_tls_client_hello` ≡ the WASM path for the fixture ClientHello (extend the existing parity harness).
- Engine gates: fmt, clippy `-D warnings`, `test --workspace`, `test --features online`, C-free gate (`ppcap-core`).

## Out of scope (→ B or later)

- **B (UI + AI + export):** JA3/JA4 chips on flow/threat cards, the flows-table `ja3`/`ja4` columns in the UI, an AI-context fingerprint mention, STIX/CSV inclusion.
- QUIC JA4 (`q` transport — pairs with QUIC ClientHello parsing); JA3S/JA4S (server side); richer per-fingerprint scoring or a dedicated `FindingKind`; a large/auto-updating signature database.

## File manifest

**Modify:** `engine/crates/ppcap-core/src/decode/mod.rs` (`fingerprint_tls_client_hello` + collect fields), `engine/crates/ppcap-core/src/model/packet.rs` (`PacketMeta.ja3/ja4`), `engine/crates/ppcap-core/src/model/flow.rs` (`FlowRecord.ja3/ja4`), `engine/crates/ppcap-core/src/columnar/mod.rs` (Parquet schema + writer), `engine/crates/ppcap-core/src/enrich/mod.rs` (`bad_ja4`/`ja4`/`matches_ja4` + embedded set + enrich wiring + `FlowEnrichment.ja4_ioc`/label + `FeedMatch.fingerprint`), `engine/crates/ppcap-core/src/score/mod.rs` (fingerprint IOC `+35`), `engine/crates/ppcap-wasm/src/lib.rs` (`FlowDto.ja3/ja4`), `engine/crates/ppcap-core/src/analyze/mod.rs` (expose `sha256_hex`).
**Create:** `engine/crates/ppcap-core/src/.../md5.rs` (vendored MD5), `engine/crates/ppcap-core/data/builtin_fingerprints.json` (attributed curated set), fingerprint + parity tests.
**No UI/AI/export change** (those are B).
