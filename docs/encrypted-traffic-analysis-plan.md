# PacketPilot — Encrypted Traffic Analysis

**Implementation Plan**

| | |
|---|---|
| **Status** | **Implemented** on this branch — engine + CLI + browser/desktop UI parity, adversarially designed, fully test-verified |
| **Feature branch** | `claude/encrypted-traffic-analysis-6195xf` |
| **Date** | 2026-07-26 |
| **Scope** | Engine (Rust: `fingerprint` JA4S + ECH/absent-SNI flags · `tls` server-ALPN parse · `quic` server-Initial keys + a bounded DCID tracker · a new bounded `EntropySampler` at the raw-frame seam · 3 new detectors + `Category::Anomalous`'s first producer · `stats` TLS-server rollup · Parquet flow schema **v10 → v11**, +3 columns) · Threat feed (`bad_ja4s`) + Time Machine (`ja4s` indicator) + STIX/MISP export · CLI (`analyze --no-encrypted-analysis` + stderr summary) · WASM/UI (FlowDto + 14-file schema lockstep, 3 new `FindingKind`s, TLS-posture card, SQL samples) |

> **Implementation status (what actually shipped).** All six milestones were executed on this
> branch, in order, each committed with the engine and UI suites green.
>
> - **M1** — `fingerprint::compute_ja4s` + server ALPN parsing + the Parquet **v10 → v11** bump
>   (`ja4s`, `entropy_c2s`, `entropy_s2c`) across the full 14-file lockstep.
> - **M2** — role-generic QUIC Initial key derivation pinned to **RFC 9001 §A.3**, plus
>   `QuicServerHelloTracker`; QUIC flows now carry server-side TLS metadata.
> - **M3** — the `entropy` module (per-flow identification state, STUN/HASSH/compression screens),
>   `detect_encrypted_unknown`, the first `Category::Anomalous` producer, and
>   `Scenario::EncryptedAnomaly`.
> - **M4** — `detect_missing_sni` + `detect_port_mismatch`, with the ClientHello
>   parse-completeness and ECH plumbing they depend on.
> - **M5** — `bad_ja4s` through feed → `FingerprintHit.ja4s` → STIX/MISP → Time Machine
>   (`IndicatorKind::Ja4s`).
> - **M6** — `analyze --no-encrypted-analysis` + stderr summary, `Summary.tls_servers` +
>   `TlsServersCard`, CertHealthPanel widening, flyout fingerprints, two SQL samples, and the
>   user-facing `docs/encrypted-traffic-analysis.md`.
>
> **Verified here:** engine `cargo fmt --all --check`, `clippy --workspace --all-targets
> -D warnings`, and `cargo test --workspace` (**851** tests, up from 764 at branch point); UI
> `tsc -b`, Vitest (**1008**), and `vite build`. **Not verifiable in this sandbox** (left to CI,
> per the BBL/PAD precedent): the wasm32 bundle rebuild (`build:wasm`), Playwright e2e, and the
> Windows Tauri desktop build.
>
> **Deviations from the plan, all deliberate:** entropy is stored `entropy_fwd`/`entropy_rev` on
> `FlowRecord` and mapped to `c2s`/`s2c` only in `oriented()`, matching the repo's orientation
> invariant rather than the plan's sketch; `compute_ja4s` takes primitives via `Ja4sInput` instead
> of `&ServerHello`, so `fingerprint` keeps no dependency on `tls`; and the decode-site ServerHello
> sniff is TCP-gated, which makes the JA4S transport marker correct by construction.

> **How this plan was produced.** Eleven parallel readers each mapped one subsystem ETA touches —
> the TLS module, fingerprinting, QUIC, flow/model/columnar schema, the detection engine, the stats
> substrate, the analyze+scoring pipeline, classification+SSH, CLI/gen/CI conventions, the WASM/UI
> parity surfaces, and docs/positioning — reading the checked-out source at this branch. The design
> was synthesised from those maps and run through an adversarial review across three lenses (engine
> correctness & reuse, hard invariants, product/detection value vs. shipped features); all three
> verdicts were *buildable with corrections*, and every correction is folded into the body
> (Appendix A). Line-number citations are anchors verified during mapping and spot-checked during
> review — `grep` before editing, as the tree evolves (Appendix B).

---

## 1. Summary & Goals

### What ships

**Encrypted Traffic Analysis (ETA)** teaches PacketPilot to *judge* encrypted traffic it cannot
read — using only handshake plaintext, wire metadata, and payload byte-distributions. **Never keys,
never decrypted content**: the existing opt-in key-log decryption path stays quarantined exactly as
it is today (§2.1). ETA has four pillars, each shippable on its own:

1. **Complete the server side of the handshake.** Today the engine fingerprints the *client*
   deeply (JA3, JA4 over TCP *and* QUIC) but the server only shallowly (legacy MD5 JA3S, TCP only).
   ETA adds **JA4S** (the modern FoxIO server fingerprint, which needs the server-chosen ALPN the
   ServerHello parser currently skips) and — via the same version-public RFC 9001/9369 Initial-key
   derivation the client side already uses — **keyless QUIC server-side extraction**: QUIC flows
   gain `ja3s`/`ja4s`/`tls_version`/`tls_cipher`, closing the "no server visibility on QUIC" gap.
2. **An entropy substrate for unidentified traffic.** A new bounded `EntropySampler` at the
   raw-frame seam accumulates a per-direction byte histogram for flows whose protocol the payload
   sniffers could *not* identify, yielding per-flow `entropy_c2s`/`entropy_s2c` (bits/byte). This
   is the missing discriminator between "unknown cleartext junk" and "unknown *ciphertext*" — the
   signature of a custom-crypto C2 channel or tunnel.
3. **Three new explainable detectors** built on 1+2:
   `encrypted_unknown_protocol` (sustained high-entropy traffic that no protocol sniffer claims —
   and the **first producer** of the fully-plumbed-but-never-assigned `Category::Anomalous`),
   `missing_sni` (parsed ClientHello with no `server_name`, ECH-aware so Encrypted Client Hello is
   never a false positive), and `port_protocol_mismatch` (TLS on an uncommon port / established
   non-TLS on 443).
4. **Analyst surfacing.** A per-server **TLS posture rollup** (`Summary.tls_servers`: version,
   cipher, JA3S/JA4S, SNI, flow/client counts per server endpoint), a dashboard card, `bad_ja4s`
   threat-feed matching + Time Machine `ja4s` indicators + STIX/MISP export, bundled SQL samples,
   and rendering the already-computed-but-never-shown `IpThreat.fingerprints`.

### What it changes vs. today's engine

| Dimension | Today | New with ETA |
|---|---|---|
| Server TLS fingerprint | MD5 JA3S, TCP only (`tls/mod.rs:663`); computed but consumed by **nothing** | + JA4S on TCP **and** QUIC; JA3S/JA4S feed the posture rollup, the threat feed (`bad_ja4s`), and Time Machine |
| QUIC server side | Nothing — only the client Initial is decrypted (`quic/mod.rs:316`); QUIC flows never get `tls_version`/`cipher`/`ja3s` | Server Initial opened with the same version-public salts (`"server in"` label, RFC 9001 §A.3-pinned); QUIC flows gain server handshake metadata |
| Unknown traffic | `Category::Unknown`, or shape-uplift to Scan/Tunnel/C2 by byte counts alone (`classify/mod.rs:162`) | Byte-distribution entropy separates unknown-*ciphertext* from unknown-cleartext; `Category::Anomalous` gets its first producer; an explainable finding names the channel |
| SNI absence | Representable (`sniff_tls_client_hello` → `Some(None)`, `decode/mod.rs:1478`) but never flagged | `missing_sni` finding, gated on a *parsed* ClientHello, ECH-aware, external-only by default |
| Port/protocol mismatch | TLS is found on any port (payload precedence) but the mismatch is never a signal; TCP/443 is trusted as "https" by port (`classify/mod.rs:240`) | `port_protocol_mismatch` finding for both directions of mismatch, SYN-gated against mid-capture false positives |
| Server posture visibility | `tls_version`/`tls_cipher`/`ja3s` sit on flow rows only; no aggregate | `Summary.tls_servers` per-endpoint rollup + dashboard card |

### Relationship to shipped features (credited, not re-promised)

Already shipped and **not** claimed by ETA: client JA3/JA4 over TCP+QUIC with SNI/ALPN parsing
(`fingerprint/mod.rs:127`), keyless QUIC *client* Initial recovery (`quic/mod.rs:316`),
`TlsCertHealth` (self-signed / expired / not-yet-valid / SNI-mismatch, TLS ≤ 1.2 leaf certs,
`detect/mod.rs:3471`), `WeakTls` (deprecated versions + 34-cipher table, `detect/mod.rs:3576`),
JA3/JA4 IOC matching (+35 with the High floor, `score/mod.rs:226`), per-host JA3 baseline novelty
(BBL), beacon/exfil detection that already covers TLS ports, DoH/DoT rollups, and HASSH/HASSHServer
extraction. ETA extends these seams — it does not duplicate them.

### Non-goals (this plan's core)

Local-first, offline, single pass, keyless. **No** decryption in the analyze pass (the key-log
path stays quarantined), **no** ML/classifiers (explainable thresholds only, per the PAD/BBL
precedent), **no** per-packet Parquet, **no** SPLT packet-length-sequence *vectors* persisted
(§16 sketches the bounded follow-up), **no** JA4X/JA4T/JA4H/JA4L, **no** SSH banner/hygiene work
(§16), **no** ECH decryption (impossible by design — ETA only *detects* ECH), **no** new
`Category` variant (Anomalous already exists; the 13-slot histogram is untouched).

---

## 2. Concept & Chosen Approach

### 2.1 The keyless principle — and the with-keys quarantine

Everything in this plan reads **handshake plaintext** (ClientHello, ServerHello, TLS ≤ 1.2
certificates), **version-public QUIC Initial protection** (RFC 9001 §5.2 / RFC 9369 §3.3.1 salts +
the wire-visible DCID — no session secrets; the client side of this already ships), and **wire
statistics** (lengths, direction, byte histograms). The existing decryption feature
(`ppcap_core::decrypt_tls_flow`, `packets.rs:177`, driven by user-supplied SSLKEYLOGFILE text) is
reachable only outside the analyze pass and its modules are `pub(crate)`/private
(`tls/mod.rs:21-26`). ETA adds **no** import from any of them into the keyless pass — that boundary
is a stated guarantee (§10) and a review checklist item.

### 2.2 Where each pillar plugs in

The engine already has the exact seams ETA needs; the genuinely new code is small and bounded:

- **Stateless per-packet parsing** (JA4S, server ALPN, ECH/absent-SNI flags) extends
  `fingerprint_tls_client_hello`'s extension walk (`fingerprint/mod.rs:184-222`) and
  `parse_server_hello_body`'s (`tls/mod.rs:619`) — both already GREASE-filter and bounds-check.
- **Stateful raw-frame observers** (QUIC DCID tracker, EntropySampler) follow the
  `TlsCertReassembler` pattern: created near `analyze/mod.rs:255`, fed at the only point where
  raw payload bytes coexist with `PacketMeta` (`analyze/mod.rs:300-303`), bounded by named caps.
- **Per-flow folds** ride `FlowRecord::observe`'s sticky first-non-empty idiom
  (`model/flow.rs:297-352`); flow-close verdicts ride `process_flow` (`analyze/mod.rs:669-750`).
- **Detectors** follow the uniform `XxxParams` + `detect_xxx(&BehaviorTracker, &Params) ->
  Vec<Finding>` shape, registered in `PipelineConfig` and extended into the findings vector
  **before** `stats.apply_findings` (`analyze/mod.rs:474-500`, ordering rule at :628) so threat
  cards, incidents, and attack chains come free.
- **Rollups** follow `encrypted_dns` (`stats/mod.rs:223`, `summary.rs:255`): a bounded map folded
  in `observe_scored_flow`, projected top-K in `finish()`, an optional `Summary` field.

### 2.3 Why a per-flow histogram, not per-packet entropy (the load-bearing design choice)

Shannon entropy of an *n*-byte sample is bounded by `log2(n)`: a 64-byte payload can never measure
above 6 bits/byte, so per-packet entropy on small C2 packets would be structurally blind — and a
per-packet `f64` field would also break `PacketMeta`'s `Eq` derive (`model/packet.rs:317`).
Instead, ETA accumulates one 256-bin `u16` histogram **per direction per flow**, but **only for
flows the payload sniffers did not identify**:

- **Identification is flow-level state, not a per-packet property** (review correction A.1 — the
  load-bearing subtlety): `l7_hint` identifies handshake/request-*shaped* payloads only, so packet
  3+ of an ordinary TLS/HTTP/QUIC flow decodes with `meta.app_proto == Unknown`, and a sampler
  gating on the current packet alone would fill with identified flows' ciphertext. The sampler
  therefore keeps its **own per-flow identification memory**: every payload-bearing packet folds
  its `app_proto` into a bounded `FlowKey → SampleState` map, where a *known* `app_proto` stores
  (or upgrades to) a cheap `Identified` **sentinel** — no histograms — and only flows whose state
  is still `Unknown` accumulate histograms. A TLS/HTTP/QUIC/DNS/OT flow identifies on its **first**
  payload packet, so it costs one sentinel entry and never allocates bins.
- **Late-identification drops** free a tracked flow's histograms the moment any evidence names the
  protocol: a packet with a known `app_proto`, a packet that sets `meta.hassh`/`hassh_server`
  (SSH has no `AppProto` variant — without this, odd-port SSH is a guaranteed false positive,
  §6.1), or an early packet carrying the **STUN magic cookie** `0x2112A442` at payload offset 4
  (ICE always precedes WebRTC SRTP on the same 5-tuple — the screen for conference media outside
  the port-named RTP range).
- **Compression screen**: each direction's *first sampled bytes* are checked against known
  container magics (gzip `1F 8B`, zlib, zstd `28 B5 2F FD`, `PK`, `Rar!`, 7z, xz) and a match
  marks the flow `Compressed` — kept out of the high-entropy candidate set (§6.1). This replaces
  the draft's `meta.download` screen, which review showed is vacuous here (it fires only on HTTP
  flows, which are already ineligible).
- Bounds: sentinel map ≤ `max_sample_states = 32_768` entries (flow-table scale, new-key-drop),
  histogram-carrying flows ≤ `max_entropy_flows = 4096` (new-key-drop at cap), sample cap
  `entropy_sample_bytes = 2048` bytes **per direction**, packets with payload `< 64` bytes are
  skipped. Worst case: 4096 × 2 × 512 B (bins) ≈ 4 MiB + sentinel map ≈ 2–3 MiB — ≈ **7 MiB**
  total, inside the ≤ 64 MiB budget (§10). A 2048-byte sample caps measurable entropy at 11 bits —
  no estimator ceiling near the 7.2 bits/byte decision threshold.
- At flow close, `process_flow` looks the flow up by `FlowKey`, computes per-direction entropy,
  writes `record.entropy_c2s/_s2c`, and **removes both the histogram and the sentinel entry**
  (memory is reclaimed at close, not EOF). `entropy_*` stays `NULL` for identified flows — the
  columns are a property of *unidentified* traffic by construction.

This is the one place ETA deliberately does *not* reuse an existing accumulator idiom: the state is
per-*flow* and payload-derived, which no `stats`/`detect` map models — the `TlsCertReassembler`
(bounded, raw-frame-fed, freed-on-completion) is the in-repo precedent it copies.

### 2.4 Corroboration philosophy (unchanged)

ETA obeys the module's stated rule: *anomaly alone tops out at Medium*. `encrypted_unknown_protocol`
and `missing_sni` emit at most Medium on their own signal; High/Critical comes only from
corroboration — an IOC floor (`score/mod.rs:291-322`), a second finding kind on the same host
(incident escalation, `detect/mod.rs:3699`), or an existing behavioral detector. The one exception
follows precedent: `port_protocol_mismatch`'s *established non-TLS on 443* arm may reach High with
volume, exactly as `WeakTls` reaches High on rank-3 evidence — it is a specific, parsed signal,
not a statistical anomaly.

---

## 3. Pillar 1a — JA4S + server ALPN (TCP)

### 3.1 Server ALPN

`parse_server_hello_body` (`tls/mod.rs:619`) walks ServerHello extensions but captures only
`supported_versions`; the ALPN body (ext `0x0010`) is skipped. Add `alpn: Option<String>` to
`struct ServerHello` (`tls/mod.rs:588`), parsed from the extension's single protocol entry.
Honesty note baked into the code comment: **TLS 1.3 servers negotiate ALPN in
EncryptedExtensions**, which is encrypted — so a captured server ALPN is a TLS ≤ 1.2 signal, and
JA4S's ALPN slot is `"00"` for TLS 1.3, which is exactly what the FoxIO spec produces for such
handshakes.

### 3.2 JA4S

New `pub(crate) fn compute_ja4s(transport: Ja4Transport, sh: &ServerHello) -> String` in
`fingerprint/mod.rs`, beside `compute_ja4` (`:292`), reusing `is_grease` (`:111`) and
`crate::analyze::sha256_hex` (the sanctioned hash impls — no new crates, per the header contract at
`fingerprint/mod.rs:1-3`). Shape per the FoxIO spec: `JA4S_a` = transport marker `t|q` + version
(from `supported_versions`-unmasked `sh.version`, same mapping as JA4) + 2-digit extension count +
ALPN first+last char (or `00`); `JA4S_b` = chosen cipher as 4 hex digits; `JA4S_c` = truncated
SHA-256 of the extension codes **in wire order** (server extensions are not sorted — unlike JA4's
client list). **Pin to FoxIO reference vectors at implementation time**; if the network policy
blocks fetching them, document the deviation in-code exactly as the QUIC v2 salt NOTE does
(`quic/mod.rs:165-169`) and verify by round-trip against `testcert::server_hello` builders.

### 3.3 Wiring

`sniff_server_hello` (`tls/mod.rs:711`) grows its return from `(version, cipher, ja3s)` to also
carry `ja4s`, **and gains a `Ja4Transport` parameter** — the current signature takes only the
payload and its decode call site is transport-ungated (`decode/mod.rs:272`), so the JA4S `t`/`q`
marker would otherwise have no source: the TCP path passes `Ja4Transport::Tcp`; the QUIC tracker
(§4.2) computes with `Quic` directly. The caller sets a new `meta.ja4s`; `FlowRecord.ja4s`
absorbs it sticky-first (`model/flow.rs:297-352`), and it becomes Parquet column 32 (§7.2).
Visibility (review-verified): `struct ServerHello` and its fields are module-private today —
they become `pub(crate)` so `fingerprint::compute_ja4s(transport, &ServerHello)` compiles
(sibling module, same crate; no public-API change). GREASE filtering is identical to JA3S's
(collection-time, `tls/mod.rs:641` area) so JA4S matches published databases. JA3S behavior is
unchanged — it still hashes `legacy_version` (`tls/mod.rs:591-592`), while JA4S uses the unmasked
version; the difference is deliberate and spec-correct for both.

---

## 4. Pillar 1b — Keyless QUIC server Initial

### 4.1 Key derivation

Add to `quic/mod.rs`: a `"server in"` sibling of the `"client in"` client-secret label
(`version_params`, `:170`) and `fn derive_server_initial_keys(version: u32, client_dcid: &[u8])`
mirroring `derive_client_initial_keys` (`:218`). Inputs remain the RFC-published salts + the
**client's original DCID** — still zero secrets. **Pin to RFC 9001 §A.3** (the server-Initial
golden vector — the appendix the client side already uses for §A.1); this also motivates finally
pinning the v2 salts to RFC 9369 Appendix A if reachable (existing NOTE at `quic/mod.rs:165-169`).

### 4.2 The bounded DCID tracker (the one new piece of QUIC state)

Server Initial keys derive from the **client's first DCID**, which is only on the client's packet —
so a stateless per-packet parse cannot open a server Initial. New `QuicServerHelloTracker`
following the `TlsCertReassembler` shape, but applying its result **inline** rather than at EOF:

- `observe(&mut self, meta: &mut PacketMeta, frame: &RawFrame)` is called in the streaming loop
  right after `decode_frame`, **before** `stats.observe_packet`/`flow.observe`
  (`analyze/mod.rs:287-303`), because it *mutates* `meta`. Verified feasible: the loop currently
  binds `Ok(ref meta)` — this becomes `ref mut meta`, with no conflict with the `frame` borrow
  (`PacketMeta` owns its data).
- On a client Initial (`identify_quic` → `Initial`, `extract` path already parses the DCID at
  `quic/mod.rs:349-353`): record `(canonical 4-tuple) → (dcid, client_direction)` in a bounded
  map — the canonical `FlowKey` is direction-symmetric, so the client's `Direction` must be
  stored or "reverse direction" is undecidable and every client-Initial retransmit would waste a
  derive+AEAD attempt (review A.14) — `MAX_QUIC_TRACKED = 4096`, new-key-drop at cap,
  **last-wins** on re-insert (handles Retry: the client's post-Retry Initial replaces the DCID,
  and per RFC 9001 §5.2 the server's keys then derive from the *new* DCID).
- On a UDP packet whose direction *opposes* the stored client direction of a tracked tuple and
  that identifies as an Initial:
  `extract_initial_crypto` with the stored DCID and `"server in"` keys (a refactor of
  `extract_initial_client_hello` (`:316`) splitting key-derivation from CRYPTO reassembly), wrap
  the recovered handshake in the synthetic 5-byte record (the established dance,
  `decode/mod.rs:709-713`), `parse_server_hello`, then set `meta.tls_version`, `meta.tls_cipher`,
  `meta.ja3s`, `meta.ja4s` (with the `q` marker) — **without touching `meta.app_proto`** (the flow
  keeps Quic/Http3; the specificity lattice at `model/packet.rs:163` is not disturbed). Precision
  on the reassembler-safety claim (review-corrected): the `TlsCertReassembler`'s ClientHello arm
  gates on `app_proto == Tls && tls_version.is_none()` (`tls/mod.rs:336`) — *not* on transport —
  and stays safe because decode tags QUIC packets `Quic`/`Http3`, never `Tls`; only its buffering
  path checks `Transport::Tcp` (`tls/mod.rs:342`). Setting `tls_version` on a Quic-tagged meta
  therefore cannot perturb it. The entry is then dropped — one parse per connection.
- Because the packet's meta is set *inline*, the values ride the normal
  `PacketMeta → FlowRecord::observe` sticky fold and reach Parquet/UI with **zero** EOF machinery,
  even for flows evicted mid-capture.

Known limits, stated: coalesced server datagrams work when the Initial is the first coalesced
packet (the normal case — `identify_quic` reads the first header; extraction bounds at
`packet_end`, `quic/mod.rs:369`); a ServerHello whose CRYPTO spans multiple server Initials is
missed (same single-datagram contract as the client side, `quic/mod.rs:19`); Version Negotiation
and draft versions still yield nothing (no keys); short-header-only captures are untouched.

---

## 5. Pillar 2 — the entropy substrate

New `EntropySampler` (suggested home: `engine/crates/ppcap-core/src/entropy/mod.rs`, single-word
module + `mod.rs`, matching `forecast/`, `baseline/`):

```rust
pub struct EntropyConfig { pub enabled: bool, pub max_sample_states: usize /*32_768*/,
    pub max_entropy_flows: usize /*4096*/, pub sample_bytes_per_dir: usize /*2048*/,
    pub min_packet_payload: usize /*64*/ }
enum SampleState { Identified, Compressed, Sampling(Box<DirHists>) }   // sentinel-vs-bins
pub struct EntropySampler { /* HashMap<FlowKey, SampleState>, caps */ }
pub struct FlowEntropy { pub c2s_bits: Option<f32>, pub s2c_bits: Option<f32>,
    pub sampled_c2s: u32, pub sampled_s2c: u32, pub compressed: bool }
impl EntropySampler {
    pub fn observe(&mut self, meta: &PacketMeta, frame: &RawFrame);  // frame-borrow seam
    pub fn take(&mut self, key: &FlowKey, initiator: Direction) -> Option<FlowEntropy>; // at flow close
}
```

- `observe` derives the L4 payload from the raw frame via the same helper
  `TlsCertReassembler::observe` uses (`crate::decode::l4_payload`, `decode/mod.rs:322` area), and
  applies the §2.3 state machine: known-`app_proto`/HASSH/STUN evidence ⇒ `Identified` (bins
  freed); container magic on first sampled bytes ⇒ `Compressed`; otherwise fold up to the
  per-direction sample cap, skipping payloads `< min_packet_payload`.
- Entropy math: plain Shannon over the 256-bin histogram, `-Σ p·log2(p)`, pure `f64` folded to
  `f32` at the end — deterministic fixed-order arithmetic over the fixed-size array; no clock, no
  RNG, wasm-safe, zero new deps.
- `take` orients fwd/rev to c2s/s2c using the record's `initiator` (the same orientation source
  `oriented()` uses, `model/flow.rs:403`) and frees the entry.
- `process_flow` calls `take` **before** `classifier.classify` so the classifier's new uplift arm
  (§6.1) can read the values, and stores them on the record for the Parquet writer
  (`entropy_c2s`/`entropy_s2c`, §7.2).

Per-packet cost on identified traffic: one `HashMap` probe hitting an `Identified` sentinel (no
bins, no payload walk beyond the cheap state check). On sampling flows: a bounded fold capped at
2 KiB per direction *per flow lifetime*. The criterion ingest bench (`benches/ingest.rs`) and the
`PHASE0_BUDGET` gates (`metrics/mod.rs:109-116`) are the acceptance check (§10).

---

## 6. Pillar 3 — the detectors

All three follow the uniform detector shape (Params + `detect_*` + evidence bullets + ATT&CK ids +
deterministic sort) and emit into the findings vector at the `analyze/mod.rs:474-500` seam.

### 6.1 `encrypted_unknown_protocol` — high-entropy unidentified channels

**Signal.** A flow that (a) no payload sniffer identified (`observed_app_proto == Unknown`) **and**
carries no SSH fingerprint (`record.hassh`/`hassh_server` both `None` — SSH has no `AppProto`
variant, so without this gate odd-port SSH is a guaranteed false positive), (b) actually exchanged
sampled payload **both ways** (`FlowEntropy.sampled_c2s > 0 && sampled_s2c > 0` — the sampler's
own payload-aware counters; raw `pkts_fwd/rev` would be satisfied by pure ACKs), (c) moved
`≥ min_payload_bytes = 4096` total, (d) measured `entropy ≥ min_entropy_bits = 7.2` in at least
one direction, and (e) is not marked `Compressed` by the sampler (§2.3). 7.2 bits/byte over a
≥ 1 KiB sample is comfortably above natural-language/binary-protocol text (≈ 4–6) and below only
ciphertext/compressed data (≈ 7.6–8.0).

**False-positive guards (the load-bearing part).**
- *Compressed transfers*: the sampler's in-stream container-magic screen (§2.3) — **not**
  `meta.download`, which review showed only fires on HTTP flows that gate (a) already excludes —
  plus exclusion of FileTransfer-classified port pairs.
- *Mid-capture TLS looks unknown*: a TCP flow with no SYN observed (`tcp_flags` OR lacks SYN) is
  excluded — its handshake predates the capture, so "unidentified" is not evidence.
- *Known-encrypted and media ports are exclusions, not reductions*: `category_for_port`
  (`classify/mod.rs:223`) naming the service port with a token that denotes an
  encrypted-by-definition or media protocol — the TunnelVpn rows (wireguard/ipsec/openvpn/pptp/
  l2tp), `https`/`quic`/`dot`/`mqtts`, the TLS email ports, `rtp`/`stun`/`turn`, and the
  RemoteAccess rows (ssh/rdp/vnc/winrm) — **excludes** the flow: high entropy there is the
  protocol working as designed, and "no protocol identifies it" would be self-contradictory for a
  port the table literally names. Ports named with normally-*cleartext* tokens (http, ftp, dns…)
  keep a one-band severity **reduction** — high entropy there is genuinely odd. Unnamed ports are
  full-severity candidates. (Review killed the draft's claim that RTP "never reaches the
  detector": port-naming sets `category`, not `observed_app_proto` — and WebRTC/Zoom media lives
  *outside* the named RTP range anyway, which is what the sampler's STUN gate (§2.3) covers.)

**Two outputs.** (1) Per flow, a new `shape_uplift` arm (`classify/mod.rs:162`), appended **after**
the existing probe → tunnel → beacon arms so no existing verdict changes: still-Unknown +
high-entropy + volume + no-HASSH ⇒ `Category::Anomalous` — its **first producer**; scoring already
handles it (`PTS_ANOMALOUS = 40`, `score/mod.rs:41-51`; Anomalous+external = 55 = Medium, within
philosophy; enrich already maps the category to T1095). Consequence of last-position, stated
plainly: a high-entropy flow ≥ 1 MiB/60 s still classifies TunnelVpn (the tunnel arm fires first),
so the *category* covers the sub-tunnel band — the cross-flow finding below is category-independent
and covers the big-tunnel case; a regression test pins this split. Second stated consequence: the
uplift arms the existing "IOC + c2/anomalous forces Critical" floor (`score/mod.rs:317`) for the
first time — an IOC-listed peer on an anomalous channel now scores Critical/90, which is exactly
the corroboration the floor was written for. The uplift keeps `app_proto_src = None` and classify
stays idempotent (entropy fields are on the record by classify time and never change after close).
(2) Cross-flow, a `BehaviorTracker` fold (`observe_encrypted_channel(client, server, server_port,
bytes, entropy)`, bounded new-key-drop map keyed `(IpAddr, IpAddr, u16)`, client/server resolved
from `record.initiator` — SYN-authoritative for every in-scope TCP flow — falling back to the
smaller-port convention only when SYN-less; the `contact_from_flow` heuristic alone would
misorient high-port services, §6.4) and `detect_encrypted_unknown(tracker,
&EncryptedUnknownParams) -> Vec<Finding>` at EOF: one finding per channel,
`FindingKind::EncryptedUnknownProtocol`, severity **Medium/50** (external dst) / **Low/30**
(internal), evidence bullets carrying entropy per direction, bytes, packet counts, and the
port-screen note; `attack = ["T1573"]` only — review scoped out T1095 on the *finding* (MITRE
defines it as non-application-layer channels like ICMP; the flow-level Anomalous → T1095 mapping
in enrich is pre-existing and untouched). High only via incident corroboration (§2.4).

### 6.2 `missing_sni` — TLS clients that name no server

**Signal.** A **completely parsed** ClientHello with no `server_name` extension. Two parse-quality
gates, both critical:
- `meta.sni == None` does *not* mean SNI-absent — the structural fallback
  (`looks_like_tls_client_hello`, `decode/mod.rs:873`) tags truncated hellos as TLS with no SNI.
- Review found the stronger trap: **both** better parse tiers clamp the extension walk to the
  captured bytes (`.min(body.len())` at `decode/mod.rs:1508` and `fingerprint/mod.rs:170`) and
  report "no SNI" when the walk simply *ran out* — and modern ClientHellos routinely span TCP
  segments (post-quantum key_shares push them past ~1700 B) with randomized extension order, so
  the SNI regularly sits in the un-captured tail. The signal therefore requires the extension
  block to be **complete in the parsed bytes**: full record present (`5 + rec_len ≤
  payload.len()`) and `pos + ext_total ≤ body.len()` (no clamp taken). A clamped or early-broken
  walk emits **no** signal.

Because all three sniff tiers currently collapse into the identical `L7Hint::Tls { sni: None, … }`
shape (`decode/mod.rs:659-683`), decode cannot distinguish them after the fact: `L7Hint::Tls`
gains parse-quality fields (`sni_parsed: bool`, `ech: bool`) set only by the full-fingerprint and
`sniff_tls_client_hello` tiers under the completeness rule above, from which
`meta.tls_sni_absent`/`meta.tls_ech` derive — never from the structural fallback.

**ECH awareness.** The extension walk (`fingerprint/mod.rs:184-222`) gains an arm for
`encrypted_client_hello` (0xfe0d) setting `TlsFingerprints.ech: bool` → `meta.tls_ech` →
`FlowRecord.tls_ech` (sticky-true). An ECH ClientHello legitimately omits/fakes SNI — ECH flows
are **excluded** from `missing_sni` and instead counted in evidence ("N ECH flows observed" on the
posture rollup). Both flags are internal FlowRecord fields (`#[serde(default)]`), **not** Parquet
columns (§7.2 keeps the column budget to 3).

**Detector.** Fold per `(client, server)` in `process_flow` (initiator-oriented, §6.4);
`detect_missing_sni` emits one finding per channel: external server only by default
(`external_only = true`), `min_flows = 2` (one hello can be a stack quirk; a *channel* of them is
a posture), `ignore_ips` allowlist for known SNI-less infrastructure (mirrors the DGA
resolver-allowlist convention). Severity **flat Low/28** — the draft's "no cert observation"
escalation to Medium is **dropped** (review correction A.4: an abbreviated TLS 1.2 *resumption*
handshake legitimately carries no Certificate message, so "no cert parse" is the normal outcome
for exactly the IP-literal/embedded cohort this detector must not misfire on). Higher severity
comes only from incident corroboration. `attack = ["T1573"]`.
Note `check_cert_health` simply skips name-matching when SNI is absent (`tls/mod.rs:126-132`) —
`missing_sni` fills exactly that blind spot without touching cert logic.

### 6.3 `port_protocol_mismatch` — the wire lies about the port, or the port about the wire

Two arms, one finding kind, `FindingKind::PortProtocolMismatch`:

- **TLS on an uncommon port** (evasion-shaped, but often benign): `observed_app_proto ∈ {Tls}` and
  the service port is **not named at all** by `category_for_port` (`classify/mod.rs:223`) and not
  in `extra_allowed_ports` (param, default: 9443 plus the STARTTLS trio 25/110/143). Review
  replaced the draft's hand-rolled `COMMON_TLS_PORTS` const — which already missed 8883 (mqtts),
  5061 (SIP-TLS), 5986 (WinRM-HTTPS), and 3389 (RDP's TLS upgrade), all ports this codebase
  itself treats as TLS-bearing — with the rule *a port the table names is by definition not
  uncommon for this engine*. Severity **Info/10** alone — this is context, not an alarm — raised
  to **Low/30** when the destination is external and the SNI is absent too.
- **Established non-TLS on 443** (tunnel-shaped): TCP service port 443, **SYN observed and
  connection established** (`tcp_established()`, `model/flow.rs:446` — the gate that kills the
  mid-capture-TLS false positive), payload exchanged, yet `observed_app_proto == Unknown`.
  Evidence includes the flow's entropy when sampled (§5 tracks these flows automatically — port
  443 with an unidentified first payload packet is in-scope for the sampler). An `ignore_ips`
  allowlist ships on this arm too: **OpenVPN-over-TCP/443 is the standard firewall-traversal
  deployment**, and a sanctioned VPN gateway moving ≥ 1 MiB would otherwise hit High on every
  capture — allowlist once, per the DGA-resolver convention. Severity **Medium/48**; **High/65**
  when `bytes ≥ high_bytes = 1 MiB` (a used tunnel, not a probe — the WeakTls-style
  specific-signal exception, §2.4). UDP/443 is **excluded**: a mid-capture QUIC flow has no long
  header to identify (`quic/mod.rs:97-100`), so "not identified as QUIC" is not evidence there.

Fold per `(client, server, server_port)` (initiator-oriented, §6.4); `attack = ["T1571"]`
(+ `"T1573"` on the 443 arm). `T1571` is added to `technique_name` (`detect/mod.rs:3989`) and both
UI technique tables (§12). Neither arm assigns `app_proto_src` or any category — classification is
untouched, so the heuristic-C2 cap and the evasive-beacon `is_named` veto (`score/mod.rs:291-307`,
`analyze/mod.rs:691`) keep their exact semantics.

### 6.4 Client/server orientation for the new folds

The existing `contact_from_flow` convention (numerically-smaller port = server,
`detect/mod.rs:1998`) misorients exactly the traffic ETA targets — services on high/unusual ports,
where the server port can exceed the client's ephemeral port roughly half the time. All three new
detector folds and the `tls_servers` rollup therefore resolve client/server/server_port from
**`record.initiator`** (SYN-locked and authoritative for every SYN-gated TCP flow in scope,
`model/flow.rs:157-162,256-268` — the same source `oriented()` uses), falling back to the
smaller-port convention only for SYN-less flows. `contact_from_flow` itself and every existing
detector are untouched.

---

## 7. Data model & schema

### 7.1 Three new `FindingKind` variants — every exhaustive site

Appended **after** `TrafficAnomaly` (ordinal stability is load-bearing — `f.kind as u8` in the
chain step key, `detect/mod.rs:4043`): `EncryptedUnknownProtocol`, `MissingSni`,
`PortProtocolMismatch`. Compiler-forced Rust arms (5 sites each):

| Site | `encrypted_unknown_protocol` | `missing_sni` | `port_protocol_mismatch` |
|---|---|---|---|
| `model/finding.rs` `as_str` (:88) | `"encrypted_unknown_protocol"` | `"missing_sni"` | `"port_protocol_mismatch"` |
| `detect/mod.rs` `stage_ordinal` (:3795) | C2 stage (same ordinal as `Beacon`) | C2 stage | C2 stage |
| `detect/mod.rs` `stage_label` (:3826) | `"Command & Control"` | `"Command & Control"` | `"Command & Control"` |
| `detect/mod.rs` `kind_phrase` (:3857) | "ran a sustained high-entropy channel no protocol identifies" | "initiated TLS without naming a server" | "spoke the wrong protocol for the port" |
| `report/mod.rs` `kind_label` (:598) | `"Encrypted Unknown Protocol"` | `"TLS Without SNI"` | `"Port / Protocol Mismatch"` |

TypeScript (3 sites + union): `types.ts` FindingKind union (:261), `KIND_META`
(`findingKinds.ts:42` — labels above + icons e.g. `Lock`, `EyeOff`, `Shuffle`), and `KIND_STAGE`
in **both** `killChain.ts:9` and `IncidentHero.tsx:12` (acknowledged duplicate maps — edit both).
`_`-fallback sites deliberately left: `victims_of`, `handoff_weight` (excluded from pivoting),
`campaign_infra_key` (**not** a campaign key in v1 — the ACR plan's documented conservatism;
promoting `encrypted_unknown_protocol` dst clusters to infra keys is an open question, §15),
`sigma_category` (`export/mod.rs:482`, `_ => "firewall"` acceptable).

### 7.2 Parquet flow schema v10 → v11 (+3 columns) — the first plan to cross this line

Prior plans kept `FLOW_PARQUET_VERSION` untouched; ETA is per-flow metadata and needs columns.
One version bump on this branch (10 → 11), columns appended in canonical order after `ioc`:

| # | Column | Arrow type | Source |
|---|---|---|---|
| 32 | `ja4s` | Utf8, nullable, **dict-encoded** (`dict_cols`, `columnar/mod.rs:223`) | `FlowRecord.ja4s` (sticky, TCP §3 / QUIC §4) |
| 33 | `entropy_c2s` | Float32, nullable | §5 (`None` = identified flow / not sampled) |
| 34 | `entropy_s2c` | Float32, nullable | §5 |

The full lockstep — **14 files** (the draft's 10-file list missed four column-count pin sites the
review found, worst of which breaks UI ingest at *runtime*, not just CI): `columnar/schema.rs`
(`flow_arrow_schema` + `flow_columns_in_order` — the `[&'static str; N]` type forces the count —
+ `FLOW_PARQUET_VERSION = 11`), `columnar/mod.rs` (Builders struct/new/finish/append +
`dict_cols` + the in-file 31-column assert around `:543`), `sql/schema.sql` (view SELECT list;
old Parquet parts read as NULL via `union_by_name`), `tests/schema_drift.rs` (hard-coded 31 → 34),
**`tests/columnar_roundtrip.rs`** (asserts `fields().len() == 31` at `:189` + round-trip values
for the three new columns), `ppcap-wasm/src/lib.rs` `FlowDto` + `from_record` (must mirror the
writer exactly), `ui/src/lib/query/flow_columns.json` (columns + `flow_schema_version: 11`),
`ui/src/lib/query/schema.ts` (`FLOW_COLUMN_TYPES` + version const; column comments feed the
NL→SQL prompt for free), **`ui/src/lib/query/schema.test.ts`** (`toHaveLength(31)` → 34),
**`ui/src/lib/query/arrow.ts`** (`buildFlowArrowTable` materializes exactly the current 31
columns as typed arrays, and `buildFlowInsertSql` generates `INSERT INTO flow SELECT
<FLOW_COLUMNS> FROM flow_ingest` — with a 34-entry `FLOW_COLUMNS` and a 31-column staging table
**every UI capture load fails at runtime**; new typed-array builders required),
**`ui/src/lib/query/arrow.test.ts`** (fixture rows + field-set assert), `ui/src/types.ts`
(FLOW_COLUMNS array + RawFlowRow + WasmFlow + FlowRow), `ui/src/lib/data.ts` (both mappers),
`ui/src/lib/flowsCsv.ts`. `OrientedFlow` + both `oriented()` arms (`model/flow.rs:32,403`) gain
the entropy pair (ja4s is direction-independent).

New non-column fields: `PacketMeta { ja4s: Option<String>, tls_sni_absent: bool, tls_ech: bool }`
(integer/bool/String only — `Eq` derive preserved; every exhaustive test literal constructor gets
the three fields, a mechanical sweep) and `FlowRecord { ja4s, tls_sni_absent, tls_ech,
entropy_c2s: Option<f32>, entropy_s2c: Option<f32> }`, all `#[serde(default)]`.

### 7.3 `Summary.tls_servers` rollup

```rust
pub struct TlsServerPosture { pub server: String, pub port: u16,
    pub tls_version: Option<String>, pub tls_cipher: Option<String>,
    pub ja3s: Option<String>, pub ja4s: Option<String>, pub sni: Option<String>,
    pub flows: u64, pub bytes: u64, pub clients: u64 }
```

Folded in `observe_scored_flow` (`stats/mod.rs:617`) for flows carrying any server-side TLS field;
server side resolved from `record.initiator` with the smaller-port fallback (§6.4 — the draft's
smaller-port-only keying would fragment a high-port server into bogus rows). Bounded map keyed
`(IpAddr, u16)`, cap 4096 new-key-drop, per-server client set capped at 64 (count saturates);
`finish()` projects `TOP_K_TLS_SERVERS = 50` sorted flows desc → bytes desc → key asc (the
`bytes` accumulator exists precisely so this tie-break is computable — review caught the draft
sorting on a field the struct didn't carry — and analysts want it on the card anyway).
`Summary.tls_servers: Vec<TlsServerPosture>` with `#[serde(default)]` (the `encrypted_dns`
precedent, `summary.rs:255`). This also fixes the mapped gap that
`ja3s`/`tls_version`/`tls_cipher` reach flows but are aggregated **nowhere**.

---

## 8. Analyze pipeline & scoring wiring

Streaming-loop order (all inside the existing borrow scope, `analyze/mod.rs:287-303`):
`decode_frame` → **`quic_tracker.observe(&mut meta, &frame)`** (mutates meta, §4.2) →
`cert_reasm.observe` → `body_carver.observe` → **`entropy_sampler.observe(&meta, &frame)`** →
`stats.observe_packet` → `flow.observe`.

`process_flow` order (`analyze/mod.rs:669-750`): **`entropy_sampler.take` → set
`record.entropy_*`** → `classifier.classify` (new Anomalous arm reads them) → scan uplift →
existing tracker folds + **`observe_encrypted_channel` / `observe_missing_sni` /
`observe_port_mismatch`** (all three read only fields already in scope at the
`observe_ja3` call site, `:705-707`) → enrich → `score_flow` → stats → Parquet → visitor.

Detector seam (`:474-500`): three `findings.extend(detect_*(&tracker, &cfg.*))` lines, before
baseline/forecast, and therefore before `stats.apply_findings` (`:628`) — cards, incidents, and
chains come free. `PipelineConfig` gains `encrypted_unknown: EncryptedUnknownParams`,
`missing_sni: MissingSniParams`, `port_mismatch: PortMismatchParams`, `entropy: EntropyConfig`
(all default-enabled).

Scoring: **no new `score/mod.rs` machinery.** Findings carry detector-chosen severity/score (the
`detect_weak_tls` pattern); flow-level effects ride the existing exhaustive `Category` match
(Anomalous is already scored, `score/mod.rs:152,317`) and the untouched IOC path — `bad_ja4s`
folds into the existing `fm.fingerprint` flag (§9), sharing the single +35 fingerprint term by
design (documented: it is still "tls fingerprint on threat feed", and the OR-not-add behavior is
the mapped current semantics, `enrich/mod.rs:692`).

---

## 9. Threat intel, Time Machine, and exports (JA4S as a first-class indicator)

Follows the ja3/ja4 chain verbatim (all sites enumerated by the mapping):
`ThreatFeedFile.bad_ja4s: Vec<String>` (`enrich/mod.rs:205-207` pattern) → lowercased `HashSet` +
labels (`:314-316`) → `matches_ja4s` (`:450` pattern) → `fingerprint_label` order ja3 → ja4 → ja4s
(`:461`) → `Enricher.enrich` sets `ja4s_ioc`, OR-ed into `FeedMatch.fingerprint` (`:688-694`).
Builtin set (`data/builtin_fingerprints.json`): one test-sentinel `ja4s` entry only (mirroring the
all-zeros JA3 sentinel convention; real known-bad JA4S seeding is a data task, §16).

**`FingerprintHit` grows a `ja4s` field** (review A.7 — without it the whole chain below is
plumbed to nothing): `FingerprintHit { ja3, ja4, label }` (`model/summary.rs:135`) is the only
carrier from flows to `ip_threats[].fingerprints`, and the STIX/MISP exporters and the Time
Machine harvest all iterate it reading only `fp.ja3`/`fp.ja4` — a `bad_ja4s` match would set the
label but export/index nothing. So: `FingerprintHit.ja4s: Option<String>` (`#[serde(default)]`),
populated in the stats fold (`stats/mod.rs:656-664`) from `record.ja4s`, read by the export loops
and `build_index`, mirrored in `ui/src/types.ts`.

Time Machine: `IndicatorKind::Ja4s` (`timemachine/mod.rs:34-43`, serde lowercase, appended last),
harvested from `Summary.tls_servers` + IOC-matched fingerprints, rescan via `matches_ja4s`; SQL
`indicator_t` enum gains `'ja4s'` (`sql/schema.sql:13` — DDL text only, no stored data migration:
the schema is emitted fresh by `init-db`). Back-compat, stated precisely (review-corrected): the
enum serializes by lowercase *name*, so old index files parse fine under the new engine regardless
of variant position — appending last preserves only `derive(Ord)` sort stability. The real
asymmetry is the reverse direction: an **old** engine reading a **new** index containing `"ja4s"`
fails the whole-file serde parse (`from_json_str` has no unknown-variant tolerance,
`timemachine/mod.rs:96-99`) while `INDEX_SCHEMA_VERSION` stays 1 — accepted and documented,
matching the `ThreatFeedFile` precedent for new feed keys.

Export: STIX pattern `x-tls-fingerprint:ja4s = '…'` (`export/mod.rs:132-151` block) and a MISP
attribute following the existing bare-`"ja4"`-type precedent (`:327-331`). Docs: the
indicator-class lists in `docs/time-machine.md:79-81,114-115` and `docs/batch-triage.md:53` are
extended in the same change.

---

## 10. Performance, Determinism & Invariants (explicit)

- **Bounded memory, accounted:** EntropySampler ≈ 7 MiB worst-case (4 MiB histograms + 2–3 MiB
  identification-sentinel map, §2.3); QUIC DCID tracker 4096 × (≤ 20 B DCID + client direction +
  key) ≈ 0.3 MiB; three detector maps + `tls_servers` map: new-key-drop at 4096–8192 entries with
  short string values ≈ 1–2 MiB combined; per-flow additions: one sticky `Option<String>` +
  2 `f32` + 2 bools ≈ negligible at the 32 Ki flow cap. Total well inside the ≤ 64 MiB
  `PHASE0_BUDGET` (`metrics/mod.rs:109-116`); the in-tree heap assert (`golden_e2e.rs:128`) and
  the `#[ignore]`d 100k budget test are the gates.
- **Throughput:** entropy folding touches only unidentified-first-payload flows and caps at 2 KiB
  per direction per flow; JA4S/ALPN/ECH parsing is a few extra branches inside already-running
  parsers; the QUIC tracker does map work only on long-header UDP. Acceptance: criterion ingest
  bench unchanged within noise; ≥ 250k pkt/s floor holds.
- **Single pass, streaming:** no second pcap read; all EOF work is pure transforms over bounded
  state (the `TlsCertReassembler` contract).
- **C-compiler-free & wasm-safe:** zero new crates; hashes reuse vendored MD5/SHA-256; `f64`/`f32`
  math only; no `Instant`/fs in any new code on the `run_source_visiting` path; ppcap-wasm builds
  ppcap-core with `default-features = false` — nothing ETA adds is feature-gated behind `online`.
- **Deterministic:** fixed-order histogram math; all candidate emissions sorted with total-order
  tie-breaks (severity desc → score desc → key asc, the house pattern); byte-identical outputs for
  identical inputs; gen fixtures seed-reproducible.
- **Never-panic:** every new parser bounds-checked `.get()`/`checked_*`, `Option` returns,
  malformed input degrades to "no signal" (release profile is `panic = "abort"`).
- **Keyless guarantee:** no import of `tls::{decrypt, keylog, decrypted_http, http2}` from any
  ETA code path — the with-keys quarantine (§2.1) is unchanged and review-checked.
- **Schema:** exactly one `FLOW_PARQUET_VERSION` bump (10 → 11) with the full lockstep of §7.2;
  `schema_drift.rs` updated in the same commit; Summary additions are `#[serde(default)]`
  additive; `SCHEMA_VERSION` (analysis output, `analyze/mod.rs:44`) is **not** bumped — all
  Summary/Finding changes are additive.
- **Privacy:** derived values only — fingerprint strings, entropy scalars, boolean flags; no
  payload bytes, no cert DER, no SNI values beyond what already ships; Safe Share (`sanitize/`)
  is unaffected (it operates on packets, and ETA adds no new payload retention for it to scrub).

---

## 11. CLI surface

ETA is on by default (params default-enabled), so `ppcap analyze <cap>` gains the new findings and
columns with no flag. Added, following the `--no-forecast` precedent:

- **`analyze --no-encrypted-analysis`** — sets `encrypted_unknown.enabled = missing_sni.enabled =
  port_mismatch.enabled = entropy.enabled = false`. Fingerprint extraction (JA4S, QUIC server
  metadata) is *metadata, not detection* and stays on, exactly as JA3/JA3S have no flag. (The
  draft's `--no-eta` was dropped in review: on a CLI, "ETA" universally reads as
  estimated-time-remaining, and the precedent flag is the self-describing `--no-forecast`.)
- **Stderr summary** — `encrypted-traffic: N finding{s}` (unless `--quiet`), mirroring the
  `forecast:` line and un-confusable with a progress ETA.
- Drive-by (mapped as stale): the `gen --scenario` help string (`cli.rs:144`) is updated to list
  all scenarios including the new one (§13) — it currently omits `attack-chain`/`traffic-spike`.
- CLI signatures are additive-only per the stability contract (`cli.rs:6-9`); one
  `Cli::try_parse_from` test per new flag.

---

## 12. WASM + UI surface

**Rides free:** the three finding kinds flow through `summary.findings` into the dashboard,
FindingsView, incidents/chains, and every export (CSV/STIX/MISP/CEF/Sigma/HTML) with no UI export
code — the wasm bridge serialises `AnalysisOutput` whole.

**Compiler-forced TS:** FindingKind union + `KIND_META` + both `KIND_STAGE` copies (§7.1);
`T1571` added to `attack.ts` TECHNIQUES **and** `killChain.ts` TECHNIQUE_NAME (separate,
partially-overlapping tables — both).

**Flow surface (the §7.2 lockstep):** `ja4s` chip beside JA3S in the FlowsTable proto cell
(`FlowsTable.tsx:173-262`), `TLS JA4S` + entropy rows in FlowDetail's L7 section
(`FlowDetail.tsx:387-441`), `ja4s` in the FlowsView filter haystack, CSV, and DuckDB (the NL→SQL
prompt picks the new columns up from `FLOW_COLUMN_TYPES` comments automatically).

**New surfaces:**
- `TlsServersCard` on the Dashboard (the `EncryptedDnsCard` pattern: `s.tls_servers ?? []`,
  hide-when-empty, top rows with version/cipher/JA4S chips, onJump pivot to Flows filtered by
  server IP).
- `CertHealthPanel` (`components/triage/CertHealthPanel.tsx:66`) widens its filter to
  `missing_sni` and `port_protocol_mismatch` only — both are TLS-posture stories, and it already
  owns the "TLS POSTURE" label. `encrypted_unknown_protocol` is **not** filed there (review A.13:
  it is by construction *not* TLS — an analyst triaging "TLS issues" would misread an
  unknown-cipher C2 candidate as a certificate problem); it surfaces through the generic
  findings/incident surfaces plus a small "Anomalous channels" tile beside `TlsServersCard`.
- Drive-by (mapped as built-but-unrendered): `IpThreat.fingerprints` (known-bad JA3/JA4 hits,
  `types.ts:161-165`) rendered in the DetailFlyout identity section.
- Two bundled SQL samples (`lib/query/samples.ts`): JA4S prevalence by server
  (`SELECT ja4s, count(*) …`), and high-entropy unknown flows
  (`WHERE entropy_c2s >= 7.2 AND app_proto = ''`); both must pass the `guardSql` sample test.

---

## 13. Testing

**Generator fixtures (closing mapped gaps — gen emits no ServerHello/QUIC/high-entropy today):**
- `gen/frames.rs`: `tls_server_hello_payload(version, cipher, alpn)` +
  `tls_server_flight_payload` (ServerHello + minimal self-signed Certificate message — enough to
  exercise the reassembler, JA4S, and cert-health together); a deterministic high-entropy payload
  builder (SplitMix64 byte stream — the mapped warning stands: existing constant-byte payloads
  (0x5A/0x17) measure ≈ 0 bits and must **not** be reused as "encrypted" fixtures).
- New `Scenario::EncryptedAnomaly` (token `encrypted-anomaly`, alias `eta`): an internal client
  running (a) a high-entropy both-ways TCP channel on an unnamed port to an external peer, (b) a
  no-SNI TLS ClientHello channel, and (c) an established non-TLS-on-443 exchange. Touches
  `from_str_opt`/`all()`/`weights_for`/the `all().len()` assertion (8 → 9) + the CLI help string.
- QUIC fixtures ride the existing `quic::testkit` (`quic/mod.rs:423`): add a
  `protected_server_initial` inverse builder next to `protected_initial`.

**Engine tests:**
- `fingerprint`: JA4S unit vectors (FoxIO reference or documented round-trip fallback, §3.2);
  ECH-flag and absent-SNI-flag parsing; GREASE filtering on the server list.
- `tls`: server-ALPN parse (present/absent/1.3-empty); `sniff_server_hello` tuple extension.
- `quic`: `derive_server_initial_keys` pinned to **RFC 9001 §A.3**; tracker round-trip
  (client Initial → server Initial → meta fields set); Retry re-key (last-DCID-wins); cap
  behavior; coalesced-datagram first-packet case.
- `entropy`: uniform-random ≈ 8.0, ASCII ≈ 4–5, constant = 0.0; per-direction caps; sentinel
  behavior (identified flows never allocate bins); the late-identification drops for
  app_proto/HASSH/STUN; the compression-magic screen; the `log2(n)` small-sample property
  documented in a test name.
- `detect`: per-detector unit tests — fires on the crafted candidate, and **silent on the
  review-derived FP roster**: mid-capture no-SYN flows, ECH flows, a *segment-split ClientHello
  whose SNI lies beyond the captured bytes* (must emit no `tls_sni_absent`), a TLS 1.2
  *resumption* channel (no Certificate message ⇒ still Low, no escalation), a WebRTC/Zoom-style
  STUN-then-SRTP flow on a non-RTP-range port, SSH on 2222 (HASSH present ⇒ excluded),
  WireGuard/OpenVPN/IPsec on their named ports (excluded), compressed transfers (magic screen),
  allowlisted ports/IPs, and one-way/ACK-only flows; determinism of emission order.
- `classify`: the uplift-precedence regression — a ≥ 1 MiB/60 s high-entropy Unknown flow stays
  `TunnelVpn` (tunnel arm first) while the sub-tunnel high-entropy flow becomes `Anomalous`;
  idempotency holds with the new arm.
- Full-pipeline e2e (`tests/eta_e2e.rs`): `gen EncryptedAnomaly → analyze::run` raises all three
  finding kinds with correct attribution and card uplift; `--no-encrypted-analysis` silences all
  three and nulls
  the entropy columns; benign `Mixed` still raises nothing (the FP regression convention,
  `analyze/mod.rs:2106`); Parquet round-trip of the three new columns; `schema_drift` updated.
- Perf: criterion ingest bench before/after; heap assert already in `golden_e2e`.

**UI:** `tsc -b`, Vitest (new KIND_META/stage entries, TlsServersCard, flyout fingerprints,
schema fixture 34/version 11, samples-pass-guard), `vite build`. CI runs the wasm build
(`build:wasm`) and Playwright per the existing pipeline; Tauri build stays CI-only, per the
BBL/PAD "not verifiable in this sandbox" precedent.

---

## 14. Phased milestones (each independently shippable)

- **M1 — JA4S + server ALPN (TCP) + schema v11.** §3 + the §7.2 lockstep (`ja4s` column; the
  entropy columns are added in the same bump but written as NULL until M3). *Value: modern server
  fingerprints on every TCP TLS flow, queryable and displayed.*
- **M2 — Keyless QUIC server Initial.** §4. *Value: QUIC flows gain
  version/cipher/JA3S/JA4S — the QUIC server blind spot closes.*
- **M3 — Entropy substrate + `encrypted_unknown_protocol`.** §5 + §6.1 (+ the high-entropy gen
  fixtures). *Value: custom-crypto C2 candidates surface with explainable evidence;
  `Category::Anomalous` becomes real.*
- **M4 — Posture detectors.** §6.2 + §6.3 (+ ECH flag). *Value: missing-SNI and port/protocol
  mismatch findings with strong FP guards.*
- **M5 — JA4S intelligence.** §9 (feed key, Time Machine indicator, STIX/MISP, doc-list updates).
  *Value: JA4S joins the IOC lifecycle end-to-end, including retro-rescan.*
- **M6 — Surfacing.** §12 (TlsServersCard, panel widening, flyout fingerprints, SQL samples) +
  `docs/encrypted-traffic-analysis.md` user doc (time-machine.md shape) + README Features bullet.
  *Value: the analyst-facing layer, and the docs debt paid.*

---

## 15. Risks, Edge Cases & Open Questions

| Risk / case | Mitigation |
|---|---|
| **Compressed ≈ encrypted entropy** | In-sampler container-magic screen on the first sampled bytes of each direction (§2.3) + FileTransfer port exclusion; threshold 7.2 over ≥ 1 KiB samples; Medium cap alone. Residual: unrecognized proprietary compression can still flag — the evidence bullets make the human call cheap. |
| **Mid-capture flows look "unknown"** | SYN/established gates on both the entropy detector and the 443 arm (§6.1, §6.3); UDP/443 excluded outright. |
| **Encrypted-by-design services on unnamed ports** (WebRTC/Zoom media outside the RTP range; SSH on 2222) | STUN-magic and HASSH late-identification drops in the sampler (§2.3) + the HASSH candidate exclusion (§6.1). Residual: a media stack that skips ICE on an unnamed port can still flag — evidence names the port and entropy so triage is fast. |
| **Sanctioned VPNs / encrypted services on their named ports** | Port-named encrypted/media tokens are full exclusions, not reductions (§6.1); OpenVPN-over-TCP/443 handled by the 443-arm `ignore_ips` allowlist (§6.3). |
| **TLS 1.2 session resumption has no Certificate** | The "no cert" escalation was removed from `missing_sni` (§6.2) — resumption channels emit flat Low at most, and only as part of a ≥ `min_flows` channel. |
| **Segment-split / clipped ClientHellos** | `tls_sni_absent` requires the extension block complete in the parsed bytes — a clamped walk emits nothing (§6.2); split-CH fixture in the silent-cases tests (§13). |
| **High-entropy long tunnels split across two verdicts** | Stated and pinned by test (§6.1): the *category* for a ≥ 1 MiB/60 s high-entropy flow stays TunnelVpn (arm order), while the cross-flow `encrypted_unknown_protocol` finding covers it — the finding, not the category, is the alert surface. |
| **ECH growth erodes `missing_sni`** | ECH is detected, excluded, and counted — as ECH adoption grows the detector's scope shrinks honestly rather than false-positiving (§6.2). |
| **JA4S spec drift / vector availability** | Pin to published vectors; if unfetchable, the in-code NOTE + round-trip convention (`quic/mod.rs:165-169` precedent) and a follow-up to pin (§16). |
| **QUIC tracker misses (multi-datagram CH, VN, drafts, short-header-only)** | Stated limits (§4.2); the fields simply stay NULL — no wrong data. Retry handled by last-DCID-wins. |
| **PacketMeta literal sweep** | Adding 3 fields touches every exhaustive test constructor — mechanical, compiler-driven, called out in the checklist. |
| **Schema-bump blast radius** | The 14-file lockstep is enumerated (§7.2), CI-guarded from both sides (`schema_drift.rs` + `schema.test.ts` + `columnar_roundtrip.rs` + `arrow.test.ts`), and the one runtime-only site (`arrow.ts` ingest SQL) is explicitly called out — partial updates cannot pass CI or load a capture. |
| **Double-reporting with existing detectors** | `encrypted_unknown_protocol` requires `observed_app_proto == Unknown`, so it cannot co-fire with TLS-based kinds on the same flow; beacon/exfil remain byte/timing-based and complementary (an encrypted-unknown *beaconing* channel firing both kinds is correct — incident correlation escalates it by design). |
| **`tls_servers` rollup on NAT/proxies** | Keyed by (server, port) — a NAT'd server aggregates clients honestly; client-count saturation at 64 is displayed as "64+". |

**Open questions for review:** (1) should `encrypted_unknown_protocol` external destinations mint
campaign infra keys (`campaign_infra_key`), or stay out per ACR conservatism? — v1: out. (2)
`min_entropy_bits` default 7.2: expose as a CLI flag now or post-feedback (PAD exposed `--forecast-z`
only after the fact)? — v1: params-only. (3) should ECH presence itself be an Info-level finding
(visibility signal for defenders) or rollup-only? — v1: rollup-only.

---

## 16. Follow-ups (net-new scope, deliberately out)

- **SPLT-style features**: a bounded first-16 per-flow packet-length/direction/gap array (≈ 6 B ×
  16 × 32 Ki flows ≈ 3 MiB) feeding derived scalars (burst count, first-packet sizes,
  interactive-vs-bulk shape) — the Cisco-ETA-style behavioral layer, kept out of v1 to avoid
  persisting vectors.
- **JA4X / cert enrichment**: serial, SPKI key type/size, issuer string, cert SHA-256 (the
  `_spki`/`_serial` fields `cert.rs:51,56` already skip past) → JA4X and richer cert hygiene.
- **SSH posture**: retain the `SSH-` banner + host-key algorithms (read-and-discarded at
  `ssh/mod.rs:115`), SSH-1 hygiene finding, HASSH feed matching (`bad_hassh`).
- **JA4S baseline novelty**: first-seen server fingerprint per host as a BBL deviation dimension
  (the `observe_ja3` template, `detect/mod.rs:892`).
- **Real known-bad JA4S seeding** for `builtin_fingerprints.json` (data curation, not code).
- **QUIC v2 salt golden-vector pinning** (RFC 9369 Appendix A) when network policy allows.
- **Encrypted-mix dashboard card** (share of TLS/QUIC/unknown-encrypted bytes) if analysts ask.

---

## 17. File-by-File Change Checklist

| File | Add / Modify | Reason |
|---|---|---|
| `engine/crates/ppcap-core/src/fingerprint/mod.rs` | Modify | `compute_ja4s` + ECH (0xfe0d) arm + `TlsFingerprints.ech` + absent-SNI signal + tests |
| `engine/crates/ppcap-core/src/tls/mod.rs` | Modify | `ServerHello.alpn` parse + `pub(crate)` visibility + `sniff_server_hello` tuple & `Ja4Transport` param + JA4S call + testkit server-flight builder |
| `engine/crates/ppcap-core/src/quic/mod.rs` | Modify | `"server in"` params + `derive_server_initial_keys` + extract refactor + RFC 9001 §A.3 vector + testkit inverse |
| `engine/crates/ppcap-core/src/quic/` (new file or `mod.rs`) | **Add** | `QuicServerHelloTracker` (bounded DCID map, inline meta mutation) |
| `engine/crates/ppcap-core/src/entropy/mod.rs` | **Add** | `EntropySampler` + `SampleState` sentinel machine + STUN/HASSH/magic screens + `EntropyConfig` + `FlowEntropy` + unit tests |
| `engine/crates/ppcap-core/src/decode/mod.rs` | Modify | `L7Hint::Tls` parse-quality fields (`sni_parsed`, `ech`) + thread `ja4s`/`tls_sni_absent`/`tls_ech` onto `PacketMeta` |
| `engine/crates/ppcap-core/src/model/packet.rs` | Modify | 3 new `PacketMeta` fields (+ every test literal constructor) |
| `engine/crates/ppcap-core/src/model/flow.rs` | Modify | `FlowRecord` fields + sticky folds + `OrientedFlow` entropy pair + `oriented()` arms |
| `engine/crates/ppcap-core/src/model/finding.rs` | Modify | 3 `FindingKind` variants + `as_str` arms |
| `engine/crates/ppcap-core/src/model/summary.rs` | Modify | `TlsServerPosture` + `Summary.tls_servers` + `FingerprintHit.ja4s` (all `#[serde(default)]`) |
| `engine/crates/ppcap-core/src/classify/mod.rs` | Modify | Anomalous entropy uplift arm in `shape_uplift` + consts + tests |
| `engine/crates/ppcap-core/src/detect/mod.rs` | Modify | 3 tracker maps + observers + candidates + `detect_*` fns + stage/phrase arms + `T1571` in `technique_name` |
| `engine/crates/ppcap-core/src/stats/mod.rs` | Modify | `tls_servers` bounded map (with bytes) + fold + `finish()` projection + `FingerprintHit.ja4s` in the rollup fold |
| `engine/crates/ppcap-core/src/analyze/mod.rs` | Modify | tracker/sampler wiring at both seams + `PipelineConfig` params + detector extends |
| `engine/crates/ppcap-core/src/enrich/mod.rs` | Modify | `bad_ja4s` feed key + `matches_ja4s` + label + `FeedMatch` ride |
| `engine/crates/ppcap-core/data/builtin_fingerprints.json` | Modify | ja4s test sentinel |
| `engine/crates/ppcap-core/src/timemachine/mod.rs` | Modify | `IndicatorKind::Ja4s` (appended) + harvest + rescan |
| `engine/crates/ppcap-core/src/export/mod.rs` | Modify | STIX/MISP ja4s indicator mapping |
| `engine/crates/ppcap-core/src/report/mod.rs` | Modify | 3 `kind_label` arms (+ tls_servers table if the HTML report grows one — optional, M6) |
| `engine/crates/ppcap-core/src/columnar/{schema,mod}.rs` · `sql/schema.sql` | Modify | v11 + 3 columns + builders + dict + view + `indicator_t 'ja4s'` |
| `engine/crates/ppcap-core/src/gen/{mod,mix,frames}.rs` | Modify | `Scenario::EncryptedAnomaly` + server-flight/high-entropy builders + aliases/weights/assertion |
| `engine/crates/ppcap-core/tests/{schema_drift,columnar_roundtrip,eta_e2e}.rs` | Modify / **Add** | 34-column guards + new-column round-trip · gen→analyze e2e for all three kinds + `--no-encrypted-analysis` |
| `engine/crates/ppcap-cli/src/cli.rs` | Modify | `--no-encrypted-analysis` + stderr summary + parse test + stale `--scenario` help fix |
| `engine/crates/ppcap-wasm/src/lib.rs` | Modify | `FlowDto` + `from_record` (+3 fields) |
| `ui/src/types.ts` · `lib/findingKinds.ts` · `lib/killChain.ts` · `cockpit/IncidentHero.tsx` | Modify | union + KIND_META + both KIND_STAGE + T1571 name |
| `ui/src/lib/query/{flow_columns.json,schema.ts,schema.test.ts,arrow.ts,arrow.test.ts}` · `lib/data.ts` · `lib/flowsCsv.ts` · `components/{FlowDetail,flows/FlowsTable}.tsx` · `views/FlowsView.tsx` | Modify | the §7.2 lockstep (incl. `buildFlowArrowTable`/`buildFlowInsertSql` typed-array builders — runtime-breaking if missed) + display |
| `ui/src/cockpit/TlsServersCard.tsx` (+test) | **Add** | posture rollup card + the "Anomalous channels" tile (§12) |
| `ui/src/components/triage/CertHealthPanel.tsx` · `components/DetailFlyout.tsx` · `lib/query/samples.ts` · `lib/attack.ts` | Modify | panel widening · fingerprints render · 2 SQL samples · T1571 |
| `docs/encrypted-traffic-analysis.md` | **Add** (M6) | User-facing doc, time-machine.md shape |
| `docs/time-machine.md` · `docs/batch-triage.md` · `README.md` | Modify (M5/M6) | indicator lists + Features bullet |
| **NOT touched** | — | `tls/{decrypt,keylog,decrypted_http,http2}.rs` (the with-keys quarantine) · `forecast/*`, `baseline/*` core logic · `carve/*`, `sanitize/*` · `flow/mod.rs` table mechanics · `score/mod.rs` constants (no new PTS/caps) · `model/{category,severity}.rs` enums · `relay/*`, `supabase/*` |

---

## Guarantees, to be verified by tests

- **Keyless** — the analyze pass imports nothing from the decryption modules; every new signal is
  derived from handshake plaintext, public Initial protection, or wire statistics.
- **Detection** — the crafted fixtures raise exactly the three new kinds at the stated severities
  with correct src/dst attribution and card uplift; benign Mixed traffic, ECH flows, mid-capture
  flows, downloads, and allowlisted channels stay silent.
- **Bounded & offline** — all new state is capped by named constants; peak heap stays within the
  Phase-0 budget; no network, nothing leaves the device.
- **Deterministic** — same input ⇒ byte-identical findings, columns, and rollups; generated
  fixtures are seed-reproducible.
- **Explainable** — every finding carries evidence bullets a human can check against the flow
  table (entropy values, ports, fingerprints, flow counts) and ATT&CK ids resolved in both engine
  and UI.
- **Schema-honest** — one Parquet version bump with the full lockstep, drift-guarded from engine
  and UI; all Summary/Finding changes additive (`#[serde(default)]`), old JSON stays readable.

---

## Appendix A — Design-review corrections (folded in)

Adversarial review across three lenses — engine correctness & reuse, hard invariants,
product/detection value — each reading this plan against the checked-out tree. All three verdicts:
*buildable with corrections* (none required a redesign). Load-bearing fixes, most severe first;
each is folded into the body section cited:

1. **Entropy admission gate was unimplementable as drafted (engine + invariants — major).**
   `l7_hint` identifies handshake-*shaped* payloads only, so packet 3+ of every ordinary
   TLS/HTTP/QUIC flow decodes `app_proto == Unknown`; a sampler gating on the current packet alone
   would fill its 4096 slots with identified flows' ciphertext, starve the detector via
   new-key-drop, and write entropy for identified flows. **Fix (§2.3, §5):** the sampler keeps its
   own per-flow identification memory — a bounded `FlowKey → SampleState` map where known
   protocols hold a bin-free `Identified` sentinel and only still-Unknown flows carry histograms;
   memory accounting updated (≈ 7 MiB, §10).
2. **The schema lockstep missed four column-count pin sites (invariants — major).** Worst:
   `ui/src/lib/query/arrow.ts` materializes exactly 31 typed-array columns and generates the
   staging-table INSERT from `FLOW_COLUMNS` — missing it breaks every UI capture load at
   *runtime*, not in CI. Also missed: `arrow.test.ts`, `schema.test.ts` (`toHaveLength(31)`),
   `tests/columnar_roundtrip.rs` (`:189`). **Fix (§7.2, §17):** lockstep is 14 files, enumerated.
3. **Segment-split ClientHellos would false-positive `missing_sni` (product — major).** Both
   blessed parse tiers clamp the extension walk to captured bytes (`decode/mod.rs:1508`,
   `fingerprint/mod.rs:170`) and report "no SNI" when the walk ran out — and modern
   (post-quantum-sized) ClientHellos routinely span segments. **Fix (§6.2):** `tls_sni_absent`
   requires the extension block complete in the parsed bytes; new `L7Hint::Tls` parse-quality
   fields carry the distinction decode currently cannot express.
4. **The `missing_sni` escalation targeted the benign cohort (product — major).** "TLS 1.2 flight
   but no cert parse" is the *normal* outcome of session resumption (abbreviated handshakes carry
   no Certificate), and IP-literal/embedded clients both omit SNI and resume. **Fix (§6.2):**
   escalation dropped; flat Low/28; corroboration via incidents only.
5. **"RTP never reaches the detector" was false, and real-world media lives off-range (engine +
   product — major).** Port-naming sets `category`, not `observed_app_proto` (no RTP/DTLS/STUN
   sniffer exists), and WebRTC/Zoom/Teams media uses ephemeral or vendor ports outside UDP
   16384-32767 — every conference call would have flagged. **Fix (§2.3, §6.1):** STUN-magic
   late-identification drop in the sampler; port-named encrypted/media tokens become full
   exclusions; the reduction band survives only for named-cleartext ports.
6. **SSH on a non-standard port collided head-on with the detector (product — major).** No
   `AppProto::Ssh` exists, so SSH-on-2222 is Unknown + ciphertext-entropy — yet the flow's own
   record carries a HASSH definitively identifying it. **Fix (§2.3, §6.1):** HASSH presence drops
   the sampler entry and excludes the flow from candidacy and the Anomalous uplift.
7. **`bad_ja4s` was plumbed to nothing (invariants — moderate).** `FingerprintHit` carries only
   ja3/ja4, and the STIX/MISP exporters + Time Machine harvest iterate exactly those fields — a
   JA4S match would label but never export/index. **Fix (§9):** `FingerprintHit.ja4s` added and
   threaded through fold, exporters, `build_index`, and the UI mirror.
8. **Two §6.1 guards were vacuous as drafted (engine + product — moderate).** `meta.download`
   fires only on HTTP flows (already ineligible), and `pkts_fwd/rev ≥ 2` is satisfied by pure
   ACKs — a one-way compressed bulk transfer passed every gate. **Fix (§2.3, §6.1):** in-sampler
   container-magic screen; both-ways gate uses the sampler's payload-aware `sampled_*` counters.
9. **Sanctioned VPNs raised findings on their own named ports (product — moderate).**
   WireGuard/IPsec/OpenVPN are port-named TunnelVpn yet payload-Unknown and ciphertext-entropy;
   a reduction still emits. **Fix (§6.1):** encrypted-by-definition port tokens are exclusions;
   plus an `ignore_ips` allowlist on the 443 arm for OpenVPN-over-TCP/443 gateways (§6.3).
10. **`COMMON_TLS_PORTS` contradicted the repo's own port table (product — moderate).** The draft
    list omitted 8883/5061/5986/3389 — all TLS-bearing per `category_for_port`. **Fix (§6.3):**
    replaced by the rule *a port the table names is not uncommon for this engine* +
    `extra_allowed_ports`.
11. **The Anomalous uplift's precedence was unspecified, and either placement changed behavior
    (engine + product — moderate).** Placed early it silently reclassifies TunnelVpn/C2 verdicts
    (perturbing `is_c2_shape` and the heuristic-C2 cap); placed last the ≥ 1 MiB case never
    becomes Anomalous. **Fix (§6.1):** appended last, the TunnelVpn band split stated and pinned
    by a regression test; the category-independent cross-flow finding covers the big-tunnel case.
12. **Smaller-port orientation misattributes exactly ETA's target traffic (engine — moderate).**
    `contact_from_flow` ignores `initiator`, so high-port services misorient ~half the time,
    fragmenting the `tls_servers` rollup and mislabeling clients. **Fix (new §6.4, §7.3):** new
    folds and the rollup orient by `record.initiator` (SYN-authoritative), smaller-port fallback
    for SYN-less flows; existing detectors untouched.
13. **`encrypted_unknown_protocol` was mis-shelved under "TLS POSTURE" (product — moderate).** It
    is by construction *not* TLS. **Fix (§12):** CertHealthPanel widens to `missing_sni` +
    `port_protocol_mismatch` only; the unknown-channel findings get an "Anomalous channels" tile.
14. **Minor, all folded:** QUIC tracker stores `(dcid, client_direction)` — the canonical FlowKey
    is direction-symmetric, so "reverse direction" was undecidable (§4.2); `quic::testkit` is
    `#[cfg(test)]` (unit-test-only; stated in §13) and `ServerHello` needs `pub(crate)` for
    `fingerprint::compute_ja4s` (§3.3); `sniff_server_hello` gains a `Ja4Transport` parameter —
    its call site is transport-ungated, so the JA4S `t`/`q` marker had no source (§3.3); the
    finding's ATT&CK drops T1095 (MITRE scopes it to non-application-layer channels; the
    flow-level Anomalous → T1095 mapping is pre-existing and untouched) (§6.1); the
    `TlsCertReassembler`-safety claim corrected — its ClientHello arm gates on
    `app_proto == Tls`, not transport (§4.2); `IndicatorKind` back-compat restated — name-based
    serde makes old→new safe, new→old fails whole-file, accepted per the feed-key precedent (§9);
    `TlsServerPosture` gains the `bytes` field its own sort key referenced (§7.3); `--no-eta`
    renamed `--no-encrypted-analysis` and the stderr prefix to `encrypted-traffic:` ("ETA" reads
    as time-remaining on a CLI) (§11); the loop's `Ok(ref meta)` becomes `ref mut meta` for the
    QUIC tracker (§4.2, verified feasible); the Anomalous uplift arming the pre-existing
    "IOC + c2/anomalous ⇒ Critical" floor is now stated (§6.1).

## Appendix B — Citation verification

Every load-bearing path/symbol/signature above was reported by eleven subsystem readers reading
the checked-out tree at `claude/encrypted-traffic-analysis-6195xf` (tip = `origin/main` at
planning time), then independently spot-checked by the three review lenses — which verified,
among others: the `analyze` seam ordering and `process_flow` field scope, the `ServerHello`/
`sniff_server_hello`/`ja3s_hash` shapes, the QUIC Initial-key derivation sites and that RFC 9001
§A.3 is genuinely the server-Initial golden vector, `PacketMeta`'s `Eq` derive vs `FlowRecord`'s
`PartialEq`-only, every proposed (severity, score) pair against the `Severity::from_score` bands,
`Category::Anomalous`'s zero producers, T1571's absence from both UI technique tables, the
`schema_drift`/`columnar_roundtrip`/`arrow.ts` column pins, and that nothing here re-promises a
shipped feature. Line-specific references are anchors, not contracts — `grep` before editing.
Two vectors are explicitly deferred to implementation time: the FoxIO JA4S reference vector and
RFC 9001 §A.3 (both may be network-gated in the build sandbox; the in-code NOTE convention at
`quic/mod.rs:165-169` covers the fallback).
