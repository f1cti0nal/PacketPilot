# PacketPilot — Encrypted Traffic Analysis

**Implementation Plan**

| | |
|---|---|
| **Status** | **Proposed — ready to implement** |
| **Feature branch** | `claude/encrypted-traffic-analysis-6195xf` |
| **Date** | 2026-07-26 |
| **Scope** | Engine (Rust: `fingerprint` JA4S + ECH/absent-SNI flags · `tls` server-ALPN parse · `quic` server-Initial keys + a bounded DCID tracker · a new bounded `EntropySampler` at the raw-frame seam · 3 new detectors + `Category::Anomalous`'s first producer · `stats` TLS-server rollup · Parquet flow schema **v10 → v11**, +3 columns) · Threat feed (`bad_ja4s`) + Time Machine (`ja4s` indicator) + STIX/MISP export · CLI (`analyze --no-eta` + stderr summary) · WASM/UI (FlowDto + 10-file schema lockstep, 3 new `FindingKind`s, TLS-posture card, SQL samples) |

> **How this plan was produced.** Eleven parallel readers each mapped one subsystem ETA touches —
> the TLS module, fingerprinting, QUIC, flow/model/columnar schema, the detection engine, the stats
> substrate, the analyze+scoring pipeline, classification+SSH, CLI/gen/CI conventions, the WASM/UI
> parity surfaces, and docs/positioning — reading the checked-out source at this branch. The design
> was synthesised from those maps and run through an adversarial review across three lenses (engine
> correctness & reuse, hard invariants, product/detection value vs. shipped features). Line-number
> citations are anchors verified during mapping — `grep` before editing, as the tree evolves
> (Appendix B).

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

- The sampler tracks a flow only if its **first payload-bearing packet** decodes with
  `meta.app_proto == AppProto::Unknown`. TLS/HTTP/DNS/QUIC/OT all identify on their first payload
  packet (`decode::l7_hint`), so identified traffic — the overwhelming majority — costs nothing.
- If a *later* packet of a tracked flow identifies the protocol, the entry is dropped: the
  substrate is self-cleaning and converges to genuinely unidentified flows only.
- Bounds: `max_entropy_flows = 4096` concurrent tracked flows (new-key-drop at cap), sample cap
  `entropy_sample_bytes = 2048` bytes **per direction**, packets with payload `< 64` bytes are
  skipped. Worst case: 4096 × 2 × 512 B (bins) + book-keeping ≈ **4.5 MiB**, inside the ≤ 64 MiB
  budget (§10). A 2048-byte sample caps measurable entropy at 11 bits — no estimator ceiling near
  the 7.2 bits/byte decision threshold.
- At flow close, `process_flow` looks the flow up by `FlowKey`, computes per-direction entropy,
  writes `record.entropy_c2s/_s2c`, and **removes the entry** (memory is reclaimed at close, not
  EOF).

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
carry `ja4s`; its caller (`decode/mod.rs:272-277`) sets a new `meta.ja4s`. `FlowRecord.ja4s`
absorbs it sticky-first (`model/flow.rs:297-352`), and it becomes Parquet column 32 (§7.2).
GREASE filtering is identical to JA3S's (collection-time, `tls/mod.rs:641` area) so JA4S matches
published databases. JA3S behavior is unchanged — it still hashes `legacy_version`
(`tls/mod.rs:591-592`), while JA4S uses the unmasked version; the difference is deliberate and
spec-correct for both.

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
  (`analyze/mod.rs:287-303`), because it *mutates* `meta`.
- On a client Initial (`identify_quic` → `Initial`, `extract` path already parses the DCID at
  `quic/mod.rs:349-353`): record `(canonical 4-tuple) → dcid` in a bounded map,
  `MAX_QUIC_TRACKED = 4096`, new-key-drop at cap, **last-wins** on re-insert (handles Retry: the
  client's post-Retry Initial replaces the DCID, and per RFC 9001 §5.2 the server's keys then
  derive from the *new* DCID).
- On a UDP packet in the *reverse* direction of a tracked tuple that identifies as an Initial:
  `extract_initial_crypto` with the stored DCID and `"server in"` keys (a refactor of
  `extract_initial_client_hello` (`:316`) splitting key-derivation from CRYPTO reassembly), wrap
  the recovered handshake in the synthetic 5-byte record (the established dance,
  `decode/mod.rs:709-713`), `parse_server_hello`, then set `meta.tls_version`, `meta.tls_cipher`,
  `meta.ja3s`, `meta.ja4s` (with the `q` marker) — **without touching `meta.app_proto`** (the flow
  keeps Quic/Http3; the specificity lattice at `model/packet.rs:163` is not disturbed, and the
  TCP-only `TlsCertReassembler` gate at `tls/mod.rs:336,342` cannot be confused because it checks
  `Transport::Tcp`). The entry is then dropped — one parse per connection.
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
pub struct EntropyConfig { pub enabled: bool, pub max_entropy_flows: usize /*4096*/,
    pub sample_bytes_per_dir: usize /*2048*/, pub min_packet_payload: usize /*64*/ }
pub struct EntropySampler { /* HashMap<FlowKey, Box<DirHists>>, caps */ }
pub struct FlowEntropy { pub c2s_bits: Option<f32>, pub s2c_bits: Option<f32>,
    pub sampled_c2s: u32, pub sampled_s2c: u32 }
impl EntropySampler {
    pub fn observe(&mut self, meta: &PacketMeta, frame: &RawFrame);  // frame-borrow seam
    pub fn take(&mut self, key: &FlowKey, initiator: Direction) -> Option<FlowEntropy>; // at flow close
}
```

- `observe` derives the L4 payload from the raw frame (as `TlsCertReassembler::observe` does),
  applies the gates of §2.3 (first-payload-unidentified, `min_packet_payload`, per-direction
  sample cap, self-cleaning drop on later identification), and folds bytes into the histograms.
- Entropy math: plain Shannon over the 256-bin histogram, `-Σ p·log2(p)`, pure `f64` folded to
  `f32` at the end — deterministic fixed-order arithmetic over the fixed-size array; no clock, no
  RNG, wasm-safe, zero new deps.
- `take` orients fwd/rev to c2s/s2c using the record's `initiator` (the same orientation source
  `oriented()` uses, `model/flow.rs:403`) and frees the entry.
- `process_flow` calls `take` **before** `classifier.classify` so the classifier's new uplift arm
  (§6.1) can read the values, and stores them on the record for the Parquet writer
  (`entropy_c2s`/`entropy_s2c`, §7.2).

Per-packet cost on identified traffic: one `HashMap` miss (the key is only present for tracked
flows). On tracked flows: a bounded `memcpy`-grade fold capped at 2 KiB per direction *per flow
lifetime*. The criterion ingest bench (`benches/ingest.rs`) and the `PHASE0_BUDGET` gates
(`metrics/mod.rs:109-116`) are the acceptance check (§10).

---

## 6. Pillar 3 — the detectors

All three follow the uniform detector shape (Params + `detect_*` + evidence bullets + ATT&CK ids +
deterministic sort) and emit into the findings vector at the `analyze/mod.rs:474-500` seam.

### 6.1 `encrypted_unknown_protocol` — high-entropy unidentified channels

**Signal.** A flow that (a) no payload sniffer identified (`observed_app_proto == Unknown`),
(b) exchanged real payload both ways (`pkts_fwd/rev ≥ min_pkts_each_way = 2` — screens scans and
one-way junk), (c) moved `≥ min_payload_bytes = 4096` total, and (d) measured
`entropy ≥ min_entropy_bits = 7.2` in at least one direction. 7.2 bits/byte over a ≥ 1 KiB sample
is comfortably above natural-language/binary-protocol text (≈ 4–6) and below only
ciphertext/compressed data (≈ 7.6–8.0).

**False-positive guards (the load-bearing part).**
- *Compressed files are also high-entropy*: candidates are screened against the existing
  magic-byte download detection — a flow whose first payload packet matched a known file container
  (`meta.download` is `Some`, `decode/mod.rs:263-297` sniffer chain) is excluded; likewise
  candidates on FileTransfer-classified port pairs.
- *Mid-capture TLS looks unknown*: a TCP flow with no SYN observed (`tcp_flags` OR lacks SYN) is
  excluded — its handshake predates the capture, so "unidentified" is not evidence.
- *Port screen*: flows whose service port the port table names (`category_for_port`,
  `classify/mod.rs:223`) get a one-band severity reduction rather than exclusion (RTP-range UDP is
  the classic benign high-entropy case and is already port-named Voip → never `Unknown`, so it
  never reaches the detector at all).

**Two outputs.** (1) Per flow, a new `shape_uplift` arm (`classify/mod.rs:162`): still-Unknown +
high-entropy + volume ⇒ `Category::Anomalous` — its **first producer**; scoring already handles it
(`PTS_ANOMALOUS = 40`, `score/mod.rs:41-51`; Anomalous+external = 55 = Medium, within philosophy;
enrich already maps it to T1095). The uplift keeps `app_proto_src = None` and classify stays
idempotent (entropy fields are on the record by classify time and never change after close).
(2) Cross-flow, a `BehaviorTracker` fold (`observe_encrypted_channel(client, server, server_port,
bytes, entropy)`, bounded new-key-drop map keyed `(IpAddr, IpAddr, u16)`) and
`detect_encrypted_unknown(tracker, &EncryptedUnknownParams) -> Vec<Finding>` at EOF: one finding
per channel, `FindingKind::EncryptedUnknownProtocol`, severity **Medium/50** (external dst) /
**Low/30** (internal), evidence bullets carrying entropy per direction, bytes, packet counts, and
the port-screen note; `attack = ["T1573", "T1095"]`. High only via incident corroboration (§2.4).

### 6.2 `missing_sni` — TLS clients that name no server

**Signal.** A **parsed** ClientHello with no `server_name` extension. The parse-quality gate is
critical (mapped warning): `meta.sni == None` does *not* mean SNI-absent — the structural fallback
(`looks_like_tls_client_hello`, `decode/mod.rs:873`) tags truncated hellos as TLS with no SNI. The
signal is therefore a new `meta.tls_sni_absent: bool`, set only on the full-fingerprint path
(`TlsFingerprints.sni == None`) or the medium path (`sniff_tls_client_hello` returning
`Some(None)`, `decode/mod.rs:1478`) — never the structural fallback.

**ECH awareness.** The extension walk (`fingerprint/mod.rs:184-222`) gains an arm for
`encrypted_client_hello` (0xfe0d) setting `TlsFingerprints.ech: bool` → `meta.tls_ech` →
`FlowRecord.tls_ech` (sticky-true). An ECH ClientHello legitimately omits/fakes SNI — ECH flows
are **excluded** from `missing_sni` and instead counted in evidence ("N ECH flows observed" on the
posture rollup). Both flags are internal FlowRecord fields (`#[serde(default)]`), **not** Parquet
columns (§7.2 keeps the column budget to 3).

**Detector.** Fold per `(client, server)` in `process_flow`; `detect_missing_sni` emits one
finding per channel: external server only by default (`external_only = true`), `min_flows = 2`
(one hello can be a stack quirk; a *channel* of them is a posture), `ignore_ips` allowlist for
known SNI-less infrastructure (mirrors the DGA resolver-allowlist convention). Severity
**Low/28**, rising to **Medium/45** when the same channel also lacks a certificate observation
(TLS 1.2 flight seen but no SNI *and* no cert parse) — never higher alone. `attack = ["T1573"]`.
Note `check_cert_health` simply skips name-matching when SNI is absent (`tls/mod.rs:126-132`) —
`missing_sni` fills exactly that blind spot without touching cert logic.

### 6.3 `port_protocol_mismatch` — the wire lies about the port, or the port about the wire

Two arms, one finding kind, `FindingKind::PortProtocolMismatch`:

- **TLS on an uncommon port** (evasion-shaped, but often benign): `observed_app_proto ∈ {Tls}` and
  service port ∉ `COMMON_TLS_PORTS` (const table: 443, 465, 563, 587, 636, 853, 989, 990, 992,
  993, 994, 995, 8443, 9443, + `extra_allowed_ports` param). STARTTLS upgrades (25/110/143/587)
  are in-table or param-tunable. Severity **Info/10** alone — this is context, not an alarm —
  raised to **Low/30** when the destination is external and the SNI is absent too.
- **Established non-TLS on 443** (tunnel-shaped): TCP service port 443, **SYN observed and
  connection established** (`tcp_established()`, `model/flow.rs:446` — the gate that kills the
  mid-capture-TLS false positive), payload exchanged, yet `observed_app_proto == Unknown`.
  Evidence includes the flow's entropy when sampled (§5 tracks these flows automatically — port
  443 with an unidentified first payload packet is in-scope for the sampler). Severity
  **Medium/48**; **High/65** when `bytes ≥ high_bytes = 1 MiB` (a used tunnel, not a probe —
  the WeakTls-style specific-signal exception, §2.4). UDP/443 is **excluded**: a mid-capture QUIC
  flow has no long header to identify (`quic/mod.rs:97-100`), so "not identified as QUIC" is not
  evidence there.

Fold per `(client, server, server_port)`; `attack = ["T1571"]` (+ `"T1573"` on the 443 arm).
`T1571` is added to `technique_name` (`detect/mod.rs:3989`) and both UI technique tables (§12).
Neither arm assigns `app_proto_src` or any category — classification is untouched, so the
heuristic-C2 cap and the evasive-beacon `is_named` veto (`score/mod.rs:291-307`,
`analyze/mod.rs:691`) keep their exact semantics.

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

The full, known 10-file lockstep (every file enumerated by the mapping): `columnar/schema.rs`
(`flow_arrow_schema` + `flow_columns_in_order` — the `[&'static str; N]` type forces the count —
+ `FLOW_PARQUET_VERSION = 11`), `columnar/mod.rs` (Builders struct/new/finish/append +
`dict_cols`), `sql/schema.sql` (view SELECT list; old Parquet parts read as NULL via
`union_by_name`), `tests/schema_drift.rs` (hard-coded 31 → 34), `ppcap-wasm/src/lib.rs` `FlowDto`
+ `from_record` (must mirror the writer exactly), `ui/src/lib/query/flow_columns.json` (columns +
`flow_schema_version: 11`), `ui/src/lib/query/schema.ts` (`FLOW_COLUMN_TYPES` + version const;
column comments feed the NL→SQL prompt for free), `ui/src/types.ts` (FLOW_COLUMNS array +
RawFlowRow + WasmFlow + FlowRow), `ui/src/lib/data.ts` (both mappers), `ui/src/lib/flowsCsv.ts`.
`OrientedFlow` + both `oriented()` arms (`model/flow.rs:32,403`) gain the entropy pair (ja4s is
direction-independent).

New non-column fields: `PacketMeta { ja4s: Option<String>, tls_sni_absent: bool, tls_ech: bool }`
(integer/bool/String only — `Eq` derive preserved; every exhaustive test literal constructor gets
the three fields, a mechanical sweep) and `FlowRecord { ja4s, tls_sni_absent, tls_ech,
entropy_c2s: Option<f32>, entropy_s2c: Option<f32> }`, all `#[serde(default)]`.

### 7.3 `Summary.tls_servers` rollup

```rust
pub struct TlsServerPosture { pub server: String, pub port: u16,
    pub tls_version: Option<String>, pub tls_cipher: Option<String>,
    pub ja3s: Option<String>, pub ja4s: Option<String>, pub sni: Option<String>,
    pub flows: u64, pub clients: u64 }
```

Folded in `observe_scored_flow` (`stats/mod.rs:617`) for flows carrying any server-side TLS field;
server side resolved by the `contact_from_flow` convention (numerically-smaller port,
`detect/mod.rs:1998`). Bounded map keyed `(IpAddr, u16)`, cap 4096 new-key-drop, per-server client
set capped at 64 (count saturates); `finish()` projects `TOP_K_TLS_SERVERS = 50` sorted flows desc
→ bytes desc → key asc. `Summary.tls_servers: Vec<TlsServerPosture>` with `#[serde(default)]`
(the `encrypted_dns` precedent, `summary.rs:255`). This also fixes the mapped gap that
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
all-zeros JA3 sentinel convention; real known-bad JA4S seeding is a data task, §16). Time Machine:
`IndicatorKind::Ja4s` (`timemachine/mod.rs:34-43`, serde lowercase, appended last), harvested from
`Summary.tls_servers` + IOC-matched fingerprints, rescan via `matches_ja4s`; SQL `indicator_t`
enum gains `'ja4s'` (`sql/schema.sql:13` — DDL text only, no stored data migration: the schema is
emitted fresh by `init-db`). Export: STIX pattern `x-tls-fingerprint:ja4s = '…'`
(`export/mod.rs:132-151` block) and a MISP attribute following the existing bare-`"ja4"`-type
precedent (`:327-331`). Docs: the indicator-class lists in `docs/time-machine.md:79-81,114-115`
and `docs/batch-triage.md:53` are extended in the same change.

---

## 10. Performance, Determinism & Invariants (explicit)

- **Bounded memory, accounted:** EntropySampler ≈ 4.5 MiB worst-case (§5); QUIC DCID tracker
  4096 × ≤ 20 B DCID + key ≈ 0.3 MiB; three detector maps + `tls_servers` map: new-key-drop at
  4096–8192 entries with short string values ≈ 1–2 MiB combined; per-flow additions: one sticky
  `Option<String>` + 2 `f32` + 2 bools ≈ negligible at the 32 Ki flow cap. Total well inside the
  ≤ 64 MiB `PHASE0_BUDGET` (`metrics/mod.rs:109-116`); the in-tree heap assert
  (`golden_e2e.rs:128`) and the `#[ignore]`d 100k budget test are the gates.
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

- **`analyze --no-eta`** — sets `encrypted_unknown.enabled = missing_sni.enabled =
  port_mismatch.enabled = entropy.enabled = false`. Fingerprint extraction (JA4S, QUIC server
  metadata) is *metadata, not detection* and stays on, exactly as JA3/JA3S have no flag.
- **Stderr summary** — `eta: N encrypted-traffic finding{s}` (unless `--quiet`), mirroring the
  `forecast:` line.
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
- `CertHealthPanel` (`components/triage/CertHealthPanel.tsx:66`) widens its filter to the three
  new kinds — it already owns the "TLS POSTURE" label; no new panel component.
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
- `entropy`: uniform-random ≈ 8.0, ASCII ≈ 4–5, constant = 0.0; per-direction caps; the
  self-cleaning drop on late identification; the `log2(n)` small-sample property documented in a
  test name.
- `detect`: per-detector unit tests (fires on the crafted candidate, silent on: mid-capture
  no-SYN flows, ECH flows, magic-byte downloads, allowlisted ports/IPs, one-way scans);
  determinism of emission order.
- Full-pipeline e2e (`tests/eta_e2e.rs`): `gen EncryptedAnomaly → analyze::run` raises all three
  finding kinds with correct attribution and card uplift; `--no-eta` silences all three and nulls
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
| **Compressed ≈ encrypted entropy** | Magic-byte screen + FileTransfer port screen + one-band port-named reduction (§6.1); threshold 7.2 over ≥ 1 KiB samples; Medium cap alone. Residual: unrecognized proprietary compression can still flag — the evidence bullets make the human call cheap. |
| **Mid-capture flows look "unknown"** | SYN/established gates on both the entropy detector and the 443 arm (§6.1, §6.3); UDP/443 excluded outright. |
| **ECH growth erodes `missing_sni`** | ECH is detected, excluded, and counted — as ECH adoption grows the detector's scope shrinks honestly rather than false-positiving (§6.2). |
| **JA4S spec drift / vector availability** | Pin to published vectors; if unfetchable, the in-code NOTE + round-trip convention (`quic/mod.rs:165-169` precedent) and a follow-up to pin (§16). |
| **QUIC tracker misses (multi-datagram CH, VN, drafts, short-header-only)** | Stated limits (§4.2); the fields simply stay NULL — no wrong data. Retry handled by last-DCID-wins. |
| **PacketMeta literal sweep** | Adding 3 fields touches every exhaustive test constructor — mechanical, compiler-driven, called out in the checklist. |
| **Schema-bump blast radius** | The 10-file lockstep is enumerated (§7.2) and CI-guarded from both sides (`schema_drift.rs` + `schema.test.ts`) — partial updates cannot pass CI. |
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
| `engine/crates/ppcap-core/src/tls/mod.rs` | Modify | `ServerHello.alpn` parse + `sniff_server_hello` tuple + JA4S call + testkit server-flight builder |
| `engine/crates/ppcap-core/src/quic/mod.rs` | Modify | `"server in"` params + `derive_server_initial_keys` + extract refactor + RFC 9001 §A.3 vector + testkit inverse |
| `engine/crates/ppcap-core/src/quic/` (new file or `mod.rs`) | **Add** | `QuicServerHelloTracker` (bounded DCID map, inline meta mutation) |
| `engine/crates/ppcap-core/src/entropy/mod.rs` | **Add** | `EntropySampler` + `EntropyConfig` + `FlowEntropy` + unit tests |
| `engine/crates/ppcap-core/src/decode/mod.rs` | Modify | thread `ja4s`/`tls_sni_absent`/`tls_ech` onto `PacketMeta` from the sniff results |
| `engine/crates/ppcap-core/src/model/packet.rs` | Modify | 3 new `PacketMeta` fields (+ every test literal constructor) |
| `engine/crates/ppcap-core/src/model/flow.rs` | Modify | `FlowRecord` fields + sticky folds + `OrientedFlow` entropy pair + `oriented()` arms |
| `engine/crates/ppcap-core/src/model/finding.rs` | Modify | 3 `FindingKind` variants + `as_str` arms |
| `engine/crates/ppcap-core/src/model/summary.rs` | Modify | `TlsServerPosture` + `Summary.tls_servers` (`#[serde(default)]`) |
| `engine/crates/ppcap-core/src/classify/mod.rs` | Modify | Anomalous entropy uplift arm in `shape_uplift` + consts + tests |
| `engine/crates/ppcap-core/src/detect/mod.rs` | Modify | 3 tracker maps + observers + candidates + `detect_*` fns + stage/phrase arms + `T1571` in `technique_name` |
| `engine/crates/ppcap-core/src/stats/mod.rs` | Modify | `tls_servers` bounded map + fold + `finish()` projection |
| `engine/crates/ppcap-core/src/analyze/mod.rs` | Modify | tracker/sampler wiring at both seams + `PipelineConfig` params + detector extends |
| `engine/crates/ppcap-core/src/enrich/mod.rs` | Modify | `bad_ja4s` feed key + `matches_ja4s` + label + `FeedMatch` ride |
| `engine/crates/ppcap-core/data/builtin_fingerprints.json` | Modify | ja4s test sentinel |
| `engine/crates/ppcap-core/src/timemachine/mod.rs` | Modify | `IndicatorKind::Ja4s` (appended) + harvest + rescan |
| `engine/crates/ppcap-core/src/export/mod.rs` | Modify | STIX/MISP ja4s indicator mapping |
| `engine/crates/ppcap-core/src/report/mod.rs` | Modify | 3 `kind_label` arms (+ tls_servers table if the HTML report grows one — optional, M6) |
| `engine/crates/ppcap-core/src/columnar/{schema,mod}.rs` · `sql/schema.sql` | Modify | v11 + 3 columns + builders + dict + view + `indicator_t 'ja4s'` |
| `engine/crates/ppcap-core/src/gen/{mod,mix,frames}.rs` | Modify | `Scenario::EncryptedAnomaly` + server-flight/high-entropy builders + aliases/weights/assertion |
| `engine/crates/ppcap-core/tests/{schema_drift,eta_e2e}.rs` | Modify / **Add** | 34-column guard · gen→analyze e2e for all three kinds + `--no-eta` |
| `engine/crates/ppcap-cli/src/cli.rs` | Modify | `--no-eta` + stderr summary + parse test + stale `--scenario` help fix |
| `engine/crates/ppcap-wasm/src/lib.rs` | Modify | `FlowDto` + `from_record` (+3 fields) |
| `ui/src/types.ts` · `lib/findingKinds.ts` · `lib/killChain.ts` · `cockpit/IncidentHero.tsx` | Modify | union + KIND_META + both KIND_STAGE + T1571 name |
| `ui/src/lib/query/{flow_columns.json,schema.ts}` · `lib/data.ts` · `lib/flowsCsv.ts` · `components/{FlowDetail,flows/FlowsTable}.tsx` · `views/FlowsView.tsx` | Modify | the §7.2 lockstep + display |
| `ui/src/cockpit/TlsServersCard.tsx` (+test) | **Add** | posture rollup card |
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

## Appendix A — Design-review corrections (to be folded in)

*Populated from the adversarial review pass (engine correctness & reuse · hard invariants ·
product/detection value) before implementation begins.*

## Appendix B — Citation verification

Every load-bearing path/symbol/signature above was reported by subsystem readers reading the
checked-out tree at `claude/encrypted-traffic-analysis-6195xf` (tip = `origin/main` at planning
time) and spot-verified during synthesis. Line-specific references are anchors, not contracts —
`grep` before editing. Two vectors are explicitly deferred to implementation time: the FoxIO JA4S
reference vector and RFC 9001 §A.3 (both may be network-gated in the build sandbox; the in-code
NOTE convention at `quic/mod.rs:165-169` covers the fallback).
