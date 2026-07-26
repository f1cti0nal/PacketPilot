# PacketPilot — Encrypted Traffic Analysis: Follow-ups

**Implementation Plan**

| | |
|---|---|
| **Status** | **Proposed — ready to implement**, sequenced into five independent PRs |
| **Parent** | [`encrypted-traffic-analysis-plan.md`](encrypted-traffic-analysis-plan.md) §16 (merged as #152) |
| **Date** | 2026-07-26 |
| **Scope** | Engine (Rust: `flow`/`model` SPLT accumulator · `ssh` banner + host-key retention + `bad_hassh` · `baseline` JA4S novelty axis · `tls/cert` + `fingerprint` JA4X · `stats` encrypted-mix rollup) · CLI (nothing new) · UI (two small surfaces) · Parquet flow schema **v11 → v12** in F1 only |

> **How this plan was produced.** Written directly against the checked-out tree at `main` after
> implementing ETA end-to-end, so the seams cited here are ones the author just worked in rather
> than ones read cold. Every path/symbol below was re-verified against `main` at `f02ab03`. Two of
> the parent plan's seven follow-ups are **not planned as work** — §7 explains why, honestly, rather
> than padding the list.

---

## 1. Summary

ETA shipped the keyless *identity* and *entropy* layers. These follow-ups add the **behavioral**
layer that the parent plan deliberately deferred, and close three "computed but consumed by
nothing" gaps of exactly the kind ETA itself closed for JA3S.

Five shippable increments, in recommended order:

| # | Increment | Why it is worth doing | Size |
|---|---|---|---|
| **F1** | **SPLT behavioral features** | The real next capability: encrypted-channel *shape* (packet sizes, direction, timing) is what distinguishes interactive C2 from bulk transfer when payload tells you nothing | Large |
| **F2** | **SSH posture** | HASSH is computed and consumed by **nothing** — the exact gap ETA closed for JA3S. It also cost ETA precision: `encrypted_unknown_protocol` needs an explicit HASSH exclusion because SSH-on-odd-port is otherwise a guaranteed false positive | Medium |
| **F3** | **JA4S baseline novelty** | A first-seen *server* fingerprint for a host is new infrastructure — the strongest cheap C2 signal, riding shipped BBL machinery | Small |
| **F4** | **JA4X + certificate enrichment** | Richer cert hygiene and an X.509 fingerprint, from fields the parser already walks past. **Caveat: value is structurally declining** (§4.1) | Medium |
| **F5** | **Encrypted-mix rollup** | "How much of this capture can I actually see into?" — one number that frames every other ETA verdict | Small |

**Not planned as work:** real known-bad JA4S seeding and the QUIC v2 golden-vector pin. Both are
blocked on things code cannot supply; §7 states why and what would unblock them.

---

## 2. F1 — SPLT behavioral features

### 2.1 What it is

Sequence-of-Packet-Lengths-and-Times: the Cisco-ETA-style observation that an encrypted channel's
*shape* betrays its purpose even when its bytes do not. A shell session is small packets, both
ways, with human-scale gaps. A file transfer is MTU-sized packets one way. A beacon is a short
burst on a clock. Today the engine collapses every flow to `pkts`/`bytes` per direction, which
erases all of it.

### 2.2 The design constraint that shapes everything

The parent plan deferred this "to avoid persisting vectors", and that constraint should hold: the
repo has no packet-level Parquet (the `packet_index` table is an unshipped roadmap line), and
adding per-flow arrays to the flow schema would be a large, awkward column. So:

> **Collect a bounded vector in memory; persist only derived scalars.**

`FlowRecord::observe` (`model/flow.rs:287`) already receives every packet's `payload_len`, `ts_ns`,
`tcp_flags`, and `Direction` — everything needed. It just throws them away.

### 2.3 Accumulator

A fixed-size array on `FlowRecord`, sized against the live-flow cap (`max_active_flows = 32_768`,
`flow/mod.rs:61`):

```rust
/// First-N packet shape. Fixed-size and inline — never a Vec, so per-flow state stays O(1)
/// and the flow table's memory bound is unchanged in character.
const SPLT_SLOTS: usize = 16;

struct SpltSlot {
    /// L4 payload length, saturating at u16::MAX (jumbo frames clamp; the shape is what matters).
    payload_len: u16,
    /// Gap from the previous recorded packet, in milliseconds, saturating.
    gap_ms: u16,
    /// Which direction carried it.
    reverse: bool,
}
```

`16 × 6 B ≈ 96 B` per flow (with padding), `× 32 Ki flows ≈ 3 MiB` — the parent plan's own estimate,
verified against the real cap. **Payload-bearing packets only** (`payload_len > 0`), so a TCP
handshake and bare ACKs do not consume the window that matters.

### 2.4 Derived scalars (what actually persists)

At flow close, the array collapses to a handful of numbers on `FlowRecord`:

| Scalar | Meaning | Signal |
|---|---|---|
| `splt_mean_len` / `splt_stddev_len` | First-N payload-size distribution | Bulk (MTU-clamped, low σ) vs interactive (small, high σ) |
| `splt_mean_gap_ms` | Inter-packet cadence | Human-scale vs machine-scale |
| `splt_direction_ratio` | Fraction of the window that was c2s | Upload-shaped vs download-shaped, *before* volume accumulates |
| `splt_burstiness` | Direction alternations ÷ slots | Request/response chatter vs one-way streaming |

Reuse `detect::StreamStats` (`detect/mod.rs:24`, Welford, O(1)) rather than a new statistic — it is
already the repo's online-moments primitive.

### 2.5 What consumes them

Two consumers, both riding shipped machinery:

1. **`encrypted_unknown_protocol` gains shape evidence.** Today its evidence is entropy + volume.
   Adding "small bidirectional packets at human cadence" vs "MTU-sized one-way streaming" turns a
   generic finding into a triage-ready one — *interactive* unknown-encrypted is far more
   C2-shaped than bulk unknown-encrypted, and the detector can say so in its evidence bullets and
   raise its band accordingly (still capped per §2.6).
2. **A new `interactive_channel` signal on encrypted flows to external peers** — an interactive
   shell shape over an encrypted channel to an external host, which is a reverse-shell tell that
   neither entropy nor beacon-timing catches.

### 2.6 Scoring discipline (unchanged)

Shape alone is weak — a legitimate SSH session and a reverse shell have identical SPLT. So shape
**modulates evidence and band within the existing caps**, and never mints a High on its own. The
`encrypted_unknown_protocol` Medium ceiling stands; SPLT can move Low→Medium inside it, not past it.

### 2.7 Schema

Flow schema **v11 → v12**, four appended `Float32`/`UInt8` columns. This is the second bump in two
features, which is worth a moment's thought: the alternative — a single packed struct column — is
worse for the DuckDB/NLQ surface, where `WHERE splt_mean_gap_ms < 500` is exactly the query an
analyst wants. Take the bump; the 14-file lockstep is now well-trodden and CI-guarded from both ends.

### 2.8 Checklist

| File | Change |
|---|---|
| `model/flow.rs` | `SpltSlot` array + `observe` fold + derived scalars + `OrientedFlow` direction-ratio flip |
| `flow/mod.rs` | Nothing — the cap already bounds it |
| `detect/mod.rs` | SPLT-aware evidence in `detect_encrypted_unknown`; new `interactive_channel` detector + `FindingKind` |
| `columnar/{schema,mod}.rs` · `sql/schema.sql` · drift guards · wasm `FlowDto` · UI lockstep | v12, +4 columns |
| `gen/mod.rs` | Extend `EncryptedAnomaly` with an interactive-shaped variant |
| `tests/eta_e2e.rs` | Shape asserted end-to-end; bulk vs interactive discriminated |

---

## 3. F2 — SSH posture

### 3.1 Why this is the highest value-per-line item

SSH is the engine's blind spot. `AppProto` has **no `Ssh` variant**, so an SSH session on any port
but 22 is `Category::Unknown` with ciphertext entropy — which is why `detect_encrypted_unknown`
carries an explicit HASSH exclusion (`is HASSH present? then it is not an unknown protocol`). That
guard works, but it is a workaround for SSH not being first-class. Meanwhile HASSH/HASSHServer are
computed on every KEXINIT and consumed by **nothing** — precisely the state JA3S was in before ETA.

### 3.2 Three changes, each small

**(a) Retain what the parser already reads and discards.** `parse_kexinit` (`ssh/mod.rs`) finds the
`SSH-…` identification line and advances past it, and binds `let _host_key = r.next()?;` for
`server_host_key_algorithms`. Both are one-line retentions:

- `meta.ssh_banner` → `FlowRecord.ssh_banner` (sticky) — the software version string
  (`SSH-2.0-OpenSSH_9.6`), which is the single most useful SSH triage datum and is pure cleartext.
- host-key algorithms → feed the hygiene check below.

**(b) An `ssh_posture` finding** covering what the banner and KEXINIT expose:

| Condition | Severity | Rationale |
|---|---|---|
| SSH-1 / `SSH-1.99` compatibility banner | High | SSH-1 is cryptographically broken |
| `ssh-dss` / `ssh-rsa` (SHA-1) host key offered | Low | Deprecated signature algorithms |
| CBC-mode or `none` cipher offered | Medium | Weak/no encryption negotiated |

This mirrors `detect_weak_tls` exactly — same shape, same `kind_str`/`severity_rank`/`evidence`
enum discipline, same "table-driven, conservative, unknown algorithms are not flagged" stance.

**(c) `bad_hassh` feed matching.** The six-site chain is now well-worn — I built the identical one
for `bad_ja4s` in ETA M5: `ThreatFeedFile` key → lowercased set → `matches_hassh` → `FlowEnrichment`
flag → `FeedMatch.fingerprint` → `FingerprintHit.hassh` → STIX/MISP + Time Machine
`IndicatorKind::Hassh`.

### 3.3 The caveat to carry forward

HASSH client/server orientation is a **port-comparison heuristic** (`dst_port < src_port ⇒ client`,
documented at `ssh/mod.rs:27-29`), which inverts when a server listens above the client's ephemeral
port. Any SSH posture feature inherits that, and the finding's evidence should not assert
client-vs-server more confidently than the heuristic supports. Retaining the **banner** actually
improves this: banners are directional in practice, so a mismatch between banner direction and
port-derived orientation is itself a usable correction — worth a follow-up test, not v1 logic.

### 3.4 Optional: `AppProto::Ssh`

Making SSH structurally identified (banner or KEXINIT ⇒ `AppProto::Ssh`) would let the ETA
exclusion be deleted rather than maintained, and would give odd-port SSH a correct category. It
touches the specificity lattice (`packet.rs:163`) and `app_bucket_for_flow` (`stats/mod.rs`), and it
changes existing classifications — so it ships as its own commit inside F2 with the
`benign_mixed_traffic` regression as the gate.

---

## 4. F3 — JA4S baseline novelty

The smallest item with a real detection payoff. BBL already learns each host's JA3 set
(`Ja3Stat`/`HostProfile.ja3` at `baseline/mod.rs:347,434`, `top_k_ja3: 16`, novelty scored at
`PTS_DEV_NEW_JA3 = 10`). Mirror it for JA4S.

**The keying nuance that makes it worth doing.** JA3 novelty answers "this host is running new
client software". JA4S novelty answers something sharper: **"this host is talking to a server stack
it has never contacted before"** — new infrastructure, which is what a C2 migration or a fresh
malicious endpoint looks like. Same machinery, different and arguably stronger question.

Changes: `observe_ja4s` on `BehaviorTracker` (the `observe_ja3` template, `detect/mod.rs:892`), a
`ja4s: Vec<Ja4sStat>` on `HostProfile` with `#[serde(default)]` (old sidecars simply have none and
fall through), a `top_k_ja4s` cap, `PTS_DEV_NEW_JA4S`, and one new deviation dimension in
`compare_to_baseline`. Engine-only; rides the existing `--baseline` path and the
`baseline_deviation` UI surface with no CLI/UI change.

### 4.1 F4 — JA4X + certificate enrichment, and an honest caveat

`cert::parse_leaf` already *positions* the fields it discards — `let _serial = field;` and
`let _spki = it.next()?;` are literally bound and dropped. Adding serial, SPKI key type/size,
issuer CN, and a cert SHA-256 is a contained extension using the existing `der.rs` walkers. JA4X
(the FoxIO X.509 fingerprint: hashed issuer RDNs, subject RDNs, and extension OIDs) is computed
**during `parse_leaf` while the DER is in hand**, then the DER is freed as now — so the
no-raw-certificate-retention contract is unchanged.

New hygiene checks this unlocks: RSA keys < 2048 bits, weak signature algorithms (MD5/SHA-1),
absurd validity windows, and cert-hash-based IOC matching (`bad_cert_sha256`).

**The caveat, stated plainly: this item's value is structurally declining.** Certificates are
visible only in TLS ≤ 1.2 (in 1.3 the Certificate message is encrypted — the parent plan says so at
its §1). As TLS 1.3 approaches universal deployment, JA4X and cert hygiene apply to a shrinking
minority of traffic. That is not an argument against building it — legacy, internal, and appliance
traffic is exactly where weak certs live, and that is exactly where cert hygiene *should* look — but
it is an argument for sequencing it **after** F1–F3, which apply to all encrypted traffic. Ranked
accordingly.

---

## 5. F5 — Encrypted-mix rollup

One number that frames every other ETA verdict: **how much of this capture can the engine see into
at all?** Bytes split across `cleartext / TLS / QUIC / unknown-encrypted / unidentified`.

Implementation note from the tree: `ProtoCounts` counts **packets**, not bytes
(`stats/mod.rs:612-614` — `self.proto.tls += f.total_pkts()`), so a byte-share card cannot reuse it
directly. `CatStat` does carry `bytes` (`stats/mod.rs:109-113`) but its axis is category, not
visibility. So F5 adds one small bounded accumulator — five `u64` counters, inherently bounded, no
new map — folded in `observe_flow`, projected as `Summary.encrypted_mix`, and rendered as a
stacked-bar card beside `TlsServersCard`.

The parent plan gated this on "if analysts ask". It is cheap enough and framing enough that it is
worth doing regardless — it is the one number that tells an analyst whether a quiet report means
*quiet traffic* or *opaque traffic*.

---

## 6. Sequencing

```
F2 (SSH posture) ──▶ F3 (JA4S novelty) ──▶ F1 (SPLT) ──▶ F5 (mix card) ──▶ F4 (JA4X/cert)
   small, closes         small, rides         large, the        small,        medium, declining
   a real gap            shipped BBL          real capability   framing       coverage
```

F2 first because it is small, closes a live gap, and *improves ETA's own precision* (§3.1). F1 is
the headline capability but is the largest; F3 and F5 are cheap wins that can land while F1 is in
review. F4 last, per §4.1.

Each is one PR, matching the repo's linear `(#NNN)` squash history and the PAD precedent where
follow-ups #140–#151 each shipped independently.

---

## 7. Not planned as work — and why

Two of the parent plan's seven follow-ups are blocked on something code cannot supply. Listing them
as tasks would be padding, so they are stated as blockers with their unblock conditions.

**Real known-bad JA4S seeding for `builtin_fingerprints.json`.** This is data curation, not code —
and it is *actively unsafe to guess at*. A fingerprint in the builtin set is merged into **every**
feed including `ThreatFeed::empty()`, and a fingerprint IOC carries a **High severity floor**
(`score/mod.rs`). A wrong entry therefore mislabels benign traffic as High on every capture, with no
user opt-out. Sourcing requires reaching abuse.ch / the FoxIO JA4+ database (network-blocked here,
§below) *and* human review of each entry's provenance. **Unblock:** a maintainer supplies vetted
entries, or the sandbox gains egress to those sources. Until then the sentinel-only set is correct.

**QUIC v2 salt golden-vector pinning (RFC 9369 Appendix A).** Verified still blocked at plan time —
`rfc-editor.org` returns **403 (CONNECT tunnel failed)** through both `curl` and the sanctioned
fetch tool. Worth keeping in perspective: the v2 constants are already round-trip-verified, and the
v1 path *is* pinned to RFC 9001 §A.1 and §A.3, so the shared derivation machinery is vector-proven —
the missing pin would only catch a mis-transcribed v2 salt. **Unblock:** any environment with
rfc-editor.org egress, or a maintainer pasting the appendix values; the test itself is ~10 lines
beside `derive_server_initial_keys_rfc9001_a3`.

---

## 8. Risks

| Risk | Mitigation |
|---|---|
| **SPLT is a fingerprinting capability** — packet shape can profile *user behavior*, not just malware | Derived scalars only, never the raw vector; first-16 payload packets only; nothing leaves the device. Worth an explicit note in the user doc: this measures channel shape, not content. |
| Second flow-schema bump in two features | The 14-file lockstep is CI-guarded from both ends and now well-trodden; `union_by_name` keeps old Parquet readable (§2.7) |
| SSH `AppProto` changes existing classifications | Ships as its own commit with the benign-traffic regression as the gate (§3.4) |
| A wrong builtin fingerprint is High-severity and un-opt-out-able | Not shipping unvetted data (§7) |
| SPLT shape alone false-positives on legitimate SSH/RDP | Shape modulates band inside existing caps, never mints High (§2.6) |

---

## 9. Guarantees these must preserve

Unchanged from the parent: **keyless** (no decryption-module imports on the analysis path),
single-pass, bounded (every new accumulator fixed-size or capped by a named constant), deterministic,
never-panic, no new dependencies, and derived-values-only retention — SPLT persists four scalars,
not a packet trace.
