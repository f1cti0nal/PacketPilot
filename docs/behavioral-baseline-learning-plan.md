# PacketPilot — Behavioral Baseline Learning

**Implementation Plan**

| | |
|---|---|
| **Status** | Proposed — ready to implement |
| **Feature branch** | `claude/behavioral-baseline-learning-7w6l0u` |
| **Date** | 2026-07-20 |
| **Scope** | Engine (Rust: new `baseline` module + `detect`/`analyze`/`model`/`score` seams) · CLI (`analyze` flags + `baseline` subcommand) · UI (React/TS Baseline tab + deviation panel) · WASM (two fold fns) · Desktop (two Tauri commands) · HTML report (findings ride through; one `kind_label` arm) |

> **How this plan was produced.** Eight parallel readers each mapped one subsystem the
> feature touches — the detection engine (`detect`), the data model (`model`), the persistence /
> Time-Machine / case patterns, the analyze+stats pipeline, the CLI, scoring+enrichment, the
> React/Tauri UI, and the repo's doc/CI conventions — reading the actual checked-out source. The
> designs below were synthesised from those maps and then run through an adversarial review across
> three lenses (engine correctness & reuse, hard invariants, product/UX). Every cited path, line
> number, and signature was verified against the checked-out tree; the adversarial corrections are
> folded in above and itemised in **Appendix A**.

---

## 1. Summary & Goals

### What ships

**Behavioral Baseline Learning (BBL)** teaches PacketPilot what *normal* looks like for each
**internal host** on a network, by learning a compact per-host **behavioral profile** across one or
more captures, persisting it as an offline JSON **sidecar** (`<name>.baseline.json`), and then — on a
new capture — comparing observed behavior against that learned profile and raising explainable
**`baseline_deviation`** findings when a host does something it has never done before or wildly out of
its established range.

It is built almost entirely from machinery the engine already has: the `BehaviorTracker`'s per-channel
`ContactSeries` accumulators (peers, ports, protocols, per-channel volume, beacon periodicity), the
Welford `StreamStats` online-statistics primitive, the `Finding` → `apply_findings` → per-IP threat-card
uplift path, the transparent `add_term` score ledger, and the Time Machine "distill to an offline JSON
sidecar, re-evaluate as a pure transform" pattern. The genuinely new code is small and bounded: a
serialisable/mergeable running-stat, three per-host bounded accumulators (hour-of-day histogram, JA3 set,
category histogram), and the learn/merge/compare transforms.

### What it changes vs. today's engine

| Dimension | Today | New with BBL |
|---|---|---|
| Detection scope | Single-capture: verdicts from what is *in this pcap* | Adds **cross-capture** memory: "this host never behaved like this in its 40-capture history" |
| Novelty signal | `Beacon`/`PortScan`/`Sweep`/`Exfil` fire on absolute thresholds | Deviations fire **relative to the host's own learned normal** (first-seen peer/port/proto/JA3, volume spike vs mean+k·σ, off-hours, new beacon) |
| Persistence | Time Machine `capture.index.json` (indicators only) | Adds `<name>.baseline.json` (per-host running stats + seen-sets), read-modify-write across captures |
| Complement | Time Machine: *"threat intel caught up — did I already talk to something now-known-bad?"* | BBL: *"my network changed — is this host doing something it never did before?"* |
| Explainability | Every score point explained via `ScoreTerm` + evidence | Deviation points use the **same `add_term` ledger** — each deviation dimension is one term + one evidence line |

### Non-goals (this plan's core)

Local-first, on-device, offline only. **No** shared/team baseline store, **no** scheduled
auto-baselining, **no** ML/clustering. Those are follow-ups (§16), scoped out exactly as Time Machine
scopes out its team-store and scheduling follow-ups.

---

## 2. Concept & Chosen Approach

### 2.1 The two questions, side by side

PacketPilot already answers the *retrospective threat-intel* question with Time Machine
(`docs/time-machine.md`). BBL answers the orthogonal *behavioral-drift* question:

- **Time Machine** — feed changes, capture is fixed. `build_index(out)` → `rescan(indices, feed)`.
- **BBL** — capture changes, the host's *own history* is the reference. `build_baseline(out)` /
  `update_baseline(profile, out)` → `compare_to_baseline(profile, out)`.

Both are **pure, offline transforms over a small JSON sidecar** — same privacy and bounded-memory
discipline. BBL deliberately mirrors Time Machine's module shape (`timemachine/mod.rs`): a
`BASELINE_SCHEMA_VERSION` const, `to_json_pretty`/`from_json_str`, `BTreeMap`-accumulate →
sorted-`Vec` for stable diffs, provenance fields, and a `#[cfg(test)]` roundtrip suite.

### 2.2 Per-entity scoping: internal hosts only

A baseline profiles the **monitored network's own hosts**, not the internet. The engine already has the
exact predicate: `IpClass::is_external()` (`enrich/mod.rs:62`) returns `true` for `Public | Cgnat`.
An **internal** (baseline-eligible) host is therefore `!classify_ip(ip).is_external()` — `Private`,
`Loopback`, `LinkLocal`, `Multicast`, `Documentation`, `Reserved`. This is the mirror image of
reputation, which gates to **external-only** (`enrich/reputation.rs:75`). BBL profiles internal hosts;
deviation findings are attributed to the internal host via `Finding.src_ip`.

### 2.3 One substrate, one snapshot

The richest per-host behavioral data lives in the **`BehaviorTracker`**: its
`channels: HashMap<ContactKey, ContactSeries>` (`detect/mod.rs:633`) already tracks, per directed
`(src, dst, dst_port)` channel, the contact count, per-channel byte volume (`bytes_out`/`bytes_in`),
inter-arrival `gaps: StreamStats` (period + jitter CV), first/last-seen, transport, and C2/named-service
shape flags. Fan-out (`fanout`) and vertical-scan (`port_scan`) maps give distinct-peer / distinct-port
sets. The `StatsAccumulator.per_ip` map supplies coarse per-host pkts/bytes/flows as a cross-check.

**Decision:** build the per-host profile from a single new **`BehaviorTracker::baseline_snapshot()`**
projection (§7.2). That one method produces a `CaptureProfile` (per-internal-host feature vectors) which
is *both* the learn payload (folded into the persisted baseline) *and* the compare input (diffed against
the persisted baseline). This resolves the only real structural blocker — `BehaviorTracker`'s fields are
private — with one public accessor instead of many.

---

## 3. The Baseline Profile — features learned

Each feature below names the exact engine field(s) that supply it. All are per **internal host**
(`IpAddr` key); everything is aggregated inside the single streaming pass, so nothing re-reads packets.

| Feature | Deviation it enables | Source (field → anchor) |
|---|---|---|
| **Peer set** (distinct external dsts) | first-seen external peer; fan-out growth | `ContactSeries` keys `ContactKey.dst` (`detect/mod.rs:137`); `fanout` map (`:634`) |
| **Service set** (distinct `(dst_port, transport)`) | first-seen destination port/service | `ContactKey.dst_port` + `transport` folded in `observe_flow_contact_with` (`:1006`); `port_scan` map |
| **Protocol / category mix** | first use of a category (e.g. `tunnel`, `remote`) | `FlowRecord.category` (`flow.rs:146`) — **net-new per-host accumulator** (§7.3); `per_category` at `stats/mod.rs:149` is capture-wide, and `ContactSeries.add_class` only flags c2/named booleans |
| **Outbound/inbound volume** | volume spike vs mean+k·σ | `ContactSeries.bytes_out/bytes_in` (`:154`); `StatsAccumulator.per_ip` bytes (`stats/mod.rs:142`) — folded into a `RunningStat` |
| **Connection / contact rate** | activity-rate spike | `ContactSeries.contacts()` + `first/last_seen()` (`:201`/`:206`) |
| **Beacon periodicity** | *new* beacon channel not previously present | `StreamStats::cv()` (`:99`) + `ContactSeries.jitter_cv()`/`interval_ns()` (`:218`/`:212`); diff `beacon_candidates()` keys (`:1383`) |
| **TLS/SSH fingerprints** (JA3 set) | first-seen JA3 for a host (new client stack / tool) | `FlowRecord.ja3` (`flow.rs:181`) — **net-new fold**, see §7.3 |
| **Active-hours histogram** `[24]` | off-hours activity vs the host's normal window | `FlowRecord.first_ts_ns` → hour-of-day — **net-new accumulator**, see §7.3 |
| **SNI / HTTP-host set** (optional, capped) | first-seen destination host | `FlowRecord.sni`/`http_host` (`flow.rs:179`/`188`); `per_domain`/`per_http_host` |

**Scoping note.** `StatsAccumulator.per_port` is keyed by port *alone*, not `(host, port)`
(`stats/mod.rs:145`) — so per-host service sets must come from the tracker's channel keys, not from
`per_port`. Likewise `per_category` (`stats/mod.rs:149`) is a capture-wide `[CatStat; 13]` with **no host
key** — per-host category history is a net-new accumulator (§7.3), not a projection of `per_category`.
These are called out because they are easy wrong turns.

---

## 4. On-disk Schema — the baseline sidecar

New module `engine/crates/ppcap-core/src/baseline/mod.rs` (lowercase single-word dir + `mod.rs`,
matching `timemachine/`, `sanitize/`, `carve/`). Types mirror `CaptureIndex` conventions
(`timemachine/mod.rs:71-87`) exactly.

### 4.1 The stat primitive — serialisable, mergeable Welford + EWMA

`StreamStats` (`detect/mod.rs:24`) has the right math (Welford `push`, `mean`/`variance`/`stddev`/`cv`)
but **derives only `Debug, Clone`, has private fields, and has no `merge`** — so it can neither be
persisted nor folded across captures. BBL adds a serde-friendly sibling in the new module and reuses the
push math verbatim:

```rust
// baseline/mod.rs
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RunningStat {
    pub count: u64,
    pub mean: f64,
    pub m2: f64,               // Welford M2; variance() = m2 / count
    pub min: f64,
    pub max: f64,
    pub ewma: f64,            // recency-weighted mean (no primitive exists in core today)
    pub first_seen_unix: i64, // wall-clock secs (i64, 0 if no clock — matches analyzed_unix_secs)
    pub last_seen_unix: i64,
}
impl RunningStat {
    pub fn observe(&mut self, x: f64, now_unix: i64, alpha: f64) { /* Welford + min/max + ewma + seen */ }
    /// Chan's parallel combine — needed to fold two persisted sidecars (order-independent for
    /// count/mean/m2/min/max; ewma is recomputed on replay, see §5).
    pub fn merge(a: &RunningStat, b: &RunningStat) -> RunningStat { /* count=na+nb; delta=mb-ma; ... */ }
    pub fn variance(&self) -> f64; pub fn stddev(&self) -> f64;
}
```

### 4.2 Per-host and top-level structs

```rust
pub const BASELINE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SeenCount {            // "have I seen this peer/port/proto/ja3 before, how often, when"
    pub captures: u64,           // # captures this value appeared in
    pub total: u64,              // total observations
    pub first_seen_unix: i64,
    pub last_seen_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostBaseline {
    pub host: String,                       // internal IP — the entity key
    pub captures_seen: u64,                 // # captures this host appeared in (confidence, §14)
    pub bytes_out: RunningStat,             // per-capture outbound volume distribution
    pub bytes_in: RunningStat,
    pub flows: RunningStat,                 // per-capture flow count
    pub peers: Vec<PeerStat>,               // top-N external dsts, sorted by ip (bounded)
    pub services: Vec<ServiceStat>,         // top-N (port,transport), sorted (bounded)
    pub categories: [SeenCount; 13],        // fixed 13 Category slots (inherently bounded)
    pub ja3: Vec<Ja3Stat>,                  // top-N JA3, sorted (bounded)
    pub hour_of_day: [u64; 24],             // active-hours histogram (fixed, bounded, mergeable)
    pub beacons: Vec<BeaconStat>,           // known regular channels: (dst,port), interval_ns, cv
    pub first_seen_unix: i64,
    pub last_seen_unix: i64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerStat    { pub ip: String, pub seen: SeenCount }
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceStat { pub port: u16, pub transport: String, pub seen: SeenCount }
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ja3Stat     { pub ja3: String, pub seen: SeenCount }
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeaconStat  { pub dst: String, pub port: u16, pub interval_ns: i64, pub jitter_cv: f64, pub seen: SeenCount }

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineProfile {
    pub schema_version: u32,                // == BASELINE_SCHEMA_VERSION
    pub engine_version: String,             // out.engine_version / env!("CARGO_PKG_VERSION")
    #[serde(default)] pub captures_merged: u64,        // provenance
    #[serde(default)] pub source_sha256s: Vec<String>, // provenance, bounded + deduped + sorted
    pub first_analyzed_unix_secs: i64,      // min over merged captures
    pub last_analyzed_unix_secs: i64,       // max
    pub first_ts_ns: i64,                   // earliest capture-window start (i64 ns)
    pub last_ts_ns: i64,                    // latest capture-window end
    pub hosts: Vec<HostBaseline>,           // sorted by host, bounded by max_hosts
}
impl BaselineProfile {
    pub fn to_json_pretty(&self) -> crate::Result<String>;   // serde_json::to_string_pretty
    pub fn from_json_str(s: &str) -> crate::Result<Self>;    // serde_json::from_str; rejects newer schema_version
}
```

Every field added after v1 carries `#[serde(default)]` (the repo-wide forward-compat convention —
`Summary`/`Finding`/`Indicator` all do this), so an older sidecar deserialises into a newer engine and
vice-versa with no migration step. Determinism: all sets are materialised as `Vec`s sorted by their key
(peers by ip, services by `(port,transport)`, ja3 by string), exactly as `build_index` drains its
`BTreeMap` into a sorted `Vec` (`timemachine/mod.rs:161`).

### 4.3 JSON example

```json
{
  "schema_version": 1,
  "engine_version": "0.1.0",
  "captures_merged": 42,
  "source_sha256s": ["…", "…"],
  "first_analyzed_unix_secs": 1749000000,
  "last_analyzed_unix_secs": 1752000000,
  "first_ts_ns": 1700000000000000000,
  "last_ts_ns": 1752000100000000000,
  "hosts": [
    {
      "host": "10.0.0.23",
      "captures_seen": 42,
      "bytes_out": { "count": 42, "mean": 1830000.0, "m2": 4.1e13, "min": 210000.0, "max": 3400000.0,
                     "ewma": 1910000.0, "first_seen_unix": 1749000000, "last_seen_unix": 1752000000 },
      "bytes_in":  { "count": 42, "mean": 22400000.0, "m2": 9.0e14, "min": 1200000.0, "max": 51000000.0,
                     "ewma": 23100000.0, "first_seen_unix": 1749000000, "last_seen_unix": 1752000000 },
      "flows": { "count": 42, "mean": 310.0, "m2": 88000.0, "min": 120.0, "max": 640.0, "ewma": 300.0,
                 "first_seen_unix": 1749000000, "last_seen_unix": 1752000000 },
      "peers": [ { "ip": "140.82.112.21", "seen": { "captures": 41, "total": 980, "first_seen_unix": 1749000000, "last_seen_unix": 1752000000 } } ],
      "services": [ { "port": 443, "transport": "tcp", "seen": { "captures": 42, "total": 4200, "first_seen_unix": 1749000000, "last_seen_unix": 1752000000 } } ],
      "categories": [ /* 13 SeenCount slots, Category order */ ],
      "ja3": [ { "ja3": "e7d705a3286e19ea42f587b344ee6865", "seen": { "captures": 40, "total": 900, "first_seen_unix": 1749000000, "last_seen_unix": 1752000000 } } ],
      "hour_of_day": [0,0,0,0,0,0,0,12,340,410,388,401,420,399,410,405,388,290,120,40,10,2,0,0],
      "beacons": [],
      "first_seen_unix": 1749000000,
      "last_seen_unix": 1752000000
    }
  ]
}
```

### 4.4 Bounds (all mirror `StatsConfig`)

```rust
pub struct BaselineConfig {
    pub max_hosts: usize,     // default 100_000 — cap on tracked internal hosts (bump_bounded eviction)
    pub top_k_peers: usize,   // default 128 — per host
    pub top_k_services: usize,// default 64  — per host
    pub top_k_ja3: usize,     // default 16  — per host
    pub top_k_beacons: usize, // default 16  — per host
    pub max_source_shas: usize,// default 256 — provenance list cap
    pub ewma_alpha: f64,      // default 0.30
}
```

`categories[13]` and `hour_of_day[24]` are fixed arrays — inherently bounded and trivially mergeable.
Per-host sets use the `bump_bounded` heavy-hitter primitive (`stats/mod.rs:1240`) so a single host cannot
grow unbounded, and `max_hosts` bounds the host count the same way `max_tracked_keys` bounds every stats
map. Peak-heap stays independent of capture size (§12).

---

## 5. Merge / Update Semantics — folding N captures over time

The persisted baseline is **read-modify-write**: load the prior sidecar (or start empty), fold this
capture's `CaptureProfile` in, write it back. This is the one place BBL differs from Time Machine and the
`case` module, both of which build fresh each run. It mirrors the `case` module's sequential,
sorted, bounded fan-out (`case/mod.rs:298-390`) but with a *statistical* fold instead of set-union.

```rust
// pure, offline — the case-module analogue, but merge-not-union
pub fn update_baseline(mut base: BaselineProfile, prof: &CaptureProfile,
                       analyzed_unix_secs: i64, cfg: &BaselineConfig) -> BaselineProfile;
pub fn merge(a: BaselineProfile, b: BaselineProfile, cfg: &BaselineConfig) -> BaselineProfile;
```

**Fold rules (all deterministic, order-independent except EWMA):**

- `RunningStat` (bytes/flows): one `observe(x, now, alpha)` per capture, or `RunningStat::merge` when
  combining two sidecars (Chan parallel Welford — order-independent for `count`/`mean`/`m2`/`min`/`max`).
- Counters (`SeenCount.captures`/`total`, `hour_of_day[h]`, `categories[c]`): additive
  `saturating_add` — commutative.
- `first_seen_unix` = `min`, `last_seen_unix` = `max` — order-independent (the accepted repo pattern for
  timestamp folds; cf. attack-chain plan's min/max folds).
- Set membership (peers/services/ja3): union, then `bump_bounded` truncation to `top_k_*` keeping the
  heaviest by `total` — deterministic tie-break by key.

**EWMA caveat (called out honestly).** EWMA is order-dependent, so `RunningStat::merge` of two sidecars
cannot reproduce a single replay's EWMA exactly. Two mitigations, pick per milestone: (a) treat EWMA as a
*hint only* (not used for the hard deviation gate — the gate uses `mean`/`stddev`, which merge exactly);
(b) recompute EWMA on the canonical per-capture `update_baseline` path (which *is* ordered by
`analyzed_unix_secs`). This plan uses (a): EWMA informs the UI "recent trend" but the deviation math is
mean+k·σ, so cross-sidecar `merge` stays sound.

---

## 6. Deviation Detection

### 6.1 One finding kind, dimensions in evidence

Add a single `FindingKind::BaselineDeviation` (`model/finding.rs:17`, append after `IcsControlCommand`
at `:71` to preserve enum ordinal → `Ord`/`Hash` stability) with `as_str` arm `=> "baseline_deviation"`
(`:76`). Deviation *dimensions* are encoded in `title`/`evidence` rather than proliferating kinds —
exactly how `beacon_finding` distinguishes strict vs evasive under one kind. The change is small, but the
compiler *will* force a new arm at every **exhaustive (no-`_`) `match FindingKind`** site (§7.4):
`finding.rs:76` `as_str`, `detect/mod.rs` `stage_ordinal`/`stage_label`/`kind_phrase`, and
`report/mod.rs:597` `kind_label`. ATT&CK ids are **not** set by a central kind match — they are attached
per-detector at `Finding` construction (`technique_name` is string-keyed with a `_ => id` fallback), so no
ATT&CK match needs updating.

A `BaselineDeviation` finding maps onto the existing `Finding` shape (`finding.rs:107`) with **no new
required fields**: `src_ip` = the deviating internal host, `dst_ip`/`dst_port` = the offending peer/port
where applicable, `evidence` = one bullet per deviation dimension, `first_seen_ns`/`last_seen_ns` = the
new capture window, `severity`/`score` from the deviation score (§6.3).

### 6.2 Deviation classes

| Class | Fires when | Reuses | Evidence line (example) | ATT&CK |
|---|---|---|---|---|
| **New external peer** | host contacts a public IP absent from `peers` | `fanout`/channel keys; `is_external()` gate | `new external peer 203.0.113.5 — not in 42-capture profile` | T1071 |
| **New service/port** | `(dst_port, transport)` absent from `services` | channel keys | `new destination port 4444/tcp` | T1571 |
| **New category** (M2) | first use of a `Category` with 0 baseline count | **net-new per-host `category[13]`** (§7.3) | `first use of category tunnel` | T1048 (context) |
| **Volume spike** | `bytes_out` > `mean + k·stddev` (k from params, default 4) | `RunningStat` (Welford) | `outbound 12MB vs baseline mean 1.8MB ±0.3MB (33σ)` | T1030/T1048 |
| **New JA3** | JA3 absent from host's `ja3` set | `observe_ja3` fold (§7.3) | `new TLS client fingerprint e7d7…6865` | T1071 |
| **Off-hours** | activity in an hour with 0 baseline count (and baseline has ≥N populated hours) | `hour_of_day[24]` | `activity 03:14 outside active window 07:00–19:00` | T1029 (context) |
| **New beacon** | a `beacon_candidates()` channel key absent from baseline `beacons` | `beacon_candidates` (`:1383`), `cv()`/`interval_ns` | `new periodic channel to 198.51.100.9:443 (~60s, cv 0.04)` | T1071.004 |

Reuse, don't reinvent: periodicity via `StreamStats::cv()`/`ContactSeries.jitter_cv()`; fan-out/scan
novelty via `fanout`/`port_scan`; the probe-vs-session gate (`SCAN_SESSION_BYTES=512`) and
cloud-provider suppression (`cloud_provider()`) so BBL "new peer" agrees with the sweep/scan detectors
and doesn't flag CDN churn.

### 6.3 Scoring — every deviation point explained

Deviation severity is assembled with the **same `add_term` ledger** as `score_flow`
(`score/mod.rs:78`), so each point reconciles to one evidence line and one `ScoreTerm`:

```rust
// score/mod.rs — new, mirrors ScoredFlow
pub struct ScoredDeviation { pub severity: Severity, pub score: u16, pub evidence: Vec<String>, pub terms: Vec<ScoreTerm> }
pub fn score_baseline_deviation(dims: &[DeviationDim]) -> ScoredDeviation; // add_term per dim; clamp to DEV_UPLIFT_CAP
```

New weight constants alongside `score/mod.rs:41-55`, chosen consistent with existing terms (weak
behavioral signal ≈ +10; deviation-alone tops out at **Medium**; High/Critical requires corroboration):

```rust
const PTS_DEV_NEW_EXTERNAL_PEER: i32 = 15; // == PTS_EXTERNAL
const PTS_DEV_NEW_CATEGORY:      i32 = 10;
const PTS_DEV_NEW_PORT:          i32 = 10;
const PTS_DEV_VOLUME_SPIKE:      i32 = 10;
const PTS_DEV_NEW_JA3:           i32 = 10;
const PTS_DEV_OFF_HOURS:         i32 = 10;
const PTS_DEV_NEW_BEACON:        i32 = 15;
const DEV_UPLIFT_CAP:            i32 = 45; // mirrors REP_UPLIFT_CAP philosophy: deviation-alone ≤ Medium
```

Severity comes from `Severity::from_score` (`severity.rs:77`, Medium 35–59). A host whose deviations
co-locate with an IOC or a `Beacon`/`DataExfil` finding escalates to High/Critical through the *existing*
`score_flow` IOC floors — never by stacking deviation points. Rationale matches the scoring module's
stated philosophy (`score/mod.rs:9-30`) and reputation's `REP_UPLIFT_CAP` — keeps synthetic/demo captures
honest.

**Carrying explainability into the card.** So a deviation appears in the machine-readable
`IpThreat.score_terms` (not only `evidence`), add `#[serde(default)] pub terms: Vec<ScoreTerm>` to
`Finding` (`finding.rs:107`) and copy it into the card in the strict-raise branches: in
`StatsAccumulator::apply_findings` (`stats/mod.rs:613`) `e.terms = f.terms.clone()` (the accumulator field
is `terms`, `stats/mod.rs:504`); in `Summary::apply_findings` (`summary.rs:443`)
`card.score_terms = f.terms.clone()` (the `IpThreat` field is `score_terms`, `summary.rs:180`, **not**
`terms`). One additive field + two one-line copies; back-compat via `serde(default)`.

---

## 7. Engine Wiring — file by file

### 7.1 New module `baseline/mod.rs` + `lib.rs` re-exports

- `engine/crates/ppcap-core/src/baseline/mod.rs` — the schema (§4), `RunningStat`, `CaptureProfile`
  (the per-capture snapshot type), `build_baseline`, `update_baseline`, `merge`, `compare_to_baseline`,
  `DeviationReport`, `BaselineConfig`, `#[cfg(test)]` suite.
- `lib.rs:37` — `pub mod baseline;` (beside `pub mod analyze;` etc.).
- `lib.rs` re-export block (beside the `timemachine::{…}` block at `:106-109`):
  ```rust
  pub use baseline::{
      build_baseline, compare_to_baseline, merge as merge_baselines, update_baseline,
      BaselineConfig, BaselineParams, BaselineProfile, CaptureProfile, DeviationReport,
      HostBaseline, RunningStat, BASELINE_SCHEMA_VERSION,
  };
  ```

### 7.2 `detect/mod.rs` — the snapshot accessor (the one structural change)

`BehaviorTracker`'s fields are private and the `*_candidates()` accessors are threshold-filtered, not
full enumerations. Add one method that projects the tracker into a per-internal-host, serialisable view —
this is the single largest edit in `detect/mod.rs`, but it is additive and read-only:

```rust
impl BehaviorTracker {
    /// Project per-internal-host behavioral features for baseline learning/compare.
    /// Reads channels/fanout/port_scan/dga/ja3/activity; gates hosts on !is_external().
    pub fn baseline_snapshot(&self, cfg: &BaselineConfig) -> CaptureProfile { /* … */ }
}
```

`CaptureProfile` is a lightweight `{ hosts: Vec<HostObservation> }` where each `HostObservation`
carries this capture's peers/services/categories/ja3/hour-histogram/beacon-keys/volume for one host — the
shape `update_baseline` folds and `compare_to_baseline` diffs.

### 7.3 `detect/mod.rs` — three net-new bounded accumulators

1. **JA3 per host** (JA3 never reaches the tracker today). Add field
   `ja3: HashMap<IpAddr, HashSet<String>>` to `BehaviorTracker` (`:631`), a bounded
   `observe_ja3(&mut self, host: IpAddr, ja3: &str)` (same `contains_key && len >= cap` guard + inner-set
   cap as `arp`/`dga`), and call it from `process_flow` right after the contact fold
   (`analyze/mod.rs:570-585`): `if let Some(j) = &record.ja3 { tracker.observe_ja3(client, j); }`.
2. **Active-hours histogram** (no hour-of-day state exists). Add
   `activity: HashMap<IpAddr, [u32; 24]>` to `BehaviorTracker`, folded in `observe_flow_contact_with`
   from the flow's `first_ts_ns` (ns → unix secs → `(secs / 3600) % 24`). Fixed 24-slot array per host,
   inherently bounded; host count bounded by `max_tracked_keys`.
3. **Per-host category histogram** (`per_category` is capture-wide, not per-host; §3 scoping note). Add
   `category: HashMap<IpAddr, [u32; 13]>` to `BehaviorTracker`, folded in `process_flow` from
   `record.category` (`Category` has 13 variants — same fixed-array discipline as `per_category`'s
   `[CatStat; 13]`). Powers the "new category" deviation (§6.2, M2).

All three feed `baseline_snapshot`. All follow the tracker's existing heavy-hitter/never-panic discipline.

### 7.4 `model/finding.rs` — the new kind (+ optional `terms`)

- `FindingKind::BaselineDeviation` variant (`:71`) + `as_str` arm (`:76`) → `"baseline_deviation"`.
- Optional (§6.3): `#[serde(default)] pub terms: Vec<ScoreTerm>` on `Finding` (`:107`). Requires importing
  `ScoreTerm` (already in `model::summary`). Additive; existing constructors default it to `vec![]`.
- Downstream exhaustive `match FindingKind` sites needing a new arm (compiler-enforced, no `_`):
  `detect/mod.rs` `stage_ordinal` (`:3639`), `stage_label` (`:3668`), `kind_phrase` (`:3697`), and
  `report/mod.rs` `kind_label` (`:597`). **Not** ATT&CK: `technique_name` (`detect/mod.rs:3828`) is
  string-keyed with a `_ => id` fallback, and deviation ATT&CK ids are set at `Finding` construction.

### 7.5 `analyze/mod.rs` — load, compare, learn

- **PipelineConfig** (`:44-104` + Default `:106-146`): add
  ```rust
  pub baseline_in:     Option<PathBuf>,  // prior profile to compare against; None => no compare
  pub update_baseline: bool,             // snapshot this capture for the CLI to persist
  pub baseline_out:    Option<PathBuf>,  // informational; the CLI does the write (keeps run() fs-free on wasm)
  pub baseline:        BaselineParams,   // deviation thresholds (k-sigma, min-captures warmup, off-hours min-hours)
  ```
  Defaults: `None` / `false` / `None` / `BaselineParams::default()` — leaves native + wasm behavior
  unchanged.
- **Load once**, next to `Enricher::new(ThreatFeed::load_opt(...))` (`:228`):
  `let baseline_in = BaselineProfile::load_opt(cfg.baseline_in.as_deref())?;` (fail-fast, offline —
  the `ThreatFeed::load_opt` pattern).
- **Compare seam** — insert after the last `detect_*` extend (`:478`), *before*
  `stats.apply_findings(&findings)` (`:511`) so deviations uplift per-IP cards and flow into
  incidents/chains like every other detector:
  ```rust
  if let Some(base) = baseline_in.as_ref() {
      let prof = tracker.baseline_snapshot(&cfg.baseline.config);
      findings.extend(compare_to_baseline(base, &prof, &cfg.baseline).into_findings());
  }
  ```
- **Learn seam** — the tracker is dropped at end of `run_source_visiting` (~`:521`). If `cfg.update_baseline`,
  snapshot it into the returned output *before* it drops:
  ```rust
  let baseline_snapshot = cfg.update_baseline.then(|| tracker.baseline_snapshot(&cfg.baseline.config));
  ```
  and add `#[serde(default)] pub baseline: Option<CaptureProfile>` to `AnalysisOutput`
  (`model/output.rs:11`), populated at the build site (`:530-545`). The CLI folds+persists it post-run
  (§9), keeping `run_source_visiting` filesystem-free (wasm-safe). *Note: the snapshot is the raw
  per-capture observation, not the merged profile — merge happens in the CLI/wasm layer so `run()` stays
  a pure analysis.*

> **Substrate note (corrected in review).** Both the compare and the snapshot read the **live
> `BehaviorTracker`**, which is *not* consumed by `stats.finish()` (`:514`). So there is no ordering
> constraint against `finish()` — only against the tracker's own EOF TLS-cert drain (`:431-451`), which
> the seams sit after. This supersedes the earlier idea of reading `StatsAccumulator` (which *is*
> consumed at `:514`); `per_ip` volume, if wanted as a cross-check, is read at the same `:479` point
> before `finish()`.

### 7.6 `score/mod.rs` — the deviation term

Add `score_baseline_deviation` + the `PTS_DEV_*`/`DEV_UPLIFT_CAP` constants (§6.3). Called by
`compare_to_baseline` (in `baseline/mod.rs`) to turn a host's deviation-dimension list into a
`ScoredDeviation`, whose `severity`/`score`/`evidence`/`terms` populate the emitted `Finding`.

---

## 8. Serialization & Backward Compatibility

- **Sidecar version:** `BASELINE_SCHEMA_VERSION: u32 = 1` const + `schema_version` field; unit test
  asserts `written == const` and a full `assert_eq!(profile, roundtrip)` (Time Machine precedent,
  `timemachine/mod.rs:350,375`). `from_json_str` tolerates an *older* `schema_version` (via
  `serde(default)` on post-v1 fields) and *rejects a newer* one with a typed `PpError` rather than
  silently mis-merging.
- **`AnalysisOutput`/`Finding` additive fields** (`baseline`, `terms`) get `#[serde(default)]` — **no
  `AnalysisOutput.schema_version` bump** (additive-optional, matching how `findings`/`incidents` were
  added). A new `Finding` field must also be set in every existing `Finding {…}` constructor (compiler
  forces this).
- **WASM ride-through:** deviation findings live on `summary.findings`, so `analyze`/`export_*` serialise
  them with **no wasm `.rs` change** — the `attack_chains` precedent (`ppcap-wasm` serialises the whole
  `AnalysisOutput`).
- **HTML report — one arm, not free:** findings render for free, **but** `report/mod.rs::kind_label`
  (`:597`) is an exhaustive `match FindingKind` with no `_`, so it needs **one new arm**
  (`BaselineDeviation => "Baseline Deviation"`) or `ppcap-core` won't compile. This corrects an earlier
  "free ride-through" assumption.
- **Do NOT touch** the Parquet/flow schema (`columnar/*`, `FLOW_PARQUET_VERSION`, `sql/schema.sql`, wasm
  `FlowDto`, UI `flow_columns.json`) — BBL is a summary-level cross-capture aggregate, not a per-flow row,
  so the `schema_drift.rs` guard is unaffected.

### 8.1 New WASM exports (browser parity)

Two thin `serde_json`-in/out fns in `ppcap-wasm/src/lib.rs`, mirroring `apply_rules`/`apply_reputation`
(fold-into-`AnalysisOutput`) — *not* the streaming `analyze` pattern, since baseline ops are offline
transforms over a summary + a sidecar:

```rust
#[wasm_bindgen] pub fn build_baseline(output_json: &str, prior_baseline_json: Option<String>, analyzed_unix_secs: i64) -> Result<String, JsValue>;  // -> merged BaselineProfile JSON
#[wasm_bindgen] pub fn compare_to_baseline(output_json: &str, baseline_json: &str) -> Result<String, JsValue>; // -> AnalysisOutput JSON with deviation findings folded in
```

Both pure, network-free, C-free (pure-Rust `serde_json` + f64). The page owns the returned baseline bytes
(there is no wasm filesystem), exactly as `sanitize` returns bytes for the page to save.

---

## 9. CLI Surface

Two surfaces, mirroring the `--index`/`rescan` precedents (`ppcap-cli/src/cli.rs`).

### 9.1 `analyze` flags (learn + compare) — mirrors `--index`

Add to the `Analyze` variant after `index` (`cli.rs:95`), same `#[arg(long)] Option<PathBuf>` style:

```rust
/// Behavioral Baseline: compare this capture's per-host profile against a saved baseline and
/// raise deviation findings (read-only).
#[arg(long)] baseline: Option<PathBuf>,
/// Behavioral Baseline: learn/merge this capture into the given baseline JSON (create-or-merge).
#[arg(long = "update-baseline")] update_baseline: Option<PathBuf>,
```

Wire the post-passes after the `--index` block (`cli.rs:430`), on the finished `out`:

- `--baseline <p>`: set `cfg.baseline_in = Some(p)` before `run()` so deviations are already folded into
  `out.summary.findings` and thus appear in `--json`/`--html`/`--csv`/`--stix` (the `--rules`
  fold-into-summary block at `:351-369` is the same shape). Prints a stderr line:
  `baseline: N hosts compared, M deviations`.
- `--update-baseline <p>`: `cfg.update_baseline = true`; after `run()`, load-or-empty the sidecar,
  `update_baseline(base, out.baseline.as_ref().unwrap(), now, &cfg)`, write `to_json_pretty()` (the exact
  `--index` write idiom at `:415-430`). Prints `updated behavioral baseline (K hosts) -> <path>`.

`now` = `SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)` — the
repo-standard clock read.

### 9.2 `baseline` subcommand (build / merge / show / diff) — mirrors `rescan`

A pure-transform subcommand over sidecar JSONs, structured exactly like `Rescan` (`cli.rs:433-496`):
empty-input guard, per-file `read_to_string` + `from_json_str` with `.with_context()`, pure core call,
human summary to stderr, `"-"`/path/omit JSON split.

```
ppcap baseline build   <summary.json…> [--out <baseline.json|->]      # build from analyze --json outputs
ppcap baseline merge    <baseline.json…> [--out <->]                  # fold several sidecars into one
ppcap baseline show    <baseline.json> [--json <->]                   # human summary + optional JSON
ppcap baseline diff    <baseline.json> <summary.json> [--json <->]    # deviation report (rescan analogue)
```

Declared as a nested `#[derive(Subcommand)] enum BaselineAction`, added to `enum Command` after `Rescan`
(`cli.rs:111`). Exit codes match repo convention: clap usage error → 2 (make positional `baseline`/
`candidate` non-`Option` like `Rescan.threat_feed`), empty-variadic/IO/parse → 1 (explicit guard +
`.with_context()?`), success → 0.

---

## 10. UI Surface

Shared React codebase, `isTauri()`-gated. Deviation findings ride the existing findings surfaces for
free; a dedicated **Baseline** tab adds the learned-profile view + deviation panel.

### 10.1 New "Baseline" tab — the five coordinated edit sites

1. `types.ts:608` — add `"baseline"` to `TAB_IDS` (TS then flags every dependent site).
2. `components/layout/AppShell.tsx:141` — add `{ id: "baseline", label: "Baseline", badge: deviationCount || undefined }` (derive the count like `chainCount`).
3. `components/layout/MobileNav.tsx:51` — add `baseline: Gauge` to `TAB_ICON` (`Record<TabId, LucideIcon>`).
4. `App.tsx:769-846` — add `tab === "baseline" ? (<BaselineView … />) :` branch; feed it
   `summary.status === "ready" ? summary.data : undefined` and the loaded `BaselineProfile`.
5. `components/layout/AppShell.tsx:257` — optional `go-baseline` command-palette action.

### 10.2 `views/BaselineView.tsx` (compose from existing primitives)

- **Empty state** (`EmptyState`): "No baseline yet — Learn from this capture" CTA.
- **Learned profile**: per-host card grid modeled on `ThreatsView.ThreatCard` (one `HostBaseline` per
  card: services, typical peers, byte mean±σ, captures-seen, active-hours sparkline).
- **This-capture deviations**: reuse `CompareView` / `lib/diff.ts` presentational parts
  (`DiffSection`/`ChangeStat`/`EntityRow`/`DeltaStat`) — the deviation view *is* a
  `diff(baselineProfile, thisCapture)`. Deviations render as `Finding`-shaped rows so
  `SeverityChip`/`kindLabel`/`sevColor` apply.

### 10.3 Deviations in the existing dashboard/findings

Add `"baseline_deviation"` to the `FindingKind` union (`types.ts:261`) **and** a `KIND_META` entry in
`lib/findingKinds.ts:40` (`{ label: "Baseline Deviation", Icon: Gauge }`). Because `kindMeta` already
falls back to a title-cased label + generic icon for unknown kinds (`findingKinds.ts:80`), the engine can
emit the kind *before* the TS union is updated without crashing. Copy
`components/triage/SignatureMatchesPanel.tsx` → `BaselineDeviationsPanel.tsx`
(`findings.filter(f => f.kind === "baseline_deviation")`, `null` if empty) and slot it into
`Dashboard.tsx:254` beside `SignatureMatchesPanel`. Findings folded into `summary.findings` also appear
in `FindingsView`, `ThreatGraph`/`ActivityHeatmap`/`AttackMatrixCard`, and CSV/STIX/Sigma exports for
free.

### 10.4 TS types + profile persistence

- `types.ts` — add `HostBaseline`/`BaselineProfile` interfaces mirroring the Rust schema (§4). The
  `BaselineProfile` is a **sidecar**, not part of `AnalysisOutput`.
- **Persistence** — new `lib/baseline.ts` mirroring `lib/recent.ts`, gated by `isTauri()`:
  - **Desktop:** `save({ defaultPath: "packetpilot-baseline.json" })` → `invoke("save_baseline", { profile, path })`; import via `open()` → `invoke("load_baseline", { path })`. Requires two new `#[tauri::command]`s in `src-tauri/src/lib.rs` (register in `invoke_handler`), following the `save_report`/`analyze_capture` template — note the Tauri build ships only `tauri_plugin_dialog` (no `tauri-plugin-fs`), so a dialog-chosen path + a Rust `std::fs::write`/`read_to_string` command is the required idiom. Silent cross-session auto-persist can use `dirs::cache_dir()/packetpilot/baseline.json` (the reputation-cache pattern).
  - **Web:** primary = **localStorage** under a scoped key (`scopedKey("packetpilot.baseline.v1")`) for the small profile JSON; export/import to a real file via File System Access API (`showSaveFilePicker`/`showOpenFilePicker`) with the existing `downloadText()` + hidden `<input type="file">` fallback (already used for "Load detection rules"). Bundled default served from `/public/sample/baseline.json` (like `SUMMARY_URL`). If profiles grow large, add a `baselines` IndexedDB store (bump `DB_VERSION` 3→4 in `recent.ts:196`).
- **Compute path:** for browser parity, call the new wasm `build_baseline`/`compare_to_baseline` (§8.1);
  or compute deviations in TS from the in-memory summary (the `lib/diff.ts` / `applyIocs` client-side
  pattern) if a Rust round-trip is not warranted for M1.

---

## 11. Testing

Mirrors the repo's in-module `#[cfg(test)]` + `gen` synthetic-fixture + Playwright e2e conventions.

### 11.1 New generator scenario

Add `Scenario::BaselineDrift` to `gen/mod.rs:44` (+ `from_str_opt` token + `all()` entry + `next_planned`
dispatch + `gen/mix.rs` weights) — updates the `Scenario::all().len()` assertion. It emits N "normal"
captures for a host set plus one "drift" capture (a host suddenly beaconing to a new peer / spiking
volume / new port), for deterministic learn→deviate fixtures. Determinism contract: same seed+count ⇒
byte-identical (`--seed` help).

### 11.2 Unit (`baseline/mod.rs` `#[cfg(test)]`)

- `running_stat_welford_matches_streamstats` — `RunningStat::observe` == `StreamStats::push` math.
- `running_stat_merge_is_order_independent` — Chan combine of two partitions == single replay (count/mean/m2/min/max).
- `baseline_serde_roundtrip_and_default` — `to_json_pretty`/`from_json_str` byte-roundtrip; `schema_version == BASELINE_SCHEMA_VERSION`; an older sidecar (missing post-v1 fields) deserialises via `serde(default)`; a newer `schema_version` is rejected.
- `merge_folds_capture_into_existing_baseline` — per-host stats update; idempotent/deterministic under input permutation (`assert_eq!` on serialised JSON).
- `compare_raises_expected_deviations` / `conforming_host_raises_no_finding` / `empty_baseline_yields_no_deviations` / `unknown_host_absent_from_baseline_is_handled_gracefully`.
- `bounded_under_many_hosts` — `max_hosts`/`top_k_*` caps hold; no unbounded growth.

### 11.3 Integration (`analyze/mod.rs` `#[cfg(test)]`, gen-driven)

`learn_then_deviate`: gen "normal" scenario → `--update-baseline` → gen "drift" scenario → analyze with
`--baseline` → assert `out.summary.findings` contains a `baseline_deviation` on the expected host at the
expected severity; assert existing fields unchanged (additive); assert
`peak_heap_bytes() < PHASE0_BUDGET.max_peak_heap_bytes`.

### 11.4 Serialization / determinism / wasm / CLI

- `baseline_is_deterministic_under_input_permutation` (BTreeMap/sorted-Vec/min-max folds).
- WASM smoke: `build_baseline` + `compare_to_baseline` round-trip through the JSON boundary (mirror `apply_rules_folds_matches_into_output`).
- CLI arg-parse tests: `analyze --baseline`/`--update-baseline` and `baseline build/merge/show/diff` (mirror `analyze_index_flag_parses` / `rescan_parses_indices_and_feed` at `cli.rs:808/823`).

### 11.5 UI

`BaselineView.test.tsx` + `BaselineDeviationsPanel.test.tsx` (Vitest, ≥80% lines/functions target) seeded
via `makeOutput({ findings: [{ kind: "baseline_deviation", … }] })`; optional e2e spec in `ui/e2e/`.

---

## 12. Performance & Invariants

- **Bounded memory, independent of capture size.** No new unbounded state: per-host maps use the
  `bump_bounded` heavy-hitter evictor (`stats/mod.rs:1240`) capped by `max_hosts`; per-host sets capped by
  `top_k_*`; `categories[13]`/`hour_of_day[24]` are fixed arrays. The compare/snapshot read only the
  already-bounded live tracker — no whole-capture buffering. The ≤64 MiB / ≥250k pkt/s / <2s-per-100k
  budget is untouched.
- **Single-pass streaming.** Learning is a post-EOF snapshot of the tracker (like the TLS-cert / carve
  drains); comparison is a pure diff at EOF. No second packet pass. The `merge`/`update` transforms run
  over summaries + sidecars only (no pcap re-read), like `rescan`.
- **C-compiler-free.** Pure-Rust `serde_json` + f64 math + `BTreeMap`/arrays — no new deps, so the CI
  "cc-free gate" (`cargo tree … | grep -E 'zstd-sys|lz4-sys|cc |cmake|…'`) stays clean.
- **Local-first privacy.** The baseline sidecar is derived stats only (no packets/payloads), stays on the
  device, and every transform is offline (`compare_to_baseline` is network-free, like `rescan`). The
  shared/team store that *would* move data off-device is explicitly out of scope (§16).
- **Time.** i64 ns for capture windows (`first_ts_ns`/`last_ts_ns`), i64 unix-secs for wall-clock
  (`analyzed_unix_secs`/`first_seen_unix`), end to end.
- **Determinism.** `BTreeMap`-accumulate → sorted-`Vec`; min/max + additive folds (order-independent);
  no `Date::now`/`rand`; `assert_eq!` roundtrip + permutation tests guard it.

---

## 13. Phased Rollout (each milestone independently shippable)

- **M1 — Sidecar + learn/compare core (engine + CLI).** `baseline/mod.rs` (schema, `RunningStat`,
  build/update/merge/compare), `BehaviorTracker::baseline_snapshot`, `FindingKind::BaselineDeviation`,
  the analyze seams, `score_baseline_deviation`, `analyze --baseline`/`--update-baseline`, the `baseline`
  subcommand. *Value: a CLI user can learn a baseline over N captures and get deviation findings on N+1,
  fully offline.* **Acceptance:** `learn_then_deviate` integration test green; deviations appear in
  `--json`/`--html`; bounded-memory + determinism tests pass; cc-free gate clean.
- **M2 — Novelty dimensions complete.** The three net-new per-host accumulators (JA3 set, active-hours
  histogram, category histogram) + new-beacon diff. *Value: first-seen-JA3, off-hours, new-category, and
  new-periodic-channel deviations.* **Acceptance:** unit tests per dimension; no perf regression.
- **M3 — WASM + browser compute.** `build_baseline`/`compare_to_baseline` wasm exports; TS types;
  localStorage/File-System-Access persistence; bundled sample baseline. *Value: the web build learns &
  compares in-browser, nothing leaves the device.* **Acceptance:** wasm smoke test; web e2e.
- **M4 — Baseline UI.** `BaselineView` (profile grid + deviation diff), `BaselineDeviationsPanel`,
  Baseline tab (five edit sites), `KIND_META` entry. *Value: analysts see the learned profile and this
  capture's drift.* **Acceptance:** Vitest ≥80%; a11y/responsive specs pass.
- **M5 — Desktop persistence + polish.** `save_baseline`/`load_baseline` Tauri commands + dialogs;
  confidence/warmup surfacing; docs (`docs/behavioral-baseline.md` user-facing, mirroring
  `time-machine.md`). *Value: desktop parity + a "Guarantees, verified by tests" doc.*
  **Acceptance:** desktop build green; user doc merged.

---

## 14. Risks, Edge Cases & Open Questions

| Risk / case | Mitigation |
|---|---|
| **Cold-start false positives** — a 1–2 capture baseline flags everything as "new" | `BaselineParams.min_captures` warmup gate (default 5): `compare_to_baseline` emits deviations for a host only once `captures_seen >= min_captures`; per-host `captures_seen` also drives a UI **confidence** badge. Volume-spike needs `RunningStat.count >= min_captures` before mean+k·σ is trusted. |
| **Baseline poisoning** — learning from an already-compromised network bakes malicious behavior into "normal" | (a) Never auto-learn: `--update-baseline` is explicit and operator-driven. (b) Don't fold captures that already carry Critical/IOC findings into the baseline by default (a `--force-learn` override exists). (c) Support **reset/prune**: `baseline` subcommand can drop a host or rebuild from a chosen clean window; the UI exposes per-host "forget". (d) Document that a baseline reflects *observed* normal, not *known-good* normal. |
| **Entity identity across DHCP/NAT** — an internal IP is not a stable host across time | Key by IP for M1 (documented limitation). The engine already collects L2 identity (`arp_hosts` IP→MAC, `dhcp_hosts` MAC→hostname) — a follow-up can key the profile on MAC/hostname where available. NAT/CGNAT egress is excluded by the `is_external` gate (CGNAT is treated external, so we don't baseline a shared NAT address as one host). |
| **Threshold tuning** — k-sigma / ratios are workload-specific | All thresholds live on `BaselineParams` (k-sigma default 4, off-hours min-populated-hours, min-captures), defaulted conservatively so deviation-alone caps at Medium; High/Critical needs corroboration (§6.3). No hard-coded magic beyond the documented defaults. |
| **Multi-network / roaming laptops** | M1 is one profile per sidecar file (one monitored network). A host that legitimately moves networks is out of scope for M1; the sidecar-per-network model composes (analyst keeps `office.baseline.json`, `dmz.baseline.json`). |
| **Malformed / adversarial sidecar JSON** | `from_json_str` returns a typed `PpError` (never panics); `run()`'s load-fail is fail-fast with `.with_context()`. Newer `schema_version` rejected explicitly. |
| **Sparse hosts** — a host seen in 1 of 40 captures | `captures_seen` gates deviation emission and is surfaced; a rarely-seen host produces low-confidence, not loud alerts. |

**Open questions for review:**
1. Default `min_captures` warmup — 5, or expose only and default 1 with a UI confidence gauge?
2. Should already-Critical/IOC captures be excluded from `--update-baseline` by default (poisoning guard),
   or folded with a warning? (This plan defaults to **exclude**, with `--force-learn`.)
3. EWMA: keep as UI-only trend hint (this plan), or make the deviation gate EWMA-aware (loses exact
   cross-sidecar merge)?
4. Beacon-diff: treat a *disappeared* baseline beacon as a deviation too (host stopped its normal
   check-in), or only *new* beacons (this plan)?

---

## 15. File-by-File Change Checklist

| File | Add / Modify | Reason |
|---|---|---|
| `engine/crates/ppcap-core/src/baseline/mod.rs` | **Add** | Schema, `RunningStat`, `CaptureProfile`, build/update/merge/compare, `DeviationReport`, tests |
| `engine/crates/ppcap-core/src/lib.rs` | Modify | `pub mod baseline;` + re-export block |
| `engine/crates/ppcap-core/src/detect/mod.rs` | Modify | `baseline_snapshot()`; `ja3`/`activity`/`category` per-host fields + folds; new arm in `stage_ordinal`/`stage_label`/`kind_phrase` |
| `engine/crates/ppcap-core/src/report/mod.rs` | Modify | one new arm in exhaustive `kind_label` match (`:597`) |
| `engine/crates/ppcap-core/src/model/finding.rs` | Modify | `FindingKind::BaselineDeviation` + `as_str`; optional `terms` field |
| `engine/crates/ppcap-core/src/model/output.rs` | Modify | `#[serde(default)] baseline: Option<CaptureProfile>` |
| `engine/crates/ppcap-core/src/analyze/mod.rs` | Modify | PipelineConfig fields; load/compare/snapshot seams; `observe_ja3` call in `process_flow` |
| `engine/crates/ppcap-core/src/stats/mod.rs` | Modify | Copy `terms` in `apply_findings` raise branch (explainability) |
| `engine/crates/ppcap-core/src/model/summary.rs` | Modify | Copy `terms` in `apply_findings` raise branch |
| `engine/crates/ppcap-core/src/score/mod.rs` | Modify | `score_baseline_deviation` + `PTS_DEV_*`/`DEV_UPLIFT_CAP` |
| `engine/crates/ppcap-core/src/gen/mod.rs` + `gen/mix.rs` | Modify | `Scenario::BaselineDrift` fixture (5-touch) |
| `engine/crates/ppcap-cli/src/cli.rs` | Modify | `analyze --baseline`/`--update-baseline`; `baseline` subcommand + dispatch; parse tests |
| `engine/crates/ppcap-wasm/src/lib.rs` | Modify | `build_baseline` + `compare_to_baseline` exports (M3) |
| `ui/src/types.ts` | Modify | `"baseline"` TabId; `"baseline_deviation"` FindingKind; `HostBaseline`/`BaselineProfile` |
| `ui/src/lib/findingKinds.ts` | Modify | `KIND_META["baseline_deviation"]` |
| `ui/src/views/BaselineView.tsx` | **Add** | Learned-profile grid + deviation diff (M4) |
| `ui/src/components/triage/BaselineDeviationsPanel.tsx` | **Add** | Dashboard panel (copy of `SignatureMatchesPanel`) |
| `ui/src/components/layout/{AppShell,MobileNav,SideNav}.tsx` | Modify | Tab registration + icon (M4) |
| `ui/src/App.tsx` | Modify | Render branch + baseline load/persist wiring |
| `ui/src/lib/baseline.ts` | **Add** | localStorage/FS-Access (web) + Tauri (desktop) persistence |
| `ui/src-tauri/src/lib.rs` | Modify | `save_baseline`/`load_baseline` commands + `invoke_handler` (M5) |
| `docs/behavioral-baseline.md` | **Add** | User-facing doc (M5, mirrors `time-machine.md`) |
| **NOT touched** | — | `columnar/*`, `FLOW_PARQUET_VERSION`, `sql/schema.sql`, wasm `FlowDto`, `ui/src/lib/query/flow_columns.json` (`schema_drift.rs` guard) — BBL is summary-level, not per-flow. `supabase/*`, `relay/*` — team store is out of scope. |

---

## 16. Out of Scope & Follow-ups

> **Scope.** This is the local-first core: learn / merge / compare over an **offline JSON baseline
> sidecar**, per internal host, entirely on-device. A **shared/team baseline store** (multiple analysts
> contributing to and querying one org-wide baseline), **scheduled auto-baselining**, **file-hash and
> passive-DNS baselining**, **MAC/hostname-stable entity identity**, and **statistical/ML upgrades**
> (clustering, seasonality) are deliberately out of scope here and tracked as follow-ups.

The shared/team store is where BBL would eventually attach to the existing `supabase/` backend (accounts,
RLS, Edge Functions) — a new migration + table + RLS policy + RPC. That path requires a network round-trip
and an account, which violates the *capture-never-leaves-the-device* invariant the product is wedged on,
so it stays out of the local-first core — the same boundary Time Machine draws for its team-case-store
follow-up. It is directly adjacent to the README roadmap's "scheduled re-scans", "shared team case store",
and "Self-hosted team server (shared cases, RBAC) — the 'hybrid' other half."

---

## Guarantees, verified by tests (target)

- **Correctness of extraction** — `baseline_snapshot` collects the expected per-host peers/services/
  categories/ja3/hours/volume, bounded by caps.
- **Deterministic merge** — folding captures in any order yields byte-identical sidecars (Welford
  parallel-combine + additive/min-max folds; `BTreeMap`→sorted-`Vec`).
- **Deviation detection** — a host diverging from its stored profile surfaces a `baseline_deviation`
  finding at the expected severity; a conforming host surfaces nothing; cold-start (below warmup) stays
  quiet.
- **Offline + bounded** — pure transforms over the summary and the sidecar; no packet re-read, no
  network; peak heap within the Phase-0 budget.
- **Explainable** — every deviation point reconciles to one `ScoreTerm` + one evidence line via the same
  `add_term` ledger as the rest of the engine.

---

## Appendix A — Design-review corrections (folded in above)

Adversarial review across engine/invariants/product lenses, most-load-bearing first:

1. **Substrate reconciliation (engine).** Two maps pointed at different substrates — `StatsAccumulator`
   (consumed by `finish()` at `analyze/mod.rs:514`) vs the live `BehaviorTracker`. Corrected: read the
   **`BehaviorTracker`** (not consumed by `finish`), so both compare (`:479`) and snapshot (`:489`) are
   unconstrained by `finish()`; a single `baseline_snapshot()` accessor serves learn *and* compare (§7.2,
   §7.5).
2. **`*Params` location (engine).** Detector tuning lives on **`PipelineConfig`**, not `DetectConfig`
   (which is memory-caps only). `BaselineParams` is added to `PipelineConfig` (§7.5).
3. **Genuinely-new code isolated (engine).** `StreamStats` is not serialisable/mergeable and there is no
   EWMA primitive — so `RunningStat` (serde + Chan merge + EWMA) is the one new algorithm; JA3 and
   hour-of-day are the two net-new bounded accumulators. Everything else is pattern-copy (§4.1, §7.3).
4. **EWMA merge honesty (invariants).** EWMA is order-dependent and cannot merge exactly across sidecars;
   the hard deviation gate uses mean+k·σ (which merges exactly), EWMA is a UI trend hint only (§5).
5. **Cold-start & poisoning (product).** Added the `min_captures` warmup gate + confidence, the
   don't-auto-learn-dirty-captures default, and reset/prune (§14).
6. **Explainability parity (product).** Deviation must appear in `IpThreat.score_terms`, not just
   `evidence` — hence the additive `Finding.terms` field + the two `apply_findings` copies (§6.3).
7. **Schema-drift guard untouched (invariants).** BBL is summary-level; the Parquet/flow schema and its
   cross-language `schema_drift.rs` guard are explicitly not touched (§8, §15).

*Second review pass — verified against the tree post-draft:*

8. **HTML report is not a zero-change ride-through (engine).** `report/mod.rs::kind_label` (`:597`) is an
   exhaustive `match FindingKind` with no `_`, so the new variant needs one arm there or `ppcap-core`
   won't compile. Corrected §1/§8/§15 (findings still render for free otherwise).
9. **Per-host category is net-new (engine).** `per_category` (`stats/mod.rs:149`) is capture-wide, not
   per-host, and `ContactSeries.add_class` stores no `Category` — so "new category" needs a *third*
   net-new per-host accumulator (`category: HashMap<IpAddr,[u32;13]>`). Added in §7.3; dimension marked M2.
10. **Compiler-forced match sites re-enumerated (engine).** The exhaustive `match FindingKind` sites are
    `finding.rs:as_str`, `detect/mod.rs:{stage_ordinal,stage_label,kind_phrase}`, and
    `report/mod.rs:kind_label` — **not** an ATT&CK map (`technique_name` is string-keyed with a `_ => id`
    fallback; attack ids are set per-detector at construction). Corrected §6.1/§7.4.
11. **`Summary::apply_findings` field name (engine).** The `IpThreat` card field is `score_terms`
    (`summary.rs:180`), not `terms`, so the summary-side copy is `card.score_terms = f.terms.clone()`.
    Corrected §6.3.

## Appendix B — Citation verification

Every load-bearing path, line, and signature in §§3–10 was read from the checked-out tree by the
subsystem readers: `detect/mod.rs` (`BehaviorTracker`, `ContactSeries`, `StreamStats`, `*Params`,
candidate accessors), `model/{finding,summary,flow,severity,output}.rs` (finding/severity/flow fields,
`apply_findings`), `timemachine/mod.rs` + `case/mod.rs` (sidecar + cross-capture patterns),
`analyze/mod.rs` + `stats/mod.rs` (pipeline seams, `bump_bounded`, caps), `score/mod.rs` +
`enrich/mod.rs` (`add_term`, weights, `is_external`), `ppcap-cli/src/cli.rs` (`--index`/`rescan`
precedents), `ppcap-wasm/src/lib.rs` (export pattern), and the UI (`App.tsx`, `views/`, `types.ts`,
`lib/{findingKinds,diff,recent,platform,tauri-detect}.ts`, `src-tauri/src/lib.rs`). Line numbers reflect
the tree at branch `claude/behavioral-baseline-learning-7w6l0u`; treat them as anchors — verify with a
local `grep` before editing, as the repo evolves.
