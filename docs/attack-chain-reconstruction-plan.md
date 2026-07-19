# PacketPilot — Auto Attack Chain Reconstruction

**Implementation Plan**

| | |
|---|---|
| **Status** | Proposed — ready to implement |
| **Feature branch** | `claude/auto-attack-chain-reconstruction-nh5b01` |
| **Date** | 2026-07-19 |
| **Scope** | Engine (Rust) + UI (React/TS) + HTML report + AI brief |

> **How this plan was produced.** Six subsystems (detect/correlation, pipeline/timing,
> serialization/report, gen/testing, UI, AI/enrich) were surveyed against source; three
> independent reconstruction algorithms were designed and judged; the strongest single
> approach was synthesized; then the plan was adversarially reviewed against the codebase.
> Every cited path, line number, and signature below was verified against the checked-out
> tree. The corrections from that review (see *Appendix A*) are already folded into the plan.

---

## 1. Summary & Goals

### What ships
A new engine post-pass, `reconstruct_attack_chains(&[Finding]) -> Vec<AttackChain>`, that upgrades PacketPilot from flat per-host incidents into **true, multi-host, temporally-ordered, causally-linked attack chains**, plus **campaign clustering** over shared adversary infrastructure and an explicit **MITRE ATT&CK tactic progression**. Chains ride through JSON → HTML report → WASM → the React UI (a new swimlane view) → the AI exec brief → (M5) STIX export. `attack_chains` is a new `#[serde(default)]` field on `Summary`; `incidents` is retained unchanged.

### What it changes vs. today's `correlate_incidents` (detect/mod.rs:3301)

| Dimension | Today | New |
|---|---|---|
| **Join key** | `f.src_ip` only (BTreeMap group, :3305) | Per-host progressions **stitched** across hosts when `victim(X) == actor(Y)` |
| **Cross-host pivots** | None | Explicit `ChainEdge{Pivot, via_kind}` (A brute-forces B → B beacons → B exfils = one chain) |
| **Ordering** | `stage_ordinal` taxonomy sort (:3317) | Real `first_seen_ns` time order; taxonomy as tie-break/fallback |
| **Causality** | None | Causal gate: `a_reach ≤ b_start + skew`, dwell ≤ 1h |
| **Structure** | Flat `Vec<Incident>` by host | DAG-forest: typed `steps` + `edges`, findings referenced by index |
| **Campaign clustering** | None | Chains sharing strong C2 / DGA / JA3 infra cluster (gated union-find) |
| **ATT&CK output** | Sorted-deduped union (:3354) | Ordered *progression* `T1046 → T1110 → T1071 → T1048` with id+name |
| **Escalation** | +1 band if ≥2 distinct kinds | +1 band per (≥2 tactics) and (≥2 hosts), plus a `confidence` score |

`incidents` remains the per-host triage unit (UI `IncidentHero`, the `generated_beacon_scenario_is_detected_as_high` test, AI context, STIX all depend on it). Chains are the **cross-host superstructure** over the same finding vector; a single-host chain degenerates to exactly one of today's incidents.

---

## 2. Chosen Algorithm

### 2.0 Synthesis of the three candidate designs
Use the **statemachine** design as the chain builder (per-host monotone progressions → causal pivot stitch → acyclic single-parent forest; reuse `stage_ordinal`/`stage_label` verbatim so the spine agrees byte-for-byte with `Incident.stages`). Adopt the **TCG** design's explicit graph output model (typed `steps`/`edges`, `finding_index` back-references, `EdgeKind`) and its total-order time key for determinism. Graft the **unionfind-campaign** design's *gated* union-find at the **chain→campaign label** layer only (never the finding layer), so a spurious infra edge merges a label, not an indivisible chain, and hub-degree suppression stops benign-infra over-merge.

### 2.1 Constants (compile-time; no config surface — preserves determinism & schema stability)

```rust
const MAX_CHAIN_HOSTS:      usize = 4096;                  // progressions tracked (mirror max_fanout_per_src)
const MAX_STEPS_PER_HOST:   usize = 64;                    // steps/host (drop lowest-score at cap)
const MAX_EDGES:            usize = 2048;                  // candidate pivot edges (drop lowest-weight)
const MAX_CHAINS:           usize = 256;                   // emitted chains (worst-first; overflow dropped)
const MAX_CHAIN_VICTIMS:    usize = 16;                    // Finding.victims cap
const SKEW_TOLERANCE_NS:    i64   = 1_000_000_000;         // 1s clock-jitter / flow-start-approx slack
const CORRELATION_WINDOW_NS:i64   = 3_600_000_000_000;     // 1h max pivot dwell
const MAX_HUB_DEGREE:       usize = 12;                    // campaign: infra above this stops auto-merge
const INFRA_MIN_DEGREE:     usize = 2;                     // campaign: infra needs >=2 distinct actors
```

### 2.2 Normalization accessors (the single home of kind-specific semantics)

```rust
// Actor = the host the step is attributed to. ArpSpoof/SynFlood keep the VICTIM in src_ip; that is
// still the correct owner of the step (the box that was DoS'd / poisoned). They simply cannot SOURCE
// a pivot (victims_of returns empty), so they never root an adversary chain over a victim.
fn actor_host(f: &Finding) -> &str { f.src_ip.as_str() }   // NEVER None — every finding gets a step

// The compromise-propagation targets: this finding's victim becomes the next stage's actor.
fn victims_of<'a>(f: &'a Finding) -> Vec<&'a str> {
    match f.kind {
        FindingKind::BruteForce | FindingKind::ExposedRemoteAccess | FindingKind::PortScan =>
            f.dst_ip.as_deref().into_iter().collect(),
        FindingKind::LateralMovement | FindingKind::HostSweep =>
            f.victims.iter().map(String::as_str).collect(),   // recovered in §4.2
        // ArpSpoof/SynFlood/Beacon/DataExfil/... never propagate compromise to a new actor:
        _ => Vec::new(),
    }
}

fn handoff_weight(k: FindingKind) -> u16 {
    match k {
        FindingKind::BruteForce          => 100, // credential compromise: strongest
        FindingKind::ExposedRemoteAccess =>  90, // foothold established
        FindingKind::LateralMovement     =>  80, // authenticated pivot
        FindingKind::HostSweep | FindingKind::PortScan => 30, // discovery-only: weak fallback
        _ => 0,
    }
}

fn tactic_ordinal(k: FindingKind) -> u8      { stage_ordinal(k) } // reuse detect/mod.rs:3396 verbatim
fn tactic_label(k: FindingKind)   -> &'static str { stage_label(k) } // reuse detect/mod.rs:3424
```

> **Correction vs. draft:** `actor_host` no longer returns `None` for ArpSpoof/SynFlood — dropping them deleted the Impact/AiTM tactics from every chain. They now attach as ordinary (leaf) steps on the victim's progression; they are barred from *sourcing* pivots purely because `victims_of` returns empty for them.

### 2.3 Total-order time key (determinism foundation — no comparator returns `Equal`)

```rust
fn t_of(f: &Finding) -> i64 { f.first_seen_ns.unwrap_or(i64::MAX) } // absent time sorts last

fn step_key(f: &Finding, idx: usize) -> (i64, u8, core::cmp::Reverse<u16>, u8, u32) {
    ( t_of(f),                    // 1. real time (i64::MAX => taxonomy takes over)
      tactic_ordinal(f.kind),     // 2. earlier kill-chain stage first on equal/absent time
      core::cmp::Reverse(f.score),// 3. stronger finding first
      f.kind as u8,               // 4. kind (FindingKind is a fieldless enum — `as u8` is valid)
      idx as u32 )                // 5. original vector index — unique final tie-break
}
```

### 2.4 The algorithm (pseudocode)

```text
fn reconstruct_attack_chains(findings: &[Finding]) -> Vec<AttackChain>:
    if findings.is_empty(): return []

    # ---- Phase 1: per-host progressions (BTreeMap => deterministic key order) ----
    progressions: BTreeMap<&str, Vec<usize>>            # values = finding indices
    for (idx, f) in findings.enumerate():
        host = actor_host(f)                            # every finding gets a step now
        if !progressions.contains(host) && progressions.len() >= MAX_CHAIN_HOSTS: continue  # drop-new-at-cap
        progressions[host].push_capped(idx, MAX_STEPS_PER_HOST, drop = lowest findings[idx].score)
    for (host, steps) in progressions:
        steps.sort_by_key(|&i| step_key(&findings[i], i))   # time, then taxonomy tie-break
    actor_set: BTreeSet<&str> = progressions.keys()

    # ---- Phase 2: candidate pivot edges (A --victim--> B) ----
    edges: Vec<PivotEdge> = []
    for (idx, f) in findings.enumerate():
        A = f.src_ip.as_str()
        if !progressions.contains(A): continue
        for B in victims_of(f):
            if B == A || !actor_set.contains(B): continue        # B must itself be a later actor
            a_reach = f.first_seen_ns
            b_start = progressions[B].iter().filter_map(|&i| findings[i].first_seen_ns).min()
            if let (Some(ar), Some(bs)) = (a_reach, b_start):    # causal gate ONLY when both known
                if ar > bs + SKEW_TOLERANCE_NS: continue         # A can't compromise B after B started
                if bs - ar > CORRELATION_WINDOW_NS: continue     # dwell too long => different episode
            edges.push_capped(PivotEdge{from:A, to:B, via_kind:f.kind, via_finding_idx:idx,
                                        a_reach, weight:handoff_weight(f.kind)},
                              MAX_EDGES, drop = lowest weight)

    # ---- Phase 3: stitch into an acyclic single-parent forest ----
    parent: BTreeMap<&str, PivotEdge> = {}
    for B in (hosts with >=1 incoming edge, sorted):
        cands = incoming(B) sorted by ( weight desc, Reverse(|b_start-a_reach|), Reverse(depth(from)), from )
        for e in cands:
            if !ancestor_walk_finds(e.from is descendant of B):  # bounded by MAX_CHAIN_HOSTS
                parent[B] = e; break
        # if every candidate would cycle, B stays a root

    # ---- Phase 4: assemble one AttackChain per tree ----
    roots = { h in progressions : parent has no entry for h }
    chains = []
    for r in sorted(roots):
        members = BFS(r) over parent-inverse, children sorted by (host_first_seen, host_str)
        chains.push_capped(build_chain(r, members, findings, edges, parent), MAX_CHAINS)
    chains.sort_by(severity.rank desc, score desc, first_ts asc, id asc)  # same discipline as incidents

    # ---- Phase 5 (M5): campaign clustering over STRONG shared infrastructure ----
    assign_campaign_ids(&mut chains, findings)                   # gated union-find, §2.6
    return chains
```

### 2.5 `build_chain` — steps, edges, escalation, confidence, narrative

```text
member_steps = concat each member host's (already time-sorted) indices
global_steps = member_steps re-sorted by step_key   -> assign ChainStep.order = position

# Edges are STRUCTURAL, not array-adjacency:
edges = []
for host in members:                                            # Progression edges, per host
    for consecutive (i, j) in that host's own time-ordered substeps:
        edges.push(ChainEdge{ from:order[i], to:order[j], kind:Progression, via_kind:None,
                              gap_ns: clamp0(t_of(j) - last_seen(i)) })
for B in members where parent[B] exists:                        # exactly one Pivot edge per stitched child
    let e = parent[B]
    from_step = order of e.via_finding_idx                      # the handoff finding on the parent
    to_step   = order of B's first (earliest) step
    edges.push(ChainEdge{ from:from_step, to:to_step, kind:Pivot, via_kind:Some(e.via_kind),
                          gap_ns: clamp0(b_first - a_reach) })

hosts   = distinct actor hosts ordered by (host_first_seen.unwrap_or(MAX), host_str)  # deterministic
tactics = distinct tactic_label in global step order
base_sev= max over member findings' severity
esc     = (tactics.len() >= 2) as u8 + (hosts.len() >= 2) as u8      # 0..2 bands
severity= escalate applied `esc` times to base_sev                   # reuse escalate() (detect:3480)
score   = min(100, max_finding_score + 10*min(tactics.len()-1, 2) + 10*min(hosts.len()-1, 1))
confidence: i32 = 40
        + 10 * min(tactics.len() as i32, 4)
        + if any pivot via_kind in {BruteForce, ExposedRemoteAccess} {15} else {0}
        + if every pivot passed the causal gate with KNOWN timestamps {10} else {0}
        +  5 * min(hosts.len() as i32 - 1, 3)
        - if any step.first_seen_ns == None {20} else {0}
        - if the only pivots are HostSweep/PortScan {10} else {0};
confidence = confidence.clamp(0, 100) as u8                          # signed math, then clamp (never underflow)
attack  = technique ids in global step order, deduped preserving first occurrence
id      = "chain:" + fnv1a(sorted distinct member host list)        # hosts disjoint across trees => unique
narrative = deterministic prose from ordered kind_phrase() verbs + pivot arrows with gap_ns
```

> **Corrections vs. draft:** structural edge construction (issue #2), signed `confidence` (issue #7), deterministic `hosts` order and deduped `attack` (issue #6).

### 2.6 Campaign clustering (M5 — gated union-find, strong-infra only)

```text
fn assign_campaign_ids(chains, findings):
    # STRONG adversary-signal endpoints only. DataExfil/Cryptomining/Malware* dst are EXCLUDED
    # (weakest signal; a shared backup/pool would falsely bind unrelated hosts).
    infra_key(f) = match f.kind:
        Beacon | TlsCertHealth        if dst external => Some("c2:" + dst_ip + ":" + dst_port)
        Dga                                            => Some("domain:" + dga_domain(f))  # from evidence sample
        _ (with ja3 surfaced on finding)               => Some("ja3:" + ja3)
        else                                           => None
    degree:          BTreeMap<InfraKey, BTreeSet<host>>       # distinct actor hosts per infra key
    infra_to_chains: BTreeMap<InfraKey, BTreeSet<chain_idx>>
    for (ci, chain) in chains: for step in chain.steps:
        if let Some(k) = infra_key(&findings[step.finding_index]):
            degree[k].insert_capped(step.actor, MAX_HUB_DEGREE+1)
            infra_to_chains[k].insert(ci)
    uf = UnionFind(chains.len())
    for (k, chain_set) in infra_to_chains:                     # BTreeMap => deterministic
        if INFRA_MIN_DEGREE <= degree[k].len() <= MAX_HUB_DEGREE && chain_set.len() >= 2:
            union all chain_set
    for cluster with >= 2 chains:
        cid = "campaign:" + fnv1a(min chain.id in cluster)     # canonical = min member id (deterministic)
        set chain.campaign_id = Some(cid) for every member
```

> **Correction vs. draft:** `DataExfil`/`Cryptomining`/`DisguisedDownload`/`Malware*` destinations no longer mint infra keys (issue #9).

### 2.7 Worked example — A → B → C2 pivot (the proof it does NOT collapse to per-host)

Findings post-detection (with new `first_seen_ns`; `t` = offset from capture start):

| idx | kind | actor `src_ip` | victim/`dst_ip` | infra | `first_seen_ns` | tactic |
|---|---|---|---|---|---|---|
| 0 | HostSweep | A=10.13.37.7 | victims=[10.66.0.1,…] (recovered §4.2) | — | 0.0s | Discovery |
| 1 | BruteForce | A=10.13.37.7 | B=10.66.0.1:22 | — | 2.5s | Credential Access |
| 2 | Beacon | B=10.66.0.1 | — | c2:45.77.13.37:443 | 30.0s | Command & Control |
| 3 | DataExfil | B=10.66.0.1 | 185.220.101.5:443 | *(not infra)* | 40.0s | Exfiltration |

- **Phase 1:** `A → [0@0.0s, 1@2.5s]`, `B → [2@30s, 3@40s]`. `actor_set = {A, B}`.
- **Phase 2:** F1 (BruteForce on A) names B; B ∈ actor_set; gate `a_reach=2.5s ≤ b_start=30s` ✓, dwell `27.5s ≤ 1h` ✓ → **edge A→B via BruteForce (w=100)**. F0 (HostSweep) names B → **edge A→B via HostSweep (w=30)**.
- **Phase 3:** B's incoming argmax by `(weight, …)` picks **BruteForce (100 > 30)**. A is not a descendant of B → no cycle. `parent[B] = (A via BruteForce, via_finding_idx=1)`. A is a root.
- **Phase 4 — one chain:** global step order `[0,1,2,3]`. Structural edges: `Progression 0→1` (A), `Pivot 1→2 via BruteForce` (parent handoff → B's first step), `Progression 2→3` (B). `hosts=[A,B]`. `tactics=[Discovery, Credential Access, C2, Exfiltration]`. `esc = 1 (≥2 tactics) + 1 (≥2 hosts) = 2` ⇒ `escalate(escalate(High)) = Critical`.

```
AttackChain  severity=Critical  score=100  confidence=95  campaign_id=None
  hosts:  [10.13.37.7, 10.66.0.1]
  ATT&CK progression:  T1046 → T1110 → T1071 → T1048
  edges:  [Progression(0→1), Pivot(1→2, via BruteForce), Progression(2→3)]
  title:  "Cross-host attack chain: 10.13.37.7 → 10.66.0.1 → C2 45.77.13.37"
```

**Contrast:** `correlate_incidents` emits **two** disconnected incidents (A: Discovery+CredAccess; B: C2+Exfil) because it joins only on `src_ip`. The new pass fuses them via `BruteForce.dst_ip == Beacon.src_ip`, time-ordered. This is a genuine cross-host reconstruction, not a per-host collapse.

---

## 3. Data Model

### 3.1 New Rust types — `model/attack_chain.rs` (new file)
Derive `Debug, Clone, PartialEq, Serialize, Deserialize` (not `Eq` — `f64` reachable via findings). Every added/optional field carries `#[serde(default)]`.

```rust
use crate::model::finding::FindingKind;
use crate::model::severity::Severity;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AttackChain {
    pub id: String,                             // "chain:" + fnv1a(sorted host set)
    pub severity: Severity,
    pub score: u16,                             // 0..=100
    pub confidence: u8,                         // 0..=100
    pub title: String,
    pub narrative: String,
    pub hosts: Vec<String>,                     // actor hosts, first-seen order (tie: host str)
    pub steps: Vec<ChainStep>,                  // time, then taxonomy tie-break
    pub edges: Vec<ChainEdge>,                  // structural: Pivot + Progression
    pub tactics: Vec<TacticStep>,               // ATT&CK tactic progression
    pub attack: Vec<String>,                    // technique ids in chain order (deduped, NOT sorted)
    #[serde(default)]
    pub campaign_id: Option<String>,            // set in M5 when >=2 chains share strong infra
    pub first_ts_ns: Option<i64>,
    pub last_ts_ns: Option<i64>,
    pub host_count: u32,
    pub tactic_count: u32,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ChainStep {
    pub order: u32,                             // 0-based global position in `steps`
    pub actor: String,                          // host of THIS step (varies on a pivot)
    pub tactic_ordinal: u8,                     // == stage_ordinal (0..=6)
    pub tactic: String,                         // stage_label
    pub kind: FindingKind,
    pub techniques: Vec<TechniqueRef>,          // id + resolved name (§9 table)
    pub peer: Option<String>,                   // dst_ip / C2 / resolver
    pub severity: Severity,
    pub score: u16,
    pub first_seen_ns: Option<i64>,
    pub last_seen_ns: Option<i64>,
    #[serde(default)]
    pub evidence: Option<String>,               // ONE representative bullet (esc()'d at render)
    pub finding_index: u32,                     // back-ref into Summary.findings — no payload re-embed
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ChainEdge {
    pub from: u32,                              // ChainStep.order
    pub to: u32,
    pub kind: EdgeKind,
    #[serde(default)]
    pub via_kind: Option<FindingKind>,          // handoff kind for a Pivot; None for Progression
    pub gap_ns: Option<i64>,                     // dwell, clamped >=0; None if unknown
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind { Pivot, Progression }

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TacticStep {
    pub ordinal: u8,
    pub tactic: String,
    pub techniques: Vec<TechniqueRef>,
    pub host: String,                           // representative host reaching this tactic
    pub first_seen_ns: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TechniqueRef { pub id: String, pub name: String }
```

`model/mod.rs`: add `pub mod attack_chain;` and `pub use attack_chain::{AttackChain, ChainStep, ChainEdge, EdgeKind, TacticStep, TechniqueRef};`. Re-export `AttackChain` from `lib.rs` beside `Incident` (lib.rs:77).

### 3.2 Changed type — `model/finding.rs` (additive; appended after `contacts` at line 125)

```rust
    /// First observed activity (ns since epoch); None when the producing detector supplies none.
    #[serde(default)]
    pub first_seen_ns: Option<i64>,
    /// Last observed activity (ns since epoch); None if unavailable.
    #[serde(default)]
    pub last_seen_ns: Option<i64>,
    /// Structured victim hosts for fan-out findings (LateralMovement targets, swept hosts),
    /// bounded to MAX_CHAIN_VICTIMS, sorted before truncation. Empty for single-peer kinds.
    #[serde(default)]
    pub victims: Vec<String>,
```

`Finding` does **not** derive `Default` (confirmed finding.rs:101), so there is no `..Default::default()` shortcut. Every `Finding { … }` literal must add the three fields — ~24 sites (each `detect_*` builder, `analyze::malware_download_finding`/`malware_signature_finding`, `rules::rule_finding`, and the test helper `mk_finding` at detect/mod.rs:5144). Compiler-guided and mechanical; `mk_finding` sets `None/None/vec![]`.

### 3.3 New TS mirror types — `ui/src/types.ts`
Append after `Incident`. Add `first_seen_ns?`/`last_seen_ns?`/`victims?` to the existing `Finding` interface; add `attack_chains?: AttackChain[]` to `Summary`. (Full interface bodies as in the draft §3.3 — `TechniqueRef`, `EdgeKind = "pivot" | "progression"`, `ChainEdge`, `ChainStep`, `TacticStep`, `AttackChain`.) Read sites use `summary.attack_chains ?? []`. `FindingKind`/`Severity` reused, never duplicated.

---

## 4. Timestamp Plumbing (the one hard prerequisite)
All folds are **min/max** (order-independent, matching `FlowRecord::observe` flow.rs:280-285 and the `ContactSeries` gap-clamp detect/mod.rs:182). Every field is O(1)-memory. Until a kind is plumbed, its `first_seen_ns = None` → `step_key` sorts it after timed findings and ordering degrades to today's taxonomy (never wrong, only lower `confidence`).

### 4.1 Channel-derived kinds (Beacon, BruteForce, DataExfil, LateralMovement, ExposedRemoteAccess)
1. **`ContactSeries`** (detect/mod.rs:154): add `first_ts_ns: Option<i64>` and `last_ts_ns: Option<i64>`. In `observe(ts_ns)` (:179): `first_ts_ns = Some(first.map_or(ts, |t| t.min(ts)))`; `last_ts_ns = Some(last.map_or(ts, |t| t.max(ts)))`. **Keep `prev_ts_ns` untouched** (it is the Welford gap anchor — repurposing it would break beacon detection). Add `first_seen()`/`last_seen()` accessors.
2. **True last-packet time (recommended, low-risk):** `contact_from_flow` sets `Contact.ts_ns = record.first_ts_ns` (:1694) and discards `record.last_ts_ns`. Add `pub last_ts_ns: i64` to `Contact` (:1646); set it from `record.last_ts_ns` in `contact_from_flow`; add the parameter **only** to `observe_flow_contact_with` (:890) and pass `c.last_ts_ns` at the feed site (analyze:561). **Keep the convenience wrapper `observe_flow_contact(...)`'s signature stable** — default `last = first` inside it — so the many detector unit tests that call it compile unchanged (issue #5). Fold `series.observe(ts, last_ts)`.
3. Each channel detector (`detect_beacons` :1706, `detect_brute_force` :2366, `detect_exfil` :1862, `detect_lateral_movement` :2481, `detect_exposed_remote_access` :2606) copies `series.first_seen()/last_seen()` onto the emitted `Finding`.

### 4.2 Victim recovery (LateralMovement, HostSweep)
- **LateralMovement (exists today):** `LateralCandidate.targets: Vec<IpAddr>` (detect/mod.rs:379) already holds the full list. In `detect_lateral_movement`, copy a **sorted-then-truncated** sample:
  ```rust
  let mut vs: Vec<String> = cand.targets.iter().map(|ip| ip.to_string()).collect();
  vs.sort(); vs.truncate(MAX_CHAIN_VICTIMS);   // sort BEFORE truncate for determinism
  finding.victims = vs;
  ```
- **HostSweep (new plumbing — distinct, lower priority):** the swept hosts live in the `fanout` set, **not** on `SweepCandidate` today. Thread a bounded (`≤ MAX_CHAIN_VICTIMS`), sorted sample from `fanout` into `SweepCandidate` → `detect_sweeps` → `Finding.victims`. This is genuinely more work than LateralMovement and is the weakest pivot (`handoff_weight=30`); it may land after the core if needed (issue #4). Single-peer kinds leave `victims` empty and the algorithm reads `dst_ip`.

### 4.3 Packet-fold kinds (DnsTunnel, Dga, IcmpTunnel, CleartextCreds, PiiExposure, Cryptomining, DisguisedDownload, SuspiciousUa, ArpSpoof, SynFlood)
For each: add `first_ts: i64`/`last_ts: i64` (min/max) to the stat struct (`DnsStats`, `DgaStats`, `IcmpStats`, `SynFloodStat`, `ToolUaStat`, `DisguisedDlStat`, `StratumStat`, the `creds`/`pii`/`arp` tuples) and thread `meta.ts_ns` through the ~9 `observe_*` signatures lacking it (`observe_pii`, `observe_cleartext_cred`, `observe_tls_cert`, `observe_weak_tls`, `observe_dns_query`, `observe_arp`, `observe_user_agent`, `observe_disguised_download`, `observe_stratum`; `observe_icmp_echo` already has ts). +16 B/key, O(1). Each detector stamps first/last onto its `Finding`. These land in follow-ups without blocking M2.

### 4.4 Carve + rule kinds
`MalwareDownload`/`MalwareSignature`: surface `CarveState.last_ts` (carve/mod.rs:951) into `CarveObservation` (:75) — value already exists. `RuleMatch` (rules.rs:644): set `first = last = frame ts` from the apply-site frame timestamp.

---

## 5. Engine Wiring

### 5.1 Signature & placement
`pub fn reconstruct_attack_chains(findings: &[Finding]) -> Vec<AttackChain>` in detect/mod.rs, sibling of `correlate_incidents`. Consumes the same finished, bounded `&[Finding]`. Because `analyze` sets `summary.findings = findings` from the *same* vector, `ChainStep.finding_index` aligns 1:1 with `Summary.findings` — no re-indexing.

### 5.2 Call site (analyze/mod.rs:503–508)
```rust
    let mut summary = stats.finish();
    summary.carved_files = carved_files;
    summary.incidents = correlate_incidents(&findings);            // KEEP (unchanged, :507)
    summary.attack_chains = reconstruct_attack_chains(&findings);  // NEW — before `summary.findings = findings`
    summary.findings = findings;
```
Indices into `findings` equal indices into `summary.findings` (same Vec, moved after).

### 5.3 `fold_rule_findings` (detect/mod.rs:3525)
```rust
pub fn fold_rule_findings(summary: &mut Summary, rule_findings: &[Finding]) {
    summary.apply_findings(rule_findings);
    summary.findings.extend_from_slice(rule_findings);
    summary.incidents = correlate_incidents(&summary.findings);
    summary.attack_chains = reconstruct_attack_chains(&summary.findings);  // NEW — indices stay valid (append-only)
}
```

### 5.4 Recommendation: ADD, do not supersede
Keep `incidents`; add `attack_chains`. `incidents` is a hard dependency of `generated_beacon_scenario_is_detected_as_high` (asserts exact `stages`), `IncidentHero`/`DetailFlyout`/`CompareView`/AI-context, and STIX export. It stays the *triage* unit; chains are the cross-host *investigation* superstructure; they share one finding vector via `finding_index` with zero duplication. Additive-only keeps every existing test green and the JSON contract monotone.

---

## 6. Serialization & Backward Compatibility

### 6.1 `Summary` field (model/summary.rs, append after `incidents` at :370)
```rust
    /// Cross-flow findings reconstructed into temporally-ordered, causally-linked attack chains
    /// (multi-host, campaign-clustered). `#[serde(default)]` keeps older summaries readable.
    #[serde(default)]
    pub attack_chains: Vec<AttackChain>,
```
Add `attack_chains: Vec::new(),` to `Summary::empty()` after `incidents: Vec::new()` (:414) — `empty()` names every field, so a miss is a compile error. Import `AttackChain` at the top of summary.rs.

### 6.2 Backward-compat guarantee
A `summary.json` from any pre-feature engine deserializes cleanly: `attack_chains` `#[serde(default)]` → `Vec::new()`; the three new `Finding` fields `#[serde(default)]` → `None/None/vec![]`. Forward-compat: old code ignores the unknown `attack_chains` key. Mirrors the `incidents`/`domain_threats` convention (summary.rs:3-6); locked by a new round-trip test (§10.5). No `SCHEMA_VERSION` bump (additive optional fields), matching how `findings`/`incidents` were added.

### 6.3 JSON & WASM re-export (no code change)
`AnalysisOutput` serializes the whole `Summary` (output.rs:29) — chains ride through; `AnalysisOutput::default()` covered once `empty()` includes the field. CLI `--json`/`--html` (cli.rs:277-299) serialize `AnalysisOutput`/call `render_html` — no edit. WASM `analyze`/`render_report`/all JSON round-trip exporters serialize `ppcap_core::AnalysisOutput`; `#[serde(default)]` covers old inputs — **no wasm `.rs` change**. **Do NOT touch** `columnar/*`, `FLOW_PARQUET_VERSION`, `sql/schema.sql`, `FlowDto` — chains are summary-level cross-flow aggregates, not per-flow rows.

---

## 7. HTML Report

### 7.1 New `attack_chains_html` (report/mod.rs, modeled on `incidents_html` :709)
As in the draft: a `<section class="card"><h2>Attack chains</h2>` with an empty-case `<p class="muted">…</p>` early return (mirroring `incidents_html`:712). Per chain: severity chip + title + `campaign_id` badge + `score/100 · conf N`; tactic-progression spine reusing `.stages`/`.stage`/`.arrow` (each stage badge annotated with its `TacticStep.host`); ATT&CK chips `id name` via `.techs`/`.tech`; `<p class="narr">`; ordered `<ul class="findings chain-steps">` with actor + kind + tactic + one evidence bullet, prefixing a `↪` pivot glyph on any step that is the `to` of a `Pivot` edge. **Every capture-derived string goes through `esc`** (report/mod.rs:334); severity through `sev_color` (:581); import `EdgeKind` and `kind_label`.

### 7.2 Insertion in `render_html` (report/mod.rs:156)
```rust
    s.push_str(&incidents_html(&sum.incidents));            // :156 (unchanged)
    s.push_str(&attack_chains_html(&sum.attack_chains));    // NEW — Section 3a
```
Optionally add an exec-summary tile (report/mod.rs:112-130) counting `sum.attack_chains.len()`.

### 7.3 CSS
Reuses existing `.card/.chip/.incident/.inc-head/.inc-host/.inc-score/.stages/.stage/.arrow/.techs/.tech/.narr/.findings/.fkind/.ftitle/.fmetrics`. Add four small classes near :1060 (`.chain-host`, `.chain-actor`, `.campaign`, `.pivot-arrow`) and add `.chain` to the `@media print` `break-inside:avoid` list (:1084). Empty case renders nothing beyond the muted line so `report_omits_*`-style tests stay green.

---

## 8. UI

### 8.1 Rendering approach — horizontal swimlane timeline, hand-rolled SVG. No node-link graph, no new dependency.
A force-directed graph already exists (`ThreatGraph.tsx`, ~500 lines hand-rolled) and answers "who talked to whom"; a chain's essence is **ordered progression over time across hosts** — one lane per host, x = time-scaled, pivot arrows between lanes. This is *simpler* geometry than the existing force layout and stays within `viz.ts` helpers + `sevColor()`/`cssVar()` theme-baking. A graph dep (reactflow/cytoscape/d3/dagre) is unwarranted (DAG ≤ ~16 lanes, canvas renderers fight theme-baking and bloat the WASM-first bundle); recharts is a cartesian-stats lib, wrong shape.

### 8.2 New files & slotting
- **`ui/src/lib/killChain.ts`** (pure): lift `KIND_STAGE`/`metric()`/`stageColor()` out of `IncidentHero.tsx` (single source of truth so the vertical stepper and the new timeline never drift) + `computeChainLayout(steps, edges) → { lanes, nodes, arrows }` (deterministic; time-scaled x from `first_seen_ns`, lane y per host, pivot arrows for cross-lane edges) + the TS `technique_name` mirror. Unit-tested in `killChain.test.ts`.
- **`ui/src/views/AttackChainView.tsx`** (new tab): full-canvas swimlane. Wire `"attackchain"` into `TAB_IDS` (types.ts), the `App.tsx` tab switch, and the `AppShell` tab bar (mirroring `CompareView`/`FindingsView`/`ThreatsView`). Returns `null` when `attack_chains?.length` is 0.
- **`ui/src/cockpit/AttackChainCard.tsx`** (dashboard): compact horizontal timeline for the primary chain, mounted in `Dashboard.tsx` after `IncidentHero`/`ThreatGraph`. Wrap in `Card`/`Panel`; returns `null` when empty.

Both consume `summary.attack_chains ?? []`, reuse `kindMeta`/`MitreTag`/`SeverityChip`, and join against `summary.ip_threats` by IP to decorate the C2 node with reputation/fingerprints (pure display join, no recompute). A step click opens `DetailFlyout` on `summary.findings[step.finding_index]` via the existing lifted `selectedIncident`/`onOpen`/`onPivot` callbacks.

### 8.3 CompareView / diff
`lib/diff.ts`: add `chains: DiffResult<AttackChain>` to `SummaryDiff`, keyed by `AttackChain.id` (fallback composite `hosts.join("→")+"|"+steps.map(s=>s.kind).join(">")`). Add `chainDeltas` emitting `FieldDelta`s for `score`/`severity`/`confidence`/step-count and a `setDelta("tactics", …)`. In `diffSummaries`: `diffByKey(before.attack_chains ?? [], after.attack_chains ?? [], keyOf, chainDeltas)`; fold chain hosts into `shared`. `CompareView.tsx`: a `<ChangeStat label="Attack Chains">` tile and a `<DiffSection title="Attack Chains" result={diff.chains} label={c => c.title}>`; widen `DiffSection`'s `<T extends IpThreat | Incident | Finding>` to include `AttackChain` (it satisfies `EntityRow` via `severity`/`score`).

### 8.4 Test files
`killChain.test.ts`, `AttackChainCard.test.tsx`, `AttackChainView.test.tsx` (render from `makeOutput({ attack_chains: [...] })`; assert tactic labels, host lanes, pivot-arrow count via SVG `role="img"` children; assert `onPivot`/`onOpen` fire), `diff.test.ts` extension. Extend `test/fixtures.ts` `makeOutput` with an `attack_chains` array seeded from the existing `10.13.37.7` 3-stage incident. Coverage ≥80% lines/functions.

---

## 9. AI Assist

### 9.1 `technique_name` table (fills a real repo gap — only 4 id→name entries exist, enrich/mod.rs:519)
Add `pub fn technique_name(id: &str) -> &'static str` in `detect/mod.rs` (or `detect/mitre.rs`) covering the ~20 ids the 22 kinds emit (T1046, T1110, T1552, T1021, T1071, T1071.004, T1048, T1568.002, T1557.002, T1499.001, T1595, T1036, T1105, T1496, T1040, T1133, T1573, T1027, T1557, T1095). Unknown id → return the id itself (never panics). `TechniqueRef` pairs each `f.attack` id with this lookup. Mirror in TS (`ui/src/lib/killChain.ts`).

### 9.2 `buildContext` (ui/src/lib/ai/context.ts)
Add a `chainSection(chain)` rendered as a new `## Reconstructed attack chains` section **before** `## Incidents`. Format: a `spine:` line (ordered distinct tactics), per-tactic bullets `- [Tactic] actor {→ | ↦} peer — Txxxx Name — one evidence bullet` (`↦` marks a cross-host `Pivot` edge so the model narrates movement), a `pivots:` line, then the engine narrative verbatim. Privacy invariant preserved (only engine rollups — id, name, host IP, tactic, one bullet; no packets/payloads/flows), so the `not.toContain("payload")` assertion holds.

### 9.3 Token budget & test interaction
Cap chains at `TOP_CHAINS = 3` with the existing "…and N more" overflow. **When a chain covers a host, demote that host's `incidentLine` to title-only** to avoid double-spending the narrative — net token cost ~neutral. **This modifies incident rendering, so update the affected `context.test.ts` assertions in the same commit** (issue #8) and re-verify the 20 000-char ceiling with the new section present. Technique output is id + short name only.

---

## 10. Testing

### 10.1 New generator scenario — `Scenario::AttackChain` (multi-host staged pivot)
The Beacon path already solves temporal staging but keeps **one** actor host; the gap is the pivot (`src_ip` must change A→B mid-chain — the existing beacon scenario's brute victim `10.66.0.1` never becomes an actor). Add:
- **`gen/mod.rs`:** `Scenario::AttackChain` to the enum, `from_str_opt` token `"chain"`/`"attack-chain"`, `all()`; a `next_attack_chain` path dispatched from `next_planned` (:363) beside the `Scenario::Beacon` branch (:370). Stages, modeled on `next_beacon` with per-stage count gates + explicit per-stage timestamp bases: **Stage 1** A scans (A=src, +0s), one swept host = B; **Stage 2** A brute-forces B:22 (A=src, +2.5s); **Stage 3** B beacons to external C2 (B=src, `BEACON_PERIOD_NS`/`(seed,cycle)`-keyed jitter/`bg_cursor`, +30s); **Stage 4** B exfils ≥1 MB to an external drop (B=src, +40s). Fixed locally-administered MACs; `record_flow` on every stage; reuse `frames.rs` builders.
- **`gen/mix.rs`:** `weights_for(AttackChain)` = benign background tuple like Beacon's `(0,90,10,0,0)`; extend `specialized_scenarios_have_expected_shapes`.
- **Unit:** `attack_chain_conserves_packet_count_and_is_deterministic` (mirror :1365); bump `Scenario::all().len()` to 7 in `scenario_parsing_roundtrips` (:1247) **and audit every CLI/enumeration site that hard-codes the scenario count** (open question #2).

### 10.2 Unit — reconstruction (detect/mod.rs `#[cfg(test)]`)
Extend `mk_finding` (add `first_seen_ns`/`victims`) or add `mk_finding_ts`:
- `pivot_links_bruteforce_victim_to_later_beacon_actor` — one chain, `hosts==[A,B]`, one `Pivot` edge `via_kind==BruteForce`, `Critical`.
- `two_unrelated_hosts_stay_separate` — two chains, no edge.
- `shared_public_resolver_does_not_merge` — two DGA-queriers of 8.8.8.8 → two chains (resolver mints no infra key, never a stitch target).
- `causal_gate_rejects_reverse_time` — B acts at 1s before A "compromises" at 30s → no pivot.
- `mutual_lateral_movement_is_acyclic` — A→B and B→A → one chain, no loop.
- `degrades_to_taxonomy_order_when_timestamps_none` — all `first_seen_ns=None` → order == `stage_ordinal`, `confidence` −20.
- `campaign_clusters_two_victims_of_same_c2` — 2 distinct beacon actors to one C2 share `campaign_id`; a single-actor C2 does not (degree 1 < INFRA_MIN_DEGREE).
- `synflood_victim_appears_as_impact_step_not_dropped` — a `SynFlood` finding produces a step (Impact tactic) attributed to its `src_ip`, and never sources a pivot (regression for issue #1).
- `data_exfil_dst_does_not_mint_campaign` — two hosts exfil to the same external sink → **not** clustered (regression for issue #9).
- `single_finding_degenerates_to_one_step_no_escalation`; `empty_findings_yield_no_chains`.

### 10.3 Unit — timestamp plumbing
- `contact_series_folds_first_and_last_min_max` (out-of-order observes → min/max).
- `lateral_movement_finding_carries_capped_sorted_victims`.
- `observe_flow_contact_wrapper_signature_unchanged` (the convenience helper still takes the old arity — regression for issue #5).
- `each_channel_detector_stamps_first_last_seen`.

### 10.4 Integration (analyze/mod.rs `#[cfg(test)]`, mirror :1223)
`generated_attack_chain_scenario_reconstructs_cross_host_chain`: generate `Scenario::AttackChain` (large `packets`, `host_count`), `run(...)` with `PipelineConfig::default()` (no feed), then assert on `out.summary.attack_chains`: exactly one chain with `hosts == [A, B]`, `severity == Critical`; `tactics == ["Discovery","Credential Access","Command & Control","Exfiltration"]`; one `Pivot` edge `via_kind == BruteForce`, its `to`-step actor == B; the brute step's `peer == B`; `attack == ["T1046","T1110","T1071","T1048"]`; C2/drop IPs are High `ip_threats`; no spurious background beacon; **`incidents` still contains the legacy per-host incidents (additive, unchanged)**. Keep `peak_heap_bytes() < PHASE0_BUDGET.max_peak_heap_bytes`.

### 10.5 Serialization, report, determinism, memory
- `attack_chains_serde_roundtrip_and_default` + a `Finding`-new-fields default test (mirror `domain_threats_serde_roundtrip_and_default`).
- `report_renders_attack_chain_section` / `report_omits_attack_chains_when_none`.
- **`reconstruct_is_deterministic_under_input_permutation`** — shuffle the input `Vec<Finding>` (fixed `first_seen_ns`), assert byte-identical `serde_json`. Load-bearing: `step_key` is a strict total order; all containers `BTreeMap`/`BTreeSet`/explicit sort; structural edges built per-host (not array-adjacency); campaign id canonicalizes to min member; folds min/max; ids FNV-derived.
- `golden_100k_budget` (`--ignored`) on real hardware after the pass lands.

---

## 11. Performance & Memory
The pass runs **once at EOF** over the finished `Vec<Finding>`, never in the per-packet hot path. `N = findings.len()` is already bounded independent of capture size by upstream detector caps (`max_tracked_keys`, `max_fanout_per_src`, `MAX_ARP_MACS`, `MAX_DGA_SUSPECT`), so the pass inherits O(1)-w.r.t.-packets and adds zero per-packet cost. Every new structure has an explicit cap with drop-new/-lowest-priority discipline (`progressions ≤ HOSTS·STEPS`, `edges ≤ MAX_EDGES`, `chains ≤ MAX_CHAINS`, `victims ≤ 16`, campaign `degree` sets ≤ `MAX_HUB_DEGREE+1`), worst-case add ≈ a few hundred KiB — well inside the 64 MiB ceiling (~38 MiB observed). Timestamp plumbing adds +16–24 B/key (O(1); no change to map cardinality caps). Time: Phase 1 O(N log N), Phase 2 O(N·16·log N), Phase 3 O(E·depth), Phase 4 O(N log N), Phase 5 O(chains·α) → **O(N log N)**, effectively O(1) in capture size; throughput budget (≥250k pkt/s, <2s/100k) untouched. Determinism cost: all folds min/max; no `HashMap` iteration reaches output without a subsequent sort.

---

## 12. Phased Rollout (each milestone independently shippable)

**M1 — Timestamp & victim plumbing** *(unblocks everything; ships value via richer findings)*
`model/finding.rs` (+3 fields), `detect/mod.rs` (`ContactSeries` first/last; thread `ts_ns` into the ~9 packet-fold `observe_*`; stamp findings; recover `LateralCandidate.targets`; **separately** plumb `SweepCandidate` swept-host sample), `Contact`+`observe_flow_contact_with` (last-packet ts; **keep the wrapper arity stable**), `analyze/mod.rs`, `carve/mod.rs`, `rules.rs`. *Acceptance:* channel-kind findings carry `first_seen_ns`; `victims` populated for Lateral (Sweep may follow); §10.3 green; existing tests pass; `golden_100k_budget` under budget.

**M2 — Engine reconstruction + JSON** *(the core feature)*
`model/attack_chain.rs`, `model/mod.rs`, `model/summary.rs` (field + `empty()` + serde test), `detect/mod.rs` (`reconstruct_attack_chains`, `technique_name`, accessors, unit tests), `analyze/mod.rs` (:507 + `fold_rule_findings`), `gen/mod.rs`+`gen/mix.rs`, integration test. *Acceptance:* §10.2/§10.4/§10.5 green; the A→B→C2 fixture reconstructs one Critical cross-host chain; SynFlood appears as an Impact step; `incidents` unchanged.

**M3 — HTML report** — `report/mod.rs`. *Acceptance:* render/omit tests green; empty case renders nothing extra.

**M4 — UI** — `types.ts`, `lib/killChain.ts`(+test, lifted helpers + technique_name), `views/AttackChainView.tsx`(+test)+`TAB_IDS`/`App.tsx`/`AppShell`, `cockpit/AttackChainCard.tsx`(+test)+`Dashboard.tsx`, `IncidentHero.tsx` (lift helpers), `lib/diff.ts`(+test), `CompareView.tsx`, `test/fixtures.ts`. *Acceptance:* swimlane renders lanes+arrows; step click opens flyout; CompareView diffs chains; coverage ≥80%.

**M5 — AI brief + campaign clustering + STIX** — `detect/mod.rs` (`assign_campaign_ids`), `ui/src/lib/ai/context.ts`(+test, with incident-narrative demotion), `export/mod.rs` (STIX grouping over `attack_chains` — additive loop, no schema break; or documented non-goal). *Acceptance:* two beacon actors of one C2 share `campaign_id`; benign resolver / shared exfil sink never cluster; AI section renders spine+pivots+narrative and `context.test.ts` privacy+size assertions green; STIX (if in scope) exports one grouping per chain.

---

## 13. Risks, Edge Cases & Open Questions

| Risk / case | Mitigation |
|---|---|
| **False-chain over-merge** | Stitching uses an identity join (`victim(X) == actor(Y)`), not co-occurrence; campaign union-find operates only at the chain→campaign *label* layer. Single-parent tree + causal gate + `handoff_weight` argmax keep each victim to one defensible parent. |
| **Benign-infra hubs (resolver / CDN / shared exfil sink)** | Benign destinations mint no infra key (only Beacon/TlsCert C2, DGA, JA3 do — DataExfil/Cryptomining dst excluded); they are never in `actor_set`, so never a stitch target or campaign glue. Campaign gate requires `INFRA_MIN_DEGREE ≤ degree ≤ MAX_HUB_DEGREE`. Tests §10.2. |
| **ArpSpoof / SynFlood attribution** | Kept as steps on their victim `src_ip` (correct owner of a DoS/poisoning); barred from sourcing pivots via empty `victims_of`. A lone SynFlood is an honest single-step Impact chain, not a deletion. |
| **Huge fan-out (worm / 4096-host sweep)** | `victims` capped 16 (sorted-then-truncated), `edges` capped, progressions capped. Inert swept leaves aren't in `actor_set` → no edges. Heavy-hitter-exact below caps, lossy above (matches `max_fanout_per_src`). |
| **DHCP churn / NAT / shared egress** | `CORRELATION_WINDOW_NS=1h` bounds dwell; causal gate rejects reverse-time. Unfixable at flow level — documented; `confidence` surfaces uncertainty. |
| **Temporally overlapping hosts** | Steps globally time-sorted; edges built structurally **per-host** (not by array adjacency) so interleaving never mis-wires progression edges. |
| **Determinism** | Strict total-order `step_key`, all ordered containers, structural per-host edges, min-member campaign id, min/max folds, FNV ids. Locked by `reconstruct_is_deterministic_under_input_permutation`. |
| **Timestamp dependence** | Graceful: `None` → `i64::MAX` → taxonomy order + `confidence −20`. M1 lands channel kinds first; packet-fold kinds follow. |
| **Single-parent tree under-represents fan-in** | Strongest/tightest deterministic parent wins; the losing edge survives in `edges` as evidence for the swimlane. |
| **`confidence`/`score` arithmetic** | Computed in signed `i32`, then `clamp(0,100)` — no `u8` underflow, honoring never-panic. |
| **`observe_flow_contact_with` signature churn** | Convenience wrapper arity kept stable (default `last=first`); only the `_with` variant + the single real feed site change — detector unit tests unaffected. |

**Open questions for review:** (1) `HostSweep` victim recovery is new `SweepCandidate` plumbing and the weakest pivot — land in M1 or defer? (2) confirm every hard-coded `Scenario::all().len()` / CLI enumeration site before bumping to 7. (3) `campaign_id` as a per-chain tag now, or promote to a top-level `Summary.campaigns: Vec<Campaign>` for a campaign UI tab later? Recommend per-chain tag for M5, promote if the UI needs a roll-up. (4) STIX grouping export in M5 or documented non-goal?

---

## 14. File-by-File Change Checklist

| File | Add / Modify | Reason |
|---|---|---|
| `engine/.../model/finding.rs` | Modify | +`first_seen_ns`/`last_seen_ns`/`victims` (`#[serde(default)]`); update all ~24 literals |
| `engine/.../model/attack_chain.rs` | **Add** | `AttackChain`/`ChainStep`/`ChainEdge`/`EdgeKind`/`TacticStep`/`TechniqueRef` |
| `engine/.../model/mod.rs` | Modify | `pub mod attack_chain;` + re-exports |
| `engine/.../model/summary.rs` | Modify | +`attack_chains` field, `empty()`, serde-default test |
| `engine/.../lib.rs` | Modify | Re-export `AttackChain` beside `Incident` |
| `engine/.../detect/mod.rs` | Modify | `reconstruct_attack_chains`, `technique_name`, accessors, `ContactSeries` first/last, LateralMovement+HostSweep victim recovery, stamp findings, `fold_rule_findings` re-run, campaign union-find, unit tests |
| `engine/.../analyze/mod.rs` | Modify | Call at :507; thread `ts_ns`/`last_ts_ns`; integration test |
| `engine/.../carve/mod.rs` | Modify | Surface `CarveState.last_ts` into `CarveObservation` |
| `engine/.../detect/rules.rs` | Modify | Stamp first/last on `RuleMatch` from frame ts |
| `engine/.../gen/mod.rs` | Modify | `Scenario::AttackChain` + `next_attack_chain` + tests + `all().len()` bump |
| `engine/.../gen/mix.rs` | Modify | `weights_for(AttackChain)` + shape test |
| `engine/.../report/mod.rs` | Modify | `attack_chains_html` + insertion :156 + 4 CSS classes + print break-inside + tests |
| `engine/.../export/mod.rs` | Modify (M5) | STIX grouping over `attack_chains` (or documented non-goal) |
| `ui/src/types.ts` | Modify | Mirror types + `Summary.attack_chains` + `Finding` ts/victims + `TAB_IDS` entry |
| `ui/src/lib/killChain.ts` (+test) | **Add** | Lifted `KIND_STAGE`/`metric`/`stageColor` + `computeChainLayout` + TS `technique_name` |
| `ui/src/views/AttackChainView.tsx` (+test) | **Add** | Swimlane tab (hand-rolled SVG) |
| `ui/src/cockpit/AttackChainCard.tsx` (+test) | **Add** | Compact dashboard timeline |
| `ui/src/App.tsx`, `ui/src/components/AppShell.tsx` | Modify | Wire `"attackchain"` tab |
| `ui/src/components/Dashboard.tsx` | Modify | Mount `AttackChainCard` |
| `ui/src/cockpit/IncidentHero.tsx` | Modify | Lift helpers into `killChain.ts` |
| `ui/src/lib/findingKinds.ts` | Modify | (optional) TS `technique_name` mirror if not in `killChain.ts` |
| `ui/src/lib/diff.ts` (+test) | Modify | `chains: DiffResult<AttackChain>` + `chainDeltas` |
| `ui/src/views/CompareView.tsx` | Modify | Chain `ChangeStat` + `DiffSection` |
| `ui/src/lib/ai/context.ts` (+test) | Modify | `chainSection` before `## Incidents`; demote covered-host narratives (update assertions) |
| `ui/src/test/fixtures.ts` | Modify | `makeOutput` gains an `attack_chains` fixture |
| **NOT touched** | — | `columnar/*`, `FLOW_PARQUET_VERSION`, `sql/schema.sql`, wasm `FlowDto` — chains ride existing `Summary` serialization |

---

## Appendix A — Design-review corrections (folded in above)

The synthesized draft was adversarially reviewed before any code was written. The following
confirmed issues were found and their fixes are already incorporated into the plan above; they
are retained here as the rationale behind several non-obvious design choices.

(most severe first)

1. **ArpSpoof / SynFlood are dropped from chains entirely, silently deleting the Impact and AiTM tactics.** `actor_host()` returns `None` for these two, and Phase 1 does `host = actor_host(f)?; else continue` — so these findings never become steps in *any* chain. The feature headline promises "MITRE ATT&CK progression" through Impact, yet `SynFlood` (T1499.001) is one of only two Impact kinds and `ArpSpoof` (T1557.002) the only AiTM kind. Dropping them is over-correction. **Fix:** These kinds already carry the *victim* in `src_ip`, so attributing the step to `src_ip` is correct — a DoS/poisoning against host B belongs in B's story. Keep them as normal steps in Phase 1; only bar them from *sourcing* a pivot edge (already guaranteed, since `victims_of()` returns empty for them) and from being *selected as a chain root when a stronger adversary root exists in the same tree* (naturally handled — they have no outgoing edges, so they only ever attach as leaves or stand alone as a legitimate single-step Impact chain).

2. **Edge (Progression) construction is under-specified for temporally overlapping hosts.** Phase 4 globally re-sorts all member steps by `step_key`, then the worked example draws `Progression A→A(0→1)` as if same-host steps are array-adjacent. When A and B activity interleaves in wall-clock time (e.g. A's exfil at 45s falls after B's beacon at 30s), a host's own steps are *not* contiguous in the sorted array, so array-adjacency yields wrong edges. **Fix:** Build edges from structure, not array position: `Progression` edges connect `step[i] → step[i+1]` **within each host's own time-ordered substep list**; the single `Pivot` edge per stitched child connects the parent's handoff step (the `via_finding_idx` step) to the child's first step. `ChainStep.order` is still the global sorted index used by `from`/`to`.

3. **`SmallVec` is an unjustified new dependency.** `victims_of` returns `SmallVec<[&str; MAX_CHAIN_VICTIMS]>`. Nothing in the surveys establishes `smallvec` as an engine dependency, and the engine's ethos is minimal, bounded, dependency-light. **Fix:** return `Vec<&str>` (already bounded by the `MAX_CHAIN_VICTIMS` cap at the source `Finding.victims`); no heap concern.

4. **HostSweep victim recovery is materially harder than LateralMovement and is conflated with it.** `LateralCandidate.targets: Vec<IpAddr>` **exists today** (confirmed detect survey §5). `SweepCandidate` does **not** carry the swept-host list — the hosts live in the `fanout` set and must be newly threaded (bounded sample) into the candidate → builder. **Fix:** call this out as distinct, lower-priority M1 work; it is also the weakest pivot (`handoff_weight(HostSweep)=30`), so if it slips, only sweep→X links (rarely the true compromise edge) are missed. BruteForce/ExposedRemoteAccess/LateralMovement — the real compromise edges — are unaffected.

5. **Threading `last_ts_ns` into `observe_flow_contact_with` has a large test blast radius.** The behavioral detector unit tests feed contacts via the `observe_flow_contact(src,dst,port,ts,c2s,s2c)` helper (gen-testing survey §2), which wraps `observe_flow_contact_with`. Adding a parameter to the `_with` signature breaks every such test. **Fix:** keep the convenience wrapper's signature stable (default `last_ts_ns = first_ts_ns`); add the parameter only to the `_with` variant and pass `record.last_ts_ns` at the single real feed site (analyze:561). Tests compile unchanged; `last_seen` is exact in production and a monotone under-estimate only in tests that don't supply it.

6. **`hosts` ordering and `attack` progression lack deterministic tiebreaks.** "Distinct hosts in first-seen order" and "technique ids in step order" are ambiguous when `first_seen_ns` ties or is `None`, and the `attack` list can contain duplicate ids if a technique recurs. **Fix:** order hosts by key `(first_seen_ns.unwrap_or(i64::MAX), host_str)`; dedupe `attack` preserving first occurrence. (`chain.id` already uses the *sorted* host set, so it is stable regardless — but the display `hosts` vec, title, and narrative read from this order and must be deterministic.)

7. **`confidence` must be computed in signed arithmetic before clamping.** The formula subtracts up to 30 (`−20 −10`) from a base that can be as low as 40; doing it in `u8` underflows and, per the never-panic contract, that is unacceptable. **Fix:** compute as `i32`, then `clamp(0, 100) as u8`.

8. **AI-context narrative demotion may break `context.test.ts`.** §9.3 demotes a covered host's `incidentLine` to title-only. `context.test.ts` asserts specific incident/narrative content and a `not.toContain("payload")` + size ceiling. **Fix:** treat the demotion as a test-touching change — update the existing assertions in the same commit; keep the privacy assertion (chains emit only engine rollups) and re-verify the size ceiling with the added `## Reconstructed attack chains` section.

9. **`DataExfil`/`Cryptomining` destinations are the weakest campaign-infra signal and can over-cluster benign-ish sinks.** A shared cloud-backup endpoint or a common mining pool would bind up to `MAX_HUB_DEGREE` unrelated hosts into one campaign. **Fix:** restrict `infra_key` to the *strong* adversary signals — `Beacon`/`TlsCertHealth` C2, `Dga` domain, and `JA3` — and **exclude** `DataExfil`/`Cryptomining`/`DisguisedDownload`/`MalwareDownload` destinations from minting an infra key (they remain chain steps; they just don't glue campaigns). This keeps clustering conservative, matching the "honest under-merge" posture.

10. **Intel exporters (STIX/MISP/CEF/Sigma) are not threaded — a real omission for a MITRE-progression security feature.** These live in `export/mod.rs` and iterate `findings`/`ip_threats`. A reconstructed, ATT&CK-ordered cross-host chain is exactly what a SOC wants as a STIX *grouping* / attack-pattern sequence. **Fix:** explicitly scope this — add a STIX grouping over `attack_chains` to M5 (additive loop, no schema break), or state as a documented non-goal. Don't leave it implicit.

11. **Minor: JSON duplication.** The three new `Finding` fields serialize in both `Summary.findings` and every `Incident.findings`; `ChainStep` additionally duplicates `evidence`/`techniques` alongside its `finding_index` back-reference. Acceptable (self-contained rendering), but note it and keep `ChainStep.evidence` to a single representative bullet as planned.

Everything else in the plan checks out: the **cross-host reconstruction genuinely works** — I trace the proof in §2.7 below. The identity join `BruteForce.dst_ip (B) == Beacon.src_ip (B)`, stitching B's progression under A as an acyclic child, then globally time-re-sorting steps, produces one Critical chain where `correlate_incidents` produces two disconnected incidents. This is a real capability gain, not a collapse to per-host grouping. Timestamp folds are min/max (order-independent), all containers are `BTreeMap`/`BTreeSet`/explicit sorts, ids are FNV-derived — determinism holds. Backward-compat is sound (`#[serde(default)]` throughout; WASM rides `AnalysisOutput` automatically; Parquet correctly untouched).

---

---

## Appendix B — Citation verification

I verified every load-bearing citation against source. All cited paths, line numbers, and signatures are accurate: `Finding` (finding.rs:102–126, `score: u16`, **does not** derive `Default`), `correlate_incidents` (3301, groups on `f.src_ip`), `stage_ordinal`/`stage_label` (3396/3424), `fold_rule_findings` (3525, re-runs `correlate_incidents` only), `mk_finding` (5144, full literal), call site (analyze:507), `Summary::empty()` (summary.rs:381, `incidents` at 414), gen dispatch (`Scenario::Beacon` at gen/mod.rs:370), `Incident.findings: Vec<Finding>` (incident.rs:32). No invented paths or misremembered signatures found. The remaining review is adversarial reasoning about the algorithm and completeness.

---
