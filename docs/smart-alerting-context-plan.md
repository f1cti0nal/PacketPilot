# PacketPilot — Smart Alerting with Context

**Implementation Plan**

| | |
|---|---|
| **Status** | **Implemented** on this branch — engine + CLI + HTML report + browser UI + WASM ride-through + AI brief, adversarially reviewed |
| **Feature branch** | `claude/smart-alerting-context-t78kzq` |
| **Date** | 2026-07-23 |
| **Scope** | Engine (Rust: new `detect/alerts.rs` pass + `model/alert.rs` contract type + three re-derive seams) · CLI (`ppcap alerts` subcommand + stderr one-liner) · HTML report (queue section) · UI (React/TS: Alerts tab + view + types) · WASM (rides through, zero new exports) · AI brief section |

> **Implementation status (what actually shipped).** Everything in §3–§11 landed: `model/alert.rs`
> + `detect/alerts.rs` (four tiers, ledger, context bundle, action table, overflow rollup) + the
> three re-derive seams + `ppcap alerts` + `alerts_html` + the Alerts tab/view/AI-brief section +
> the regenerated bundled sample (12 findings → 6 alerts). Verified here: 822 engine tests
> (17 new alert unit tests, 4 e2e, 2 report, 2 CLI, 1 reputation seam), 1018 UI tests, clippy,
> `tsc`, Playwright (new alerts spec + updated digit-key spec; the two remaining local e2e
> failures reproduce on the pre-change baseline in this sandbox — pre-existing). Not verifiable
> in this sandbox: the Tauri desktop shell and a real `wasm32` build (the wasm crate typechecks
> against the new core with zero source changes). One design correction found during
> implementation is folded in as Appendix A #13 (chain tier is strictly cross-host).

> **How this plan was produced.** Six parallel subsystem readers mapped the engine pipeline,
> findings/scoring/correlation machinery, baseline/forecast modules, model/report/CLI/wasm
> surfaces, and the UI. Three independent designs were then produced from three angles
> (SOC-analyst workflow · engine correctness & reuse · false-positive/noise safety) and
> adversarially judged by three lenses (engine · product · safety). No single design won all
> three lenses; this plan is the synthesis, taking each lens winner's core and folding every
> judge-flagged flaw into the design — the corrections are listed in Appendix A. Every cited
> path/line was verified against the checked-out tree; treat line numbers as anchors (Appendix B).

---

## 1. Summary & Goals

**What ships.** **Smart Alerting with Context (SAC)**: a pure, deterministic post-pass that turns
the finished analysis — findings, per-host incidents, cross-host attack chains, per-IP threat
cards — into a **short, ranked, deduplicated, fully-explained alert queue**, where each alert is a
self-sufficient triage card: *who* (actor host, with ARP/DHCP identity), *what* (verb-phrase
headline + narrative), *how bad* (priority band), *why trust it* (a transparent `ScoreTerm`
ledger plus a confidence figure), *the context* (threat intel, reputation, passive DNS, cloud
attribution, baseline novelty, kill-chain position, carved files, DNS-visibility caveats — all
joined from data the engine already computed), *what next* (a recommended action), and *what it
covers* (back-references into `summary.findings`, `summary.incidents`, `summary.attack_chains`).
A 40-finding noisy capture becomes a queue of well under 10 alerts, and **no finding is ever
silently dropped**: every finding index belongs to exactly one alert — grouping is the
suppression mechanism, and membership is the explanation.

**What it changes vs. today's engine:**

| Today | With SAC |
|---|---|
| A flat `findings` table (dozens of rows: `weak_tls` noise interleaved with the one beacon that matters), a per-host `incidents` list, and `attack_chains` — three views, no single triage order | One ranked `summary.alerts` queue that subsumes all three: chains outrank incidents outrank singletons outrank hygiene rollups, fused with corroboration/novelty/confidence |
| Severity is the only rank axis; a heuristic Medium and a corroborated Medium sort identically | `priority` (0..=100) fuses story score with IOC/reputation corroboration, baseline/forecast novelty, chain confidence, and environment dampens — every point a visible `ScoreTerm` |
| Context is scattered: identity in `arp_hosts`/`dhcp_hosts`, domains in `resolved_ips`, verdicts in `ip_threats`, novelty in deviation evidence | Each alert carries the joined context bundle; the card answers the questions that today require five pivots |
| No noise layer: 9 hosts with weak TLS produce 9 incident rows | One "Weak TLS posture: 9 hosts" rollup, capped below High, with every member index attached |
| Nothing recommends an action | A deterministic per-kind `action` line ("Isolate 10.66.0.1; block 45.77.13.37:443 at the egress firewall") |

**How SAC complements its siblings:** BBL (docs/behavioral-baseline-learning-plan.md) and PAD
(docs/predictive-anomaly-detection-plan.md) *produce* weak self-relative signals; ACR
(docs/attack-chain-reconstruction-plan.md) *stitches* findings into cross-host stories. SAC is
the layer the three were building toward: it consumes all of them and formalizes the house
corroboration doctrine (`DEV_UPLIFT_CAP`/`FC_UPLIFT_CAP`/`REP_UPLIFT_CAP`) as the *queue order
itself*. The Time Machine's `newly_flagged` ("the actionable alerts", docs/time-machine.md) named
the concept; SAC builds the first-class type.

**Non-goals (this plan's core).** No cross-capture alert state (ack/dismiss persistence, alert
diffing between captures), no alert-specific SIEM export formats, no scheduled re-scans or feed
subscriptions, no ML ranking, no new detectors, and no new `FindingKind` — SAC derives, it does
not detect. Those are follow-ups (§16), scoped out exactly as ACR scopes out its STIX grouping
and BBL scopes out its team baseline store.

---

## 2. Concept & Chosen Approach

### 2.1 One alert = one adversary story

The alert pass partitions **findings by actor host** (`Finding.src_ip`), then walks a strict
four-tier precedence ladder. Two verified structural facts make this total and deterministic:
`reconstruct_attack_chains` places every chain host in exactly one chain tree (single-parent
forest, detect/mod.rs:4132), and `correlate_incidents` emits exactly one `Incident` per actor
host (detect/mod.rs:3699-3711). Coverage is **by host, not by step index**, because
`MAX_STEPS_PER_HOST=64` can evict step references — covering by `chain.hosts` is cap-proof.

- **Tier 1 — Chain alerts** (`source: chain`). Each *cross-host* chain (`host_count >= 2`)
  claims the findings of all its hosts. Single-host chains — even multi-tactic — do not
  qualify: reconstruction emits a chain for every actor host, so a single-host chain is that
  host's incident re-wrapped (the incident already carries the multi-stage escalation and
  narrative), and a `tactic_count`-based gate would let two weak posture kinds on one host
  masquerade as a "chain" and dodge the hygiene rollup (implementation correction; Appendix
  A #13).
- **Tier 2 — Standalone strong findings** (`source: finding`). A finding on a *chain host* that
  is **not** one of that chain's steps and is standalone-eligible (kind in `NEVER_ROLLUP` =
  {`MalwareDownload`, `MalwareSignature`, `RuleMatch`, `IcsControlCommand`, `ArpSpoof`} or
  severity ≥ High) gets its **own** alert — a chain must never swallow an unrelated strong story
  on a pivot host. (Steps evicted by the 64-step cap are the lowest-scoring ones, hence never
  standalone-eligible — they stay safely inside the chain alert's host coverage.)
- **Tier 3 — Host alerts** (`source: host`). Every non-chain host whose remaining findings are
  *not* weak-only claims **all** its findings as one alert, with the host's existing
  `Incident` as the story (base score, title, narrative). A weak finding on an implicated host
  therefore rides *inside* that host's alert as corroboration — it can never be buried in a
  fleet-wide rollup (the anti-burying rule).
- **Tier 4 — Hygiene rollups** (`source: rollup`). What remains lives on weak-only hosts
  (every finding kind ∈ `WEAK_KINDS`, max severity ≤ Medium). It groups **per kind** across
  hosts: "Weak TLS posture: 9 hosts (12 findings)". `WEAK_KINDS` = {`WeakTls`, `TlsCertHealth`,
  `CleartextCreds`, `PiiExposure`, `SuspiciousUa`, `PortScan`, `BaselineDeviation`,
  `TrafficAnomaly`}. A lone Medium **beacon** host is *not* weak-only — it gets a real Tier-3
  host alert, never a "rollup of 1".

**Coverage invariant (the load-bearing rule, test-enforced):** the multiset union of
`finding_indices` over all alerts equals `{0 .. summary.findings.len()}`, each index exactly
once; `Σ alert.finding_count == summary.findings.len()`. This holds **under truncation** too
(§2.3). Alerts never mutate `findings`/`incidents`/`attack_chains` — all four vectors coexist,
and alerts hold only back-references.

### 2.2 Priority: the corroboration doctrine as a queue order

`priority: u16` (0..=100), banded by the **existing** `Severity::from_score` cutoffs — no new
threshold vocabulary (`act_now` 85-100, `investigate` 60-84, `review` 35-59, `log` 15-34,
`info` 0-14). Base is always the **existing story score** (chain.score / incident.score /
finding.score / worst rollup member) — never re-derived, so the multi-stage escalation that
`correlate_incidents` (+15, +1 band) and `build_chain` (+10/tactic, +10/host) already encode is
never stacked twice. Uplifts are bounded (`ALERT_UPLIFT_CAP = 25`, mirroring `REP_UPLIFT_CAP`),
and the **floor discipline generalizes the weak-alone-caps-at-Medium doctrine beyond kind
lists**: `base < 60 && corroboration == 0 ⇒ priority ≤ 59`. High/Critical urgency arises only
from a story already High+ or from IOC/reputation corroboration — never from point-stacking.
Every point (including materialized caps/floors/clamps — a deliberate, documented divergence
from `score_flow`, where clamps are evidence-only) is a `ScoreTerm` in `priority_terms`, and
`Σ terms == priority` is test-enforced.

### 2.3 Noise control: group-and-tell, never delete

Three visible mechanisms and **zero** tombstone rows, no `suppressed` status, and no
volume-relative rank cutoff (a benching rule that depends on *other* alerts' count is gameable
by decoy flooding and semantically empty — rejected in review, Appendix A):

1. **Coverage fold** — a story told by a higher tier is not re-told lower; the covering alert
   carries the receipts (`finding_indices`, `incident_hosts`, `chain_id`).
2. **Hygiene rollups** — the weak-signal long tail compresses per kind, capped below High by the
   floor discipline, with every member index attached and auditable.
3. **Bounded emission with an overflow rollup** — after ranking, the queue truncates to
   `MAX_ALERTS = 32`, but (a) alerts with `priority >= 60` or matching `never_dampen` are
   **never** dropped (soft bound, documented), and (b) the dropped tail collapses into **one**
   synthetic overflow rollup carrying all its finding indices and counts — the coverage
   invariant survives truncation absolutely.

**`never_dampen`** (checked once, applied by *skipping* dampen terms entirely — never
applied-then-floored, so the ledger can never show a malicious-peer alert being
cloud-dampened): severity == Critical, or any member kind ∈ {`MalwareDownload`,
`MalwareSignature`, `IcsControlCommand`}, or any implicated card `ioc`, or ≥1
reputation-malicious verdict, or a multi-host chain. Baseline warmup needs no handling here:
`min_captures = 5` suppresses deviation *emission* upstream, and SAC never downweights
non-baseline detectors — a cold environment gets full behavioral alerting from capture one.

---

## 3. Data Model

New file `engine/crates/ppcap-core/src/model/alert.rs` (registered as `pub mod alert;` in
model/mod.rs and re-exported from lib.rs beside `Incident`/`AttackChain`). Derives mirror the
sibling contract types: `Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize`; enums
are `snake_case`, append-last; integer math only (no f64 — wasm byte-parity).

```rust
use crate::model::severity::Severity;
use crate::model::summary::ScoreTerm;   // REUSED — the transparent-ledger type (summary.rs:145)

/// Which layer of the correlation hierarchy this alert is told from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSource { Chain, Host, Finding, Rollup }   // append-last for new tiers

/// Priority band. Cutoffs are Severity::from_score's, verbatim — no new threshold vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityBand { Info, Log, Review, Investigate, ActNow }  // ascending: Ord == urgency

impl PriorityBand {
    pub fn from_priority(p: u16) -> Self { /* 85+ ActNow · 60-84 Investigate · 35-59 Review
                                              · 15-34 Log · else Info */ }
    pub fn rank(self) -> u8 { self as u8 }
    pub fn as_str(self) -> &'static str { /* snake_case wire tokens */ }
}

/// Typed context-entry kind. Ord = fixed render order; append-last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextKind {
    Identity, ThreatIntel, Reputation, BaselineNovelty, ForecastAnomaly,
    KillChain, PassiveDns, CloudProvider, CarvedFile, EncryptedDns,
}

/// One deterministic context fact, with an optional back-ref to its source finding.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ContextEntry {
    pub kind: ContextKind,
    pub text: String,
    #[serde(default)] pub finding_index: Option<u32>,
    #[serde(default)] pub ip: Option<String>,
}

/// Actor identity, joined from arp_hosts (ip→mac) + dhcp_hosts (mac→hostname/vendor).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HostContext {
    pub ip: String,
    #[serde(default)] pub hostname: Option<String>,
    #[serde(default)] pub mac: Option<String>,
    #[serde(default)] pub vendor: Option<String>,
    pub internal: bool,                       // !classify_ip(ip).is_external()
    #[serde(default)] pub cloud: Option<String>,
    /// The actor has a BaselineDeviation member finding in this capture.
    #[serde(default)] pub new_to_baseline: bool,
}

/// One external peer of interest, worst-first, capped MAX_ALERT_PEERS = 4.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PeerContext {
    pub ip: String,
    #[serde(default)] pub domain: Option<String>,       // resolved_ips passive-DNS join
    #[serde(default)] pub cloud: Option<String>,        // cloud_provider / cloud: tag
    pub ioc: bool,                                      // IpThreat.ioc
    /// Count of Malicious reputation verdicts on the peer's card (0 when the pass never ran).
    #[serde(default)] pub reputation_malicious: u8,
    #[serde(default)] pub dst_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AlertContext {
    pub actor: HostContext,
    #[serde(default)] pub peers: Vec<PeerContext>,      // cap 4
    #[serde(default)] pub entries: Vec<ContextEntry>,   // cap 12, (kind ordinal, text) order
}

/// One row of the ranked triage queue. Back-references only — findings are never cloned
/// (deliberate divergence from Incident.findings: one source of truth, and indices stay valid
/// because fold_rule_findings only appends).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Alert {
    /// "alert:{:016x}" — fnv1a64 over a tier-prefixed stable key (§5.4); unique by construction.
    pub id: String,
    pub source: AlertSource,
    pub band: PriorityBand,
    /// 0..=100 fused rank (§4). Σ priority_terms == priority, test-enforced.
    pub priority: u16,
    /// 0..=100. Chain alerts copy AttackChain.confidence verbatim; others use §4.3.
    pub confidence: u8,
    /// Copied from the source story (worst member) — the judgment axis, never rewritten from
    /// priority (the rank axis). The two can disagree; the UI shows both.
    pub severity: Severity,
    pub title: String,
    /// Reuses chain.narrative / incident.narrative / finding.title; rollups from kind_phrase().
    pub narrative: String,
    /// Deterministic recommended next step, from the per-kind action table (§5.6).
    pub action: String,
    /// Primary actor host (chain root / incident host / finding src_ip / first rollup host).
    pub actor: String,
    /// Implicated actor hosts, first-seen order then IP asc; cap MAX_ALERT_HOSTS = 16.
    pub hosts: Vec<String>,
    /// Total distinct actor hosts (>= hosts.len(); rollups can exceed the listing cap).
    pub host_count: u32,
    /// Primary external peer (C2/drop) when the story names exactly one distinct dst.
    #[serde(default)] pub peer: Option<String>,
    /// ATT&CK technique ids in story order, deduped preserving first occurrence.
    pub attack: Vec<String>,
    /// Furthest kill-chain stage reached (stage_label of max stage_ordinal over members).
    pub stage: String,
    pub stage_ordinal: u8,
    /// "What to watch for next": the label one stage past stage_ordinal; None at Impact.
    #[serde(default)] pub next_stage: Option<String>,
    pub priority_terms: Vec<ScoreTerm>,
    pub context: AlertContext,
    /// ALL member indices into summary.findings, ascending, uncapped — complete receipts.
    pub finding_indices: Vec<u32>,
    /// == finding_indices.len(); the coverage invariant sums this.
    pub finding_count: u32,
    #[serde(default)] pub chain_id: Option<String>,     // AttackChain.id back-ref (Chain tier)
    /// Hosts whose per-host Incident this alert subsumes.
    #[serde(default)] pub incident_hosts: Vec<String>,
    pub first_seen_ns: Option<i64>,                     // min over members; None if all untimed
    pub last_seen_ns: Option<i64>,                      // max over members
}
```

`Summary` gains one field, appended after `attack_chains` (model/summary.rs:379):

```rust
    /// Ranked, deduplicated, context-bundled triage queue derived from findings / incidents /
    /// attack chains / threat cards (§ smart-alerting plan). `#[serde(default)]` keeps older
    /// summaries readable.
    #[serde(default)]
    pub alerts: Vec<Alert>,
```

plus `alerts: Vec::new(),` in `Summary::empty()` (summary.rs:390-425) and in the exhaustive
`summary_with(...)` test constructor at enrich/reputation.rs:303 (both compile-error-guarded).
`schema_version` stays 1 — additive `#[serde(default)]`, the same evolution `incidents` and
`attack_chains` used.

**On-disk example (one Tier-1 alert, abbreviated):**

```json
{
  "id": "alert:9f2c41a07be3d512", "source": "chain", "band": "act_now",
  "priority": 92, "confidence": 85, "severity": "critical",
  "title": "Cross-host attack chain: 10.13.37.7 → 10.66.0.1 → C2 45.77.13.37",
  "narrative": "10.13.37.7 swept the network, then brute-forced credentials on 10.66.0.1; …",
  "action": "Isolate 10.66.0.1; block 45.77.13.37:443 at the egress firewall",
  "actor": "10.13.37.7", "hosts": ["10.13.37.7", "10.66.0.1"], "host_count": 2,
  "peer": "45.77.13.37", "attack": ["T1046", "T1110", "T1071", "T1048"],
  "stage": "Exfiltration", "stage_ordinal": 5, "next_stage": "Impact",
  "priority_terms": [
    {"label": "base: attack-chain score", "points": 87},
    {"label": "corroborated: IOC feed hit on 45.77.13.37", "points": 10},
    {"label": "novel: deviates from learned baseline", "points": 5},
    {"label": "confidence: 85%", "points": 6},
    {"label": "cap: uplift bounded at +25", "points": -[delta when binding]},
    {"label": "clamp: raw 112 -> 100", "points": -12}
  ],
  "context": {
    "actor": {"ip": "10.13.37.7", "hostname": "ACCT-LT-042", "mac": "aa:bb:cc:dd:ee:ff",
              "vendor": "Dell Inc", "internal": true, "cloud": null, "new_to_baseline": true},
    "peers": [{"ip": "45.77.13.37", "domain": "update.evil-cdn.net", "cloud": null,
               "ioc": true, "reputation_malicious": 2, "dst_port": 443}],
    "entries": [
      {"kind": "identity", "text": "identity: 10.13.37.7 = ACCT-LT-042 (Dell Inc) [aa:bb:cc:dd:ee:ff]"},
      {"kind": "threat_intel", "text": "threat intel: 45.77.13.37 matches the offline IOC feed", "ip": "45.77.13.37"},
      {"kind": "baseline_novelty", "text": "baseline: first-ever external peer for this host", "finding_index": 7},
      {"kind": "kill_chain", "text": "kill chain: Discovery → Credential Access → C2 → Exfiltration; next expected: Impact"},
      {"kind": "passive_dns", "text": "passive dns: 45.77.13.37 resolved from update.evil-cdn.net (14 answers)", "ip": "45.77.13.37"}
    ]
  },
  "finding_indices": [2, 4, 7, 9, 11], "finding_count": 5,
  "chain_id": "chain:6a1b2c3d4e5f6071", "incident_hosts": ["10.13.37.7", "10.66.0.1"],
  "first_seen_ns": 12000000000, "last_seen_ns": 341000000000
}
```

---

## 4. Priority, Confidence & the Ledger

All knobs are compile-time constants in `detect/alerts.rs` — **no config surface** (the
attack-chain precedent: compile-time constants preserve determinism and schema stability, and
the re-derive seams `fold_rule_findings` / `apply_reputation` have no config channel, so any
tunable would fork native-vs-wasm output or break three public signatures). Like incidents and
chains, alerts cannot be disabled.

```rust
const MAX_ALERTS: usize = 32;            // soft bound: priority>=60 / never_dampen rows never drop
const MAX_ALERT_HOSTS: usize = 16;       // mirrors MAX_CHAIN_VICTIMS
const MAX_ALERT_PEERS: usize = 4;
const MAX_CONTEXT_ENTRIES: usize = 12;

pub const PTS_ALERT_IOC: i32 = 10;       // any implicated card has ioc == true (offline feed),
                                         // or a MalwareDownload/MalwareSignature member
pub const PTS_ALERT_REP: i32 = 10;       // >=1 Malicious reputation verdict on an implicated card
pub const PTS_ALERT_NOVEL: i32 = 5;      // a BaselineDeviation member (novel vs learned self)
pub const PTS_ALERT_ANOM: i32 = 5;       // a TrafficAnomaly member (own-forecast departure)
pub const PTS_ALERT_CLOUD_PEER: i32 = -10; // every external peer cloud-tagged, none IOC/rep-bad
pub const PTS_ALERT_UNTIMED: i32 = -5;   // every member finding is untimestamped
pub const ALERT_UPLIFT_CAP: i32 = 25;    // total POSITIVE adjustment ceiling (== REP_UPLIFT_CAP)
pub const CAP_UNCORROBORATED: u16 = 59;  // base < High && zero corroboration ⇒ never crosses High
pub const FLOOR_ALERT_IOC: u16 = 60;     // IOC-backed forces Investigate (mirrors the IOC High floor)
pub const FLOOR_ALERT_REP_CONSENSUS: u16 = 90; // >=2 malicious providers forces ActNow (mirrors Critical floor)
```

### 4.1 Formula (signed i32, exact order, clamp last)

1. `base` = the existing story score: `chain.score` / `incident.score` / `finding.score` /
   worst rollup member. Term `"base: attack-chain score"` etc. **Never** re-derive structure
   bonuses — chain/incident scores already embed them (double-count guard, test-pinned).
2. Corroboration: `+PTS_ALERT_IOC` (term `"corroborated: IOC feed hit on {ip}"`),
   `+PTS_ALERT_REP` (`"corroborated: reputation malicious on {ip}"`). Implicated IPs =
   `hosts ∪ member dst_ips`, looked up in `summary.ip_threats`.
3. Novelty: `+PTS_ALERT_NOVEL` / `+PTS_ALERT_ANOM` for BaselineDeviation / TrafficAnomaly
   members (warmup already gates emission upstream, so novelty here is trustworthy).
4. Confidence adjustment: `((confidence as i32 - 60) / 4).clamp(-15, 10)`, term
   `"confidence: {c}%"` when nonzero.
5. Dampens — **skipped entirely under `never_dampen`** (§2.3): cloud-peer
   (`PTS_ALERT_CLOUD_PEER`, only when ≥1 external peer exists and all are cloud-tagged clean),
   untimed (`PTS_ALERT_UNTIMED`).
6. Positive pool cap: positive contributions from steps 2-4 are summed and capped at
   `ALERT_UPLIFT_CAP`; when binding, a materialized term `"cap: uplift bounded at +25"` carries
   the negative delta.
7. Floors: IOC-backed ⇒ `max(p, 60)`; ≥2 distinct malicious providers on one implicated card ⇒
   `max(p, 90)` — each a materialized term when binding.
8. Floor discipline (the generalized weak-alone cap): `base < 60 && corroboration == 0 ⇒
   min(p, 59)`, term `"cap: uncorroborated story stays below High"`.
9. Final `clamp(0, 100)`, materialized as `"clamp: raw N -> M"` when binding.

`band = PriorityBand::from_priority(priority)`. **Ledger integrity** (deliberate divergence from
`score_flow`, where clamps are evidence-only): caps/floors/clamps are materialized as signed
`ScoreTerm`s so `Σ priority_terms == priority` exactly — the alert has no separate evidence
vector, the ledger *is* the explanation, and a test recomputes priority from the serialized
terms.

### 4.2 Sort & truncation

Total order: `(priority desc, severity.rank desc, tier asc [Chain < Host < Finding < Rollup],
first_seen_ns asc with None last, id asc)` — ids are unique by construction (§5.4), so the sort
is strict. Then the §2.3 truncation with the overflow rollup.

### 4.3 Confidence (u8)

Chain alerts copy `AttackChain.confidence` verbatim (the house formula, detect/mod.rs). Others:
class base 90 if any MalwareDownload/MalwareSignature member · 75 if any RuleMatch · 50 if all
members ∈ `WEAK_KINDS` · else 70; `+5·min(distinct_kinds-1, 2)`; `+10` if IOC/rep-corroborated;
`-10` if every member is untimed; clamp 0..=100.

---

## 5. Engine Wiring (file by file)

### 5.1 `detect/alerts.rs` (new)

`pub fn derive_alerts(summary: &Summary) -> Vec<Alert>` — **pure and idempotent** over the
finished Summary (reads `findings`/`incidents`/`attack_chains`/`ip_threats`/`resolved_ips`/
`arp_hosts`/`dhcp_hosts`/`encrypted_dns`/`carved_files`; ignores `summary.alerts`; writes
nothing; no clock; BTree containers only). Registered as `pub mod alerts;` in detect/mod.rs
(precedent: `detect/rules.rs`) — the correlation passes stay siblings. Reuses, not reimplements:
`stage_ordinal`/`stage_label`/`kind_phrase` (detect/mod.rs:3794-3884 — made `pub(crate)`),
`technique_name` (:3989), `fnv1a64` (:4027, made `pub(crate)`), `Severity::from_score`,
`ScoreTerm`, `enrich::classify_ip`/`cloud_provider`. Re-exported from lib.rs beside
`fold_rule_findings`.

### 5.2 Seams (three, all re-derive — never patch)

1. **analyze/mod.rs:576** — after `summary.findings = findings;`:
   `summary.alerts = crate::detect::alerts::derive_alerts(&summary);`
   The offline/native/wasm-analyze baseline: alerts exist with zero flags, zero network.
2. **detect/mod.rs:4742-4747 `fold_rule_findings`** — append after the chains re-run:
   `summary.alerts = crate::detect::alerts::derive_alerts(summary);`
   This is the parity mechanism: cli.rs:462 (Suricata rules), wasm lib.rs:602 (`apply_rules`)
   and wasm lib.rs:691 (`compare_to_baseline` deviation folding) all get byte-identical alert
   semantics with **zero** wasm changes. Indices stay valid because folds only append.
3. **enrich/reputation.rs `apply_reputation`** — after the ip_threats re-sort (:133-139):
   `summary.alerts = crate::detect::alerts::derive_alerts(summary);`
   Answer to *derive before or after reputation*: **both** — derived offline first, re-derived
   when reputation mutates the very cards the corroboration terms read (malicious floors can
   un-cap an alert past 59; benign attribution becomes context only — behavioral-finding hosts
   are never suppressed, the existing reputation invariant carries over). The wasm
   `apply_reputation` export (lib.rs:616-622) calls this same core fn — browser parity free.

Derivation order inside fold: `apply_findings → extend → correlate_incidents →
reconstruct_attack_chains → derive_alerts` (alerts read incidents + chains, so they go last).
Cost: O(F log F) over already-bounded inputs; zero per-packet cost.

### 5.3 The claim algorithm (deterministic pseudocode)

```text
host_findings: BTreeMap<&str, Vec<u32>> grouped by src_ip (ascending indices)
claimed = [false; n]
chain_hosts_all = union of hosts of QUALIFYING chains
Tier 1: for chain in attack_chains (already worst-first) where qualifies(chain):
          step_set = chain.steps[].finding_index
          for h in chain.hosts: for i in host_findings[h] where !claimed[i]:
            if standalone_eligible(f[i]) && !step_set.contains(i) { continue }  // Tier 2's
            claim(i) → members
          emit Chain alert (members ascending)
Tier 2: for i in 0..n where !claimed[i] && standalone_eligible(f[i]) && src_ip(i) ∈ chain_hosts_all:
          claim(i); emit Finding alert
Tier 3: for (host, idxs) in host_findings (BTreeMap ⇒ sorted): rem = unclaimed idxs
          if rem.is_empty() || weak_only(rem) { continue }
          claim all rem; emit Host alert (base = the host's Incident)
Tier 4: remaining, grouped by kind (BTreeMap): emit one Rollup per kind
rank → sort → truncate-with-overflow-rollup
```

`weak_only(rem)` = all kinds ∈ `WEAK_KINDS` **and** max severity ≤ Medium.

### 5.4 Ids (unique by construction, stable across folds)

`"alert:{:016x}"` = `fnv1a64` of a tier-prefixed key: Chain `"chain:" + chain.id`; Host
`"host:" + host`; Finding `"finding:{kind}:{src}:{dst?}:{port?}:{k}"` where `k` is the
per-key ordinal in ascending index order (collision-free even for repeated same-key rule
matches — the flaw review caught); Rollup `"rollup:" + kind.as_str()`; overflow
`"rollup:overflow"`. Append-only folds preserve earlier ordinals ⇒ ids are stable across the
three seams.

### 5.5 Context assembly (all sources already in Summary)

Identity: `arp_hosts` (ip→mac) ⋈ `dhcp_hosts` (mac→hostname/vendor_class). PassiveDns:
`resolved_ips` peer join. Cloud: `cloud_provider(ip)` + card `cloud:` tags. ThreatIntel/
Reputation: `ip_threats` card fields. BaselineNovelty/ForecastAnomaly: the member finding's
first evidence bullet + `finding_index` back-ref. KillChain: member stages via
`stage_label`, techniques via `technique_name`, plus `next_stage`. CarvedFile: `carved_files`
rows touching actor/peers. EncryptedDns: "host resolves via DoH — passive DNS is blind here"
(explains *absent* context). Entries sorted `(kind ordinal, text)`, capped 12; peers worst-first
`(ioc desc, rep_malicious desc, card score desc, ip asc)`, capped 4.

### 5.6 Action table

`action_for(kind, actor, peer, port)` — deterministic imperative templates keyed on the
representative kind (the member with max `(stage_ordinal, score)`; for chains this is the
furthest-stage strongest step): Beacon → "Isolate {actor}; block {peer}:{port} at the egress
firewall" · DataExfil → "Isolate {actor}; determine what data left toward {peer}" ·
MalwareDownload/MalwareSignature → "Quarantine {actor}; hunt the file hash across the fleet" ·
IcsControlCommand → "Verify {actor} is an authorized HMI/engineering workstation now" ·
BruteForce → "Lock the targeted accounts on {peer}; review authentication logs" · WeakTls/
TlsCertHealth rollups → "Schedule TLS configuration remediation on the listed hosts" · … (full
table in code; every kind covered, compiler-forced exhaustive match).

---

## 6. Serialization & Backward Compatibility

- `Summary.alerts` is `#[serde(default)]` — older summaries deserialize with `alerts == []`;
  older UIs ignore the unknown key. `schema_version` stays 1.
- All alert sub-structs use `#[serde(default)]` on every field that could be absent in future
  revisions; enums are snake_case append-last with `as_str()` tokens.
- **Do NOT touch:** `columnar/*`, `FLOW_PARQUET_VERSION`, `sql/schema.sql`, wasm `FlowDto`,
  `ui/src/lib/query/flow_columns.json` (schema_drift.rs guard) — alerts are summary-level.
- WASM ride-through: `AnalyzeResult` serializes the whole `AnalysisOutput` (lib.rs:574-578) —
  new fields flow to the browser automatically; the fold/reputation seams re-derive inside
  shared core fns. Zero wasm .rs changes.

---

## 7. CLI Surface

- **stderr one-liner** (after all post-hoc passes, so printed numbers match the JSON —
  cli.rs, after the rules block near :462):
  `alerts: 6 from 41 findings — 1 act-now, 2 investigate, 3 review; top: "Cross-host attack chain: …"`.
  Omitted when the queue is empty (mirrors the baseline/forecast one-liner convention).
- **`ppcap alerts <summary.json> [--out <path>] [--json]`** — a pure-transform subcommand
  mirroring `rescan`: loads an `AnalysisOutput` JSON, re-derives the queue (idempotent), prints
  a ranked human table to stdout (or the updated JSON with `--json`/`--out`). Uses: inspect a
  saved analysis; regenerate `ui/public/sample/summary.json` additively (§10). Exit codes 0/1/2
  per house convention.
- No `analyze` flags — defaults-only is what makes the three-seam re-derive parity exact.

---

## 8. HTML Report

New `fn alerts_html(alerts: &[Alert]) -> String` in report/mod.rs, modeled on `incidents_html`
(:717), inserted in `render_html` **before** `incidents_html` at :158 — the queue is the first
triage section. Per alert: band chip, `priority N/100 · conf M%`, title, actor identity line,
action line, context entries as a list, the term ledger as `(±N)` rows, member count. Rollups
show host/member counts. Empty case returns `""` (omit-when-empty convention, :663-711
precedent). Every capture-derived string through `esc()` (:339). Band chip styles added to
`const STYLE`; `.alert` joins the print `break-inside: avoid` set.

---

## 9. UI Surface

Coordinated edit sites (the five-site tab pattern):

1. `types.ts:708` — `TAB_IDS` gains `"alerts"` right after `"dashboard"`; mirror types
   (`Alert`, `AlertSource`, `PriorityBand`, `AlertContext`, `HostContext`, `PeerContext`,
   `ContextEntry`, `ContextKind` as string unions; `alerts?: Alert[]` on `Summary` with the
   "absent in older summaries" doc).
2. `MobileNav.tsx:52` — `TAB_ICON` adds `alerts: BellRing` (lucide).
3. `AppShell.tsx:145` — tabs entry `{ id: "alerts", label: "Alerts", badge: actionable }` where
   `actionable = alerts.filter(a => a.band === "act_now" || a.band === "investigate").length`
   (the badge counts actionable bands only — deliberately anti-noise); command-palette
   "Go to Alerts" action.
4. `App.tsx:814-908` — render branch → `views/AlertsView.tsx`.
5. `views/AlertsView.tsx` (new; BaselineView/ThreatsView are the models): ranked card list —
   band chip, priority + confidence, title, actor identity line, context chips (IOC / rep /
   cloud / new-to-baseline), action line, "covers N findings" — with expandable detail: the
   full context entries, the term ledger, member finding rows (rendered from
   `summary.findings[i]`), and an "Open chain" pivot when `chain_id` is set. Pure helpers in
   `lib/alerts.ts` (band label/color/order, term formatting), unit-tested.
6. AI brief (`lib/ai/context.ts`): `## Alert queue` as the FIRST section (before the chain
   section), `TOP_ALERTS = 5` with the "…and N more" idiom; covered hosts' incident lines
   demote to title-only (the chainSection precedent); privacy invariant intact (engine rollups
   only); 20k-char ceiling re-verified in context.test.ts.

---

## 10. Sample Data & E2E

`ui/public/sample/summary.json` is a checked-in engine output. Regenerate **additively** via
`ppcap alerts ui/public/sample/summary.json --json` (same engine, same struct field order — the
only diff is the new `alerts` key), keeping the e2e suite's existing expectations intact.
Playwright: extend an existing spec (or add `alerts.spec.ts`) — load the sample, open the
Alerts tab, assert ranked cards render and the badge counts actionable alerts.

---

## 11. Testing

**Engine unit (`detect/alerts.rs` `#[cfg(test)]`, hand-built Summaries via a local
`mk_summary(findings)` helper that runs `correlate_incidents` + `reconstruct_attack_chains`
first):**

- `forty_findings_collapse_to_under_ten_alerts` — the headline compression promise.
- `every_finding_covered_exactly_once` — the coverage invariant on shaped fixtures, including a
  truncation-overflow shape.
- `chain_alert_covers_member_hosts_and_incidents` — chain hosts produce no Tier-3 alert;
  `incident_hosts` receipts present.
- `unrelated_malware_on_chain_host_gets_own_alert` — the Tier-2 story-identity rule.
- `lone_medium_beacon_is_a_host_alert_not_a_rollup` — the weak-only gate excludes real stories.
- `weak_group_on_implicated_host_rides_host_alert` — the anti-burying rule (weak findings on a
  host with a real story corroborate it, never roll up fleet-wide).
- `uncorroborated_weak_signals_cap_below_high` / `ioc_floors_investigate` /
  `reputation_consensus_floors_act_now` — floors/caps with their materialized terms.
- `cloud_peers_dampen_but_never_dampen_skips_terms` — under `never_dampen` the dampen terms
  never appear (not applied-then-floored).
- `priority_terms_ledger_reproduces_priority` — Σ terms == priority, byte-exact labels.
- `truncation_emits_overflow_rollup_and_never_drops_actionable`.
- `derive_alerts_is_deterministic_under_finding_permutation` — shuffle findings, rebuild
  incidents/chains/alerts, byte-identical JSON (mirrors the ACR permutation test).
- `derive_alerts_is_idempotent` — re-running over a Summary with alerts already set is a no-op.
- `alerts_serde_roundtrip_and_default` — pre-feature JSON deserializes with `alerts == []`.
- `empty_summary_yields_no_alerts`.

**Seam tests:** `fold_rule_findings_rederives_alerts` (detect tests); 
`apply_reputation_rederives_alerts_with_corroboration` (reputation tests via the extended
`summary_with` ctor — priority rises, Reputation context appears, consensus floors ActNow).

**Integration (`tests/alerts_e2e.rs`, forecast_e2e.rs as template):** run `Scenario::AttackChain`
through `analyze::run` — assert exactly one Chain alert on top covering the staged findings,
band ≥ investigate, KillChain + Identity context present, coverage invariant, and same-seed
determinism; a `Scenario::Mixed` run asserting compression + the coverage invariant end-to-end.

**Report:** `report_renders_alert_queue_section` / `report_omits_alerts_when_none` + esc() XSS
assertion (report_html.rs).

**UI (Vitest):** `lib/alerts.test.ts`; `AlertsView.test.tsx` via `makeOutput` fixture extension
(ranked cards, expand shows members, chain pivot fires); AppShell badge test (actionable only);
`context.test.ts` (alert section first, demotion, `not.toContain("payload")`, 20k cap).

---

## 12. Performance & Invariants

- **Bounded memory:** the pass is O(findings) over already-capped inputs (detector caps,
  `MAX_CHAINS=256`, `top_k_ip_threats=50`); output bounded by `MAX_ALERTS` soft-capped rows ×
  capped context/peers/hosts; `finding_indices` total exactly `findings.len()` (u32s).
- **Single-pass streaming untouched:** SAC is a pure post-EOF transform; zero per-packet cost.
- **C-compiler-free:** no new dependencies; pure-Rust integer math.
- **Deterministic:** BTree containers, strict total-order sort ending in unique `id asc`,
  FNV-1a ids, no clock, no HashMap iteration order reaching output — locked by the permutation
  test.
- **Offline & local-first:** reads only the Summary; reputation context appears only if the
  opt-in pass ran; nothing leaves the device.
- **Schema untouched:** Parquet/DuckDB/flow surfaces unmodified (schema_drift.rs stays green).
- **Explainable:** Σ priority_terms == priority (test); grouping is visible membership;
  nothing is ever silently dropped (coverage invariant, absolute under truncation).

---

## 13. Phased Rollout (each milestone independently shippable)

- **M1 — Model + core pass.** `model/alert.rs`, `detect/alerts.rs` (four tiers, ledger,
  rollups, truncation-with-overflow), Summary field + `empty()` + `summary_with`, analyze seam,
  full unit suite. *Value:* `--json` consumers get the ranked queue. **Acceptance:** unit tests
  incl. coverage/permutation/ledger pass; `cargo test` green.
- **M2 — Re-derive seams + CLI.** fold/reputation seams + their tests, stderr one-liner,
  `ppcap alerts` subcommand + parse/dispatch tests. *Value:* alerts stay correct under
  rules/reputation; native+wasm parity locked. **Acceptance:** seam tests + CLI tests green.
- **M3 — HTML report.** `alerts_html` + insertion + tests. *Value:* the shareable report leads
  with the queue. **Acceptance:** report tests green, esc() asserted.
- **M4 — UI tab.** types.ts mirrors + five tab sites + `AlertsView` + `lib/alerts.ts` +
  fixtures + Vitest + regenerated sample + Playwright smoke. *Value:* the analyst's first
  screen. **Acceptance:** `npm test`, typecheck, e2e green.
- **M5 — AI brief + docs.** `alertSection` + context tests; this plan finalized with
  implementation-status blockquote. *Value:* the AI brief leads with the queue. **Acceptance:**
  context.test.ts green.

---

## 14. Risks, Edge Cases & Open Questions

| Risk | Mitigation |
|---|---|
| Chain alert swallows an unrelated strong story on a pivot host | Tier-2 standalone extraction (`NEVER_ROLLUP` kinds / ≥High non-step findings get their own alert); test-locked |
| Weak findings buried in fleet rollups while their host is under attack | Host-claiming absorbs weak findings into the host's real alert (anti-burying); test-locked |
| Double-counting structure bonuses (chain/incident scores already escalated) | base = existing story score, no re-derived structure terms; ledger test pins it |
| Cloud dampen hides a real C2 behind a CDN | `never_dampen` skips dampen terms for IOC/rep/malware/ICS/Critical/multi-host-chain alerts; beacons are never cloud-*suppressed* (only dampened, and only when uncorroborated) |
| Truncation silently breaks coverage | Overflow rollup absorbs the dropped tail; actionable rows never drop; invariant test runs on truncation-shaped fixtures |
| Decoy flooding games a relative rank cutoff | No relative suppression exists — rank is volume-independent |
| Same-key finding alerts collide (repeated rule matches) | Per-key ordinal in the id (§5.4) |
| Params divergence across native/wasm/fold derivations | No config surface at all; compile-time consts; three seams re-derive the same pure fn |
| Sample regen breaks e2e expectations | Additive regen via `ppcap alerts --json` keeps every existing field byte-identical |

**Open questions for review:** (1) Should Tier-4 rollups split per-severity as well as per-kind
when a kind spans Info..Medium? (v1: no — the ledger and member list carry it.) (2) Should the
UI Alerts tab replace Dashboard as the post-analysis landing? (v1: no — tab #2, badge carries
urgency.) (3) Should `ppcap alerts` also accept a case.json to build a cross-capture queue?
(Deferred to the case-level follow-up, §16.)

---

## 15. File-by-File Change Checklist

| File | Add/Modify | Reason |
|---|---|---|
| `engine/crates/ppcap-core/src/model/alert.rs` | **Add** | Alert/AlertSource/PriorityBand/AlertContext/HostContext/PeerContext/ContextEntry/ContextKind |
| `engine/crates/ppcap-core/src/model/mod.rs` | Modify | `pub mod alert;` + re-exports |
| `engine/crates/ppcap-core/src/model/summary.rs` | Modify | `alerts` field + `Summary::empty()` |
| `engine/crates/ppcap-core/src/detect/alerts.rs` | **Add** | `derive_alerts` + tiers + ledger + context + action table + unit tests |
| `engine/crates/ppcap-core/src/detect/mod.rs` | Modify | `pub mod alerts;`, `pub(crate)` on stage vocab + `fnv1a64`, fold seam re-derive |
| `engine/crates/ppcap-core/src/analyze/mod.rs` | Modify | derive seam after `summary.findings = findings;` |
| `engine/crates/ppcap-core/src/enrich/reputation.rs` | Modify | re-derive seam + `summary_with` ctor + seam test |
| `engine/crates/ppcap-core/src/report/mod.rs` | Modify | `alerts_html` + insertion + styles |
| `engine/crates/ppcap-core/src/lib.rs` | Modify | re-exports (`Alert`, `derive_alerts`, …) |
| `engine/crates/ppcap-core/tests/alerts_e2e.rs` | **Add** | scenario integration tests |
| `engine/crates/ppcap-cli/src/cli.rs` | Modify | stderr one-liner + `ppcap alerts` subcommand + tests |
| `ui/src/types.ts` | Modify | TAB_IDS + mirror types + `Summary.alerts?` |
| `ui/src/components/layout/MobileNav.tsx` | Modify | TAB_ICON entry |
| `ui/src/components/layout/AppShell.tsx` | Modify | tabs entry + badge + palette action |
| `ui/src/App.tsx` | Modify | render branch |
| `ui/src/views/AlertsView.tsx` (+ test) | **Add** | the queue view |
| `ui/src/lib/alerts.ts` (+ test) | **Add** | band/term helpers |
| `ui/src/lib/ai/context.ts` (+ test) | Modify | alert brief section |
| `ui/src/test/fixtures.ts` | Modify | alerts in `makeOutput` |
| `ui/public/sample/summary.json` | Modify | additive regen with alerts |
| `ui/e2e/*` | Modify/Add | alerts tab smoke |
| **NOT touched** | — | `columnar/*`, `FLOW_PARQUET_VERSION`, `sql/schema.sql`, wasm `FlowDto`, `flow_columns.json`, `ppcap-wasm/src/lib.rs`, `supabase/*`, `relay/*` |

---

## 16. Out of Scope & Follow-ups

- **Alert diffing / CompareView integration** — new/resolved/priority-delta between two
  captures keyed by `Alert.id` (the Time Machine `newly_flagged` spirit at the alert layer).
- **Alert-native SIEM egress** — CEF/Sigma/STIX emitters for alerts beside the finding exports.
- **`Scenario::AlertTriage` gen fixture** — a purpose-built noisy-office capture as the
  canonical compression acceptance fixture (unit fixtures cover compression in v1).
- **Case-level queue** — a cross-capture alert rollup in `case.json` (batch triage), fusing
  `shared_indicators` recurrence into priority.
- **Ack/dismiss persistence** — a sidecar mirroring the baseline/timemachine pattern for
  analyst state; enables "new since last review".
- **UI sensitivity control** — the PAD §12 open question generalized: a user-tunable
  weak-signal dampen (needs a config-surface story that preserves the three-seam parity).

---

**Guarantees, verified by tests**

- Every finding index appears in exactly one alert; the invariant survives truncation.
- Σ `priority_terms` == `priority`, byte-exact labels; caps/floors visible as terms.
- Uncorroborated weak stories never cross into the High band; IOC forces ≥60; reputation
  consensus forces ≥90; dampen terms never appear on `never_dampen` alerts.
- Deterministic under finding permutation; idempotent under re-derivation; byte-identical
  across the analyze / fold / reputation seams for the same inputs.
- Older summaries load with `alerts == []`; no Parquet/DuckDB/flow schema drift.

---

## Appendix A — Design-review corrections (folded in)

1. **(safety — major)** engine-reuse's relative rank-cutoff suppression (`status: Suppressed`
   past top-16) was rejected: suppression as a function of *unrelated* alert volume is gameable
   by decoy flooding and semantically empty. Replaced by group-and-tell with no status field.
2. **(safety — major)** Hard `MAX_ALERTS` truncation (engine-reuse, noise-safety) silently broke
   the coverage invariant. Replaced by soc-workflow's overflow rollup + never-drop-actionable.
3. **(product — major)** Coverage-by-host alone (engine-reuse) let a chain swallow an unrelated
   malware story on a pivot host. Fixed by Tier-2 standalone extraction for non-step
   `NEVER_ROLLUP`/≥High findings on chain hosts.
4. **(product — major)** soc-workflow's Tier-4 sent a lone Medium beacon to a "rollup of 1".
   Fixed: `weak_only` gates on `WEAK_KINDS` membership, and Beacon is not weak.
5. **(engine)** soc-workflow's finding-alert id `fnv1a(kind+src+dst+port)` collides for repeated
   same-key findings. Fixed with the per-key ordinal.
6. **(engine)** `AlertParams` on `PipelineConfig` (soc-workflow) silently reverts to defaults in
   every fold/reputation re-derive. Dropped: no config surface (attack-chain precedent).
7. **(engine)** Re-deriving multi-stage/multi-host bonuses (soc-workflow) double-counts what
   chain/incident scores embed. Fixed: base = existing story score.
8. **(safety)** noise-safety's custom bands (70/40/15) let a 59-capped weak alert present as
   "Investigate". Fixed: bands reuse `Severity::from_score` cutoffs verbatim.
9. **(safety)** Dampens applied-then-floored would show a cloud dampen on a malicious-peer
   alert. Fixed: `never_dampen` skips the terms entirely.
10. **(engine)** `why: Vec<String>` as a byte-duplicate of the terms (engine-reuse) dropped;
    the UI/report render `"{label} ({points:+})"` from the terms.
11. **(safety)** Per-member suppressed tombstone rows (noise-safety) bloat the JSON; membership
    in the rollup is the audit trail.
12. **(product)** Alert.severity rewritten from priority (engine-reuse) conflated the judgment
    and rank axes; severity is copied from the source story, band carries the rank.
13. **(engine — found during implementation)** The planned chain-qualification gate
    (`tactic_count >= 2 || severity >= High`) was wrong in practice: `reconstruct_attack_chains`
    emits a chain for *every* actor host, so any host with two finding kinds spanning stages
    qualified as a "chain" — including two weak posture kinds, which would dodge the hygiene
    rollup. Tier 1 is now strictly cross-host (`host_count >= 2`); single-host stories are the
    host tier's, where the incident base already carries multi-stage escalation.

## Appendix B — Citation verification

Every `path/file.rs:line` in this plan was checked against the branch tree at planning time
(`analyze/mod.rs:474-576` post-pass block, `summary.rs:379/:390/:433`, `finding.rs:17/:121`,
`detect/mod.rs:3699/:3794/:4027/:4132/:4742`, `reputation.rs:62/:133-139/:303`,
`report/mod.rs:44/:158/:339/:663/:717`, `cli.rs:433/:462`, wasm `lib.rs:574/:602/:616/:691`,
`types.ts:708`, `MobileNav.tsx:52`, `AppShell.tsx:145`, `App.tsx:814-908`). Treat line numbers
as anchors — grep before editing; the seams are named by function, not by line, wherever the
code is the authority.
