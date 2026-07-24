//! Smart Alerting with Context. Fully implemented contract type.
//!
//! An [`Alert`] is one row of the **ranked, deduplicated, context-bundled triage queue** derived
//! from the finished analysis — the layer above [`crate::model::finding::Finding`] (raw
//! detections), [`crate::model::incident::Incident`] (per-host correlation) and
//! [`crate::model::attack_chain::AttackChain`] (cross-host stories). Where those answer *"what
//! happened"*, an alert answers *"what do I look at first, and why"*: it fuses the story's score
//! with threat-intel corroboration, baseline/forecast novelty, and reconstruction confidence into
//! a transparent `priority` ledger, joins the context an analyst would otherwise pivot for
//! (ARP/DHCP identity, passive DNS, cloud attribution, reputation, kill-chain position), and
//! recommends a next action. Produced by [`crate::detect::alerts::derive_alerts`]; surfaced in the
//! summary JSON, the HTML report, and the UI.
//!
//! ## Invariants
//!
//! - **Coverage:** every index into `Summary.findings` appears in exactly one alert's
//!   `finding_indices` — grouping is the noise mechanism, and membership is the explanation;
//!   nothing is ever silently dropped (the invariant survives truncation via an overflow rollup).
//! - **Ledger:** `Σ priority_terms.points == priority`, with caps/floors/clamps materialized as
//!   signed terms (a deliberate, documented divergence from `score_flow`, where clamps are
//!   evidence-only — an alert has no separate evidence vector, the ledger *is* the explanation).
//! - Alerts hold **back-references only** (`finding_indices`, `chain_id`, `incident_hosts`);
//!   findings are never cloned, and the referenced vectors are never mutated by the alert pass.

use crate::model::severity::Severity;
use crate::model::summary::ScoreTerm;

/// Which layer of the correlation hierarchy this alert is told from. Appended-last discipline for
/// any new tier (keeps existing variant ordinals stable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSource {
    /// A qualifying cross-host / multi-tactic attack chain (tier 1).
    Chain,
    /// A single actor host's story — its per-host incident (tier 3).
    Host,
    /// One standalone strong finding extracted from a chain host so the chain cannot swallow an
    /// unrelated story (tier 2).
    Finding,
    /// A cross-host per-kind hygiene rollup, or the truncation overflow rollup (tier 4).
    Rollup,
}

impl AlertSource {
    /// Stable snake_case token (matches the serde wire form).
    pub fn as_str(self) -> &'static str {
        match self {
            AlertSource::Chain => "chain",
            AlertSource::Host => "host",
            AlertSource::Finding => "finding",
            AlertSource::Rollup => "rollup",
        }
    }

    /// Tier precedence for the queue sort (lower = stronger story shape).
    pub fn tier(self) -> u8 {
        match self {
            AlertSource::Chain => 0,
            AlertSource::Host => 1,
            AlertSource::Finding => 2,
            AlertSource::Rollup => 3,
        }
    }
}

/// Priority band of the queue. The cutoffs are [`Severity::from_score`]'s, verbatim — no new
/// threshold vocabulary (`act_now` 85-100 · `investigate` 60-84 · `review` 35-59 · `log` 15-34 ·
/// `info` 0-14). Ascending declaration so `Ord` equals urgency.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PriorityBand {
    Info,
    Log,
    Review,
    Investigate,
    ActNow,
}

impl PriorityBand {
    /// Band of a 0..=100 priority — the same cutoffs as [`Severity::from_score`].
    pub fn from_priority(p: u16) -> PriorityBand {
        match p {
            85..=u16::MAX => PriorityBand::ActNow,
            60..=84 => PriorityBand::Investigate,
            35..=59 => PriorityBand::Review,
            15..=34 => PriorityBand::Log,
            _ => PriorityBand::Info,
        }
    }

    /// 0..=4 urgency rank (higher = more urgent).
    pub fn rank(self) -> u8 {
        self as u8
    }

    /// Stable snake_case token (matches the serde wire form).
    pub fn as_str(self) -> &'static str {
        match self {
            PriorityBand::Info => "info",
            PriorityBand::Log => "log",
            PriorityBand::Review => "review",
            PriorityBand::Investigate => "investigate",
            PriorityBand::ActNow => "act_now",
        }
    }
}

/// Typed context-entry kind. The declaration order is the fixed render order (`Ord` is the sort
/// key); append new kinds last to keep existing variant ordinals stable.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ContextKind {
    /// ARP/DHCP asset identity for the actor ("which machine is this").
    Identity,
    /// Offline IOC-feed hit on an implicated card.
    ThreatIntel,
    /// Online reputation verdicts on an implicated card (present only if the opt-in pass ran).
    Reputation,
    /// A baseline-deviation member: behavior first-seen vs the host's learned self.
    BaselineNovelty,
    /// A traffic-anomaly member: departure from the host's own within-capture forecast.
    ForecastAnomaly,
    /// Kill-chain position and the next expected stage.
    KillChain,
    /// Passive-DNS domain attribution for a peer.
    PassiveDns,
    /// Cloud-provider attribution for a peer (also the dampen-term justification).
    CloudProvider,
    /// A carved HTTP file touching the actor/peers (hash, size, known-bad flag).
    CarvedFile,
    /// DNS-visibility caveat: the actor resolves via DoH/DoT, so passive DNS is blind.
    EncryptedDns,
}

/// One deterministic context fact, with an optional back-reference to the finding it came from.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ContextEntry {
    pub kind: ContextKind,
    /// One human-readable sentence (escaped only at render time, like finding evidence).
    pub text: String,
    /// Back-ref into `Summary.findings` when a specific finding produced this fact.
    /// `#[serde(default)]` keeps older summaries readable.
    #[serde(default)]
    pub finding_index: Option<u32>,
    /// The subject IP for host/peer-scoped entries (the UI's join key).
    /// `#[serde(default)]` keeps older summaries readable.
    #[serde(default)]
    pub ip: Option<String>,
}

/// The primary actor's asset identity, joined from `arp_hosts` (IP→MAC) and `dhcp_hosts`
/// (MAC→hostname/vendor-class) — the "which machine is this" answer on the card.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HostContext {
    pub ip: String,
    /// DHCP-reported hostname, when the MAC join found one. `#[serde(default)]` for forward compat.
    #[serde(default)]
    pub hostname: Option<String>,
    /// MAC address from ARP, when observed. `#[serde(default)]` for forward compat.
    #[serde(default)]
    pub mac: Option<String>,
    /// DHCP vendor-class identifier, when reported. `#[serde(default)]` for forward compat.
    #[serde(default)]
    pub vendor: Option<String>,
    /// `!classify_ip(ip).is_external()` — internal/private address space.
    pub internal: bool,
    /// Cloud-provider attribution when the actor itself is cloud address space.
    #[serde(default)]
    pub cloud: Option<String>,
    /// The actor has a `BaselineDeviation` member finding in this capture (first-seen behavior
    /// vs its learned baseline). `#[serde(default)]` keeps older summaries readable.
    #[serde(default)]
    pub new_to_baseline: bool,
}

/// One external peer of interest (C2 / drop / scan target), worst-first, bounded.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PeerContext {
    pub ip: String,
    /// Passive-DNS domain the peer last resolved from, when known. `#[serde(default)]`.
    #[serde(default)]
    pub domain: Option<String>,
    /// Cloud-provider attribution, when the peer is cloud address space. `#[serde(default)]`.
    #[serde(default)]
    pub cloud: Option<String>,
    /// The peer's threat card matched the offline IOC feed.
    pub ioc: bool,
    /// Count of `Malicious` reputation verdicts on the peer's card (0 when the pass never ran).
    /// `#[serde(default)]` keeps older summaries readable.
    #[serde(default)]
    pub reputation_malicious: u8,
    /// The destination service port the story used toward this peer, when it names one.
    #[serde(default)]
    pub dst_port: Option<u16>,
}

/// The joined context bundle on one alert.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AlertContext {
    /// The primary actor's identity.
    pub actor: HostContext,
    /// External peers of interest, worst-first, capped. `#[serde(default)]`.
    #[serde(default)]
    pub peers: Vec<PeerContext>,
    /// Typed context facts, ordered by (kind ordinal, text), capped. `#[serde(default)]`.
    #[serde(default)]
    pub entries: Vec<ContextEntry>,
}

/// One row of the ranked triage queue. Carries back-references only — findings are never cloned
/// (deliberate divergence from `Incident.findings`: one source of truth, and indices stay valid
/// because `fold_rule_findings` only appends to `Summary.findings`).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Alert {
    /// `"alert:{:016x}"` — FNV-1a of a tier-prefixed stable key (unique by construction, stable
    /// across the analyze / fold / reputation re-derivations).
    pub id: String,
    pub source: AlertSource,
    /// Band of `priority` (the [`Severity::from_score`] cutoffs — no new thresholds).
    pub band: PriorityBand,
    /// 0..=100 fused rank. `Σ priority_terms == priority`, test-enforced.
    pub priority: u16,
    /// 0..=100 trust figure. Chain alerts copy `AttackChain.confidence` verbatim.
    pub confidence: u8,
    /// Copied from the source story (worst member) — the *judgment* axis, never rewritten from
    /// `priority` (the *rank* axis). The two can disagree; the UI shows both.
    pub severity: Severity,
    /// One-line headline (reuses the source story's title where one exists).
    pub title: String,
    /// Deterministic narrative (chain/incident narrative, or built from `kind_phrase`).
    pub narrative: String,
    /// Recommended next step, from the per-kind action table.
    pub action: String,
    /// Primary actor host (chain root / incident host / finding src_ip / first rollup host).
    pub actor: String,
    /// Implicated actor hosts, story order then IP asc; capped (`host_count` keeps the total).
    pub hosts: Vec<String>,
    /// Total distinct actor hosts (>= `hosts.len()`; rollups can exceed the listing cap).
    pub host_count: u32,
    /// Primary external peer (C2 / drop) when the story names exactly one distinct destination.
    /// `#[serde(default)]` keeps older summaries readable.
    #[serde(default)]
    pub peer: Option<String>,
    /// ATT&CK technique ids in story order, deduplicated preserving first occurrence.
    pub attack: Vec<String>,
    /// Furthest kill-chain stage reached (`stage_label` of the max member `stage_ordinal`).
    pub stage: String,
    pub stage_ordinal: u8,
    /// "What to watch for next": the stage label one past `stage_ordinal`; `None` at Impact.
    /// `#[serde(default)]` keeps older summaries readable.
    #[serde(default)]
    pub next_stage: Option<String>,
    /// The transparent rank ledger (base + every adjustment, caps/floors materialized).
    pub priority_terms: Vec<ScoreTerm>,
    pub context: AlertContext,
    /// ALL member indices into `Summary.findings`, ascending, uncapped — complete receipts.
    pub finding_indices: Vec<u32>,
    /// `== finding_indices.len()`; the coverage invariant sums this across the queue.
    pub finding_count: u32,
    /// Back-ref to `AttackChain.id` for chain alerts. `#[serde(default)]`.
    #[serde(default)]
    pub chain_id: Option<String>,
    /// Hosts whose per-host `Incident` this alert subsumes. `#[serde(default)]`.
    #[serde(default)]
    pub incident_hosts: Vec<String>,
    /// Earliest member activity (ns since the capture epoch); `None` if every member is untimed.
    pub first_seen_ns: Option<i64>,
    /// Latest member activity (ns); `None` if every member is untimed.
    pub last_seen_ns: Option<i64>,
}

/// Compact projection of one alert for diff rows (no context bundle — the full alert lives
/// in its own summary's queue).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AlertDiffEntry {
    pub id: String,
    pub source: AlertSource,
    pub band: PriorityBand,
    pub priority: u16,
    pub severity: Severity,
    pub title: String,
    pub actor: String,
}

/// One story present in both queues whose rank moved (priority and/or band).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AlertDiffChange {
    pub id: String,
    /// The AFTER side's headline (the current story).
    pub title: String,
    pub actor: String,
    pub before_priority: u16,
    pub after_priority: u16,
    /// `after - before` (signed) — positive means the story got worse.
    pub delta: i32,
    pub before_band: PriorityBand,
    pub after_band: PriorityBand,
}

/// The pairwise diff of two alert queues (same network, two points in time), matched by the
/// stable alert id — Time Machine's `newly_flagged` idea generalized from indicators to whole
/// stories. Produced by [`crate::detect::alerts::diff_alerts`].
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AlertDiff {
    /// Stories only in the newer queue, worst-first — the actionable delta.
    pub new_alerts: Vec<AlertDiffEntry>,
    /// Stories only in the older queue, worst-first — resolved (or no longer observed).
    pub resolved: Vec<AlertDiffEntry>,
    /// Stories in both whose rank moved, by |delta| desc — a climbing story is the early
    /// warning.
    pub changed: Vec<AlertDiffChange>,
    /// Stories in both with an identical rank.
    pub unchanged: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn band_cutoffs_match_severity_from_score() {
        // The band boundaries are Severity::from_score's, verbatim.
        for p in 0..=100u16 {
            let band = PriorityBand::from_priority(p);
            let sev = Severity::from_score(p);
            let expect = match sev {
                Severity::Critical => PriorityBand::ActNow,
                Severity::High => PriorityBand::Investigate,
                Severity::Medium => PriorityBand::Review,
                Severity::Low => PriorityBand::Log,
                Severity::Info => PriorityBand::Info,
            };
            assert_eq!(band, expect, "priority {p}");
        }
    }

    #[test]
    fn band_ord_matches_urgency() {
        assert!(PriorityBand::ActNow > PriorityBand::Investigate);
        assert!(PriorityBand::Investigate > PriorityBand::Review);
        assert!(PriorityBand::Review > PriorityBand::Log);
        assert!(PriorityBand::Log > PriorityBand::Info);
        assert_eq!(PriorityBand::ActNow.rank(), 4);
        assert_eq!(PriorityBand::Info.rank(), 0);
    }

    #[test]
    fn wire_tokens_roundtrip() {
        for (v, tok) in [
            (AlertSource::Chain, "\"chain\""),
            (AlertSource::Host, "\"host\""),
            (AlertSource::Finding, "\"finding\""),
            (AlertSource::Rollup, "\"rollup\""),
        ] {
            assert_eq!(serde_json::to_string(&v).unwrap(), tok);
            assert_eq!(v.as_str(), tok.trim_matches('"'));
        }
        for (v, tok) in [
            (PriorityBand::ActNow, "\"act_now\""),
            (PriorityBand::Investigate, "\"investigate\""),
            (PriorityBand::Review, "\"review\""),
            (PriorityBand::Log, "\"log\""),
            (PriorityBand::Info, "\"info\""),
        ] {
            assert_eq!(serde_json::to_string(&v).unwrap(), tok);
            assert_eq!(v.as_str(), tok.trim_matches('"'));
        }
        let k: ContextKind = serde_json::from_str("\"baseline_novelty\"").unwrap();
        assert_eq!(k, ContextKind::BaselineNovelty);
    }

    #[test]
    fn context_kind_ord_is_render_order() {
        assert!(ContextKind::Identity < ContextKind::ThreatIntel);
        assert!(ContextKind::KillChain < ContextKind::PassiveDns);
        assert!(ContextKind::CarvedFile < ContextKind::EncryptedDns);
    }
}
