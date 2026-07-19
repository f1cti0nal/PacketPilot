//! Reconstructed attack chains. Fully implemented contract type.
//!
//! An [`AttackChain`] is the cross-host *investigation* superstructure over the behavioral
//! [`crate::model::finding::Finding`] set: where a [`crate::model::incident::Incident`] collapses
//! findings under one actor host, a chain follows the compromise across hosts — an attacker who
//! sweeps the network, brute-forces host B, and then watches B beacon to a C2 and exfiltrate is a
//! single **temporally-ordered, causally-linked** story, not two disconnected incidents. Chains are
//! produced by [`crate::detect::reconstruct_attack_chains`] and surfaced in the summary JSON, the
//! HTML report, and the UI. `incidents` is retained unchanged; chains are additive.
//!
//! Every step references its source finding by index into `Summary.findings` (no payload is
//! re-embedded), and the whole structure is a DAG-forest: `steps` are time-ordered nodes and
//! `edges` are the typed transitions (per-host [`EdgeKind::Progression`] and cross-host
//! [`EdgeKind::Pivot`]).

use crate::model::finding::FindingKind;
use crate::model::severity::Severity;

/// One reconstructed attack chain: a connected component of the finding graph, rendered as a
/// time-ordered sequence of [`ChainStep`]s joined by typed [`ChainEdge`]s, with an explicit MITRE
/// ATT&CK tactic progression.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AttackChain {
    /// Stable id, `"chain:"` + an FNV-1a hash of the sorted distinct host set (disjoint across
    /// chains, so the id is unique within a summary).
    pub id: String,
    /// Chain severity — the worst contributing finding, escalated one band per breadth axis
    /// (≥2 distinct tactics, ≥2 distinct hosts).
    pub severity: Severity,
    /// Representative 0..=100 score (escalated for multi-tactic / multi-host chains).
    pub score: u16,
    /// Reconstruction confidence 0..=100 (higher = stronger pivots + known timestamps).
    pub confidence: u8,
    /// One-line headline.
    pub title: String,
    /// Human-readable narrative of the chain, in kill-chain order with pivot arrows.
    pub narrative: String,
    /// Distinct actor hosts, in first-seen order (tie-broken by host string).
    pub hosts: Vec<String>,
    /// The chain's steps, ordered by time then kill-chain taxonomy.
    pub steps: Vec<ChainStep>,
    /// Typed transitions between steps (per-host progression + cross-host pivots).
    pub edges: Vec<ChainEdge>,
    /// The ATT&CK tactic progression (distinct tactics in step order).
    pub tactics: Vec<TacticStep>,
    /// Technique ids in chain order, deduplicated preserving first occurrence (NOT sorted).
    pub attack: Vec<String>,
    /// Campaign id when this chain clusters with others over shared adversary infrastructure
    /// (assigned by the M5 campaign pass); `None` otherwise. `#[serde(default)]` keeps older
    /// summaries readable.
    #[serde(default)]
    pub campaign_id: Option<String>,
    /// Earliest step timestamp (ns since the capture epoch); `None` if no step is timestamped.
    pub first_ts_ns: Option<i64>,
    /// Latest step timestamp (ns since the capture epoch); `None` if no step is timestamped.
    pub last_ts_ns: Option<i64>,
    /// Distinct actor-host count (mirrors `hosts.len()`, surfaced for convenient rendering).
    pub host_count: u32,
    /// Distinct tactic count (mirrors `tactics.len()`).
    pub tactic_count: u32,
}

/// One node in an [`AttackChain`]: a single behavioral finding placed in the chain's timeline and
/// attributed to its actor host. The heavy payload lives in `Summary.findings[finding_index]`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ChainStep {
    /// 0-based position of this step in the chain's `steps` vector (the node id used by edges).
    pub order: u32,
    /// The host this step is attributed to (varies across a pivot).
    pub actor: String,
    /// Kill-chain stage ordinal (equals `stage_ordinal`, 0..=6).
    pub tactic_ordinal: u8,
    /// Human kill-chain stage label (equals `stage_label`).
    pub tactic: String,
    /// The underlying finding kind.
    pub kind: FindingKind,
    /// ATT&CK techniques (id + resolved name) for this step.
    pub techniques: Vec<TechniqueRef>,
    /// The peer host this step touched (dst / C2 / resolver), when the finding names one.
    pub peer: Option<String>,
    /// Step severity (the finding's severity).
    pub severity: Severity,
    /// Step 0..=100 score (the finding's score).
    pub score: u16,
    /// First observed activity for the underlying finding (ns); `None` if untimestamped.
    pub first_seen_ns: Option<i64>,
    /// Last observed activity for the underlying finding (ns); `None` if untimestamped.
    pub last_seen_ns: Option<i64>,
    /// One representative evidence bullet from the finding. `#[serde(default)]` keeps older
    /// summaries readable.
    #[serde(default)]
    pub evidence: Option<String>,
    /// Back-reference into `Summary.findings` — the full finding (evidence, ATT&CK, metrics).
    pub finding_index: u32,
}

/// A typed transition between two [`ChainStep`]s (referenced by their `order`).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ChainEdge {
    /// Source step `order`.
    pub from: u32,
    /// Destination step `order`.
    pub to: u32,
    /// Transition kind.
    pub kind: EdgeKind,
    /// The handoff finding kind for a [`EdgeKind::Pivot`]; `None` for a progression edge.
    /// `#[serde(default)]` keeps older summaries readable.
    #[serde(default)]
    pub via_kind: Option<FindingKind>,
    /// Dwell time between the two steps (ns), clamped to `>= 0`; `None` when unknown.
    pub gap_ns: Option<i64>,
}

/// The kind of a [`ChainEdge`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// A cross-host handoff: the victim of the `from` step became the actor of the `to` step.
    Pivot,
    /// Same-host progression along the kill chain (consecutive steps on one host).
    Progression,
}

/// One stage in the chain's MITRE ATT&CK tactic progression.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TacticStep {
    /// Kill-chain ordinal (equals `stage_ordinal`).
    pub ordinal: u8,
    /// Human tactic label (equals `stage_label`).
    pub tactic: String,
    /// Techniques observed at this tactic across the chain.
    pub techniques: Vec<TechniqueRef>,
    /// A representative host that reached this tactic (the earliest step's actor).
    pub host: String,
    /// The earliest step timestamp at this tactic (ns); `None` if untimestamped.
    pub first_seen_ns: Option<i64>,
}

/// A MITRE ATT&CK technique reference: the id plus its resolved human name.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TechniqueRef {
    /// Technique id (e.g. `"T1071"`).
    pub id: String,
    /// Resolved technique name (e.g. `"Application Layer Protocol"`); the id itself if unknown.
    pub name: String,
}
