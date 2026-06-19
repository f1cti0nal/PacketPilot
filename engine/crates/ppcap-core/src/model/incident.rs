//! Correlated incidents. Fully implemented contract type.
//!
//! A [`Incident`] collapses every behavioral [`crate::model::finding::Finding`] attributed to one
//! host into a single ranked story, ordered along the kill chain (discovery → command-and-control
//! → exfiltration). This is the *"is this a real incident?"* layer: a host that both swept the
//! network *and* beaconed to a C2 is a confirmed multi-stage compromise, escalated above any
//! single finding's severity. Incidents are the natural unit an analyst triages and the object a
//! downstream SOC/STIX export would emit.

use crate::model::finding::Finding;
use crate::model::severity::Severity;

/// A per-host correlation of one or more behavioral findings.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Incident {
    /// The implicated host (the actor the findings are attributed to).
    pub host: String,
    /// Incident severity — the worst contributing finding, escalated one band when the host
    /// exhibits two or more distinct stages (a multi-stage chain is a confirmed incident).
    pub severity: Severity,
    /// Representative 0..=100 score (escalated for multi-stage chains).
    pub score: u16,
    /// One-line headline.
    pub title: String,
    /// Human-readable narrative of what the host did, in kill-chain order.
    pub narrative: String,
    /// Kill-chain stage labels in order, e.g. `["Discovery", "Command & Control"]`.
    pub stages: Vec<String>,
    /// Sorted union of MITRE ATT&CK technique ids across the contributing findings.
    pub attack: Vec<String>,
    /// The contributing findings, ordered by kill-chain stage.
    pub findings: Vec<Finding>,
}
