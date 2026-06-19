//! Cross-flow behavioral findings. Fully implemented contract type.
//!
//! A [`Finding`] is a *named, explainable* conclusion drawn across many flows — "host X is
//! beaconing to Y", "host X swept N hosts on port P" — produced by the `detect` stage from the
//! behavioral substrate. Unlike a per-flow [`crate::model::severity::Severity`] verdict (which
//! is dominated by the IOC feed), a finding lets the engine reach a High/Critical conclusion
//! from *behavior alone*, with no threat-feed hit. Findings are surfaced in the summary JSON
//! and the UI alongside the per-IP threat cards.

use crate::model::severity::Severity;

/// The kind of behavioral detection.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// Periodic command-and-control beaconing (regular callbacks to a destination).
    Beacon,
    /// Horizontal sweep: one source touching many distinct destination hosts.
    HostSweep,
    /// Data exfiltration: a large asymmetric outbound transfer to an external peer.
    DataExfil,
    /// DNS tunneling / DGA: high-volume, high-entropy DNS queries (C2 / exfil over DNS).
    DnsTunnel,
}

impl FindingKind {
    /// Stable snake_case token (matches the serde wire form).
    pub fn as_str(self) -> &'static str {
        match self {
            FindingKind::Beacon => "beacon",
            FindingKind::HostSweep => "host_sweep",
            FindingKind::DataExfil => "data_exfil",
            FindingKind::DnsTunnel => "dns_tunnel",
        }
    }
}

/// A cross-flow behavioral detection with an explainable evidence trail.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    /// Representative 0..=100 threat score, in the band of `severity` (parallels the per-flow
    /// `threat_score`). Used when uplifting per-IP threat cards.
    pub score: u16,
    /// Human-readable one-line headline.
    pub title: String,
    /// The source host the behavior is attributed to.
    pub src_ip: String,
    /// Destination host; `None` for fan-out findings (e.g. a sweep hits many hosts).
    pub dst_ip: Option<String>,
    /// Destination service port, when the finding is tied to one.
    pub dst_port: Option<u16>,
    /// MITRE ATT&CK technique ids (e.g. `["T1071"]`).
    pub attack: Vec<String>,
    /// Explainable evidence bullets (mirrors the per-flow score evidence style).
    pub evidence: Vec<String>,
    /// Candidate beacon period in nanoseconds; `None` for non-beacon findings.
    pub interval_ns: Option<i64>,
    /// Beacon jitter (coefficient of variation of inter-contact gaps); `None` otherwise.
    pub jitter_cv: Option<f64>,
    /// Contributing contact / connection count.
    pub contacts: Option<u64>,
}
