//! Incident timelines. Fully implemented contract type.
//!
//! An [`AlertTimeline`] retells one [`crate::model::alert::Alert`] as a single chronological story
//! across every host it implicates: the first contact with the peer, the DNS answer that resolved
//! it, the file it downloaded, each detection as it starts, and the cross-host hops the attack
//! chain reconstructed. It is the hand-off artifact — the CLI, the HTML report and the UI all
//! render the same rows — and every row carries a [`PacketScope`] so the packets behind it are one
//! carve away. Produced by [`crate::detect::timeline::derive_timelines`] alongside the alert queue;
//! like alerts, timelines hold back-references (`finding_index`) and never mutate their sources.

use crate::model::severity::Severity;

/// What one timeline row records. The declaration order is the tie-break render order for rows
/// sharing a timestamp (context before the detection it explains); append new kinds last.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TimelineEventKind {
    /// The first flow observed between two of the story's endpoints.
    FirstContact,
    /// A DNS answer that resolved one of the story's peers.
    DnsAnswer,
    /// A cross-host handoff: the victim of one step became the actor of the next.
    Pivot,
    /// A file carved from a cleartext HTTP download (SHA-256 is the IOC).
    FileDownload,
    /// A behavioral detection (one member finding) starting.
    Detection,
}

impl TimelineEventKind {
    /// Stable snake_case token (matches the serde wire form).
    pub fn as_str(self) -> &'static str {
        match self {
            TimelineEventKind::FirstContact => "first_contact",
            TimelineEventKind::DnsAnswer => "dns_answer",
            TimelineEventKind::Pivot => "pivot",
            TimelineEventKind::FileDownload => "file_download",
            TimelineEventKind::Detection => "detection",
        }
    }

    /// Short human label for tables and exports.
    pub fn label(self) -> &'static str {
        match self {
            TimelineEventKind::FirstContact => "First contact",
            TimelineEventKind::DnsAnswer => "DNS answer",
            TimelineEventKind::Pivot => "Lateral hop",
            TimelineEventKind::FileDownload => "Download",
            TimelineEventKind::Detection => "Detection",
        }
    }
}

/// The packets behind one timeline row: frames touching `host` (and `peer`, and `port`, when set)
/// inside `[start_ns, end_ns]`. Mirrors [`crate::packets::CarveTarget::Scope`] one-to-one so the
/// UI and CLI can carve it without re-deriving anything.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PacketScope {
    pub host: String,
    /// Restrict to frames between `host` and this peer. `#[serde(default)]`.
    #[serde(default)]
    pub peer: Option<String>,
    /// Restrict to frames with this port on either side. `#[serde(default)]`.
    #[serde(default)]
    pub port: Option<u16>,
    pub start_ns: i64,
    pub end_ns: i64,
}

impl PacketScope {
    /// The scope as a capture filter (tcpdump / Wireshark capture-filter syntax), for pulling the
    /// same packets with any tool. The time window is not expressible in BPF; pair it with
    /// `start_ns..end_ns`.
    pub fn bpf(&self) -> String {
        let mut f = format!("host {}", self.host);
        if let Some(p) = &self.peer {
            f.push_str(&format!(" and host {p}"));
        }
        if let Some(port) = self.port {
            f.push_str(&format!(" and port {port}"));
        }
        f
    }
}

/// One row of an [`AlertTimeline`].
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TimelineEvent {
    /// When it happened (ns since the capture epoch); `None` sorts last (an untimed detection).
    pub ts_ns: Option<i64>,
    /// When it stopped, for rows that span time (a beacon, an exfil). `#[serde(default)]`.
    #[serde(default)]
    pub end_ns: Option<i64>,
    pub kind: TimelineEventKind,
    /// The host this row belongs to (its lane in the swimlane rendering).
    pub host: String,
    /// The other endpoint, when the row names one. `#[serde(default)]`.
    #[serde(default)]
    pub peer: Option<String>,
    /// The service port, when the row names one. `#[serde(default)]`.
    #[serde(default)]
    pub dst_port: Option<u16>,
    /// One-line description (escaped only at render time).
    pub title: String,
    /// A supporting detail (an evidence bullet, the full hash). `#[serde(default)]`.
    #[serde(default)]
    pub detail: Option<String>,
    pub severity: Severity,
    /// Kill-chain stage label for detections and hops. `#[serde(default)]`.
    #[serde(default)]
    pub tactic: Option<String>,
    /// ATT&CK technique ids. `#[serde(default)]`.
    #[serde(default)]
    pub attack: Vec<String>,
    /// Back-ref into `Summary.findings` for detection / hop rows. `#[serde(default)]`.
    #[serde(default)]
    pub finding_index: Option<u32>,
    /// The packets behind this row; `None` only when `host` is not an IP address.
    #[serde(default)]
    pub packets: Option<PacketScope>,
}

/// One alert's chronological, cross-host story.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AlertTimeline {
    /// Back-ref to `Alert.id`.
    pub alert_id: String,
    /// The alert's headline.
    pub title: String,
    /// Distinct hosts with at least one row, in first-row order.
    pub hosts: Vec<String>,
    /// Earliest timed row (ns); `None` if nothing is timed.
    pub first_ts_ns: Option<i64>,
    /// Latest timed row end (ns); `None` if nothing is timed.
    pub last_ts_ns: Option<i64>,
    /// Rows in time order (untimed last), capped.
    pub events: Vec<TimelineEvent>,
    /// Rows before the cap (`>= events.len()`).
    pub event_count: u32,
}

/// A DNS answer that mapped `ip` from `domain`, first seen at `first_seen_ns`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DnsAnswer {
    pub ip: String,
    pub domain: String,
    /// The host the first answer was delivered to. `#[serde(default)]`.
    #[serde(default)]
    pub client: Option<String>,
    pub first_seen_ns: i64,
}

/// The earliest flow observed between two endpoints.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FirstContact {
    /// The endpoint that opened the first flow.
    pub initiator: String,
    pub responder: String,
    /// The responder's port on that flow (`None` for portless transports). `#[serde(default)]`.
    #[serde(default)]
    pub port: Option<u16>,
    pub first_seen_ns: i64,
}

/// Timestamped context recorded by the streaming pass for the endpoints the findings name, so the
/// timeline can be re-derived from a saved summary without the capture.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TimelineContext {
    /// Ascending by `ip`. `#[serde(default)]`.
    #[serde(default)]
    pub dns_answers: Vec<DnsAnswer>,
    /// Ascending by `(initiator, responder)`. `#[serde(default)]`.
    #[serde(default)]
    pub first_contacts: Vec<FirstContact>,
}

impl TimelineContext {
    pub fn is_empty(&self) -> bool {
        self.dns_answers.is_empty() && self.first_contacts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_ord_is_tie_break_order() {
        assert!(TimelineEventKind::FirstContact < TimelineEventKind::DnsAnswer);
        assert!(TimelineEventKind::Pivot < TimelineEventKind::Detection);
        for k in [
            TimelineEventKind::FirstContact,
            TimelineEventKind::DnsAnswer,
            TimelineEventKind::Pivot,
            TimelineEventKind::FileDownload,
            TimelineEventKind::Detection,
        ] {
            assert_eq!(
                serde_json::to_string(&k).unwrap(),
                format!("\"{}\"", k.as_str())
            );
        }
    }

    #[test]
    fn bpf_names_every_narrowing() {
        let mut p = PacketScope {
            host: "10.0.0.7".into(),
            peer: None,
            port: None,
            start_ns: 0,
            end_ns: 1,
        };
        assert_eq!(p.bpf(), "host 10.0.0.7");
        p.peer = Some("45.77.13.37".into());
        p.port = Some(443);
        assert_eq!(p.bpf(), "host 10.0.0.7 and host 45.77.13.37 and port 443");
    }

    #[test]
    fn old_summaries_without_timelines_still_parse() {
        let out = crate::model::output::AnalysisOutput::default();
        let v = serde_json::to_value(&out).unwrap();
        // Empty context + timelines are skipped on the wire...
        assert!(v["summary"].get("timelines").is_none());
        assert!(v["summary"].get("timeline_context").is_none());
        // ...and their absence deserializes back to empty.
        let back: crate::model::output::AnalysisOutput = serde_json::from_value(v).unwrap();
        assert!(back.summary.timelines.is_empty());
        assert!(back.summary.timeline_context.is_empty());
    }
}
