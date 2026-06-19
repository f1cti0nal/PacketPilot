//! The capture-wide summary and its sub-structs. Fully implemented contract type.
//!
//! [`Summary`] is the headline JSON object. It is bounded-memory derived by the
//! `stats` stage and carries both the human-facing rollups (top talkers, histograms,
//! category breakdown) and the bench/golden fidelity counters ([`ProtoCounts`],
//! `non_ip_frames`). Field aliases required by the bench contract are documented inline.

use crate::enrich::IpClass;
use crate::model::category::Category;
use crate::model::finding::Finding;
use crate::model::incident::Incident;
use crate::model::severity::Severity;

/// Protocol-fidelity tallies the bench/golden contract asserts against the generator
/// manifest. Every decoded frame increments exactly one of the protocol buckets plus the
/// relevant L4 path; `truncated`/`non_ipv4` capture the edge cases.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProtoCounts {
    pub tcp: u64,
    pub udp: u64,
    pub dns: u64,
    pub http: u64,
    pub tls: u64,
    pub other_tcp: u64,
    pub other_udp: u64,
    /// Decode-truncated frames.
    pub truncated: u64,
    /// ARP / non-IPv4 frames.
    pub non_ipv4: u64,
}

/// One top-talker row (an IP endpoint with its rolled-up traffic).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TopTalker {
    pub ip: String,
    pub pkts: u64,
    pub bytes: u64,
    pub flows: u64,
}

/// One node in the protocol hierarchy, keyed by a dotted path (e.g. `"ip.tcp.https"`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProtoCount {
    pub path: String,
    pub pkts: u64,
    pub bytes: u64,
}

/// One port-histogram row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PortCount {
    pub port: u16,
    pub transport: String,
    pub pkts: u64,
    pub bytes: u64,
}

/// One per-second time bucket.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TimeBucket {
    pub epoch_sec: i64,
    pub pkts: u64,
    pub bytes: u64,
}

/// One category-breakdown row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CategoryCount {
    pub category: Category,
    pub flows: u64,
    pub pkts: u64,
    pub bytes: u64,
}

/// Flow counts partitioned by [`Severity`] band.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SeverityCounts {
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub info: u64,
}

impl SeverityCounts {
    /// Total flows counted across all bands.
    pub fn total(&self) -> u64 {
        self.critical + self.high + self.medium + self.low + self.info
    }

    /// Increment the bucket for `s`.
    pub fn bump(&mut self, s: Severity) {
        match s {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
    }
}

/// One per-IP threat rollup row (the worst verdict seen across that IP's flows).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IpThreat {
    pub ip: String,
    pub ip_class: IpClass,
    /// Representative (max) severity across this IP's flows.
    pub severity: Severity,
    /// Representative (max) threat_score across this IP's flows.
    pub score: u16,
    pub flows: u64,
    pub bytes: u64,
    pub ioc: bool,
    /// `["public"|"internal"]`, plus `"ioc"` if any flow matched the feed.
    pub tags: Vec<String>,
    /// Sorted union of ATT&CK ids across this IP's flows.
    pub attack: Vec<String>,
    /// Capped, deduped union of flow evidence strings.
    pub evidence: Vec<String>,
}

/// Capture-wide summary. The headline JSON object. Bounded-memory derived.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Summary {
    pub total_packets: u64,
    /// Sum of wire_len (alias for bench "total_wire_bytes").
    pub total_bytes: u64,
    /// Sum of cap_len.
    pub captured_bytes: u64,
    /// Alias for bench "distinct_flows".
    pub total_flows: u64,
    pub decode_errors: u64,
    /// ARP / non-IP count (bench invariant).
    pub non_ip_frames: u64,
    /// Bench protocol-fidelity contract.
    pub proto: ProtoCounts,
    pub first_ts_ns: Option<i64>,
    pub last_ts_ns: Option<i64>,
    /// 0 if fewer than 2 packets.
    pub duration_ns: i64,
    pub unique_hosts: u64,
    /// len <= top_k_talkers, desc by bytes.
    pub top_talkers: Vec<TopTalker>,
    /// desc by bytes.
    pub protocol_hierarchy: Vec<ProtoCount>,
    /// len <= top_k_ports, desc by pkts.
    pub port_histogram: Vec<PortCount>,
    /// ascending epoch_sec, gaps omitted (per-second).
    pub time_histogram: Vec<TimeBucket>,
    /// fixed `Category::all()` order, covers all flows.
    pub category_breakdown: Vec<CategoryCount>,
    /// Flow counts per severity band.
    pub severity_counts: SeverityCounts,
    /// desc by score; len <= top_k_ip_threats.
    pub ip_threats: Vec<IpThreat>,
    /// Cross-flow behavioral findings (beaconing, sweeps, exfil) from the `detect` stage.
    /// `#[serde(default)]` keeps older summaries (written before this field existed) readable.
    #[serde(default)]
    pub findings: Vec<Finding>,
    /// Findings correlated into per-host incidents (kill-chain ordered). `#[serde(default)]`
    /// keeps older summaries readable.
    #[serde(default)]
    pub incidents: Vec<Incident>,
}

impl Summary {
    /// An all-zero summary for empty captures.
    pub fn empty() -> Summary {
        Summary {
            total_packets: 0,
            total_bytes: 0,
            captured_bytes: 0,
            total_flows: 0,
            decode_errors: 0,
            non_ip_frames: 0,
            proto: ProtoCounts::default(),
            first_ts_ns: None,
            last_ts_ns: None,
            duration_ns: 0,
            unique_hosts: 0,
            top_talkers: Vec::new(),
            protocol_hierarchy: Vec::new(),
            port_histogram: Vec::new(),
            time_histogram: Vec::new(),
            category_breakdown: Vec::new(),
            severity_counts: SeverityCounts::default(),
            ip_threats: Vec::new(),
            findings: Vec::new(),
            incidents: Vec::new(),
        }
    }

    /// Capture start in ns, defaulting to 0 when no packets were seen.
    pub fn capture_start_ns(&self) -> i64 {
        self.first_ts_ns.unwrap_or(0)
    }

    /// Capture end in ns, defaulting to 0 when no packets were seen.
    pub fn capture_end_ns(&self) -> i64 {
        self.last_ts_ns.unwrap_or(0)
    }
}
