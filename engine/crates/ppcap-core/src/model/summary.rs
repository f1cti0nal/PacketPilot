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

/// One time-histogram bucket. `epoch_sec` is the bucket's start (Unix seconds, aligned to a
/// multiple of the summary's [`Summary::time_bucket_secs`] width); `pkts`/`bytes` are the
/// totals that fell inside the `[epoch_sec, epoch_sec + width)` window.
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

/// A malware TLS fingerprint matched on this IP's flows (the IOC-matched subset;
/// display-only). Deduped and capped per-IP.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FingerprintHit {
    #[serde(default)]
    pub ja3: Option<String>,
    #[serde(default)]
    pub ja4: Option<String>,
    pub label: String,
}

/// One additive scoring contribution (label + signed points). Mirrors the `(±N)` evidence string.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScoreTerm {
    pub label: String,
    pub points: i32,
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
    /// Per-provider online reputation verdicts (empty unless the reputation pass ran).
    /// `#[serde(default)]` keeps older summaries (written before this field) readable.
    #[serde(default)]
    pub reputation: Vec<crate::enrich::ReputationVerdict>,
    /// Matched malware TLS fingerprints (IOC-matched subset only; deduped + capped).
    /// `#[serde(default)]` keeps older summaries readable.
    #[serde(default)]
    pub fingerprints: Vec<FingerprintHit>,
    /// Additive scoring terms from the IP's worst (representative) flow. Mirrors the
    /// per-term `(±N)` evidence strings; useful for structured score explanation.
    /// `#[serde(default)]` keeps older summaries readable.
    #[serde(default)]
    pub score_terms: Vec<ScoreTerm>,
}

/// One per-domain (TLS SNI host) rollup row, ranked by traffic. A display surface — not
/// severity-scored. `reputation` is empty unless the (opt-in) domain reputation pass ran.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DomainThreat {
    pub host: String,
    pub flows: u64,
    pub bytes: u64,
    /// Per-provider domain reputation verdicts (VirusTotal). Empty unless the pass ran.
    #[serde(default)]
    pub reputation: Vec<crate::enrich::ReputationVerdict>,
}

/// One HTTP host rollup row: a request `Host` and the number of flows that carried it. Ranked by
/// flow count — a display surface for the capture's web destinations.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HttpHostCount {
    pub host: String,
    pub flows: u64,
}

/// One HTTP User-Agent rollup row: a request `User-Agent` and the number of flows that carried it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UserAgentCount {
    pub user_agent: String,
    pub flows: u64,
}

/// One passive-DNS rollup row: a resolved IP and the domain a DNS `A`/`AAAA` answer mapped it from,
/// with how many response packets carried that mapping. Lets a later flow to that IP be attributed
/// back to the domain it came from.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedDomain {
    pub ip: String,
    pub domain: String,
    pub resolutions: u64,
}

/// One L2 host rollup row: an IP and the MAC address that claimed it via ARP (`aa:bb:cc:dd:ee:ff`).
/// The OUI (first three bytes) identifies the device vendor — surfaced as L2 asset identity.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArpHost {
    pub ip: String,
    pub mac: String,
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
    /// Activity timeline: ascending `epoch_sec`, empty buckets omitted. Bounded to
    /// `stats.max_time_buckets` buckets via an adaptive [`time_bucket_secs`](Self::time_bucket_secs)
    /// width, so the series stays small (and the report sparkline readable) for any capture
    /// length. Σ `pkts` still equals `total_packets` (re-bucketing only re-groups).
    pub time_histogram: Vec<TimeBucket>,
    /// Width, in seconds, of each [`time_histogram`](Self::time_histogram) bucket (>= 1). 1 for
    /// short captures (per-second), widening to a "nice" interval (2/5/.../min/hour/day) as the
    /// capture lengthens. `#[serde(default)]` -> 1 keeps older (per-second) summaries readable.
    #[serde(default = "default_time_bucket_secs")]
    pub time_bucket_secs: i64,
    /// fixed `Category::all()` order, covers all flows.
    pub category_breakdown: Vec<CategoryCount>,
    /// Flow counts per severity band.
    pub severity_counts: SeverityCounts,
    /// desc by score; len <= top_k_ip_threats.
    pub ip_threats: Vec<IpThreat>,
    /// Top TLS SNI hosts by traffic. `#[serde(default)]` keeps older summaries readable.
    #[serde(default)]
    pub domain_threats: Vec<DomainThreat>,
    /// Top HTTP request `Host` headers by flow count. `#[serde(default)]` keeps older summaries
    /// readable.
    #[serde(default)]
    pub http_hosts: Vec<HttpHostCount>,
    /// Top HTTP request `User-Agent` headers by flow count. `#[serde(default)]` keeps older
    /// summaries readable.
    #[serde(default)]
    pub user_agents: Vec<UserAgentCount>,
    /// Passive DNS: resolved-IP → domain mappings from DNS answers, ranked by resolution count.
    /// `#[serde(default)]` keeps older summaries readable.
    #[serde(default)]
    pub resolved_ips: Vec<ResolvedDomain>,
    /// L2 host identity: IP → MAC bindings observed via ARP. `#[serde(default)]` keeps older
    /// summaries readable.
    #[serde(default)]
    pub arp_hosts: Vec<ArpHost>,
    /// Cross-flow behavioral findings (beaconing, sweeps, exfil) from the `detect` stage.
    /// `#[serde(default)]` keeps older summaries (written before this field existed) readable.
    #[serde(default)]
    pub findings: Vec<Finding>,
    /// Findings correlated into per-host incidents (kill-chain ordered). `#[serde(default)]`
    /// keeps older summaries readable.
    #[serde(default)]
    pub incidents: Vec<Incident>,
}

/// Serde fallback for [`Summary::time_bucket_secs`] on summaries written before the field
/// existed: those used a fixed per-second histogram, so 1 is the faithful interpretation.
fn default_time_bucket_secs() -> i64 {
    1
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
            time_bucket_secs: 1,
            category_breakdown: Vec::new(),
            severity_counts: SeverityCounts::default(),
            ip_threats: Vec::new(),
            domain_threats: Vec::new(),
            http_hosts: Vec::new(),
            user_agents: Vec::new(),
            resolved_ips: Vec::new(),
            arp_hosts: Vec::new(),
            findings: Vec::new(),
            incidents: Vec::new(),
        }
    }

    /// Merge post-hoc [`Finding`]s (e.g. from an imported ruleset) into the per-IP threat
    /// rollups so rule matches elevate the implicated hosts' threat cards. Both endpoints of a
    /// finding are uplifted; an already-higher card is never lowered (raise-only, mirrors the
    /// `StatsAccumulator::apply_findings` invariant used during the streaming pass). Only IPs
    /// already present in `ip_threats` are touched — no new rows are created.
    pub fn apply_findings(&mut self, findings: &[Finding]) {
        // Matches the streaming pass's default `max_evidence_per_ip` so the rules pass cannot
        // push a card past the cap the streaming-built cards were held to.
        const MAX_EVIDENCE: usize = 6;
        for f in findings {
            for ip_str in std::iter::once(f.src_ip.as_str()).chain(f.dst_ip.as_deref()) {
                let Some(card) = self.ip_threats.iter_mut().find(|c| c.ip == ip_str) else {
                    continue;
                };
                // Raise score/severity (never lower).
                if f.severity > card.severity
                    || (f.severity == card.severity && f.score > card.score)
                {
                    card.severity = f.severity;
                    card.score = f.score;
                    card.evidence.clear();
                }
                // Merge ATT&CK ids (deduped, sorted).
                for atk in &f.attack {
                    if !card.attack.contains(atk) {
                        card.attack.push(atk.clone());
                    }
                }
                card.attack.sort();
                // Append evidence (capped, deduped).
                for ev in &f.evidence {
                    if card.evidence.len() < MAX_EVIDENCE && !card.evidence.contains(ev) {
                        card.evidence.push(ev.clone());
                    }
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipthreat_reputation_defaults_empty_on_old_json() {
        // An older summary row written before the field existed must still deserialize.
        let json = r#"{"ip":"203.0.113.7","ip_class":"public","severity":"low","score":20,
            "flows":3,"bytes":1000,"ioc":false,"tags":["public"],"attack":[],"evidence":[]}"#;
        let row: IpThreat = serde_json::from_str(json).unwrap();
        assert!(row.reputation.is_empty());
    }

    #[test]
    fn ip_threat_score_terms_defaults_empty_on_old_json() {
        // An older summary row written before score_terms existed must still deserialize.
        let json = r#"{"ip":"203.0.113.7","ip_class":"public","severity":"low","score":20,"flows":3,"bytes":1000,"ioc":false,"tags":["public"],"attack":[],"evidence":[]}"#;
        let row: IpThreat = serde_json::from_str(json).unwrap();
        assert!(row.score_terms.is_empty());
    }

    #[test]
    fn apply_findings_uplifts_endpoints_raise_only() {
        use crate::model::finding::{Finding, FindingKind};
        use crate::model::severity::Severity;

        // Two cards: a low one (uplift target) + an already-critical one (must not be lowered).
        let low: IpThreat = serde_json::from_str(
            r#"{"ip":"203.0.113.7","ip_class":"public","severity":"low","score":20,
                "flows":3,"bytes":1000,"ioc":false,"tags":["public"],"attack":[],"evidence":[]}"#,
        )
        .unwrap();
        let crit: IpThreat = serde_json::from_str(
            r#"{"ip":"198.51.100.9","ip_class":"public","severity":"critical","score":95,
                "flows":5,"bytes":2000,"ioc":true,"tags":["public"],"attack":["T1041"],"evidence":[]}"#,
        )
        .unwrap();

        let mut s = crate::model::output::AnalysisOutput::default().summary;
        s.ip_threats = vec![low, crit];

        let f = Finding {
            kind: FindingKind::RuleMatch,
            severity: Severity::High,
            score: 70,
            title: "sig hit".into(),
            src_ip: "203.0.113.7".into(),
            dst_ip: Some("198.51.100.9".into()),
            dst_port: Some(443),
            attack: vec!["T1071".into()],
            evidence: vec!["rule sid:5".into()],
            interval_ns: None,
            jitter_cv: None,
            contacts: None,
        };
        s.apply_findings(std::slice::from_ref(&f));

        // src card (low) uplifted to High/70 with the rule's evidence + ATT&CK.
        let src = s.ip_threats.iter().find(|c| c.ip == "203.0.113.7").unwrap();
        assert_eq!(src.severity, Severity::High);
        assert_eq!(src.score, 70);
        assert!(src.attack.contains(&"T1071".to_string()));
        assert!(src.evidence.iter().any(|e| e.contains("sid:5")));

        // dst card (critical) is NOT lowered to High; it merges the ATT&CK id only.
        let dst = s
            .ip_threats
            .iter()
            .find(|c| c.ip == "198.51.100.9")
            .unwrap();
        assert_eq!(dst.severity, Severity::Critical);
        assert_eq!(dst.score, 95);
        assert!(dst.attack.contains(&"T1071".to_string()));

        // No new rows created for an IP absent from ip_threats.
        let g = Finding {
            src_ip: "10.0.0.1".into(),
            dst_ip: None,
            ..f.clone()
        };
        s.apply_findings(std::slice::from_ref(&g));
        assert_eq!(s.ip_threats.len(), 2);
    }

    #[test]
    fn domain_threats_serde_roundtrip_and_default() {
        let dt = DomainThreat {
            host: "a.example".into(),
            flows: 3,
            bytes: 99,
            reputation: vec![],
        };
        let j = serde_json::to_string(&dt).unwrap();
        assert_eq!(serde_json::from_str::<DomainThreat>(&j).unwrap(), dt);

        // Old summaries (no domain_threats key) still deserialize → empty.
        let out = crate::model::output::AnalysisOutput::default();
        let mut v = serde_json::to_value(&out).unwrap();
        v["summary"]
            .as_object_mut()
            .unwrap()
            .remove("domain_threats");
        let back: crate::model::output::AnalysisOutput = serde_json::from_value(v).unwrap();
        assert!(back.summary.domain_threats.is_empty());
    }
}
