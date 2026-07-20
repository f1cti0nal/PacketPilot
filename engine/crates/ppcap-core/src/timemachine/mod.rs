//! Time Machine — retrospective re-scan of saved captures against updated threat intel.
//!
//! An analyst keeps captures around. When a threat feed later learns that an IP,
//! domain, or TLS fingerprint is malicious, the interesting question is: *did any
//! capture I already cleared actually talk to it?* Time Machine answers that
//! **without re-streaming the pcap**: at analysis time it distills a capture into a
//! compact [`CaptureIndex`] of its network indicators, and later [`rescan`]
//! re-evaluates those indicators against an updated [`ThreatFeed`], surfacing the
//! ones that were clean before but are dirty now.
//!
//! This is the local-first, no-backend core of the feature: everything is a pure
//! transform over a small JSON sidecar and an offline feed — same privacy and
//! bounded-memory discipline as the rest of the engine. Scheduling, feed
//! subscriptions, and a shared case store are deliberately out of scope here.
//!
//! Scope note: the index carries the indicator classes the offline [`ThreatFeed`]
//! can match — IPs, domains (SNI + passive DNS), and JA3/JA4 fingerprints. File
//! hashes are captured for provenance but not re-matched (the feed has no hash
//! set); that's a documented future extension.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::enrich::ThreatFeed;
use crate::model::output::AnalysisOutput;

/// On-disk schema version for the capture index.
pub const INDEX_SCHEMA_VERSION: u32 = 1;

/// The class of a re-scannable indicator. Lowercase serde tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndicatorKind {
    /// An external IP address (v4/v6).
    Ip,
    /// A domain / TLS SNI host / passive-DNS name.
    Domain,
    /// A JA3 TLS client fingerprint (md5 hex).
    Ja3,
    /// A JA4 TLS client fingerprint.
    Ja4,
}

impl IndicatorKind {
    /// Stable display token.
    pub fn as_str(self) -> &'static str {
        match self {
            IndicatorKind::Ip => "ip",
            IndicatorKind::Domain => "domain",
            IndicatorKind::Ja3 => "ja3",
            IndicatorKind::Ja4 => "ja4",
        }
    }
}

/// One distinct indicator observed in a capture, plus whether it was already
/// flagged (IOC / malicious-reputation) *at analysis time*. The `flagged`
/// bit is what lets a rescan distinguish a *newly*-dirty indicator from one that
/// was already known bad when the capture was first analyzed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Indicator {
    pub kind: IndicatorKind,
    pub value: String,
    #[serde(default)]
    pub flagged_at_capture: bool,
}

/// A compact, re-scannable distillation of one analyzed capture. Contains only
/// derived indicators + provenance — no packets, no payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureIndex {
    pub schema_version: u32,
    /// `env!("CARGO_PKG_VERSION")` of the engine that wrote the index.
    pub engine_version: String,
    pub source_path: String,
    /// SHA-256 of the source capture, if it was computed (`analyze --hash`).
    pub source_sha256: Option<String>,
    /// When the capture was analyzed (unix seconds); `0` if the caller had no clock.
    pub analyzed_unix_secs: i64,
    /// Capture time span (ns since epoch) — lets a rescan report *when* the contact
    /// happened, not just that it did.
    pub first_ts_ns: i64,
    pub last_ts_ns: i64,
    /// Distinct indicators, sorted (kind, value) for stable diffs.
    pub indicators: Vec<Indicator>,
}

impl CaptureIndex {
    /// Serialize as pretty JSON.
    pub fn to_json_pretty(&self) -> crate::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse a capture index from JSON.
    pub fn from_json_str(s: &str) -> crate::Result<CaptureIndex> {
        Ok(serde_json::from_str(s)?)
    }
}

/// True if any reputation verdict marks the subject malicious.
fn rep_malicious(reps: &[crate::enrich::ReputationVerdict]) -> bool {
    reps.iter().any(|r| r.malicious)
}

/// Build a [`CaptureIndex`] from a completed analysis. Collects the feed-matchable
/// indicators (IPs, domains, JA3/JA4) and records, per indicator, whether it was
/// already flagged at analysis time (IOC hit or malicious reputation).
///
/// `analyzed_unix_secs` is the wall-clock analysis time (0 when unavailable).
pub fn build_index(out: &AnalysisOutput, analyzed_unix_secs: i64) -> CaptureIndex {
    let s = &out.summary;

    // Accumulate into maps so a value seen both clean and flagged records "flagged".
    // (kind, value) -> flagged. BTreeSet-of-key would lose the flag; use a small vec+sort.
    use std::collections::BTreeMap;
    let mut acc: BTreeMap<(IndicatorKind, String), bool> = BTreeMap::new();
    let add = |acc: &mut BTreeMap<(IndicatorKind, String), bool>,
               kind: IndicatorKind,
               value: String,
               flagged: bool| {
        if value.is_empty() {
            return;
        }
        let e = acc.entry((kind, value)).or_insert(false);
        *e = *e || flagged;
    };

    // Per-IP threat rollups: the authoritative external-IP set + the `ioc` flag.
    for t in &s.ip_threats {
        let flagged = t.ioc || rep_malicious(&t.reputation);
        add(&mut acc, IndicatorKind::Ip, t.ip.clone(), flagged);
        // Fingerprints observed on this IP; flagged if the IP itself was an IOC.
        for fp in &t.fingerprints {
            if let Some(j) = fp.ja3.as_ref().filter(|v| !v.is_empty()) {
                add(&mut acc, IndicatorKind::Ja3, j.clone(), flagged);
            }
            if let Some(j) = fp.ja4.as_ref().filter(|v| !v.is_empty()) {
                add(&mut acc, IndicatorKind::Ja4, j.clone(), flagged);
            }
        }
    }

    // TLS SNI hosts.
    for d in &s.domain_threats {
        add(
            &mut acc,
            IndicatorKind::Domain,
            d.host.clone(),
            rep_malicious(&d.reputation),
        );
    }

    // Passive-DNS names (and the IPs they resolved to). A later feed listing either
    // the domain or the resolved IP is exactly the retrospective signal we want.
    for r in &s.resolved_ips {
        add(&mut acc, IndicatorKind::Domain, r.domain.clone(), false);
        add(&mut acc, IndicatorKind::Ip, r.ip.clone(), false);
    }

    let indicators = acc
        .into_iter()
        .map(|((kind, value), flagged_at_capture)| Indicator {
            kind,
            value,
            flagged_at_capture,
        })
        .collect();

    CaptureIndex {
        schema_version: INDEX_SCHEMA_VERSION,
        engine_version: out.engine_version.clone(),
        source_path: out.source_path.clone(),
        source_sha256: out.source_sha256.clone(),
        analyzed_unix_secs,
        first_ts_ns: s.first_ts_ns.unwrap_or(0),
        last_ts_ns: s.last_ts_ns.unwrap_or(0),
        indicators,
    }
}

/// One indicator that a rescan found to match the updated feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RescanHit {
    pub source_path: String,
    pub source_sha256: Option<String>,
    /// Original analysis time (unix seconds) — "this capture from <when> matches now".
    pub analyzed_unix_secs: i64,
    /// Capture span, so the analyst can pivot to the exact window.
    pub first_ts_ns: i64,
    pub last_ts_ns: i64,
    pub kind: IndicatorKind,
    pub value: String,
    /// Feed family/label for the match, when the feed provides one (fingerprints).
    pub label: Option<String>,
    /// True when this indicator was ALREADY flagged at analysis time (i.e. the feed
    /// knew it then too) — informational; `newly_flagged` excludes these.
    pub was_flagged_at_capture: bool,
}

/// The result of a retrospective rescan across one or more capture indices.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RescanReport {
    /// Indicators that are dirty in the updated feed but were clean at capture time —
    /// the actionable "time machine" alerts.
    pub newly_flagged: Vec<RescanHit>,
    /// Indicators dirty now that were also flagged at capture time (already known).
    pub still_flagged: Vec<RescanHit>,
    /// How many capture indices were scanned.
    pub indices_scanned: usize,
    /// How many distinct indicators were evaluated across all indices.
    pub indicators_evaluated: usize,
}

/// Does the updated feed match this indicator now? Returns `(matched, label)`.
fn feed_matches(feed: &ThreatFeed, ind: &Indicator) -> (bool, Option<String>) {
    match ind.kind {
        IndicatorKind::Ip => match ind.value.parse() {
            Ok(ip) => (feed.matches_ip(ip), None),
            Err(_) => (false, None),
        },
        IndicatorKind::Domain => (feed.matches_domain(&ind.value), None),
        IndicatorKind::Ja3 => (
            feed.matches_ja3(&ind.value),
            feed.fingerprint_label(Some(&ind.value), None),
        ),
        IndicatorKind::Ja4 => (
            feed.matches_ja4(&ind.value),
            feed.fingerprint_label(None, Some(&ind.value)),
        ),
    }
}

/// Re-evaluate every indicator in `indices` against the updated `feed`. Indicators
/// that match now split into `newly_flagged` (were clean at capture) and
/// `still_flagged` (were already known bad). Pure and offline.
pub fn rescan(indices: &[CaptureIndex], feed: &ThreatFeed) -> RescanReport {
    let mut report = RescanReport {
        indices_scanned: indices.len(),
        ..Default::default()
    };
    for idx in indices {
        report.indicators_evaluated += idx.indicators.len();
        for ind in &idx.indicators {
            let (matched, label) = feed_matches(feed, ind);
            if !matched {
                continue;
            }
            let hit = RescanHit {
                source_path: idx.source_path.clone(),
                source_sha256: idx.source_sha256.clone(),
                analyzed_unix_secs: idx.analyzed_unix_secs,
                first_ts_ns: idx.first_ts_ns,
                last_ts_ns: idx.last_ts_ns,
                kind: ind.kind,
                value: ind.value.clone(),
                label,
                was_flagged_at_capture: ind.flagged_at_capture,
            };
            if ind.flagged_at_capture {
                report.still_flagged.push(hit);
            } else {
                report.newly_flagged.push(hit);
            }
        }
    }
    report
}

/// Convenience: the set of distinct indicator values of one kind (used by callers
/// that want to cross-reference, and by tests).
pub fn distinct_values(idx: &CaptureIndex, kind: IndicatorKind) -> BTreeSet<String> {
    idx.indicators
        .iter()
        .filter(|i| i.kind == kind)
        .map(|i| i.value.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::ThreatFeed;
    use crate::model::summary::{DomainThreat, FingerprintHit, IpThreat, ResolvedDomain};

    fn ip_threat(ip: &str, ioc: bool, ja3: Option<&str>) -> IpThreat {
        IpThreat {
            ip: ip.to_string(),
            ip_class: crate::enrich::IpClass::Public,
            severity: crate::model::severity::Severity::Info,
            score: 0,
            flows: 1,
            bytes: 100,
            ioc,
            tags: vec![],
            attack: vec![],
            evidence: vec![],
            reputation: vec![],
            fingerprints: ja3
                .map(|j| {
                    vec![FingerprintHit {
                        ja3: Some(j.to_string()),
                        ja4: None,
                        label: "test".to_string(),
                    }]
                })
                .unwrap_or_default(),
            score_terms: vec![],
        }
    }

    fn sample_output() -> AnalysisOutput {
        let mut out = AnalysisOutput {
            engine_version: "test".to_string(),
            source_path: "cap.pcap".to_string(),
            source_sha256: Some("abc".to_string()),
            ..Default::default()
        };
        out.summary.first_ts_ns = Some(1_700_000_000_000_000_000);
        out.summary.last_ts_ns = Some(1_700_000_100_000_000_000);
        out.summary.ip_threats = vec![
            ip_threat(
                "203.0.113.5",
                false,
                Some("aaaa1111bbbb2222cccc3333dddd4444"),
            ),
            ip_threat("198.51.100.9", true, None), // already an IOC at capture
        ];
        out.summary.domain_threats = vec![DomainThreat {
            host: "cdn.example.com".to_string(),
            flows: 2,
            bytes: 200,
            reputation: vec![],
        }];
        out.summary.resolved_ips = vec![ResolvedDomain {
            ip: "203.0.113.5".to_string(),
            domain: "later-bad.example".to_string(),
            resolutions: 1,
        }];
        out
    }

    fn feed_with(json: &str) -> ThreatFeed {
        ThreatFeed::from_json_str(json).unwrap()
    }

    #[test]
    fn build_index_collects_and_flags() {
        let idx = build_index(&sample_output(), 1_752_000_000);
        assert_eq!(idx.schema_version, INDEX_SCHEMA_VERSION);
        assert_eq!(idx.source_path, "cap.pcap");
        // IPs from ip_threats + resolved_ips (deduped).
        let ips = distinct_values(&idx, IndicatorKind::Ip);
        assert!(ips.contains("203.0.113.5"));
        assert!(ips.contains("198.51.100.9"));
        // Domains from domain_threats + passive DNS.
        let domains = distinct_values(&idx, IndicatorKind::Domain);
        assert!(domains.contains("cdn.example.com"));
        assert!(domains.contains("later-bad.example"));
        // JA3 captured.
        assert!(
            distinct_values(&idx, IndicatorKind::Ja3).contains("aaaa1111bbbb2222cccc3333dddd4444")
        );
        // The IOC IP is flagged; the clean one is not.
        let flagged: std::collections::HashMap<_, _> = idx
            .indicators
            .iter()
            .map(|i| ((i.kind, i.value.as_str()), i.flagged_at_capture))
            .collect();
        assert!(flagged[&(IndicatorKind::Ip, "198.51.100.9")]);
        assert!(!flagged[&(IndicatorKind::Ip, "203.0.113.5")]);
    }

    #[test]
    fn index_json_roundtrips() {
        let idx = build_index(&sample_output(), 42);
        let json = idx.to_json_pretty().unwrap();
        let back = CaptureIndex::from_json_str(&json).unwrap();
        assert_eq!(idx, back);
    }

    #[test]
    fn rescan_detects_newly_dirty_ip() {
        let idx = build_index(&sample_output(), 1_752_000_000);
        // A feed that NOW lists the previously-clean 203.0.113.5.
        let feed = feed_with(r#"{"bad_ips":["203.0.113.5"]}"#);
        let report = rescan(&[idx], &feed);
        assert_eq!(report.indices_scanned, 1);
        assert!(report.indicators_evaluated > 0);
        // 203.0.113.5 was clean at capture → newly flagged.
        assert!(report
            .newly_flagged
            .iter()
            .any(|h| h.kind == IndicatorKind::Ip && h.value == "203.0.113.5"));
        // Its provenance is carried through.
        let hit = report
            .newly_flagged
            .iter()
            .find(|h| h.value == "203.0.113.5")
            .unwrap();
        assert_eq!(hit.source_path, "cap.pcap");
        assert_eq!(hit.analyzed_unix_secs, 1_752_000_000);
    }

    #[test]
    fn rescan_excludes_already_flagged() {
        let idx = build_index(&sample_output(), 1);
        // Feed lists the IP that was ALREADY an IOC at capture.
        let feed = feed_with(r#"{"bad_ips":["198.51.100.9"]}"#);
        let report = rescan(&[idx], &feed);
        // It matches, but as "still flagged", not "newly".
        assert!(report.newly_flagged.is_empty());
        assert!(report
            .still_flagged
            .iter()
            .any(|h| h.value == "198.51.100.9"));
    }

    #[test]
    fn rescan_matches_domain_and_passive_dns() {
        let idx = build_index(&sample_output(), 1);
        let feed = feed_with(r#"{"bad_domains":["later-bad.example"]}"#);
        let report = rescan(&[idx], &feed);
        assert!(report
            .newly_flagged
            .iter()
            .any(|h| h.kind == IndicatorKind::Domain && h.value == "later-bad.example"));
    }

    #[test]
    fn rescan_matches_ja3_with_label() {
        let idx = build_index(&sample_output(), 1);
        let feed = feed_with(r#"{"bad_ja3":["aaaa1111bbbb2222cccc3333dddd4444"]}"#);
        let report = rescan(&[idx], &feed);
        let hit = report
            .newly_flagged
            .iter()
            .find(|h| h.kind == IndicatorKind::Ja3);
        // The JA3 was on a non-IOC IP at capture → newly flagged; label surfaced if the feed carries one.
        assert!(hit.is_some(), "JA3 must be detected as newly dirty");
    }

    #[test]
    fn rescan_clean_feed_yields_nothing() {
        let idx = build_index(&sample_output(), 1);
        let feed = feed_with(r#"{"ips":["10.0.0.1"]}"#);
        let report = rescan(&[idx], &feed);
        assert!(report.newly_flagged.is_empty());
        assert!(report.still_flagged.is_empty());
    }
}
