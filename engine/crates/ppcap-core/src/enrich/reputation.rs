//! Always-compiled reputation types + the pure, network-free severity folding.
//!
//! Provider adapters + HTTP live behind the `online` feature in [`crate::enrich::online`];
//! THIS module compiles everywhere (incl. `wasm32`) so the browser applies verdicts via the
//! WASM `apply_reputation` export and gets the SAME scoring as native callers.

use crate::model::severity::Severity;
use crate::model::summary::Summary;
use std::collections::BTreeMap;
use std::collections::HashSet;

/// Per-provider reputation status. Distinguishes "no data" from "clean" so absence is never
/// read as innocence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RepStatus {
    /// Provider asserts malicious → raises severity.
    Malicious,
    /// Provider asserts KNOWN-benign attribution → suppression-worthy (GreyNoise benign / RIOT).
    Benign,
    /// Analyzed, no adverse signal, but no positive benign attribution → 0 pts, never suppresses.
    Clean,
    /// Analyzed but inconclusive.
    #[default]
    Unknown,
    /// Provider has no record (HTTP 404 / NotFoundError) — NOT "clean".
    NotFound,
    /// Lookup failed/skipped: error, bad key, quota exhausted, offline.
    Unavailable,
}

/// One provider's verdict for one indicator. `source` is a `String` (not `&'static str`) so it
/// round-trips through JSON on the WASM boundary.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReputationVerdict {
    /// `"abuseipdb" | "greynoise" | "virustotal"`.
    pub source: String,
    pub status: RepStatus,
    /// `== matches!(status, RepStatus::Malicious)`. Retained for wire back-compat / convenience.
    pub malicious: bool,
    /// 0..=100; `Some(0)` when `Clean`; `None` when `Unknown`/`NotFound`/`Unavailable`.
    pub score: Option<u8>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Provider report page for the indicator (evidence drill-down).
    #[serde(default)]
    pub link: Option<String>,
    /// Unix seconds the verdict was fetched (cache freshness / "as of" display).
    #[serde(default)]
    pub fetched_at: i64,
}

/// Points one malicious provider contributes (a "soft IOC" — see `score::PTS_IOC`).
const PTS_REP_MALICIOUS: u16 = 25;
/// Ceiling on total reputation uplift — multiple providers cannot exceed one soft IOC in points;
/// consensus escalates via the Critical FLOOR, not via runaway points.
const REP_UPLIFT_CAP: u16 = 25;

/// Fold per-indicator reputation verdicts into the per-IP threat cards. Pure + deterministic;
/// mirrors `score::score_flow`'s idiom (bounded points, an evidence line per adjustment). Applies
/// ONLY to public-IP cards. `verdicts` is keyed by the card's `ip` string.
pub fn apply_reputation(
    summary: &mut Summary,
    verdicts: &BTreeMap<String, Vec<ReputationVerdict>>,
) {
    // Hosts with a behavioral finding can never be suppressed (local detectors outrank online
    // benign attribution). Key on src_ip AND dst_ip.
    let finding_hosts: HashSet<&str> = summary
        .findings
        .iter()
        .flat_map(|f| std::iter::once(f.src_ip.as_str()).chain(f.dst_ip.as_deref()))
        .collect();

    for card in summary.ip_threats.iter_mut() {
        if !card.ip_class.is_external() {
            continue;
        }
        let Some(vs) = verdicts.get(&card.ip) else {
            continue;
        };
        if vs.is_empty() {
            continue;
        }
        card.reputation = vs.clone();

        let mal_count = vs
            .iter()
            .filter(|v| v.status == RepStatus::Malicious)
            .count();
        let has_benign = vs.iter().any(|v| v.status == RepStatus::Benign);

        if mal_count >= 1 {
            let points = (PTS_REP_MALICIOUS * mal_count as u16).min(REP_UPLIFT_CAP);
            card.score = (card.score + points).min(100);
            for v in vs.iter().filter(|v| v.status == RepStatus::Malicious) {
                let pct = v.score.map(|s| format!(" {s}%")).unwrap_or_default();
                let tags = if v.tags.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", v.tags.join(","))
                };
                card.evidence.push(format!(
                    "reputation: {} malicious{}{} (+{})",
                    v.source, pct, tags, points
                ));
            }
            let mut sev = Severity::from_score(card.score);
            if sev < Severity::High {
                sev = Severity::High;
                card.score = card.score.max(60);
                card.evidence
                    .push("floor: reputation malicious forces High (>= 60)".to_string());
            }
            if mal_count >= 2 {
                sev = Severity::Critical;
                card.score = card.score.max(90);
                card.evidence.push(
                    "floor: 2+ providers agree malicious forces Critical (>= 90)".to_string(),
                );
            }
            card.severity = sev;
            if !card.tags.iter().any(|t| t == "reputation") {
                card.tags.push("reputation".to_string());
            }
        } else if has_benign && !card.ioc && !finding_hosts.contains(card.ip.as_str()) {
            // Suppress path implemented in Task A4.
            suppress(card, vs);
        }
        // Clean / Unknown / NotFound / Unavailable: attached above; no score/severity change.
    }

    // A reputation uplift can reorder the table — re-sort (mirrors `stats.finish()` ordering).
    summary.ip_threats.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then(b.severity.rank().cmp(&a.severity.rank()))
            .then(b.flows.cmp(&a.flows))
            .then(a.ip.cmp(&b.ip))
    });
}

/// Attach VirusTotal domain reputation verdicts to `summary.domain_threats`, keyed by host.
/// Pure, network-free, deterministic — the single source of the domain-enrichment rule (mirrors
/// [`apply_reputation`]). Display-only: it does NOT change severity or raise incidents.
pub fn apply_domain_reputation(
    summary: &mut Summary,
    verdicts: &BTreeMap<String, Vec<ReputationVerdict>>,
) {
    for d in summary.domain_threats.iter_mut() {
        if let Some(vs) = verdicts.get(&d.host) {
            if !vs.is_empty() {
                d.reputation = vs.clone();
            }
        }
    }
}

fn downgrade_one_band(sev: Severity, score: u16) -> (Severity, u16) {
    match sev {
        Severity::Critical => (Severity::High, score.min(84)),
        Severity::High => (Severity::Medium, score.min(59)),
        Severity::Medium => (Severity::Low, score.min(34)),
        Severity::Low => (Severity::Info, score.min(14)),
        Severity::Info => (Severity::Info, score),
    }
}

/// Downgrade a card one severity band on a positive known-benign attribution (GreyNoise
/// benign / RIOT). Caller has already verified: no local IOC, no behavioral finding.
fn suppress(card: &mut crate::model::summary::IpThreat, vs: &[ReputationVerdict]) {
    let b = vs.iter().find(|v| v.status == RepStatus::Benign);
    let (src, name) = b
        .map(|v| {
            (
                v.source.as_str(),
                v.tags.first().map(String::as_str).unwrap_or("known benign"),
            )
        })
        .unwrap_or(("reputation", "known benign"));
    card.evidence.push(format!(
        "reputation: {src} benign '{name}' — known benign (-1 band)"
    ));
    let (sev, score) = downgrade_one_band(card.severity, card.score);
    card.severity = sev;
    card.score = score;
}

#[cfg(test)]
mod domain_tests {
    use super::*;

    #[test]
    fn apply_domain_reputation_attaches_by_host() {
        use crate::model::summary::DomainThreat;
        let mut summary = crate::model::output::AnalysisOutput::default().summary;
        summary.domain_threats = vec![
            DomainThreat { host: "evil.example".into(), flows: 1, bytes: 1, reputation: vec![] },
            DomainThreat { host: "good.example".into(), flows: 1, bytes: 1, reputation: vec![] },
        ];
        let mut verdicts: BTreeMap<String, Vec<ReputationVerdict>> = BTreeMap::new();
        verdicts.insert("evil.example".into(), vec![ReputationVerdict {
            source: "virustotal".into(), status: RepStatus::Malicious, malicious: true,
            score: Some(90), tags: vec![], link: None, fetched_at: 0,
        }]);
        apply_domain_reputation(&mut summary, &verdicts);
        let evil = summary.domain_threats.iter().find(|d| d.host == "evil.example").unwrap();
        assert_eq!(evil.reputation.len(), 1);
        assert_eq!(evil.reputation[0].status, RepStatus::Malicious);
        let good = summary.domain_threats.iter().find(|d| d.host == "good.example").unwrap();
        assert!(good.reputation.is_empty()); // host not in verdicts → unchanged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_serde_roundtrip_snake_case() {
        let v = ReputationVerdict {
            source: "abuseipdb".to_string(),
            status: RepStatus::Malicious,
            malicious: true,
            score: Some(96),
            tags: vec!["ssh".to_string(), "brute-force".to_string()],
            link: Some("https://www.abuseipdb.com/check/203.0.113.7".to_string()),
            fetched_at: 1_750_500_000,
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("\"status\":\"malicious\""));
        let back: ReputationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn status_default_is_unknown() {
        assert_eq!(RepStatus::default(), RepStatus::Unknown);
    }
}

#[cfg(test)]
mod apply_tests {
    use super::*;
    use crate::enrich::IpClass;
    use crate::model::summary::{IpThreat, ProtoCounts, SeverityCounts, Summary};

    fn verdict(source: &str, status: RepStatus, score: Option<u8>) -> ReputationVerdict {
        ReputationVerdict {
            source: source.to_string(),
            status,
            malicious: status == RepStatus::Malicious,
            score,
            tags: vec![],
            link: None,
            fetched_at: 0,
        }
    }

    fn card(ip: &str, class: IpClass, sev: Severity, score: u16, ioc: bool) -> IpThreat {
        IpThreat {
            ip: ip.to_string(),
            ip_class: class,
            severity: sev,
            score,
            flows: 1,
            bytes: 100,
            ioc,
            tags: vec![],
            attack: vec![],
            evidence: vec![],
            reputation: vec![],
        }
    }

    fn summary_with(
        threats: Vec<IpThreat>,
        findings: Vec<crate::model::finding::Finding>,
    ) -> Summary {
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
            top_talkers: vec![],
            protocol_hierarchy: vec![],
            port_histogram: vec![],
            time_histogram: vec![],
            time_bucket_secs: 1,
            category_breakdown: vec![],
            severity_counts: SeverityCounts::default(),
            ip_threats: threats,
            domain_threats: Vec::new(),
            findings,
            incidents: vec![],
        }
    }

    fn map(pairs: Vec<(&str, Vec<ReputationVerdict>)>) -> BTreeMap<String, Vec<ReputationVerdict>> {
        pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    #[test]
    fn single_malicious_floors_to_high() {
        let mut s = summary_with(
            vec![card(
                "203.0.113.7",
                IpClass::Public,
                Severity::Low,
                20,
                false,
            )],
            vec![],
        );
        apply_reputation(
            &mut s,
            &map(vec![(
                "203.0.113.7",
                vec![verdict("abuseipdb", RepStatus::Malicious, Some(96))],
            )]),
        );
        let c = &s.ip_threats[0];
        assert_eq!(c.severity, Severity::High);
        assert!(c.score >= 60);
        assert_eq!(c.reputation.len(), 1);
        assert!(c
            .evidence
            .iter()
            .any(|e| e.contains("reputation: abuseipdb malicious")));
        assert!(c
            .evidence
            .iter()
            .any(|e| e == "floor: reputation malicious forces High (>= 60)"));
    }

    #[test]
    fn consensus_two_malicious_floors_to_critical() {
        let mut s = summary_with(
            vec![card(
                "203.0.113.7",
                IpClass::Public,
                Severity::Medium,
                40,
                false,
            )],
            vec![],
        );
        apply_reputation(
            &mut s,
            &map(vec![(
                "203.0.113.7",
                vec![
                    verdict("abuseipdb", RepStatus::Malicious, Some(96)),
                    verdict("virustotal", RepStatus::Malicious, Some(80)),
                ],
            )]),
        );
        let c = &s.ip_threats[0];
        assert_eq!(c.severity, Severity::Critical);
        assert!(c.score >= 90);
        assert!(c
            .evidence
            .iter()
            .any(|e| e.contains("2+ providers agree malicious")));
    }

    fn benign(source: &str, name: &str) -> ReputationVerdict {
        ReputationVerdict {
            source: source.to_string(),
            status: RepStatus::Benign,
            malicious: false,
            score: Some(5),
            tags: vec![name.to_string()],
            link: None,
            fetched_at: 0,
        }
    }

    fn finding(src_ip: &str) -> crate::model::finding::Finding {
        crate::model::finding::Finding {
            kind: crate::model::finding::FindingKind::Beacon,
            severity: Severity::High,
            score: 70,
            title: "t".to_string(),
            src_ip: src_ip.to_string(),
            dst_ip: None,
            dst_port: None,
            attack: vec![],
            evidence: vec![],
            interval_ns: None,
            jitter_cv: None,
            contacts: None,
        }
    }

    #[test]
    fn benign_downgrades_one_band_when_unguarded() {
        let mut s = summary_with(
            vec![card(
                "203.0.113.9",
                IpClass::Public,
                Severity::Medium,
                40,
                false,
            )],
            vec![],
        );
        apply_reputation(
            &mut s,
            &map(vec![(
                "203.0.113.9",
                vec![benign("greynoise", "Shodan.io")],
            )]),
        );
        let c = &s.ip_threats[0];
        assert_eq!(c.severity, Severity::Low);
        assert!(c.score <= 34);
        assert!(c.evidence.iter().any(|e| e.contains("known benign")));
    }

    #[test]
    fn benign_never_suppresses_a_card_with_local_ioc() {
        let mut s = summary_with(
            vec![card(
                "203.0.113.9",
                IpClass::Public,
                Severity::High,
                65,
                true,
            )],
            vec![],
        );
        apply_reputation(
            &mut s,
            &map(vec![(
                "203.0.113.9",
                vec![benign("greynoise", "Shodan.io")],
            )]),
        );
        assert_eq!(s.ip_threats[0].severity, Severity::High);
    }

    #[test]
    fn benign_never_suppresses_a_host_with_behavioral_finding() {
        let mut s = summary_with(
            vec![card(
                "203.0.113.9",
                IpClass::Public,
                Severity::High,
                70,
                false,
            )],
            vec![finding("203.0.113.9")],
        );
        apply_reputation(
            &mut s,
            &map(vec![(
                "203.0.113.9",
                vec![benign("greynoise", "Shodan.io")],
            )]),
        );
        assert_eq!(s.ip_threats[0].severity, Severity::High);
    }

    #[test]
    fn internal_card_is_untouched() {
        let mut s = summary_with(
            vec![card("10.0.0.5", IpClass::Private, Severity::Low, 20, false)],
            vec![],
        );
        apply_reputation(
            &mut s,
            &map(vec![(
                "10.0.0.5",
                vec![verdict("abuseipdb", RepStatus::Malicious, Some(96))],
            )]),
        );
        assert_eq!(s.ip_threats[0].severity, Severity::Low);
        assert!(s.ip_threats[0].reputation.is_empty());
    }

    #[test]
    fn unknown_and_notfound_attach_but_dont_move_score() {
        let mut s = summary_with(
            vec![card(
                "203.0.113.7",
                IpClass::Public,
                Severity::Low,
                20,
                false,
            )],
            vec![],
        );
        apply_reputation(
            &mut s,
            &map(vec![(
                "203.0.113.7",
                vec![
                    verdict("greynoise", RepStatus::NotFound, None),
                    verdict("virustotal", RepStatus::Unknown, None),
                ],
            )]),
        );
        let c = &s.ip_threats[0];
        assert_eq!(c.severity, Severity::Low);
        assert_eq!(c.score, 20);
        assert_eq!(c.reputation.len(), 2);
    }

    #[test]
    fn uplifted_card_resorts_to_top() {
        let mut s = summary_with(
            vec![
                card("203.0.113.1", IpClass::Public, Severity::High, 70, false),
                card("203.0.113.2", IpClass::Public, Severity::Low, 20, false),
            ],
            vec![],
        );
        // The low card gets consensus-malicious -> Critical, must rise to index 0.
        apply_reputation(
            &mut s,
            &map(vec![(
                "203.0.113.2",
                vec![
                    verdict("abuseipdb", RepStatus::Malicious, Some(96)),
                    verdict("greynoise", RepStatus::Malicious, Some(90)),
                ],
            )]),
        );
        assert_eq!(s.ip_threats[0].ip, "203.0.113.2");
        assert_eq!(s.ip_threats[0].severity, Severity::Critical);
    }
}
