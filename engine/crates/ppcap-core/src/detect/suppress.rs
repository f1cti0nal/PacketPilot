//! "Teach it once" — analyst suppression rules applied to the alert queue.
//!
//! An analyst marks an alert benign; [`rules_for_alert`] turns that verdict into one
//! [`SuppressionRule`] per member finding, at a chosen [`TeachScope`]. Rule files load through
//! [`load_rules`] (normalize, validate, dedupe by id, drop expired), get attached to a summary
//! with [`apply_suppressions`], and from then on every alert re-derivation hides the matching
//! findings — recording each one in `Summary.suppressions`, so nothing is silently dropped.
//!
//! Pure and offline like the rest of `detect`: no clock (expiry takes `today` from the caller),
//! no network, no `f64`, deterministic order.

use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::enrich::{canonicalize_ip, parse_cidr, Cidr, RepStatus};
use crate::model::finding::{Finding, FindingKind};
use crate::model::summary::Summary;
use crate::model::suppression::{
    BlockReason, SuppressionFile, SuppressionHit, SuppressionOutcome, SuppressionRule,
};

use super::fnv1a64;

/// Days a newly taught rule stays active unless the analyst picks otherwise, so allowlists
/// cannot silently go stale.
pub const DEFAULT_RULE_TTL_DAYS: i64 = 90;

/// Kinds no rule may hide: content/intel-confirmed malware, active MITM, and safety-critical
/// OT writes. Mirrors the alert queue's `never_rollup` doctrine minus `RuleMatch` (an imported
/// signature that fires on known-good traffic is exactly what an analyst needs to tune out).
pub fn is_protected_kind(kind: FindingKind) -> bool {
    matches!(
        kind,
        FindingKind::MalwareDownload
            | FindingKind::MalwareSignature
            | FindingKind::ArpSpoof
            | FindingKind::IcsControlCommand
    )
}

/// How broadly a "mark benign" verdict generalizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeachScope {
    /// Same kind, same source, same destination, same port.
    Exact,
    /// Same kind from this source host, to anywhere.
    Source,
    /// Same kind to this destination (and port), from any host — e.g. every client talking to
    /// an internal NTP server.
    Destination,
}

/// The stable id of a normalized match key.
pub fn rule_id(kind: &str, src: Option<&str>, dst: Option<&str>, dst_port: Option<u16>) -> String {
    let key = format!(
        "{kind}|{}|{}|{}",
        src.unwrap_or("*"),
        dst.unwrap_or("*"),
        dst_port.map_or_else(|| "*".to_string(), |p| p.to_string()),
    );
    format!("sup:{:016x}", fnv1a64(key.as_bytes()))
}

/// Trim a host field; empty / `*` / `any` mean wildcard.
fn normalize_host(h: Option<&str>) -> Option<String> {
    let h = h?.trim();
    if h.is_empty() || h == "*" || h.eq_ignore_ascii_case("any") {
        None
    } else {
        Some(h.to_string())
    }
}

/// Canonical form of a rule: trimmed fields, wildcards as `None`, and an id derived from the
/// match key when the file did not carry one.
pub fn normalize_rule(rule: &SuppressionRule) -> SuppressionRule {
    let kind = rule.kind.trim().to_ascii_lowercase();
    let src = normalize_host(rule.src.as_deref());
    let dst = normalize_host(rule.dst.as_deref());
    let id = if rule.id.trim().is_empty() {
        rule_id(&kind, src.as_deref(), dst.as_deref(), rule.dst_port)
    } else {
        rule.id.trim().to_string()
    };
    SuppressionRule {
        id,
        kind,
        src,
        dst,
        dst_port: rule.dst_port,
        reason: rule.reason.trim().to_string(),
        author: rule.author.clone(),
        created: rule.created.clone(),
        expires: rule.expires.clone(),
    }
}

/// A host matcher: one address or a network.
enum HostMatch {
    Ip(IpAddr),
    Net(Cidr),
}

impl HostMatch {
    fn parse(s: &str) -> Option<HostMatch> {
        if s.contains('/') {
            parse_cidr(s).ok().map(HostMatch::Net)
        } else {
            s.parse::<IpAddr>()
                .ok()
                .map(|ip| HostMatch::Ip(canonicalize_ip(ip)))
        }
    }

    fn matches(&self, ip: &str) -> bool {
        let Ok(ip) = ip.parse::<IpAddr>() else {
            return false;
        };
        let ip = canonicalize_ip(ip);
        match self {
            HostMatch::Ip(want) => *want == ip,
            HostMatch::Net(net) => net.contains(ip),
        }
    }
}

/// A rule compiled for matching. Rules with an unparseable host never compile.
struct Compiled<'a> {
    rule: &'a SuppressionRule,
    src: Option<HostMatch>,
    dst: Option<HostMatch>,
}

fn compile(rule: &SuppressionRule) -> Result<Compiled<'_>, String> {
    let host = |field: &str, v: &Option<String>| -> Result<Option<HostMatch>, String> {
        match v {
            None => Ok(None),
            Some(s) => HostMatch::parse(s)
                .map(Some)
                .ok_or_else(|| format!("{field} {s:?} is not an IP address or CIDR")),
        }
    };
    Ok(Compiled {
        rule,
        src: host("src", &rule.src)?,
        dst: host("dst", &rule.dst)?,
    })
}

impl Compiled<'_> {
    fn matches(&self, f: &Finding) -> bool {
        if self.rule.kind != f.kind.as_str() {
            return false;
        }
        if let Some(src) = &self.src {
            if !src.matches(&f.src_ip) {
                return false;
            }
        }
        if let Some(dst) = &self.dst {
            match f.dst_ip.as_deref() {
                Some(ip) if dst.matches(ip) => {}
                _ => return false,
            }
        }
        if let Some(port) = self.rule.dst_port {
            if f.dst_port != Some(port) {
                return false;
            }
        }
        true
    }
}

/// The result of loading one or more rule files.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct LoadedRules {
    /// Normalized, valid, unexpired rules, deduplicated by id (first file wins), in file order.
    pub active: Vec<SuppressionRule>,
    /// Rules whose `expires` date is before `today`.
    pub expired: Vec<SuppressionRule>,
    /// Rules that can never match, with why (bad host syntax).
    pub invalid: Vec<(SuppressionRule, String)>,
    /// Rules naming a finding kind this build does not know (kept active; they never match).
    pub unknown_kind: Vec<SuppressionRule>,
    /// Count of rules dropped as duplicates of an earlier id.
    pub duplicates: usize,
}

/// Whether `kind` is a finding-kind token this build knows.
pub fn is_known_kind(kind: &str) -> bool {
    serde_json::from_value::<FindingKind>(serde_json::Value::String(kind.to_string())).is_ok()
}

/// Normalize, validate and merge rule files in priority order. `today` (`YYYY-MM-DD`) drops
/// rules whose `expires` is strictly earlier; `None` keeps every rule.
pub fn load_rules(files: &[SuppressionFile], today: Option<&str>) -> LoadedRules {
    let mut out = LoadedRules::default();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for file in files {
        for raw in &file.rules {
            let rule = normalize_rule(raw);
            if !seen.insert(rule.id.clone()) {
                out.duplicates += 1;
                continue;
            }
            if let Err(why) = compile(&rule) {
                out.invalid.push((rule, why));
                continue;
            }
            if rule.kind.is_empty() {
                out.invalid.push((rule, "kind is required".to_string()));
                continue;
            }
            if let (Some(today), Some(exp)) = (today, rule.expires.as_deref()) {
                if exp.trim() < today {
                    out.expired.push(rule);
                    continue;
                }
            }
            if !is_known_kind(&rule.kind) {
                out.unknown_kind.push(rule.clone());
            }
            out.active.push(rule);
        }
    }
    out
}

/// The guardrail that keeps a finding in the queue despite a matching rule, if any.
fn block_reason(summary: &Summary, f: &Finding) -> Option<BlockReason> {
    if is_protected_kind(f.kind) {
        return Some(BlockReason::ProtectedKind);
    }
    let cards: Vec<_> = std::iter::once(f.src_ip.as_str())
        .chain(f.dst_ip.as_deref())
        .filter_map(|ip| summary.ip_threats.iter().find(|c| c.ip == ip))
        .collect();
    if cards.iter().any(|c| c.ioc) {
        return Some(BlockReason::ThreatIntel);
    }
    if cards.iter().any(|c| {
        c.reputation
            .iter()
            .any(|v| v.status == RepStatus::Malicious)
    }) {
        return Some(BlockReason::Reputation);
    }
    None
}

/// Match `summary.suppression_rules` against `summary.findings`. Pure; ascending by finding
/// index; the first matching rule (in rule order) is the one recorded.
pub fn match_suppressions(summary: &Summary) -> Vec<SuppressionHit> {
    if summary.suppression_rules.is_empty() {
        return Vec::new();
    }
    let compiled: Vec<Compiled<'_>> = summary
        .suppression_rules
        .iter()
        .filter_map(|r| compile(r).ok())
        .collect();
    let mut hits = Vec::new();
    for (i, f) in summary.findings.iter().enumerate() {
        let Some(c) = compiled.iter().find(|c| c.matches(f)) else {
            continue;
        };
        let outcome = match block_reason(summary, f) {
            Some(why) => SuppressionOutcome::Blocked(why),
            None => SuppressionOutcome::Suppressed,
        };
        hits.push(SuppressionHit {
            finding_index: i as u32,
            rule_id: c.rule.id.clone(),
            outcome,
        });
    }
    hits
}

/// Indices of findings a rule actually hid (the alert queue skips exactly these).
pub fn suppressed_indices(summary: &Summary) -> BTreeSet<u32> {
    match_suppressions(summary)
        .into_iter()
        .filter(|h| h.outcome == SuppressionOutcome::Suppressed)
        .map(|h| h.finding_index)
        .collect()
}

/// Attach `rules` to the summary (replacing any earlier set) and re-derive the alert queue.
pub fn apply_suppressions(summary: &mut Summary, rules: Vec<SuppressionRule>) {
    summary.suppression_rules = rules;
    super::alerts::refresh_alerts(summary);
}

/// Who taught a verdict, why, and for how long — the metadata stamped on every new rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TeachMeta {
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub author: Option<String>,
    /// `YYYY-MM-DD`.
    #[serde(default)]
    pub created: Option<String>,
    /// `YYYY-MM-DD`; `None` never expires.
    #[serde(default)]
    pub expires: Option<String>,
}

/// The rule a "mark benign" verdict on one finding produces at `scope`.
pub fn rule_for_finding(f: &Finding, scope: TeachScope, meta: &TeachMeta) -> SuppressionRule {
    let (src, dst, dst_port) = match scope {
        TeachScope::Exact => (Some(f.src_ip.clone()), f.dst_ip.clone(), f.dst_port),
        TeachScope::Source => (Some(f.src_ip.clone()), None, None),
        TeachScope::Destination => (None, f.dst_ip.clone(), f.dst_port),
    };
    normalize_rule(&SuppressionRule {
        id: String::new(),
        kind: f.kind.as_str().to_string(),
        src,
        dst,
        dst_port,
        reason: meta.reason.clone(),
        author: meta.author.clone(),
        created: meta.created.clone(),
        expires: meta.expires.clone(),
    })
}

/// Why an alert could not be taught as benign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeachError {
    /// No alert in `summary.alerts` has this id.
    UnknownAlert(String),
}

impl std::fmt::Display for TeachError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TeachError::UnknownAlert(id) => write!(f, "no alert with id {id}"),
        }
    }
}

/// What teaching one alert produced.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Taught {
    /// One rule per distinct match key among the alert's suppressible members, in member order.
    pub rules: Vec<SuppressionRule>,
    /// Member finding indices a rule would not hide (protected kind / IOC / reputation), with
    /// why — the UI warns instead of pretending the alert will vanish.
    pub kept: Vec<(u32, BlockReason)>,
}

/// Turn "this alert is benign" into rules covering its member findings at `scope`.
/// A destination-scoped verdict on a fan-out finding (no single destination) falls back to
/// the source scope rather than producing a kind-wide wildcard.
pub fn rules_for_alert(
    summary: &Summary,
    alert_id: &str,
    scope: TeachScope,
    meta: &TeachMeta,
) -> Result<Taught, TeachError> {
    let alert = summary
        .alerts
        .iter()
        .find(|a| a.id == alert_id)
        .ok_or_else(|| TeachError::UnknownAlert(alert_id.to_string()))?;
    let mut rules: Vec<SuppressionRule> = Vec::new();
    let mut kept = Vec::new();
    for &i in &alert.finding_indices {
        let Some(f) = summary.findings.get(i as usize) else {
            continue;
        };
        if let Some(why) = block_reason(summary, f) {
            kept.push((i, why));
            continue;
        }
        let scope = if scope == TeachScope::Destination && f.dst_ip.is_none() {
            TeachScope::Source
        } else {
            scope
        };
        let rule = rule_for_finding(f, scope, meta);
        if !rules.iter().any(|r| r.id == rule.id) {
            rules.push(rule);
        }
    }
    Ok(Taught { rules, kept })
}

/// Merge `new` rules into a file, keeping existing rules (and their metadata) on id clashes.
/// Returns how many rules were added.
pub fn merge_into_file(file: &mut SuppressionFile, new: &[SuppressionRule]) -> usize {
    let mut have: BTreeSet<String> = file.rules.iter().map(|r| normalize_rule(r).id).collect();
    let mut added = 0;
    for r in new {
        let r = normalize_rule(r);
        if have.insert(r.id.clone()) {
            file.rules.push(r);
            added += 1;
        }
    }
    added
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::{IpClass, ReputationVerdict};
    use crate::model::severity::Severity;
    use crate::model::summary::IpThreat;

    fn card(ip: &str) -> IpThreat {
        IpThreat {
            ip: ip.to_string(),
            ip_class: IpClass::Public,
            severity: Severity::Medium,
            score: 50,
            flows: 1,
            bytes: 1,
            ioc: false,
            tags: Vec::new(),
            attack: Vec::new(),
            evidence: Vec::new(),
            reputation: Vec::new(),
            fingerprints: Vec::new(),
            score_terms: Vec::new(),
        }
    }

    fn finding(kind: FindingKind, src: &str, dst: Option<&str>, port: Option<u16>) -> Finding {
        Finding {
            kind,
            severity: Severity::Medium,
            score: 45,
            title: format!("{} from {src}", kind.as_str()),
            src_ip: src.to_string(),
            dst_ip: dst.map(str::to_string),
            dst_port: port,
            attack: Vec::new(),
            evidence: Vec::new(),
            interval_ns: None,
            jitter_cv: None,
            contacts: None,
            first_seen_ns: Some(1),
            last_seen_ns: Some(2),
            victims: Vec::new(),
        }
    }

    fn rule(
        kind: &str,
        src: Option<&str>,
        dst: Option<&str>,
        port: Option<u16>,
    ) -> SuppressionRule {
        normalize_rule(&SuppressionRule {
            id: String::new(),
            kind: kind.into(),
            src: src.map(str::to_string),
            dst: dst.map(str::to_string),
            dst_port: port,
            reason: "known good".into(),
            author: None,
            created: None,
            expires: None,
        })
    }

    fn summary_with(findings: Vec<Finding>) -> Summary {
        let mut s = Summary::empty();
        s.incidents = crate::detect::correlate_incidents(&findings);
        s.attack_chains = crate::detect::reconstruct_attack_chains(&findings);
        s.findings = findings;
        super::super::alerts::refresh_alerts(&mut s);
        s
    }

    fn covered(s: &Summary) -> usize {
        let in_alerts: u32 = s.alerts.iter().map(|a| a.finding_count).sum();
        let hidden = s
            .suppressions
            .iter()
            .filter(|h| h.outcome == SuppressionOutcome::Suppressed)
            .count();
        in_alerts as usize + hidden
    }

    #[test]
    fn rule_id_is_stable_and_wildcard_aware() {
        let a = rule("missing_sni", Some(" 10.0.0.5 "), Some("any"), None);
        let b = rule("missing_sni", Some("10.0.0.5"), None, None);
        assert_eq!(a.id, b.id);
        assert!(a.id.starts_with("sup:"));
        assert_eq!(a.dst, None);
        let c = rule("missing_sni", Some("10.0.0.5"), None, Some(443));
        assert_ne!(a.id, c.id);
    }

    #[test]
    fn matches_exact_cidr_and_wildcards() {
        let f = finding(
            FindingKind::MissingSni,
            "10.1.2.3",
            Some("52.1.1.1"),
            Some(443),
        );
        for (r, want) in [
            (
                rule("missing_sni", Some("10.1.2.3"), Some("52.1.1.1"), Some(443)),
                true,
            ),
            (rule("missing_sni", Some("10.0.0.0/8"), None, None), true),
            (
                rule("missing_sni", None, Some("52.1.1.0/24"), Some(443)),
                true,
            ),
            (rule("missing_sni", None, None, Some(8443)), false),
            (rule("missing_sni", Some("10.1.2.4"), None, None), false),
            (rule("weak_tls", Some("10.1.2.3"), None, None), false),
            (
                rule("missing_sni", None, Some("::ffff:52.1.1.1"), None),
                true,
            ),
        ] {
            assert_eq!(compile(&r).unwrap().matches(&f), want, "{r:?}");
        }
        // A destination constraint never matches a fan-out finding with no destination.
        let sweep = finding(FindingKind::HostSweep, "10.1.2.3", None, Some(445));
        let r = rule("host_sweep", None, Some("10.0.0.0/8"), None);
        assert!(!compile(&r).unwrap().matches(&sweep));
    }

    #[test]
    fn suppressed_findings_leave_the_queue_but_stay_accounted_for() {
        let findings = vec![
            finding(
                FindingKind::MissingSni,
                "10.0.0.5",
                Some("52.1.1.1"),
                Some(443),
            ),
            finding(
                FindingKind::MissingSni,
                "10.0.0.6",
                Some("52.1.1.1"),
                Some(443),
            ),
            finding(
                FindingKind::WeakTls,
                "10.0.0.7",
                Some("52.9.9.9"),
                Some(443),
            ),
        ];
        let mut s = summary_with(findings);
        let before: u32 = s.alerts.iter().map(|a| a.finding_count).sum();
        assert_eq!(before, 3);
        apply_suppressions(
            &mut s,
            vec![rule("missing_sni", None, Some("52.1.1.1"), Some(443))],
        );
        assert_eq!(s.suppressions.len(), 2);
        assert!(s
            .suppressions
            .iter()
            .all(|h| h.outcome == SuppressionOutcome::Suppressed));
        assert!(s.alerts.iter().all(|a| !a.finding_indices.contains(&0)));
        assert!(s.alerts.iter().all(|a| !a.finding_indices.contains(&1)));
        assert_eq!(covered(&s), s.findings.len());
        // Removing the rules restores the original queue exactly.
        let original = summary_with(s.findings.clone());
        apply_suppressions(&mut s, Vec::new());
        assert_eq!(s.alerts, original.alerts);
        assert!(s.suppressions.is_empty());
    }

    #[test]
    fn guardrails_keep_protected_and_intel_backed_findings() {
        let findings = vec![
            finding(
                FindingKind::MalwareDownload,
                "10.0.0.5",
                Some("52.1.1.1"),
                Some(80),
            ),
            finding(
                FindingKind::Beacon,
                "10.0.0.6",
                Some("45.77.13.37"),
                Some(443),
            ),
            finding(
                FindingKind::Beacon,
                "10.0.0.7",
                Some("45.77.13.38"),
                Some(443),
            ),
        ];
        let mut s = summary_with(findings);
        let mut ioc = card("45.77.13.37");
        ioc.ioc = true;
        let mut rep = card("45.77.13.38");
        rep.reputation = vec![ReputationVerdict {
            source: "abuseipdb".into(),
            status: RepStatus::Malicious,
            malicious: true,
            score: Some(99),
            tags: Vec::new(),
            link: None,
            fetched_at: 0,
        }];
        s.ip_threats = vec![ioc, rep];
        apply_suppressions(
            &mut s,
            vec![
                rule("malware_download", None, None, None),
                rule("beacon", Some("10.0.0.0/8"), None, None),
            ],
        );
        let outcomes: Vec<_> = s.suppressions.iter().map(|h| h.outcome).collect();
        assert_eq!(
            outcomes,
            vec![
                SuppressionOutcome::Blocked(BlockReason::ProtectedKind),
                SuppressionOutcome::Blocked(BlockReason::ThreatIntel),
                SuppressionOutcome::Blocked(BlockReason::Reputation),
            ]
        );
        let in_alerts: u32 = s.alerts.iter().map(|a| a.finding_count).sum();
        assert_eq!(in_alerts, 3);
    }

    #[test]
    fn load_rules_dedupes_expires_and_flags_bad_rules() {
        let team = SuppressionFile {
            version: 1,
            rules: vec![
                SuppressionRule {
                    reason: "team".into(),
                    ..rule("missing_sni", Some("10.0.0.5"), None, None)
                },
                SuppressionRule {
                    expires: Some("2026-01-01".into()),
                    ..rule("weak_tls", None, None, None)
                },
                rule("beacon", Some("not-an-ip"), None, None),
                rule("future_kind", None, None, None),
            ],
        };
        let mine = SuppressionFile {
            version: 1,
            rules: vec![SuppressionRule {
                id: String::new(),
                reason: "mine".into(),
                ..rule("missing_sni", Some("10.0.0.5"), None, None)
            }],
        };
        let loaded = load_rules(&[team, mine], Some("2026-10-29"));
        assert_eq!(loaded.active.len(), 2);
        assert_eq!(loaded.active[0].reason, "team");
        assert_eq!(loaded.duplicates, 1);
        assert_eq!(loaded.expired.len(), 1);
        assert_eq!(loaded.invalid.len(), 1);
        assert_eq!(loaded.unknown_kind.len(), 1);
        // Without a date nothing expires.
        assert!(load_rules(
            &[SuppressionFile {
                version: 1,
                rules: vec![SuppressionRule {
                    expires: Some("2000-01-01".into()),
                    ..rule("weak_tls", None, None, None)
                }]
            }],
            None
        )
        .expired
        .is_empty());
    }

    #[test]
    fn teaching_an_alert_hides_it_on_the_next_capture() {
        let findings = vec![
            finding(
                FindingKind::MissingSni,
                "10.0.0.5",
                Some("52.1.1.1"),
                Some(443),
            ),
            finding(
                FindingKind::MissingSni,
                "10.0.0.6",
                Some("52.1.1.1"),
                Some(443),
            ),
        ];
        let s = summary_with(findings.clone());
        let alert = s.alerts[0].clone();
        let meta = TeachMeta {
            reason: "IoT hub talks by IP".into(),
            author: Some("john".into()),
            created: Some("2026-10-29".into()),
            expires: Some("2027-01-27".into()),
        };
        let taught = rules_for_alert(&s, &alert.id, TeachScope::Destination, &meta).unwrap();
        assert_eq!(
            taught.rules.len(),
            1,
            "both members share one destination key"
        );
        assert_eq!(taught.rules[0].src, None);
        assert_eq!(taught.rules[0].author.as_deref(), Some("john"));
        assert!(taught.kept.is_empty());

        let mut file = SuppressionFile::default();
        assert_eq!(merge_into_file(&mut file, &taught.rules), 1);
        assert_eq!(merge_into_file(&mut file, &taught.rules), 0);
        let json = serde_json::to_string_pretty(&file).unwrap();
        let reread: SuppressionFile = serde_json::from_str(&json).unwrap();

        let mut next = summary_with(findings);
        apply_suppressions(&mut next, load_rules(&[reread], Some("2026-11-01")).active);
        assert!(next.alerts.is_empty());
        assert_eq!(covered(&next), 2);

        assert_eq!(
            rules_for_alert(&s, "alert:nope", TeachScope::Exact, &meta),
            Err(TeachError::UnknownAlert("alert:nope".into()))
        );
    }

    #[test]
    fn destination_scope_on_fan_out_falls_back_to_source() {
        let s = summary_with(vec![finding(FindingKind::PortScan, "10.0.0.9", None, None)]);
        let id = s.alerts[0].id.clone();
        let taught =
            rules_for_alert(&s, &id, TeachScope::Destination, &TeachMeta::default()).unwrap();
        assert_eq!(taught.rules[0].src.as_deref(), Some("10.0.0.9"));
        assert_eq!(taught.rules[0].dst, None);
    }
}
