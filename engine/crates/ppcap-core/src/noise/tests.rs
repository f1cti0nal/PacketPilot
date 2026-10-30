use super::*;
use crate::detect::alerts::refresh_alerts;
use crate::model::finding::{Finding, FindingKind};
use crate::model::severity::Severity;

fn finding(kind: FindingKind, src: &str) -> Finding {
    Finding {
        kind,
        severity: Severity::High,
        score: 80,
        title: format!("{}: {src}", kind.as_str()),
        src_ip: src.to_string(),
        dst_ip: Some("45.77.13.37".to_string()),
        dst_port: Some(443),
        attack: vec!["T1071".to_string()],
        evidence: vec![format!("{} evidence", kind.as_str())],
        interval_ns: None,
        jitter_cv: None,
        contacts: None,
        first_seen_ns: Some(1_700_000_000_000_000_000),
        last_seen_ns: Some(1_700_000_060_000_000_000),
        victims: Vec::new(),
    }
}

fn summary(flows: u64, findings: Vec<Finding>) -> Summary {
    let mut s = Summary::empty();
    s.total_packets = 4_200_000;
    s.total_flows = flows;
    s.findings = findings;
    refresh_alerts(&mut s);
    s
}

#[test]
fn counts_and_estimate_follow_the_formula() {
    let s = summary(
        61_000,
        vec![
            finding(FindingKind::Beacon, "10.0.0.7"),
            finding(FindingKind::PortScan, "10.0.0.7"),
            finding(FindingKind::Beacon, "10.0.0.9"),
        ],
    );
    let b = s
        .noise_budget
        .clone()
        .expect("refresh_alerts derives the budget");
    assert_eq!(
        (b.packets, b.flows, b.findings, b.suppressed),
        (4_200_000, 61_000, 3, 0)
    );
    assert_eq!(b.stories, s.alerts.len() as u64);
    assert!(b.stories >= 1 && b.stories <= 3);
    let r = ReviewRates::default();
    let manual = 61.0 * r.minutes_per_1k_flows + 3.0 * r.minutes_per_finding;
    assert_eq!(b.manual_minutes, manual);
    assert_eq!(b.queue_minutes, b.stories as f64 * r.minutes_per_story);
    assert_eq!(b.saved_minutes, manual - b.queue_minutes);
    assert!(b.headline().starts_with("4.2M packets → 61k flows → "));
    assert!(b.headline().ends_with("saved (estimate)"));
    assert!(b.explain().contains("3 findings (0 suppressed)"));
}

#[test]
fn never_claims_negative_savings() {
    let mut s = summary(10, vec![finding(FindingKind::Beacon, "10.0.0.7")]);
    apply_review_rates(
        &mut s,
        ReviewRates {
            minutes_per_story: 400.0,
            ..ReviewRates::default()
        },
    );
    let b = s.noise_budget.unwrap();
    assert_eq!(b.saved_minutes, 0.0);
    assert!(b.headline().ends_with("no review time saved"));
}

#[test]
fn team_rates_survive_rederivation() {
    let mut s = summary(5_000, vec![finding(FindingKind::Beacon, "10.0.0.7")]);
    let team = ReviewRates {
        minutes_per_finding: 30.0,
        ..ReviewRates::default()
    };
    apply_review_rates(&mut s, team);
    refresh_alerts(&mut s);
    assert_eq!(s.noise_budget.as_ref().unwrap().rates, team);
    assert_eq!(s.noise_budget.unwrap().manual_minutes, 5.0 * 5.0 + 30.0);
}

#[test]
fn suppressed_findings_are_counted() {
    use crate::model::suppression::{SuppressionHit, SuppressionOutcome};
    let mut s = summary(1_000, vec![finding(FindingKind::Beacon, "10.0.0.7")]);
    s.suppressions = vec![SuppressionHit {
        finding_index: 0,
        rule_id: "r1".into(),
        outcome: SuppressionOutcome::Suppressed,
    }];
    let b = noise_budget(&s, ReviewRates::default());
    assert_eq!((b.findings, b.suppressed), (1, 1));
}

#[test]
fn rates_file_parses_partially_and_reports_every_problem() {
    let r = parse_review_rates(r#"{"version":1,"minutes_per_finding":20}"#).unwrap();
    assert_eq!(r.minutes_per_finding, 20.0);
    assert_eq!(
        r.minutes_per_story,
        ReviewRates::default().minutes_per_story
    );
    let errs =
        parse_review_rates(r#"{"version":2,"minutes_per_story":-1,"minutes_per_finding":9999}"#)
            .unwrap_err();
    assert_eq!(errs.len(), 3, "{errs:?}");
    assert!(parse_review_rates("not json").is_err());
}

#[test]
fn older_summaries_without_a_budget_still_load() {
    let mut s = Summary::empty();
    s.noise_budget = None;
    let json = serde_json::to_string(&s).unwrap();
    assert!(!json.contains("noise_budget"));
    let back: Summary = serde_json::from_str(&json).unwrap();
    assert!(back.noise_budget.is_none());
}

#[test]
fn compact_numbers_and_saved_phrases() {
    assert_eq!(compact(950), "950");
    assert_eq!(compact(61_234), "61k");
    assert_eq!(compact(4_249_999), "4.2M");
    assert_eq!(compact(1_000), "1k");
    assert_eq!(compact(2_500_000_000), "2.5B");
    assert_eq!(saved_phrase(0.4), "no review time saved");
    assert_eq!(saved_phrase(25.2), "about 25 min saved (estimate)");
    assert_eq!(saved_phrase(370.0), "about 6 h saved (estimate)");
    assert_eq!(saved_phrase(100.0), "about 1.5 h saved (estimate)");
    assert_eq!(saved_phrase(900.0), "about 15 h saved (estimate)");
}
