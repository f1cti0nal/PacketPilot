//! Black-box tests for the transparent scorer: band boundaries, the IOC floor, the
//! C2/Anomalous Critical floor, scan-shaped behavior evidence, exact evidence strings, and
//! the 0..=100 clamp.

use std::net::{IpAddr, Ipv4Addr};

use ppcap_core::model::flow::{FlowKey, FlowRecord};
use ppcap_core::model::packet::Transport;
use ppcap_core::{score_flow, Category, FeedMatch, Severity};

fn rec(cat: Category) -> FlowRecord {
    let key = FlowKey {
        lo_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        hi_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        lo_port: 1234,
        hi_port: 443,
        transport: Transport::Tcp,
    };
    let mut r = FlowRecord::new(key, 0);
    r.category = cat;
    r
}

#[test]
fn bands_from_score() {
    assert_eq!(Severity::from_score(14), Severity::Info);
    assert_eq!(Severity::from_score(15), Severity::Low);
    assert_eq!(Severity::from_score(34), Severity::Low);
    assert_eq!(Severity::from_score(35), Severity::Medium);
    assert_eq!(Severity::from_score(59), Severity::Medium);
    assert_eq!(Severity::from_score(60), Severity::High);
    assert_eq!(Severity::from_score(84), Severity::High);
    assert_eq!(Severity::from_score(85), Severity::Critical);
}

#[test]
fn benign_web_is_info() {
    let s = score_flow(&rec(Category::Web), &FeedMatch::default());
    assert_eq!(s.severity, Severity::Info);
    assert_eq!(s.score, 0);
    assert!(s.evidence.iter().any(|e| e == "all-internal peers (-10)"));
}

#[test]
fn ioc_forces_high() {
    let s = score_flow(
        &rec(Category::Web),
        &FeedMatch {
            domain: true,
            ..Default::default()
        },
    );
    assert_eq!(s.severity, Severity::High);
    assert!(s.score >= 60);
    assert!(s
        .evidence
        .iter()
        .any(|e| e == "ioc: sni on threat feed (+35)"));
    assert!(s
        .evidence
        .iter()
        .any(|e| e == "floor: ioc match forces High (>= 60)"));
}

#[test]
fn ioc_plus_c2_forces_critical() {
    let mut r = rec(Category::C2);
    r.pkts_fwd = 3;
    r.pkts_rev = 3;
    r.bytes_fwd = 100;
    r.bytes_rev = 100;
    let s = score_flow(
        &r,
        &FeedMatch {
            ip: true,
            ..Default::default()
        },
    );
    assert_eq!(s.severity, Severity::Critical);
    assert!(s.score >= 90);
    assert_eq!(s.attack, vec!["T1071".to_string()]);
    assert!(s.evidence.iter().any(|e| e == "category c2 (+45)"));
    assert!(s
        .evidence
        .iter()
        .any(|e| e == "ioc: endpoint ip on threat feed (+35)"));
    assert!(s
        .evidence
        .iter()
        .any(|e| e == "floor: ioc + c2/anomalous forces Critical (>= 90)"));
}

/// Build a flow whose peer is a genuinely-public IP (so the externality term is +15, not the
/// all-internal -10). `rec()` alone is all-RFC1918.
fn external_rec(cat: Category) -> FlowRecord {
    let mut r = rec(cat);
    r.key.hi_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)); // public
    r
}

#[test]
fn heuristic_c2_external_without_corroboration_held_at_medium() {
    // A small, two-way flow to a public peer that the classifier labeled C2 purely by shape
    // (`app_proto_src == None`): +45 (c2) +15 (external) +10 (beacon-shaped) = 70, which would
    // otherwise land High. With no IOC corroboration it must be held at Medium so a weak
    // single-flow heuristic cannot flag a benign public IP as High.
    let mut r = external_rec(Category::C2);
    r.pkts_fwd = 3;
    r.pkts_rev = 3;
    r.bytes_fwd = 100;
    r.bytes_rev = 100;
    assert!(r.app_proto_src.is_none(), "shape-only C2 has no app-proto provenance");
    let s = score_flow(&r, &FeedMatch::default());
    assert_eq!(s.severity, Severity::Medium, "uncorroborated heuristic C2 caps at Medium");
    assert!(s.score <= 59, "score held below the High band, got {}", s.score);
    // The additive terms stay transparent; the cap is a reconciliation note, not a term.
    assert!(s.evidence.iter().any(|e| e == "category c2 (+45)"));
    assert!(s
        .evidence
        .iter()
        .any(|e| e.starts_with("cap: heuristic c2 candidate")));
}

#[test]
fn heuristic_c2_external_with_ioc_still_critical() {
    // The IOC floor is the corroboration path to Critical and must survive the cap.
    let mut r = external_rec(Category::C2);
    r.pkts_fwd = 3;
    r.pkts_rev = 3;
    r.bytes_fwd = 100;
    r.bytes_rev = 100;
    let s = score_flow(
        &r,
        &FeedMatch {
            ip: true,
            ..Default::default()
        },
    );
    assert_eq!(s.severity, Severity::Critical);
    assert!(s.score >= 90);
    assert!(
        !s.evidence.iter().any(|e| e.starts_with("cap:")),
        "an IOC-corroborated C2 is never capped"
    );
}

#[test]
fn confident_c2_external_reaches_high() {
    // A future DPI-confident C2 (non-null app_proto_src) is NOT a mere shape candidate, so the
    // cap does not apply and it reaches High on points: +45 +15 +10 = 70.
    let mut r = external_rec(Category::C2);
    r.pkts_fwd = 3;
    r.pkts_rev = 3;
    r.bytes_fwd = 100;
    r.bytes_rev = 100;
    r.app_proto_src = Some("payload");
    let s = score_flow(&r, &FeedMatch::default());
    assert_eq!(s.severity, Severity::High);
    assert!(s.score >= 60);
    assert!(!s.evidence.iter().any(|e| e.starts_with("cap:")));
}

#[test]
fn network_service_external_is_benign() {
    // NTP/DHCP/SNMP/etc. to a public server: +3 (benign category) +15 (external) = 18 -> Low.
    // No C2 term, no confidence cap — the category itself is now benign.
    let mut r = external_rec(Category::NetworkService);
    r.pkts_fwd = 3;
    r.pkts_rev = 3;
    r.bytes_fwd = 100;
    r.bytes_rev = 100;
    let s = score_flow(&r, &FeedMatch::default());
    assert_eq!(s.severity, Severity::Low);
    assert!(s.evidence.iter().any(|e| e == "category network_service (+3)"));
    assert!(!s.evidence.iter().any(|e| e.starts_with("cap:")));
}

#[test]
fn scan_shaped_evidence() {
    let mut r = rec(Category::Scan);
    r.pkts_fwd = 1;
    r.pkts_rev = 0;
    let s = score_flow(&r, &FeedMatch::default());
    assert!(s.evidence.iter().any(|e| e == "category scan (+25)"));
    assert!(s
        .evidence
        .iter()
        .any(|e| e == "behavior: scan-shaped probe (+10)"));
    assert_eq!(s.severity, Severity::Low);
}

#[test]
fn evidence_strings_are_exact() {
    let s = score_flow(&rec(Category::Unknown), &FeedMatch::default());
    assert!(s.evidence.iter().any(|e| e == "category unknown (+0)"));
}

#[test]
fn score_never_exceeds_100() {
    let mut r = rec(Category::C2);
    r.pkts_fwd = 3;
    r.pkts_rev = 3;
    r.bytes_fwd = 100;
    r.bytes_rev = 100;
    let s = score_flow(
        &r,
        &FeedMatch {
            ip: true,
            domain: true,
            ..Default::default()
        },
    );
    assert!(s.score <= 100);
}
