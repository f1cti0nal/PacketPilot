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
