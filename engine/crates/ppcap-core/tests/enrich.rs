//! Black-box tests for the offline enrichment surface: IP class table, IOC feed matching
//! (exact IP / CIDR v4+v6 / domain / suffix), and the ATT&CK mapping.

use std::net::IpAddr;

use ppcap_core::enrich::{attack_for, classify_ip, IpClass, ThreatFeed, ThreatFeedFile};
use ppcap_core::Category;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn ip_class_table() {
    // IPv4.
    assert_eq!(classify_ip(ip("10.0.0.10")), IpClass::Private);
    assert_eq!(classify_ip(ip("172.16.5.1")), IpClass::Private);
    assert_eq!(classify_ip(ip("192.168.1.1")), IpClass::Private);
    assert_eq!(classify_ip(ip("127.0.0.1")), IpClass::Loopback);
    assert_eq!(classify_ip(ip("169.254.1.1")), IpClass::LinkLocal);
    assert_eq!(classify_ip(ip("100.64.0.1")), IpClass::Cgnat);
    assert_eq!(classify_ip(ip("100.127.255.255")), IpClass::Cgnat);
    assert_eq!(classify_ip(ip("100.128.0.1")), IpClass::Public); // boundary
    assert_eq!(classify_ip(ip("224.0.0.1")), IpClass::Multicast);
    assert_eq!(classify_ip(ip("192.0.2.5")), IpClass::Documentation);
    assert_eq!(classify_ip(ip("198.51.100.5")), IpClass::Documentation);
    assert_eq!(classify_ip(ip("203.0.113.5")), IpClass::Documentation);
    assert_eq!(classify_ip(ip("0.1.2.3")), IpClass::Reserved);
    assert_eq!(classify_ip(ip("240.0.0.1")), IpClass::Reserved);
    assert_eq!(classify_ip(ip("255.255.255.255")), IpClass::Reserved);
    assert_eq!(classify_ip(ip("8.8.8.8")), IpClass::Public);
    // IPv6.
    assert_eq!(classify_ip(ip("::1")), IpClass::Loopback);
    assert_eq!(classify_ip(ip("fe80::1")), IpClass::LinkLocal);
    assert_eq!(classify_ip(ip("fc00::1")), IpClass::Private);
    assert_eq!(classify_ip(ip("fd12::1")), IpClass::Private);
    assert_eq!(classify_ip(ip("ff02::1")), IpClass::Multicast);
    assert_eq!(classify_ip(ip("2001:db8::1")), IpClass::Documentation);
    assert_eq!(classify_ip(ip("2606:4700::1")), IpClass::Public);
    assert_eq!(classify_ip(ip("::ffff:10.0.0.1")), IpClass::Private); // mapped look-through
    assert_eq!(classify_ip(ip("::")), IpClass::Reserved);

    // Public and CGNAT (carrier space) are "external"; private + doc/reserved stay internal.
    assert!(classify_ip(ip("8.8.8.8")).is_external());
    assert!(!classify_ip(ip("10.0.0.10")).is_external());
    assert!(
        classify_ip(ip("100.64.0.1")).is_external(),
        "CGNAT is a real off-network peer"
    );
    assert!(
        !classify_ip(ip("203.0.113.5")).is_external(),
        "RFC5737 documentation ranges stay internal"
    );
}

fn demo_feed() -> ThreatFeed {
    ThreatFeed::from_file(ThreatFeedFile {
        version: 1,
        label: "test".into(),
        bad_ips: vec!["10.0.5.10".into()],
        bad_cidrs: vec!["10.0.5.0/24".into(), "2001:db8:bad::/48".into()],
        bad_domains: vec!["auth.bank.example".into()],
        bad_suffixes: vec![".evil.example".into()],
        bad_ja3: vec![],
        bad_ja4: vec![],
    })
    .expect("feed builds")
}

#[test]
fn ip_ioc_matching_exact_and_cidr() {
    let f = demo_feed();
    assert!(f.matches_ip(ip("10.0.5.10")));
    assert!(f.matches_ip(ip("10.0.5.200"))); // via /24
    assert!(!f.matches_ip(ip("10.0.6.10")));
    assert!(f.matches_ip(ip("2001:db8:bad::1"))); // CIDR v6
    assert!(!f.matches_ip(ip("2001:db8:dead::1")));
}

#[test]
fn domain_ioc_matching_exact_and_suffix() {
    let f = demo_feed();
    assert!(f.matches_domain("auth.bank.example"));
    assert!(f.matches_domain("AUTH.BANK.EXAMPLE")); // case-insensitive
    assert!(f.matches_domain("auth.bank.example.")); // trailing dot
    assert!(f.matches_domain("x.evil.example")); // suffix
    assert!(f.matches_domain("evil.example")); // bare suffix matches
    assert!(!f.matches_domain("notevil.example")); // label-boundary safe
}

#[test]
fn empty_feed_matches_nothing() {
    // empty() now seeds the embedded builtin fingerprint set (ja3/ja4), so is_empty() returns
    // false. IP/domain matching is still absent because builtins contain only fingerprints.
    let f = ThreatFeed::empty();
    assert!(!f.is_empty()); // builtins are present
    assert!(!f.matches_ip(ip("10.0.5.10")));
    assert!(!f.matches_domain("auth.bank.example"));
}

#[test]
fn loads_shipped_sample_feed() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("data/sample_iocs.json");
    let f = ThreatFeed::load(&path).expect("sample feed loads");
    assert!(!f.is_empty());
    assert!(f.matches_ip(ip("10.0.0.10")));
    assert!(f.matches_ip(ip("10.0.5.10")));
    assert!(f.matches_domain("auth.bank.example"));
}

#[test]
fn attack_mapping_table() {
    assert_eq!(attack_for(Category::Scan).unwrap().id, "T1046");
    assert_eq!(attack_for(Category::C2).unwrap().id, "T1071");
    assert_eq!(attack_for(Category::TunnelVpn).unwrap().id, "T1572");
    assert_eq!(attack_for(Category::Anomalous).unwrap().id, "T1095");
    assert!(attack_for(Category::Web).is_none());
    assert!(attack_for(Category::Dns).is_none());
    assert!(attack_for(Category::Unknown).is_none());
}
