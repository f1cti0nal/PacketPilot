//! Offline threat enrichment: IP address-space classification + a local JSON IOC feed +
//! MITRE ATT&CK technique mapping.
//!
//! Everything here is pure / offline-first. The only I/O is reading the threat-feed JSON
//! once at run start ([`ThreatFeed::load`]); after that, enrichment is allocation-light
//! (evidence strings are built only when an indicator actually matches). A
//! [`ReputationProvider`] trait documents the Phase-3 online seam but is NOT wired into the
//! pipeline — real providers need a key + network and would return nothing on the synthetic
//! RFC1918/RFC5737 corpus, so they are intentionally omitted.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::model::category::Category;
use crate::model::flow::FlowRecord;
use crate::{PpError, Result};

// ---------------------------------------------------------------------------------------
// IP address-space classification (pure; IPv4 + IPv6).
// ---------------------------------------------------------------------------------------

/// Address-space classification of one IP. Pure; no I/O. `as_str` is kebab-case (UI/JSON);
/// serde kebab-case mirrors `Category`'s wire convention.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum IpClass {
    Private,
    Loopback,
    LinkLocal,
    Cgnat,
    Multicast,
    Documentation,
    Reserved,
    #[default]
    Public,
}

impl IpClass {
    /// Stable kebab-case token used in JSON/UI.
    pub fn as_str(self) -> &'static str {
        match self {
            IpClass::Private => "private",
            IpClass::Loopback => "loopback",
            IpClass::LinkLocal => "link-local",
            IpClass::Cgnat => "cgnat",
            IpClass::Multicast => "multicast",
            IpClass::Documentation => "documentation",
            IpClass::Reserved => "reserved",
            IpClass::Public => "public",
        }
    }

    /// Only fully routable space counts as "external"; CGNAT/doc/reserved do NOT raise score.
    pub fn is_external(self) -> bool {
        matches!(self, IpClass::Public)
    }
}

/// Classify an [`IpAddr`] into its address-space [`IpClass`].
///
/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is looked through to its IPv4 class so the trust
/// decision is consistent regardless of how the endpoint was encoded.
pub fn classify_ip(ip: IpAddr) -> IpClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify_v4(v4);
            }
            classify_v6(v6)
        }
    }
}

fn classify_v4(a: Ipv4Addr) -> IpClass {
    let o = a.octets();
    if a.is_loopback() {
        return IpClass::Loopback; // 127/8
    }
    if a.is_link_local() {
        return IpClass::LinkLocal; // 169.254/16
    }
    if a.is_private() {
        return IpClass::Private; // 10/8, 172.16/12, 192.168/16
    }
    if o[0] == 100 && (o[1] & 0xC0) == 0x40 {
        return IpClass::Cgnat; // 100.64/10
    }
    if a.is_multicast() {
        return IpClass::Multicast; // 224/4
    }
    if a.is_documentation() {
        return IpClass::Documentation; // RFC5737
    }
    if o[0] == 0 || o[0] >= 240 || a.is_broadcast() {
        return IpClass::Reserved; // 0/8, 240/4, 255.255.255.255
    }
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return IpClass::Reserved; // 192.0.0/24 IETF protocol assignments
    }
    IpClass::Public
}

fn classify_v6(a: Ipv6Addr) -> IpClass {
    if a.is_loopback() {
        return IpClass::Loopback;
    }
    if a == Ipv6Addr::UNSPECIFIED {
        return IpClass::Reserved;
    }
    let s = a.segments();
    if (s[0] & 0xffc0) == 0xfe80 {
        return IpClass::LinkLocal; // fe80::/10
    }
    if (s[0] & 0xfe00) == 0xfc00 {
        return IpClass::Private; // ULA fc00::/7
    }
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return IpClass::Documentation; // 2001:db8::/32
    }
    if a.is_multicast() {
        return IpClass::Multicast; // ff00::/8
    }
    IpClass::Public
}

// ---------------------------------------------------------------------------------------
// Threat feed: local JSON IOC store.
// ---------------------------------------------------------------------------------------

/// On-disk JSON shape of a threat feed. All fields default so a partial file still loads.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ThreatFeedFile {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub bad_ips: Vec<String>,
    #[serde(default)]
    pub bad_cidrs: Vec<String>,
    /// Exact host (case-insensitive, trailing dot ignored).
    #[serde(default)]
    pub bad_domains: Vec<String>,
    /// Suffix like `".evil.example"` (label-boundary safe).
    #[serde(default)]
    pub bad_suffixes: Vec<String>,
    #[serde(default)]
    pub bad_ja3: Vec<String>,
}

/// A parsed CIDR network (family + prefix length).
struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(q)) => masked_eq(&n.octets(), &q.octets(), self.prefix),
            (IpAddr::V6(n), IpAddr::V6(q)) => masked_eq(&n.octets(), &q.octets(), self.prefix),
            _ => false,
        }
    }
}

/// Compare the first `prefix` bits of two equal-length octet slices.
fn masked_eq(net: &[u8], q: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if net[..full] != q[..full] {
        return false;
    }
    let rem = prefix % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - rem);
    (net[full] & mask) == (q[full] & mask)
}

/// Canonicalize an [`IpAddr`] by looking an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`)
/// through to its native IPv4 form. This keeps IOC matching consistent with
/// [`classify_ip`] regardless of how the endpoint was encoded, so a feed listing a plain v4
/// indicator still matches a mapped-v6 query (and vice versa).
fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

/// Lowercase a host and strip a single trailing dot for canonical comparison.
fn normalize_host(h: &str) -> String {
    let h = h.strip_suffix('.').unwrap_or(h);
    h.to_ascii_lowercase()
}

/// Does `h` end at `s` (a leading-dot suffix like `.evil.example`) on a label boundary?
fn host_has_suffix(h: &str, s: &str) -> bool {
    let bare = s.strip_prefix('.').unwrap_or(s);
    h == bare || h.ends_with(s)
}

/// A loaded, queryable IOC feed. All collections are normalized at load.
pub struct ThreatFeed {
    label: String,
    ips: HashSet<IpAddr>,
    cidrs: Vec<Cidr>,
    domains: HashSet<String>, // lowercased, trailing-dot stripped
    suffixes: Vec<String>,    // lowercased, leading '.'
    ja3: HashSet<String>,     // lowercased
}

impl ThreatFeed {
    /// An empty feed (matches nothing). Used when no `--threat-feed` is supplied.
    pub fn empty() -> ThreatFeed {
        ThreatFeed {
            label: String::new(),
            ips: HashSet::new(),
            cidrs: Vec::new(),
            domains: HashSet::new(),
            suffixes: Vec::new(),
            ja3: HashSet::new(),
        }
    }

    /// Load + parse a feed JSON from `path`. Fails fast on IO, JSON, or a malformed indicator
    /// so a typo cannot silently disarm detection.
    pub fn load(path: &Path) -> Result<ThreatFeed> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| PpError::io(format!("read threat feed {}", path.display()), e))?;
        let file: ThreatFeedFile = serde_json::from_str(&text)?;
        ThreatFeed::from_file(file)
    }

    /// `None` => an empty feed; `Some(p)` => [`ThreatFeed::load`]. The pipeline calls this.
    pub fn load_opt(path: Option<&Path>) -> Result<ThreatFeed> {
        match path {
            Some(p) => ThreatFeed::load(p),
            None => Ok(ThreatFeed::empty()),
        }
    }

    /// Build a feed from a JSON string (same shape as [`ThreatFeed::load`]). Useful for
    /// tests and in-memory feeds.
    pub fn from_json_str(s: &str) -> Result<ThreatFeed> {
        let file: ThreatFeedFile = serde_json::from_str(s)?;
        ThreatFeed::from_file(file)
    }

    /// Build a feed from an already-parsed [`ThreatFeedFile`], validating every indicator.
    pub fn from_file(f: ThreatFeedFile) -> Result<ThreatFeed> {
        let mut ips = HashSet::new();
        for s in &f.bad_ips {
            let ip: IpAddr = s
                .trim()
                .parse()
                .map_err(|_| PpError::Config(format!("threat feed: bad indicator {s}")))?;
            // Store the canonical form so a mapped-v6 entry matches a native-v4 query.
            ips.insert(canonicalize_ip(ip));
        }

        let mut cidrs = Vec::new();
        for s in &f.bad_cidrs {
            cidrs.push(parse_cidr(s)?);
        }

        let mut domains = HashSet::new();
        for d in &f.bad_domains {
            domains.insert(normalize_host(d.trim()));
        }

        let mut suffixes = Vec::new();
        for s in &f.bad_suffixes {
            let s = s.trim().to_ascii_lowercase();
            // Ensure a leading dot so matching is label-boundary safe.
            let s = if s.starts_with('.') {
                s
            } else {
                format!(".{s}")
            };
            suffixes.push(s);
        }

        let ja3 = f
            .bad_ja3
            .iter()
            .map(|j| j.trim().to_ascii_lowercase())
            .collect();

        Ok(ThreatFeed {
            label: f.label,
            ips,
            cidrs,
            domains,
            suffixes,
            ja3,
        })
    }

    /// True when the feed contains no indicators at all.
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty()
            && self.cidrs.is_empty()
            && self.domains.is_empty()
            && self.suffixes.is_empty()
            && self.ja3.is_empty()
    }

    /// The feed's free-text label (provenance).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Exact-IP match OR any CIDR containing `ip`.
    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        // Normalize the query the same way indicators are stored so an IPv4-mapped IPv6
        // endpoint matches a native-v4 indicator/CIDR and vice versa.
        let ip = canonicalize_ip(ip);
        self.ips.contains(&ip) || self.cidrs.iter().any(|c| c.contains(ip))
    }

    /// Exact-domain (case-insensitive, dot-stripped) OR any configured suffix.
    pub fn matches_domain(&self, host: &str) -> bool {
        let h = normalize_host(host);
        if self.domains.contains(&h) {
            return true;
        }
        self.suffixes.iter().any(|s| host_has_suffix(&h, s))
    }

    /// Exact JA3 (case-insensitive) match.
    pub fn matches_ja3(&self, ja3: &str) -> bool {
        self.ja3.contains(&ja3.to_ascii_lowercase())
    }
}

/// Parse a `"net/prefix"` CIDR string, validating the prefix against the address family.
fn parse_cidr(s: &str) -> Result<Cidr> {
    let s = s.trim();
    let (net_s, pfx_s) = s
        .split_once('/')
        .ok_or_else(|| PpError::Config(format!("threat feed: bad indicator {s}")))?;
    let net: IpAddr = net_s
        .parse()
        .map_err(|_| PpError::Config(format!("threat feed: bad indicator {s}")))?;
    let prefix: u8 = pfx_s
        .parse()
        .map_err(|_| PpError::Config(format!("threat feed: bad indicator {s}")))?;
    let max = match net {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        return Err(PpError::Config(format!("threat feed: bad indicator {s}")));
    }
    // Canonicalize an IPv4-mapped IPv6 network down to native v4 so it matches native-v4
    // queries. The mapped prefix consumes the 96-bit ::ffff: header, so the equivalent v4
    // prefix is prefix - 96 (a /128 -> /32). Only do this when the prefix covers the full
    // header (>= 96); a shorter prefix spans into the header bits and cannot be expressed as
    // a v4 network, so it is left as the original v6 form.
    let (net, prefix) = match canonicalize_ip(net) {
        IpAddr::V4(v4) if prefix >= 96 => (IpAddr::V4(v4), prefix - 96),
        _ => (net, prefix),
    };
    Ok(Cidr { net, prefix })
}

// ---------------------------------------------------------------------------------------
// MITRE ATT&CK mapping.
// ---------------------------------------------------------------------------------------

/// A MITRE ATT&CK technique (id + display name).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttackTechnique {
    pub id: &'static str,
    pub name: &'static str,
}

/// Map a traffic [`Category`] to its representative ATT&CK technique, if any.
pub fn attack_for(cat: Category) -> Option<AttackTechnique> {
    use Category::*;
    Some(match cat {
        Scan => AttackTechnique {
            id: "T1046",
            name: "Network Service Discovery",
        },
        C2 => AttackTechnique {
            id: "T1071",
            name: "Application Layer Protocol",
        },
        TunnelVpn => AttackTechnique {
            id: "T1572",
            name: "Protocol Tunneling",
        },
        Anomalous => AttackTechnique {
            id: "T1095",
            name: "Non-Application Layer Protocol",
        },
        Web | Dns | Email | FileTransfer | RemoteAccess | Voip | IotOt | Unknown => return None,
    })
}

// ---------------------------------------------------------------------------------------
// Reputation types (always-compiled; extended struct lives in `reputation` module).
// ---------------------------------------------------------------------------------------

pub mod reputation;
pub use reputation::{apply_domain_reputation, apply_reputation, RepStatus, ReputationVerdict};

#[cfg(feature = "online")]
pub mod online;

/// Online IP/domain reputation. NOT wired into the Phase-2 pipeline. Real providers
/// (AbuseIPDB/GreyNoise/VirusTotal) need a key + network and would return nothing on
/// RFC1918/RFC5737 synthetic IPs, so they are intentionally omitted (offline-first). They
/// would live behind a future `enrich::online` cargo feature.
pub trait ReputationProvider {
    fn lookup_ip(&self, ip: IpAddr) -> Option<ReputationVerdict>;
    fn lookup_domain(&self, host: &str) -> Option<ReputationVerdict>;
}

/// The default, do-nothing reputation provider (offline).
pub struct NoopReputation;

impl ReputationProvider for NoopReputation {
    fn lookup_ip(&self, _ip: IpAddr) -> Option<ReputationVerdict> {
        None
    }
    fn lookup_domain(&self, _host: &str) -> Option<ReputationVerdict> {
        None
    }
}

// ---------------------------------------------------------------------------------------
// Enricher + per-flow enrichment.
// ---------------------------------------------------------------------------------------

/// Per-flow enrichment derived from address classes + the threat feed.
#[derive(Debug, Clone, Default)]
pub struct FlowEnrichment {
    pub lo_class: IpClass,
    pub hi_class: IpClass,
    pub ip_ioc: bool,
    pub domain_ioc: bool,
    /// Reserved; always false in Phase 2 (no JA3 on `FlowRecord` yet).
    pub ja3_ioc: bool,
    /// Human-readable matched indicators, e.g. `["ip 10.0.5.10", "sni auth.bank.example"]`.
    pub ioc_labels: Vec<String>,
}

impl FlowEnrichment {
    /// Whether any IOC matched this flow.
    pub fn any_ioc(&self) -> bool {
        self.ip_ioc || self.domain_ioc || self.ja3_ioc
    }
}

/// Compact feed-match summary the scorer consumes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FeedMatch {
    pub ip: bool,
    pub domain: bool,
}

impl FeedMatch {
    /// Whether either an IP or a domain indicator matched.
    pub fn any(self) -> bool {
        self.ip || self.domain
    }
}

/// Owns the loaded feed (and the offline reputation provider) and enriches flows.
pub struct Enricher {
    feed: ThreatFeed,
    #[allow(dead_code)]
    rep: Box<dyn ReputationProvider + Send + Sync>,
}

impl Enricher {
    /// Build an enricher around a loaded feed (offline reputation provider).
    pub fn new(feed: ThreatFeed) -> Enricher {
        Enricher {
            feed,
            rep: Box::new(NoopReputation),
        }
    }

    /// An enricher with an empty feed (no enrichment).
    pub fn offline() -> Enricher {
        Enricher::new(ThreatFeed::empty())
    }

    /// The underlying feed (for callers that want its label / emptiness).
    pub fn feed(&self) -> &ThreatFeed {
        &self.feed
    }

    /// Classify both endpoints and match the feed against IPs + SNI. Allocates evidence
    /// strings only when an indicator actually matches.
    pub fn enrich(&self, rec: &FlowRecord) -> FlowEnrichment {
        let mut e = FlowEnrichment {
            lo_class: classify_ip(rec.key.lo_ip),
            hi_class: classify_ip(rec.key.hi_ip),
            ..Default::default()
        };
        if self.feed.matches_ip(rec.key.lo_ip) {
            e.ip_ioc = true;
            e.ioc_labels.push(format!("ip {}", rec.key.lo_ip));
        }
        if self.feed.matches_ip(rec.key.hi_ip) {
            e.ip_ioc = true;
            e.ioc_labels.push(format!("ip {}", rec.key.hi_ip));
        }
        if let Some(h) = &rec.sni {
            if self.feed.matches_domain(h) {
                e.domain_ioc = true;
                e.ioc_labels.push(format!("sni {h}"));
            }
        }
        e
    }

    /// Compact match summary for the scorer.
    pub fn feed_match(&self, e: &FlowEnrichment) -> FeedMatch {
        FeedMatch {
            ip: e.ip_ioc,
            domain: e.domain_ioc,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ipv4_class_table() {
        assert_eq!(classify_ip(ip("10.0.0.10")), IpClass::Private);
        assert_eq!(classify_ip(ip("172.16.5.1")), IpClass::Private);
        assert_eq!(classify_ip(ip("192.168.1.1")), IpClass::Private);
        assert_eq!(classify_ip(ip("127.0.0.1")), IpClass::Loopback);
        assert_eq!(classify_ip(ip("169.254.1.1")), IpClass::LinkLocal);
        assert_eq!(classify_ip(ip("100.64.0.1")), IpClass::Cgnat);
        assert_eq!(classify_ip(ip("100.127.255.255")), IpClass::Cgnat);
        assert_eq!(classify_ip(ip("100.128.0.1")), IpClass::Public);
        assert_eq!(classify_ip(ip("224.0.0.1")), IpClass::Multicast);
        assert_eq!(classify_ip(ip("192.0.2.5")), IpClass::Documentation);
        assert_eq!(classify_ip(ip("198.51.100.5")), IpClass::Documentation);
        assert_eq!(classify_ip(ip("203.0.113.5")), IpClass::Documentation);
        assert_eq!(classify_ip(ip("0.1.2.3")), IpClass::Reserved);
        assert_eq!(classify_ip(ip("240.0.0.1")), IpClass::Reserved);
        assert_eq!(classify_ip(ip("255.255.255.255")), IpClass::Reserved);
        assert_eq!(classify_ip(ip("8.8.8.8")), IpClass::Public);
    }

    #[test]
    fn ipv6_class_table() {
        assert_eq!(classify_ip(ip("::1")), IpClass::Loopback);
        assert_eq!(classify_ip(ip("fe80::1")), IpClass::LinkLocal);
        assert_eq!(classify_ip(ip("fc00::1")), IpClass::Private);
        assert_eq!(classify_ip(ip("fd12::1")), IpClass::Private);
        assert_eq!(classify_ip(ip("ff02::1")), IpClass::Multicast);
        assert_eq!(classify_ip(ip("2001:db8::1")), IpClass::Documentation);
        assert_eq!(classify_ip(ip("2606:4700::1")), IpClass::Public);
        assert_eq!(classify_ip(ip("::ffff:10.0.0.1")), IpClass::Private);
        assert_eq!(classify_ip(ip("::")), IpClass::Reserved);
    }

    fn feed() -> ThreatFeed {
        ThreatFeed::from_file(ThreatFeedFile {
            version: 1,
            label: "t".into(),
            bad_ips: vec!["10.0.5.10".into()],
            bad_cidrs: vec!["10.0.5.0/24".into(), "2001:db8:bad::/48".into()],
            bad_domains: vec!["auth.bank.example".into()],
            bad_suffixes: vec![".evil.example".into()],
            bad_ja3: vec![],
        })
        .unwrap()
    }

    #[test]
    fn ip_and_cidr_matching() {
        let f = feed();
        assert!(f.matches_ip(ip("10.0.5.10")));
        assert!(f.matches_ip(ip("10.0.5.200"))); // via /24
        assert!(!f.matches_ip(ip("10.0.6.10")));
        assert!(f.matches_ip(ip("2001:db8:bad::1")));
        assert!(!f.matches_ip(ip("2001:db8:dead::1")));
    }

    #[test]
    fn ipv4_mapped_ipv6_matches_native_v4_indicator() {
        let f = feed();
        // A native-v4 indicator/CIDR must match the IPv4-mapped IPv6 encoding of the same
        // endpoint, consistent with classify_ip looking through the mapping.
        assert!(f.matches_ip(ip("::ffff:10.0.5.10"))); // exact-IP via mapping
        assert!(f.matches_ip(ip("::ffff:10.0.5.200"))); // /24 CIDR via mapping
        assert!(!f.matches_ip(ip("::ffff:10.0.6.10")));

        // And the reverse: a feed authored with a mapped-v6 indicator/CIDR matches native v4.
        let g = ThreatFeed::from_file(ThreatFeedFile {
            version: 1,
            label: "t".into(),
            bad_ips: vec!["::ffff:1.2.3.4".into()],
            bad_cidrs: vec!["::ffff:1.2.3.0/120".into()],
            bad_domains: vec![],
            bad_suffixes: vec![],
            bad_ja3: vec![],
        })
        .unwrap();
        assert!(g.matches_ip(ip("1.2.3.4")));
        assert!(g.matches_ip(ip("1.2.3.99"))); // /120 mapped == v4 /24
        assert!(!g.matches_ip(ip("1.2.4.4")));
    }

    #[test]
    fn domain_and_suffix_matching() {
        let f = feed();
        assert!(f.matches_domain("auth.bank.example"));
        assert!(f.matches_domain("AUTH.BANK.EXAMPLE"));
        assert!(f.matches_domain("auth.bank.example."));
        assert!(f.matches_domain("x.evil.example"));
        assert!(f.matches_domain("evil.example"));
        assert!(!f.matches_domain("notevil.example"));
        assert!(!ThreatFeed::empty().matches_domain("auth.bank.example"));
    }

    #[test]
    fn attack_mapping() {
        assert_eq!(attack_for(Category::Scan).unwrap().id, "T1046");
        assert_eq!(attack_for(Category::C2).unwrap().id, "T1071");
        assert_eq!(attack_for(Category::TunnelVpn).unwrap().id, "T1572");
        assert_eq!(attack_for(Category::Anomalous).unwrap().id, "T1095");
        assert!(attack_for(Category::Web).is_none());
        assert!(attack_for(Category::Dns).is_none());
        assert!(attack_for(Category::Unknown).is_none());
    }
}
