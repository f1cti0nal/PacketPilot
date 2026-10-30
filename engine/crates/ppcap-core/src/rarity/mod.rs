//! Environment rarity — "what is new to this network?" across the case history.
//!
//! The per-host baseline ([`crate::baseline`]) asks whether a *host* did something it never did
//! before. This module asks the network-wide question: has *anyone here* ever resolved this domain,
//! presented this JA4/JA3 client fingerprint, sent this User-Agent, been served this certificate, or
//! reached this external address? It reuses the same offline baseline sidecar, so a solo analyst
//! and a SOC team share history the same way: by passing the JSON file around.
//!
//! Pipeline:
//! 1. [`EnvTracker`] folds sightings during the streaming pass (bounded: [`MAX_ENV_ITEMS`] values,
//!    [`MAX_HOSTS_PER_ITEM`] hosts each). Only sightings attributed to an internal host count.
//! 2. [`EnvTracker::snapshot`] projects them onto [`crate::baseline::CaptureProfile::environment`];
//!    [`crate::baseline::update_baseline`] folds that into the sidecar's network-wide history.
//! 3. [`rarity_report`] diffs the snapshot against the history: the "new to this network" list
//!    (gated on [`crate::baseline::BaselineParams::min_env_captures`] so a young baseline never
//!    calls everything new) and the "only one host" list (works with no history at all).
//! 4. [`combo_findings`] raises one `BaselineDeviation` finding per host only when new client
//!    software and a new place line up on that host — a lone new domain is context, not an alert.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::baseline::{BaselineParams, BaselineProfile};
use crate::enrich::{classify_ip, IpClass};
use crate::model::finding::{Finding, FindingKind};
use crate::score::{score_baseline_deviation, PTS_ENV_NEW_PLACE, PTS_ENV_NEW_SOFTWARE};

/// Cap on distinct `(kind, value)` sightings tracked per capture. A brand-new value at capacity is
/// dropped and counted in [`EnvSnapshot::dropped`].
pub const MAX_ENV_ITEMS: usize = 16_384;
/// Cap on internal hosts remembered per sighting (the "how widespread" signal saturates here).
pub const MAX_HOSTS_PER_ITEM: usize = 16;
/// Cap on external peers remembered per domain (the SNI / HTTP Host to address link alerts join on).
pub const MAX_PEERS_PER_ITEM: usize = 8;
/// Cap on distinct internal hosts counted for the single-host gate.
const MAX_INTERNAL_HOSTS: usize = 65_536;
/// Longest stored value (User-Agents can be arbitrarily long); truncated on a char boundary.
const MAX_VALUE_CHARS: usize = 256;
/// Rows kept per report list (the `*_total` counters keep the exact count).
pub const MAX_REPORT_ITEMS: usize = 100;
/// "Only one host" needs a population to be meaningful: below this many internal hosts every
/// value is trivially single-host.
pub const MIN_HOSTS_FOR_SINGLE: u64 = 5;

/// What kind of environment indicator a sighting is. Declaration order is the report order.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorKind {
    /// TLS JA4 client fingerprint.
    Ja4,
    /// TLS JA3 client fingerprint.
    Ja3,
    /// HTTP User-Agent.
    UserAgent,
    /// Server leaf certificate, by SHA-256 of its DER (label: subject CN).
    Cert,
    /// Registered domain from a DNS query, TLS SNI or HTTP Host (label: first full name seen).
    #[default]
    Domain,
    /// External destination IP an internal host connected to.
    Destination,
}

impl IndicatorKind {
    /// Human phrase for evidence strings.
    pub fn phrase(self) -> &'static str {
        match self {
            IndicatorKind::Ja4 => "JA4 fingerprint",
            IndicatorKind::Ja3 => "JA3 fingerprint",
            IndicatorKind::UserAgent => "user agent",
            IndicatorKind::Cert => "server certificate",
            IndicatorKind::Domain => "domain",
            IndicatorKind::Destination => "external destination",
        }
    }

    /// Client-side software identity (a new tool or stack on the host).
    pub fn is_software(self) -> bool {
        matches!(
            self,
            IndicatorKind::Ja4 | IndicatorKind::Ja3 | IndicatorKind::UserAgent
        )
    }
}

/// One environment value observed in a single capture — the snapshot row.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EnvObservation {
    pub kind: IndicatorKind,
    pub value: String,
    /// Display hint: the full name for a domain, the subject CN for a certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Internal hosts that produced the sighting, sorted, at most [`MAX_HOSTS_PER_ITEM`].
    pub hosts: Vec<String>,
    /// True when more hosts than `hosts` lists were seen.
    #[serde(default)]
    pub hosts_truncated: bool,
    /// Sightings this capture.
    pub count: u64,
    /// First sighting this capture (ns since epoch; `0` when untimed).
    #[serde(default)]
    pub first_ts_ns: i64,
    /// For a domain named in TLS SNI or HTTP Host: the external addresses it was reached at
    /// (sorted, at most [`MAX_PEERS_PER_ITEM`]). Lets an alert on that address name the domain
    /// even when no DNS answer was captured.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<String>,
}

/// This capture's environment sightings. Carried on [`crate::baseline::CaptureProfile`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EnvSnapshot {
    /// Sorted by `(kind, value)`.
    #[serde(default)]
    pub items: Vec<EnvObservation>,
    /// Distinct internal hosts that produced any sighting (saturates at a large cap).
    #[serde(default)]
    pub internal_hosts: u64,
    /// New values dropped at the tracker cap (the snapshot is incomplete when non-zero).
    #[serde(default)]
    pub dropped: u64,
}

impl EnvSnapshot {
    pub fn is_empty(&self) -> bool {
        self.items.is_empty() && self.internal_hosts == 0 && self.dropped == 0
    }
}

#[derive(Debug, Default)]
struct EnvItem {
    hosts: BTreeSet<IpAddr>,
    hosts_truncated: bool,
    count: u64,
    first_ts_ns: i64,
    label: Option<String>,
    peers: BTreeSet<IpAddr>,
}

/// Streaming, bounded collector of environment sightings.
#[derive(Debug, Default)]
pub struct EnvTracker {
    items: HashMap<(IndicatorKind, String), EnvItem>,
    internal_hosts: std::collections::HashSet<IpAddr>,
    dropped: u64,
}

/// True for an address that is one of the monitored network's own hosts: the same "not external"
/// rule the per-host baseline uses, minus multicast and loopback (never a real client).
fn is_internal_host(ip: IpAddr) -> bool {
    let class = classify_ip(ip);
    !class.is_external() && !matches!(class, IpClass::Multicast | IpClass::Loopback)
}

/// Truncate to [`MAX_VALUE_CHARS`] on a char boundary.
fn clip(s: &str) -> String {
    match s.char_indices().nth(MAX_VALUE_CHARS) {
        Some((i, _)) => s[..i].to_string(),
        None => s.to_string(),
    }
}

/// Two-label public suffixes common enough that `name.co.uk` must not collapse to `co.uk`.
/// Not a full public-suffix list (that would be a large embedded table); unlisted multi-part
/// suffixes degrade to the last two labels, which only makes those domains coarser.
const MULTI_PART_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk", "com.au",
    "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "ac.jp",
    "co.za", "co.in", "net.in", "org.in", "co.kr", "or.kr", "com.br", "net.br", "com.cn", "net.cn",
    "org.cn", "com.mx", "com.tr", "com.sg", "com.hk", "com.tw", "com.ar", "co.il", "com.my",
    "co.id", "com.ua", "com.pl", "com.ru", "co.th", "com.vn", "com.ph",
];

/// Normalize a DNS name, SNI or HTTP Host into its registered domain. Strips a port and trailing
/// dot, lowercases, and drops IP literals, single-label names, reverse lookups and mDNS names.
pub fn registered_domain(name: &str) -> Option<String> {
    let mut s = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.starts_with('[') {
        return None; // bracketed IPv6 literal (HTTP Host form)
    }
    if let Some((host, port)) = s.rsplit_once(':') {
        if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && !host.contains(':') {
            s = host.to_string();
        }
    }
    if s.is_empty() || s.parse::<IpAddr>().is_ok() {
        return None;
    }
    if s.ends_with(".arpa") || s.ends_with(".local") {
        return None;
    }
    let labels: Vec<&str> = s.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }
    if !labels.iter().all(|l| {
        l.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }) {
        return None;
    }
    let n = labels.len();
    let last_two = format!("{}.{}", labels[n - 2], labels[n - 1]);
    if n >= 3 && MULTI_PART_SUFFIXES.contains(&last_two.as_str()) {
        return Some(format!("{}.{last_two}", labels[n - 3]));
    }
    if MULTI_PART_SUFFIXES.contains(&last_two.as_str()) {
        return None; // the bare suffix itself is not a registrable domain
    }
    Some(last_two)
}

impl EnvTracker {
    pub fn new() -> EnvTracker {
        EnvTracker::default()
    }

    /// Record one sighting of `value` by internal `host`. Non-internal hosts and empty values are
    /// ignored; a brand-new value at [`MAX_ENV_ITEMS`] is dropped and counted.
    pub fn observe(
        &mut self,
        kind: IndicatorKind,
        value: &str,
        host: IpAddr,
        ts_ns: i64,
        label: Option<&str>,
    ) {
        self.observe_with_peer(kind, value, host, ts_ns, label, None);
    }

    /// [`Self::observe`], also remembering the external `peer` the value was seen going to.
    fn observe_with_peer(
        &mut self,
        kind: IndicatorKind,
        value: &str,
        host: IpAddr,
        ts_ns: i64,
        label: Option<&str>,
        peer: Option<IpAddr>,
    ) {
        let value = value.trim();
        if value.is_empty() || !is_internal_host(host) {
            return;
        }
        if self.internal_hosts.len() < MAX_INTERNAL_HOSTS {
            self.internal_hosts.insert(host);
        }
        let key = (kind, clip(value));
        let item = match self.items.get_mut(&key) {
            Some(item) => item,
            None => {
                if self.items.len() >= MAX_ENV_ITEMS {
                    self.dropped += 1;
                    return;
                }
                self.items.entry(key).or_default()
            }
        };
        item.count += 1;
        if ts_ns != 0 && (item.first_ts_ns == 0 || ts_ns < item.first_ts_ns) {
            item.first_ts_ns = ts_ns;
        }
        if !item.hosts.contains(&host) {
            if item.hosts.len() < MAX_HOSTS_PER_ITEM {
                item.hosts.insert(host);
            } else {
                item.hosts_truncated = true;
            }
        }
        if let Some(p) = peer {
            if item.peers.len() < MAX_PEERS_PER_ITEM {
                item.peers.insert(p);
            }
        }
        if item.label.is_none() {
            if let Some(l) = label.map(str::trim).filter(|l| !l.is_empty()) {
                item.label = Some(clip(l));
            }
        }
    }

    /// A DNS query `qname` asked by `src`.
    pub fn observe_dns(&mut self, src: IpAddr, qname: &str, ts_ns: i64) {
        if let Some(d) = registered_domain(qname) {
            self.observe(IndicatorKind::Domain, &d, src, ts_ns, Some(qname));
        }
    }

    /// The software and place identity a closed flow carries, attributed to its client. The
    /// client is the flow's initiator (its SYN sender, else its first packet), so an internal host
    /// reaching a service on a port above its own source port is still attributed correctly.
    /// `fallback` is the port-oriented `(client, server)` pair, used when the initiator is not an
    /// internal host (a flow first seen mid-stream from the server side).
    pub fn observe_flow(
        &mut self,
        record: &crate::model::flow::FlowRecord,
        fallback: (IpAddr, IpAddr),
        ts_ns: i64,
    ) {
        let by_initiator = match record.initiator {
            crate::model::flow::Direction::Forward => (record.key.lo_ip, record.key.hi_ip),
            crate::model::flow::Direction::Reverse => (record.key.hi_ip, record.key.lo_ip),
        };
        let (client, server) = if is_internal_host(by_initiator.0) {
            by_initiator
        } else {
            fallback
        };
        if !is_internal_host(client) {
            return;
        }
        let ext_server = classify_ip(server).is_external().then_some(server);
        for name in [record.sni.as_deref(), record.http_host.as_deref()]
            .into_iter()
            .flatten()
        {
            if let Some(d) = registered_domain(name) {
                let label = name.trim().trim_end_matches('.').to_ascii_lowercase();
                self.observe_with_peer(
                    IndicatorKind::Domain,
                    &d,
                    client,
                    ts_ns,
                    Some(&label),
                    ext_server,
                );
            }
        }
        if let Some(j) = record.ja4.as_deref() {
            self.observe(IndicatorKind::Ja4, j, client, ts_ns, None);
        }
        if let Some(j) = record.ja3.as_deref() {
            self.observe(IndicatorKind::Ja3, j, client, ts_ns, None);
        }
        if let Some(ua) = record.http_ua.as_deref() {
            self.observe(IndicatorKind::UserAgent, ua, client, ts_ns, None);
        }
        if classify_ip(server).is_external() {
            self.observe(
                IndicatorKind::Destination,
                &server.to_string(),
                client,
                ts_ns,
                None,
            );
        }
    }

    /// A server leaf certificate (SHA-256 of its DER) served to `client`.
    pub fn observe_cert(&mut self, client: IpAddr, sha256: &str, cn: Option<&str>, ts_ns: i64) {
        self.observe(IndicatorKind::Cert, sha256, client, ts_ns, cn);
    }

    /// Project the sightings, sorted by `(kind, value)` for stable output.
    pub fn snapshot(&self) -> EnvSnapshot {
        let mut items: Vec<EnvObservation> = self
            .items
            .iter()
            .map(|((kind, value), it)| EnvObservation {
                kind: *kind,
                value: value.clone(),
                label: it.label.clone(),
                hosts: it.hosts.iter().map(|h| h.to_string()).collect(),
                hosts_truncated: it.hosts_truncated,
                count: it.count,
                first_ts_ns: it.first_ts_ns,
                peers: it.peers.iter().map(|p| p.to_string()).collect(),
            })
            .collect();
        items.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.value.cmp(&b.value)));
        EnvSnapshot {
            items,
            internal_hosts: self.internal_hosts.len() as u64,
            dropped: self.dropped,
        }
    }
}

// ---- The report -------------------------------------------------------------------------------

/// One rare indicator in the report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RareIndicator {
    pub kind: IndicatorKind,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Internal hosts that produced it this capture (sorted, capped).
    pub hosts: Vec<String>,
    #[serde(default)]
    pub hosts_truncated: bool,
    /// Sightings this capture.
    pub count: u64,
    /// First sighting this capture (ns since epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen_ns: Option<i64>,
    /// Earlier captures in the history that saw it (`0` for a new indicator).
    #[serde(default)]
    pub history_captures: u64,
    /// For a domain seen in TLS SNI / HTTP Host: the external addresses it was reached at.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<String>,
}

/// The "new to this network" and "only one host" view for one capture.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RarityReport {
    /// A baseline sidecar was loaded for comparison.
    #[serde(default)]
    pub baseline_loaded: bool,
    /// Captures in the baseline's environment history.
    #[serde(default)]
    pub history_captures: u64,
    /// A baseline was loaded but has fewer than `min_env_captures` captures, so nothing is called
    /// new yet.
    #[serde(default)]
    pub warming_up: bool,
    /// Distinct internal hosts in this capture's sightings.
    #[serde(default)]
    pub internal_hosts: u64,
    /// Indicators no earlier capture in the history saw (capped at [`MAX_REPORT_ITEMS`]).
    #[serde(default)]
    pub new: Vec<RareIndicator>,
    #[serde(default)]
    pub new_total: u64,
    /// Indicators exactly one internal host produced, on a network with at least
    /// [`MIN_HOSTS_FOR_SINGLE`] hosts, and never seen network-wide in the history (capped).
    #[serde(default)]
    pub single_host: Vec<RareIndicator>,
    #[serde(default)]
    pub single_host_total: u64,
    /// The tracker hit its cap, so some values were not considered.
    #[serde(default)]
    pub incomplete: bool,
}

impl RarityReport {
    /// Cap both lists at [`MAX_REPORT_ITEMS`], keeping first the rows that touch `focus` (IPs a
    /// finding names, as producing host or as the value) so the alerts built from the stored
    /// report still see their own first-seen indicators on a capture with many new values.
    /// Otherwise the `(kind, value)` order is kept; `*_total` keep the exact counts.
    pub fn truncate_for(&mut self, focus: &BTreeSet<String>) {
        let touches = |r: &RareIndicator| {
            r.hosts.iter().any(|h| focus.contains(h))
                || focus.contains(&r.value)
                || r.peers.iter().any(|p| focus.contains(p))
        };
        for list in [&mut self.new, &mut self.single_host] {
            if list.len() > MAX_REPORT_ITEMS {
                // Stable: within each group the (kind, value) order survives.
                list.sort_by_key(|r| !touches(r));
                list.truncate(MAX_REPORT_ITEMS);
                list.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.value.cmp(&b.value)));
            }
        }
    }

    /// New indicators that name `ip` as a producing host or as the indicator value (a first-seen
    /// destination).
    pub fn new_touching<'a>(&'a self, ip: &'a str) -> impl Iterator<Item = &'a RareIndicator> {
        self.new
            .iter()
            .filter(move |r| r.hosts.iter().any(|h| h == ip) || r.value == ip)
    }
}

fn to_rare(o: &EnvObservation, history_captures: u64) -> RareIndicator {
    RareIndicator {
        kind: o.kind,
        value: o.value.clone(),
        label: o.label.clone(),
        hosts: o.hosts.clone(),
        hosts_truncated: o.hosts_truncated,
        count: o.count,
        first_seen_ns: (o.first_ts_ns != 0).then_some(o.first_ts_ns),
        history_captures,
        peers: o.peers.clone(),
    }
}

/// Diff this capture's sightings against the baseline's network-wide history. The `new` and
/// `single_host` lists come back complete (detection reads them whole); call
/// [`RarityReport::truncate_for`] before storing or printing the report.
pub fn rarity_report(
    base: Option<&BaselineProfile>,
    snap: &EnvSnapshot,
    params: &BaselineParams,
) -> RarityReport {
    let known: BTreeMap<(IndicatorKind, &str), (u64, u32)> = base
        .map(|b| {
            b.environment
                .iter()
                .map(|e| ((e.kind, e.value.as_str()), (e.seen.captures, e.max_hosts)))
                .collect()
        })
        .unwrap_or_default();
    let history_captures = base.map_or(0, |b| b.env_captures);
    let mature = base.is_some() && history_captures >= params.min_env_captures.max(1);

    let mut new = Vec::new();
    let mut single = Vec::new();
    for o in &snap.items {
        // (sorted by (kind, value) already, so both lists keep that order)
        let hist = known.get(&(o.kind, o.value.as_str())).copied();
        if mature && hist.is_none() {
            new.push(to_rare(o, 0));
        }
        let widespread_before = hist.is_some_and(|(_, max_hosts)| max_hosts > 1);
        if snap.internal_hosts >= MIN_HOSTS_FOR_SINGLE
            && o.kind != IndicatorKind::Destination
            && o.hosts.len() == 1
            && !o.hosts_truncated
            && !widespread_before
        {
            single.push(to_rare(o, hist.map_or(0, |(c, _)| c)));
        }
    }
    let new_total = new.len() as u64;
    let single_host_total = single.len() as u64;
    RarityReport {
        baseline_loaded: base.is_some(),
        history_captures,
        warming_up: base.is_some() && !mature,
        internal_hosts: snap.internal_hosts,
        new,
        new_total,
        single_host: single,
        single_host_total,
        incomplete: snap.dropped > 0,
    }
}

/// One `BaselineDeviation` finding per host where new client software (JA4/JA3/User-Agent) and a
/// new place (domain/certificate/destination) line up. Hosts in `skip` (already carrying a
/// per-host deviation) are left alone so one story is not told twice. Medium at most.
pub fn combo_findings(report: &RarityReport, skip: &BTreeSet<String>) -> Vec<Finding> {
    let mut per_host: BTreeMap<&str, (Vec<&RareIndicator>, Vec<&RareIndicator>)> = BTreeMap::new();
    for r in &report.new {
        for h in &r.hosts {
            let slot = per_host.entry(h.as_str()).or_default();
            if r.kind.is_software() {
                slot.0.push(r);
            } else {
                slot.1.push(r);
            }
        }
    }
    let describe = |r: &RareIndicator| match &r.label {
        Some(l) if r.kind == IndicatorKind::Cert => {
            format!("{} {} ({l})", r.kind.phrase(), short(&r.value))
        }
        Some(l) if r.kind == IndicatorKind::Domain && l != &r.value => {
            format!("{} {} ({l})", r.kind.phrase(), r.value)
        }
        _ => format!("{} {}", r.kind.phrase(), short(&r.value)),
    };
    let mut out = Vec::new();
    for (host, (software, places)) in per_host {
        if software.is_empty() || places.is_empty() || skip.contains(host) {
            continue;
        }
        let dims = vec![
            (
                format!(
                    "new to this network: {}{}",
                    describe(software[0]),
                    more(software.len())
                ),
                PTS_ENV_NEW_SOFTWARE,
            ),
            (
                format!(
                    "new to this network: {}{}",
                    describe(places[0]),
                    more(places.len())
                ),
                PTS_ENV_NEW_PLACE,
            ),
        ];
        let scored = score_baseline_deviation(&dims);
        let dst = places
            .iter()
            .find(|r| r.kind == IndicatorKind::Destination)
            .map(|r| r.value.clone());
        let first = software
            .iter()
            .chain(places.iter())
            .filter_map(|r| r.first_seen_ns)
            .min();
        let mut evidence = scored.evidence;
        evidence.push(format!(
            "network history: {} earlier capture{}",
            report.history_captures,
            if report.history_captures == 1 {
                ""
            } else {
                "s"
            }
        ));
        out.push(Finding {
            kind: FindingKind::BaselineDeviation,
            severity: scored.severity,
            score: scored.score,
            title: format!(
                "{host} runs software never seen on this network and reaches a new place"
            ),
            src_ip: host.to_string(),
            dst_ip: dst,
            dst_port: None,
            attack: Vec::new(),
            evidence,
            interval_ns: None,
            jitter_cv: None,
            contacts: None,
            first_seen_ns: first,
            last_seen_ns: None,
            victims: Vec::new(),
        });
    }
    out
}

/// Shorten a long fingerprint / hash for evidence text (char-boundary safe).
fn short(v: &str) -> String {
    if v.chars().count() > 40 {
        let s: String = v.chars().take(40).collect();
        format!("{s}…")
    } else {
        v.to_string()
    }
}

fn more(n: usize) -> String {
    if n > 1 {
        format!(" (+{} more)", n - 1)
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::{EnvStat, SeenCount};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn registered_domain_normalizes() {
        assert_eq!(
            registered_domain("WWW.Example.COM."),
            Some("example.com".into())
        );
        assert_eq!(
            registered_domain("api.example.com:8443"),
            Some("example.com".into())
        );
        assert_eq!(
            registered_domain("news.bbc.co.uk"),
            Some("bbc.co.uk".into())
        );
        assert_eq!(registered_domain("co.uk"), None);
        assert_eq!(registered_domain("10.0.0.1"), None);
        assert_eq!(registered_domain("10.0.0.1:80"), None);
        assert_eq!(registered_domain("[::1]:80"), None);
        assert_eq!(registered_domain("printer.local"), None);
        assert_eq!(registered_domain("1.0.0.10.in-addr.arpa"), None);
        assert_eq!(registered_domain("localhost"), None);
        assert_eq!(registered_domain("bad name.com"), None);
    }

    #[test]
    fn tracker_attributes_only_internal_hosts_and_bounds_hosts() {
        let mut t = EnvTracker::new();
        t.observe_dns(ip("8.8.8.8"), "evil.com", 1);
        assert!(
            t.snapshot().items.is_empty(),
            "external clients are not our hosts"
        );
        for i in 0..20 {
            t.observe_dns(ip(&format!("10.0.0.{i}")), "a.example.com", 100 - i);
        }
        let s = t.snapshot();
        assert_eq!(s.items.len(), 1);
        let it = &s.items[0];
        assert_eq!(it.value, "example.com");
        assert_eq!(it.label.as_deref(), Some("a.example.com"));
        assert_eq!(it.hosts.len(), MAX_HOSTS_PER_ITEM);
        assert!(it.hosts_truncated);
        assert_eq!(it.count, 20);
        assert_eq!(it.first_ts_ns, 81);
        assert_eq!(s.internal_hosts, 20);
    }

    #[test]
    fn tracker_caps_items() {
        let mut t = EnvTracker::new();
        for i in 0..(MAX_ENV_ITEMS + 5) {
            t.observe(IndicatorKind::Ja3, &format!("{i}"), ip("10.0.0.1"), 0, None);
        }
        let s = t.snapshot();
        assert_eq!(s.items.len(), MAX_ENV_ITEMS);
        assert_eq!(s.dropped, 5);
    }

    #[test]
    fn long_values_are_clipped_on_char_boundary() {
        let mut t = EnvTracker::new();
        let ua = "é".repeat(400);
        t.observe(IndicatorKind::UserAgent, &ua, ip("10.0.0.1"), 0, None);
        assert_eq!(t.snapshot().items[0].value.chars().count(), MAX_VALUE_CHARS);
    }

    fn base_with(env_captures: u64, known: &[(IndicatorKind, &str, u32)]) -> BaselineProfile {
        let mut b = BaselineProfile::new();
        b.env_captures = env_captures;
        b.environment = known
            .iter()
            .map(|(k, v, h)| EnvStat {
                kind: *k,
                value: v.to_string(),
                label: None,
                seen: SeenCount {
                    captures: 3,
                    total: 9,
                    first_seen_unix: 1,
                    last_seen_unix: 2,
                },
                max_hosts: *h,
            })
            .collect();
        b
    }

    fn snap_of(t: &EnvTracker) -> EnvSnapshot {
        t.snapshot()
    }

    #[test]
    fn report_gates_new_on_history_and_finds_single_host() {
        let mut t = EnvTracker::new();
        for i in 1..=6 {
            t.observe_dns(ip(&format!("10.0.0.{i}")), "common.com", 5);
        }
        t.observe_dns(ip("10.0.0.1"), "rare.com", 7);
        t.observe(IndicatorKind::Ja4, "t13d_new", ip("10.0.0.1"), 9, None);
        t.observe(
            IndicatorKind::Destination,
            "8.8.4.4",
            ip("10.0.0.1"),
            9,
            None,
        );
        let snap = snap_of(&t);
        let params = BaselineParams::default();

        // No baseline: nothing is new, but the single-host list works.
        let r = rarity_report(None, &snap, &params);
        assert!(!r.baseline_loaded && !r.warming_up);
        assert!(r.new.is_empty());
        let singles: Vec<&str> = r.single_host.iter().map(|x| x.value.as_str()).collect();
        assert_eq!(
            singles,
            vec!["t13d_new", "rare.com"],
            "destinations never listed"
        );

        // Young baseline: warming up, nothing new.
        let young = base_with(2, &[(IndicatorKind::Domain, "common.com", 6)]);
        let r = rarity_report(Some(&young), &snap, &params);
        assert!(r.warming_up);
        assert!(r.new.is_empty());

        // Mature baseline: the unknowns are new.
        let mature = base_with(
            3,
            &[
                (IndicatorKind::Domain, "common.com", 6),
                (IndicatorKind::Domain, "rare.com", 4),
            ],
        );
        let r = rarity_report(Some(&mature), &snap, &params);
        assert!(!r.warming_up);
        let new: Vec<&str> = r.new.iter().map(|x| x.value.as_str()).collect();
        assert_eq!(new, vec!["t13d_new", "8.8.4.4"]);
        // rare.com was seen on several hosts before: not "only one host" any more.
        assert!(r.single_host.iter().all(|x| x.value != "rare.com"));
        assert_eq!(r.new_touching("10.0.0.1").count(), 2);
        assert_eq!(r.new_touching("8.8.4.4").count(), 1);
    }

    #[test]
    fn small_networks_have_no_single_host_list() {
        let mut t = EnvTracker::new();
        t.observe_dns(ip("10.0.0.1"), "a.com", 1);
        t.observe_dns(ip("10.0.0.2"), "b.com", 1);
        let r = rarity_report(None, &t.snapshot(), &BaselineParams::default());
        assert!(r.single_host.is_empty());
    }

    #[test]
    fn combo_needs_software_and_place_on_one_host() {
        let mut t = EnvTracker::new();
        t.observe(IndicatorKind::Ja4, "t13d_new", ip("10.0.0.1"), 9, None);
        t.observe_dns(ip("10.0.0.1"), "x.newsite.com", 7);
        t.observe(IndicatorKind::Ja3, "abc", ip("10.0.0.2"), 9, None);
        t.observe_dns(ip("10.0.0.3"), "other.com", 7);
        let base = base_with(5, &[]);
        let r = rarity_report(Some(&base), &t.snapshot(), &BaselineParams::default());
        let f = combo_findings(&r, &BTreeSet::new());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].src_ip, "10.0.0.1");
        assert_eq!(f[0].kind, FindingKind::BaselineDeviation);
        assert_eq!(f[0].severity, crate::model::severity::Severity::Medium);
        assert_eq!(f[0].first_seen_ns, Some(7));
        assert!(f[0].evidence.iter().any(|e| e.contains("newsite.com")));
        // A host with its own per-host deviation is not told twice.
        let skip: BTreeSet<String> = ["10.0.0.1".to_string()].into();
        assert!(combo_findings(&r, &skip).is_empty());
    }

    #[test]
    fn merge_folds_environment_history_and_old_sidecars_read_empty() {
        let params = BaselineParams::default();
        let a = base_with(
            2,
            &[
                (IndicatorKind::Domain, "a.com", 1),
                (IndicatorKind::Ja4, "x", 2),
            ],
        );
        let b = base_with(
            3,
            &[
                (IndicatorKind::Domain, "a.com", 4),
                (IndicatorKind::Domain, "b.com", 1),
            ],
        );
        let m = crate::baseline::merge(a, b, &params);
        assert_eq!(m.env_captures, 5);
        let vals: Vec<&str> = m.environment.iter().map(|e| e.value.as_str()).collect();
        assert_eq!(vals, vec!["x", "a.com", "b.com"], "sorted by (kind, value)");
        let a_com = &m.environment[1];
        assert_eq!(a_com.seen.captures, 6);
        assert_eq!(a_com.max_hosts, 4);

        // Capping keeps the most-seen values.
        let tight = BaselineParams {
            max_env_items: 1,
            ..BaselineParams::default()
        };
        let a = base_with(1, &[(IndicatorKind::Domain, "a.com", 1)]);
        let b = base_with(
            1,
            &[
                (IndicatorKind::Domain, "a.com", 1),
                (IndicatorKind::Domain, "b.com", 1),
            ],
        );
        let m = crate::baseline::merge(a, b, &tight);
        assert_eq!(m.environment.len(), 1);
        assert_eq!(m.environment[0].value, "a.com");

        // A sidecar written before environment rarity has no history and never calls things new.
        let old = r#"{"schema_version":1,"engine_version":"t","captures_merged":9,"first_analyzed_unix_secs":0,"last_analyzed_unix_secs":0,"first_ts_ns":0,"last_ts_ns":0,"hosts":[]}"#;
        let p = BaselineProfile::from_json_str(old).unwrap();
        assert_eq!(p.env_captures, 0);
        let mut t = EnvTracker::new();
        t.observe_dns(ip("10.0.0.1"), "a.com", 1);
        let r = rarity_report(Some(&p), &t.snapshot(), &params);
        assert!(r.warming_up && r.new.is_empty());
        // And a fresh sidecar does not grow empty environment keys.
        assert!(!BaselineProfile::new()
            .to_json_pretty()
            .unwrap()
            .contains("environment"));
    }

    #[test]
    fn flow_is_oriented_by_its_initiator_and_links_domains_to_peers() {
        use crate::model::flow::{FlowKey, FlowRecord};
        use crate::model::packet::Transport;
        // 10.0.0.5:40000 opens TLS to 45.33.32.156:50000 — the internal side has the LOWER port,
        // so the port rule alone would call the external address the client.
        let (key, dir) = FlowKey::normalized(
            ip("10.0.0.5"),
            40000,
            ip("45.33.32.156"),
            50000,
            Transport::Tcp,
        );
        let mut rec = FlowRecord::new(key, 5);
        rec.initiator = dir;
        rec.sni = Some("svc.newsite.example".into());
        rec.ja4 = Some("t13d_x".into());
        let mut t = EnvTracker::new();
        // The port-oriented pair a caller would pass: (45.33.32.156, 10.0.0.5).
        t.observe_flow(&rec, (ip("45.33.32.156"), ip("10.0.0.5")), 5);
        let s = t.snapshot();
        let kinds: Vec<(IndicatorKind, &str)> =
            s.items.iter().map(|o| (o.kind, o.value.as_str())).collect();
        assert_eq!(
            kinds,
            vec![
                (IndicatorKind::Ja4, "t13d_x"),
                (IndicatorKind::Domain, "newsite.example"),
                (IndicatorKind::Destination, "45.33.32.156"),
            ]
        );
        assert!(s
            .items
            .iter()
            .all(|o| o.hosts == vec!["10.0.0.5".to_string()]));
        let dom = s
            .items
            .iter()
            .find(|o| o.kind == IndicatorKind::Domain)
            .unwrap();
        assert_eq!(dom.peers, vec!["45.33.32.156".to_string()]);

        // A flow first seen from the server side falls back to the port orientation.
        let (key, _) = FlowKey::normalized(
            ip("45.33.32.156"),
            443,
            ip("10.0.0.6"),
            51000,
            Transport::Tcp,
        );
        let mut rec = FlowRecord::new(key, 6);
        rec.initiator = if key.lo_ip == ip("45.33.32.156") {
            crate::model::flow::Direction::Forward
        } else {
            crate::model::flow::Direction::Reverse
        };
        rec.ja4 = Some("t13d_y".into());
        t.observe_flow(&rec, (ip("10.0.0.6"), ip("45.33.32.156")), 6);
        let s = t.snapshot();
        let y = s.items.iter().find(|o| o.value == "t13d_y").unwrap();
        assert_eq!(y.hosts, vec!["10.0.0.6".to_string()]);
    }

    #[test]
    fn combos_see_every_new_value_and_the_stored_list_keeps_finding_rows() {
        let mut t = EnvTracker::new();
        for i in 0..150 {
            t.observe(
                IndicatorKind::Ja3,
                &format!("a{i:03}"),
                ip("10.0.0.2"),
                1,
                None,
            );
        }
        // Sorts after every "a…" fingerprint, so a plain cap would drop it.
        t.observe(IndicatorKind::Ja3, "zzz", ip("10.0.0.9"), 1, None);
        t.observe(
            IndicatorKind::Destination,
            "45.33.32.156",
            ip("10.0.0.9"),
            1,
            None,
        );
        let base = base_with(5, &[]);
        let mut r = rarity_report(Some(&base), &t.snapshot(), &BaselineParams::default());
        assert_eq!(r.new.len(), 152, "complete until truncated");
        let combo = combo_findings(&r, &BTreeSet::new());
        assert!(combo.iter().any(|f| f.src_ip == "10.0.0.9"), "{combo:?}");
        let focus: BTreeSet<String> = ["10.0.0.9".to_string()].into();
        r.truncate_for(&focus);
        assert_eq!(r.new.len(), MAX_REPORT_ITEMS);
        assert_eq!(r.new_total, 152);
        assert!(r.new.iter().any(|n| n.value == "zzz"));
        assert!(r.new.iter().any(|n| n.value == "45.33.32.156"));
        assert!(r
            .new
            .windows(2)
            .all(|w| (w[0].kind, &w[0].value) <= (w[1].kind, &w[1].value)));
    }

    // ---- Through the real pipeline ------------------------------------------------------------

    use crate::gen::frames::{
        build_ethernet, build_ipv4, build_tcp, build_udp, dns_query_payload,
        tls_client_hello_payload, IP_PROTO_TCP, IP_PROTO_UDP, TCP_ACK, TCP_PSH,
    };
    use std::net::Ipv4Addr;

    fn frame(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        payload: &[u8],
        udp: bool,
    ) -> Vec<u8> {
        let l4 = if udp {
            build_udp(src, dst, sport, dport, payload)
        } else {
            build_tcp(src, dst, sport, dport, TCP_PSH | TCP_ACK, payload)
        };
        let proto = if udp { IP_PROTO_UDP } else { IP_PROTO_TCP };
        let mut f = build_ethernet([2; 6], [6; 6], 0x0800);
        f.extend(build_ipv4(src, dst, proto, 64, l4.len()));
        f.extend(l4);
        f
    }

    /// One "day" on a six-host network: everyone resolves and browses the same site. `extra`
    /// adds 10.0.0.9's unusual activity.
    fn day_capture(path: &std::path::Path, day: i64, extra: bool) {
        let resolver = Ipv4Addr::new(10, 0, 0, 1);
        let site = Ipv4Addr::new(93, 184, 216, 34);
        let mut frames = Vec::new();
        for h in 4..=9u8 {
            let host = Ipv4Addr::new(10, 0, 0, h);
            frames.push(frame(
                host,
                resolver,
                40000 + h as u16,
                53,
                &dns_query_payload("www.common.com", h as u16),
                true,
            ));
            frames.push(frame(
                host,
                site,
                50000 + h as u16,
                443,
                &tls_client_hello_payload("www.common.com"),
                false,
            ));
        }
        if extra {
            let host = Ipv4Addr::new(10, 0, 0, 9);
            let drop = Ipv4Addr::new(45, 33, 32, 156);
            frames.push(frame(
                host,
                resolver,
                41000,
                53,
                &dns_query_payload("cdn.badsite.net", 7),
                true,
            ));
            let req =
                b"GET /p HTTP/1.1\r\nHost: cdn.badsite.net\r\nUser-Agent: EvilAgent/1.0\r\n\r\n";
            frames.push(frame(host, drop, 52000, 80, req, false));
        }
        let mut buf = Vec::new();
        crate::gen::container::write_pcap_header(&mut buf, crate::reader::LinkType::Ethernet)
            .unwrap();
        let base_ns = 1_700_000_000_000_000_000i64 + day * 86_400_000_000_000;
        for (i, f) in frames.iter().enumerate() {
            crate::gen::container::write_legacy_record(
                &mut buf,
                base_ns + i as i64 * 1_000_000,
                f.len() as u32,
                f.len() as u32,
            )
            .unwrap();
            buf.extend_from_slice(f);
        }
        std::fs::write(path, buf).unwrap();
    }

    #[test]
    fn pipeline_learns_history_then_flags_what_is_new() {
        use crate::analyze::{run, PipelineConfig};
        let dir = tempfile::tempdir().unwrap();
        let pcap = dir.path().join("day.pcap");
        let bpath = dir.path().join("baseline.json");
        let params = BaselineParams::default();
        let mut base = BaselineProfile::new();

        for day in 0..3 {
            day_capture(&pcap, day, false);
            let cfg = PipelineConfig {
                update_baseline: true,
                baseline_in: (day > 0).then(|| bpath.clone()),
                ..Default::default()
            };
            let out = run(&pcap, &cfg, |_, _, _| {}).unwrap();
            let r = out.summary.rarity.as_ref().expect("rarity report");
            assert_eq!(
                r.internal_hosts, 6,
                "resolver is not a client; six browsing hosts"
            );
            if day > 0 {
                assert!(r.warming_up, "day {day}: young baseline calls nothing new");
                assert!(r.new.is_empty());
            }
            assert!(r.single_host.is_empty(), "everyone does the same thing");
            let snap = out.baseline.as_ref().unwrap();
            assert!(snap
                .environment
                .items
                .iter()
                .any(|o| o.kind == IndicatorKind::Domain
                    && o.value == "common.com"
                    && o.hosts.len() == 6));
            base = crate::baseline::update_baseline(base, &out, 1_000 + day, &params);
            std::fs::write(&bpath, base.to_json_pretty().unwrap()).unwrap();
        }
        assert_eq!(base.env_captures, 3);
        let common = base
            .environment
            .iter()
            .find(|e| e.value == "common.com")
            .unwrap();
        assert_eq!(common.seen.captures, 3);
        assert_eq!(common.max_hosts, 6);
        // The sidecar survives a JSON round trip with its history.
        let reread =
            BaselineProfile::from_json_str(&std::fs::read_to_string(&bpath).unwrap()).unwrap();
        assert_eq!(reread.environment, base.environment);

        // Day 4: same routine, plus one host with a new tool reaching a new place.
        day_capture(&pcap, 3, true);
        let cfg = PipelineConfig {
            baseline_in: Some(bpath.clone()),
            ..Default::default()
        };
        let out = run(&pcap, &cfg, |_, _, _| {}).unwrap();
        let r = out.summary.rarity.as_ref().unwrap();
        assert!(!r.warming_up);
        assert_eq!(r.history_captures, 3);
        let new: Vec<(IndicatorKind, &str)> =
            r.new.iter().map(|n| (n.kind, n.value.as_str())).collect();
        assert!(
            new.contains(&(IndicatorKind::UserAgent, "EvilAgent/1.0")),
            "{new:?}"
        );
        assert!(
            new.contains(&(IndicatorKind::Domain, "badsite.net")),
            "{new:?}"
        );
        assert!(
            new.contains(&(IndicatorKind::Destination, "45.33.32.156")),
            "{new:?}"
        );
        assert!(!new
            .iter()
            .any(|(_, v)| *v == "common.com" || *v == "93.184.216.34"));
        assert!(r
            .new
            .iter()
            .all(|n| n.hosts == vec!["10.0.0.9".to_string()]));
        assert!(r.single_host.iter().any(|n| n.value == "badsite.net"));

        let combo: Vec<&Finding> = out
            .summary
            .findings
            .iter()
            .filter(|f| f.kind == FindingKind::BaselineDeviation && f.src_ip == "10.0.0.9")
            .collect();
        assert_eq!(combo.len(), 1, "{:?}", out.summary.findings);
        assert!(combo[0].evidence.iter().any(|e| e.contains("EvilAgent")));
        // The alert carrying it names what is new to the network and takes the first-seen uplift.
        let alert = out
            .summary
            .alerts
            .iter()
            .find(|a| {
                a.context
                    .entries
                    .iter()
                    .any(|e| e.kind == crate::model::alert::ContextKind::NewToNetwork)
            })
            .expect("an alert with new-to-network context");
        assert!(alert
            .priority_terms
            .iter()
            .any(|t| t.label.contains("new to this network")));
    }
}
