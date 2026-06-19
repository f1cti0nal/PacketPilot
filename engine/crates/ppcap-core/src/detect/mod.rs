//! Behavioral detection substrate.
//!
//! This module turns the engine from "classify flows" into "measure behavior". It holds the
//! streaming, bounded-memory primitives that cross-flow detectors (C2 beaconing, host sweeps,
//! data exfiltration) consume — none of which can be expressed on a single aggregated
//! [`FlowRecord`] row.
//!
//! The cornerstone primitive is [`StreamStats`]: an O(1)-memory running mean/variance over a
//! stream of samples (Welford's online algorithm). For beaconing, the samples are the
//! inter-arrival gaps between successive contacts from a host to a destination; a regular
//! beacon has a near-zero **coefficient of variation** (low jitter relative to its period),
//! while ad-hoc traffic does not. Retaining only five fixed-size fields — never the samples
//! themselves — keeps detection within the engine's bounded-memory contract regardless of how
//! many contacts a flow makes.

/// Streaming mean/variance over a stream of `i64` samples using Welford's online algorithm.
///
/// Memory is O(1): the individual samples are never retained, only five fixed-size running
/// fields. Variance is reported as the **population** variance (divide by `count`), which is
/// the appropriate jitter measure for a fixed observed series of inter-arrival gaps.
#[derive(Debug, Clone)]
pub struct StreamStats {
    count: u64,
    mean: f64,
    /// Sum of squares of differences from the running mean (Welford's M2).
    m2: f64,
    min: i64,
    max: i64,
}

impl Default for StreamStats {
    fn default() -> Self {
        StreamStats::new()
    }
}

impl StreamStats {
    /// An empty accumulator.
    pub fn new() -> StreamStats {
        StreamStats {
            count: 0,
            mean: 0.0,
            m2: 0.0,
            min: i64::MAX,
            max: i64::MIN,
        }
    }

    /// Fold one sample into the running statistics.
    pub fn push(&mut self, sample: i64) {
        self.count += 1;
        let x = sample as f64;
        let delta = x - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
        if sample < self.min {
            self.min = sample;
        }
        if sample > self.max {
            self.max = sample;
        }
    }

    /// Number of samples observed.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Running arithmetic mean; `0.0` when empty.
    pub fn mean(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.mean
        }
    }

    /// Population variance (`M2 / count`); `0.0` when fewer than two samples.
    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            self.m2 / self.count as f64
        }
    }

    /// Population standard deviation (`sqrt(variance)`).
    pub fn stddev(&self) -> f64 {
        self.variance().sqrt()
    }

    /// Coefficient of variation (`stddev / mean`); `0.0` when the mean is zero or empty.
    ///
    /// This is the periodicity discriminator: a regular beacon yields a value near zero, ad-hoc
    /// traffic yields a large one.
    pub fn cv(&self) -> f64 {
        if self.count == 0 || self.mean == 0.0 {
            0.0
        } else {
            self.stddev() / self.mean.abs()
        }
    }

    /// Smallest sample seen; `0` when empty.
    pub fn min(&self) -> i64 {
        if self.count == 0 {
            0
        } else {
            self.min
        }
    }

    /// Largest sample seen; `0` when empty.
    pub fn max(&self) -> i64 {
        if self.count == 0 {
            0
        } else {
            self.max
        }
    }
}

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Identity of a directed "destination contact channel": one source reaching one
/// `(dst_ip, dst_port)` service. Beaconing periodicity is measured per channel because each
/// callback is a *separate* flow (new ephemeral source port), so the signal cannot live on a
/// single aggregated [`crate::model::flow::FlowRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContactKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
}

impl ContactKey {
    /// Construct a channel key.
    pub fn new(src: IpAddr, dst: IpAddr, dst_port: u16) -> ContactKey {
        ContactKey { src, dst, dst_port }
    }
}

/// The streaming inter-arrival series for one [`ContactKey`]: how regularly a source contacts
/// a destination. Holds only a counter, the previous timestamp, and a fixed-size
/// [`StreamStats`] over the gaps — O(1) memory per channel regardless of contact count.
#[derive(Debug, Clone, Default)]
pub struct ContactSeries {
    contacts: u64,
    prev_ts_ns: Option<i64>,
    gaps: StreamStats,
    /// Bytes sent client -> server across this channel (the exfil-relevant direction).
    bytes_out: u64,
    /// Bytes sent server -> client across this channel.
    bytes_in: u64,
}

impl ContactSeries {
    /// An empty series.
    pub fn new() -> ContactSeries {
        ContactSeries::default()
    }

    /// Record one contact at `ts_ns`. Out-of-order timestamps clamp the gap to zero so a
    /// non-monotonic capture never produces a negative interval.
    pub fn observe(&mut self, ts_ns: i64) {
        self.contacts += 1;
        if let Some(prev) = self.prev_ts_ns {
            self.gaps.push((ts_ns - prev).max(0));
        }
        self.prev_ts_ns = Some(ts_ns);
    }

    /// Number of contacts recorded.
    pub fn contacts(&self) -> u64 {
        self.contacts
    }

    /// Mean inter-contact gap in nanoseconds (the candidate beacon period); `0.0` with fewer
    /// than two contacts.
    pub fn interval_ns(&self) -> f64 {
        self.gaps.mean()
    }

    /// Coefficient of variation of the inter-contact gaps — the periodicity score (near zero
    /// == regular beacon).
    pub fn jitter_cv(&self) -> f64 {
        self.gaps.cv()
    }

    /// Fold directional byte counts for this channel.
    pub fn add_bytes(&mut self, out: u64, inb: u64) {
        self.bytes_out = self.bytes_out.saturating_add(out);
        self.bytes_in = self.bytes_in.saturating_add(inb);
    }

    /// Total bytes sent client -> server on this channel.
    pub fn bytes_out(&self) -> u64 {
        self.bytes_out
    }

    /// Total bytes sent server -> client on this channel.
    pub fn bytes_in(&self) -> u64 {
        self.bytes_in
    }
}

/// A destination channel that looks like a periodic beacon.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BeaconCandidate {
    pub key: ContactKey,
    pub contacts: u64,
    pub interval_ns: f64,
    pub jitter_cv: f64,
}

/// A destination channel with a large asymmetric outbound transfer (exfil shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExfilCandidate {
    pub key: ContactKey,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

/// A `(source, port)` pair that reached many distinct hosts (horizontal sweep shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepCandidate {
    pub src: IpAddr,
    pub dst_port: u16,
    pub hosts: usize,
}

/// A channel with many connection attempts to one authentication service (brute-force shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BruteForceCandidate {
    pub key: ContactKey,
    pub attempts: u64,
}

/// A `(source, admin-port)` pair that opened established sessions to several distinct hosts
/// (lateral-movement shape). `targets` are the distinct destinations whose channel carried a
/// real bidirectional session; internality is left to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LateralCandidate {
    pub src: IpAddr,
    pub dst_port: u16,
    pub targets: Vec<IpAddr>,
}

/// Per-`(source, resolver)` DNS query statistics.
#[derive(Debug, Clone, Default)]
struct DnsStats {
    queries: u64,
    /// Sum of the per-query most-dense-label Shannon entropy (avg = sum / queries).
    entropy_sum: f64,
    max_label_len: u16,
    /// One example qname for the finding evidence.
    sample: Option<String>,
}

/// A `(source, resolver)` channel whose DNS queries look like tunneling / DGA.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsTunnelCandidate {
    pub src: IpAddr,
    pub resolver: IpAddr,
    pub queries: u64,
    pub avg_entropy: f64,
    pub max_label_len: u16,
    pub sample: Option<String>,
}

/// Tuning for the behavioral tracker. Both caps keep memory bounded on adversarial captures.
#[derive(Debug, Clone)]
pub struct DetectConfig {
    /// Cap on distinct contact channels (and distinct fan-out sources) tracked.
    pub max_tracked_keys: usize,
    /// Cap on distinct destination hosts retained per source for sweep detection.
    pub max_fanout_per_src: usize,
}

impl Default for DetectConfig {
    fn default() -> Self {
        DetectConfig {
            max_tracked_keys: 2_000_000,
            max_fanout_per_src: 4096,
        }
    }
}

/// Streaming, bounded cross-flow behavioral tracker.
///
/// Fed one *contact* (a new connection's directed `src -> dst:port` + timestamp) at a time, it
/// maintains (a) a per-channel inter-arrival series for beaconing and (b) a per-`(source, port)`
/// set of distinct destination hosts for horizontal sweep detection. Keying the fan-out on the
/// destination port (not the source alone) distinguishes a one-port-many-hosts sweep from a
/// busy client talking to many hosts across assorted ports. Both maps degrade gracefully at
/// capacity (a brand-new key is dropped) so peak memory stays bounded.
pub struct BehaviorTracker {
    cfg: DetectConfig,
    channels: HashMap<ContactKey, ContactSeries>,
    fanout: HashMap<(IpAddr, u16), HashSet<IpAddr>>,
    /// Per-`(source, resolver)` DNS query statistics for tunneling / DGA detection.
    dns: HashMap<(IpAddr, IpAddr), DnsStats>,
}

impl BehaviorTracker {
    /// Create an empty tracker.
    pub fn new(cfg: DetectConfig) -> BehaviorTracker {
        BehaviorTracker {
            cfg,
            channels: HashMap::new(),
            fanout: HashMap::new(),
            dns: HashMap::new(),
        }
    }

    /// Fold one DNS query: `src` asked `resolver` for `qname`. Accumulates the volume, the
    /// distribution of the most-information-dense label's Shannon entropy, and the longest label
    /// length — the signals that separate tunneling / DGA from ordinary lookups. Bounded: a
    /// brand-new `(src, resolver)` at capacity is dropped.
    pub fn observe_dns_query(&mut self, src: IpAddr, resolver: IpAddr, qname: &str) {
        let key = (src, resolver);
        if !self.dns.contains_key(&key) && self.dns.len() >= self.cfg.max_tracked_keys.max(1) {
            return;
        }
        // The data-carrying label is the longest one; measure its entropy and length.
        let longest = qname.split('.').max_by_key(|l| l.len()).unwrap_or("");
        let entropy = shannon_entropy(longest);
        let label_len = longest.len().min(u16::MAX as usize) as u16;
        let e = self.dns.entry(key).or_default();
        e.queries += 1;
        e.entropy_sum += entropy;
        if label_len > e.max_label_len {
            e.max_label_len = label_len;
        }
        if e.sample.is_none() && !qname.is_empty() {
            e.sample = Some(qname.to_string());
        }
    }

    /// Fold one contact: a new `src -> dst:dst_port` connection observed at `ts_ns`. Timing-only
    /// convenience wrapper over [`observe_flow_contact`](Self::observe_flow_contact).
    pub fn observe_contact(&mut self, src: IpAddr, dst: IpAddr, dst_port: u16, ts_ns: i64) {
        self.observe_flow_contact(src, dst, dst_port, ts_ns, 0, 0);
    }

    /// Fold one closed flow's contact: directed `src -> dst:dst_port` at `ts_ns` plus the
    /// directional byte counts (`bytes_out` = client->server, `bytes_in` = server->client).
    pub fn observe_flow_contact(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        dst_port: u16,
        ts_ns: i64,
        bytes_out: u64,
        bytes_in: u64,
    ) {
        // Per-channel inter-arrival series + byte totals (bounded: a brand-new channel at
        // capacity is dropped — best-effort heavy-hitter signal, not an exact set).
        let key = ContactKey::new(src, dst, dst_port);
        if let Some(series) = self.channels.get_mut(&key) {
            series.observe(ts_ns);
            series.add_bytes(bytes_out, bytes_in);
        } else if self.channels.len() < self.cfg.max_tracked_keys.max(1) {
            let mut series = ContactSeries::new();
            series.observe(ts_ns);
            series.add_bytes(bytes_out, bytes_in);
            self.channels.insert(key, series);
        }

        // Per-(source, port) distinct destination-host set (sweep signal), bounded in both the
        // number of (src, port) keys and the hosts retained per key.
        let fkey = (src, dst_port);
        if let Some(set) = self.fanout.get_mut(&fkey) {
            if set.len() < self.cfg.max_fanout_per_src {
                set.insert(dst);
            }
        } else if self.fanout.len() < self.cfg.max_tracked_keys.max(1) {
            let mut set = HashSet::new();
            set.insert(dst);
            self.fanout.insert(fkey, set);
        }
    }

    /// Borrow the inter-arrival series for a channel, if tracked.
    pub fn series(&self, key: ContactKey) -> Option<&ContactSeries> {
        self.channels.get(&key)
    }

    /// Number of distinct destination hosts `src` contacted on `dst_port` (the sweep fan-out).
    pub fn fanout(&self, src: IpAddr, dst_port: u16) -> usize {
        self.fanout.get(&(src, dst_port)).map_or(0, |set| set.len())
    }

    /// Whether `src` contacted at least `threshold` distinct hosts on `dst_port`.
    pub fn is_sweeper(&self, src: IpAddr, dst_port: u16, threshold: usize) -> bool {
        self.fanout(src, dst_port) >= threshold
    }

    /// All `(src, port)` pairs that reached at least `min_hosts` distinct destination hosts — a
    /// horizontal sweep. Port gating is left to the caller. Returned in deterministic order.
    pub fn sweep_candidates(&self, min_hosts: usize) -> Vec<SweepCandidate> {
        let mut out: Vec<SweepCandidate> = self
            .fanout
            .iter()
            .filter(|(_, hosts)| hosts.len() >= min_hosts)
            .map(|(&(src, dst_port), hosts)| SweepCandidate {
                src,
                dst_port,
                hosts: hosts.len(),
            })
            .collect();
        out.sort_by(|a, b| {
            b.hosts
                .cmp(&a.hosts)
                .then(a.src.cmp(&b.src))
                .then(a.dst_port.cmp(&b.dst_port))
        });
        out
    }

    /// All `(src, resolver)` channels whose DNS queries look like tunneling / DGA: at least
    /// `min_queries` queries, an average most-dense-label entropy at or above `min_avg_entropy`,
    /// and a longest label at or above `min_label_len`. Returned strongest (most queries) first.
    pub fn dns_tunnel_candidates(
        &self,
        min_queries: u64,
        min_avg_entropy: f64,
        min_label_len: u16,
    ) -> Vec<DnsTunnelCandidate> {
        let mut out: Vec<DnsTunnelCandidate> = self
            .dns
            .iter()
            .filter(|(_, s)| {
                s.queries >= min_queries
                    && s.max_label_len >= min_label_len
                    && s.entropy_sum / s.queries as f64 >= min_avg_entropy
            })
            .map(|(&(src, resolver), s)| DnsTunnelCandidate {
                src,
                resolver,
                queries: s.queries,
                avg_entropy: s.entropy_sum / s.queries as f64,
                max_label_len: s.max_label_len,
                sample: s.sample.clone(),
            })
            .collect();
        out.sort_by(|a, b| {
            b.queries
                .cmp(&a.queries)
                .then(a.src.cmp(&b.src))
                .then(a.resolver.cmp(&b.resolver))
        });
        out
    }

    /// Number of distinct contact channels currently tracked (for bound assertions).
    pub fn tracked_channels(&self) -> usize {
        self.channels.len()
    }

    /// All channels that look like a periodic beacon: at least `min_contacts` contacts with a
    /// jitter CV at or below `max_cv`. Returned in deterministic key order.
    pub fn beacon_candidates(&self, min_contacts: u64, max_cv: f64) -> Vec<BeaconCandidate> {
        let mut out: Vec<BeaconCandidate> = self
            .channels
            .iter()
            .filter(|(_, s)| {
                s.contacts() >= min_contacts && s.interval_ns() > 0.0 && s.jitter_cv() <= max_cv
            })
            .map(|(k, s)| BeaconCandidate {
                key: *k,
                contacts: s.contacts(),
                interval_ns: s.interval_ns(),
                jitter_cv: s.jitter_cv(),
            })
            .collect();
        out.sort_by_key(|c| c.key);
        out
    }

    /// All channels that look like data exfiltration: outbound bytes at or above `min_bytes_out`
    /// with an out/in ratio at or above `min_ratio` (an asymmetric upload). Externality is left
    /// to the caller. Returned in deterministic key order.
    pub fn exfil_candidates(&self, min_bytes_out: u64, min_ratio: f64) -> Vec<ExfilCandidate> {
        let mut out: Vec<ExfilCandidate> = self
            .channels
            .iter()
            .filter(|(_, s)| {
                s.bytes_out() >= min_bytes_out
                    && s.bytes_out() as f64 >= min_ratio * (s.bytes_in() as f64 + 1.0)
            })
            .map(|(k, s)| ExfilCandidate {
                key: *k,
                bytes_out: s.bytes_out(),
                bytes_in: s.bytes_in(),
            })
            .collect();
        out.sort_by_key(|c| c.key);
        out
    }

    /// All channels that look like a credential brute force: at least `min_attempts` separate
    /// connection attempts to a destination service whose port is in `auth_ports`. Each login
    /// attempt is a distinct flow (new ephemeral source port), so the signal lives on the
    /// cross-flow contact count, not a single [`crate::model::flow::FlowRecord`]. Returned
    /// strongest (most attempts) first.
    pub fn brute_force_candidates(
        &self,
        min_attempts: u64,
        auth_ports: &[u16],
    ) -> Vec<BruteForceCandidate> {
        let mut out: Vec<BruteForceCandidate> = self
            .channels
            .iter()
            .filter(|(k, s)| s.contacts() >= min_attempts && auth_ports.contains(&k.dst_port))
            .map(|(k, s)| BruteForceCandidate {
                key: *k,
                attempts: s.contacts(),
            })
            .collect();
        out.sort_by(|a, b| b.attempts.cmp(&a.attempts).then(a.key.cmp(&b.key)));
        out
    }

    /// All `(source, admin-port)` pairs that opened an *established* session — at least
    /// `min_session_bytes` in **each** direction, which a SYN scan / bare handshake never reaches —
    /// to one or more distinct destinations on a port in `lateral_ports`. The byte floor per
    /// direction is what separates lateral movement (real remote-admin sessions) from a horizontal
    /// probe sweep. Internality of the endpoints and the host-count threshold are left to the
    /// caller. Returned in deterministic order; `targets` are sorted and deduplicated.
    pub fn lateral_candidates(
        &self,
        min_session_bytes: u64,
        lateral_ports: &[u16],
    ) -> Vec<LateralCandidate> {
        use std::collections::{BTreeMap, BTreeSet};
        let mut groups: BTreeMap<(IpAddr, u16), BTreeSet<IpAddr>> = BTreeMap::new();
        for (k, s) in &self.channels {
            if lateral_ports.contains(&k.dst_port)
                && s.bytes_out() >= min_session_bytes
                && s.bytes_in() >= min_session_bytes
            {
                groups.entry((k.src, k.dst_port)).or_default().insert(k.dst);
            }
        }
        groups
            .into_iter()
            .map(|((src, dst_port), set)| LateralCandidate {
                src,
                dst_port,
                targets: set.into_iter().collect(),
            })
            .collect()
    }
}

use crate::enrich::classify_ip;
use crate::model::finding::{Finding, FindingKind};
use crate::model::flow::FlowRecord;
use crate::model::incident::Incident;
use crate::model::severity::Severity;

/// Interactive remote-login service ports treated as credential-brute-force targets. Repeated
/// separate connections to one of these from a single source is anomalous (you reuse one SSH/RDP
/// session, you do not open twenty), and benign churn on them is low — unlike high-volume service
/// ports (SMB 445, LDAP 389, the database ports) where a workstation legitimately opens many
/// connections to a file server / DC. Used as both [`BruteForceParams::auth_ports`] and
/// [`BeaconParams::ignore_ports`] so the two detectors never disagree about a channel.
pub const INTERACTIVE_AUTH_PORTS: &[u16] = &[
    21,   // FTP
    22,   // SSH
    23,   // Telnet
    3389, // RDP
    5900, // VNC
];

/// Tuning for the beaconing detector.
#[derive(Debug, Clone)]
pub struct BeaconParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum contacts on a channel before it can be called a beacon.
    pub min_contacts: u64,
    /// Maximum jitter (coefficient of variation) to still count as "regular".
    pub max_jitter_cv: f64,
    /// Ignore channels whose period is below this (sub-second chatter is not a beacon).
    pub min_interval_ns: i64,
    /// Ignore channels whose period is above this (too sparse to call periodic).
    pub max_interval_ns: i64,
    /// Destination ports excluded from beacon detection. A throttled credential guesser or a
    /// periodic remote-admin agent produces a regular, low-jitter series to an auth / admin
    /// service that would otherwise satisfy the beacon predicate too; excluding the auth AND
    /// lateral-movement ports keeps a brute force / lateral fan-out from also being reported as a
    /// C2 beacon (legitimate C2 rarely beacons over an interactive-login or remote-admin port).
    pub ignore_ports: Vec<u16>,
}

impl Default for BeaconParams {
    fn default() -> Self {
        BeaconParams {
            enabled: true,
            // A low jitter CV is only trustworthy with enough samples; too few contacts let
            // benign traffic look periodic by chance (a multiple-comparisons effect across many
            // channels). Real beacons check in many times, so require a solid minimum.
            min_contacts: 12,
            max_jitter_cv: 0.15,
            min_interval_ns: 1_000_000_000,              // 1 s
            max_interval_ns: 24 * 3_600 * 1_000_000_000, // 24 h
            // The union of the auth ports (brute-force territory) and the remote-admin ports
            // (lateral-movement territory): a regular series to any of these is owned by the
            // more-specific detector, never reported as a beacon.
            ignore_ports: merged_ports(INTERACTIVE_AUTH_PORTS, LATERAL_PORTS),
        }
    }
}

/// Sorted, deduplicated union of two port lists (for default ignore sets).
fn merged_ports(a: &[u16], b: &[u16]) -> Vec<u16> {
    let mut v: Vec<u16> = a.iter().chain(b.iter()).copied().collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// One closed flow reduced to a directed contact: the initiating client, the service it
/// reached, the connection-start time, and the directional byte totals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Contact {
    pub client: IpAddr,
    pub server: IpAddr,
    pub server_port: u16,
    pub ts_ns: i64,
    /// Bytes client -> server (the exfil-relevant "outbound" direction).
    pub bytes_out: u64,
    /// Bytes server -> client.
    pub bytes_in: u64,
}

/// Derive the directed [`Contact`] from a closed flow, or `None` for a non-port transport.
///
/// The server is the well-known (numerically smaller) port side — matching how `stats` picks
/// the service port — and the client is the ephemeral side. The contact time is the flow's
/// first timestamp, i.e. the connection-initiation instant, which is the correct sample for
/// beacon periodicity.
pub fn contact_from_flow(record: &FlowRecord) -> Option<Contact> {
    if !record.key.transport.has_ports() {
        return None;
    }
    // The smaller port is the well-known service side (the server); the other endpoint is the
    // ephemeral client that initiated the connection. `bytes_out` is client->server (the
    // exfil-relevant direction); FlowRecord stores bytes as fwd = lo->hi, rev = hi->lo.
    let (client, server, server_port, bytes_out, bytes_in) =
        if record.key.lo_port <= record.key.hi_port {
            // server = lo, client = hi -> client->server is hi->lo = bytes_rev.
            (
                record.key.hi_ip,
                record.key.lo_ip,
                record.key.lo_port,
                record.bytes_rev,
                record.bytes_fwd,
            )
        } else {
            // server = hi, client = lo -> client->server is lo->hi = bytes_fwd.
            (
                record.key.lo_ip,
                record.key.hi_ip,
                record.key.hi_port,
                record.bytes_fwd,
                record.bytes_rev,
            )
        };
    Some(Contact {
        client,
        server,
        server_port,
        ts_ns: record.first_ts_ns,
        bytes_out,
        bytes_in,
    })
}

/// Detect periodic C2 beaconing from the behavioral tracker: one [`Finding`] per destination
/// channel whose contacts are frequent enough ([`BeaconParams::min_contacts`]), regular enough
/// ([`BeaconParams::max_jitter_cv`]), and within the plausible period window. Severity is High
/// for an external destination, Medium for an internal one. Returned in deterministic order.
pub fn detect_beacons(tracker: &BehaviorTracker, params: &BeaconParams) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.beacon_candidates(params.min_contacts, params.max_jitter_cv) {
        // Reject periods outside the plausible beacon window (sub-second chatter / too sparse).
        if c.interval_ns < params.min_interval_ns as f64
            || c.interval_ns > params.max_interval_ns as f64
        {
            continue;
        }
        // A regular, low-jitter series to an auth service is a (throttled) brute force, not a C2
        // beacon — skip the auth ports so the two detectors never double-report one channel.
        if params.ignore_ports.contains(&c.key.dst_port) {
            continue;
        }
        let dst = c.key.dst;
        let external = classify_ip(dst).is_external();
        // A periodic beacon to an external peer is High; to an internal one, Medium. The score
        // is a representative point inside the matching band (parallels per-flow threat_score).
        let (severity, score) = if external {
            (Severity::High, 70)
        } else {
            (Severity::Medium, 45)
        };
        let interval_secs = c.interval_ns / 1e9;
        let evidence = vec![
            format!(
                "periodic beaconing: {} contacts to {}:{}",
                c.contacts, dst, c.key.dst_port
            ),
            format!(
                "interval ~{interval_secs:.0}s, jitter CV {:.3} (low = machine-regular)",
                c.jitter_cv
            ),
            if external {
                "external destination".to_string()
            } else {
                "internal destination".to_string()
            },
        ];
        findings.push(Finding {
            kind: FindingKind::Beacon,
            severity,
            score,
            title: format!(
                "Periodic beacon: {} -> {}:{} every ~{interval_secs:.0}s",
                c.key.src, dst, c.key.dst_port
            ),
            src_ip: c.key.src.to_string(),
            dst_ip: Some(dst.to_string()),
            dst_port: Some(c.key.dst_port),
            attack: vec!["T1071".to_string()],
            evidence,
            interval_ns: Some(c.interval_ns.round() as i64),
            jitter_cv: Some(c.jitter_cv),
            contacts: Some(c.contacts),
        });
    }
    findings
}

/// Tuning for the data-exfiltration detector.
#[derive(Debug, Clone)]
pub struct ExfilParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum outbound bytes on a channel to consider it exfil.
    pub min_bytes_out: u64,
    /// Minimum out/in ratio (asymmetry): outbound must dominate inbound by this factor.
    pub min_ratio: f64,
    /// Outbound bytes at or above this escalate the finding to Critical.
    pub critical_bytes_out: u64,
}

impl Default for ExfilParams {
    fn default() -> Self {
        ExfilParams {
            enabled: true,
            min_bytes_out: 1_000_000,        // 1 MB
            min_ratio: 4.0,                  // 4x more out than in
            critical_bytes_out: 100_000_000, // 100 MB
        }
    }
}

/// Detect data exfiltration from the behavioral tracker: one [`Finding`] per channel with a
/// large, asymmetric outbound transfer to an **external** peer. Severity is High, escalating to
/// Critical past [`ExfilParams::critical_bytes_out`]. Returned in deterministic order.
pub fn detect_exfil(tracker: &BehaviorTracker, params: &ExfilParams) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.exfil_candidates(params.min_bytes_out, params.min_ratio) {
        let dst = c.key.dst;
        // Only data leaving the network counts as exfiltration.
        if !classify_ip(dst).is_external() {
            continue;
        }
        let (severity, score) = if c.bytes_out >= params.critical_bytes_out {
            (Severity::Critical, 90)
        } else {
            (Severity::High, 72)
        };
        let ratio = c.bytes_out as f64 / (c.bytes_in as f64 + 1.0);
        findings.push(Finding {
            kind: FindingKind::DataExfil,
            severity,
            score,
            title: format!(
                "Data exfiltration: {} -> {}:{} ({} out)",
                c.key.src,
                dst,
                c.key.dst_port,
                human_bytes(c.bytes_out)
            ),
            src_ip: c.key.src.to_string(),
            dst_ip: Some(dst.to_string()),
            dst_port: Some(c.key.dst_port),
            attack: vec!["T1048".to_string()],
            evidence: vec![
                format!(
                    "outbound {} to external {}:{}",
                    human_bytes(c.bytes_out),
                    dst,
                    c.key.dst_port
                ),
                format!(
                    "{ratio:.0}x more out than in (asymmetric upload; {} in)",
                    human_bytes(c.bytes_in)
                ),
                "external destination".to_string(),
            ],
            interval_ns: None,
            jitter_cv: None,
            contacts: None,
        });
    }
    findings
}

/// Tuning for the host-sweep detector.
#[derive(Debug, Clone)]
pub struct SweepParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum distinct destination hosts on one `(src, port)` to call it a sweep.
    pub min_hosts: usize,
    /// Ports excluded from sweep detection — ordinary client traffic (web/DNS/NTP) routinely
    /// fans out to many hosts and is not a scan. A sweep of these is indistinguishable from a
    /// busy browser without payload analysis, so they are skipped to avoid false positives.
    pub ignore_ports: Vec<u16>,
}

impl Default for SweepParams {
    fn default() -> Self {
        SweepParams {
            enabled: true,
            min_hosts: 16,
            ignore_ports: vec![80, 443, 8080, 8443, 53, 123],
        }
    }
}

/// Detect horizontal host sweeps from the behavioral tracker: one [`Finding`] per `(src, port)`
/// that reached at least [`SweepParams::min_hosts`] distinct hosts on a non-ignored port. These
/// are network-service / remote-system discovery; severity is High, ATT&CK T1046. Deterministic
/// order.
pub fn detect_sweeps(tracker: &BehaviorTracker, params: &SweepParams) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.sweep_candidates(params.min_hosts) {
        if params.ignore_ports.contains(&c.dst_port) {
            continue;
        }
        findings.push(Finding {
            kind: FindingKind::HostSweep,
            severity: Severity::High,
            score: 65,
            title: format!(
                "Host sweep: {} probed {} hosts on port {}",
                c.src, c.hosts, c.dst_port
            ),
            src_ip: c.src.to_string(),
            dst_ip: None,
            dst_port: Some(c.dst_port),
            attack: vec!["T1046".to_string()],
            evidence: vec![
                format!(
                    "{} distinct destination hosts contacted on port {}",
                    c.hosts, c.dst_port
                ),
                "horizontal scan / remote-system discovery".to_string(),
            ],
            interval_ns: None,
            jitter_cv: None,
            contacts: None,
        });
    }
    findings
}

/// Tuning for the credential brute-force detector.
#[derive(Debug, Clone)]
pub struct BruteForceParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum connection attempts to one auth service before it counts as a brute force.
    pub min_attempts: u64,
    /// Destination ports treated as authentication services. Gating on these is the
    /// false-positive guard. The default is the *interactive remote-login* services
    /// ([`INTERACTIVE_AUTH_PORTS`]) where many separate connections from one source is
    /// unambiguously anomalous; high-churn services (SMB, LDAP, the databases) are deliberately
    /// left out of the default to avoid firing on legitimate enterprise service churn — the same
    /// "skip what you cannot cleanly disambiguate" stance as [`SweepParams::ignore_ports`]. Add
    /// them here when the deployment warrants it.
    pub auth_ports: Vec<u16>,
}

impl Default for BruteForceParams {
    fn default() -> Self {
        BruteForceParams {
            enabled: true,
            min_attempts: 20,
            auth_ports: INTERACTIVE_AUTH_PORTS.to_vec(),
        }
    }
}

/// Human service name for a well-known authentication port (for evidence/title text).
fn auth_service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        110 => "POP3",
        143 => "IMAP",
        389 => "LDAP",
        445 => "SMB",
        636 => "LDAPS",
        1433 => "MSSQL",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        5985 => "WinRM",
        _ => "auth service",
    }
}

/// Detect credential brute force from the behavioral tracker: one [`Finding`] per `(src, dst)`
/// channel that made at least [`BruteForceParams::min_attempts`] connection attempts to an
/// authentication service ([`BruteForceParams::auth_ports`]). High severity, ATT&CK T1110.
/// Deterministic order.
pub fn detect_brute_force(tracker: &BehaviorTracker, params: &BruteForceParams) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.brute_force_candidates(params.min_attempts, &params.auth_ports) {
        let dst = c.key.dst;
        let port = c.key.dst_port;
        let service = auth_service_name(port);
        findings.push(Finding {
            kind: FindingKind::BruteForce,
            severity: Severity::High,
            score: 68,
            title: format!(
                "Brute force: {} -> {}:{} ({} {} attempts)",
                c.key.src, dst, port, c.attempts, service
            ),
            src_ip: c.key.src.to_string(),
            dst_ip: Some(dst.to_string()),
            dst_port: Some(port),
            attack: vec!["T1110".to_string()],
            evidence: vec![
                format!(
                    "{} connection attempts to {} {}:{}",
                    c.attempts, service, dst, port
                ),
                "many separate logins to one auth service — password guessing".to_string(),
            ],
            interval_ns: None,
            jitter_cv: None,
            contacts: Some(c.attempts),
        });
    }
    findings
}

/// Remote-administration / remote-execution service ports used to pivot between hosts (the MITRE
/// T1021 sub-techniques): SSH, RPC/DCOM, SMB, RDP, VNC, WinRM. Established sessions to several
/// internal peers on these is the lateral-movement signature.
pub const LATERAL_PORTS: &[u16] = &[
    22,   // SSH (T1021.004)
    135,  // RPC / DCOM / WMI (T1021.003)
    445,  // SMB / admin shares (T1021.002)
    3389, // RDP (T1021.001)
    5900, // VNC (T1021.005)
    5985, // WinRM HTTP (T1021.006)
    5986, // WinRM HTTPS
];

/// Human service name for a well-known lateral-movement port (for evidence/title text).
fn lateral_service_name(port: u16) -> &'static str {
    match port {
        22 => "SSH",
        135 => "RPC",
        445 => "SMB",
        3389 => "RDP",
        5900 => "VNC",
        5985 | 5986 => "WinRM",
        _ => "remote-admin",
    }
}

/// Tuning for the lateral-movement detector.
///
/// **False-positive note.** This detector recognizes a *behavior* (an internal host opening admin
/// sessions to many internal peers), and that behavior is shared by legitimate east-west
/// infrastructure: backup / imaging servers, configuration management (SCCM, Ansible, WinRM),
/// patch/WSUS, monitoring and inventory collectors, jump hosts, and domain controllers all fan out
/// over SMB/RPC/RDP/WinRM by design. No purely network-level signal separates those from an
/// attacker pivot — it needs asset-role context the engine does not have. The session-byte floor
/// only excludes scans/handshakes; it does **not** distinguish benign from malicious admin fan-out.
/// The intended workflow is therefore: surface the finding with explainable evidence, and let the
/// operator exempt known management sources via [`LateralMovementParams::ignore_src`]. Treat a
/// standalone finding as "review this east-west fan-out", and trust the kill-chain correlation to
/// escalate it only when it sits alongside Discovery / Credential Access / C2 / Exfiltration.
#[derive(Debug, Clone)]
pub struct LateralMovementParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum distinct internal hosts reached with an established admin session.
    pub min_hosts: usize,
    /// Minimum bytes in **each** direction for a channel to count as an established session
    /// (rather than a SYN scan / bare handshake). A real remote-admin session moves well past
    /// this both ways; a probe does not.
    pub min_session_bytes: u64,
    /// Remote-administration ports considered. Defaults to [`LATERAL_PORTS`].
    pub lateral_ports: Vec<u16>,
    /// Source IPs exempt from lateral-movement detection — the escape hatch for known management
    /// infrastructure (backup / SCCM / monitoring / jump hosts / DCs) whose admin fan-out is
    /// expected. Empty by default; populate it per deployment to silence the recurring benign
    /// east-west finding without disabling the detector.
    pub ignore_src: Vec<IpAddr>,
}

impl Default for LateralMovementParams {
    fn default() -> Self {
        LateralMovementParams {
            enabled: true,
            // Below the host-sweep floor (16) so a few established admin sessions read as a
            // pivot, not a broad probe; high enough that a single targeted RDP/SSH is not flagged.
            min_hosts: 4,
            min_session_bytes: 512,
            lateral_ports: LATERAL_PORTS.to_vec(),
            ignore_src: Vec::new(),
        }
    }
}

/// Detect lateral movement from the behavioral tracker: one [`Finding`] per **internal** source
/// that opened an established admin session to at least [`LateralMovementParams::min_hosts`]
/// distinct **internal** hosts on one remote-administration port. East-west only (an external peer
/// is exfil/C2, not lateral movement) and session-gated (a SYN sweep is Discovery, not movement).
/// High severity, ATT&CK T1021. Deterministic order.
pub fn detect_lateral_movement(
    tracker: &BehaviorTracker,
    params: &LateralMovementParams,
) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.lateral_candidates(params.min_session_bytes, &params.lateral_ports) {
        // Lateral movement is east-west: the actor must be internal.
        if classify_ip(c.src).is_external() {
            continue;
        }
        // Known management infrastructure (backup / SCCM / monitoring / jump hosts) fans out over
        // these ports by design — let the operator exempt those sources rather than disable the
        // detector wholesale.
        if params.ignore_src.contains(&c.src) {
            continue;
        }
        // Count only internal targets (an internal host reaching out to external admin services is
        // not lateral movement within the network).
        let internal: Vec<IpAddr> = c
            .targets
            .into_iter()
            .filter(|d| !classify_ip(*d).is_external())
            .collect();
        if internal.len() < params.min_hosts {
            continue;
        }
        let port = c.dst_port;
        let service = lateral_service_name(port);
        // A couple of representative targets for the evidence, without unbounding the string.
        let sample: Vec<String> = internal.iter().take(3).map(|ip| ip.to_string()).collect();
        findings.push(Finding {
            kind: FindingKind::LateralMovement,
            severity: Severity::High,
            score: 70,
            title: format!(
                "Lateral movement: {} -> {} internal hosts over {} ({})",
                c.src,
                internal.len(),
                service,
                port
            ),
            src_ip: c.src.to_string(),
            // A fan-out finding implicates many destinations; like a sweep, it has no single dst.
            dst_ip: None,
            dst_port: Some(port),
            attack: vec!["T1021".to_string()],
            evidence: vec![
                format!(
                    "established {} sessions to {} distinct internal hosts on port {}",
                    service,
                    internal.len(),
                    port
                ),
                format!("e.g. {}", sample.join(", ")),
                "east-west admin sessions across hosts — pivoting / remote execution".to_string(),
            ],
            interval_ns: None,
            jitter_cv: None,
            contacts: Some(internal.len() as u64),
        });
    }
    findings
}

/// Drop host-sweep findings that lateral movement already explains: an established admin
/// fan-out to many internal hosts on a port is movement (real sessions), not a probe sweep, so
/// the more-specific lateral-movement finding wins for that `(src, port)`. Sweep findings carry no
/// `dst_ip` (fan-out), so the match is on `(src_ip, dst_port)`.
pub fn suppress_swept_by_lateral(sweeps: Vec<Finding>, lateral: &[Finding]) -> Vec<Finding> {
    use std::collections::HashSet;
    let claimed: HashSet<(&str, Option<u16>)> = lateral
        .iter()
        .map(|f| (f.src_ip.as_str(), f.dst_port))
        .collect();
    sweeps
        .into_iter()
        .filter(|s| !claimed.contains(&(s.src_ip.as_str(), s.dst_port)))
        .collect()
}

/// Tuning for the DNS tunneling / DGA detector.
#[derive(Debug, Clone)]
pub struct DnsTunnelParams {
    /// Master switch.
    pub enabled: bool,
    /// Minimum DNS queries on a `(src, resolver)` channel to consider it.
    pub min_queries: u64,
    /// Minimum average most-dense-label Shannon entropy (bits/char). Random tunnel/DGA labels
    /// run high (~3.8+); ordinary domains run lower.
    pub min_avg_entropy: f64,
    /// Minimum longest-label length — encoded payloads use long labels.
    pub min_label_len: u16,
}

impl Default for DnsTunnelParams {
    fn default() -> Self {
        DnsTunnelParams {
            enabled: true,
            min_queries: 30,
            min_avg_entropy: 3.5,
            min_label_len: 20,
        }
    }
}

/// Detect DNS tunneling / DGA from the behavioral tracker: one [`Finding`] per `(src, resolver)`
/// channel whose DNS queries are high-volume and high-entropy with long labels — the signature
/// of data/C2 smuggled inside DNS names. High severity, ATT&CK T1071.004. Deterministic order.
pub fn detect_dns_tunnel(tracker: &BehaviorTracker, params: &DnsTunnelParams) -> Vec<Finding> {
    if !params.enabled {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for c in tracker.dns_tunnel_candidates(
        params.min_queries,
        params.min_avg_entropy,
        params.min_label_len,
    ) {
        let mut evidence = vec![
            format!(
                "{} DNS queries to {} with avg label entropy {:.2} (max label {} chars)",
                c.queries, c.resolver, c.avg_entropy, c.max_label_len
            ),
            "high-entropy, long-label queries — data/C2 tunneled over DNS".to_string(),
        ];
        if let Some(sample) = &c.sample {
            // Bound the shown sample so a giant label cannot bloat the evidence.
            let shown: String = sample.chars().take(80).collect();
            evidence.push(format!("example: {shown}"));
        }
        findings.push(Finding {
            kind: FindingKind::DnsTunnel,
            severity: Severity::High,
            score: 74,
            title: format!(
                "DNS tunneling: {} -> {} ({} high-entropy queries)",
                c.src, c.resolver, c.queries
            ),
            src_ip: c.src.to_string(),
            dst_ip: Some(c.resolver.to_string()),
            dst_port: Some(53),
            attack: vec!["T1071.004".to_string()],
            evidence,
            interval_ns: None,
            jitter_cv: None,
            contacts: Some(c.queries),
        });
    }
    findings
}

/// Shannon entropy (bits per byte) of a string's byte distribution; `0.0` for empty input.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

/// Correlate behavioral findings into per-host incidents, ordered along the kill chain
/// (discovery -> command-and-control -> exfiltration). A host exhibiting two or more distinct
/// stages is escalated one severity band — a multi-stage chain is a confirmed incident.
/// Incidents are returned worst-first.
pub fn correlate_incidents(findings: &[Finding]) -> Vec<Incident> {
    use std::collections::{BTreeMap, BTreeSet};

    // Group every finding under its actor host (the source it is attributed to).
    let mut by_host: BTreeMap<&str, Vec<Finding>> = BTreeMap::new();
    for f in findings {
        by_host
            .entry(f.src_ip.as_str())
            .or_default()
            .push(f.clone());
    }

    let mut incidents: Vec<Incident> = by_host
        .into_iter()
        .map(|(host, mut fs)| {
            // Order the contributing findings along the kill chain (then strongest first).
            fs.sort_by(|a, b| {
                stage_ordinal(a.kind)
                    .cmp(&stage_ordinal(b.kind))
                    .then(b.score.cmp(&a.score))
            });

            let distinct_kinds: BTreeSet<FindingKind> = fs.iter().map(|f| f.kind).collect();
            let multi_stage = distinct_kinds.len() >= 2;

            let base_sev = fs
                .iter()
                .map(|f| f.severity)
                .max()
                .unwrap_or(Severity::Info);
            let base_score = fs.iter().map(|f| f.score).max().unwrap_or(0);
            // A multi-stage chain is a confirmed incident: escalate one band / bump the score.
            let severity = if multi_stage {
                escalate(base_sev)
            } else {
                base_sev
            };
            let score = if multi_stage {
                (base_score + 15).min(100)
            } else {
                base_score
            };

            // Distinct stage labels, in kill-chain order.
            let mut stages: Vec<String> = Vec::new();
            for f in &fs {
                let label = stage_label(f.kind).to_string();
                if !stages.contains(&label) {
                    stages.push(label);
                }
            }

            // ATT&CK union, sorted + deduped.
            let attack: BTreeSet<String> =
                fs.iter().flat_map(|f| f.attack.iter().cloned()).collect();

            let (title, narrative) = if fs.len() == 1 {
                (fs[0].title.clone(), fs[0].title.clone())
            } else {
                let mut seen = BTreeSet::new();
                let phrases: Vec<&str> = fs
                    .iter()
                    .filter(|f| seen.insert(f.kind))
                    .map(|f| kind_phrase(f.kind))
                    .collect();
                (
                    format!("Multi-stage incident on {host}"),
                    format!("{host} {}.", join_phrases(&phrases)),
                )
            };

            Incident {
                host: host.to_string(),
                severity,
                score,
                title,
                narrative,
                stages,
                attack: attack.into_iter().collect(),
                findings: fs,
            }
        })
        .collect();

    incidents.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then(b.score.cmp(&a.score))
            .then(a.host.cmp(&b.host))
    });
    incidents
}

/// Kill-chain stage of a finding kind (lower = earlier in the chain).
fn stage_ordinal(kind: FindingKind) -> u8 {
    match kind {
        FindingKind::HostSweep => 0,       // discovery
        FindingKind::BruteForce => 1,      // credential access
        FindingKind::LateralMovement => 2, // lateral movement
        FindingKind::Beacon => 3,          // command-and-control
        FindingKind::DataExfil => 4,       // exfiltration
        FindingKind::DnsTunnel => 4,       // exfiltration / C2 over DNS
    }
}

/// Human kill-chain stage label for a finding kind.
fn stage_label(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::HostSweep => "Discovery",
        FindingKind::BruteForce => "Credential Access",
        FindingKind::LateralMovement => "Lateral Movement",
        FindingKind::Beacon => "Command & Control",
        FindingKind::DataExfil => "Exfiltration",
        FindingKind::DnsTunnel => "Exfiltration",
    }
}

/// Narrative verb phrase for a finding kind.
fn kind_phrase(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::HostSweep => "swept the network",
        FindingKind::BruteForce => "brute-forced credentials",
        FindingKind::LateralMovement => "moved laterally",
        FindingKind::Beacon => "beaconed to a C2",
        FindingKind::DataExfil => "exfiltrated data",
        FindingKind::DnsTunnel => "tunneled data over DNS",
    }
}

/// Raise a severity by one band, saturating at `Critical`.
fn escalate(sev: Severity) -> Severity {
    match sev {
        Severity::Info => Severity::Low,
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        Severity::High | Severity::Critical => Severity::Critical,
    }
}

/// Join phrases as "a, then b, then c".
fn join_phrases(phrases: &[&str]) -> String {
    match phrases {
        [] => String::new(),
        [only] => only.to_string(),
        [first, rest @ ..] => {
            let mut s = first.to_string();
            for p in rest {
                s.push_str(", then ");
                s.push_str(p);
            }
            s
        }
    }
}

/// Compact base-1024 byte rendering for evidence strings (e.g. `5.0 MB`).
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// Absolute-tolerance float compare for the statistical assertions.
    fn approx(a: f64, b: f64) {
        assert!((a - b).abs() < 1e-9, "expected ~{b}, got {a}");
    }

    #[test]
    fn empty_stats_are_zeroed() {
        let s = StreamStats::new();
        assert_eq!(s.count(), 0);
        approx(s.mean(), 0.0);
        approx(s.variance(), 0.0);
        approx(s.stddev(), 0.0);
        approx(s.cv(), 0.0);
        assert_eq!(s.min(), 0);
        assert_eq!(s.max(), 0);
    }

    #[test]
    fn single_sample_reports_mean_and_zero_variance() {
        let mut s = StreamStats::new();
        s.push(100);
        assert_eq!(s.count(), 1);
        approx(s.mean(), 100.0);
        approx(s.variance(), 0.0);
        approx(s.cv(), 0.0);
        assert_eq!(s.min(), 100);
        assert_eq!(s.max(), 100);
    }

    #[test]
    fn constant_stream_has_zero_variance_and_cv() {
        let mut s = StreamStats::new();
        for _ in 0..5 {
            s.push(60);
        }
        assert_eq!(s.count(), 5);
        approx(s.mean(), 60.0);
        approx(s.variance(), 0.0);
        approx(s.stddev(), 0.0);
        approx(s.cv(), 0.0);
    }

    #[test]
    fn known_sequence_matches_population_variance() {
        // Classic worked example: [2,4,4,4,5,5,7,9] -> mean 5, population variance 4,
        // stddev 2, cv 0.4.
        let mut s = StreamStats::new();
        for x in [2, 4, 4, 4, 5, 5, 7, 9] {
            s.push(x);
        }
        assert_eq!(s.count(), 8);
        approx(s.mean(), 5.0);
        approx(s.variance(), 4.0);
        approx(s.stddev(), 2.0);
        approx(s.cv(), 0.4);
    }

    #[test]
    fn min_and_max_track_extremes() {
        let mut s = StreamStats::new();
        for x in [5, 1, 9, 3] {
            s.push(x);
        }
        assert_eq!(s.min(), 1);
        assert_eq!(s.max(), 9);
    }

    #[test]
    fn periodic_series_has_lower_cv_than_irregular() {
        // A near-periodic beacon: ~60s period with tiny jitter -> tiny CV.
        let mut beacon = StreamStats::new();
        for gap in [60, 61, 59, 60, 60] {
            beacon.push(gap);
        }
        // Ad-hoc human traffic: wildly varying inter-arrival gaps -> large CV.
        let mut irregular = StreamStats::new();
        for gap in [5, 120, 30, 200, 1] {
            irregular.push(gap);
        }
        assert!(
            beacon.cv() < 0.1,
            "periodic CV should be near zero, got {}",
            beacon.cv()
        );
        assert!(
            beacon.cv() < irregular.cv(),
            "beacon CV {} should be below irregular CV {}",
            beacon.cv(),
            irregular.cv()
        );
    }

    // 60-second period expressed in nanoseconds (the engine's time unit).
    const SEC: i64 = 1_000_000_000;

    #[test]
    fn first_contact_has_no_interval() {
        let mut s = ContactSeries::new();
        s.observe(1_000 * SEC);
        assert_eq!(s.contacts(), 1);
        approx(s.interval_ns(), 0.0);
        approx(s.jitter_cv(), 0.0);
    }

    #[test]
    fn periodic_contacts_yield_low_jitter() {
        let mut s = ContactSeries::new();
        // Callbacks every ~60s with a little jitter.
        for &t in &[0, 60, 121, 179, 240, 301] {
            s.observe(t * SEC);
        }
        assert_eq!(s.contacts(), 6);
        // Mean gap is about one minute.
        assert!(
            (s.interval_ns() - 60.0 * SEC as f64).abs() < 2.0 * SEC as f64,
            "interval {} not ~60s",
            s.interval_ns()
        );
        assert!(
            s.jitter_cv() < 0.1,
            "jitter CV {} not near zero",
            s.jitter_cv()
        );
    }

    #[test]
    fn out_of_order_contact_clamps_gap_to_zero() {
        let mut s = ContactSeries::new();
        s.observe(100 * SEC);
        s.observe(40 * SEC); // earlier than the previous timestamp
        assert_eq!(s.contacts(), 2);
        // The negative raw gap must be clamped, never producing a negative interval.
        assert!(
            s.interval_ns() >= 0.0,
            "interval went negative: {}",
            s.interval_ns()
        );
    }

    #[test]
    fn tracks_distinct_destination_hosts_per_source() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let attacker = ip(10, 0, 0, 9);
        // One source touches 20 distinct destination hosts on port 445 (SMB sweep).
        for last in 1..=20u8 {
            t.observe_contact(attacker, ip(10, 0, 1, last), 445, 0);
        }
        assert_eq!(t.fanout(attacker, 445), 20);
        assert!(t.is_sweeper(attacker, 445, 15));
        assert!(!t.is_sweeper(attacker, 445, 21));
        // Fan-out is per-port: nothing was seen on 443.
        assert_eq!(t.fanout(attacker, 443), 0);
        // An unrelated source has no fan-out.
        assert_eq!(t.fanout(ip(10, 0, 0, 1), 445), 0);
        assert!(!t.is_sweeper(ip(1, 1, 1, 1), 445, 1));
    }

    #[test]
    fn detect_sweeps_flags_service_port_and_ignores_web() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let attacker = ip(10, 0, 0, 9);
        // SMB sweep: 20 distinct hosts on 445.
        for last in 1..=20u8 {
            t.observe_contact(attacker, ip(10, 0, 1, last), 445, 0);
        }
        // A busy browser: 20 hosts on 443 must NOT be flagged (ignored port).
        for last in 1..=20u8 {
            t.observe_contact(attacker, ip(10, 0, 2, last), 443, 0);
        }

        let findings = detect_sweeps(&t, &SweepParams::default());
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::HostSweep);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.src_ip, "10.0.0.9");
        assert_eq!(f.dst_port, Some(445));
        assert!(f.dst_ip.is_none()); // a fan-out finding has no single destination
        assert!(
            f.attack.iter().any(|a| a == "T1046"),
            "attack: {:?}",
            f.attack
        );
    }

    #[test]
    fn detect_sweeps_below_threshold_or_disabled_yield_nothing() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let attacker = ip(10, 0, 0, 9);
        // Only 5 hosts on 445 — below min_hosts.
        for last in 1..=5u8 {
            t.observe_contact(attacker, ip(10, 0, 1, last), 445, 0);
        }
        assert!(detect_sweeps(&t, &SweepParams::default()).is_empty());

        // Now well above threshold, but disabled.
        for last in 6..=25u8 {
            t.observe_contact(attacker, ip(10, 0, 1, last), 445, 0);
        }
        let params = SweepParams {
            enabled: false,
            ..SweepParams::default()
        };
        assert!(detect_sweeps(&t, &params).is_empty());
    }

    #[test]
    fn detect_brute_force_flags_repeated_auth_attempts_high() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let attacker = ip(10, 0, 0, 9);
        let victim = ip(10, 0, 0, 5);
        // 25 separate connection attempts to the victim's SSH service (each a distinct flow).
        for i in 0..25i64 {
            t.observe_contact(attacker, victim, 22, i * SEC);
        }
        // A handful of benign HTTPS connections to the same victim must NOT be a brute force.
        for i in 0..3i64 {
            t.observe_contact(attacker, victim, 443, i * SEC);
        }

        let findings = detect_brute_force(&t, &BruteForceParams::default());
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::BruteForce);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.src_ip, "10.0.0.9");
        assert_eq!(f.dst_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(f.dst_port, Some(22));
        assert!(f.attack.iter().any(|a| a == "T1110"), "attack: {:?}", f.attack);
        assert!(f.contacts.unwrap() >= 20);
        assert!(
            f.title.contains("SSH"),
            "title should name the service: {}",
            f.title
        );
    }

    #[test]
    fn detect_brute_force_ignores_non_auth_ports_and_below_threshold() {
        // Many attempts, but to a non-auth port (8080) — not a credential brute force.
        let mut high_vol = BehaviorTracker::new(DetectConfig::default());
        for i in 0..50i64 {
            high_vol.observe_contact(ip(10, 0, 0, 9), ip(10, 0, 0, 5), 8080, i * SEC);
        }
        assert!(detect_brute_force(&high_vol, &BruteForceParams::default()).is_empty());

        // An auth port, but only a few attempts — below the threshold.
        let mut few = BehaviorTracker::new(DetectConfig::default());
        for i in 0..5i64 {
            few.observe_contact(ip(10, 0, 0, 9), ip(10, 0, 0, 5), 3389, i * SEC);
        }
        assert!(detect_brute_force(&few, &BruteForceParams::default()).is_empty());

        // A high-churn service (SMB 445) is NOT in the default auth_ports — many connections to a
        // file server are ordinary, so the default must not flag them.
        let mut smb = BehaviorTracker::new(DetectConfig::default());
        for i in 0..50i64 {
            smb.observe_contact(ip(10, 0, 0, 9), ip(10, 0, 0, 5), 445, i * SEC);
        }
        assert!(detect_brute_force(&smb, &BruteForceParams::default()).is_empty());
    }

    #[test]
    fn detect_brute_force_disabled_yields_nothing() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        for i in 0..30i64 {
            t.observe_contact(ip(10, 0, 0, 9), ip(10, 0, 0, 5), 22, i * SEC);
        }
        let params = BruteForceParams {
            enabled: false,
            ..BruteForceParams::default()
        };
        assert!(detect_brute_force(&t, &params).is_empty());
    }

    #[test]
    fn regular_auth_channel_is_brute_force_not_beacon() {
        // A throttled credential guesser: 25 regular, low-jitter SSH attempts ~5 s apart. That
        // timing ALSO satisfies the beacon predicate (>=12 contacts, CV~0, interval in [1s,24h]),
        // so without a guard the one channel would be reported as BOTH a brute force AND a C2
        // beacon. BeaconParams.ignore_ports skips the auth ports, so it is only a brute force.
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let attacker = ip(10, 0, 0, 9);
        let victim = ip(10, 0, 0, 5);
        for i in 0..25i64 {
            t.observe_contact(attacker, victim, 22, i * 5 * SEC);
        }

        let beacons = detect_beacons(&t, &BeaconParams::default());
        let brutes = detect_brute_force(&t, &BruteForceParams::default());
        assert!(
            beacons.iter().all(|b| b.dst_port != Some(22)),
            "auth-port channel must not be reported as a beacon: {beacons:?}"
        );
        assert_eq!(brutes.len(), 1, "the channel is a brute force: {brutes:?}");
        assert_eq!(brutes[0].dst_port, Some(22));

        // Prove it is the GUARD, not the timing, that prevents the overlap: clear ignore_ports and
        // the identical channel now also trips the beacon detector.
        let no_ignore = BeaconParams {
            ignore_ports: vec![],
            ..BeaconParams::default()
        };
        assert!(
            detect_beacons(&t, &no_ignore)
                .iter()
                .any(|b| b.dst_port == Some(22)),
            "without the guard the auth channel would also look like a beacon"
        );
    }

    #[test]
    fn lateral_movement_flags_established_admin_fanout_high() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let attacker = ip(10, 0, 0, 9); // internal
                                        // Established RDP sessions (bytes both ways) to 5 distinct internal hosts.
        for h in 1..=5u8 {
            t.observe_flow_contact(attacker, ip(10, 0, 1, h), 3389, h as i64 * SEC, 4000, 4000);
        }

        let findings = detect_lateral_movement(&t, &LateralMovementParams::default());
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::LateralMovement);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.src_ip, "10.0.0.9");
        assert!(f.dst_ip.is_none(), "fan-out finding has no single dst");
        assert_eq!(f.dst_port, Some(3389));
        assert!(f.attack.iter().any(|a| a == "T1021"), "attack: {:?}", f.attack);
        assert_eq!(f.contacts, Some(5));
        assert!(f.title.contains("RDP"), "title names the service: {}", f.title);
    }

    #[test]
    fn lateral_movement_ignores_probes_external_and_below_threshold() {
        // SYN-only fan-out: 8 hosts on 445, no bytes back (a sweep, not established sessions).
        let mut probes = BehaviorTracker::new(DetectConfig::default());
        for h in 1..=8u8 {
            probes.observe_flow_contact(ip(10, 0, 0, 9), ip(10, 0, 1, h), 445, 0, 60, 0);
        }
        assert!(detect_lateral_movement(&probes, &LateralMovementParams::default()).is_empty());

        // Established sessions, but to EXTERNAL hosts — that is C2/exfil, not lateral movement.
        let mut external = BehaviorTracker::new(DetectConfig::default());
        for h in 1..=6u8 {
            external.observe_flow_contact(ip(10, 0, 0, 9), ip(8, 8, 8, h), 22, 0, 4000, 4000);
        }
        assert!(detect_lateral_movement(&external, &LateralMovementParams::default()).is_empty());

        // Established internal sessions, but only to 2 hosts — below the host threshold.
        let mut few = BehaviorTracker::new(DetectConfig::default());
        for h in 1..=2u8 {
            few.observe_flow_contact(ip(10, 0, 0, 9), ip(10, 0, 1, h), 445, 0, 4000, 4000);
        }
        assert!(detect_lateral_movement(&few, &LateralMovementParams::default()).is_empty());
    }

    #[test]
    fn lateral_movement_disabled_yields_nothing() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        for h in 1..=6u8 {
            t.observe_flow_contact(ip(10, 0, 0, 9), ip(10, 0, 1, h), 445, 0, 4000, 4000);
        }
        let params = LateralMovementParams {
            enabled: false,
            ..LateralMovementParams::default()
        };
        assert!(detect_lateral_movement(&t, &params).is_empty());
    }

    #[test]
    fn suppress_swept_by_lateral_drops_overlapping_sweep_only() {
        // A sweep and a lateral-movement finding on the SAME (src, port): the established-session
        // interpretation (lateral) wins, so that sweep is dropped. An unrelated sweep survives.
        let overlap_sweep =
            mk_finding(FindingKind::HostSweep, "10.0.0.9", Severity::High, 65, &["T1046"]);
        let other_sweep =
            mk_finding(FindingKind::HostSweep, "10.0.0.7", Severity::High, 65, &["T1046"]);
        let lateral = mk_finding(
            FindingKind::LateralMovement,
            "10.0.0.9",
            Severity::High,
            70,
            &["T1021"],
        );
        // mk_finding sets dst_port = Some(443) for all; align the non-overlapping sweep to a
        // different port so only the matching (src, port) is suppressed.
        let mut other_sweep = other_sweep;
        other_sweep.dst_port = Some(445);

        let kept = suppress_swept_by_lateral(
            vec![overlap_sweep.clone(), other_sweep.clone()],
            &[lateral],
        );
        assert_eq!(kept.len(), 1, "only the overlapping sweep is dropped: {kept:?}");
        assert_eq!(kept[0].src_ip, "10.0.0.7");
    }

    #[test]
    fn lateral_movement_respects_source_allowlist() {
        // A benign internal admin server (e.g. backup / SCCM) fans out established SMB sessions to
        // several internal hosts — the dominant false-positive surface. By default it fires (the
        // behavior is real); exempting the known source via ignore_src silences it without
        // disabling the detector. This makes the FP tunable and the guard non-vacuous.
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let infra = ip(10, 0, 0, 9);
        for h in 1..=5u8 {
            t.observe_flow_contact(infra, ip(10, 0, 1, h), 445, h as i64 * SEC, 4000, 4000);
        }
        assert_eq!(
            detect_lateral_movement(&t, &LateralMovementParams::default()).len(),
            1,
            "established admin fan-out fires by default"
        );
        let params = LateralMovementParams {
            ignore_src: vec![infra],
            ..LateralMovementParams::default()
        };
        assert!(
            detect_lateral_movement(&t, &params).is_empty(),
            "an allowlisted source is exempt"
        );
    }

    #[test]
    fn beacon_ignores_remote_admin_ports() {
        // A periodic, low-jitter ESTABLISHED series on SMB (445) — a remote-admin / monitoring
        // cadence — must not be reported as a C2 beacon. 445 is not an interactive-auth port, so
        // this guards extending BeaconParams.ignore_ports to the lateral-movement ports.
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let src = ip(10, 0, 0, 9);
        let dst = ip(10, 0, 0, 5);
        for i in 0..16i64 {
            t.observe_flow_contact(src, dst, 445, i * 30 * SEC, 2000, 2000);
        }
        assert!(
            detect_beacons(&t, &BeaconParams::default())
                .iter()
                .all(|b| b.dst_port != Some(445)),
            "admin-port cadence must not be a beacon"
        );
        // Prove it is the guard, not the timing: clear ignore_ports and 445 trips the beacon.
        let no_ignore = BeaconParams {
            ignore_ports: vec![],
            ..BeaconParams::default()
        };
        assert!(
            detect_beacons(&t, &no_ignore)
                .iter()
                .any(|b| b.dst_port == Some(445)),
            "without the guard the admin cadence would look like a beacon"
        );
    }

    #[test]
    fn established_admin_spray_reports_both_credential_access_and_lateral_movement() {
        // A source that opens many established SSH sessions to each of several internal hosts is a
        // credential spray AND a pivot. Both detectors fire (brute force per host, lateral movement
        // for the fan-out) and correlation orders them Credential Access -> Lateral Movement — the
        // intended kill-chain coexistence on the shared port 22 (not a double-count to suppress).
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let attacker = ip(10, 0, 0, 9);
        for h in 1..=4u8 {
            let victim = ip(10, 0, 1, h);
            for i in 0..22i64 {
                t.observe_flow_contact(attacker, victim, 22, i * SEC, 800, 800);
            }
        }
        let brutes = detect_brute_force(&t, &BruteForceParams::default());
        let lateral = detect_lateral_movement(&t, &LateralMovementParams::default());
        assert_eq!(brutes.len(), 4, "one brute finding per sprayed host: {brutes:?}");
        assert_eq!(lateral.len(), 1, "one lateral fan-out finding: {lateral:?}");
        // Port 22 is in the beacon ignore set, so the regular cadence is NOT also a beacon.
        assert!(detect_beacons(&t, &BeaconParams::default()).is_empty());

        let mut all = brutes;
        all.extend(lateral);
        let inc = correlate_incidents(&all);
        assert_eq!(inc.len(), 1);
        assert_eq!(inc[0].stages, vec!["Credential Access", "Lateral Movement"]);
    }

    #[test]
    fn beacon_candidate_surfaced_for_periodic_destination() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let bot = ip(10, 0, 0, 5);
        let c2 = ip(203, 0, 113, 7);
        // Regular callbacks to the C2 every ~60s.
        for i in 0..8i64 {
            t.observe_contact(bot, c2, 443, i * 60 * SEC + (i % 2) * SEC);
        }
        // A one-off connection to a benign host must NOT look like a beacon.
        t.observe_contact(bot, ip(10, 0, 0, 2), 80, 5 * SEC);

        let candidates = t.beacon_candidates(5, 0.15);
        assert_eq!(candidates.len(), 1, "candidates: {candidates:?}");
        let c = candidates[0];
        assert_eq!(c.key, ContactKey::new(bot, c2, 443));
        assert!(c.contacts >= 5);
        assert!(c.jitter_cv <= 0.15);

        // The channel is queryable directly too.
        let series = t
            .series(ContactKey::new(bot, c2, 443))
            .expect("series tracked");
        assert_eq!(series.contacts(), 8);
    }

    #[test]
    fn tracker_drops_new_channels_at_capacity() {
        let cfg = DetectConfig {
            max_tracked_keys: 1,
            max_fanout_per_src: 4096,
        };
        let mut t = BehaviorTracker::new(cfg);
        let src = ip(10, 0, 0, 5);
        // First channel is tracked.
        t.observe_contact(src, ip(203, 0, 113, 1), 443, 0);
        // A second distinct channel at capacity is dropped (graceful degradation).
        t.observe_contact(src, ip(203, 0, 113, 2), 443, 0);
        assert_eq!(t.tracked_channels(), 1);
        assert!(t
            .series(ContactKey::new(src, ip(203, 0, 113, 1), 443))
            .is_some());
        assert!(t
            .series(ContactKey::new(src, ip(203, 0, 113, 2), 443))
            .is_none());
    }

    /// Feed `n` near-periodic contacts (`period_s` seconds apart, +/- 1s jitter) into a channel.
    fn feed_periodic(
        t: &mut BehaviorTracker,
        src: IpAddr,
        dst: IpAddr,
        port: u16,
        n: i64,
        period_s: i64,
    ) {
        for i in 0..n {
            let ts = i * period_s * SEC + (i % 2) * SEC;
            t.observe_contact(src, dst, port, ts);
        }
    }

    #[test]
    fn periodic_external_channel_yields_high_beacon_finding() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let bot = ip(10, 0, 0, 5);
        let c2 = ip(8, 8, 8, 8); // a Public (external) address standing in for the C2
        feed_periodic(&mut t, bot, c2, 443, 16, 60);

        let findings = detect_beacons(&t, &BeaconParams::default());
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        let b = &findings[0];
        assert_eq!(b.kind, FindingKind::Beacon);
        assert_eq!(b.severity, Severity::High); // external destination
        assert_eq!(b.src_ip, "10.0.0.5");
        assert_eq!(b.dst_ip.as_deref(), Some("8.8.8.8"));
        assert_eq!(b.dst_port, Some(443));
        assert!(
            b.attack.iter().any(|a| a == "T1071"),
            "attack: {:?}",
            b.attack
        );
        assert!(b.contacts.unwrap() >= 6);
        assert!(b.jitter_cv.unwrap() < 0.15);
        assert!(b.interval_ns.unwrap() > 0);
        assert!(!b.evidence.is_empty());
    }

    #[test]
    fn beacon_score_sits_in_its_severity_band() {
        // External beacon -> High band (60..=84).
        let mut ext = BehaviorTracker::new(DetectConfig::default());
        feed_periodic(&mut ext, ip(10, 0, 0, 5), ip(8, 8, 8, 8), 443, 16, 60);
        let f = detect_beacons(&ext, &BeaconParams::default());
        assert_eq!(f.len(), 1);
        assert!(
            (60..=84).contains(&f[0].score),
            "external score {} not in High band",
            f[0].score
        );

        // Internal beacon -> Medium band (35..=59).
        let mut int = BehaviorTracker::new(DetectConfig::default());
        feed_periodic(&mut int, ip(10, 0, 0, 5), ip(10, 0, 0, 9), 8080, 16, 30);
        let g = detect_beacons(&int, &BeaconParams::default());
        assert_eq!(g.len(), 1);
        assert!(
            (35..=59).contains(&g[0].score),
            "internal score {} not in Medium band",
            g[0].score
        );
    }

    #[test]
    fn internal_beacon_is_medium_severity() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        feed_periodic(&mut t, ip(10, 0, 0, 5), ip(10, 0, 0, 9), 8080, 16, 30);
        let findings = detect_beacons(&t, &BeaconParams::default());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium); // internal destination
    }

    #[test]
    fn subthreshold_or_irregular_channels_yield_no_finding() {
        // Too few contacts.
        let mut few = BehaviorTracker::new(DetectConfig::default());
        feed_periodic(&mut few, ip(10, 0, 0, 5), ip(203, 0, 113, 7), 443, 3, 60);
        assert!(detect_beacons(&few, &BeaconParams::default()).is_empty());

        // Enough contacts but wildly irregular timing (high CV) — not a beacon.
        let mut irregular = BehaviorTracker::new(DetectConfig::default());
        let bot = ip(10, 0, 0, 5);
        let c2 = ip(203, 0, 113, 7);
        for ts in [0, 5, 130, 140, 600, 605, 1800, 1810] {
            irregular.observe_contact(bot, c2, 443, ts * SEC);
        }
        assert!(detect_beacons(&irregular, &BeaconParams::default()).is_empty());
    }

    #[test]
    fn disabled_params_yield_no_findings() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        feed_periodic(&mut t, ip(10, 0, 0, 5), ip(203, 0, 113, 7), 443, 8, 60);
        let params = BeaconParams {
            enabled: false,
            ..BeaconParams::default()
        };
        assert!(detect_beacons(&t, &params).is_empty());
    }

    #[test]
    fn contact_from_flow_picks_service_port_and_initiator() {
        use crate::model::flow::FlowKey;
        use crate::model::packet::Transport;
        // Client 10.0.0.5:50000 -> server 203.0.113.7:443.
        let (key, _dir) = FlowKey::normalized(
            ip(10, 0, 0, 5),
            50000,
            ip(203, 0, 113, 7),
            443,
            Transport::Tcp,
        );
        let rec = FlowRecord::new(key, 1234);
        let c = contact_from_flow(&rec).expect("port-bearing flow");
        assert_eq!(c.client, ip(10, 0, 0, 5));
        assert_eq!(c.server, ip(203, 0, 113, 7));
        assert_eq!(c.server_port, 443);
        assert_eq!(c.ts_ns, 1234);
    }

    #[test]
    fn contact_from_flow_is_none_for_portless_transport() {
        use crate::model::flow::FlowKey;
        use crate::model::packet::Transport;
        let (key, _dir) =
            FlowKey::normalized(ip(10, 0, 0, 5), 0, ip(10, 0, 0, 6), 0, Transport::Icmp);
        let rec = FlowRecord::new(key, 0);
        assert!(contact_from_flow(&rec).is_none());
    }

    #[test]
    fn channel_folds_directional_bytes() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let src = ip(10, 0, 0, 5);
        let ext = ip(8, 8, 8, 8);
        t.observe_flow_contact(src, ext, 443, 0, 500_000, 1_000);
        t.observe_flow_contact(src, ext, 443, SEC, 700_000, 2_000);
        let s = t
            .series(ContactKey::new(src, ext, 443))
            .expect("channel tracked");
        assert_eq!(s.contacts(), 2);
        assert_eq!(s.bytes_out(), 1_200_000);
        assert_eq!(s.bytes_in(), 3_000);
    }

    #[test]
    fn exfil_candidate_for_large_asymmetric_outbound() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let src = ip(10, 0, 0, 5);
        let ext = ip(8, 8, 8, 8);
        // Big asymmetric upload — exfil shape.
        t.observe_flow_contact(src, ext, 443, 0, 5_000_000, 10_000);
        // A download (inbound-heavy) is NOT exfil.
        t.observe_flow_contact(src, ext, 80, 0, 10_000, 5_000_000);
        // A small channel is below the volume floor.
        t.observe_flow_contact(src, ip(10, 0, 0, 9), 445, 0, 1_000, 100);

        let cands = t.exfil_candidates(1_000_000, 4.0);
        assert_eq!(cands.len(), 1, "candidates: {cands:?}");
        assert_eq!(cands[0].key, ContactKey::new(src, ext, 443));
        assert!(cands[0].bytes_out >= 1_000_000);
    }

    #[test]
    fn detect_exfil_flags_external_upload_high() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let src = ip(10, 0, 0, 5);
        // Large asymmetric upload to an external peer.
        t.observe_flow_contact(src, ip(8, 8, 8, 8), 443, 0, 5_000_000, 10_000);
        // Same shape but to an INTERNAL peer — not exfil out of the network.
        t.observe_flow_contact(src, ip(10, 0, 0, 9), 445, 0, 5_000_000, 10_000);

        let findings = detect_exfil(&t, &ExfilParams::default());
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::DataExfil);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.dst_ip.as_deref(), Some("8.8.8.8"));
        assert_eq!(f.dst_port, Some(443));
        assert!(
            f.attack.iter().any(|a| a == "T1048"),
            "attack: {:?}",
            f.attack
        );
        assert!(!f.evidence.is_empty());
    }

    #[test]
    fn detect_exfil_escalates_huge_volume_to_critical() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let src = ip(10, 0, 0, 5);
        t.observe_flow_contact(src, ip(8, 8, 8, 8), 443, 0, 200_000_000, 10_000);
        let findings = detect_exfil(&t, &ExfilParams::default());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn detect_exfil_disabled_yields_nothing() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        t.observe_flow_contact(ip(10, 0, 0, 5), ip(8, 8, 8, 8), 443, 0, 5_000_000, 10_000);
        let params = ExfilParams {
            enabled: false,
            ..ExfilParams::default()
        };
        assert!(detect_exfil(&t, &params).is_empty());
    }

    fn mk_finding(
        kind: FindingKind,
        src: &str,
        sev: Severity,
        score: u16,
        attack: &[&str],
    ) -> Finding {
        Finding {
            kind,
            severity: sev,
            score,
            title: format!("{} on {src}", kind.as_str()),
            src_ip: src.to_string(),
            dst_ip: Some("1.2.3.4".to_string()),
            dst_port: Some(443),
            attack: attack.iter().map(|s| s.to_string()).collect(),
            evidence: Vec::new(),
            interval_ns: None,
            jitter_cv: None,
            contacts: None,
        }
    }

    #[test]
    fn single_finding_yields_one_unescalated_incident() {
        let f = mk_finding(
            FindingKind::Beacon,
            "10.0.0.5",
            Severity::High,
            70,
            &["T1071"],
        );
        let inc = correlate_incidents(&[f]);
        assert_eq!(inc.len(), 1);
        assert_eq!(inc[0].host, "10.0.0.5");
        assert_eq!(inc[0].severity, Severity::High); // single stage — not escalated
        assert_eq!(inc[0].findings.len(), 1);
        assert_eq!(inc[0].stages, vec!["Command & Control"]);
    }

    #[test]
    fn multi_stage_chain_escalates_and_orders_by_kill_chain() {
        let host = "10.13.37.7";
        // Added out of kill-chain order: exfil, beacon, sweep.
        let exfil = mk_finding(FindingKind::DataExfil, host, Severity::High, 72, &["T1048"]);
        let beacon = mk_finding(FindingKind::Beacon, host, Severity::High, 70, &["T1071"]);
        let sweep = mk_finding(FindingKind::HostSweep, host, Severity::High, 65, &["T1046"]);

        let inc = correlate_incidents(&[exfil, beacon, sweep]);
        assert_eq!(inc.len(), 1);
        let i = &inc[0];
        assert_eq!(i.host, host);
        // Three distinct stages -> escalate High to Critical.
        assert_eq!(i.severity, Severity::Critical);
        assert_eq!(
            i.stages,
            vec!["Discovery", "Command & Control", "Exfiltration"]
        );
        // Contributing findings ordered along the kill chain.
        assert_eq!(i.findings.len(), 3);
        assert_eq!(i.findings[0].kind, FindingKind::HostSweep);
        assert_eq!(i.findings[1].kind, FindingKind::Beacon);
        assert_eq!(i.findings[2].kind, FindingKind::DataExfil);
        // ATT&CK union, sorted.
        assert_eq!(i.attack, vec!["T1046", "T1048", "T1071"]);
        assert!(i.narrative.contains("swept"), "narrative: {}", i.narrative);
    }

    #[test]
    fn brute_force_sorts_into_credential_access_between_discovery_and_c2() {
        let host = "10.13.37.7";
        // Added out of kill-chain order: beacon (C2), sweep (discovery), brute force (cred access).
        let beacon = mk_finding(FindingKind::Beacon, host, Severity::High, 70, &["T1071"]);
        let sweep = mk_finding(FindingKind::HostSweep, host, Severity::High, 65, &["T1046"]);
        let brute = mk_finding(FindingKind::BruteForce, host, Severity::High, 68, &["T1110"]);

        let inc = correlate_incidents(&[beacon, sweep, brute]);
        assert_eq!(inc.len(), 1);
        let i = &inc[0];
        // Three distinct stages -> escalate High to Critical.
        assert_eq!(i.severity, Severity::Critical);
        assert_eq!(
            i.stages,
            vec!["Discovery", "Credential Access", "Command & Control"]
        );
        // Findings ordered along the kill chain: sweep -> brute force -> beacon.
        assert_eq!(i.findings[0].kind, FindingKind::HostSweep);
        assert_eq!(i.findings[1].kind, FindingKind::BruteForce);
        assert_eq!(i.findings[2].kind, FindingKind::Beacon);
        assert_eq!(i.attack, vec!["T1046", "T1071", "T1110"]);
    }

    #[test]
    fn full_five_stage_kill_chain_orders_and_escalates() {
        let host = "10.13.37.7";
        // Added out of order; correlation must sort them along the full kill chain.
        let exfil = mk_finding(FindingKind::DataExfil, host, Severity::High, 72, &["T1048"]);
        let lateral = mk_finding(
            FindingKind::LateralMovement,
            host,
            Severity::High,
            70,
            &["T1021"],
        );
        let beacon = mk_finding(FindingKind::Beacon, host, Severity::High, 70, &["T1071"]);
        let sweep = mk_finding(FindingKind::HostSweep, host, Severity::High, 65, &["T1046"]);
        let brute = mk_finding(FindingKind::BruteForce, host, Severity::High, 68, &["T1110"]);

        let inc = correlate_incidents(&[exfil, lateral, beacon, sweep, brute]);
        assert_eq!(inc.len(), 1);
        let i = &inc[0];
        assert_eq!(i.severity, Severity::Critical);
        assert_eq!(
            i.stages,
            vec![
                "Discovery",
                "Credential Access",
                "Lateral Movement",
                "Command & Control",
                "Exfiltration"
            ]
        );
        let kinds: Vec<FindingKind> = i.findings.iter().map(|f| f.kind).collect();
        assert_eq!(
            kinds,
            vec![
                FindingKind::HostSweep,
                FindingKind::BruteForce,
                FindingKind::LateralMovement,
                FindingKind::Beacon,
                FindingKind::DataExfil,
            ]
        );
        assert!(i.narrative.contains("moved laterally"), "narrative: {}", i.narrative);
    }

    #[test]
    fn different_hosts_are_separate_incidents_ranked_worst_first() {
        let a = mk_finding(
            FindingKind::Beacon,
            "10.0.0.5",
            Severity::Medium,
            45,
            &["T1071"],
        );
        let b1 = mk_finding(
            FindingKind::HostSweep,
            "10.0.0.9",
            Severity::High,
            65,
            &["T1046"],
        );
        let b2 = mk_finding(
            FindingKind::Beacon,
            "10.0.0.9",
            Severity::High,
            70,
            &["T1071"],
        );

        let inc = correlate_incidents(&[a, b1, b2]);
        assert_eq!(inc.len(), 2);
        // 10.0.0.9 is multi-stage -> Critical, ranks first.
        assert_eq!(inc[0].host, "10.0.0.9");
        assert_eq!(inc[0].severity, Severity::Critical);
        assert_eq!(inc[1].host, "10.0.0.5");
        assert_eq!(inc[1].severity, Severity::Medium);
    }

    /// A 32-char base32 label with high entropy, deterministic per `seed`.
    fn tunnel_label(seed: u64) -> String {
        const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xDEAD_BEEF;
        (0..32)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                ALPHA[(x % 32) as usize] as char
            })
            .collect()
    }

    #[test]
    fn shannon_entropy_reflects_randomness() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert!(shannon_entropy("aaaaaaaa") < 1e-9); // one symbol -> zero entropy
                                                     // A normal label is low-entropy; a random tunnel label is clearly higher.
        assert!(shannon_entropy("example") < 3.0);
        assert!(
            shannon_entropy(&tunnel_label(1)) > 3.0,
            "entropy {}",
            shannon_entropy(&tunnel_label(1))
        );
    }

    #[test]
    fn dns_tunnel_detected_for_high_entropy_volume() {
        let mut t = BehaviorTracker::new(DetectConfig::default());
        let bot = ip(10, 0, 0, 5);
        let resolver = ip(10, 0, 0, 1);
        for i in 0..40u64 {
            let qname = format!("{}.tunnel.evil.example", tunnel_label(i));
            t.observe_dns_query(bot, resolver, &qname);
        }
        let f = detect_dns_tunnel(&t, &DnsTunnelParams::default());
        assert_eq!(f.len(), 1, "findings: {f:?}");
        assert_eq!(f[0].kind, FindingKind::DnsTunnel);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].src_ip, "10.0.0.5");
        assert_eq!(f[0].dst_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(f[0].dst_port, Some(53));
        assert!(f[0].attack.iter().any(|a| a == "T1071.004"));
        assert!(f[0].contacts.unwrap() >= 30);
    }

    #[test]
    fn benign_or_low_volume_dns_is_not_flagged() {
        // Ordinary domains: short, low-entropy labels.
        let mut benign = BehaviorTracker::new(DetectConfig::default());
        for _ in 0..60 {
            benign.observe_dns_query(ip(10, 0, 0, 5), ip(10, 0, 0, 1), "www.example.com");
        }
        assert!(detect_dns_tunnel(&benign, &DnsTunnelParams::default()).is_empty());

        // High-entropy but only a few queries -> below the volume floor.
        let mut few = BehaviorTracker::new(DetectConfig::default());
        for i in 0..5u64 {
            let q = format!("{}.t.evil.example", tunnel_label(i));
            few.observe_dns_query(ip(10, 0, 0, 5), ip(10, 0, 0, 1), &q);
        }
        assert!(detect_dns_tunnel(&few, &DnsTunnelParams::default()).is_empty());
    }
}
