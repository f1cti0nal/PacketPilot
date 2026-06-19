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
}

impl BehaviorTracker {
    /// Create an empty tracker.
    pub fn new(cfg: DetectConfig) -> BehaviorTracker {
        BehaviorTracker {
            cfg,
            channels: HashMap::new(),
            fanout: HashMap::new(),
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

        // Per-source distinct destination-host set (sweep signal), bounded in both the number
        // of sources and the hosts retained per source.
        if let Some(set) = self.fanout.get_mut(&src) {
            if set.len() < self.cfg.max_fanout_per_src {
                set.insert(dst);
            }
        } else if self.fanout.len() < self.cfg.max_tracked_keys.max(1) {
            let mut set = HashSet::new();
            set.insert(dst);
            self.fanout.insert(src, set);
        }
    }

    /// Borrow the inter-arrival series for a channel, if tracked.
    pub fn series(&self, key: ContactKey) -> Option<&ContactSeries> {
        self.channels.get(&key)
    }

    /// Number of distinct destination hosts `src` has contacted (the sweep fan-out).
    pub fn fanout(&self, src: IpAddr) -> usize {
        self.fanout.get(&src).map_or(0, |set| set.len())
    }

    /// Whether `src` contacted at least `threshold` distinct destination hosts.
    pub fn is_sweeper(&self, src: IpAddr, threshold: usize) -> bool {
        self.fanout(src) >= threshold
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
}

use crate::enrich::classify_ip;
use crate::model::finding::{Finding, FindingKind};
use crate::model::flow::FlowRecord;
use crate::model::severity::Severity;

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
        }
    }
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
            t.observe_contact(attacker, ip(10, 0, 0, last), 445, 0);
        }
        assert_eq!(t.fanout(attacker), 20);
        assert!(t.is_sweeper(attacker, 15));
        assert!(!t.is_sweeper(attacker, 21));
        // An unrelated source has no fan-out.
        assert_eq!(t.fanout(ip(10, 0, 0, 1)), 0);
        assert!(!t.is_sweeper(ip(1, 1, 1, 1), 1));
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
}
