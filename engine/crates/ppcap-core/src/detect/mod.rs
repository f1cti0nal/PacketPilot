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
}

/// A destination channel that looks like a periodic beacon.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BeaconCandidate {
    pub key: ContactKey,
    pub contacts: u64,
    pub interval_ns: f64,
    pub jitter_cv: f64,
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
/// maintains (a) a per-channel inter-arrival series for beaconing and (b) a per-source set of
/// distinct destination hosts for horizontal sweep detection. Both maps degrade gracefully at
/// capacity (a brand-new key is dropped) so peak memory stays bounded.
pub struct BehaviorTracker {
    cfg: DetectConfig,
    channels: HashMap<ContactKey, ContactSeries>,
    fanout: HashMap<IpAddr, HashSet<IpAddr>>,
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

    /// Fold one contact: a new `src -> dst:dst_port` connection observed at `ts_ns`.
    pub fn observe_contact(&mut self, src: IpAddr, dst: IpAddr, dst_port: u16, ts_ns: i64) {
        // Per-channel inter-arrival series (bounded: a brand-new channel at capacity is
        // dropped — best-effort heavy-hitter signal, not an exact set).
        let key = ContactKey::new(src, dst, dst_port);
        if let Some(series) = self.channels.get_mut(&key) {
            series.observe(ts_ns);
        } else if self.channels.len() < self.cfg.max_tracked_keys.max(1) {
            let mut series = ContactSeries::new();
            series.observe(ts_ns);
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
}
