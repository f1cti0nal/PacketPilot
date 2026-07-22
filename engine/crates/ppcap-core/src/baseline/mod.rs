//! Behavioral Baseline Learning — learn a per-internal-host behavioral profile across captures,
//! persist it as an offline JSON sidecar, and compare a new capture against it to raise
//! explainable "baseline deviation" findings.
//!
//! This is the local-first, no-backend core of the feature: everything is a pure transform over a
//! small JSON sidecar. A [`CaptureProfile`] is this capture's per-host egress snapshot (produced by
//! [`crate::detect::BehaviorTracker::baseline_snapshot`] during the streaming pass);
//! [`update_baseline`] folds one such snapshot into a persisted [`BaselineProfile`] (running
//! per-host statistics + seen sets), and [`compare_to_baseline`] diffs a fresh snapshot against the
//! learned profile — a host doing something it never did before yields a
//! [`FindingKind::BaselineDeviation`] finding.
//!
//! It complements Time Machine: Time Machine asks *"threat intel caught up — did I already talk to
//! something now-known-bad?"*; a baseline asks *"my network changed — is this host doing something
//! it never did before?"*
//!
//! Deviation dimensions (per internal host, egress-scoped where applicable): first-seen external
//! peer, first-seen destination port, outbound-volume spike (mean + k·σ), first-seen TLS JA3
//! fingerprint, first-use traffic category, off-hours activity (vs the host's learned active
//! window), and a newly-periodic channel (beacon) absent from the host's beacon profile.
//!
//! Scope note: this is the local-first core over an offline JSON sidecar. A shared/team baseline
//! store, scheduled auto-baselining, and statistical/ML upgrades are out of scope here and tracked
//! as follow-ups. Invariants preserved: bounded memory (per-host `top_k` caps + a host cap),
//! C-compiler-free (pure-Rust `serde_json` + f64), local-first (offline sidecar, pure compare),
//! i64 ns capture windows / i64 unix-secs wall-clock, and deterministic output (`BTreeMap`
//! accumulate → sorted `Vec`; order-independent stat folds).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::finding::{Finding, FindingKind};
use crate::model::output::AnalysisOutput;
use crate::model::severity::Severity;
use crate::score::{
    score_baseline_deviation, PTS_DEV_NEW_BEACON, PTS_DEV_NEW_CATEGORY, PTS_DEV_NEW_EXTERNAL_PEER,
    PTS_DEV_NEW_JA3, PTS_DEV_NEW_PORT, PTS_DEV_OFF_HOURS, PTS_DEV_VOLUME_FORECAST,
    PTS_DEV_VOLUME_SPIKE,
};

/// On-disk schema version for the baseline sidecar.
pub const BASELINE_SCHEMA_VERSION: u32 = 1;

/// Tuning + bounds for baseline learning and comparison. Defaults are conservative so a deviation
/// alone stays at Medium (see [`crate::score::DEV_UPLIFT_CAP`]).
#[derive(Debug, Clone, PartialEq)]
pub struct BaselineParams {
    /// Master switch: when `false`, [`compare_to_baseline`] emits nothing.
    pub enabled: bool,
    /// Warm-up gate: a host must have appeared in at least this many captures before its baseline
    /// is trusted enough to raise deviations (cold-start false-positive guard).
    pub min_captures: u64,
    /// Outbound-volume spike threshold: flag when observed bytes exceed `mean + k·stddev`.
    pub volume_k: f64,
    /// Cap on tracked internal hosts in the profile (bounded memory).
    pub max_hosts: usize,
    /// Cap on tracked external peers per host.
    pub top_k_peers: usize,
    /// Cap on tracked destination service ports per host.
    pub top_k_services: usize,
    /// Cap on tracked JA3 fingerprints per host.
    pub top_k_ja3: usize,
    /// Cap on tracked beacon channels per host.
    pub top_k_beacons: usize,
    /// Minimum regular contacts before a channel is considered beacon-shaped in the snapshot.
    pub min_beacon_contacts: u64,
    /// Maximum inter-arrival coefficient-of-variation for a channel to count as a beacon.
    pub max_beacon_cv: f64,
    /// Off-hours guard: a baseline must have at least this many *and* fewer than 24 populated hours
    /// to have a meaningful active window (else "off-hours" is not raised — a 24/7 or too-sparse
    /// baseline has no defined window).
    pub min_active_hours: u32,
    /// Cap on the provenance `source_sha256s` list.
    pub max_source_shas: usize,
    /// EWMA smoothing factor for the recency-weighted mean (hint only; the deviation gate uses
    /// `mean + k·stddev`, which merges exactly).
    pub ewma_alpha: f64,

    // ---- Cross-capture predictive mode (trend-aware volume) ----
    /// When `true`, and a host has at least `min_forecast_points` per-capture volume samples, the
    /// outbound-volume deviation is judged against a **Holt trend forecast** of the next capture
    /// (`forecast ± forecast_z·σ`) instead of the static `mean + volume_k·σ` gate — so a host on a
    /// legitimate rising trend does not false-positive, but an *off-trend* jump still fires.
    pub forecast_enabled: bool,
    /// Prediction-band half-width (in residual σ) for the cross-capture volume forecast.
    pub forecast_z: f64,
    /// Minimum per-capture volume samples before the trend forecast is trusted (else fall back to the
    /// static gate). Must be ≥ 3 for a trend + residual to exist.
    pub min_forecast_points: u64,
    /// Cap on retained per-capture volume samples per host (a bounded recency ring for the forecast).
    pub max_recent_points: usize,

    // ---- Seasonality (Holt-Winters additive) ----
    /// When `true`, and a host has enough per-*phase* history, the volume forecast is season-aware:
    /// it learns an additive seasonal factor per phase slot (e.g. per weekday) and forecasts with
    /// **level + trend + seasonal factor** (Holt-Winters additive over the deseasonalised history),
    /// so a host's normal weekly/diurnal rhythm does not false-positive but an *off-rhythm* value
    /// does. Falls back to the plain trend forecast when the per-phase profile is too sparse.
    pub seasonal_enabled: bool,
    /// Number of seasonal phase slots — the season length. `7` = day-of-week (default), `24` =
    /// hour-of-day. Pair with `seasonal_slot_secs`.
    pub seasonal_period: u32,
    /// Wall-clock seconds per phase slot — `86_400` = day-of-week (default), `3_600` = hour-of-day.
    /// A capture's phase is `(capture_unix / seasonal_slot_secs) % seasonal_period`.
    pub seasonal_slot_secs: i64,
    /// Minimum samples in a phase slot before that slot's seasonal expectation is trusted.
    pub min_seasonal_samples: u64,
    /// Minimum distinct populated phase slots before seasonality engages (else the plain trend
    /// forecast is used — a profile with only one phase carries no seasonal information).
    pub min_seasonal_phases: u32,
}

impl Default for BaselineParams {
    fn default() -> Self {
        BaselineParams {
            enabled: true,
            min_captures: 5,
            volume_k: 4.0,
            max_hosts: 100_000,
            top_k_peers: 128,
            top_k_services: 64,
            top_k_ja3: 16,
            top_k_beacons: 16,
            min_beacon_contacts: 4,
            max_beacon_cv: 0.35,
            min_active_hours: 3,
            max_source_shas: 256,
            ewma_alpha: 0.30,
            forecast_enabled: true,
            forecast_z: 3.0,
            min_forecast_points: 4,
            max_recent_points: 24,
            seasonal_enabled: true,
            seasonal_period: 7,         // day-of-week
            seasonal_slot_secs: 86_400, // one day per slot
            min_seasonal_samples: 2,
            min_seasonal_phases: 3,
        }
    }
}

impl BaselineParams {
    /// Human label for the configured seasonal cycle (for evidence strings).
    fn seasonal_label(&self) -> &'static str {
        match (self.seasonal_slot_secs, self.seasonal_period) {
            (86_400, 7) => "day-of-week",
            (3_600, 24) => "hour-of-day",
            _ => "seasonal",
        }
    }
}

/// The phase slot `[0, seasonal_period)` for a wall-clock second under the configured seasonal cycle.
/// `0` when seasonality is misconfigured (period/slot ≤ 0), so callers degrade gracefully.
fn seasonal_phase(unix: i64, params: &BaselineParams) -> usize {
    if params.seasonal_period == 0 || params.seasonal_slot_secs <= 0 {
        return 0;
    }
    let period = params.seasonal_period as i64;
    (unix
        .div_euclid(params.seasonal_slot_secs)
        .rem_euclid(period)) as usize
}

/// Fold `value` into a per-phase seasonal profile, resizing/rebuilding to `period` slots if needed
/// (a period change starts the seasonal history fresh — bounded and deterministic).
fn observe_seasonal(
    profile: &mut Vec<RunningStat>,
    phase: usize,
    value: f64,
    period: usize,
    alpha: f64,
) {
    if profile.len() != period {
        *profile = vec![RunningStat::default(); period];
    }
    if let Some(slot) = profile.get_mut(phase) {
        slot.observe(value, alpha);
    }
}

/// Merge two per-phase seasonal profiles slot-wise (order-independent; missing slots default).
fn merge_seasonal(a: &[RunningStat], b: &[RunningStat]) -> Vec<RunningStat> {
    let n = a.len().max(b.len());
    (0..n)
        .map(|i| {
            let da = a.get(i).cloned().unwrap_or_default();
            let db = b.get(i).cloned().unwrap_or_default();
            RunningStat::merge(&da, &db)
        })
        .collect()
}

// ---- Running statistics -----------------------------------------------------------------------

/// A serialisable, mergeable online statistic: Welford mean/variance + min/max + an EWMA. Holds
/// only O(1) summary state (never the samples), so a per-host volume distribution stays bounded.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RunningStat {
    pub count: u64,
    pub mean: f64,
    /// Welford M2 aggregate; population `variance() == m2 / count`.
    pub m2: f64,
    pub min: f64,
    pub max: f64,
    /// Recency-weighted mean (order-dependent; a UI trend hint, not used by the deviation gate).
    pub ewma: f64,
}

impl RunningStat {
    /// Fold one sample (Welford update + min/max + EWMA).
    pub fn observe(&mut self, x: f64, alpha: f64) {
        self.count += 1;
        let delta = x - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
        if self.count == 1 {
            self.min = x;
            self.max = x;
            self.ewma = x;
        } else {
            self.min = self.min.min(x);
            self.max = self.max.max(x);
            self.ewma = alpha * x + (1.0 - alpha) * self.ewma;
        }
    }

    /// Combine two independently-accumulated stats (Chan's parallel Welford). Order-independent for
    /// `count`/`mean`/`m2`/`min`/`max`; `ewma` is averaged (order-dependent, documented — it is a
    /// hint only). Merging with an empty stat is the identity.
    pub fn merge(a: &RunningStat, b: &RunningStat) -> RunningStat {
        if a.count == 0 {
            return b.clone();
        }
        if b.count == 0 {
            return a.clone();
        }
        let na = a.count as f64;
        let nb = b.count as f64;
        let n = na + nb;
        let delta = b.mean - a.mean;
        RunningStat {
            count: a.count + b.count,
            mean: a.mean + delta * nb / n,
            m2: a.m2 + b.m2 + delta * delta * na * nb / n,
            min: a.min.min(b.min),
            max: a.max.max(b.max),
            ewma: (a.ewma + b.ewma) / 2.0,
        }
    }

    /// Population variance (`m2 / count`); `0.0` when empty.
    pub fn variance(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.m2 / self.count as f64
        }
    }

    /// Population standard deviation.
    pub fn stddev(&self) -> f64 {
        self.variance().max(0.0).sqrt()
    }
}

/// A membership counter that also tracks recency — "have I seen this peer / port before, in how
/// many captures, first and last when".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SeenCount {
    /// Distinct captures this value appeared in.
    pub captures: u64,
    /// Total observations across all captures.
    pub total: u64,
    /// Wall-clock unix seconds of first / last appearance (`0` if the caller had no clock).
    pub first_seen_unix: i64,
    pub last_seen_unix: i64,
}

impl SeenCount {
    fn observe(&mut self, total_delta: u64, now_unix: i64) {
        self.captures += 1;
        self.total = self.total.saturating_add(total_delta.max(1));
        self.first_seen_unix = fold_min_ts(self.first_seen_unix, now_unix);
        self.last_seen_unix = fold_max_ts(self.last_seen_unix, now_unix);
    }

    fn merge(a: &SeenCount, b: &SeenCount) -> SeenCount {
        SeenCount {
            captures: a.captures + b.captures,
            total: a.total.saturating_add(b.total),
            first_seen_unix: fold_min_ts(a.first_seen_unix, b.first_seen_unix),
            last_seen_unix: fold_max_ts(a.last_seen_unix, b.last_seen_unix),
        }
    }
}

/// One per-capture volume sample in a host's cross-capture history: the capture's wall-clock second
/// and the observed value. The series is kept sorted by `unix` and capped, so a Holt trend forecast
/// (cross-capture predictive mode) sees the samples in chronological order deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RecentPoint {
    pub unix: i64,
    pub value: f64,
}

/// Append `point`, then keep the series sorted by `unix` (stable) and truncated to the most-recent
/// `cap` samples. Deterministic and order-independent under merge (samples carry their own time).
fn push_recent(series: &mut Vec<RecentPoint>, point: RecentPoint, cap: usize) {
    series.push(point);
    series.sort_by_key(|p| p.unix);
    if series.len() > cap {
        let drop = series.len() - cap;
        series.drain(0..drop); // drop the oldest
    }
}

/// Merge two per-capture volume histories: concatenate, sort by time, keep the most-recent `cap`.
fn merge_recent(a: &[RecentPoint], b: &[RecentPoint], cap: usize) -> Vec<RecentPoint> {
    let mut out: Vec<RecentPoint> = a.iter().chain(b.iter()).copied().collect();
    out.sort_by_key(|p| p.unix);
    if out.len() > cap {
        let drop = out.len() - cap;
        out.drain(0..drop);
    }
    out
}

/// A tracked external peer for a host.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerStat {
    pub ip: String,
    pub seen: SeenCount,
}

/// A tracked destination service port for a host.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceStat {
    pub port: u16,
    pub seen: SeenCount,
}

/// A tracked TLS JA3 client fingerprint for a host.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ja3Stat {
    pub ja3: String,
    pub seen: SeenCount,
}

/// A tracked beacon-shaped egress channel `(dst, port)` for a host, with its latest observed
/// period + jitter (informational) and how often it was seen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeaconStat {
    pub dst: String,
    pub port: u16,
    /// Latest observed mean inter-contact interval (ns).
    pub interval_ns: i64,
    /// Latest observed inter-arrival coefficient of variation (regularity; lower = more regular).
    pub jitter_cv: f64,
    pub seen: SeenCount,
}

/// One beacon-shaped egress channel observed in a single capture (the snapshot form of
/// [`BeaconStat`]).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BeaconObs {
    pub dst: String,
    pub port: u16,
    pub interval_ns: i64,
    pub jitter_cv: f64,
}

// ---- Per-capture snapshot (the learn payload) -------------------------------------------------

/// One internal host's egress behavior observed in a single capture — the projection produced by
/// [`crate::detect::BehaviorTracker::baseline_snapshot`]. Peers/services are the *external*
/// destinations only (the monitored network's egress); all counts are for this capture alone.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HostObservation {
    pub host: String,
    pub bytes_out: u64,
    pub bytes_in: u64,
    /// Distinct egress connections (contacts) initiated by this host.
    pub flows: u64,
    /// External peer IPs contacted (sorted, capped).
    pub peers: Vec<String>,
    /// External destination ports contacted (sorted, capped).
    pub services: Vec<u16>,
    /// Distinct TLS JA3 client fingerprints this host presented (sorted, capped).
    #[serde(default)]
    pub ja3: Vec<String>,
    /// Contacts by hour-of-day (UTC), 24 slots — the host's active window this capture.
    #[serde(default)]
    pub hour_of_day: [u32; 24],
    /// Flow counts by traffic category, 13 slots in `Category` order.
    #[serde(default)]
    pub categories: [u32; 13],
    /// Beacon-shaped egress channels observed this capture (sorted, capped).
    #[serde(default)]
    pub beacons: Vec<BeaconObs>,
}

/// This capture's per-internal-host behavioral snapshot. Serialised onto
/// [`AnalysisOutput::baseline`] so the CLI can fold it into a persisted [`BaselineProfile`] after
/// the run (the streaming pass stays filesystem-free).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CaptureProfile {
    /// Per-host observations, sorted by host for stable diffs.
    pub hosts: Vec<HostObservation>,
}

// ---- The persisted baseline sidecar -----------------------------------------------------------

/// A learned per-internal-host behavioral profile for one host, accumulated across captures.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostBaseline {
    /// Internal IP — the entity key.
    pub host: String,
    /// How many captures this host appeared in (confidence / warm-up gate).
    pub captures_seen: u64,
    /// Per-capture outbound / inbound volume distributions.
    pub bytes_out: RunningStat,
    pub bytes_in: RunningStat,
    /// Per-capture egress connection-count distribution.
    pub flows: RunningStat,
    /// Learned external peers, sorted by ip (bounded).
    pub peers: Vec<PeerStat>,
    /// Learned destination service ports, sorted by port (bounded).
    pub services: Vec<ServiceStat>,
    /// Learned TLS JA3 client fingerprints, sorted by value (bounded).
    #[serde(default)]
    pub ja3: Vec<Ja3Stat>,
    /// Cumulative contacts by hour-of-day (UTC), 24 slots — the host's learned active window.
    #[serde(default)]
    pub hour_of_day: [u64; 24],
    /// Cumulative flow counts by traffic category, 13 slots in `Category` order.
    #[serde(default)]
    pub categories: [u64; 13],
    /// Learned beacon-shaped channels, sorted by (dst, port) (bounded).
    #[serde(default)]
    pub beacons: Vec<BeaconStat>,
    /// Cross-capture per-metric history — bounded, time-ordered recency rings the Holt trend forecast
    /// (predictive mode) fits on, for outbound bytes, inbound bytes, and egress connection count.
    /// `#[serde(default)]` keeps older sidecars readable (they fall back to the static `mean + k·σ`
    /// gate until enough captures rebuild the series).
    #[serde(default)]
    pub bytes_out_recent: Vec<RecentPoint>,
    #[serde(default)]
    pub bytes_in_recent: Vec<RecentPoint>,
    #[serde(default)]
    pub flows_recent: Vec<RecentPoint>,
    /// Seasonal profiles — one [`RunningStat`] per phase slot (e.g. per weekday), learned from each
    /// capture's *capture-time* phase, for the Holt-Winters additive seasonal factor. `#[serde(default)]`
    /// so older sidecars (no profiles) simply use the plain trend forecast until enough phases fill in.
    #[serde(default)]
    pub bytes_out_seasonal: Vec<RunningStat>,
    #[serde(default)]
    pub bytes_in_seasonal: Vec<RunningStat>,
    #[serde(default)]
    pub flows_seasonal: Vec<RunningStat>,
    pub first_seen_unix: i64,
    pub last_seen_unix: i64,
}

impl HostBaseline {
    fn new(host: String) -> HostBaseline {
        HostBaseline {
            host,
            captures_seen: 0,
            bytes_out: RunningStat::default(),
            bytes_in: RunningStat::default(),
            flows: RunningStat::default(),
            peers: Vec::new(),
            services: Vec::new(),
            ja3: Vec::new(),
            hour_of_day: [0u64; 24],
            categories: [0u64; 13],
            beacons: Vec::new(),
            bytes_out_recent: Vec::new(),
            bytes_in_recent: Vec::new(),
            flows_recent: Vec::new(),
            bytes_out_seasonal: Vec::new(),
            bytes_in_seasonal: Vec::new(),
            flows_seasonal: Vec::new(),
            first_seen_unix: 0,
            last_seen_unix: 0,
        }
    }

    /// Fold one capture's observation. `now_unix` is the wall-clock analysis time (provenance);
    /// `capture_unix` is the capture's own wall-clock second (from its timestamp window) — the recency
    /// rings order by, and the seasonal profiles phase on, *capture* time, so re-analysing captures
    /// out of order still yields the right trend and rhythm.
    fn observe(
        &mut self,
        obs: &HostObservation,
        now_unix: i64,
        capture_unix: i64,
        params: &BaselineParams,
    ) {
        self.captures_seen += 1;
        self.bytes_out
            .observe(obs.bytes_out as f64, params.ewma_alpha);
        self.bytes_in
            .observe(obs.bytes_in as f64, params.ewma_alpha);
        self.flows.observe(obs.flows as f64, params.ewma_alpha);
        // Cross-capture predictive mode: retain this capture's outbound/inbound volume and connection
        // count as capture-time-stamped samples for the Holt trend forecast (bounded recency rings).
        for (ring, value) in [
            (&mut self.bytes_out_recent, obs.bytes_out as f64),
            (&mut self.bytes_in_recent, obs.bytes_in as f64),
            (&mut self.flows_recent, obs.flows as f64),
        ] {
            push_recent(
                ring,
                RecentPoint {
                    unix: capture_unix,
                    value,
                },
                params.max_recent_points,
            );
        }
        // Seasonality: fold each metric into its capture-time phase slot (Holt-Winters seasonal factor).
        let phase = seasonal_phase(capture_unix, params);
        let period = params.seasonal_period as usize;
        observe_seasonal(
            &mut self.bytes_out_seasonal,
            phase,
            obs.bytes_out as f64,
            period,
            params.ewma_alpha,
        );
        observe_seasonal(
            &mut self.bytes_in_seasonal,
            phase,
            obs.bytes_in as f64,
            period,
            params.ewma_alpha,
        );
        observe_seasonal(
            &mut self.flows_seasonal,
            phase,
            obs.flows as f64,
            period,
            params.ewma_alpha,
        );
        self.first_seen_unix = fold_min_ts(self.first_seen_unix, now_unix);
        self.last_seen_unix = fold_max_ts(self.last_seen_unix, now_unix);

        // Peers: fold into a keyed map, observe, re-materialize sorted + capped.
        let mut peers: BTreeMap<String, SeenCount> = std::mem::take(&mut self.peers)
            .into_iter()
            .map(|p| (p.ip, p.seen))
            .collect();
        for ip in &obs.peers {
            peers.entry(ip.clone()).or_default().observe(1, now_unix);
        }
        self.peers = cap_peers(peers, params.top_k_peers);

        // Services: same discipline, keyed by port.
        let mut services: BTreeMap<u16, SeenCount> = std::mem::take(&mut self.services)
            .into_iter()
            .map(|s| (s.port, s.seen))
            .collect();
        for port in &obs.services {
            services.entry(*port).or_default().observe(1, now_unix);
        }
        self.services = cap_services(services, params.top_k_services);

        // JA3: keyed set with recency.
        let mut ja3: BTreeMap<String, SeenCount> = std::mem::take(&mut self.ja3)
            .into_iter()
            .map(|j| (j.ja3, j.seen))
            .collect();
        for j in &obs.ja3 {
            ja3.entry(j.clone()).or_default().observe(1, now_unix);
        }
        self.ja3 = cap_ja3(ja3, params.top_k_ja3);

        // Hour-of-day + category: element-wise additive histograms.
        for (slot, add) in self.hour_of_day.iter_mut().zip(obs.hour_of_day.iter()) {
            *slot = slot.saturating_add(*add as u64);
        }
        for (slot, add) in self.categories.iter_mut().zip(obs.categories.iter()) {
            *slot = slot.saturating_add(*add as u64);
        }

        // Beacons: keyed by (dst, port); refresh latest interval/cv + recency.
        let mut beacons: BTreeMap<(String, u16), (i64, f64, SeenCount)> =
            std::mem::take(&mut self.beacons)
                .into_iter()
                .map(|b| ((b.dst, b.port), (b.interval_ns, b.jitter_cv, b.seen)))
                .collect();
        for b in &obs.beacons {
            let e = beacons.entry((b.dst.clone(), b.port)).or_insert((
                b.interval_ns,
                b.jitter_cv,
                SeenCount::default(),
            ));
            e.0 = b.interval_ns;
            e.1 = b.jitter_cv;
            e.2.observe(1, now_unix);
        }
        self.beacons = cap_beacons(beacons, params.top_k_beacons);
    }

    fn merge(a: &HostBaseline, b: &HostBaseline, params: &BaselineParams) -> HostBaseline {
        let mut peers: BTreeMap<String, SeenCount> = a
            .peers
            .iter()
            .map(|p| (p.ip.clone(), p.seen.clone()))
            .collect();
        for p in &b.peers {
            peers
                .entry(p.ip.clone())
                .and_modify(|e| *e = SeenCount::merge(e, &p.seen))
                .or_insert_with(|| p.seen.clone());
        }
        let mut services: BTreeMap<u16, SeenCount> = a
            .services
            .iter()
            .map(|s| (s.port, s.seen.clone()))
            .collect();
        for s in &b.services {
            services
                .entry(s.port)
                .and_modify(|e| *e = SeenCount::merge(e, &s.seen))
                .or_insert_with(|| s.seen.clone());
        }
        // JA3 union.
        let mut ja3: BTreeMap<String, SeenCount> = a
            .ja3
            .iter()
            .map(|j| (j.ja3.clone(), j.seen.clone()))
            .collect();
        for j in &b.ja3 {
            ja3.entry(j.ja3.clone())
                .and_modify(|e| *e = SeenCount::merge(e, &j.seen))
                .or_insert_with(|| j.seen.clone());
        }
        // Beacon union (latest interval/cv from b when present).
        let mut beacons: BTreeMap<(String, u16), (i64, f64, SeenCount)> = a
            .beacons
            .iter()
            .map(|x| {
                (
                    (x.dst.clone(), x.port),
                    (x.interval_ns, x.jitter_cv, x.seen.clone()),
                )
            })
            .collect();
        for x in &b.beacons {
            beacons
                .entry((x.dst.clone(), x.port))
                .and_modify(|e| {
                    e.0 = x.interval_ns;
                    e.1 = x.jitter_cv;
                    e.2 = SeenCount::merge(&e.2, &x.seen);
                })
                .or_insert((x.interval_ns, x.jitter_cv, x.seen.clone()));
        }
        // Element-wise histogram add.
        let mut hour_of_day = a.hour_of_day;
        for (slot, add) in hour_of_day.iter_mut().zip(b.hour_of_day.iter()) {
            *slot = slot.saturating_add(*add);
        }
        let mut categories = a.categories;
        for (slot, add) in categories.iter_mut().zip(b.categories.iter()) {
            *slot = slot.saturating_add(*add);
        }
        HostBaseline {
            host: a.host.clone(),
            captures_seen: a.captures_seen + b.captures_seen,
            bytes_out: RunningStat::merge(&a.bytes_out, &b.bytes_out),
            bytes_in: RunningStat::merge(&a.bytes_in, &b.bytes_in),
            flows: RunningStat::merge(&a.flows, &b.flows),
            peers: cap_peers(peers, params.top_k_peers),
            services: cap_services(services, params.top_k_services),
            ja3: cap_ja3(ja3, params.top_k_ja3),
            hour_of_day,
            categories,
            beacons: cap_beacons(beacons, params.top_k_beacons),
            bytes_out_recent: merge_recent(
                &a.bytes_out_recent,
                &b.bytes_out_recent,
                params.max_recent_points,
            ),
            bytes_in_recent: merge_recent(
                &a.bytes_in_recent,
                &b.bytes_in_recent,
                params.max_recent_points,
            ),
            flows_recent: merge_recent(&a.flows_recent, &b.flows_recent, params.max_recent_points),
            bytes_out_seasonal: merge_seasonal(&a.bytes_out_seasonal, &b.bytes_out_seasonal),
            bytes_in_seasonal: merge_seasonal(&a.bytes_in_seasonal, &b.bytes_in_seasonal),
            flows_seasonal: merge_seasonal(&a.flows_seasonal, &b.flows_seasonal),
            first_seen_unix: fold_min_ts(a.first_seen_unix, b.first_seen_unix),
            last_seen_unix: fold_max_ts(a.last_seen_unix, b.last_seen_unix),
        }
    }
}

/// The persisted baseline sidecar — derived statistics only (no packets/payloads), plus provenance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineProfile {
    pub schema_version: u32,
    /// `env!("CARGO_PKG_VERSION")` of the engine that wrote the profile.
    pub engine_version: String,
    /// Provenance: how many captures were folded in.
    #[serde(default)]
    pub captures_merged: u64,
    /// Provenance: the source hashes folded in, sorted + deduped + bounded.
    #[serde(default)]
    pub source_sha256s: Vec<String>,
    /// Earliest / latest capture analysis time (unix seconds).
    pub first_analyzed_unix_secs: i64,
    pub last_analyzed_unix_secs: i64,
    /// Earliest / latest capture window across merged captures (ns since epoch).
    pub first_ts_ns: i64,
    pub last_ts_ns: i64,
    /// Per-internal-host profiles, sorted by host, bounded by `max_hosts`.
    pub hosts: Vec<HostBaseline>,
}

impl BaselineProfile {
    /// An empty profile stamped with the current engine version.
    pub fn new() -> BaselineProfile {
        BaselineProfile {
            schema_version: BASELINE_SCHEMA_VERSION,
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            captures_merged: 0,
            source_sha256s: Vec::new(),
            first_analyzed_unix_secs: 0,
            last_analyzed_unix_secs: 0,
            first_ts_ns: 0,
            last_ts_ns: 0,
            hosts: Vec::new(),
        }
    }

    /// Serialize as pretty JSON.
    pub fn to_json_pretty(&self) -> crate::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse a baseline from JSON. Rejects a sidecar written by a newer schema version rather than
    /// silently mis-merging (an older version deserialises via `#[serde(default)]`).
    pub fn from_json_str(s: &str) -> crate::Result<BaselineProfile> {
        let p: BaselineProfile = serde_json::from_str(s)?;
        if p.schema_version > BASELINE_SCHEMA_VERSION {
            return Err(crate::PpError::Config(format!(
                "baseline schema_version {} is newer than this engine supports ({})",
                p.schema_version, BASELINE_SCHEMA_VERSION
            )));
        }
        Ok(p)
    }

    /// Load a baseline sidecar from an optional path. `None` returns `Ok(None)` without touching the
    /// filesystem (wasm-safe: the browser passes `None`).
    pub fn load_opt(path: Option<&std::path::Path>) -> crate::Result<Option<BaselineProfile>> {
        match path {
            None => Ok(None),
            Some(p) => {
                let text = std::fs::read_to_string(p)
                    .map_err(|e| crate::PpError::io(format!("read baseline {}", p.display()), e))?;
                Ok(Some(BaselineProfile::from_json_str(&text)?))
            }
        }
    }

    /// Look up a host's learned profile.
    pub fn host(&self, ip: &str) -> Option<&HostBaseline> {
        self.hosts.iter().find(|h| h.host == ip)
    }
}

impl Default for BaselineProfile {
    fn default() -> Self {
        BaselineProfile::new()
    }
}

// ---- Fold helpers -----------------------------------------------------------------------------

/// Fold a timestamp minimum, treating `0` as "unknown" (ignored).
fn fold_min_ts(cur: i64, new: i64) -> i64 {
    if new == 0 {
        cur
    } else if cur == 0 {
        new
    } else {
        cur.min(new)
    }
}

/// Fold a timestamp maximum, treating `0` as "unknown" (ignored).
fn fold_max_ts(cur: i64, new: i64) -> i64 {
    if new == 0 {
        cur
    } else {
        cur.max(new)
    }
}

/// Materialize a peer map into a `Vec` sorted by ip, keeping the top-`k` by frequency (a
/// heavy-hitter cap: most-seen peers survive; ties break by ip for determinism).
fn cap_peers(map: BTreeMap<String, SeenCount>, k: usize) -> Vec<PeerStat> {
    let mut v: Vec<PeerStat> = map
        .into_iter()
        .map(|(ip, seen)| PeerStat { ip, seen })
        .collect();
    if v.len() > k {
        v.sort_by(|a, b| {
            b.seen
                .captures
                .cmp(&a.seen.captures)
                .then(b.seen.total.cmp(&a.seen.total))
                .then(a.ip.cmp(&b.ip))
        });
        v.truncate(k);
    }
    v.sort_by(|a, b| a.ip.cmp(&b.ip));
    v
}

/// Materialize a service map into a `Vec` sorted by port, keeping the top-`k` by frequency.
fn cap_services(map: BTreeMap<u16, SeenCount>, k: usize) -> Vec<ServiceStat> {
    let mut v: Vec<ServiceStat> = map
        .into_iter()
        .map(|(port, seen)| ServiceStat { port, seen })
        .collect();
    if v.len() > k {
        v.sort_by(|a, b| {
            b.seen
                .captures
                .cmp(&a.seen.captures)
                .then(b.seen.total.cmp(&a.seen.total))
                .then(a.port.cmp(&b.port))
        });
        v.truncate(k);
    }
    v.sort_by_key(|s| s.port);
    v
}

/// Materialize a JA3 map into a `Vec` sorted by value, keeping the top-`k` by frequency.
fn cap_ja3(map: BTreeMap<String, SeenCount>, k: usize) -> Vec<Ja3Stat> {
    let mut v: Vec<Ja3Stat> = map
        .into_iter()
        .map(|(ja3, seen)| Ja3Stat { ja3, seen })
        .collect();
    if v.len() > k {
        v.sort_by(|a, b| {
            b.seen
                .captures
                .cmp(&a.seen.captures)
                .then(b.seen.total.cmp(&a.seen.total))
                .then(a.ja3.cmp(&b.ja3))
        });
        v.truncate(k);
    }
    v.sort_by(|a, b| a.ja3.cmp(&b.ja3));
    v
}

/// Materialize a beacon map into a `Vec` sorted by (dst, port), keeping the top-`k` by frequency.
fn cap_beacons(map: BTreeMap<(String, u16), (i64, f64, SeenCount)>, k: usize) -> Vec<BeaconStat> {
    let mut v: Vec<BeaconStat> = map
        .into_iter()
        .map(|((dst, port), (interval_ns, jitter_cv, seen))| BeaconStat {
            dst,
            port,
            interval_ns,
            jitter_cv,
            seen,
        })
        .collect();
    if v.len() > k {
        v.sort_by(|a, b| {
            b.seen
                .captures
                .cmp(&a.seen.captures)
                .then_with(|| (a.dst.as_str(), a.port).cmp(&(b.dst.as_str(), b.port)))
        });
        v.truncate(k);
    }
    v.sort_by(|a, b| (a.dst.as_str(), a.port).cmp(&(b.dst.as_str(), b.port)));
    v
}

/// Keep the top-`max_hosts` host profiles (by captures-seen then outbound volume), then sort by
/// host for stable on-disk order.
fn cap_hosts(mut hosts: Vec<HostBaseline>, max_hosts: usize) -> Vec<HostBaseline> {
    if hosts.len() > max_hosts {
        hosts.sort_by(|a, b| {
            b.captures_seen
                .cmp(&a.captures_seen)
                .then(b.bytes_out.mean.total_cmp(&a.bytes_out.mean))
                .then(a.host.cmp(&b.host))
        });
        hosts.truncate(max_hosts);
    }
    hosts.sort_by(|a, b| a.host.cmp(&b.host));
    hosts
}

// ---- Learn / merge ----------------------------------------------------------------------------

/// Fold one analyzed capture into a baseline (read-modify-write). Reads the capture's
/// [`CaptureProfile`] snapshot (from [`AnalysisOutput::baseline`]) plus its provenance
/// (`source_sha256`, capture window). `now_unix` is the wall-clock analysis time (`0` if
/// unavailable). Returns the updated profile; a capture with no snapshot is a no-op.
pub fn update_baseline(
    mut base: BaselineProfile,
    out: &AnalysisOutput,
    now_unix: i64,
    params: &BaselineParams,
) -> BaselineProfile {
    let prof = match &out.baseline {
        Some(p) => p,
        None => return base,
    };

    // The capture's own wall-clock second (from its timestamp window) — the seasonal phase source.
    // Falls back to the analysis time when the capture carried no timestamps.
    let capture_unix = match out.summary.first_ts_ns {
        Some(ns) if ns != 0 => ns.div_euclid(1_000_000_000),
        _ => now_unix,
    };
    let mut hosts: BTreeMap<String, HostBaseline> = std::mem::take(&mut base.hosts)
        .into_iter()
        .map(|h| (h.host.clone(), h))
        .collect();
    for obs in &prof.hosts {
        hosts
            .entry(obs.host.clone())
            .or_insert_with(|| HostBaseline::new(obs.host.clone()))
            .observe(obs, now_unix, capture_unix, params);
    }

    // Provenance.
    base.captures_merged += 1;
    if !out.engine_version.is_empty() {
        base.engine_version = out.engine_version.clone();
    }
    if let Some(h) = &out.source_sha256 {
        if !base.source_sha256s.contains(h) {
            base.source_sha256s.push(h.clone());
            base.source_sha256s.sort();
            base.source_sha256s.truncate(params.max_source_shas);
        }
    }
    base.first_analyzed_unix_secs = fold_min_ts(base.first_analyzed_unix_secs, now_unix);
    base.last_analyzed_unix_secs = fold_max_ts(base.last_analyzed_unix_secs, now_unix);
    let f = out.summary.first_ts_ns.unwrap_or(0);
    let l = out.summary.last_ts_ns.unwrap_or(0);
    base.first_ts_ns = fold_min_ts(base.first_ts_ns, f);
    base.last_ts_ns = fold_max_ts(base.last_ts_ns, l);

    base.hosts = cap_hosts(hosts.into_values().collect(), params.max_hosts);
    base
}

/// Build a baseline from scratch by folding several analyzed captures in order. `now_unix` stamps
/// each fold (best effort — the same wall-clock for all when the caller has one clock).
pub fn build_baseline(
    outs: &[&AnalysisOutput],
    now_unix: i64,
    params: &BaselineParams,
) -> BaselineProfile {
    let mut base = BaselineProfile::new();
    for out in outs {
        base = update_baseline(base, out, now_unix, params);
    }
    base
}

/// Merge two persisted baselines into one (order-independent for the statistical fields; `ewma` is
/// averaged). Used to combine sidecars learned separately.
pub fn merge(a: BaselineProfile, b: BaselineProfile, params: &BaselineParams) -> BaselineProfile {
    let mut hosts: BTreeMap<String, HostBaseline> =
        a.hosts.into_iter().map(|h| (h.host.clone(), h)).collect();
    for hb in b.hosts {
        match hosts.get(&hb.host) {
            Some(existing) => {
                let merged = HostBaseline::merge(existing, &hb, params);
                hosts.insert(hb.host.clone(), merged);
            }
            None => {
                hosts.insert(hb.host.clone(), hb);
            }
        }
    }
    let mut shas = a.source_sha256s;
    for h in b.source_sha256s {
        if !shas.contains(&h) {
            shas.push(h);
        }
    }
    shas.sort();
    shas.dedup();
    shas.truncate(params.max_source_shas);
    BaselineProfile {
        schema_version: BASELINE_SCHEMA_VERSION,
        engine_version: if !b.engine_version.is_empty() {
            b.engine_version
        } else {
            a.engine_version
        },
        captures_merged: a.captures_merged + b.captures_merged,
        source_sha256s: shas,
        first_analyzed_unix_secs: fold_min_ts(
            a.first_analyzed_unix_secs,
            b.first_analyzed_unix_secs,
        ),
        last_analyzed_unix_secs: fold_max_ts(a.last_analyzed_unix_secs, b.last_analyzed_unix_secs),
        first_ts_ns: fold_min_ts(a.first_ts_ns, b.first_ts_ns),
        last_ts_ns: fold_max_ts(a.last_ts_ns, b.last_ts_ns),
        hosts: cap_hosts(hosts.into_values().collect(), params.max_hosts),
    }
}

// ---- Compare ----------------------------------------------------------------------------------

/// One host's deviation from its learned baseline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Deviation {
    pub host: String,
    pub severity: Severity,
    pub score: u16,
    pub title: String,
    /// Representative deviating peer (a first-seen external peer), when applicable.
    pub peer: Option<String>,
    /// Representative deviating port (a first-seen destination port), when applicable.
    pub port: Option<u16>,
    /// Explainable evidence bullets (one per deviation dimension), reconciling to `score`.
    pub evidence: Vec<String>,
}

/// The result of comparing a capture snapshot against a baseline.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeviationReport {
    pub deviations: Vec<Deviation>,
    /// How many hosts in the snapshot had a baseline to compare against.
    pub hosts_compared: usize,
}

impl DeviationReport {
    /// Convert deviations into `Finding`s (kind [`FindingKind::BaselineDeviation`]) for folding into
    /// the summary alongside the other detectors.
    pub fn into_findings(self) -> Vec<Finding> {
        self.deviations
            .into_iter()
            .map(|d| Finding {
                kind: FindingKind::BaselineDeviation,
                severity: d.severity,
                score: d.score,
                title: d.title,
                src_ip: d.host,
                dst_ip: d.peer,
                dst_port: d.port,
                attack: Vec::new(),
                evidence: d.evidence,
                interval_ns: None,
                jitter_cv: None,
                contacts: None,
                first_seen_ns: None,
                last_seen_ns: None,
                victims: Vec::new(),
            })
            .collect()
    }
}

/// Judge one per-capture volume metric (`obs_desc` describes the observed value, e.g.
/// `"outbound 50000000 bytes"`) against the host's cross-capture history. Prefers the **Holt trend
/// forecast** (`forecast ± forecast_z·σ` via [`crate::forecast::forecast_next`]) when there are at
/// least `min_forecast_points` samples — so a legitimate rising trend is not flagged, but an
/// off-trend jump, or a collapse below the trend, fires — and otherwise falls back to the static
/// `mean + volume_k·σ` gate (older sidecars with no series). Returns a `(evidence, points)` deviation
/// dimension, or `None` when the value is expected (or the host is still in volume warm-up).
/// Season-aware (Holt-Winters additive) one-step forecast for the value at seasonal phase `phase`,
/// or `None` when the per-phase profile is too sparse to carry seasonal information (caller then uses
/// the plain trend forecast). Learns an additive seasonal factor per phase (`slot.mean − overall
/// level`), deseasonalises the recency ring, runs Holt (level+trend) on it, then re-adds this phase's
/// factor. Falls back to the phase's own distribution when the ring is too short for a trend.
fn seasonal_forecast(
    recent: &[RecentPoint],
    seasonal: &[RunningStat],
    phase: usize,
    params: &BaselineParams,
) -> Option<crate::forecast::ForecastNext> {
    if !params.seasonal_enabled || seasonal.is_empty() {
        return None;
    }
    let populated: Vec<usize> = (0..seasonal.len())
        .filter(|&p| seasonal[p].count >= params.min_seasonal_samples)
        .collect();
    if (populated.len() as u32) < params.min_seasonal_phases {
        return None; // too few distinct phases to carry a rhythm
    }
    let target = seasonal.get(phase)?;
    if target.count < params.min_seasonal_samples {
        return None; // no trusted expectation for this phase
    }
    let global = populated.iter().map(|&p| seasonal[p].mean).sum::<f64>() / populated.len() as f64;
    let factor = |p: usize| -> f64 {
        seasonal
            .get(p)
            .filter(|s| s.count >= params.min_seasonal_samples)
            .map(|s| s.mean - global)
            .unwrap_or(0.0)
    };
    let deseason: Vec<f64> = recent
        .iter()
        .map(|pt| pt.value - factor(seasonal_phase(pt.unix, params)))
        .collect();
    match crate::forecast::forecast_next(&deseason, &crate::forecast::ForecastParams::default()) {
        Some(fc) => Some(crate::forecast::ForecastNext {
            forecast: (fc.forecast + factor(phase)).max(0.0),
            sigma: fc.sigma,
            points: fc.points,
        }),
        None => {
            // Ring too short for a trend: fall back to this phase's own distribution (seasonal-naive).
            let sigma = target.stddev().max(0.15 * target.mean.max(1.0)).max(1.0);
            Some(crate::forecast::ForecastNext {
                forecast: target.mean,
                sigma,
                points: target.count as usize,
            })
        }
    }
}

fn volume_forecast_dim(
    obs_desc: &str,
    observed: f64,
    recent: &[RecentPoint],
    stat: &RunningStat,
    seasonal: &[RunningStat],
    phase: usize,
    params: &BaselineParams,
) -> Option<(String, i32)> {
    if stat.count < params.min_captures {
        return None; // too little history to trust this metric
    }
    // Seasonal (Holt-Winters additive) supersedes the plain trend when the per-phase profile is rich
    // enough — a value inside its own rhythm's band is expected even if it's high (or low) overall.
    if let Some(fc) = seasonal_forecast(recent, seasonal, phase, params) {
        let hi = fc.forecast + params.forecast_z * fc.sigma;
        let lo = (fc.forecast - params.forecast_z * fc.sigma).max(0.0);
        if observed > hi {
            let z = (observed - fc.forecast) / fc.sigma.max(1.0);
            return Some((
                format!(
                    "baseline: {obs_desc} broke its {} seasonal forecast — predicted {:.0} ± {:.0} for this slot (Holt-Winters over {} captures, {:.1}σ off rhythm)",
                    params.seasonal_label(), fc.forecast, fc.sigma, fc.points, z
                ),
                PTS_DEV_VOLUME_FORECAST,
            ));
        } else if observed < lo && fc.forecast > fc.sigma {
            return Some((
                format!(
                    "baseline: {obs_desc} fell below its {} seasonal forecast — predicted {:.0} ± {:.0} for this slot (Holt-Winters over {} captures)",
                    params.seasonal_label(), fc.forecast, fc.sigma, fc.points
                ),
                PTS_DEV_VOLUME_FORECAST,
            ));
        }
        return None; // within the seasonal band — expected for this rhythm
    }
    let series: Vec<f64> = recent.iter().map(|p| p.value).collect();
    let forecast =
        if params.forecast_enabled && series.len() as u64 >= params.min_forecast_points.max(3) {
            crate::forecast::forecast_next(&series, &crate::forecast::ForecastParams::default())
        } else {
            None
        };
    match forecast {
        Some(fc) => {
            let hi = fc.forecast + params.forecast_z * fc.sigma;
            let lo = (fc.forecast - params.forecast_z * fc.sigma).max(0.0);
            if observed > hi {
                let z = (observed - fc.forecast) / fc.sigma.max(1.0);
                Some((
                    format!(
                        "baseline: {obs_desc} broke its cross-capture forecast — predicted {:.0} ± {:.0} from {} prior captures ({:.1}σ off trend)",
                        fc.forecast, fc.sigma, fc.points, z
                    ),
                    PTS_DEV_VOLUME_FORECAST,
                ))
            } else if observed < lo && fc.forecast > fc.sigma {
                // Fell well below what the trend predicted (metric quieter than its history).
                Some((
                    format!(
                        "baseline: {obs_desc} fell below its cross-capture forecast — predicted {:.0} ± {:.0} from {} prior captures",
                        fc.forecast, fc.sigma, fc.points
                    ),
                    PTS_DEV_VOLUME_FORECAST,
                ))
            } else {
                None
            }
        }
        None => {
            let mean = stat.mean;
            let sd = stat.stddev();
            if sd > 0.0 && observed > mean + params.volume_k * sd {
                let z = (observed - mean) / sd;
                Some((
                    format!(
                        "baseline: {obs_desc} vs mean {:.0} ± {:.0} ({:.1}σ over {} captures)",
                        mean, sd, z, stat.count
                    ),
                    PTS_DEV_VOLUME_SPIKE,
                ))
            } else {
                None
            }
        }
    }
}

/// Compare a capture's [`CaptureProfile`] snapshot against a learned baseline, returning the hosts
/// that deviated. Pure and offline. A host with no baseline, or whose baseline is still in warm-up
/// (`captures_seen < params.min_captures`), is skipped. Deviations sort worst-first.
///
/// The capture time is unknown here, so seasonality is not phased (phase 0). Prefer
/// [`compare_to_baseline_at`] when the capture's wall-clock second is available (the analyze/CLI/wasm
/// paths do), so day-of-week / hour-of-day rhythm phasing engages.
pub fn compare_to_baseline(
    base: &BaselineProfile,
    prof: &CaptureProfile,
    params: &BaselineParams,
) -> DeviationReport {
    compare_to_baseline_at(base, prof, 0, params)
}

/// Seasonality-aware [`compare_to_baseline`]: `capture_unix` is this capture's wall-clock second (its
/// timestamp-window start), the source of the seasonal phase for the Holt-Winters seasonal forecast.
pub fn compare_to_baseline_at(
    base: &BaselineProfile,
    prof: &CaptureProfile,
    capture_unix: i64,
    params: &BaselineParams,
) -> DeviationReport {
    let mut report = DeviationReport::default();
    if !params.enabled {
        return report;
    }
    let phase = seasonal_phase(capture_unix, params);
    for obs in &prof.hosts {
        let hb = match base.host(&obs.host) {
            Some(h) => h,
            None => continue, // unknown host — nothing to compare against
        };
        report.hosts_compared += 1;
        if hb.captures_seen < params.min_captures {
            continue; // warm-up: too little history to trust
        }

        let mut dims: Vec<(String, i32)> = Vec::new();
        let mut peer: Option<String> = None;
        let mut port: Option<u16> = None;

        // --- New external peers ---
        let known_peers: std::collections::HashSet<&str> =
            hb.peers.iter().map(|p| p.ip.as_str()).collect();
        let mut new_peers: Vec<&String> = obs
            .peers
            .iter()
            .filter(|ip| !known_peers.contains(ip.as_str()))
            .collect();
        new_peers.sort();
        if !new_peers.is_empty() {
            peer = Some(new_peers[0].clone());
            dims.push((
                format!(
                    "baseline: new external peer(s) {} — not in this host's {}-capture profile",
                    fmt_list_str(&new_peers, 6),
                    hb.captures_seen
                ),
                PTS_DEV_NEW_EXTERNAL_PEER,
            ));
        }

        // --- New destination ports ---
        let known_ports: std::collections::HashSet<u16> =
            hb.services.iter().map(|s| s.port).collect();
        let mut new_ports: Vec<u16> = obs
            .services
            .iter()
            .copied()
            .filter(|p| !known_ports.contains(p))
            .collect();
        new_ports.sort_unstable();
        new_ports.dedup();
        if !new_ports.is_empty() {
            port = Some(new_ports[0]);
            dims.push((
                format!(
                    "baseline: new destination port(s) {} — not in this host's service profile",
                    fmt_list_u16(&new_ports, 6)
                ),
                PTS_DEV_NEW_PORT,
            ));
        }

        // --- Volume metrics (outbound / inbound bytes, connection count): cross-capture predictive
        //     (trend-aware) when the host has enough per-capture history, else the static mean + k·σ
        //     gate. The forecast supersedes the static gate so a host on a legitimate rising trend is
        //     not flagged (the mean lags a trend and would false-positive), while an off-*trend* jump
        //     — or a collapse below the trend — still fires. ---
        dims.extend(
            [
                volume_forecast_dim(
                    &format!("outbound {} bytes", obs.bytes_out),
                    obs.bytes_out as f64,
                    &hb.bytes_out_recent,
                    &hb.bytes_out,
                    &hb.bytes_out_seasonal,
                    phase,
                    params,
                ),
                volume_forecast_dim(
                    &format!("inbound {} bytes", obs.bytes_in),
                    obs.bytes_in as f64,
                    &hb.bytes_in_recent,
                    &hb.bytes_in,
                    &hb.bytes_in_seasonal,
                    phase,
                    params,
                ),
                volume_forecast_dim(
                    &format!("{} connections", obs.flows),
                    obs.flows as f64,
                    &hb.flows_recent,
                    &hb.flows,
                    &hb.flows_seasonal,
                    phase,
                    params,
                ),
            ]
            .into_iter()
            .flatten(),
        );

        // --- New TLS JA3 fingerprint ---
        let known_ja3: std::collections::HashSet<&str> =
            hb.ja3.iter().map(|j| j.ja3.as_str()).collect();
        let mut new_ja3: Vec<&String> = obs
            .ja3
            .iter()
            .filter(|j| !known_ja3.contains(j.as_str()))
            .collect();
        new_ja3.sort();
        if !new_ja3.is_empty() {
            dims.push((
                format!(
                    "baseline: new TLS client fingerprint(s) {} — not in this host's JA3 profile",
                    fmt_list_str(&new_ja3, 3)
                ),
                PTS_DEV_NEW_JA3,
            ));
        }

        // --- First use of a traffic category ---
        let mut new_cats: Vec<&'static str> = Vec::new();
        for (c, cat) in crate::model::category::Category::all().iter().enumerate() {
            if obs.categories.get(c).copied().unwrap_or(0) > 0
                && hb.categories.get(c).copied().unwrap_or(0) == 0
            {
                new_cats.push(cat.as_str());
            }
        }
        if !new_cats.is_empty() {
            dims.push((
                format!(
                    "baseline: first use of category {} for this host",
                    new_cats.join(", ")
                ),
                PTS_DEV_NEW_CATEGORY,
            ));
        }

        // --- Off-hours activity (only when the baseline has a defined active window) ---
        let populated = hb.hour_of_day.iter().filter(|&&v| v > 0).count() as u32;
        if populated >= params.min_active_hours && populated < 24 {
            let mut off: Vec<usize> = (0..24)
                .filter(|&h| obs.hour_of_day[h] > 0 && hb.hour_of_day[h] == 0)
                .collect();
            off.sort_unstable();
            if !off.is_empty() {
                let hours: Vec<String> = off.iter().take(6).map(|h| format!("{h:02}:00")).collect();
                dims.push((
                    format!(
                        "baseline: activity at {} UTC outside the host's usual active window",
                        hours.join(", ")
                    ),
                    PTS_DEV_OFF_HOURS,
                ));
            }
        }

        // --- Newly-periodic channel (beacon) not in the host's beacon profile ---
        let known_beacons: std::collections::HashSet<(&str, u16)> = hb
            .beacons
            .iter()
            .map(|b| (b.dst.as_str(), b.port))
            .collect();
        let mut new_beacons: Vec<&BeaconObs> = obs
            .beacons
            .iter()
            .filter(|b| !known_beacons.contains(&(b.dst.as_str(), b.port)))
            .collect();
        new_beacons.sort_by(|a, b| (a.dst.as_str(), a.port).cmp(&(b.dst.as_str(), b.port)));
        if let Some(b0) = new_beacons.first() {
            if peer.is_none() {
                peer = Some(b0.dst.clone());
            }
            if port.is_none() {
                port = Some(b0.port);
            }
            let interval_s = (b0.interval_ns as f64) / 1e9;
            dims.push((
                format!(
                    "baseline: new periodic channel to {}:{} (~{:.0}s, cv {:.2}) not in the host's beacon profile",
                    b0.dst, b0.port, interval_s, b0.jitter_cv
                ),
                PTS_DEV_NEW_BEACON,
            ));
        }

        if dims.is_empty() {
            continue;
        }
        let scored = score_baseline_deviation(&dims);
        let n = dims.len();
        report.deviations.push(Deviation {
            host: obs.host.clone(),
            severity: scored.severity,
            score: scored.score,
            title: format!(
                "{} deviated from its learned baseline ({} signal{})",
                obs.host,
                n,
                if n == 1 { "" } else { "s" }
            ),
            peer,
            port,
            evidence: scored.evidence,
        });
    }

    report.deviations.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then(b.score.cmp(&a.score))
            .then(a.host.cmp(&b.host))
    });
    report
}

/// Join up to `max` strings with `, `, appending `(+N more)` when truncated.
fn fmt_list_str(items: &[&String], max: usize) -> String {
    let shown: Vec<&str> = items.iter().take(max).map(|s| s.as_str()).collect();
    let mut out = shown.join(", ");
    if items.len() > max {
        out.push_str(&format!(" (+{} more)", items.len() - max));
    }
    out
}

/// Join up to `max` ports with `, `, appending `(+N more)` when truncated.
fn fmt_list_u16(items: &[u16], max: usize) -> String {
    let shown: Vec<String> = items.iter().take(max).map(|p| p.to_string()).collect();
    let mut out = shown.join(", ");
    if items.len() > max {
        out.push_str(&format!(" (+{} more)", items.len() - max));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(host: &str, bytes_out: u64, peers: &[&str], services: &[u16]) -> HostObservation {
        HostObservation {
            host: host.to_string(),
            bytes_out,
            bytes_in: bytes_out / 4,
            flows: (peers.len() as u64).max(1),
            peers: peers.iter().map(|s| s.to_string()).collect(),
            services: services.to_vec(),
            ..Default::default()
        }
    }

    /// An observation with each volume metric set independently, over a fixed known peer/service (so
    /// only the volume dimensions can deviate, not new-peer/new-port).
    fn obs_metrics(host: &str, bytes_out: u64, bytes_in: u64, flows: u64) -> HostObservation {
        HostObservation {
            host: host.to_string(),
            bytes_out,
            bytes_in,
            flows,
            peers: vec!["203.0.113.7".to_string()],
            services: vec![443],
            ..Default::default()
        }
    }

    /// Build a baseline for one host by folding `obs` observations at distinct wall-clock seconds.
    fn fold_all(host: &str, samples: &[(u64, u64, u64)]) -> BaselineProfile {
        let params = BaselineParams::default();
        let mut base = BaselineProfile::new();
        for (i, &(out, in_, flows)) in samples.iter().enumerate() {
            let prof = CaptureProfile {
                hosts: vec![obs_metrics(host, out, in_, flows)],
            };
            base = update_baseline(
                base,
                &output_with(prof, &format!("m{i}"), 10, 20),
                1_000 + i as i64,
                &params,
            );
        }
        base
    }

    fn output_with(prof: CaptureProfile, sha: &str, f: i64, l: i64) -> AnalysisOutput {
        let mut out = AnalysisOutput {
            engine_version: "test".to_string(),
            source_sha256: Some(sha.to_string()),
            baseline: Some(prof),
            ..Default::default()
        };
        out.summary.first_ts_ns = Some(f);
        out.summary.last_ts_ns = Some(l);
        out
    }

    #[test]
    fn running_stat_welford_and_merge() {
        let xs = [10.0, 20.0, 30.0, 40.0, 50.0];
        let mut whole = RunningStat::default();
        for &x in &xs {
            whole.observe(x, 0.3);
        }
        assert_eq!(whole.count, 5);
        assert!((whole.mean - 30.0).abs() < 1e-9);
        // Population variance of 10..50 step 10 == 200.
        assert!((whole.variance() - 200.0).abs() < 1e-6);
        assert_eq!(whole.min, 10.0);
        assert_eq!(whole.max, 50.0);

        // Merge of two partitions equals the whole (mean/m2/min/max), order-independent.
        let mut a = RunningStat::default();
        for &x in &xs[..2] {
            a.observe(x, 0.3);
        }
        let mut b = RunningStat::default();
        for &x in &xs[2..] {
            b.observe(x, 0.3);
        }
        let m = RunningStat::merge(&a, &b);
        assert_eq!(m.count, 5);
        assert!((m.mean - whole.mean).abs() < 1e-9);
        assert!((m.m2 - whole.m2).abs() < 1e-6);
        assert_eq!(m.min, 10.0);
        assert_eq!(m.max, 50.0);
        // Empty is the identity.
        assert_eq!(RunningStat::merge(&RunningStat::default(), &whole).count, 5);
    }

    #[test]
    fn learn_persist_roundtrip() {
        let params = BaselineParams::default();
        let prof = CaptureProfile {
            hosts: vec![obs("10.0.0.5", 1000, &["203.0.113.7"], &[443])],
        };
        let base = update_baseline(
            BaselineProfile::new(),
            &output_with(prof, "abc", 100, 200),
            1_752_000_000,
            &params,
        );
        assert_eq!(base.schema_version, BASELINE_SCHEMA_VERSION);
        assert_eq!(base.captures_merged, 1);
        assert_eq!(base.hosts.len(), 1);
        assert_eq!(base.hosts[0].host, "10.0.0.5");
        assert_eq!(base.hosts[0].captures_seen, 1);
        assert_eq!(base.first_ts_ns, 100);
        assert_eq!(base.last_ts_ns, 200);

        let json = base.to_json_pretty().unwrap();
        let back = BaselineProfile::from_json_str(&json).unwrap();
        assert_eq!(base, back);
    }

    #[test]
    fn newer_schema_is_rejected() {
        let mut base = BaselineProfile::new();
        base.schema_version = BASELINE_SCHEMA_VERSION + 1;
        let json = base.to_json_pretty().unwrap();
        assert!(BaselineProfile::from_json_str(&json).is_err());
    }

    #[test]
    fn merge_is_order_independent() {
        let params = BaselineParams::default();
        let p1 = CaptureProfile {
            hosts: vec![obs("10.0.0.5", 1000, &["203.0.113.7"], &[443])],
        };
        let p2 = CaptureProfile {
            hosts: vec![obs("10.0.0.5", 2000, &["203.0.113.8"], &[80])],
        };
        let a = update_baseline(
            BaselineProfile::new(),
            &output_with(p1.clone(), "a", 10, 20),
            1,
            &params,
        );
        let b = update_baseline(
            BaselineProfile::new(),
            &output_with(p2.clone(), "b", 30, 40),
            2,
            &params,
        );
        let ab = merge(a.clone(), b.clone(), &params);
        let ba = merge(b, a, &params);
        // Statistical/set fields are order-independent (ewma differs — not asserted).
        assert_eq!(ab.hosts.len(), 1);
        assert_eq!(ab.hosts[0].captures_seen, 2);
        assert_eq!(ba.hosts[0].captures_seen, 2);
        assert_eq!(ab.hosts[0].bytes_out.count, ba.hosts[0].bytes_out.count);
        assert!((ab.hosts[0].bytes_out.mean - ba.hosts[0].bytes_out.mean).abs() < 1e-9);
        // Both peers learned.
        let peers: Vec<&str> = ab.hosts[0].peers.iter().map(|p| p.ip.as_str()).collect();
        assert!(peers.contains(&"203.0.113.7") && peers.contains(&"203.0.113.8"));
    }

    /// A richer observation exercising the M2 dimensions (JA3 / hours / categories / beacons).
    #[allow(clippy::too_many_arguments)]
    fn obs_full(
        host: &str,
        bytes: u64,
        peers: &[&str],
        svcs: &[u16],
        ja3: &[&str],
        active_hours: &[usize],
        cats: &[usize],
        beacons: &[(&str, u16)],
    ) -> HostObservation {
        let mut hod = [0u32; 24];
        for &h in active_hours {
            hod[h] = 10;
        }
        let mut c = [0u32; 13];
        for &ci in cats {
            c[ci] = 5;
        }
        HostObservation {
            host: host.to_string(),
            bytes_out: bytes,
            bytes_in: bytes / 4,
            flows: (peers.len() as u64).max(1),
            peers: peers.iter().map(|s| s.to_string()).collect(),
            services: svcs.to_vec(),
            ja3: ja3.iter().map(|s| s.to_string()).collect(),
            hour_of_day: hod,
            categories: c,
            beacons: beacons
                .iter()
                .map(|(d, p)| BeaconObs {
                    dst: d.to_string(),
                    port: *p,
                    interval_ns: 60_000_000_000,
                    jitter_cv: 0.05,
                })
                .collect(),
        }
    }

    fn warm_full(base_obs: &HostObservation, n: u64, params: &BaselineParams) -> BaselineProfile {
        let mut base = BaselineProfile::new();
        for i in 0..n {
            let out = AnalysisOutput {
                engine_version: "t".to_string(),
                baseline: Some(CaptureProfile {
                    hosts: vec![base_obs.clone()],
                }),
                ..Default::default()
            };
            base = update_baseline(base, &out, 1000 + i as i64, params);
        }
        base
    }

    #[test]
    fn m2_novelty_dimensions_raise_deviations() {
        let params = BaselineParams::default();
        // Baseline: active 08–17 UTC, category Web(0), JA3 "aaaa", beacon to 203.0.113.7:443.
        let base_obs = obs_full(
            "10.0.0.5",
            1000,
            &["203.0.113.7"],
            &[443],
            &["aaaaaaaa"],
            &[8, 9, 10, 17],
            &[0],
            &[("203.0.113.7", 443)],
        );
        let base = warm_full(&base_obs, params.min_captures, &params);
        // Persisted profile with M2 fields roundtrips.
        assert_eq!(
            base,
            BaselineProfile::from_json_str(&base.to_json_pretty().unwrap()).unwrap()
        );

        // New capture: new JA3, first-use category TunnelVpn(7), off-hour 03, new beacon.
        let dev = obs_full(
            "10.0.0.5",
            1000,
            &["203.0.113.7"],
            &[443],
            &["aaaaaaaa", "bbbbbbbb"],
            &[8, 9, 3],
            &[0, 7],
            &[("203.0.113.7", 443), ("198.51.100.9", 8443)],
        );
        let report = compare_to_baseline(&base, &CaptureProfile { hosts: vec![dev] }, &params);
        assert_eq!(report.deviations.len(), 1);
        let ev = &report.deviations[0].evidence;
        assert!(ev.iter().any(|e| e.contains("fingerprint")), "{ev:?}");
        assert!(ev.iter().any(|e| e.contains("category")), "{ev:?}");
        assert!(ev.iter().any(|e| e.contains("active window")), "{ev:?}");
        assert!(ev.iter().any(|e| e.contains("periodic channel")), "{ev:?}");
        // Deviation-alone stays at Medium at most.
        assert!(report.deviations[0].severity.rank() <= Severity::Medium.rank());
    }

    #[test]
    fn m2_conforming_is_quiet() {
        let params = BaselineParams::default();
        let base_obs = obs_full(
            "10.0.0.5",
            1000,
            &["203.0.113.7"],
            &[443],
            &["aaaaaaaa"],
            &[8, 9, 10, 17],
            &[0],
            &[("203.0.113.7", 443)],
        );
        let base = warm_full(&base_obs, params.min_captures, &params);
        let report = compare_to_baseline(
            &base,
            &CaptureProfile {
                hosts: vec![base_obs.clone()],
            },
            &params,
        );
        assert!(report.deviations.is_empty(), "{:?}", report.deviations);
    }

    fn out1(o: &HostObservation) -> AnalysisOutput {
        AnalysisOutput {
            engine_version: "t".to_string(),
            baseline: Some(CaptureProfile {
                hosts: vec![o.clone()],
            }),
            ..Default::default()
        }
    }

    #[test]
    fn merge_is_order_independent_with_m2_fields() {
        let params = BaselineParams::default();
        // Two captures with overlapping ("common") and disjoint ja3/hours/categories/beacons.
        let a_obs = obs_full(
            "10.0.0.5",
            1000,
            &["203.0.113.7"],
            &[443],
            &["aaaa", "common"],
            &[8, 9],
            &[0, 1],
            &[("203.0.113.7", 443)],
        );
        let b_obs = obs_full(
            "10.0.0.5",
            2000,
            &["203.0.113.8"],
            &[80],
            &["bbbb", "common"],
            &[9, 10],
            &[1, 7],
            &[("203.0.113.8", 80)],
        );
        let a = update_baseline(BaselineProfile::new(), &out1(&a_obs), 1, &params);
        let b = update_baseline(BaselineProfile::new(), &out1(&b_obs), 2, &params);
        let ab = merge(a.clone(), b.clone(), &params);
        let ba = merge(b, a, &params);
        let ha = &ab.hosts[0];
        let hb = &ba.hosts[0];
        assert_eq!(ha.captures_seen, hb.captures_seen);
        assert_eq!(ha.hour_of_day, hb.hour_of_day);
        assert_eq!(ha.categories, hb.categories);
        let ja3_map = |h: &HostBaseline| -> BTreeMap<String, u64> {
            h.ja3
                .iter()
                .map(|j| (j.ja3.clone(), j.seen.captures))
                .collect()
        };
        assert_eq!(ja3_map(ha), ja3_map(hb));
        let bc_map = |h: &HostBaseline| -> BTreeMap<(String, u16), u64> {
            h.beacons
                .iter()
                .map(|x| ((x.dst.clone(), x.port), x.seen.captures))
                .collect()
        };
        assert_eq!(bc_map(ha), bc_map(hb));
        // The "common" JA3 appeared in both captures.
        assert_eq!(
            ha.ja3
                .iter()
                .find(|j| j.ja3 == "common")
                .unwrap()
                .seen
                .captures,
            2
        );
        // Hour 9 was active in both captures.
        assert_eq!(
            ha.hour_of_day[9],
            a_obs.hour_of_day[9] as u64 + b_obs.hour_of_day[9] as u64
        );
    }

    #[test]
    fn m1_sidecar_deserializes_into_m2_engine() {
        // A schema_version:1 sidecar written by M1 (no ja3/hour_of_day/categories/beacons keys).
        let json = r#"{
          "schema_version":1,"engine_version":"0.1.0","captures_merged":3,"source_sha256s":[],
          "first_analyzed_unix_secs":0,"last_analyzed_unix_secs":0,"first_ts_ns":0,"last_ts_ns":0,
          "hosts":[{"host":"10.0.0.5","captures_seen":3,
            "bytes_out":{"count":3,"mean":1000.0,"m2":0.0,"min":1000.0,"max":1000.0,"ewma":1000.0},
            "bytes_in":{"count":3,"mean":250.0,"m2":0.0,"min":250.0,"max":250.0,"ewma":250.0},
            "flows":{"count":3,"mean":1.0,"m2":0.0,"min":1.0,"max":1.0,"ewma":1.0},
            "peers":[{"ip":"203.0.113.7","seen":{"captures":3,"total":3,"first_seen_unix":0,"last_seen_unix":0}}],
            "services":[{"port":443,"seen":{"captures":3,"total":3,"first_seen_unix":0,"last_seen_unix":0}}],
            "first_seen_unix":0,"last_seen_unix":0}]}"#;
        let p = BaselineProfile::from_json_str(json).unwrap();
        assert_eq!(p.hosts.len(), 1);
        let h = &p.hosts[0];
        assert!(h.ja3.is_empty() && h.beacons.is_empty());
        assert_eq!(h.hour_of_day, [0u64; 24]);
        assert_eq!(h.categories, [0u64; 13]);
        assert_eq!(h.peers.len(), 1);
    }

    #[test]
    fn off_hours_guard_boundaries() {
        let params = BaselineParams::default(); // min_active_hours = 3
        let has_offhours = |r: &DeviationReport| {
            r.deviations
                .iter()
                .any(|d| d.evidence.iter().any(|e| e.contains("active window")))
        };

        // (1) Sparse window (2 populated hours < min_active_hours) suppresses off-hours.
        let sparse = obs_full(
            "10.0.0.5",
            1000,
            &["203.0.113.7"],
            &[443],
            &[],
            &[8, 9],
            &[0],
            &[],
        );
        let base = warm_full(&sparse, params.min_captures, &params);
        let dev = obs_full(
            "10.0.0.5",
            1000,
            &["203.0.113.7"],
            &[443],
            &[],
            &[3],
            &[0],
            &[],
        );
        assert!(!has_offhours(&compare_to_baseline(
            &base,
            &CaptureProfile { hosts: vec![dev] },
            &params
        )));

        // (2) 24/7 baseline (all 24 populated) has no off-hours.
        let all24: Vec<usize> = (0..24).collect();
        let full = obs_full(
            "10.0.0.5",
            1000,
            &["203.0.113.7"],
            &[443],
            &[],
            &all24,
            &[0],
            &[],
        );
        let base = warm_full(&full, params.min_captures, &params);
        let dev = obs_full(
            "10.0.0.5",
            1000,
            &["203.0.113.7"],
            &[443],
            &[],
            &[3],
            &[0],
            &[],
        );
        assert!(!has_offhours(&compare_to_baseline(
            &base,
            &CaptureProfile { hosts: vec![dev] },
            &params
        )));

        // (3) Defined window (3 <= populated < 24) + a cold hour DOES flag off-hours.
        let win = obs_full(
            "10.0.0.5",
            1000,
            &["203.0.113.7"],
            &[443],
            &[],
            &[8, 9, 10],
            &[0],
            &[],
        );
        let base = warm_full(&win, params.min_captures, &params);
        let dev = obs_full(
            "10.0.0.5",
            1000,
            &["203.0.113.7"],
            &[443],
            &[],
            &[8, 3],
            &[0],
            &[],
        );
        assert!(has_offhours(&compare_to_baseline(
            &base,
            &CaptureProfile { hosts: vec![dev] },
            &params
        )));
    }

    #[test]
    fn constant_baseline_uses_a_scale_relative_band() {
        // A perfectly constant baseline has sd == 0. The old static gate skipped it entirely — a
        // blind spot where a huge spike went unflagged. Predictive mode uses a scale-relative σ
        // floor, so a modest value near the constant baseline stays quiet, but a large jump is caught.
        let params = BaselineParams::default();
        let base = warm_baseline(
            "10.0.0.5",
            params.min_captures,
            1000,
            &["203.0.113.7"],
            &[443],
        );
        // A small bump stays within the scale-relative band.
        let near = obs("10.0.0.5", 1050, &["203.0.113.7"], &[443]);
        let quiet = compare_to_baseline(&base, &CaptureProfile { hosts: vec![near] }, &params);
        assert!(
            quiet.deviations.is_empty(),
            "a small bump on a constant baseline stays quiet: {:?}",
            quiet.deviations
        );
        // A large spike is now caught (the sd==0 blind spot is closed).
        let spike = obs("10.0.0.5", 50_000_000, &["203.0.113.7"], &[443]);
        let report = compare_to_baseline(&base, &CaptureProfile { hosts: vec![spike] }, &params);
        assert_eq!(report.deviations.len(), 1);
        assert!(report.deviations[0]
            .evidence
            .iter()
            .any(|e| e.contains("cross-capture forecast")));
    }

    /// Build a warmed-up baseline (N identical captures) for a host, then compare.
    fn warm_baseline(
        host: &str,
        n: u64,
        bytes: u64,
        peers: &[&str],
        svcs: &[u16],
    ) -> BaselineProfile {
        let params = BaselineParams::default();
        let mut base = BaselineProfile::new();
        for i in 0..n {
            let prof = CaptureProfile {
                hosts: vec![obs(host, bytes, peers, svcs)],
            };
            base = update_baseline(
                base,
                &output_with(prof, &format!("s{i}"), 10, 20),
                1000 + i as i64,
                &params,
            );
        }
        base
    }

    #[test]
    fn conforming_host_raises_no_deviation() {
        let params = BaselineParams::default();
        let base = warm_baseline("10.0.0.5", 6, 1000, &["203.0.113.7"], &[443]);
        let prof = CaptureProfile {
            hosts: vec![obs("10.0.0.5", 1000, &["203.0.113.7"], &[443])],
        };
        let report = compare_to_baseline(&base, &prof, &params);
        assert_eq!(report.hosts_compared, 1);
        assert!(report.deviations.is_empty(), "{:?}", report.deviations);
    }

    #[test]
    fn new_peer_and_port_raise_deviation() {
        let params = BaselineParams::default();
        let base = warm_baseline("10.0.0.5", 6, 1000, &["203.0.113.7"], &[443]);
        let prof = CaptureProfile {
            hosts: vec![obs(
                "10.0.0.5",
                1000,
                &["203.0.113.7", "198.51.100.9"],
                &[443, 4444],
            )],
        };
        let report = compare_to_baseline(&base, &prof, &params);
        assert_eq!(report.deviations.len(), 1);
        let d = &report.deviations[0];
        assert_eq!(d.host, "10.0.0.5");
        assert_eq!(d.peer.as_deref(), Some("198.51.100.9"));
        assert_eq!(d.port, Some(4444));
        assert_eq!(d.severity, Severity::from_score(d.score));
        assert!(d.evidence.iter().any(|e| e.contains("198.51.100.9")));
        assert!(d.evidence.iter().any(|e| e.contains("4444")));
        // The deviation becomes a BaselineDeviation finding.
        let findings = report.into_findings();
        assert_eq!(findings[0].kind, FindingKind::BaselineDeviation);
        assert_eq!(findings[0].src_ip, "10.0.0.5");
    }

    #[test]
    fn volume_spike_raises_deviation() {
        let params = BaselineParams::default();
        // Vary the baseline a little so stddev > 0.
        let mut base = BaselineProfile::new();
        for (i, b) in [900u64, 1000, 1100, 950, 1050, 1000]
            .into_iter()
            .enumerate()
        {
            let prof = CaptureProfile {
                hosts: vec![obs("10.0.0.5", b, &["203.0.113.7"], &[443])],
            };
            base = update_baseline(
                base,
                &output_with(prof, &format!("s{i}"), 10, 20),
                1000 + i as i64,
                &params,
            );
        }
        // A 50 MB egress dwarfs the ~1 KB baseline.
        let prof = CaptureProfile {
            hosts: vec![obs("10.0.0.5", 50_000_000, &["203.0.113.7"], &[443])],
        };
        let report = compare_to_baseline(&base, &prof, &params);
        assert_eq!(report.deviations.len(), 1);
        assert!(report.deviations[0]
            .evidence
            .iter()
            .any(|e| e.contains("outbound") && e.contains("σ")));
    }

    /// Build a baseline for one host from a rising per-capture volume trend (`start`, `start+step`,
    /// … over `n` captures), each with a distinct wall-clock second.
    fn rising_baseline(host: &str, n: u64, start: u64, step: u64) -> BaselineProfile {
        let params = BaselineParams::default();
        let mut base = BaselineProfile::new();
        for i in 0..n {
            let bytes = start + i * step;
            let prof = CaptureProfile {
                hosts: vec![obs(host, bytes, &["203.0.113.7"], &[443])],
            };
            base = update_baseline(
                base,
                &output_with(prof, &format!("t{i}"), 10, 20),
                1_000 + i as i64,
                &params,
            );
        }
        base
    }

    #[test]
    fn recent_series_is_bounded_and_time_ordered() {
        let mut s: Vec<RecentPoint> = Vec::new();
        for (u, v) in [(5, 5.0), (1, 1.0), (3, 3.0), (2, 2.0), (4, 4.0)] {
            push_recent(&mut s, RecentPoint { unix: u, value: v }, 3);
        }
        // Kept the 3 most-recent by time, in ascending order (oldest dropped).
        assert_eq!(s.iter().map(|p| p.unix).collect::<Vec<_>>(), vec![3, 4, 5]);
        let a = vec![
            RecentPoint {
                unix: 1,
                value: 1.0,
            },
            RecentPoint {
                unix: 4,
                value: 4.0,
            },
        ];
        let b = vec![
            RecentPoint {
                unix: 2,
                value: 2.0,
            },
            RecentPoint {
                unix: 3,
                value: 3.0,
            },
        ];
        assert_eq!(
            merge_recent(&a, &b, 3)
                .iter()
                .map(|p| p.unix)
                .collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
    }

    #[test]
    fn predictive_mode_stays_quiet_on_trend_growth() {
        let params = BaselineParams::default();
        // A host whose egress steadily rises: 1, 2, … 8 MB across 8 captures.
        let base = rising_baseline("10.0.0.5", 8, 1_000_000, 1_000_000);
        assert_eq!(base.host("10.0.0.5").unwrap().bytes_out_recent.len(), 8);
        // The next capture continues the trend (~9 MB) — predictive mode must NOT flag it.
        let prof = CaptureProfile {
            hosts: vec![obs("10.0.0.5", 9_000_000, &["203.0.113.7"], &[443])],
        };
        let report = compare_to_baseline(&base, &prof, &params);
        assert!(
            report.deviations.is_empty(),
            "legitimate on-trend growth must not deviate: {:?}",
            report.deviations
        );
    }

    #[test]
    fn predictive_mode_catches_off_trend_jump_the_static_gate_misses() {
        let params = BaselineParams::default();
        let base = rising_baseline("10.0.0.5", 8, 1_000_000, 1_000_000);
        let hb = base.host("10.0.0.5").unwrap();

        // The trend forecast's upper band and the *static* mean+k·σ threshold — a genuine gap must
        // exist between them (that gap is exactly what predictive mode adds).
        let recent: Vec<f64> = hb.bytes_out_recent.iter().map(|p| p.value).collect();
        let fc =
            crate::forecast::forecast_next(&recent, &crate::forecast::ForecastParams::default())
                .expect("enough points to forecast");
        let band_hi = fc.forecast + params.forecast_z * fc.sigma;
        let static_threshold = hb.bytes_out.mean + params.volume_k * hb.bytes_out.stddev();
        assert!(
            band_hi < static_threshold,
            "predictive band ({band_hi:.0}) should be tighter than the static gate ({static_threshold:.0})"
        );

        // A value in that gap: below the static gate (the old detector is silent) but above the
        // trend forecast — predictive mode catches it.
        let observed = ((band_hi + static_threshold) / 2.0) as u64;
        assert!((observed as f64) < static_threshold && (observed as f64) > band_hi);
        let prof = CaptureProfile {
            hosts: vec![obs("10.0.0.5", observed, &["203.0.113.7"], &[443])],
        };
        let report = compare_to_baseline(&base, &prof, &params);
        assert_eq!(
            report.deviations.len(),
            1,
            "the off-trend jump must deviate"
        );
        assert!(
            report.deviations[0]
                .evidence
                .iter()
                .any(|e| e.contains("cross-capture forecast")),
            "{:?}",
            report.deviations[0].evidence
        );
    }

    #[test]
    fn predictive_falls_back_to_static_without_a_series() {
        // An older sidecar has the `bytes_out` distribution but no per-capture recency ring; the
        // static mean+k·σ gate must still run (serde(default) back-compat).
        let params = BaselineParams::default();
        let mut base = BaselineProfile::new();
        for (i, b) in [900u64, 1000, 1100, 950, 1050, 1000]
            .into_iter()
            .enumerate()
        {
            let prof = CaptureProfile {
                hosts: vec![obs("10.0.0.5", b, &["203.0.113.7"], &[443])],
            };
            base = update_baseline(
                base,
                &output_with(prof, &format!("s{i}"), 10, 20),
                1_000 + i as i64,
                &params,
            );
        }
        for h in base.hosts.iter_mut() {
            // Simulate an old sidecar: no per-metric recency rings at all.
            h.bytes_out_recent.clear();
            h.bytes_in_recent.clear();
            h.flows_recent.clear();
        }
        let prof = CaptureProfile {
            hosts: vec![obs("10.0.0.5", 50_000_000, &["203.0.113.7"], &[443])],
        };
        let report = compare_to_baseline(&base, &prof, &params);
        assert_eq!(report.deviations.len(), 1);
        assert!(
            report.deviations[0]
                .evidence
                .iter()
                .any(|e| e.contains("vs mean")),
            "fallback uses the static-gate evidence: {:?}",
            report.deviations[0].evidence
        );
    }

    #[test]
    fn predictive_mode_flags_inbound_off_trend() {
        let params = BaselineParams::default();
        // Outbound + connection count steady; inbound rises 1 → 8 MB over 8 captures.
        let samples: Vec<(u64, u64, u64)> = (0u64..8)
            .map(|i| (1000, 1_000_000 + i * 1_000_000, 1))
            .collect();
        let base = fold_all("10.0.0.5", &samples);
        // Inbound jumps far off its trend (which predicts ~9 MB); outbound/flows unchanged.
        let prof = CaptureProfile {
            hosts: vec![obs_metrics("10.0.0.5", 1000, 40_000_000, 1)],
        };
        let report = compare_to_baseline(&base, &prof, &params);
        assert_eq!(report.deviations.len(), 1);
        let ev = &report.deviations[0].evidence;
        assert!(
            ev.iter()
                .any(|e| e.contains("inbound") && e.contains("cross-capture forecast")),
            "inbound off-trend must fire: {ev:?}"
        );
        assert!(
            !ev.iter().any(|e| e.contains("outbound")),
            "outbound was on-baseline and must not deviate: {ev:?}"
        );
    }

    #[test]
    fn predictive_mode_flags_connection_count_off_trend() {
        let params = BaselineParams::default();
        // Bytes steady; connection count rises 10, 20, … 80 over 8 captures.
        let samples: Vec<(u64, u64, u64)> = (0u64..8).map(|i| (1000, 1000, 10 + i * 10)).collect();
        let base = fold_all("10.0.0.5", &samples);
        // A burst of connections far off the trend (which predicts ~90).
        let prof = CaptureProfile {
            hosts: vec![obs_metrics("10.0.0.5", 1000, 1000, 400)],
        };
        let report = compare_to_baseline(&base, &prof, &params);
        assert_eq!(report.deviations.len(), 1);
        assert!(
            report.deviations[0]
                .evidence
                .iter()
                .any(|e| e.contains("connections") && e.contains("cross-capture forecast")),
            "{:?}",
            report.deviations[0].evidence
        );
    }

    /// A host with a weekday/weekend outbound rhythm (~10 MB weekdays, ~1 MB weekends) over two
    /// weeks; inbound + connections flat so only outbound carries a season. `day 12 → phase 5` is a
    /// "weekend" slot.
    fn seasonal_weekly_baseline(host: &str) -> BaselineProfile {
        let params = BaselineParams::default();
        let mut base = BaselineProfile::new();
        for day in 0i64..14 {
            let out = if (day % 7) < 5 { 10_000_000 } else { 1_000_000 };
            let prof = CaptureProfile {
                hosts: vec![obs_metrics(host, out, 500_000, 5)],
            };
            let ts = day * 86_400 * 1_000_000_000;
            base = update_baseline(
                base,
                &output_with(prof, &format!("d{day}"), ts, ts + 1_000_000_000),
                1_000 + day,
                &params,
            );
        }
        base
    }

    #[test]
    fn seasonality_flags_off_rhythm_value_a_flat_forecast_misses() {
        let params = BaselineParams::default();
        let base = seasonal_weekly_baseline("10.0.0.5");
        // Two weeks => all 7 day-of-week slots learned.
        assert_eq!(base.host("10.0.0.5").unwrap().bytes_out_seasonal.len(), 7);
        let weekend_unix = 12 * 86_400; // phase 5 — a "weekend" slot (expects ~1 MB)

        // A weekend capture carrying a weekday-high 10 MB — off-rhythm.
        let prof = CaptureProfile {
            hosts: vec![obs_metrics("10.0.0.5", 10_000_000, 500_000, 5)],
        };

        // Seasonality ON: the value breaks the weekend seasonal band.
        let seasonal = compare_to_baseline_at(&base, &prof, weekend_unix, &params);
        assert_eq!(seasonal.deviations.len(), 1);
        assert!(
            seasonal.deviations[0]
                .evidence
                .iter()
                .any(|e| e.contains("seasonal") && e.contains("outbound")),
            "off-rhythm value must fire a seasonal deviation: {:?}",
            seasonal.deviations[0].evidence
        );

        // Seasonality OFF: 10 MB is unremarkable against the flat trend — no deviation. This is the
        // value seasonality adds.
        let flat_params = BaselineParams {
            seasonal_enabled: false,
            ..params.clone()
        };
        let flat = compare_to_baseline_at(&base, &prof, weekend_unix, &flat_params);
        assert!(
            flat.deviations.is_empty(),
            "a flat (non-seasonal) forecast should not flag this value: {:?}",
            flat.deviations
        );
    }

    #[test]
    fn seasonal_phase_maps_day_of_week_and_hour_of_day() {
        let dow = BaselineParams::default(); // slot 86400, period 7
        assert_eq!(seasonal_phase(0, &dow), 0);
        assert_eq!(seasonal_phase(86_400, &dow), 1);
        assert_eq!(seasonal_phase(12 * 86_400, &dow), 5); // 12 % 7
        assert_eq!(seasonal_phase(7 * 86_400, &dow), 0); // wraps
        let hod = BaselineParams {
            seasonal_slot_secs: 3_600,
            seasonal_period: 24,
            ..Default::default()
        };
        assert_eq!(seasonal_phase(3_600 * 5, &hod), 5);
        assert_eq!(seasonal_phase(3_600 * 25, &hod), 1); // 25 % 24
                                                         // Misconfigured (period 0) degrades to phase 0.
        let bad = BaselineParams {
            seasonal_period: 0,
            ..Default::default()
        };
        assert_eq!(seasonal_phase(999_999, &bad), 0);
    }

    #[test]
    fn seasonality_stays_quiet_in_rhythm() {
        let params = BaselineParams::default();
        let base = seasonal_weekly_baseline("10.0.0.5");
        // A weekend capture with the weekend-normal ~1 MB — in-rhythm, must not fire, even though
        // 1 MB is far below the host's overall (weekday-dominated) mean.
        let prof = CaptureProfile {
            hosts: vec![obs_metrics("10.0.0.5", 1_000_000, 500_000, 5)],
        };
        let report = compare_to_baseline_at(&base, &prof, 12 * 86_400, &params);
        assert!(
            report.deviations.is_empty(),
            "in-rhythm value must not deviate: {:?}",
            report.deviations
        );
    }

    #[test]
    fn cold_start_is_quiet() {
        let params = BaselineParams::default();
        // Only 2 captures < min_captures(5): warm-up gate suppresses deviations.
        let base = warm_baseline("10.0.0.5", 2, 1000, &["203.0.113.7"], &[443]);
        let prof = CaptureProfile {
            hosts: vec![obs("10.0.0.5", 1000, &["9.9.9.9"], &[31337])],
        };
        let report = compare_to_baseline(&base, &prof, &params);
        assert_eq!(report.hosts_compared, 1);
        assert!(report.deviations.is_empty());
    }

    #[test]
    fn unknown_host_and_empty_baseline_are_graceful() {
        let params = BaselineParams::default();
        let base = warm_baseline("10.0.0.5", 6, 1000, &["203.0.113.7"], &[443]);
        // A host not in the baseline is skipped.
        let prof = CaptureProfile {
            hosts: vec![obs("10.0.0.99", 1000, &["9.9.9.9"], &[443])],
        };
        let report = compare_to_baseline(&base, &prof, &params);
        assert_eq!(report.hosts_compared, 0);
        assert!(report.deviations.is_empty());
        // An empty baseline yields nothing.
        let empty = compare_to_baseline(&BaselineProfile::new(), &prof, &params);
        assert!(empty.deviations.is_empty());
    }

    #[test]
    fn hosts_and_sets_stay_bounded_and_sorted() {
        let params = BaselineParams {
            top_k_peers: 3,
            ..Default::default()
        };
        let peers: Vec<String> = (0..20).map(|i| format!("203.0.113.{i}")).collect();
        let peer_refs: Vec<&str> = peers.iter().map(|s| s.as_str()).collect();
        let base = {
            let prof = CaptureProfile {
                hosts: vec![obs("10.0.0.5", 1000, &peer_refs, &[443])],
            };
            update_baseline(
                BaselineProfile::new(),
                &output_with(prof, "a", 10, 20),
                1,
                &params,
            )
        };
        assert!(base.hosts[0].peers.len() <= 3);
        // Sorted by ip on disk.
        let mut sorted = base.hosts[0].peers.clone();
        sorted.sort_by(|a, b| a.ip.cmp(&b.ip));
        assert_eq!(base.hosts[0].peers, sorted);
    }
}
