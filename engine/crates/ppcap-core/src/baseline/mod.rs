//! Behavioral Baseline Learning — learn a per-internal-host behavioral profile across captures,
//! persist it as an offline JSON sidecar, and compare a new capture against it to raise
//! explainable "baseline deviation" findings.
//!
//! This is the local-first, no-backend core of the feature: everything is a pure transform over a
//! small JSON sidecar. A [`CaptureProfile`] is this capture's per-host egress snapshot (produced by
//! [`crate::detect::BehaviorTracker::baseline_snapshot`] during the streaming pass);
//! [`update_baseline`] folds one such snapshot into a persisted [`BaselineProfile`] (running
//! per-host statistics + seen peer/port sets), and [`compare_to_baseline`] diffs a fresh snapshot
//! against the learned profile — a host doing something it never did before (a first-seen external
//! peer or destination port, or an outbound-volume spike well beyond its historical distribution)
//! yields a [`FindingKind::BaselineDeviation`] finding.
//!
//! It complements Time Machine: Time Machine asks *"threat intel caught up — did I already talk to
//! something now-known-bad?"*; a baseline asks *"my network changed — is this host doing something
//! it never did before?"*
//!
//! Scope note: this Phase-1 (M1) core learns the highest-signal egress dimensions — external peers,
//! destination ports, and outbound volume — per internal host, over the offline sidecar. First-seen
//! JA3, off-hours activity, per-host category novelty, and new-beacon detection are deliberately out
//! of scope here and tracked as follow-ups; a shared/team baseline store is out of the local-first
//! core entirely. Invariants preserved: bounded memory (per-host `top_k` caps + a host cap),
//! C-compiler-free (pure-Rust `serde_json` + f64), local-first (offline sidecar, pure compare),
//! i64 ns capture windows / i64 unix-secs wall-clock, and deterministic output (`BTreeMap`
//! accumulate → sorted `Vec`; order-independent stat folds).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::finding::{Finding, FindingKind};
use crate::model::output::AnalysisOutput;
use crate::model::severity::Severity;
use crate::score::{
    score_baseline_deviation, PTS_DEV_NEW_EXTERNAL_PEER, PTS_DEV_NEW_PORT, PTS_DEV_VOLUME_SPIKE,
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
    /// Cap on the provenance `source_sha256s` list.
    pub max_source_shas: usize,
    /// EWMA smoothing factor for the recency-weighted mean (hint only; the deviation gate uses
    /// `mean + k·stddev`, which merges exactly).
    pub ewma_alpha: f64,
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
            max_source_shas: 256,
            ewma_alpha: 0.30,
        }
    }
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
            first_seen_unix: 0,
            last_seen_unix: 0,
        }
    }

    fn observe(&mut self, obs: &HostObservation, now_unix: i64, params: &BaselineParams) {
        self.captures_seen += 1;
        self.bytes_out
            .observe(obs.bytes_out as f64, params.ewma_alpha);
        self.bytes_in
            .observe(obs.bytes_in as f64, params.ewma_alpha);
        self.flows.observe(obs.flows as f64, params.ewma_alpha);
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
        HostBaseline {
            host: a.host.clone(),
            captures_seen: a.captures_seen + b.captures_seen,
            bytes_out: RunningStat::merge(&a.bytes_out, &b.bytes_out),
            bytes_in: RunningStat::merge(&a.bytes_in, &b.bytes_in),
            flows: RunningStat::merge(&a.flows, &b.flows),
            peers: cap_peers(peers, params.top_k_peers),
            services: cap_services(services, params.top_k_services),
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

    let mut hosts: BTreeMap<String, HostBaseline> = std::mem::take(&mut base.hosts)
        .into_iter()
        .map(|h| (h.host.clone(), h))
        .collect();
    for obs in &prof.hosts {
        hosts
            .entry(obs.host.clone())
            .or_insert_with(|| HostBaseline::new(obs.host.clone()))
            .observe(obs, now_unix, params);
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

/// Compare a capture's [`CaptureProfile`] snapshot against a learned baseline, returning the hosts
/// that deviated. Pure and offline. A host with no baseline, or whose baseline is still in warm-up
/// (`captures_seen < params.min_captures`), is skipped. Deviations sort worst-first.
pub fn compare_to_baseline(
    base: &BaselineProfile,
    prof: &CaptureProfile,
    params: &BaselineParams,
) -> DeviationReport {
    let mut report = DeviationReport::default();
    if !params.enabled {
        return report;
    }
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

        // --- Outbound volume spike ---
        if hb.bytes_out.count >= params.min_captures {
            let mean = hb.bytes_out.mean;
            let sd = hb.bytes_out.stddev();
            if sd > 0.0 {
                let threshold = mean + params.volume_k * sd;
                let observed = obs.bytes_out as f64;
                if observed > threshold {
                    let z = (observed - mean) / sd;
                    dims.push((
                        format!(
                            "baseline: outbound {} bytes vs mean {:.0} ± {:.0} ({:.1}σ over {} captures)",
                            obs.bytes_out, mean, sd, z, hb.bytes_out.count
                        ),
                        PTS_DEV_VOLUME_SPIKE,
                    ));
                }
            }
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
        }
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
