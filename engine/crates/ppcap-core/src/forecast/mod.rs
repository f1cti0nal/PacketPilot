//! Predictive Anomaly Detection — online per-host traffic forecasting.
//!
//! Every other detector in the engine fires on an **absolute threshold** (a beacon period, a scan
//! fan-out, an exfil byte count) or **set membership** (an IOC hit, a first-seen peer). This one
//! *forecasts*: for each internal host it builds a within-capture traffic time-series (outbound
//! bytes per fixed-width bin) and runs an online **one-step-ahead forecaster** — Holt's double
//! exponential smoothing (a `level` + a `trend`) — to predict each bin from the host's own recent
//! trajectory. A bin whose actual volume falls outside the forecast's **prediction band**
//! (`forecast ± z·σ`, σ from an EWMA of the forecast residuals) is a point anomaly (a spike or a
//! drop); a *sustained* departure is a level shift, caught by a two-sided **CUSUM** changepoint.
//!
//! ## Why this is not Behavioral Baseline Learning
//!
//! BBL (`crate::baseline`) collapses each capture into **one per-host aggregate** and compares it to
//! a distribution learned across **many prior captures** (needs a warm-up of ≥ N captures and is
//! blind to *when within a capture* the volume arrived). Predictive Anomaly Detection needs **no
//! cross-capture history** — it learns the host's normal trajectory *inside this single capture* and
//! flags the temporal shape (a burst at 03:14, a ramp, a drop-to-silence) that a single-number
//! aggregate structurally cannot see. The two are complementary: BBL answers "is this capture
//! unusual for this host's history?"; this answers "did this host's traffic do something its own
//! forecast did not predict, right here?".
//!
//! ## Invariants
//!
//! Pure `f64` math, **no** allocation-per-packet and **no** network — a single post-EOF pass over an
//! already-bounded per-host bin series (built by [`crate::stats::StatsAccumulator`], top-K hosts,
//! ≤ `max_time_buckets` bins each). O(1) forecaster state per host. Deterministic: the input series
//! is sorted by host, the pass is fixed-order, and the emitted anomalies are sorted worst-first with
//! a total-order tie-break — no `HashMap` iteration leaks into the output, no clock, no RNG.

use crate::model::finding::{Finding, FindingKind};
use crate::model::severity::Severity;
use crate::score::{score_traffic_anomaly, PTS_FC_DROP, PTS_FC_LEVEL_SHIFT, PTS_FC_SPIKE};

/// Tunable thresholds for the forecaster. Defaults are deliberately conservative: the warm-up, the
/// scale-relative σ floor, and a wide (`z = 4`) band keep uniform / bursty-but-benign traffic silent,
/// and the score cap ([`crate::score::FC_UPLIFT_CAP`]) holds an anomaly-alone verdict at Medium.
#[derive(Debug, Clone, PartialEq)]
pub struct ForecastParams {
    /// Master switch. When `false`, [`detect_traffic_anomalies`] is a no-op (empty report).
    pub enabled: bool,
    /// Holt **level** smoothing factor `α` (0 < α ≤ 1). Higher = tracks recent level faster.
    pub level_alpha: f64,
    /// Holt **trend** smoothing factor `β` (0 ≤ β ≤ 1). Higher = tracks slope changes faster.
    pub trend_beta: f64,
    /// Residual-variance EWMA smoothing factor `γ` (0 < γ ≤ 1) — how fast σ adapts.
    pub var_gamma: f64,
    /// Prediction-band half-width in residual σ. A bin is a point anomaly when `|actual − forecast|`
    /// exceeds `z·σ`.
    pub z: f64,
    /// Warm-up: number of leading bins to fold into the forecaster before its band is trusted. Below
    /// this a host raises nothing (the single-capture analogue of BBL's `min_captures`).
    pub min_bins: usize,
    /// CUSUM slack `k` in σ units (the per-bin drift the changepoint tolerates before accumulating).
    pub cusum_k: f64,
    /// CUSUM decision threshold `h` in σ units (accumulated drift that declares a level shift).
    pub cusum_h: f64,
    /// Ignore a host whose busiest bin is below this many bytes (a trivial talker — nothing to model).
    pub min_bin_bytes: u64,
    /// Cap on the number of hosts forecast (the heaviest by total bytes); bounds work + output.
    pub max_hosts: usize,
    /// Cap on emitted anomalies (worst-first; the tail is dropped after sorting).
    pub max_findings: usize,
    /// For the per-peer egress decomposition: the number of top peers (by bytes) to forecast as
    /// sub-series for each decomposed host. Bounds the peer fan-out per host so a chatty host does
    /// not explode the series count. `0` disables the peer pass.
    pub max_peers_per_host: usize,
    /// For the per-**port** egress decomposition: the number of top service ports (by bytes) to
    /// forecast as sub-series for each decomposed host. Bounds the port fan-out per host. `0`
    /// disables the port pass.
    pub max_ports_per_host: usize,
    /// σ floor as a fraction of the host's mean bin volume, so a host that means 1 MB/bin does not
    /// flag a few-KB wobble as "many σ". `σ = max(√var, sigma_floor_frac·mean, 1)`.
    pub sigma_floor_frac: f64,
}

impl Default for ForecastParams {
    fn default() -> Self {
        ForecastParams {
            enabled: true,
            level_alpha: 0.4,
            trend_beta: 0.2,
            var_gamma: 0.3,
            z: 4.0,
            min_bins: 8,
            cusum_k: 0.5,
            cusum_h: 6.0,
            min_bin_bytes: 8_192,
            max_hosts: 256,
            max_findings: 256,
            max_peers_per_host: 8,
            max_ports_per_host: 8,
            sigma_floor_frac: 0.15,
        }
    }
}

/// One internal host's within-capture traffic series: outbound bytes per fixed-width time bin,
/// **gap-filled with zeros** so the series is contiguous — a silent bin must be *seen* as a zero for
/// a drop-to-silence to be detectable. `start_epoch_sec` is the first bin's start (Unix seconds);
/// `bin_secs` the bin width. Built by the stats accumulator; consumed here read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSeries {
    pub host: String,
    pub start_epoch_sec: i64,
    pub bin_secs: i64,
    pub bins: Vec<u64>,
    /// When `Some`, this series is a **sub-series**: not the host's whole traffic but only its
    /// exchange with this one peer (an external destination for egress). A peer-resolved anomaly is
    /// attributed to `host` with the peer carried into the finding's `dst_ip`, so a spike to one
    /// destination that the host's blended aggregate masks (the egress-proxy blind spot) is caught
    /// and named. `None` for a whole-host series. `#[serde]`-free; defaults to `None`.
    pub peer: Option<String>,
    /// When `Some`, this series is a **per-port sub-series**: only the host's egress on this service
    /// port (the well-known side). A port-resolved anomaly carries the port into the finding's
    /// `dst_port`, catching a spike concentrated on one service — even one spread across many peers,
    /// which the per-peer split would divide away. Mutually exclusive with `peer`; `None` otherwise.
    pub port: Option<u16>,
}

/// Which direction of a host's traffic a series measures — its **egress** (bytes it sent) or its
/// **ingress** (bytes it received). Drives the evidence wording and the ATT&CK context; a finding is
/// attributed to the host either way (the sender for egress, the *receiving victim* for ingress).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlowDir {
    /// Bytes the host sent (exfil burst / outbound-flood participation).
    #[default]
    Out,
    /// Bytes the host received (a volumetric inbound flood, or bulk inbound staging).
    In,
}

impl FlowDir {
    /// The direction word used in evidence strings.
    pub fn word(self) -> &'static str {
        match self {
            FlowDir::Out => "outbound",
            FlowDir::In => "inbound",
        }
    }
    /// ATT&CK context id for an anomalous volume in this direction (Exfil vs Network DoS).
    fn attack(self) -> &'static str {
        match self {
            FlowDir::Out => "T1048", // Exfiltration Over Alternative Protocol
            FlowDir::In => "T1498",  // Network Denial of Service
        }
    }
    /// Preposition tying a host to the peer of a sub-series: the host *sent to* a peer (egress) or
    /// *received from* one (ingress). Used only when a series is peer-resolved.
    fn peer_prep(self) -> &'static str {
        match self {
            FlowDir::Out => "to",
            FlowDir::In => "from",
        }
    }
}

/// The per-host series to forecast plus the shared bin width. Deterministically ordered (hosts
/// sorted, bins ascending in time) by the builder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ForecastInput {
    pub bin_secs: i64,
    pub series: Vec<HostSeries>,
    /// Whether `series` measures egress or ingress (defaults to egress for back-compatible literals).
    pub direction: FlowDir,
}

/// The three shapes a forecast departure can take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HitKind {
    /// Actual jumped above the upper band (`forecast + z·σ`).
    Spike,
    /// Actual fell below the lower band (`forecast − z·σ`) where the forecast was non-trivial.
    Drop,
    /// A sustained level shift (CUSUM crossed `h`) — a ramp/plateau, not a single-bin blip.
    LevelShift,
}

/// One flagged bin (internal — aggregated into at most one [`Anomaly`] per host).
#[derive(Debug, Clone, Copy)]
struct Hit {
    kind: HitKind,
    bin: usize,
    actual: f64,
    forecast: f64,
    sigma: f64,
    /// Signed standardized residual `(actual − forecast) / σ`.
    z: f64,
}

/// A per-host predictive traffic anomaly (one host → one finding, aggregating its hit kinds).
#[derive(Debug, Clone, PartialEq)]
pub struct Anomaly {
    pub host: String,
    pub severity: Severity,
    pub score: u16,
    pub title: String,
    pub evidence: Vec<String>,
    pub first_seen_ns: Option<i64>,
    pub last_seen_ns: Option<i64>,
    /// ATT&CK technique ids attached (context — anomalous egress volume).
    pub attack: Vec<String>,
    /// The peer this anomaly is resolved to, for a per-peer sub-series (carried into the finding's
    /// `dst_ip`); `None` for a whole-host anomaly.
    pub peer: Option<String>,
    /// The service port this anomaly is resolved to, for a per-port sub-series (carried into the
    /// finding's `dst_port`); `None` otherwise. Mutually exclusive with `peer`.
    pub port: Option<u16>,
}

/// The result of forecasting a capture's per-host traffic series.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ForecastReport {
    pub anomalies: Vec<Anomaly>,
    /// How many hosts had enough (non-trivial) traffic to be forecast.
    pub hosts_analyzed: usize,
}

impl ForecastReport {
    /// Convert anomalies into [`Finding`]s (kind [`FindingKind::TrafficAnomaly`]) for folding into
    /// the summary alongside the other detectors. `src_ip` is the deviating host; a whole-host
    /// anomaly leaves `dst_ip`/`dst_port` `None`, a per-peer sub-series carries the peer into
    /// `dst_ip`, and a per-port sub-series carries the port into `dst_port`.
    pub fn into_findings(self) -> Vec<Finding> {
        self.anomalies
            .into_iter()
            .map(|a| Finding {
                kind: FindingKind::TrafficAnomaly,
                severity: a.severity,
                score: a.score,
                title: a.title,
                src_ip: a.host,
                dst_ip: a.peer,
                dst_port: a.port,
                attack: a.attack,
                evidence: a.evidence,
                interval_ns: None,
                jitter_cv: None,
                contacts: None,
                first_seen_ns: a.first_seen_ns,
                last_seen_ns: a.last_seen_ns,
                victims: Vec::new(),
            })
            .collect()
    }
}

/// Forecast every host series and raise anomalies. Pure, offline, deterministic. A host with too
/// few bins (warm-up) or only trivial traffic raises nothing.
pub fn detect_traffic_anomalies(input: &ForecastInput, p: &ForecastParams) -> ForecastReport {
    let mut report = ForecastReport::default();
    if !p.enabled {
        return report;
    }
    for s in &input.series {
        let peak = s.bins.iter().copied().max().unwrap_or(0);
        if peak < p.min_bin_bytes {
            continue; // trivial talker — nothing worth modelling
        }
        report.hosts_analyzed += 1;
        let hits = forecast_host(s, p);
        if let Some(anomaly) = aggregate(s, &hits, input.direction) {
            report.anomalies.push(anomaly);
        }
    }
    // Worst-first, with a total-order tie-break so the emitted order is deterministic. The peer
    // tie-break keeps two sub-series of the same host from ordering non-deterministically.
    report.anomalies.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| b.severity.cmp(&a.severity))
            .then_with(|| a.host.cmp(&b.host))
            .then_with(|| a.peer.cmp(&b.peer))
            .then_with(|| a.port.cmp(&b.port))
    });
    report.anomalies.truncate(p.max_findings);
    report
}

/// A one-step-ahead forecast of the value *after* a series, with the residual σ that sizes its
/// prediction band. The caller decides the band width (`forecast ± z·σ`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ForecastNext {
    /// Predicted next value (clamped to ≥ 0).
    pub forecast: f64,
    /// Residual standard deviation (EWMA of forecast residuals, floored to the series scale).
    pub sigma: f64,
    /// Number of points the forecast was fit on.
    pub points: usize,
}

/// Forecast the value one step *beyond* `values` (index `n`) using the same Holt level+trend
/// recurrence as [`detect_traffic_anomalies`], returning the forecast and its residual σ. This is the
/// reusable core behind both intra-capture bin forecasting and the baseline module's *cross-capture*
/// predictive mode (Holt over a host's per-capture volume history). Returns `None` for fewer than 3
/// points (too few to seed a trend and a residual). Pure, deterministic, `O(n)` / `O(1)` state.
pub fn forecast_next(values: &[f64], p: &ForecastParams) -> Option<ForecastNext> {
    let n = values.len();
    if n < 3 {
        return None;
    }
    let mean = values.iter().sum::<f64>() / n as f64;
    let sigma_floor = (p.sigma_floor_frac * mean).max(1.0);
    let mut level = values[0];
    let mut trend = values[1] - values[0];
    let mut variance = 0.0f64;
    for &y in &values[1..] {
        let f = level + trend;
        let resid = y - f;
        let prev = level;
        level = p.level_alpha * y + (1.0 - p.level_alpha) * (level + trend);
        trend = p.trend_beta * (level - prev) + (1.0 - p.trend_beta) * trend;
        variance = p.var_gamma * resid * resid + (1.0 - p.var_gamma) * variance;
    }
    Some(ForecastNext {
        forecast: (level + trend).max(0.0),
        sigma: variance.sqrt().max(sigma_floor),
        points: n,
    })
}

/// Run the online Holt forecaster + residual-band + CUSUM over one host's series. Returns the flagged
/// bins (may be empty). O(n) time, O(1) state.
fn forecast_host(s: &HostSeries, p: &ForecastParams) -> Vec<Hit> {
    let n = s.bins.len();
    let mut hits: Vec<Hit> = Vec::new();
    // Need at least a couple of bins to seed level+trend, and the warm-up before we trust the band.
    if n < p.min_bins.max(3) {
        return hits;
    }
    let mean: f64 = s.bins.iter().map(|&b| b as f64).sum::<f64>() / n as f64;
    if mean <= 0.0 {
        return hits;
    }
    let sigma_floor = (p.sigma_floor_frac * mean).max(1.0);

    // Holt initialisation from the first two bins.
    let mut level = s.bins[0] as f64;
    let mut trend = s.bins[1] as f64 - s.bins[0] as f64;
    let mut var = 0.0f64; // EWMA of squared forecast residuals
    let mut cusum_hi = 0.0f64;
    let mut cusum_lo = 0.0f64;

    for t in 1..n {
        let y = s.bins[t] as f64;
        let forecast = level + trend;
        let resid = y - forecast;
        // σ from residual history seen *before* this bin (var not yet updated with `resid`).
        let sigma = var.sqrt().max(sigma_floor);
        let z = resid / sigma;

        if t >= p.min_bins {
            // Point anomalies: actual outside the band.
            if z >= p.z {
                hits.push(Hit {
                    kind: HitKind::Spike,
                    bin: t,
                    actual: y,
                    forecast,
                    sigma,
                    z,
                });
            } else if z <= -p.z && forecast > sigma_floor {
                // A drop only matters when the forecast expected meaningful traffic.
                hits.push(Hit {
                    kind: HitKind::Drop,
                    bin: t,
                    actual: y,
                    forecast,
                    sigma,
                    z,
                });
            }
            // Two-sided CUSUM on the standardized residual (clamped so one huge bin can't overflow).
            let sz = z.clamp(-1e6, 1e6);
            cusum_hi = (cusum_hi + sz - p.cusum_k).max(0.0);
            cusum_lo = (cusum_lo - sz - p.cusum_k).max(0.0);
            if cusum_hi > p.cusum_h || cusum_lo > p.cusum_h {
                hits.push(Hit {
                    kind: HitKind::LevelShift,
                    bin: t,
                    actual: y,
                    forecast,
                    sigma,
                    z,
                });
                cusum_hi = 0.0;
                cusum_lo = 0.0;
            }
        }

        // Advance the smoother (Holt) and the residual-variance EWMA.
        let prev_level = level;
        level = p.level_alpha * y + (1.0 - p.level_alpha) * (level + trend);
        trend = p.trend_beta * (level - prev_level) + (1.0 - p.trend_beta) * trend;
        var = p.var_gamma * resid * resid + (1.0 - p.var_gamma) * var;
    }
    hits
}

/// Fold a host's hits into a single [`Anomaly`] (one finding per host, aggregating hit kinds — the
/// same one-host-one-finding shape BBL uses). Returns `None` when there were no hits.
fn aggregate(s: &HostSeries, hits: &[Hit], dir: FlowDir) -> Option<Anomaly> {
    if hits.is_empty() {
        return None;
    }
    let word = dir.word();
    // For a sub-series, an infix names what the anomaly is concentrated on: a peer ("to <peer>" /
    // "from <peer>") or a service port ("on port <p>"). Empty for a whole-host series (leaving the
    // wording unchanged). `peer` and `port` are mutually exclusive by construction.
    let dest = match (&s.peer, s.port) {
        (Some(peer), _) => format!(" {} {}", dir.peer_prep(), peer),
        (_, Some(port)) => format!(" on port {port}"),
        _ => String::new(),
    };
    // The worst instance of each kind (largest |z|), for the evidence line.
    let worst = |k: HitKind| -> Option<Hit> {
        hits.iter().filter(|h| h.kind == k).copied().max_by(|a, b| {
            a.z.abs()
                .partial_cmp(&b.z.abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    };

    let bin_ns =
        |bin: usize| -> i64 { (s.start_epoch_sec + bin as i64 * s.bin_secs) * 1_000_000_000 };

    let mut dims: Vec<(String, i32)> = Vec::new();
    let mut attack: Vec<String> = Vec::new();

    if let Some(h) = worst(HitKind::Spike) {
        dims.push((
            format!(
                "forecast: {word} {}{dest} at {} — one-step forecast {} (±{}), {:.0}σ above expected",
                human_bytes(h.actual as u64),
                hhmmss(s.start_epoch_sec + h.bin as i64 * s.bin_secs),
                human_bytes(h.forecast.max(0.0) as u64),
                human_bytes(h.sigma as u64),
                h.z,
            ),
            PTS_FC_SPIKE,
        ));
        // Anomalous volume — Exfiltration (egress) / Network DoS (ingress) context.
        push_unique(&mut attack, dir.attack());
    }
    if let Some(h) = worst(HitKind::LevelShift) {
        dims.push((
            format!(
                "forecast: sustained {word} level shift{dest} near {} — actual {}, forecast {} (CUSUM changepoint)",
                hhmmss(s.start_epoch_sec + h.bin as i64 * s.bin_secs),
                human_bytes(h.actual as u64),
                human_bytes(h.forecast.max(0.0) as u64),
            ),
            PTS_FC_LEVEL_SHIFT,
        ));
        push_unique(&mut attack, dir.attack());
    }
    if let Some(h) = worst(HitKind::Drop) {
        dims.push((
            format!(
                "forecast: {word}{dest} dropped to {} at {} — forecast {} (±{}), {:.0}σ below expected",
                human_bytes(h.actual as u64),
                hhmmss(s.start_epoch_sec + h.bin as i64 * s.bin_secs),
                human_bytes(h.forecast.max(0.0) as u64),
                human_bytes(h.sigma as u64),
                h.z.abs(),
            ),
            PTS_FC_DROP,
        ));
    }

    let scored = score_traffic_anomaly(&dims);
    // A headline built from the single most extreme hit overall.
    let head = hits
        .iter()
        .max_by(|a, b| {
            a.z.abs()
                .partial_cmp(&b.z.abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .copied()
        .expect("hits is non-empty");
    let verb = match head.kind {
        HitKind::Spike => "traffic spike",
        HitKind::Drop => "traffic drop",
        HitKind::LevelShift => "sustained traffic shift",
    };
    let title = format!(
        "{host}: predictive {word} {verb}{dest} — actual {actual} vs forecast {fc} ({z:.0}σ)",
        host = s.host,
        actual = human_bytes(head.actual as u64),
        fc = human_bytes(head.forecast.max(0.0) as u64),
        z = head.z.abs(),
    );

    let (mut first_bin, mut last_bin) = (usize::MAX, 0usize);
    for h in hits {
        first_bin = first_bin.min(h.bin);
        last_bin = last_bin.max(h.bin);
    }

    Some(Anomaly {
        host: s.host.clone(),
        severity: scored.severity,
        score: scored.score,
        title,
        evidence: scored.evidence,
        first_seen_ns: Some(bin_ns(first_bin)),
        last_seen_ns: Some(bin_ns(last_bin) + s.bin_secs * 1_000_000_000),
        attack,
        peer: s.peer.clone(),
        port: s.port,
    })
}

fn push_unique(v: &mut Vec<String>, id: &str) {
    if !v.iter().any(|x| x == id) {
        v.push(id.to_string());
    }
}

/// Compact base-1024 byte rendering for evidence strings (e.g. `5.0 MB`). Local copy — `detect`'s is
/// private; the function is tiny and pure.
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

/// `HH:MM:SS` UTC wall-clock for a Unix second — dep-free (no `chrono`), so the C-free / pure-Rust
/// invariant holds. Negative (pre-epoch) seconds wrap via `rem_euclid`, matching the histogram's
/// floor-division alignment.
fn hhmmss(epoch_sec: i64) -> String {
    let secs_of_day = epoch_sec.rem_euclid(86_400);
    let h = secs_of_day / 3_600;
    let m = (secs_of_day % 3_600) / 60;
    let s = secs_of_day % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> ForecastParams {
        ForecastParams::default()
    }

    /// Build a single-host series with the given per-bin byte values.
    fn series(host: &str, bins: &[u64]) -> HostSeries {
        HostSeries {
            host: host.to_string(),
            start_epoch_sec: 1_700_000_000,
            bin_secs: 1,
            bins: bins.to_vec(),
            peer: None,
            port: None,
        }
    }

    /// A peer-resolved sub-series (host's exchange with one peer) for the given per-bin values.
    fn peer_series(host: &str, peer: &str, bins: &[u64]) -> HostSeries {
        HostSeries {
            peer: Some(peer.to_string()),
            ..series(host, bins)
        }
    }

    /// A port-resolved sub-series (host's egress on one service port) for the given per-bin values.
    fn port_series(host: &str, port: u16, bins: &[u64]) -> HostSeries {
        HostSeries {
            port: Some(port),
            ..series(host, bins)
        }
    }

    fn input(series: Vec<HostSeries>) -> ForecastInput {
        ForecastInput {
            bin_secs: 1,
            series,
            direction: FlowDir::Out,
        }
    }

    fn input_dir(series: Vec<HostSeries>, direction: FlowDir) -> ForecastInput {
        ForecastInput {
            bin_secs: 1,
            series,
            direction,
        }
    }

    #[test]
    fn steady_traffic_raises_nothing() {
        // A flat, high-volume series conforms to its own forecast — silence.
        let s = series("10.0.0.1", &vec![1_000_000u64; 40]);
        let rep = detect_traffic_anomalies(&input(vec![s]), &params());
        assert_eq!(rep.hosts_analyzed, 1);
        assert!(rep.anomalies.is_empty(), "steady traffic must not flag");
    }

    #[test]
    fn ingress_direction_labels_evidence_inbound() {
        // The same spike series, tagged as ingress, must read "inbound" (never "outbound") and carry
        // the Network-DoS ATT&CK context.
        let mut bins = vec![1_000_000u64; 30];
        bins[20] = 40_000_000;
        let rep = detect_traffic_anomalies(
            &input_dir(vec![series("10.0.0.3", &bins)], FlowDir::In),
            &params(),
        );
        assert_eq!(rep.anomalies.len(), 1);
        let a = &rep.anomalies[0];
        assert!(
            a.evidence.iter().any(|e| e.contains("inbound")),
            "{:?}",
            a.evidence
        );
        assert!(
            !a.evidence.iter().any(|e| e.contains("outbound")),
            "{:?}",
            a.evidence
        );
        assert!(a.title.contains("inbound"), "{}", a.title);
        assert!(a.attack.iter().any(|t| t == "T1498"), "{:?}", a.attack);
    }

    #[test]
    fn peer_resolved_series_names_the_destination() {
        // A per-peer egress sub-series: the spike must name the peer ("to <peer>") in the evidence
        // and title, and the anomaly must carry the peer so `into_findings` sets `dst_ip`.
        let mut bins = vec![1_000_000u64; 30];
        bins[20] = 40_000_000;
        let rep = detect_traffic_anomalies(
            &input(vec![peer_series("10.0.0.5", "203.0.113.9", &bins)]),
            &params(),
        );
        assert_eq!(rep.anomalies.len(), 1);
        let a = &rep.anomalies[0];
        assert_eq!(a.peer.as_deref(), Some("203.0.113.9"));
        assert!(
            a.evidence.iter().any(|e| e.contains("to 203.0.113.9")),
            "evidence names the peer: {:?}",
            a.evidence
        );
        assert!(
            a.title.contains("to 203.0.113.9"),
            "title names the peer: {}",
            a.title
        );
        // The peer rides into the finding's dst_ip (host-shape signal → no dst_port).
        let findings = ForecastReport {
            anomalies: vec![a.clone()],
            hosts_analyzed: 1,
        }
        .into_findings();
        let f = &findings[0];
        assert_eq!(f.src_ip, "10.0.0.5");
        assert_eq!(f.dst_ip.as_deref(), Some("203.0.113.9"));
        assert!(f.dst_port.is_none());
    }

    #[test]
    fn ingress_peer_series_says_from_the_source() {
        // In + peer: the sub-series infix preposition flips to "from" (the flood *source*), not "to".
        let mut bins = vec![1_000_000u64; 30];
        bins[20] = 40_000_000;
        let rep = detect_traffic_anomalies(
            &input_dir(vec![peer_series("10.0.0.9", "8.8.8.8", &bins)], FlowDir::In),
            &params(),
        );
        assert_eq!(rep.anomalies.len(), 1);
        let a = &rep.anomalies[0];
        assert_eq!(a.peer.as_deref(), Some("8.8.8.8"));
        assert!(
            a.evidence.iter().any(|e| e.contains("from 8.8.8.8")),
            "{:?}",
            a.evidence
        );
        assert!(
            a.evidence.iter().any(|e| e.contains("inbound")),
            "{:?}",
            a.evidence
        );
        assert!(
            !a.evidence.iter().any(|e| e.contains("to 8.8.8.8")),
            "{:?}",
            a.evidence
        );
    }

    #[test]
    fn port_resolved_series_names_the_service_port() {
        // A per-port egress sub-series: the spike must name the port ("on port 4444") in the
        // evidence and title, and the anomaly must carry the port so `into_findings` sets `dst_port`
        // (and leaves `dst_ip` unset — the signal is port-tied, not peer-tied).
        let mut bins = vec![1_000_000u64; 30];
        bins[20] = 40_000_000;
        let rep = detect_traffic_anomalies(
            &input(vec![port_series("10.0.0.5", 4444, &bins)]),
            &params(),
        );
        assert_eq!(rep.anomalies.len(), 1);
        let a = &rep.anomalies[0];
        assert_eq!(a.port, Some(4444));
        assert!(
            a.evidence.iter().any(|e| e.contains("on port 4444")),
            "evidence names the port: {:?}",
            a.evidence
        );
        assert!(
            a.title.contains("on port 4444"),
            "title names the port: {}",
            a.title
        );
        let findings = ForecastReport {
            anomalies: vec![a.clone()],
            hosts_analyzed: 1,
        }
        .into_findings();
        let f = &findings[0];
        assert_eq!(f.src_ip, "10.0.0.5");
        assert_eq!(f.dst_port, Some(4444));
        assert!(f.dst_ip.is_none());
    }

    #[test]
    fn slow_linear_growth_is_not_an_anomaly() {
        // Holt's trend term should track a steady ramp without flagging every bin.
        let bins: Vec<u64> = (0..40).map(|i| 1_000_000 + i * 50_000).collect();
        let rep = detect_traffic_anomalies(&input(vec![series("10.0.0.2", &bins)]), &params());
        assert!(
            rep.anomalies.is_empty(),
            "a smooth linear ramp should be forecast, not flagged: {:?}",
            rep.anomalies
        );
    }

    #[test]
    fn sudden_spike_is_flagged() {
        // Flat, then one bin 40x higher — a clear point anomaly.
        let mut bins = vec![1_000_000u64; 30];
        bins[20] = 40_000_000;
        let rep = detect_traffic_anomalies(&input(vec![series("10.0.0.3", &bins)]), &params());
        assert_eq!(
            rep.anomalies.len(),
            1,
            "the spike must raise exactly one host finding"
        );
        let a = &rep.anomalies[0];
        assert_eq!(a.host, "10.0.0.3");
        assert!(a.severity >= Severity::Low);
        assert!(
            a.evidence.iter().any(|e| e.contains("above expected")),
            "{:?}",
            a.evidence
        );
        assert!(a.attack.iter().any(|t| t == "T1048"));
    }

    #[test]
    fn drop_to_silence_is_flagged() {
        // Steady traffic then the host goes dark for several bins.
        let mut bins = vec![2_000_000u64; 30];
        for b in bins.iter_mut().skip(20) {
            *b = 0;
        }
        let rep = detect_traffic_anomalies(&input(vec![series("10.0.0.4", &bins)]), &params());
        assert_eq!(rep.anomalies.len(), 1, "the drop must raise a finding");
        let a = &rep.anomalies[0];
        assert!(
            a.evidence
                .iter()
                .any(|e| e.contains("below expected") || e.contains("level shift")),
            "{:?}",
            a.evidence
        );
    }

    #[test]
    fn sustained_level_shift_is_flagged() {
        // A durable step up (not a single blip) should trip the CUSUM changepoint.
        let mut bins = vec![1_000_000u64; 40];
        for b in bins.iter_mut().skip(20) {
            *b = 5_000_000;
        }
        let rep = detect_traffic_anomalies(&input(vec![series("10.0.0.5", &bins)]), &params());
        assert_eq!(rep.anomalies.len(), 1);
        let a = &rep.anomalies[0];
        assert!(a.first_seen_ns.is_some() && a.last_seen_ns.is_some());
    }

    #[test]
    fn warmup_short_series_stays_silent() {
        // Fewer than `min_bins` bins: no reliable forecast, so no finding even with a big jump.
        let bins = vec![1_000_000, 1_000_000, 50_000_000];
        let rep = detect_traffic_anomalies(&input(vec![series("10.0.0.6", &bins)]), &params());
        assert!(
            rep.anomalies.is_empty(),
            "too-short series must not flag (warm-up)"
        );
    }

    #[test]
    fn trivial_host_is_ignored() {
        // A host whose peak bin is below `min_bin_bytes` is not modelled at all.
        let bins = vec![10u64; 40];
        let rep = detect_traffic_anomalies(&input(vec![series("10.0.0.7", &bins)]), &params());
        assert_eq!(rep.hosts_analyzed, 0);
        assert!(rep.anomalies.is_empty());
    }

    #[test]
    fn disabled_is_a_noop() {
        let mut bins = vec![1_000_000u64; 30];
        bins[20] = 40_000_000;
        let p = ForecastParams {
            enabled: false,
            ..Default::default()
        };
        let rep = detect_traffic_anomalies(&input(vec![series("10.0.0.8", &bins)]), &p);
        assert!(rep.anomalies.is_empty() && rep.hosts_analyzed == 0);
    }

    #[test]
    fn output_is_deterministic_and_worst_first() {
        // Two anomalous hosts of differing magnitude; the worse must sort first, regardless of input
        // order, and the run must be byte-reproducible.
        let mut big = vec![1_000_000u64; 30];
        big[20] = 80_000_000;
        let mut small = vec![1_000_000u64; 30];
        small[20] = 20_000_000;
        let a = detect_traffic_anomalies(
            &input(vec![series("10.0.0.20", &small), series("10.0.0.10", &big)]),
            &params(),
        );
        let b = detect_traffic_anomalies(
            &input(vec![series("10.0.0.10", &big), series("10.0.0.20", &small)]),
            &params(),
        );
        assert_eq!(
            a.anomalies, b.anomalies,
            "order-independent, deterministic output"
        );
        assert_eq!(a.anomalies.len(), 2);
        assert!(a.anomalies[0].score >= a.anomalies[1].score, "worst-first");
        assert_eq!(a.anomalies[0].host, "10.0.0.10");
    }

    #[test]
    fn anomaly_caps_at_medium_alone() {
        // Even a huge multi-kind anomaly is capped so behaviour-alone never reaches High.
        let mut bins = vec![1_000_000u64; 40];
        bins[20] = 200_000_000;
        for b in bins.iter_mut().skip(25) {
            *b = 9_000_000;
        }
        let rep = detect_traffic_anomalies(&input(vec![series("10.0.0.9", &bins)]), &params());
        assert_eq!(rep.anomalies.len(), 1);
        assert!(
            rep.anomalies[0].severity <= Severity::Medium,
            "an anomaly alone must not exceed Medium (corroboration escalates, not points)"
        );
    }

    #[test]
    fn into_findings_maps_fields() {
        let mut bins = vec![1_000_000u64; 30];
        bins[20] = 40_000_000;
        let rep = detect_traffic_anomalies(&input(vec![series("10.0.0.30", &bins)]), &params());
        let findings = rep.into_findings();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::TrafficAnomaly);
        assert_eq!(f.src_ip, "10.0.0.30");
        assert!(f.dst_ip.is_none());
        assert!(f.first_seen_ns.is_some());
        assert!(!f.evidence.is_empty());
    }

    #[test]
    fn forecast_next_needs_three_points() {
        assert!(forecast_next(&[], &params()).is_none());
        assert!(forecast_next(&[1.0], &params()).is_none());
        assert!(forecast_next(&[1.0, 2.0], &params()).is_none());
        assert!(forecast_next(&[1.0, 2.0, 3.0], &params()).is_some());
    }

    #[test]
    fn forecast_next_projects_a_rising_trend() {
        // A steady linear ramp: the one-step-ahead forecast should extrapolate the trend, landing
        // near the next value (well within a few σ) rather than at the lagging mean.
        let values: Vec<f64> = (0..12)
            .map(|i| 1_000_000.0 + i as f64 * 100_000.0)
            .collect();
        let fc = forecast_next(&values, &params()).unwrap();
        let next_on_trend = 12.0 * 100_000.0 + 1_000_000.0; // 2.2M
        assert!(
            (fc.forecast - next_on_trend).abs() < 5.0 * fc.sigma.max(1.0),
            "forecast {} should track the trend toward {next_on_trend} (σ={})",
            fc.forecast,
            fc.sigma
        );
        // The trend forecast must sit far above the series mean (which a static gate would use).
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        assert!(
            fc.forecast > mean,
            "trend forecast {} > mean {mean}",
            fc.forecast
        );
    }

    #[test]
    fn forecast_next_is_deterministic() {
        let v = [1.0, 3.0, 2.0, 5.0, 4.0, 6.0, 8.0, 7.0];
        assert_eq!(forecast_next(&v, &params()), forecast_next(&v, &params()));
    }

    #[test]
    fn hhmmss_formats_utc() {
        assert_eq!(hhmmss(0), "00:00:00");
        assert_eq!(hhmmss(3_661), "01:01:01");
        // 2023-11-14T22:13:20Z
        assert_eq!(hhmmss(1_700_000_000), "22:13:20");
    }
}
