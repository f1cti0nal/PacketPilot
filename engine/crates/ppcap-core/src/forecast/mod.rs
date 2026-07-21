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
}

/// The per-host series to forecast plus the shared bin width. Deterministically ordered (hosts
/// sorted, bins ascending in time) by the builder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ForecastInput {
    pub bin_secs: i64,
    pub series: Vec<HostSeries>,
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
    /// the summary alongside the other detectors. `src_ip` is the deviating host; the anomaly is a
    /// host-egress-shape signal, so `dst_ip`/`dst_port` are `None`.
    pub fn into_findings(self) -> Vec<Finding> {
        self.anomalies
            .into_iter()
            .map(|a| Finding {
                kind: FindingKind::TrafficAnomaly,
                severity: a.severity,
                score: a.score,
                title: a.title,
                src_ip: a.host,
                dst_ip: None,
                dst_port: None,
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
        if let Some(anomaly) = aggregate(s, &hits) {
            report.anomalies.push(anomaly);
        }
    }
    // Worst-first, with a total-order tie-break so the emitted order is deterministic.
    report.anomalies.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| b.severity.cmp(&a.severity))
            .then_with(|| a.host.cmp(&b.host))
    });
    report.anomalies.truncate(p.max_findings);
    report
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
fn aggregate(s: &HostSeries, hits: &[Hit]) -> Option<Anomaly> {
    if hits.is_empty() {
        return None;
    }
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
                "forecast: outbound {} at {} — one-step forecast {} (±{}), {:.0}σ above expected",
                human_bytes(h.actual as u64),
                hhmmss(s.start_epoch_sec + h.bin as i64 * s.bin_secs),
                human_bytes(h.forecast.max(0.0) as u64),
                human_bytes(h.sigma as u64),
                h.z,
            ),
            PTS_FC_SPIKE,
        ));
        // Anomalous outbound volume — Exfiltration Over Alternative Protocol (context).
        push_unique(&mut attack, "T1048");
    }
    if let Some(h) = worst(HitKind::LevelShift) {
        dims.push((
            format!(
                "forecast: sustained level shift near {} — actual {}, forecast {} (CUSUM changepoint)",
                hhmmss(s.start_epoch_sec + h.bin as i64 * s.bin_secs),
                human_bytes(h.actual as u64),
                human_bytes(h.forecast.max(0.0) as u64),
            ),
            PTS_FC_LEVEL_SHIFT,
        ));
        push_unique(&mut attack, "T1048");
    }
    if let Some(h) = worst(HitKind::Drop) {
        dims.push((
            format!(
                "forecast: outbound dropped to {} at {} — forecast {} (±{}), {:.0}σ below expected",
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
        "{host}: predictive {verb} — actual {actual} vs forecast {fc} ({z:.0}σ)",
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
        }
    }

    fn input(series: Vec<HostSeries>) -> ForecastInput {
        ForecastInput {
            bin_secs: 1,
            series,
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
    fn hhmmss_formats_utc() {
        assert_eq!(hhmmss(0), "00:00:00");
        assert_eq!(hhmmss(3_661), "01:01:01");
        // 2023-11-14T22:13:20Z
        assert_eq!(hhmmss(1_700_000_000), "22:13:20");
    }
}
