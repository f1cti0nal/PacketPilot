// Client-side traffic forecaster — a faithful TypeScript port of the engine's Predictive Anomaly
// Detection math (`engine/crates/ppcap-core/src/forecast/mod.rs`, documented in
// `docs/predictive-anomaly-detection-plan.md` §3), used purely to *draw* a forecast band over the
// timeline chart. It mirrors the engine's Holt double-exponential smoother (level + trend) with a
// prediction band from an EWMA of the forecast residuals and a scale-relative σ floor.
//
// Note on scope: the engine forecasts each internal host's *egress* series; this overlay runs the
// same recurrence over the capture-wide `time_histogram` (total bytes per bin) the UI already has,
// so the band is the "expected total-traffic envelope". Bins the engine actually flagged (per-host)
// are marked separately from the finding set — the band is context, not the detector.

/** Tunables mirroring `ForecastParams::default()` in the engine (only the band-relevant ones). */
export interface ForecastBandParams {
  /** Holt level smoothing α (0 < α ≤ 1). */
  levelAlpha: number;
  /** Holt trend smoothing β (0 ≤ β ≤ 1). */
  trendBeta: number;
  /** Residual-variance EWMA smoothing γ (0 < γ ≤ 1). */
  varGamma: number;
  /** Prediction-band half-width in residual σ. */
  z: number;
  /** σ floor as a fraction of the series mean (so a big-mean series ignores small wobbles). */
  sigmaFloorFrac: number;
}

export const DEFAULT_FORECAST_BAND: ForecastBandParams = {
  levelAlpha: 0.4,
  trendBeta: 0.2,
  varGamma: 0.3,
  z: 4.0,
  sigmaFloorFrac: 0.15,
};

/** Per-bin one-step-ahead forecast and its `forecast ± z·σ` prediction band (all length `n`). */
export interface ForecastBand {
  forecast: number[];
  upper: number[];
  lower: number[];
}

/**
 * Run the online Holt forecaster over `values` (one per time bin, in order) and return the per-bin
 * forecast and prediction band. Pure and deterministic; `O(n)` time, `O(1)` state — the same
 * recurrence the engine uses. `values` should be contiguous (the caller aligns it to the chart's
 * visible buckets); bins below zero are clamped out of the band.
 */
export function forecastBand(
  values: number[],
  params: ForecastBandParams = DEFAULT_FORECAST_BAND,
): ForecastBand {
  const n = values.length;
  const forecast = new Array<number>(n).fill(0);
  const upper = new Array<number>(n).fill(0);
  const lower = new Array<number>(n).fill(0);
  if (n === 0) return { forecast, upper, lower };

  const mean = values.reduce((a, b) => a + b, 0) / n;
  const sigmaFloor = Math.max(params.sigmaFloorFrac * mean, 1);

  // Seed level/trend from the first two bins; bin 0 has no forecast, so pin its band to the actual.
  let level = values[0];
  let trend = n > 1 ? values[1] - values[0] : 0;
  let variance = 0; // EWMA of squared forecast residuals
  forecast[0] = values[0];
  upper[0] = values[0];
  lower[0] = values[0];

  for (let t = 1; t < n; t++) {
    const y = values[t];
    const f = level + trend;
    const sigma = Math.max(Math.sqrt(variance), sigmaFloor);
    forecast[t] = Math.max(0, f);
    upper[t] = Math.max(0, f + params.z * sigma);
    lower[t] = Math.max(0, f - params.z * sigma);

    const resid = y - f;
    const prevLevel = level;
    level = params.levelAlpha * y + (1 - params.levelAlpha) * (level + trend);
    trend = params.trendBeta * (level - prevLevel) + (1 - params.trendBeta) * trend;
    variance = params.varGamma * resid * resid + (1 - params.varGamma) * variance;
  }

  return { forecast, upper, lower };
}

/** True when `value` breaches its band (outside `[lower, upper]`) — a bin the forecaster would flag. */
export function breachesBand(value: number, band: ForecastBand, i: number): boolean {
  return value > band.upper[i] || value < band.lower[i];
}
