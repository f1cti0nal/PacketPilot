// ActivityHeatmap — full-bleed timeline ribbon. One cyan-opacity cell per time
// bucket (log-scaled by bytes); the brightest column is the exfil burst, marked
// critical. Hover a cell for its timestamp / packet / byte readout.
import { useMemo, useState } from "react";
import { cn } from "../lib/cn";
import { forecastBand } from "../lib/forecast";
import { humanBytes, humanNumber, nsToDateTime, nsToTime, durationHumanNs } from "../lib/format";
import { Card } from "./primitives";
import type { Finding, TimeHistogramEntry } from "../types";

interface ActivityHeatmapProps {
  histogram: TimeHistogramEntry[];
  bucketSecs?: number;
  findings?: Finding[];
  className?: string;
}

export function ActivityHeatmap({ histogram, bucketSecs, findings, className }: ActivityHeatmapProps): JSX.Element {
  const [hovered, setHovered] = useState<number | null>(null);

  // The peak is only an "exfil burst" if a data-exfil finding corroborates it;
  // otherwise it is simply the busiest bucket. Never claim threat from volume.
  const hasExfil = (findings ?? []).some((f) => f.kind === "data_exfil");
  const markerColor = hasExfil ? "var(--color-sev-critical)" : "var(--color-accent)";
  const markerLabel = hasExfil ? "exfil burst" : "peak volume";

  const { cells, peakIndex, first, last, unit } = useMemo(() => {
    const maxBytes = histogram.reduce((m, b) => Math.max(m, b.bytes), 0);
    const denom = Math.log1p(maxBytes) || 1;
    let peak = -1;
    let peakBytes = -1;
    const out = histogram.map((b, i) => {
      // Log-normalize bytes into [0.06, 1] so quiet buckets stay faintly visible.
      const norm = maxBytes > 0 ? Math.log1p(b.bytes) / denom : 0;
      const t = 0.06 + norm * 0.94;
      if (b.bytes > peakBytes) {
        peakBytes = b.bytes;
        peak = i;
      }
      return { entry: b, t };
    });
    const secs = bucketSecs && bucketSecs > 0 ? bucketSecs : 1;
    return {
      cells: out,
      peakIndex: peakBytes > 0 ? peak : -1,
      first: histogram.length ? histogram[0].epoch_sec : 0,
      last: histogram.length ? histogram[histogram.length - 1].epoch_sec : 0,
      unit: `per ${durationHumanNs(secs * 1e9)}`,
    };
  }, [histogram, bucketSecs]);

  // Forecast-band overlay: the Predictive Anomaly Detection forecaster (same Holt + residual-EWMA
  // band as the engine) run over the visible byte series, so the analyst sees the "expected traffic
  // envelope" behind the actual line, with the bins the engine flagged (`traffic_anomaly` findings)
  // marked. The band is capture-wide context; the markers are the real per-host detections.
  const overlay = useMemo(() => {
    const n = histogram.length;
    if (n < 3) return null; // too few bins for a meaningful forecast
    const values = histogram.map((b) => b.bytes);
    const maxY = values.reduce((m, v) => Math.max(m, v), 0);
    if (maxY <= 0) return null;
    const band = forecastBand(values);

    // Bins covered by a traffic_anomaly finding window (the engine's per-host detections).
    const anomalyBins = new Set<number>();
    for (const f of findings ?? []) {
      if (f.kind !== "traffic_anomaly") continue;
      const lo = f.first_seen_ns;
      const hi = f.last_seen_ns;
      if (lo == null || hi == null) continue;
      for (let i = 0; i < n; i++) {
        const ns = histogram[i].epoch_sec * 1e9;
        if (ns >= lo && ns < hi) anomalyBins.add(i);
      }
    }

    const H = 40;
    const topPad = 3;
    const usable = H - topPad;
    const px = (i: number) => (n === 1 ? 0.5 : i + 0.5);
    const py = (v: number) => H - (Math.min(Math.max(v, 0), maxY) / maxY) * usable;

    const upper = band.upper.map((v, i) => `${px(i)},${py(v)}`);
    const lower = band.lower.map((v, i) => `${px(i)},${py(v)}`).reverse();
    const bandPath = `M${upper.join(" L")} L${lower.join(" L")} Z`;
    const forecastPath = `M${band.forecast.map((v, i) => `${px(i)},${py(v)}`).join(" L")}`;
    const actualPath = `M${values.map((v, i) => `${px(i)},${py(v)}`).join(" L")}`;
    const markers = [...anomalyBins].sort((a, b) => a - b).map((i) => px(i));
    return { n, H, bandPath, forecastPath, actualPath, markers };
  }, [histogram, findings]);

  if (histogram.length === 0) {
    return (
      <Card label="TIMELINE" title="Activity" className={className}>
        <div className="py-6 text-center t-body text-[var(--color-text-faint)]">
          No timeline data
        </div>
      </Card>
    );
  }

  const hov = hovered != null ? cells[hovered] : null;

  return (
    <Card label="TIMELINE" title="Activity" className={className}>
      <div className="relative">
        {/* Forecast-band overlay: expected total-traffic envelope (Holt + residual band) with the
            engine's traffic_anomaly bins marked. Shares the ribbon's even-spaced time axis. */}
        {overlay && (
          <div className="mb-1.5">
            <div className="mb-1 flex items-center gap-3 t-label normal-case tracking-normal text-[var(--color-text-faint)]">
              <span className="flex items-center gap-1.5">
                <span
                  aria-hidden
                  className="inline-block h-2 w-3 rounded-[1px]"
                  style={{ backgroundColor: "color-mix(in srgb, var(--color-accent) 22%, transparent)" }}
                />
                forecast band
              </span>
              <span className="flex items-center gap-1.5">
                <span aria-hidden className="inline-block h-[2px] w-3 rounded-full bg-[var(--color-accent-strong)]" />
                actual bytes
              </span>
              {overlay.markers.length > 0 && (
                <span className="flex items-center gap-1.5">
                  <span aria-hidden className="inline-block h-2.5 w-[2px] rounded-full bg-[var(--color-sev-high)]" />
                  forecast anomaly
                </span>
              )}
            </div>
            <svg
              viewBox={`0 0 ${overlay.n} ${overlay.H}`}
              preserveAspectRatio="none"
              className="block h-[42px] w-full overflow-visible"
              role="img"
              aria-label={
                "Traffic forecast band — expected total-traffic envelope with actual bytes" +
                (overlay.markers.length > 0
                  ? `; ${overlay.markers.length} bin${overlay.markers.length === 1 ? "" : "s"} flagged as a traffic anomaly`
                  : "")
              }
            >
              <path d={overlay.bandPath} fill="var(--color-accent)" fillOpacity={0.16} stroke="none" />
              <path
                d={overlay.forecastPath}
                fill="none"
                stroke="var(--color-accent)"
                strokeOpacity={0.55}
                strokeWidth={1}
                strokeDasharray="3 2"
                vectorEffect="non-scaling-stroke"
              />
              <path
                d={overlay.actualPath}
                fill="none"
                stroke="var(--color-accent-strong)"
                strokeWidth={1.25}
                strokeLinejoin="round"
                vectorEffect="non-scaling-stroke"
              />
              {overlay.markers.map((mx, k) => (
                <line
                  key={k}
                  x1={mx}
                  y1={0}
                  x2={mx}
                  y2={overlay.H}
                  stroke="var(--color-sev-high)"
                  strokeOpacity={0.55}
                  strokeWidth={1}
                  vectorEffect="non-scaling-stroke"
                />
              ))}
            </svg>
          </div>
        )}

        {/* Ribbon */}
        <div
          className="flex gap-px"
          onMouseLeave={() => setHovered(null)}
          role="img"
          aria-label={
            `Activity ${unit}, ${nsToDateTime(first * 1e9)} to ${nsToDateTime(last * 1e9)}` +
            (peakIndex >= 0
              ? `; ${markerLabel} at ${nsToTime(cells[peakIndex].entry.epoch_sec * 1e9)}, ${humanBytes(cells[peakIndex].entry.bytes)}`
              : "")
          }
        >
          {cells.map((c, i) => {
            const isPeak = i === peakIndex;
            return (
              <div key={i} className="relative flex-1" onMouseEnter={() => setHovered(i)}>
                {isPeak && (
                  <>
                    <div
                      aria-hidden
                      className="absolute -top-[5px] left-0 right-0 h-[2px] rounded-full"
                      style={{ backgroundColor: markerColor }}
                    />
                    <div
                      aria-hidden
                      className="absolute -top-[3px] left-1/2 h-0 w-0 -translate-x-1/2"
                      style={{
                        borderLeft: "3px solid transparent",
                        borderRight: "3px solid transparent",
                        borderTop: `3px solid ${markerColor}`,
                      }}
                    />
                  </>
                )}
                <div
                  className={cn(
                    "h-[30px] rounded-[var(--r-micro)] transition-[outline] duration-100",
                    hovered === i && "outline outline-1 outline-[var(--color-accent-strong)]",
                  )}
                  style={{
                    backgroundColor: `color-mix(in srgb, var(--color-accent) ${Math.round(c.t * 100)}%, var(--color-surface-2))`,
                  }}
                />
              </div>
            );
          })}
        </div>

        {/* Tooltip */}
        {hov && (
          <div
            className="pointer-events-none absolute -top-[6px] z-10 -translate-y-full rounded-[var(--r-tile)] border border-[var(--color-border-strong)] bg-[var(--color-surface-3)] px-2.5 py-1.5 shadow-[var(--sh-float)]"
            style={{
              left: `${((hovered! + 0.5) / cells.length) * 100}%`,
              transform: "translate(-50%, -100%)",
            }}
          >
            <div className="font-mono-num text-[12px] text-[var(--color-text)]">
              {nsToTime(hov.entry.epoch_sec * 1e9)}
              <span className="ml-1.5 t-tag text-[var(--color-text-faint)]">{unit}</span>
            </div>
            <div className="mt-0.5 flex items-center gap-2 whitespace-nowrap t-tag text-[var(--color-text-dim)]">
              <span className="font-mono-num">{humanNumber(hov.entry.pkts)}</span> pkts
              <span className="text-[var(--color-text-faint)]">·</span>
              <span className="font-mono-num">{humanBytes(hov.entry.bytes)}</span>
            </div>
          </div>
        )}

        {/* Axis */}
        <div className="mt-2 flex items-center justify-between gap-3">
          <span className="font-mono-num t-label">{nsToDateTime(first * 1e9)}</span>
          <span className="t-label flex items-center gap-1.5 normal-case tracking-normal">
            <span
              aria-hidden
              className="inline-block h-1.5 w-1.5 rounded-full"
              style={{ backgroundColor: markerColor }}
            />
            bright column = {markerLabel}
          </span>
          <span className="font-mono-num t-label">{nsToDateTime(last * 1e9)}</span>
        </div>
      </div>
    </Card>
  );
}

export default ActivityHeatmap;
