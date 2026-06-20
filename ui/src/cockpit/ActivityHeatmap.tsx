// ActivityHeatmap — full-bleed timeline ribbon. One cyan-opacity cell per time
// bucket (log-scaled by bytes); the brightest column is the exfil burst, marked
// critical. Hover a cell for its timestamp / packet / byte readout.
import { useMemo, useState } from "react";
import { cn } from "../lib/cn";
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

  if (histogram.length === 0) {
    return (
      <Card label="TIMELINE" title="Activity" className={className}>
        <div className="flex h-[30px] items-center justify-center rounded-[var(--r-micro)] bg-[var(--color-surface-2)] t-label">
          No timeline data
        </div>
      </Card>
    );
  }

  const hov = hovered != null ? cells[hovered] : null;

  return (
    <Card label="TIMELINE" title="Activity" className={className}>
      <div className="relative">
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
