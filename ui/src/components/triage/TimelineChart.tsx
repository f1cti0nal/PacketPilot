import { useMemo } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  type TooltipProps,
} from "recharts";
import { Activity } from "lucide-react";
import type { TimeHistogramEntry } from "../../types";
import {
  compactNumber,
  humanBytes,
  humanNumber,
  nsToTime,
} from "../../lib/format";

export interface TimelineChartProps {
  histogram: TimeHistogramEntry[];
  metric?: "pkts" | "bytes"; // default "pkts"
}

interface ChartDatum {
  epoch_sec: number;
  pkts: number;
  bytes: number;
  value: number;
}

const ACCENT = "var(--color-accent)";

/** epoch_sec (whole seconds) -> UTC HH:MM:SS via the shared ns helper. */
const fmtTime = (epochSec: number): string => nsToTime(epochSec * 1e9);

function CustomTooltip({
  active,
  payload,
}: TooltipProps<number, string>): JSX.Element | null {
  if (!active || !payload || payload.length === 0) return null;
  const datum = payload[0]?.payload as ChartDatum | undefined;
  if (!datum) return null;
  return (
    <div className="rounded-md border border-border bg-surface-2 px-3 py-2 text-xs shadow-lg">
      <div className="mb-1 font-mono-num text-[var(--color-text)]">
        {fmtTime(datum.epoch_sec)}
      </div>
      <div className="flex items-center justify-between gap-4">
        <span className="text-[var(--color-text-dim)]">Packets/s</span>
        <span className="font-mono-num text-[var(--color-text)]">
          {humanNumber(datum.pkts)}
        </span>
      </div>
      <div className="flex items-center justify-between gap-4">
        <span className="text-[var(--color-text-dim)]">Bytes/s</span>
        <span className="font-mono-num text-[var(--color-text)]">
          {humanBytes(datum.bytes)}
        </span>
      </div>
    </div>
  );
}

export function TimelineChart({
  histogram,
  metric = "pkts",
}: TimelineChartProps): JSX.Element {
  const data = useMemo<ChartDatum[]>(
    () =>
      histogram.map((h) => ({
        epoch_sec: h.epoch_sec,
        pkts: h.pkts,
        bytes: h.bytes,
        value: metric === "bytes" ? h.bytes : h.pkts,
      })),
    [histogram, metric],
  );

  const yTickFormatter = useMemo(
    () =>
      metric === "bytes"
        ? (v: number) => humanBytes(v)
        : (v: number) => compactNumber(v),
    [metric],
  );

  if (data.length === 0) {
    return (
      <div
        data-component="TimelineChart"
        className="flex h-full min-h-[12rem] flex-col items-center justify-center gap-2 text-[var(--color-text-faint)]"
      >
        <Activity size={20} aria-hidden />
        <span className="text-sm">No timeline data</span>
      </div>
    );
  }

  return (
    <div
      data-component="TimelineChart"
      className="h-full min-h-[12rem] w-full text-[var(--color-text-dim)]"
    >
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart
          data={data}
          margin={{ top: 8, right: 12, bottom: 4, left: 4 }}
        >
          <defs>
            <linearGradient id="timeline-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={ACCENT} stopOpacity={0.35} />
              <stop offset="100%" stopColor={ACCENT} stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid
            stroke="var(--color-grid)"
            strokeDasharray="3 3"
            vertical={false}
          />
          <XAxis
            dataKey="epoch_sec"
            tickFormatter={fmtTime}
            tick={{ fill: "var(--color-text-faint)", fontSize: 11 }}
            stroke="var(--color-border)"
            minTickGap={48}
            tickMargin={8}
          />
          <YAxis
            width={56}
            tickFormatter={yTickFormatter}
            tick={{ fill: "var(--color-text-faint)", fontSize: 11 }}
            stroke="var(--color-border)"
            tickMargin={4}
          />
          <Tooltip
            content={<CustomTooltip />}
            cursor={{ stroke: ACCENT, strokeWidth: 1, strokeOpacity: 0.4 }}
          />
          <Area
            type="monotone"
            dataKey="value"
            name={metric === "bytes" ? "Bytes/s" : "Packets/s"}
            stroke={ACCENT}
            strokeWidth={1.75}
            fill="url(#timeline-fill)"
            isAnimationActive={false}
            dot={false}
            activeDot={{ r: 3, fill: ACCENT, stroke: "var(--color-bg)" }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

export default TimelineChart;
