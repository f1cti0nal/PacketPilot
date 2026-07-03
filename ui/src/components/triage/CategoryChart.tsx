import { useMemo } from "react";
import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  type TooltipProps,
} from "recharts";
import { BarChart3 } from "lucide-react";
import type { CategoryBreakdownEntry, Severity } from "../../types";
import {
  normCategory,
  severityForCategory,
  SEVERITY_META,
} from "../../lib/severity";
import { compactNumber, humanBytes, humanNumber } from "../../lib/format";

export interface CategoryChartProps {
  breakdown: CategoryBreakdownEntry[];
  metric?: "flows" | "pkts" | "bytes"; // default "flows"
  onBarClick?: (category: string) => void;
}

interface ChartDatum {
  category: string; // normalized snake-case token
  label: string; // human-readable axis label
  severity: Severity;
  color: string; // resolved CSS color for this severity
  flows: number;
  pkts: number;
  bytes: number;
  value: number; // the active metric, used for bar length + sort
}

const METRIC_LABEL: Record<NonNullable<CategoryChartProps["metric"]>, string> = {
  flows: "Flows",
  pkts: "Packets",
  bytes: "Bytes",
};

/** Pretty axis label from a normalized snake-case category token. */
function prettyCategory(token: string): string {
  return token
    .split("_")
    .map((w) => (w ? w[0].toUpperCase() + w.slice(1) : w))
    .join(" ");
}

/** Resolve a severity CSS custom property to a concrete color string. */
function severityColor(severity: Severity): string {
  const cssVar = SEVERITY_META[severity].cssVar;
  if (typeof window !== "undefined") {
    const resolved = getComputedStyle(document.documentElement)
      .getPropertyValue(cssVar)
      .trim();
    if (resolved) return resolved;
  }
  return `var(${cssVar})`;
}

function CategoryTooltip({
  active,
  payload,
}: TooltipProps<number, string>): JSX.Element | null {
  if (!active || !payload || payload.length === 0) return null;
  const datum = payload[0]?.payload as ChartDatum | undefined;
  if (!datum) return null;
  const meta = SEVERITY_META[datum.severity];
  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2 text-xs">
      <div className="mb-1 flex items-center gap-2">
        <span
          className="inline-block h-2.5 w-2.5 rounded-sm"
          style={{ backgroundColor: datum.color }}
        />
        <span className="font-medium text-[var(--color-text)]">
          {datum.label}
        </span>
        <span className="text-[var(--color-text-faint)]">{meta.label}</span>
      </div>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-[var(--color-text-dim)]">
        <dt>Flows</dt>
        <dd className="text-right font-mono-num text-[var(--color-text)]">
          {humanNumber(datum.flows)}
        </dd>
        <dt>Packets</dt>
        <dd className="text-right font-mono-num text-[var(--color-text)]">
          {humanNumber(datum.pkts)}
        </dd>
        <dt>Bytes</dt>
        <dd className="text-right font-mono-num text-[var(--color-text)]">
          {humanBytes(datum.bytes)}
        </dd>
      </dl>
    </div>
  );
}

export function CategoryChart({
  breakdown,
  metric = "flows",
  onBarClick,
}: CategoryChartProps) {
  const data = useMemo<ChartDatum[]>(() => {
    return breakdown
      .filter((e) => e.flows > 0)
      .map((e): ChartDatum => {
        const token = normCategory(e.category);
        const severity = severityForCategory(e.category);
        return {
          category: token,
          label: prettyCategory(token),
          severity,
          color: severityColor(severity),
          flows: e.flows,
          pkts: e.pkts,
          bytes: e.bytes,
          value: e[metric],
        };
      })
      .sort((a, b) => b.value - a.value);
  }, [breakdown, metric]);

  if (data.length === 0) {
    return (
      <div
        data-component="CategoryChart"
        className="flex h-full min-h-40 flex-col items-center justify-center gap-2 text-[var(--color-text-faint)]"
      >
        <BarChart3 className="h-6 w-6" aria-hidden />
        <span className="text-sm">No categorized flows</span>
      </div>
    );
  }

  // Roughly 36px per row plus axis padding keeps bars readable for any count.
  const height = Math.max(160, data.length * 36 + 24);
  const clickable = typeof onBarClick === "function";

  return (
    <div data-component="CategoryChart" className="w-full" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          layout="vertical"
          data={data}
          margin={{ top: 4, right: 16, bottom: 4, left: 8 }}
          barCategoryGap="25%"
        >
          <XAxis
            type="number"
            tickFormatter={(v: number) => compactNumber(v)}
            stroke="var(--color-border)"
            tick={{ fill: "var(--color-text-faint)", fontSize: 11 }}
            tickLine={false}
            axisLine={{ stroke: "var(--color-border)" }}
          />
          <YAxis
            type="category"
            dataKey="label"
            width={96}
            stroke="var(--color-border)"
            tick={{ fill: "var(--color-text-dim)", fontSize: 12 }}
            tickLine={false}
            axisLine={false}
          />
          <Tooltip
            content={<CategoryTooltip />}
            cursor={{ fill: "var(--color-surface-2)", opacity: 0.4 }}
          />
          <Bar
            dataKey="value"
            name={METRIC_LABEL[metric]}
            radius={[0, 3, 3, 0]}
            isAnimationActive={false}
            onClick={
              clickable
                ? (entry: ChartDatum) => onBarClick?.(entry.category)
                : undefined
            }
            cursor={clickable ? "pointer" : "default"}
          >
            {data.map((d) => (
              <Cell key={d.category} fill={d.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export default CategoryChart;
