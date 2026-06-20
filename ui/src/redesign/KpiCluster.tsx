// Zone 1 — instrument-cluster KPI band. Hairline-divided cells (one continuous
// gauge cluster, not separate cards). The rightmost cells carry the VERDICT:
// the incident counter (not the misleading per-flow strip) + a calm context ring.
import { useMemo, type ReactNode } from "react";
import { AlertOctagon } from "lucide-react";
import { compactNumber, durationHumanNs, humanBytes, humanNumber } from "../lib/format";
import { SEVERITY_ORDER } from "../lib/severity";
import type { AnalysisOutput, Severity } from "../types";
import { Sparkline } from "./primitives";
import { SeverityRing } from "./instruments";

/** Even-stride downsample so sparklines stay crisp regardless of bucket count. */
function sample(arr: number[], n: number): number[] {
  if (arr.length <= n) return arr;
  const out: number[] = [];
  const step = arr.length / n;
  for (let i = 0; i < n; i++) out.push(arr[Math.floor(i * step)]);
  return out;
}

export function KpiCluster({ output }: { output: AnalysisOutput }) {
  const s = output.summary;
  const { pkts, bytes } = useMemo(() => {
    const h = s.time_histogram ?? [];
    return { pkts: sample(h.map((e) => e.pkts), 36), bytes: sample(h.map((e) => e.bytes), 36) };
  }, [s.time_histogram]);

  const incidents = s.incidents ?? [];
  const criticalIncidents = incidents.filter((i) => i.severity === "critical").length;
  const counts = s.severity_counts ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const onFire = incidents.length > 0;

  // Verdict color follows the WORST incident severity — not mere presence — so an
  // all-high capture never falsely reads critical-red.
  const worstSev: Severity = onFire
    ? incidents.reduce<Severity>(
        (w, i) => (SEVERITY_ORDER.indexOf(i.severity) < SEVERITY_ORDER.indexOf(w) ? i.severity : w),
        incidents[0].severity,
      )
    : "info";
  const verdictColor = `var(--color-sev-${worstSev})`;
  const isCritical = worstSev === "critical";

  return (
    <div className="card grid grid-cols-2 gap-px overflow-hidden bg-[var(--color-border)] sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7">
      <Cell label="Packets" value={humanNumber(s.total_packets)}>
        <Sparkline values={pkts} color="var(--color-accent)" />
      </Cell>
      <Cell label="Bytes" value={humanBytes(s.total_bytes)}>
        <Sparkline values={bytes} color="var(--color-accent-strong)" />
      </Cell>
      <Cell label="Flows" value={humanNumber(s.total_flows)} sub={`${humanNumber(s.unique_hosts)} hosts`} />
      <Cell label="Hosts" value={humanNumber(s.unique_hosts)} />
      <Cell label="Duration" value={durationHumanNs(s.duration_ns)} sub={`${s.time_bucket_secs ?? 1}s buckets`} />

      {/* THE verdict cell — replaces the misleading per-flow severity strip. */}
      <div
        className="flex flex-col justify-center gap-0.5 bg-[var(--color-surface-1)] px-4 py-2.5"
        style={
          onFire
            ? {
                background: `color-mix(in srgb, ${verdictColor} 7%, var(--color-surface-1))`,
                boxShadow: `inset 2px 0 0 ${verdictColor}${isCritical ? `, inset 0 0 30px -18px ${verdictColor}` : ""}`,
              }
            : undefined
        }
      >
        <span className="t-label inline-flex items-center gap-1">
          {onFire && <AlertOctagon size={11} style={{ color: verdictColor }} />}
          Incidents
        </span>
        <div className="flex items-baseline gap-1.5">
          <span className="t-kpi font-mono-num" style={{ color: onFire ? verdictColor : "var(--color-sev-low)" }}>
            {incidents.length}
          </span>
          {criticalIncidents > 0 && (
            <span className="font-mono-num text-xs font-semibold uppercase tracking-wide" style={{ color: "var(--color-sev-critical)" }}>
              {criticalIncidents} critical
            </span>
          )}
        </div>
        <span className="text-[11px] text-[var(--color-text-faint)]">{onFire ? "active — see hero" : "none detected"}</span>
      </div>

      {/* Context ring — the most colorful widget rendered as the calmest. */}
      <div className="flex items-center gap-2.5 bg-[var(--color-surface-1)] px-4 py-2.5">
        <SeverityRing counts={counts} size={52} />
        <div className="flex flex-col gap-0.5">
          <span className="t-label">Per-flow mix</span>
          <span className="font-mono-num text-[11px] text-[var(--color-text-dim)]">{compactNumber(counts.low)} low</span>
          <span className="font-mono-num text-[11px] text-[var(--color-text-faint)]">{compactNumber(counts.info)} info</span>
        </div>
      </div>
    </div>
  );
}

function Cell({ label, value, sub, children }: { label: string; value: string; sub?: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col justify-center gap-0.5 bg-[var(--color-surface-1)] px-4 py-2.5">
      <span className="t-label">{label}</span>
      <span className="font-display font-semibold tabular-nums text-[20px] leading-tight text-[var(--color-text)] sm:text-[28px]">
        {value}
      </span>
      {children}
      {sub && <span className="text-[11px] text-[var(--color-text-faint)]">{sub}</span>}
    </div>
  );
}

export default KpiCluster;
