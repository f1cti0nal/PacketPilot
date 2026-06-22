import type { Finding } from "../../types";
import { ScoreBadge } from "./ScoreBadge";

/** Humanize a nanosecond interval to a compact period string. */
function humanizeInterval(ns: number): string {
  const s = ns / 1e9;
  if (s < 1) return `${Math.round(ns / 1e6)}ms`;
  if (s < 90) return `${s < 10 ? s.toFixed(1) : Math.round(s)}s`;
  const m = s / 60;
  if (m < 90) return `${m < 10 ? m.toFixed(1) : Math.round(m)}m`;
  return `${(m / 60).toFixed(1)}h`;
}

/** Compact "why this severity" metrics row for a finding: score + any present beacon/contact metrics. */
export function FindingMetrics({ finding }: { finding: Finding }) {
  const parts: { label: string; value: string }[] = [];
  if (finding.interval_ns != null) parts.push({ label: "period", value: humanizeInterval(finding.interval_ns) });
  if (finding.jitter_cv != null) parts.push({ label: "jitter", value: finding.jitter_cv.toFixed(2) });
  if (finding.contacts != null) parts.push({ label: "contacts", value: String(finding.contacts) });
  return (
    <div className="flex flex-wrap items-center gap-2">
      <ScoreBadge score={finding.score} severity={finding.severity} />
      {parts.map((p) => (
        <span key={p.label} className="font-mono-num text-[0.7rem] text-[var(--color-text-faint)]">
          {p.label} <span className="text-[var(--color-text-dim)]">{p.value}</span>
        </span>
      ))}
    </div>
  );
}
