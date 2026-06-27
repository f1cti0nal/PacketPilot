import type { Severity } from "../../types";
import { severityColor } from "../../lib/palette";

/** A 0–100 score chip colored by severity band. */
export function ScoreBadge({ score, severity }: { score: number; severity?: Severity }) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const color = severity ? severityColor(severity) : "var(--color-text-dim)";
  return (
    <span
      className="font-mono-num inline-flex items-center rounded px-1.5 py-0.5 text-[0.7rem] font-semibold tabular-nums"
      style={{ color, backgroundColor: "var(--color-surface-2)" }}
      title={`Score ${clamped}/100`}
    >
      {clamped}
      <span className="text-[var(--color-text-faint)]">/100</span>
    </span>
  );
}
