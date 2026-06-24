import { parseScoreTerms } from "../../lib/scoreTerms";
import { SectionLabel } from "../../cockpit/primitives";
import { sevColor } from "../../cockpit/viz";
import type { Severity, ScoreTerm } from "../../types";

/** Visual +N / -N breakdown waterfall for a threat score's evidence strings. */
export function ScoreWaterfall({
  evidence,
  score,
  severity,
  scoreTerms,
}: {
  evidence: string[];
  score: number;
  severity: Severity;
  scoreTerms?: ScoreTerm[];
}) {
  const { terms, notes } = scoreTerms && scoreTerms.length
    ? { terms: scoreTerms, notes: parseScoreTerms(evidence).notes }
    : parseScoreTerms(evidence);
  if (terms.length === 0 && notes.length === 0) return null;

  const maxAbs = Math.max(1, ...terms.map((t) => Math.abs(t.points)));

  return (
    <div className="flex flex-col gap-1">
      <SectionLabel>Score breakdown</SectionLabel>

      {/* Additive term rows */}
      {terms.map((t, i) => {
        const positive = t.points >= 0;
        // positive raises the threat (alarming = critical red); negative reduces it (accent).
        // NB: the token is --color-sev-critical; bare --color-critical is undefined (renders invisible).
        const color = positive ? "var(--color-sev-critical)" : "var(--color-accent)";
        const barWidth = `${(Math.abs(t.points) / maxAbs) * 100}%`;
        const signed = `${positive ? "+" : ""}${t.points}`;
        return (
          <div key={i} className="flex items-center gap-2 text-xs">
            {/* Label — truncate long strings */}
            <span
              className="w-40 min-w-0 shrink-0 truncate text-[var(--color-text-dim)]"
              title={t.label}
            >
              {t.label}
            </span>
            {/* Proportional bar */}
            <div className="flex flex-1 items-center">
              <div
                className="h-1.5 rounded-sm"
                style={{ width: barWidth, backgroundColor: color, minWidth: "2px" }}
              />
            </div>
            {/* Signed delta */}
            <span
              className="font-mono-num w-10 shrink-0 text-right text-xs tabular-nums"
              style={{ color }}
            >
              {signed}
            </span>
          </div>
        );
      })}

      {/* Final score row */}
      <div
        className="mt-1 flex items-center gap-1 text-xs font-semibold"
        style={{ color: sevColor(severity) }}
      >
        <span>Score</span>
        <span className="font-mono-num tabular-nums">{score}/100</span>
      </div>

      {/* Non-additive notes (clamp/floor annotations) */}
      {notes.length > 0 && (
        <div className="mt-0.5 flex flex-col gap-0.5">
          {notes.map((n, i) => (
            <span
              key={i}
              className="font-mono-num text-[var(--color-text-faint)] text-[0.65rem] leading-snug"
            >
              {n}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
