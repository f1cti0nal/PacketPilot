// Category threat matrix — severity-sorted horizontal bars. The deliberate
// inversion: scan/c2/anomalous float to the top regardless of volume, so the
// dangerous categories are unmissable even though web/dns dominate by flows.
import { useMemo } from "react";
import { humanNumber } from "../lib/format";
import { normCategory, severityForCategory, SEVERITY_ORDER } from "../lib/severity";
import { severityColor } from "../lib/palette";
import { Card, SeverityChip } from "./primitives";
import type { CategoryBreakdownEntry, Severity } from "../types";

interface Row {
  token: string;
  label: string;
  sev: Severity;
  color: string;
  flows: number;
  rank: number;
}

/** "file_transfer" -> "File Transfer". */
function titleCase(token: string): string {
  return token
    .split("_")
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

export function CategoryMatrix({
  breakdown,
  onJump,
}: {
  breakdown: CategoryBreakdownEntry[];
  onJump?: (category: string) => void;
}): JSX.Element {
  const rows = useMemo<Row[]>(() => {
    const mapped = breakdown
      .filter((e) => e.flows > 0)
      .map((e): Row => {
        const token = normCategory(e.category);
        const sev = severityForCategory(e.category);
        const idx = SEVERITY_ORDER.indexOf(sev);
        return {
          token,
          label: titleCase(token),
          sev,
          color: severityColor(sev),
          flows: e.flows,
          // "none" (idx -1) floats to the very top alongside critical.
          rank: idx === -1 ? -1 : idx,
        };
      });
    // Severity-first, then flows desc — the inversion is the point.
    mapped.sort((a, b) => a.rank - b.rank || b.flows - a.flows);
    return mapped;
  }, [breakdown]);

  const maxFlows = useMemo(
    () => rows.reduce((m, r) => (r.flows > m ? r.flows : m), 0),
    [rows],
  );

  return (
    <Card
      label="TRAFFIC"
      title="Category threat matrix"
      right={
        <span className="font-mono-num t-tag text-[var(--color-text-dim)]">
          {rows.length} cat
        </span>
      }
    >
      {rows.length === 0 ? (
        <div className="py-6 text-center t-body text-[var(--color-text-faint)]">
          No categorized traffic
        </div>
      ) : (
        <ul className="flex flex-col gap-0.5">
          {rows.map((r, i) => {
            const pct = maxFlows > 0 ? (r.flows / maxFlows) * 100 : 0;
            const interactive = !!onJump;
            const body = (
              <>
                {/* left: severity spine + label */}
                <span
                  aria-hidden
                  className="h-7 w-0.5 shrink-0 rounded-full"
                  style={{ backgroundColor: r.color }}
                />
                <span className="flex w-32 shrink-0 items-center gap-2 truncate text-sm text-[var(--color-text)]">
                  <span className="truncate">{r.label}</span>
                  {i < 2 && <SeverityChip severity={r.sev} />}
                </span>
                {/* center: track + fill */}
                <span className="h-2 flex-1 overflow-hidden rounded-full bg-[var(--color-surface-3)]">
                  <span
                    className="block h-full rounded-full"
                    style={{ width: `${pct}%`, backgroundColor: r.color }}
                  />
                </span>
                {/* right: flow count */}
                <span className="font-mono-num w-16 shrink-0 text-right text-sm text-[var(--color-text-dim)]">
                  {humanNumber(r.flows)}
                </span>
              </>
            );

            const a11yLabel = `${r.label}, ${r.sev}, ${humanNumber(r.flows)} flows`;
            if (interactive) {
              return (
                <li key={r.token}>
                  <button
                    type="button"
                    onClick={() => onJump(r.token)}
                    aria-label={a11yLabel}
                    className="flex w-full cursor-pointer items-center gap-3 rounded-[var(--r-tile)] px-2 py-1.5 text-left transition-colors hover:bg-[var(--color-surface-2)]"
                  >
                    {body}
                  </button>
                </li>
              );
            }
            return (
              <li
                key={r.token}
                aria-label={a11yLabel}
                className="flex items-center gap-3 rounded-[var(--r-tile)] px-2 py-1.5"
              >
                {body}
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

export default CategoryMatrix;
