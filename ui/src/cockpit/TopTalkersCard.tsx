// Ranked "top talkers" — bar-in-row hosts. Reference data, subordinate to the
// hero: calm bars, no glow. Flagged hosts (C2 / exfil / attacker) get a tiny
// critical marker and brighter text so the eye finds them first.
import { useMemo } from "react";
import { cn } from "../lib/cn";
import { humanNumber, humanBytes } from "../lib/format";
import { Card } from "./primitives";
import type { TopTalker } from "../types";

const DEFAULT_FLAGGED = ["45.77.13.37", "185.220.101.5", "10.13.37.7"];
const ACCENT_BAR = "color-mix(in srgb, var(--color-accent) 12%, transparent)";
const CRITICAL = "var(--color-sev-critical)";

export function TopTalkersCard({
  talkers,
  limit,
  onSelect,
  flagged = DEFAULT_FLAGGED,
}: {
  talkers: TopTalker[];
  limit?: number;
  onSelect?: (ip: string) => void;
  flagged?: string[];
}): JSX.Element {
  const rows = useMemo(() => talkers.slice(0, limit ?? 8), [talkers, limit]);
  const maxBytes = useMemo(
    () => rows.reduce((m, t) => Math.max(m, t.bytes), 0) || 1,
    [rows],
  );
  const flaggedSet = useMemo(() => new Set(flagged), [flagged]);

  return (
    <Card label="HOSTS" title="Top talkers">
      {rows.length === 0 ? (
        <div className="t-body py-6 text-center text-[var(--color-text-faint)]">
          No host activity
        </div>
      ) : (
        <ul className="flex flex-col">
          {rows.map((t, i) => {
            const isFlagged = flaggedSet.has(t.ip);
            const barPct = (t.bytes / maxBytes) * 100;

            const inner = (
              <>
                {/* bytes bar — right-aligned, behind the text */}
                <span
                  aria-hidden
                  className="absolute inset-y-0 right-0 rounded-[var(--r-micro)]"
                  style={{ width: `${barPct}%`, backgroundColor: ACCENT_BAR }}
                />
                <div className="relative flex min-w-0 flex-1 flex-col gap-0.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono-num w-4 shrink-0 text-right t-tag text-[var(--color-text-faint)]">
                      {i + 1}
                    </span>
                    {isFlagged && (
                      <span
                        aria-hidden
                        className="shrink-0 rounded-full"
                        style={{ width: 6, height: 6, backgroundColor: CRITICAL }}
                      />
                    )}
                    <span
                      className={cn(
                        "font-mono-num min-w-0 flex-1 truncate t-row",
                        isFlagged
                          ? "font-medium text-[var(--color-text)]"
                          : "text-[var(--color-text-dim)]",
                      )}
                    >
                      {t.ip}
                    </span>
                    <span className="font-mono-num shrink-0 text-xs text-[var(--color-text)]">{humanBytes(t.bytes)}</span>
                  </div>
                  <div className="font-mono-num flex items-center gap-3 pl-6 t-tag text-[var(--color-text-faint)]">
                    <span>{humanNumber(t.pkts)} pkts</span>
                    <span>{humanNumber(t.flows)} flows</span>
                  </div>
                </div>
              </>
            );

            return (
              <li key={t.ip}>
                {onSelect ? (
                  <button
                    type="button"
                    onClick={() => onSelect(t.ip)}
                    className="relative flex w-full items-center justify-between overflow-hidden rounded-[var(--r-tile)] px-2 py-1.5 text-left transition-colors hover:bg-[var(--color-surface-2)]"
                  >
                    {inner}
                  </button>
                ) : (
                  <div className="relative flex w-full items-center justify-between overflow-hidden rounded-[var(--r-tile)] px-2 py-1.5">
                    {inner}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

export default TopTalkersCard;
