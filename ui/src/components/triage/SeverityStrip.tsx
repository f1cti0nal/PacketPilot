import { useMemo } from "react";
import clsx from "clsx";
import {
  AlertOctagon,
  AlertTriangle,
  CircleAlert,
  HelpCircle,
  Info,
  ShieldAlert,
  type LucideIcon,
} from "lucide-react";
import type { SeverityCounts, Severity } from "../../types";
import { SEVERITY_META, SEVERITY_ORDER } from "../../lib/severity";
import { compactNumber, humanNumber, percent } from "../../lib/format";

export interface SeverityStripProps {
  counts: SeverityCounts;
  active?: Severity | null;
  onSelect?: (s: Severity) => void;
}

/** Per-severity icon — visual reinforcement of the colored chip. */
const SEVERITY_ICON: Record<Severity, LucideIcon> = {
  critical: AlertOctagon,
  high: AlertTriangle,
  medium: CircleAlert,
  low: ShieldAlert,
  info: Info,
  none: HelpCircle,
};

/** One-line legend describing what each severity bucket means in triage. */
const SEVERITY_HINT: Record<Severity, string> = {
  critical: "C2 / anomalous — active compromise",
  high: "scans — strongly suspicious",
  medium: "tunnels & remote access — egress of interest",
  low: "low-risk / external noise",
  info: "web, DNS, VoIP — ordinary traffic",
  none: "uncategorized flows",
};

/** The five engine buckets shown by the strip. */
const STRIP_ORDER = SEVERITY_ORDER as Exclude<Severity, "none">[];

export function SeverityStrip({
  counts,
  active = null,
  onSelect,
}: SeverityStripProps) {
  const total = useMemo(
    () => STRIP_ORDER.reduce((acc, sev) => acc + (counts[sev] ?? 0), 0),
    [counts],
  );

  return (
    <section
      data-component="SeverityStrip"
      aria-label="Severity breakdown"
      className="flex flex-col gap-3"
    >
      <div className="flex items-baseline justify-between gap-2">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-text-dim)]">
          What matters
        </h2>
        <span className="font-mono-num text-xs text-[var(--color-text-faint)]">
          {humanNumber(total)} flows
        </span>
      </div>

      <div className="flex flex-wrap gap-2">
        {STRIP_ORDER.map((sev) => {
          const meta = SEVERITY_META[sev];
          const value = counts[sev] ?? 0;
          const Icon = SEVERITY_ICON[sev];
          const color = `var(${meta.cssVar})`;
          const isActive = active === sev;
          const isEmpty = value === 0;
          const interactive = !!onSelect;

          const handleClick = () => onSelect?.(sev);

          return (
            <button
              key={sev}
              type="button"
              disabled={!interactive}
              aria-pressed={interactive ? isActive : undefined}
              onClick={handleClick}
              title={`${meta.label}: ${humanNumber(value)} flows (${percent(
                value,
                total,
              )}) — ${SEVERITY_HINT[sev]}`}
              className={clsx(
                "group flex items-center gap-2 rounded-lg border px-3 py-2 text-left transition-colors",
                "focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]",
                interactive && "cursor-pointer hover:bg-[var(--color-surface-2)]",
                !interactive && "cursor-default",
                isEmpty && !isActive && "opacity-50",
              )}
              style={{
                background: isActive
                  ? `color-mix(in srgb, ${color} 16%, var(--color-surface))`
                  : "var(--color-surface)",
                borderColor: isActive
                  ? color
                  : `color-mix(in srgb, ${color} 35%, var(--color-border))`,
              }}
            >
              <span
                aria-hidden="true"
                className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md"
                style={{
                  background: `color-mix(in srgb, ${color} 18%, transparent)`,
                  color,
                }}
              >
                <Icon size={16} strokeWidth={2.25} />
              </span>

              <span className="flex flex-col leading-tight">
                <span
                  className="font-mono-num text-lg font-semibold"
                  style={{ color }}
                >
                  {compactNumber(value)}
                </span>
                <span className="text-xs font-medium text-[var(--color-text)]">
                  {meta.label}
                </span>
              </span>
            </button>
          );
        })}
      </div>

      <p className="text-xs leading-relaxed text-[var(--color-text-faint)]">
        Severity comes from the engine threat score (category + IOC reputation +
        behavior), not category alone:{" "}
        {STRIP_ORDER.map((sev, i) => (
          <span key={sev}>
            {i > 0 && <span className="text-[var(--color-text-faint)]"> · </span>}
            <span style={{ color: `var(${SEVERITY_META[sev].cssVar})` }}>
              {SEVERITY_META[sev].label}
            </span>{" "}
            {SEVERITY_HINT[sev]}
          </span>
        ))}
        .
      </p>
    </section>
  );
}

export default SeverityStrip;
