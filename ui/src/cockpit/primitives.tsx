// Shared Cockpit atoms. Every widget composes these so corner-radii, glow
// discipline, and type rhythm stay coherent across independently-built panels.
import { useId, type ReactNode } from "react";
import { cn } from "../lib/cn";
import { SEVERITY_META } from "../lib/severity";
import type { Severity } from "../types";
import { sparkline, sevColor } from "./viz";

/** Opaque grid panel with a hairline border + optional titled header. */
export function Card({
  title,
  label,
  right,
  className,
  bodyClassName,
  children,
}: {
  title?: string;
  label?: string;
  right?: ReactNode;
  className?: string;
  bodyClassName?: string;
  children: ReactNode;
}) {
  return (
    <section className={cn("card flex min-w-0 flex-col shadow-[var(--sh-rest)]", className)}>
      {(title || label || right) && (
        <header className="flex items-center justify-between gap-3 px-4 pt-3.5 pb-2">
          <div className="min-w-0">
            {label && <div className="t-label">{label}</div>}
            {title && <h3 className="t-title text-[var(--color-text)]">{title}</h3>}
          </div>
          {right}
        </header>
      )}
      <div className={cn("min-w-0 flex-1 px-4 pb-4", !title && !label && "pt-4", bodyClassName)}>
        {children}
      </div>
    </section>
  );
}

/** 11px uppercase mono section label — the connective tissue of the layout. */
export function SectionLabel({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("t-label", className)}>{children}</div>;
}

/** Severity-colored pill. */
export function SeverityChip({ severity, className }: { severity: Severity; className?: string }) {
  const color = sevColor(severity);
  const label = SEVERITY_META[severity]?.label ?? severity;
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center gap-1.5 rounded-[var(--r-chip)] border px-2 py-0.5 t-tag font-semibold uppercase",
        className,
      )}
      style={{ color, borderColor: color, backgroundColor: "var(--color-surface-2)" }}
    >
      <span aria-hidden className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
      {label}
    </span>
  );
}

export function SeverityDot({ severity, size = 8 }: { severity: Severity; size?: number }) {
  return (
    <span
      aria-hidden
      className="inline-block shrink-0 rounded-full"
      style={{ width: size, height: size, backgroundColor: sevColor(severity) }}
    />
  );
}

/** A MITRE ATT&CK technique chip. */
export function MitreTag({ id }: { id: string }) {
  return (
    <span
      className="font-mono-num rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-1.5 py-0.5 t-tag text-[var(--color-text-dim)]"
      title={`MITRE ATT&CK ${id}`}
    >
      {id}
    </span>
  );
}

/** Thin severity-tinted 0–100 score bar. */
export function ScoreBar({ score, severity, className }: { score: number; severity: Severity; className?: string }) {
  const color = sevColor(severity);
  const pct = Math.max(0, Math.min(100, score));
  return (
    <div className={cn("h-1 w-full overflow-hidden rounded-full bg-[var(--color-surface-3)]", className)}>
      <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: color }} />
    </div>
  );
}

/** Severity-colored IOC marker dot (known indicator feed). Flat — never glows. */
export function IocDot() {
  return (
    <span
      title="On a known indicator-of-compromise feed"
      className="inline-block h-1.5 w-1.5 shrink-0 rounded-full"
      style={{ backgroundColor: "var(--color-sev-critical)" }}
    />
  );
}

/** Dense, bordered, shadow-free console container (threats / incidents / flows). */
export function Panel({
  title, label, count, icon, accent, right, className, bodyClassName, children,
}: {
  title?: string; label?: string; count?: string | number; icon?: ReactNode;
  accent?: Severity; right?: ReactNode; className?: string; bodyClassName?: string; children: ReactNode;
}) {
  const accentColor = accent ? sevColor(accent) : undefined;
  return (
    <section
      className={cn(
        "flex min-w-0 flex-col overflow-hidden rounded-[var(--r-card)] border border-[var(--color-border)] bg-[var(--color-panel)]",
        className,
      )}
      style={accentColor ? { borderLeft: `2px solid ${accentColor}`, borderRadius: "0 var(--r-card) var(--r-card) 0" } : undefined}
    >
      {(title || label || right || icon) && (
        <header className="flex items-center gap-2 border-b border-[var(--color-border)] px-3.5 py-2.5">
          {icon && <span aria-hidden className="text-[var(--color-text-dim)]">{icon}</span>}
          <div className="min-w-0">
            {label && <div className="t-label">{label}</div>}
            {title && <h3 className="t-title text-[var(--color-text)]">{title}</h3>}
          </div>
          {count !== undefined && (
            <span className="font-mono-num t-tag text-[var(--color-text-faint)]">{count}</span>
          )}
          {right && <span className="ml-auto">{right}</span>}
        </header>
      )}
      <div className={cn("min-w-0 flex-1", bodyClassName)}>{children}</div>
    </section>
  );
}

/** KPI metric tile: muted label + large mono value + optional sub line. */
export function StatTile({ label, value, sub, accent, mono = true }: {
  label: string; value: ReactNode; sub?: ReactNode; accent?: boolean; mono?: boolean;
}) {
  return (
    <div className="rounded-[var(--r-tile)] bg-[var(--color-surface-2)] px-3 py-2.5">
      <div className="t-label text-[var(--color-text-dim)]">{label}</div>
      <div className={cn("mt-0.5 text-[var(--fs-display)] font-medium leading-none", mono && "font-mono-num",
        accent ? "text-[var(--color-accent-strong)]" : "text-[var(--color-text)]")}>{value}</div>
      {sub && <div className="mt-1 t-tag text-[var(--color-text-faint)]">{sub}</div>}
    </div>
  );
}

/** Neutral or accent tag chip. */
export function Tag({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "accent" }) {
  const isAccent = tone === "accent";
  return (
    <span className="inline-flex items-center rounded-[var(--r-chip)] border px-1.5 py-0.5 t-tag"
      style={{
        color: isAccent ? "var(--color-accent-strong)" : "var(--color-text-dim)",
        borderColor: "var(--color-border)",
        backgroundColor: isAccent ? "color-mix(in srgb, var(--color-accent) 12%, transparent)" : "var(--color-surface-2)",
      }}>{children}</span>
  );
}

/** Offline cloud/hosting attribution chip ("☁ AWS"). */
export function ProvenanceChip({ provider }: { provider: string }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-[var(--r-chip)] border border-[var(--color-border)] px-1.5 py-0.5 t-tag text-[var(--color-text-dim)]"
      title="Offline cloud/hosting attribution (coarse hint)">☁ {provider}</span>
  );
}

/** Section toolbar — search / filters / actions row above a data grid. */
export function Toolbar({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("flex flex-wrap items-center gap-2", className)}>{children}</div>;
}

/** Consistent section title + count + right actions. */
export function SectionHeader({ title, count, right }: { title: string; count?: string | number; right?: ReactNode }) {
  return (
    <div className="flex items-center gap-2 pb-2">
      <h2 className="t-title text-[var(--color-text)]">{title}</h2>
      {count !== undefined && <span className="font-mono-num t-tag text-[var(--color-text-faint)]">{count}</span>}
      {right && <span className="ml-auto">{right}</span>}
    </div>
  );
}

/** Inline micro-sparkline (area + line + endpoint dot). */
export function Sparkline({
  values,
  width = 84,
  height = 22,
  color = "var(--color-accent)",
  strokeWidth = 1.5,
}: {
  values: number[];
  width?: number;
  height?: number;
  color?: string;
  strokeWidth?: number;
}) {
  const id = useId().replace(/:/g, "");
  const { line, area, lastX, lastY } = sparkline(values, width, height, strokeWidth + 0.5);
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="overflow-visible" aria-hidden>
      <defs>
        <linearGradient id={`spk-${id}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity={0.28} />
          <stop offset="100%" stopColor={color} stopOpacity={0} />
        </linearGradient>
      </defs>
      <path d={area} fill={`url(#spk-${id})`} />
      <path d={line} fill="none" stroke={color} strokeWidth={strokeWidth} strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={lastX} cy={lastY} r={1.7} fill={color} />
    </svg>
  );
}
