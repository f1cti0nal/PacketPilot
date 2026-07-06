import { useMemo, useState } from "react";
import { Search, X } from "lucide-react";
import type { IpThreat, Severity } from "../types";
import { SEVERITY_META, SEVERITY_ORDER } from "../lib/severity";
import { humanBytes, humanNumber } from "../lib/format";
import { sevColor } from "../cockpit/viz";
import { ScoreBar, IocDot, Toolbar } from "../cockpit/primitives";
import { ReputationChip, ReputationNotChecked } from "../cockpit/ReputationChip";
import { EmptyState } from "../components/state/EmptyState";
import { cn } from "../lib/cn";

export interface ThreatsViewProps {
  threats: IpThreat[];
  /** Currently active/focused host (drives the card highlight). */
  activeIp?: string | null;
  /** Pivot into a host: opens its incident on the dashboard, or its filtered flows. */
  onSelect: (ip: string) => void;
  /** Whether reputation connectors are configured. Drives the "not checked" vs "not looked up"
   *  copy on external hosts that carry no verdicts (default false = offline/local mode). */
  reputationConfigured?: boolean;
}

/** Worst-severity first, then highest score — the same ranking the old threat rail used. */
const worstFirst = (a: IpThreat, b: IpThreat) =>
  SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || b.score - a.score;

/**
 * Threat watchlist as a full-width view — the "who do I chase" spine, promoted from a fixed
 * left rail into a first-class navigable view. Ranked worst-first, filterable by host, and each
 * card pivots into the host (incident on the dashboard, or filtered Flows) via `onSelect`.
 * Cards are real buttons, so the watchlist stays keyboard-navigable exactly like the old rail.
 */
export function ThreatsView({ threats, activeIp = null, onSelect, reputationConfigured = false }: ThreatsViewProps) {
  const [query, setQuery] = useState("");

  const sorted = useMemo(() => [...threats].sort(worstFirst), [threats]);
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return sorted;
    return sorted.filter((t) => t.ip.toLowerCase().includes(q) || t.ip_class.toLowerCase().includes(q));
  }, [sorted, query]);

  if (threats.length === 0) {
    return (
      <EmptyState
        title="No threats to watch"
        hint="Ranked hosts appear here once a capture is analyzed. Load a capture to get started."
      />
    );
  }

  const inputBase =
    "rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] " +
    "text-[length:var(--fs-body)] text-[var(--color-text)] placeholder:text-[var(--color-text-faint)] " +
    "focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)] focus:border-[var(--color-accent)]";

  return (
    <div data-component="ThreatsView" className="flex h-full min-h-0 flex-col gap-3">
      <Toolbar className="gap-2">
        <div className="relative min-w-[16rem] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--color-text-faint)]" aria-hidden />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter watchlist by host or class…"
            aria-label="Filter threats"
            className={cn(inputBase, "w-full py-1.5 pl-8 pr-8")}
          />
          {query && (
            <button
              type="button"
              onClick={() => setQuery("")}
              aria-label="Clear text filter"
              className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--color-text-faint)] hover:text-[var(--color-text)]"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
        <div className="ml-auto text-[length:var(--fs-body)] text-[var(--color-text-dim)]">
          <span className="font-mono-num text-[var(--color-text)]">{humanNumber(filtered.length)}</span>
          {" / "}
          <span className="font-mono-num">{humanNumber(threats.length)}</span>
          {" hosts"}
        </div>
      </Toolbar>

      <div className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden">
        {filtered.length === 0 ? (
          <EmptyState title="No hosts match the current filter" hint="Try clearing the text filter." />
        ) : (
          <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {filtered.map((t) => (
              <li key={t.ip}>
                <ThreatCard threat={t} active={activeIp === t.ip} onSelect={onSelect} reputationConfigured={reputationConfigured} />
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function ThreatCard({
  threat,
  active,
  onSelect,
  reputationConfigured,
}: {
  threat: IpThreat;
  active: boolean;
  onSelect: (ip: string) => void;
  reputationConfigured: boolean;
}) {
  const color = sevColor(threat.severity);
  const external = threat.ip_class === "public" || threat.ip_class === "cgnat";
  return (
    <button
      type="button"
      onClick={() => onSelect(threat.ip)}
      aria-current={active ? "true" : undefined}
      aria-label={`${threat.ip}, ${threat.severity}, score ${threat.score} of 100${threat.ioc ? ", on an indicator feed" : ""}`}
      className={cn(
        "relative flex w-full flex-col gap-2.5 overflow-hidden rounded-[var(--r-card)] border bg-[var(--color-panel)] px-3.5 py-3 text-left transition-colors",
        active
          ? "border-[var(--color-accent)] bg-[var(--color-surface-2)]"
          : "border-[var(--color-border)] hover:border-[var(--color-border-strong)] hover:bg-[var(--color-surface-2)]",
      )}
    >
      <span aria-hidden className="absolute inset-y-0 left-0 w-0.5" style={{ backgroundColor: active ? "var(--color-accent)" : color }} />
      <div className="flex items-center gap-2 pl-1.5">
        <span className="font-mono-num min-w-0 flex-1 truncate text-sm text-[var(--color-text)]">{threat.ip}</span>
        {threat.ioc && <IocDot />}
        <SeverityLabel severity={threat.severity} color={color} />
        <span className="font-mono-num shrink-0 text-sm font-medium tabular-nums" style={{ color }}>
          {threat.score}
        </span>
      </div>
      <ScoreBar score={threat.score} severity={threat.severity as Severity} className="ml-1.5" />
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 pl-1.5 text-[var(--color-text-faint)]">
        <span className="t-tag uppercase">{threat.ip_class}</span>
        <span className="font-mono-num t-tag">{humanNumber(threat.flows)} flows</span>
        <span className="font-mono-num t-tag">{humanBytes(threat.bytes)}</span>
        {threat.reputation && threat.reputation.length > 0 ? (
          <ReputationChip reputation={threat.reputation} />
        ) : external ? (
          <ReputationNotChecked configured={reputationConfigured} />
        ) : null}
      </div>
    </button>
  );
}

function SeverityLabel({ severity, color }: { severity: Severity; color: string }) {
  return (
    <span
      className="shrink-0 rounded-[var(--r-chip)] border px-1.5 py-0.5 t-tag font-medium uppercase"
      style={{ color, borderColor: color, backgroundColor: "var(--color-surface-2)" }}
    >
      {SEVERITY_META[severity]?.label ?? severity}
    </span>
  );
}

export default ThreatsView;
