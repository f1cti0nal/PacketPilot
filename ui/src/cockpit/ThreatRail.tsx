// Persistent left threat rail — the "who do I chase" spine that never scrolls
// away. Ranked ip_threats[], severity→score, with a compact 64px collapsed mode.
import { cn } from "../lib/cn";
import { humanBytes, humanNumber } from "../lib/format";
import { SEVERITY_ORDER } from "../lib/severity";
import type { IpThreat, Severity } from "../types";
import { sevColor } from "./viz";
import { ScoreBar, IocDot } from "./primitives";
import { ReputationChip } from "./ReputationChip";

const worstFirst = (a: IpThreat, b: IpThreat) =>
  SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || b.score - a.score;

export function ThreatRail({
  threats,
  collapsed,
  activeIp = null,
  onSelect,
}: {
  threats: IpThreat[];
  collapsed: boolean;
  activeIp?: string | null;
  onSelect: (ip: string) => void;
}) {
  const sorted = [...threats].sort(worstFirst);

  return (
    <aside
      className={cn(
        "z-20 flex shrink-0 flex-col border-r border-[var(--color-border)] bg-[var(--color-surface)] transition-[width] duration-200",
        collapsed ? "w-16" : "w-[280px]",
      )}
    >
      {/* Watchlist header */}
      {!collapsed && (
        <div className="flex items-baseline justify-between px-3 pb-1.5 pt-3">
          <span className="t-label">Threat watchlist</span>
          <span className="font-mono-num text-xs text-[var(--color-text-faint)]">{humanNumber(sorted.length)}</span>
        </div>
      )}

      {/* Rows */}
      <div className="min-h-0 flex-1 overflow-y-auto px-2 pb-3">
        <ul className="flex flex-col gap-1">
          {sorted.map((t) => {
            const color = sevColor(t.severity);
            const active = activeIp === t.ip;
            return (
              <li key={t.ip}>
                <button
                  type="button"
                  onClick={() => onSelect(t.ip)}
                  aria-current={active ? "true" : undefined}
                  aria-label={`${t.ip}, ${t.severity}, score ${t.score} of 100${t.ioc ? ", on an indicator feed" : ""}`}
                  title={`${t.ip} — ${t.severity} ${t.score}/100`}
                  className={cn(
                    "group relative w-full overflow-hidden rounded-[var(--r-tile)] text-left transition-colors",
                    collapsed ? "flex items-center justify-center py-2" : "px-2.5 py-2",
                    active ? "bg-[var(--color-surface-2)] text-[var(--color-accent)]" : "text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)]",
                  )}
                >
                  <span
                    aria-hidden
                    className="absolute inset-y-0 left-0 w-0.5 transition-colors"
                    style={{ backgroundColor: active ? "var(--color-accent)" : color }}
                  />
                  {collapsed ? (
                    <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: color }} />
                  ) : (
                    <RailRow threat={t} color={color} />
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      </div>
    </aside>
  );
}

function RailRow({ threat, color }: { threat: IpThreat; color: string }) {
  return (
    <div className="flex flex-col gap-1.5 pl-1.5">
      <div className="flex items-center gap-2">
        <span className="font-mono-num min-w-0 flex-1 truncate text-[13px] text-[var(--color-text)]">{threat.ip}</span>
        {threat.ioc && <IocDot />}
        <span className="font-mono-num shrink-0 text-xs font-medium tabular-nums" style={{ color }}>
          {threat.score}
        </span>
      </div>
      <ScoreBar score={threat.score} severity={threat.severity as Severity} />
      <div className="flex items-center gap-2 text-[var(--color-text-faint)]">
        <span className="t-tag uppercase">{threat.ip_class}</span>
        <span className="font-mono-num t-tag">{humanNumber(threat.flows)} fl</span>
        <span className="font-mono-num t-tag">{humanBytes(threat.bytes)}</span>
        {threat.reputation && threat.reputation.length > 0 && <ReputationChip reputation={threat.reputation} />}
      </div>
    </div>
  );
}

export default ThreatRail;
