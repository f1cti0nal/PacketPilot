import { Card } from "./primitives";
import { humanNumber } from "../lib/format";
import type { HttpHostCount, UserAgentCount } from "../types";

/** A labelled bar list (label + flow count + proportional bar). Rows drill into Flows when onSelect is set. */
function BarList({
  rows,
  max,
  onSelect,
}: {
  rows: { label: string; flows: number }[];
  max: number;
  onSelect?: (label: string) => void;
}) {
  return (
    <ul className="flex flex-col gap-1.5">
      {rows.map((r, i) => {
        const pct = Math.max(2, Math.round((r.flows / max) * 100));
        const body = (
          <>
            <div className="flex items-center gap-2 text-xs">
              <span className="truncate text-[var(--color-text)]" title={r.label}>
                {r.label}
              </span>
              <span className="font-mono-num ml-auto shrink-0 text-[var(--color-text-faint)]">
                {humanNumber(r.flows)}
              </span>
            </div>
            <div className="h-1 w-full overflow-hidden rounded-[var(--r-micro)] bg-[var(--color-surface-2)]">
              <div
                className="h-full rounded-[var(--r-micro)] bg-[var(--color-accent)]"
                style={{ width: `${pct}%` }}
              />
            </div>
          </>
        );
        return (
          <li key={`${r.label}-${i}`}>
            {onSelect ? (
              <button
                type="button"
                onClick={() => onSelect(r.label)}
                title={`Show flows for ${r.label}`}
                className="flex w-full flex-col gap-1 rounded-[var(--r-micro)] text-left transition-colors hover:bg-[var(--color-surface-2)]"
              >
                {body}
              </button>
            ) : (
              <div className="flex flex-col gap-1">{body}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}

/**
 * HTTP overview: the capture's most-contacted HTTP `Host` headers and most-common client
 * `User-Agent`s, ranked by flow count (engine `summary.http_hosts` / `summary.user_agents`). The
 * aggregate companion to the per-flow Host/UA columns; surfaces the web destinations and client mix
 * at a glance. Display-only; hidden when no HTTP requests were seen.
 */
export function HttpOverviewCard({
  hosts,
  userAgents,
  onSelect,
}: {
  hosts: HttpHostCount[];
  userAgents: UserAgentCount[];
  /** Drill into Flows filtered on the clicked host or User-Agent. Rows are static when omitted. */
  onSelect?: (query: string) => void;
}) {
  const h = hosts ?? [];
  const ua = userAgents ?? [];
  if (h.length === 0 && ua.length === 0) return null;
  const hMax = h[0]?.flows ?? 1;
  const uMax = ua[0]?.flows ?? 1;
  const dash = <span className="text-xs text-[var(--color-text-faint)]">—</span>;

  return (
    <Card label="HTTP" title="HTTP overview">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div>
          <div className="t-tag mb-1.5 uppercase text-[var(--color-text-faint)]">Top hosts</div>
          {h.length ? (
            <BarList
              rows={h.slice(0, 8).map((x) => ({ label: x.host, flows: x.flows }))}
              max={hMax}
              onSelect={onSelect}
            />
          ) : (
            dash
          )}
        </div>
        <div>
          <div className="t-tag mb-1.5 uppercase text-[var(--color-text-faint)]">User-Agents</div>
          {ua.length ? (
            <BarList
              rows={ua.slice(0, 8).map((x) => ({ label: x.user_agent, flows: x.flows }))}
              max={uMax}
              onSelect={onSelect}
            />
          ) : (
            dash
          )}
        </div>
      </div>
    </Card>
  );
}

export default HttpOverviewCard;
