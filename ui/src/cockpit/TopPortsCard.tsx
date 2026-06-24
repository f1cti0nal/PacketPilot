import { useMemo } from "react";
import type { PortHistogramEntry } from "../types";
import { Card } from "./primitives";
import { humanBytes, humanNumber } from "../lib/format";
import { serviceName } from "../lib/services";

/**
 * Top ports / services: the busiest ports in the capture, with well-known service names. A
 * port-level complement to the app-protocol `ProtocolMix` — surfaces traffic on non-standard ports
 * (no service name) that the app-proto view hides. Display-only; hidden when no ports were seen.
 */
export function TopPortsCard({ ports }: { ports: PortHistogramEntry[] }) {
  const top = useMemo(
    () => [...(ports ?? [])].sort((a, b) => b.pkts - a.pkts || b.bytes - a.bytes).slice(0, 8),
    [ports],
  );
  if (top.length === 0) return null;
  const max = top[0].pkts || 1;

  return (
    <Card
      label="PORTS"
      title="Top ports"
      right={
        <span className="font-mono-num t-tag text-[var(--color-text-dim)]">
          {humanNumber(ports.length)} seen
        </span>
      }
    >
      <ul className="flex flex-col gap-2">
        {top.map((p) => {
          const svc = serviceName(p.port);
          const pct = Math.max(2, Math.round((p.pkts / max) * 100));
          return (
            <li key={`${p.transport}-${p.port}`} className="flex flex-col gap-1">
              <div className="flex items-center gap-2 text-xs">
                <span className="font-mono-num font-medium text-[var(--color-text)]">{p.port}</span>
                <span className="t-tag uppercase text-[var(--color-text-faint)]">{p.transport}</span>
                {svc ? (
                  <span className="t-tag text-[var(--color-text-dim)]">{svc}</span>
                ) : (
                  <span className="t-tag text-[var(--color-text-faint)]">non-standard</span>
                )}
                <span className="font-mono-num ml-auto shrink-0 text-[var(--color-text-faint)]">
                  {humanNumber(p.pkts)} pk · {humanBytes(p.bytes)}
                </span>
              </div>
              <div className="h-1 w-full overflow-hidden rounded bg-[var(--color-surface-2)]">
                <div
                  className="h-full rounded bg-[var(--color-accent)]"
                  style={{ width: `${pct}%` }}
                />
              </div>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}

export default TopPortsCard;
