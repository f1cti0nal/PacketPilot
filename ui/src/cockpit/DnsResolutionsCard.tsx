import { Card } from "./primitives";
import { humanNumber } from "../lib/format";
import type { ResolvedDomain } from "../types";

/**
 * Passive DNS: the IP → domain mappings learned from DNS `A`/`AAAA` answers in the capture, ranked
 * by how many responses carried each. Lets an analyst attribute a flow's destination IP back to the
 * domain it resolved from (a C2 IP → its domain). Display-only; hidden when no DNS answers were seen.
 */
export function DnsResolutionsCard({ resolved }: { resolved: ResolvedDomain[] }) {
  const rows = resolved ?? [];
  if (rows.length === 0) return null;

  return (
    <Card
      label="DNS"
      title="Passive DNS"
      right={
        <span className="font-mono-num t-tag text-[var(--color-text-dim)]">
          {humanNumber(rows.length)} resolved
        </span>
      }
    >
      <ul className="flex flex-col divide-y divide-[var(--color-border)]">
        {rows.slice(0, 12).map((r) => (
          <li
            key={`${r.ip}-${r.domain}`}
            className="flex items-baseline gap-2 py-1.5 text-xs"
          >
            <span className="font-mono-num min-w-0 max-w-[55%] truncate text-[var(--color-text)]" title={r.ip}>
              {r.ip}
            </span>
            <span className="text-[var(--color-text-faint)]">←</span>
            <span className="truncate text-[var(--color-text-dim)]" title={r.domain}>
              {r.domain}
            </span>
            {r.resolutions > 1 && (
              <span className="font-mono-num ml-auto shrink-0 text-[0.65rem] text-[var(--color-text-faint)]">
                ×{humanNumber(r.resolutions)}
              </span>
            )}
          </li>
        ))}
      </ul>
    </Card>
  );
}

export default DnsResolutionsCard;
