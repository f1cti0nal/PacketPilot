import { Card } from "./primitives";
import { humanNumber } from "../lib/format";
import { vendorForMac } from "../lib/oui";
import type { ArpHost } from "../types";

/**
 * Local hosts (L2): the IP → MAC bindings observed via ARP, with a best-effort device vendor from
 * the MAC's OUI (virtualization stacks, single-board / IoT silicon, common vendors). The local-segment
 * asset inventory — spotting a Raspberry Pi, an ESP IoT device, or a VM at a glance. Display-only;
 * hidden when no ARP was seen (e.g. an internet-only / tunneled capture).
 */
export function LocalHostsCard({ hosts }: { hosts: ArpHost[] }) {
  const rows = hosts ?? [];
  if (rows.length === 0) return null;

  return (
    <Card
      label="L2"
      title="Local hosts"
      right={
        <span className="font-mono-num t-tag text-[var(--color-text-dim)]">
          {humanNumber(rows.length)} hosts
        </span>
      }
    >
      <ul className="flex flex-col divide-y divide-[var(--color-border)]">
        {rows.slice(0, 14).map((h) => {
          const vendor = vendorForMac(h.mac);
          return (
            <li key={`${h.ip}-${h.mac}`} className="flex items-baseline gap-2 py-1.5 text-xs">
              <span className="font-mono-num shrink-0 text-[var(--color-text)]">{h.ip}</span>
              <span className="font-mono-num truncate text-[var(--color-text-faint)]" title={h.mac}>
                {h.mac}
              </span>
              {vendor && (
                <span className="ml-auto shrink-0 rounded border border-[var(--color-border)] px-1 text-[0.65rem] text-[var(--color-text-dim)]">
                  {vendor}
                </span>
              )}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}

export default LocalHostsCard;
