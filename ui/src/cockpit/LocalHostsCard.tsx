import { Card } from "./primitives";
import { humanNumber } from "../lib/format";
import { vendorForMac } from "../lib/oui";
import type { ArpHost, DhcpHost } from "../types";

interface HostRow {
  mac: string;
  ip?: string;
  hostname?: string;
  /** Device/OS vendor: OUI lookup from the MAC, falling back to the DHCP vendor-class identifier. */
  vendor?: string;
}

/** Merge ARP (IP↔MAC, OUI vendor) and DHCP (MAC↔hostname, vendor class) into one row per MAC. */
function mergeHosts(arp: ArpHost[], dhcp: DhcpHost[]): HostRow[] {
  const byMac = new Map<string, HostRow>();
  for (const h of arp) {
    byMac.set(h.mac, { mac: h.mac, ip: h.ip, vendor: vendorForMac(h.mac) ?? undefined });
  }
  for (const d of dhcp) {
    const row = byMac.get(d.mac) ?? { mac: d.mac };
    row.hostname = d.hostname ?? row.hostname;
    // Prefer the precise OUI vendor; fall back to the DHCP vendor-class hint.
    row.vendor = row.vendor ?? d.vendor_class ?? undefined;
    byMac.set(d.mac, row);
  }
  // Hosts with an IP first (ascending), then DHCP-only hosts by MAC.
  return [...byMac.values()].sort((a, b) => {
    if (a.ip && b.ip) return a.ip.localeCompare(b.ip);
    if (a.ip) return -1;
    if (b.ip) return 1;
    return a.mac.localeCompare(b.mac);
  });
}

/**
 * Local hosts (L2): the on-segment asset inventory, merging two passive identity sources — ARP
 * (IP ↔ MAC, with a best-effort device vendor from the MAC's OUI) and DHCP (the client's
 * self-reported hostname + vendor class). Spots a Raspberry Pi, an ESP IoT device, a VM, or a named
 * workstation at a glance. Display-only; hidden when neither source saw anything.
 */
export function LocalHostsCard({
  arp,
  dhcp,
}: {
  arp: ArpHost[];
  dhcp?: DhcpHost[];
}) {
  const rows = mergeHosts(arp ?? [], dhcp ?? []);
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
        {rows.slice(0, 14).map((h) => (
          <li key={h.mac} className="flex items-baseline gap-2 py-1.5 text-xs">
            {h.hostname && (
              <span className="shrink-0 truncate font-medium text-[var(--color-text)]" title={h.hostname}>
                {h.hostname}
              </span>
            )}
            {h.ip && <span className="font-mono-num shrink-0 text-[var(--color-text)]">{h.ip}</span>}
            <span className="font-mono-num truncate text-[var(--color-text-faint)]" title={h.mac}>
              {h.mac}
            </span>
            {h.vendor && (
              <span className="ml-auto shrink-0 rounded border border-[var(--color-border)] px-1 text-[0.65rem] text-[var(--color-text-dim)]">
                {h.vendor}
              </span>
            )}
          </li>
        ))}
      </ul>
    </Card>
  );
}

export default LocalHostsCard;
