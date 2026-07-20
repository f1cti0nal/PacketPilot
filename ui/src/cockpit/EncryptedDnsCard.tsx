import { Card } from "./primitives";
import { humanNumber } from "../lib/format";
import type { EncryptedDnsHost } from "../types";

/**
 * Encrypted DNS (DoH/DoT): client hosts whose name resolution is hidden from network monitoring —
 * a TLS flow to a known DNS-over-HTTPS resolver (by SNI) or to the DNS-over-TLS port (853). This is
 * the exact resolution the passive-DNS panel *cannot* see, and a known malware-evasion channel (C2
 * lookups over DoH). Informational visibility — "whose DNS is a blind spot" — not an alert.
 * Display-only; hidden when none were seen.
 */
export function EncryptedDnsCard({ hosts }: { hosts: EncryptedDnsHost[] }) {
  const rows = hosts ?? [];
  if (rows.length === 0) return null;

  return (
    <Card
      label="ENCRYPTED DNS"
      title="Encrypted DNS"
      right={
        <span className="font-mono-num t-tag text-[var(--color-text-dim)]">
          {humanNumber(rows.length)} hosts
        </span>
      }
    >
      <ul className="flex flex-col divide-y divide-[var(--color-border)]">
        {rows.slice(0, 12).map((h) => (
          <li
            key={`${h.host}-${h.resolver}`}
            className="flex items-baseline gap-2 py-1.5 text-xs"
          >
            <span className="font-mono-num shrink-0 truncate text-[var(--color-text)]" title={h.host}>
              {h.host}
            </span>
            <span className="text-[var(--color-text-faint)]">→</span>
            <span className="font-mono-num truncate text-[var(--color-text-dim)]" title={h.resolver}>
              {h.resolver}
            </span>
            {h.flows > 1 && (
              <span className="font-mono-num ml-auto shrink-0 t-tag text-[var(--color-text-faint)]">
                ×{humanNumber(h.flows)}
              </span>
            )}
          </li>
        ))}
      </ul>
    </Card>
  );
}

export default EncryptedDnsCard;
