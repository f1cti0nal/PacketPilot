import { Card } from "./primitives";
import { humanNumber } from "../lib/format";
import type { SizeBucket, TtlCount } from "../types";

/**
 * Map an *observed* TTL to a likely originating OS / device family. Initial TTLs are 64
 * (Linux/macOS/BSD), 128 (Windows), or 255 (many network devices); each decrements one per hop,
 * so we bucket by the nearest initial value at or above the observed TTL.
 */
function ttlHint(ttl: number): string | null {
  if (ttl > 128) return "network";
  if (ttl > 64) return "Windows";
  if (ttl > 32) return "Linux/macOS";
  if (ttl > 0) return "low/many-hop";
  return null;
}

/**
 * Packet-size & TTL distributions — classic capture-shape triage. The size histogram separates
 * control-plane chatter (tiny ACK/SYN packets) from near-MTU bulk transfer; the TTL distribution
 * fingerprints the originating stacks and surfaces odd values (possible spoofing / extra hops).
 * Display-only; hidden when the summary carries neither distribution (older captures).
 */
export function PacketDistributionsCard({
  sizes,
  ttls,
}: {
  sizes: SizeBucket[];
  ttls: TtlCount[];
}) {
  const sizeRows = sizes ?? [];
  const ttlRows = ttls ?? [];
  // Hide only when there's genuinely nothing to show (older summaries lack both fields, and an
  // empty capture yields all-zero buckets).
  const hasSizes = sizeRows.some((b) => b.pkts > 0);
  if (!hasSizes && ttlRows.length === 0) return null;

  const sizeMax = Math.max(1, ...sizeRows.map((b) => b.pkts));
  const ttlMax = Math.max(1, ...ttlRows.map((t) => t.pkts));

  return (
    <Card label="WIRE" title="Packet size & TTL">
      <div className="grid gap-6 sm:grid-cols-2">
        {hasSizes && (
          <div>
            <div className="t-tag mb-2 uppercase text-[var(--color-text-faint)]">Wire size (bytes)</div>
            <ul className="flex flex-col gap-1.5">
              {sizeRows.map((b) => (
                <li key={b.label} className="flex items-center gap-2 text-xs">
                  <span className="font-mono-num w-[4.5rem] shrink-0 text-right text-[var(--color-text-dim)]">
                    {b.label}
                  </span>
                  <span className="relative h-3 flex-1 overflow-hidden rounded-[var(--r-micro)] bg-[var(--color-surface-2)]">
                    <span
                      className="absolute inset-y-0 left-0 rounded-[var(--r-micro)] bg-[var(--color-accent)]"
                      style={{ width: `${(b.pkts / sizeMax) * 100}%` }}
                    />
                  </span>
                  <span className="font-mono-num w-14 shrink-0 text-right text-[var(--color-text)]">
                    {humanNumber(b.pkts)}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
        {ttlRows.length > 0 && (
          <div>
            <div className="t-tag mb-2 uppercase text-[var(--color-text-faint)]">TTL / hop limit</div>
            <ul className="flex flex-col gap-1.5">
              {ttlRows.map((t) => {
                const hint = ttlHint(t.ttl);
                return (
                  <li key={t.ttl} className="flex items-center gap-2 text-xs">
                    <span className="font-mono-num w-8 shrink-0 text-right text-[var(--color-text)]">
                      {t.ttl}
                    </span>
                    <span className="w-[4.5rem] shrink-0 t-tag text-[var(--color-text-faint)]">
                      {hint}
                    </span>
                    <span className="relative h-3 flex-1 overflow-hidden rounded-[var(--r-micro)] bg-[var(--color-surface-2)]">
                      <span
                        className="absolute inset-y-0 left-0 rounded-[var(--r-micro)] bg-[var(--color-sev-low)]"
                        style={{ width: `${(t.pkts / ttlMax) * 100}%` }}
                      />
                    </span>
                    <span className="font-mono-num w-14 shrink-0 text-right text-[var(--color-text-dim)]">
                      {humanNumber(t.pkts)}
                    </span>
                  </li>
                );
              })}
            </ul>
          </div>
        )}
      </div>
    </Card>
  );
}

export default PacketDistributionsCard;
