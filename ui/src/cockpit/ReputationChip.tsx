import type { ReputationVerdict, RepStatus } from "../types";

const RANK: Record<RepStatus, number> = { malicious: 5, benign: 4, unknown: 3, clean: 2, notfound: 1, unavailable: 0 };
const COLOR: Record<RepStatus, string> = {
  malicious: "var(--color-critical, #ef4444)", benign: "var(--color-low, #22c55e)",
  unknown: "var(--color-text-faint)", clean: "var(--color-text-faint)",
  notfound: "var(--color-text-faint)", unavailable: "var(--color-text-faint)",
};

/** Compact summary of a card's reputation verdicts: the worst status + the provider that set it. */
export function ReputationChip({ reputation }: { reputation: ReputationVerdict[] }) {
  if (!reputation || reputation.length === 0) return null;
  const worst = [...reputation].sort((a, b) => RANK[b.status] - RANK[a.status])[0];
  const label = worst.score != null ? `${worst.status} ${worst.score}` : worst.status;
  return (
    <span className="t-tag inline-flex items-center gap-1" title={reputation.map((v) => `${v.source}: ${v.status}`).join(" · ")}>
      <span aria-hidden style={{ width: 6, height: 6, borderRadius: 9999, background: COLOR[worst.status] }} />
      <span style={{ color: COLOR[worst.status] }}>{worst.source} {label}</span>
    </span>
  );
}
