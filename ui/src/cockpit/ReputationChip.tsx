import { useState } from "react";
import type { ReputationVerdict, RepStatus } from "../types";
import { ProviderVerdictList } from "../components/transparency/ProviderVerdictList";

const RANK: Record<RepStatus, number> = { malicious: 5, benign: 4, unknown: 3, clean: 2, notfound: 1, unavailable: 0 };
const COLOR: Record<RepStatus, string> = {
  malicious: "var(--color-critical, #ef4444)", benign: "var(--color-low, #22c55e)",
  unknown: "var(--color-text-faint)", clean: "var(--color-text-faint)",
  notfound: "var(--color-text-faint)", unavailable: "var(--color-text-faint)",
};

/** Compact reputation summary (worst status) that expands to the full per-provider breakdown on click. */
export function ReputationChip({ reputation }: { reputation: ReputationVerdict[] }) {
  const [open, setOpen] = useState(false);
  if (!reputation || reputation.length === 0) return null;
  const worst = [...reputation].sort((a, b) => RANK[b.status] - RANK[a.status])[0];
  const label = worst.score != null ? `${worst.status} ${worst.score}` : worst.status;
  return (
    <span className="relative inline-flex">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="t-tag inline-flex items-center gap-1"
        title={reputation.map((vd) => `${vd.source}: ${vd.status}`).join(" · ")}
      >
        <span aria-hidden style={{ width: 6, height: 6, borderRadius: 9999, background: COLOR[worst.status] }} />
        <span style={{ color: COLOR[worst.status] }}>{worst.source} {label}</span>
      </button>
      {open && (
        <div className="absolute left-0 top-full z-20 mt-1 min-w-[16rem] rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] p-2 shadow-lg">
          <ProviderVerdictList verdicts={reputation} />
        </div>
      )}
    </span>
  );
}
