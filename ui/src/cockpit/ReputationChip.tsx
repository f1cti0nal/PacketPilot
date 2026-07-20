import { useState } from "react";
import type { ReputationVerdict, RepStatus } from "../types";
import { ProviderVerdictList } from "../components/transparency/ProviderVerdictList";

const RANK: Record<RepStatus, number> = { malicious: 5, benign: 4, unknown: 3, clean: 2, notfound: 1, unavailable: 0 };
const COLOR: Record<RepStatus, string> = {
  malicious: "var(--color-sev-critical)", benign: "var(--color-sev-low)",
  unknown: "var(--color-text-faint)", clean: "var(--color-text-faint)",
  notfound: "var(--color-text-faint)", unavailable: "var(--color-text-faint)",
};

/** Explicit "reputation not checked" affordance for an EXTERNAL IP that carries no verdicts, so an
 *  empty reputation is never read as "clean / benign" (mirrors the engine's "absence is never
 *  innocence"). `configured=false` = no connectors set up (offline default); `true` = configured
 *  but this host wasn't queried. Deliberately neutral gray — never a verdict hue. */
export function ReputationNotChecked({ configured }: { configured: boolean }) {
  const label = configured ? "reputation not looked up" : "reputation not checked";
  const title = configured
    ? "This host was not queried (quota / priority cap / lookup failure)."
    : "No reputation connectors configured (offline); absence is not innocence.";
  return (
    <span className="t-tag inline-flex items-center gap-1 text-[var(--color-text-faint)]" title={title}>
      <span
        aria-hidden
        style={{ width: 6, height: 6, borderRadius: 9999, background: "var(--color-text-faint)", opacity: 0.55 }}
      />
      {label}
    </span>
  );
}

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
        aria-label={`Reputation ${worst.status} from ${worst.source}; show per-provider details`}
        className="t-tag inline-flex items-center gap-1"
        title={reputation.map((vd) => `${vd.source}: ${vd.status}`).join(" · ")}
      >
        <span aria-hidden style={{ width: 6, height: 6, borderRadius: 9999, background: COLOR[worst.status] }} />
        <span style={{ color: COLOR[worst.status] }}>{worst.source} {label}</span>
      </button>
      {open && (
        <div className="pp-pop-in absolute left-0 top-full z-20 mt-1 min-w-[16rem] rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] p-2">
          <ProviderVerdictList verdicts={reputation} />
        </div>
      )}
    </span>
  );
}
