// Dashboard card: the primary (worst) reconstructed attack chain as a compact swimlane. Renders
// nothing when there are no chains, so the dashboard is unchanged on single-host captures.
import type { AttackChain } from "../types";
import { Card, SeverityChip, MitreTag } from "./primitives";
import { ChainSwimlane } from "./ChainSwimlane";

export function AttackChainCard({
  chains,
  onOpenFinding,
}: {
  chains: AttackChain[];
  onOpenFinding?: (findingIndex: number) => void;
}) {
  if (!chains.length) return null;
  const top = chains[0];
  const more = chains.length - 1;

  return (
    <Card
      label="Attack chain"
      title={top.title}
      right={<SeverityChip severity={top.severity} />}
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-[var(--color-text-dim)]">
        <span className="font-mono-num">
          {top.score}/100 · conf {top.confidence}
        </span>
        <span>
          {top.host_count} host{top.host_count === 1 ? "" : "s"} · {top.tactic_count} tactic
          {top.tactic_count === 1 ? "" : "s"}
        </span>
        {top.campaign_id && (
          <span className="rounded-[var(--r-micro)] border border-[var(--color-border)] px-1.5 py-0.5">
            campaign
          </span>
        )}
      </div>
      <div className="mt-2 flex flex-wrap gap-1">
        {top.attack.map((t) => (
          <MitreTag key={t} id={t} />
        ))}
      </div>
      <p className="mt-2 max-w-2xl text-[13px] text-[var(--color-text-dim)]">{top.narrative}</p>
      <div className="mt-3">
        <ChainSwimlane chain={top} onOpenFinding={onOpenFinding} />
      </div>
      {more > 0 && (
        <p className="mt-2 t-tag text-[var(--color-text-faint)]">
          +{more} more chain{more === 1 ? "" : "s"} — see the Attack Chains tab.
        </p>
      )}
    </Card>
  );
}

export default AttackChainCard;
