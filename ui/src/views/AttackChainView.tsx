// Full-tab view: every reconstructed attack chain as a horizontal swimlane, worst-first, with the
// tactic progression, ATT&CK techniques, and narrative. Empty state when nothing was reconstructed.
import { useEffect, useRef } from "react";
import type { AttackChain } from "../types";
import { Card, SeverityChip, MitreTag } from "../cockpit/primitives";
import { ChainSwimlane } from "../cockpit/ChainSwimlane";
import { techniqueName } from "../lib/killChain";
import { EmptyState } from "../components/state/EmptyState";

export function AttackChainView({
  chains,
  onOpenFinding,
  focusId = null,
}: {
  chains: AttackChain[];
  onOpenFinding?: (findingIndex: number) => void;
  /** Chain id to scroll to and highlight on mount / change — the Alerts "Open chain" pivot. */
  focusId?: string | null;
}) {
  const focusRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const el = focusRef.current;
    // scrollIntoView is absent in jsdom — guard so tests (and odd embedders) never crash.
    if (focusId && el && typeof el.scrollIntoView === "function") {
      el.scrollIntoView({ block: "start", behavior: "smooth" });
    }
  }, [focusId, chains]);

  if (!chains.length) {
    return (
      <EmptyState
        title="No attack chains reconstructed"
        hint="Attack chains appear when behavior links across hosts or stages — an actor sweeping, brute-forcing, then a victim beaconing out. Single-stage captures show none."
      />
    );
  }

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-4 p-4">
      {chains.map((chain) => {
        const focused = chain.id === focusId;
        return (
          <div
            key={chain.id}
            ref={focused ? focusRef : undefined}
            data-focused={focused ? "true" : undefined}
            className={focused ? "rounded-[var(--r-card)] ring-2 ring-[var(--color-accent)]" : undefined}
          >
        <Card
          label="Attack chain"
          title={chain.title}
          right={<SeverityChip severity={chain.severity} />}
        >
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-[var(--color-text-dim)]">
            <span className="font-mono-num">
              {chain.score}/100 · conf {chain.confidence}
            </span>
            <span>
              {chain.host_count} host{chain.host_count === 1 ? "" : "s"} · {chain.tactic_count} tactic
              {chain.tactic_count === 1 ? "" : "s"}
            </span>
            {chain.campaign_id && (
              <span className="rounded-[var(--r-micro)] border border-[var(--color-border)] px-1.5 py-0.5">
                {chain.campaign_id}
              </span>
            )}
          </div>

          <p className="mt-2 max-w-3xl text-[13px] text-[var(--color-text-dim)]">{chain.narrative}</p>

          <div className="mt-3">
            <ChainSwimlane chain={chain} width={860} onOpenFinding={onOpenFinding} />
          </div>

          {/* ATT&CK technique progression (id + resolved name). */}
          <div className="mt-3 flex flex-wrap gap-2">
            {chain.attack.map((id) => (
              <span
                key={id}
                className="inline-flex items-center gap-1.5 rounded-[var(--r-micro)] border border-[var(--color-border)] px-2 py-0.5 t-tag"
              >
                <MitreTag id={id} />
                <span className="text-[var(--color-text-faint)]">{techniqueName(id)}</span>
              </span>
            ))}
          </div>
        </Card>
          </div>
        );
      })}
    </div>
  );
}

export default AttackChainView;
