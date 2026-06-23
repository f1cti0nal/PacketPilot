import type { AnalysisOutput } from "../types";

/** A mutable holder for the per-capture rules base (mirrors a React ref). */
export interface RuleBaseRef {
  current: { key: string; data: AnalysisOutput } | null;
}

/**
 * Pick the base {@link AnalysisOutput} to apply an imported ruleset over, snapshotting it
 * per capture. The snapshot is taken on the first apply for a given `key` (capturing the
 * then-current state, including any reputation enrichment); subsequent applies for the SAME
 * capture reuse that snapshot. This guarantees re-loading a ruleset **replaces** rather than
 * **stacks** (no duplicated rule findings) and never clobbers a prior enrichment pass. A new
 * `key` (a different capture) re-snapshots. Mutates `ref`.
 */
export function pickRuleBase(
  ref: RuleBaseRef,
  key: string,
  current: AnalysisOutput,
): AnalysisOutput {
  if (ref.current?.key === key) return ref.current.data;
  ref.current = { key, data: current };
  return current;
}
