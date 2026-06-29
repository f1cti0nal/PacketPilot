import type { AnalysisOutput, ReputationVerdict } from "../../types";

/**
 * Attach VirusTotal file-hash verdicts to `summary.carved_files`, keyed by sha256. Display-only —
 * the engine never emits `reputation`; this is the TS analog of the engine's `apply_domain_reputation`
 * (which likewise only decorates, never re-scores). Its `(json, verdicts) => Promise<AnalysisOutput>`
 * signature matches the `apply` parameter App's `enrichAndCommit` expects, so it drops straight into
 * the reputation chain. Pure — parses a fresh copy and never mutates the input.
 */
export async function applyFileReputation(
  json: string,
  verdicts: Record<string, ReputationVerdict[]>,
): Promise<AnalysisOutput> {
  const out = JSON.parse(json) as AnalysisOutput;
  const files = out.summary.carved_files;
  if (files) {
    for (const f of files) {
      const vs = verdicts[f.sha256] ?? verdicts[f.sha256.toLowerCase()];
      if (vs?.length) f.reputation = vs;
    }
  }
  return out;
}
