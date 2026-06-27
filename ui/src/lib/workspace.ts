// Workspace-level rollups for the Home overview. Every stat is computed entirely from
// the cached per-capture summaries already held in the Recent list — no engine re-run,
// fully offline. Pure and dependency-light so it stays unit-testable.
import type { AnalysisOutput, Finding, Incident, RecentEntry, Severity } from "../types";
import { kindLabel } from "./findingKinds";

/** Severity rank for "which is worse" comparisons. Higher = more severe; "none" = nothing. */
const SEV_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  none: 0,
};

const worse = (a: Severity, b: Severity): Severity => (SEV_RANK[a] >= SEV_RANK[b] ? a : b);

/** The threat verdict for ONE capture, derived from its cached summary. */
export interface CaptureVerdict {
  /** Worst severity among the capture's incidents (or findings when uncorrelated); "none" if clean. */
  worst: Severity;
  /** How many incidents/findings sit at {@link worst} (0 when clean). */
  worstCount: number;
  /** Total behavioral findings in the capture. */
  findings: number;
  /** Weighted threat magnitude (Σ severity-rank over findings) — drives the trend sparkline. */
  threatScore: number;
}

/**
 * Reduce a capture's cached output to a single verdict. Prefers correlated incidents
 * (the dashboard's headline verdict) and falls back to raw findings when none exist.
 */
export function captureVerdict(output: AnalysisOutput): CaptureVerdict {
  const s = output.summary;
  const incidents: Incident[] = s.incidents ?? [];
  const findings: Finding[] = s.findings ?? [];
  const ranked: { severity: Severity }[] = incidents.length > 0 ? incidents : findings;

  let worst: Severity = "none";
  for (const r of ranked) worst = worse(worst, r.severity);
  const worstCount = worst === "none" ? 0 : ranked.filter((r) => r.severity === worst).length;
  const threatScore = findings.reduce((acc, fnd) => acc + (SEV_RANK[fnd.severity] ?? 0), 0);

  return { worst, worstCount, findings: findings.length, threatScore };
}

/** Default number of most-recent captures the trend sparkline spans. */
export const TREND_WINDOW = 8;

export interface RecurringThreat {
  kind: string;
  label: string;
  /** Number of distinct captures this finding kind appeared in. */
  captures: number;
}

/** Aggregate stats across every cached capture in the Recent list. */
export interface WorkspaceRollup {
  captures: number;
  totalFlows: number;
  totalFindings: number;
  /** Findings at critical or high severity, summed across all captures. */
  criticalHigh: number;
  /** Per-capture weighted threat score, oldest → newest, capped at {@link TREND_WINDOW}. */
  trend: number[];
  /** True when the newest capture in the trend window scores above the oldest. */
  trendRising: boolean;
  /** Finding kinds ranked by how many captures they recur in (top {@link maxRecurring}). */
  recurring: RecurringThreat[];
}

/**
 * Roll up the Recent list (newest-first) into workspace-wide stats for the Home overview.
 * Everything is read from each entry's cached {@link RecentEntry.summary} — offline, no re-analysis.
 */
export function workspaceRollup(entries: RecentEntry[], maxRecurring = 4): WorkspaceRollup {
  let totalFlows = 0;
  let totalFindings = 0;
  let criticalHigh = 0;
  const kindCaptures = new Map<string, number>();

  for (const e of entries) {
    totalFlows += e.flowCount ?? 0;
    const findings = e.summary.summary.findings ?? [];
    totalFindings += findings.length;
    criticalHigh += findings.filter(
      (fnd) => fnd.severity === "critical" || fnd.severity === "high",
    ).length;
    // Count each kind ONCE per capture so "recurring" measures spread across captures,
    // not raw volume within a single one.
    for (const k of new Set(findings.map((fnd) => fnd.kind))) {
      kindCaptures.set(k, (kindCaptures.get(k) ?? 0) + 1);
    }
  }

  // entries are newest-first; the trend reads left-to-right as oldest → newest.
  const chronological = [...entries].reverse();
  const trend = chronological
    .slice(-TREND_WINDOW)
    .map((e) => captureVerdict(e.summary).threatScore);
  const trendRising = trend.length >= 2 && trend[trend.length - 1] > trend[0];

  const recurring = [...kindCaptures.entries()]
    .map(([kind, captures]) => ({ kind, label: kindLabel(kind), captures }))
    .sort((a, b) => b.captures - a.captures || a.label.localeCompare(b.label))
    .slice(0, maxRecurring);

  return {
    captures: entries.length,
    totalFlows,
    totalFindings,
    criticalHigh,
    trend,
    trendRising,
    recurring,
  };
}
