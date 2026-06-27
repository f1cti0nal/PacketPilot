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
  /** Sum of every capture's total bytes on the wire. */
  totalBytes: number;
  /**
   * Distinct host IPs across the workspace, deduplicated by IP. Computed from the union of the
   * hosts each summary actually enumerates (top talkers, IP threats, ARP bindings, resolved IPs).
   * This is a true distinct count but a LOWER BOUND — it can't see hosts beyond those lists, since
   * the cached summaries don't carry the full per-capture host set (`unique_hosts` is only a count).
   */
  distinctHosts: number;
  /** Most recent analyzedAt (epoch ms) across the workspace, or null when empty. */
  lastAnalyzed: number | null;
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
  let totalBytes = 0;
  let totalFindings = 0;
  let criticalHigh = 0;
  let lastAnalyzed: number | null = null;
  const kindCaptures = new Map<string, number>();
  const hosts = new Set<string>();

  for (const e of entries) {
    totalFlows += e.flowCount ?? 0;
    if (lastAnalyzed === null || e.analyzedAt > lastAnalyzed) lastAnalyzed = e.analyzedAt;
    const s = e.summary.summary;
    totalBytes += s.total_bytes ?? 0;
    // Distinct hosts: union of every host IP the summary enumerates (deduped across captures).
    for (const t of s.top_talkers ?? []) hosts.add(t.ip);
    for (const t of s.ip_threats ?? []) hosts.add(t.ip);
    for (const a of s.arp_hosts ?? []) hosts.add(a.ip);
    for (const r of s.resolved_ips ?? []) hosts.add(r.ip);
    const findings = s.findings ?? [];
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
    totalBytes,
    distinctHosts: hosts.size,
    lastAnalyzed,
    totalFindings,
    criticalHigh,
    trend,
    trendRising,
    recurring,
  };
}

/** Workspace triage-review status, derived from per-host triage annotations. */
export interface ReviewStatus {
  /** Captures with at least one untriaged critical/high incident host. */
  capturesNeedingReview: number;
  /** Total untriaged critical/high hosts across the workspace. */
  untriagedHosts: number;
  /** The most-severe capture still needing review (for a "Review" shortcut), or null. */
  topCapture: RecentEntry | null;
}

/**
 * Cross-reference each capture's critical/high incident hosts against the analyst's triage
 * annotations to surface what still needs review. Pure: the caller supplies the set of already-
 * triaged hosts per capture (annotations live in localStorage; this stays testable + storage-free).
 */
export function reviewStatus(
  entries: RecentEntry[],
  triagedHostsOf: (entry: RecentEntry) => Set<string>,
): ReviewStatus {
  let capturesNeedingReview = 0;
  let untriagedHosts = 0;
  let top: { entry: RecentEntry; rank: number } | null = null;

  for (const entry of entries) {
    const triaged = triagedHostsOf(entry);
    const critHosts = new Set(
      (entry.summary.summary.incidents ?? [])
        .filter((i) => i.severity === "critical" || i.severity === "high")
        .map((i) => i.host),
    );
    let n = 0;
    for (const host of critHosts) if (!triaged.has(host)) n++;
    if (n === 0) continue;
    capturesNeedingReview++;
    untriagedHosts += n;
    const v = captureVerdict(entry.summary);
    const rank = SEV_RANK[v.worst] * 1000 + v.worstCount;
    if (!top || rank > top.rank) top = { entry, rank };
  }

  return { capturesNeedingReview, untriagedHosts, topCapture: top?.entry ?? null };
}
