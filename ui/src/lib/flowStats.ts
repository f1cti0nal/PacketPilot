// Aggregate stats over a set of flow rows — drives the Flows view's live filter-summary bar.
// Pure and dependency-free so it stays unit-testable.
import type { FlowRow } from "../types";

export interface FlowStats {
  flows: number;
  bytes: number;
  packets: number;
  /** Flows flagged as on a known indicator-of-compromise feed. */
  iocs: number;
  /** Categories present, ranked by flow count (top N). */
  topCategories: { category: string; flows: number }[];
}

export function flowStats(rows: FlowRow[], topN = 3): FlowStats {
  let bytes = 0;
  let packets = 0;
  let iocs = 0;
  const cats = new Map<string, number>();
  for (const r of rows) {
    bytes += r.bytesTotal;
    packets += r.pkts;
    if (r.ioc) iocs++;
    cats.set(r.category, (cats.get(r.category) ?? 0) + 1);
  }
  const topCategories = [...cats.entries()]
    .map(([category, flows]) => ({ category, flows }))
    .sort((a, b) => b.flows - a.flows || a.category.localeCompare(b.category))
    .slice(0, topN);
  return { flows: rows.length, bytes, packets, iocs, topCategories };
}
