import type { Severity, CategoryBreakdownEntry } from "../types";

/** Unify kebab (summary) + snake (parquet) to snake. "file-transfer"->"file_transfer". */
export const normCategory = (c: string): string =>
  c.trim().toLowerCase().replace(/[-\s]+/g, "_");

const CATEGORY_SEVERITY: Record<string, Severity> = {
  c2: "critical",
  anomalous: "critical", // CRITICAL — active compromise
  scan: "high", // HIGH — strongly suspicious
  tunnel_vpn: "medium",
  remote_access: "medium", // MEDIUM — egress of interest
  web: "info",
  dns: "info",
  email: "info",
  file_transfer: "info",
  voip: "info",
  iot_ot: "info", // INFO — ordinary traffic
  unknown: "none", // NONE — uncategorized
};

export function severityForCategory(category: string): Severity {
  return CATEGORY_SEVERITY[normCategory(category)] ?? "none";
}

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export const SEVERITY_META: Record<Severity, { label: string; cssVar: string }> = {
  critical: { label: "Critical", cssVar: "--color-sev-critical" },
  high: { label: "High", cssVar: "--color-sev-high" },
  medium: { label: "Medium", cssVar: "--color-sev-medium" },
  low: { label: "Low", cssVar: "--color-sev-low" },
  info: { label: "Info", cssVar: "--color-sev-info" },
  none: { label: "Uncategorized", cssVar: "--color-sev-none" },
};

export interface SeverityRollup {
  bySeverity: Record<
    Severity,
    { flows: number; pkts: number; bytes: number; categories: string[] }
  >;
  total: { flows: number; pkts: number; bytes: number };
}

export function rollupSeverity(
  breakdown: CategoryBreakdownEntry[],
): SeverityRollup {
  const empty = () => ({
    flows: 0,
    pkts: 0,
    bytes: 0,
    categories: [] as string[],
  });
  const bySeverity = Object.fromEntries(
    SEVERITY_ORDER.map((s) => [s, empty()]),
  ) as SeverityRollup["bySeverity"];
  const total = { flows: 0, pkts: 0, bytes: 0 };
  for (const e of breakdown) {
    const sev = severityForCategory(e.category);
    const b = bySeverity[sev];
    b.flows += e.flows;
    b.pkts += e.pkts;
    b.bytes += e.bytes;
    if (e.flows > 0) b.categories.push(normCategory(e.category));
    total.flows += e.flows;
    total.pkts += e.pkts;
    total.bytes += e.bytes;
  }
  return { bySeverity, total };
}
