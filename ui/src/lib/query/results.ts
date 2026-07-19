/**
 * Result-set presentation helpers shared by the ResultsGrid and CSV export:
 * one formatting rule per Arrow type so the grid and the exported file always
 * agree on what a value looks like.
 */

import type { QueryResult, QueryResultColumn } from "./engine";

/** True when this column holds timestamps (Arrow label e.g. "Timestamp<MICROSECOND, UTC>"). */
export function isTimestampColumn(col: QueryResultColumn): boolean {
  return /^timestamp/i.test(col.type);
}

/** "2025-07-19 04:40:00.000" (UTC) from an epoch-ms number (Arrow timestamp value). */
function formatTimestamp(ms: number): string {
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return String(ms);
  return d.toISOString().replace("T", " ").replace("Z", "");
}

/**
 * Display string for one result cell. NULL renders as "" for CSV; the grid
 * substitutes its own dim placeholder for empty strings on null values.
 */
export function formatCell(value: unknown, col: QueryResultColumn): string {
  if (value == null) return "";
  if (typeof value === "number" && isTimestampColumn(col)) return formatTimestamp(value);
  if (typeof value === "bigint" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (typeof value === "string") return value;
  // Exotic nested values (structs/lists) — render as JSON rather than [object Object].
  try {
    return JSON.stringify(value, (_k, v: unknown) => (typeof v === "bigint" ? v.toString() : v));
  } catch {
    return String(value);
  }
}

/** RFC-4180 CSV of the full result (header row + every materialized row). */
export function resultsToCsv(result: QueryResult): string {
  const escape = (s: string) => (/[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);
  const lines = [result.columns.map((c) => escape(c.name)).join(",")];
  for (const row of result.rows) {
    lines.push(row.map((v, i) => escape(formatCell(v, result.columns[i]))).join(","));
  }
  return lines.join("\n") + "\n";
}
