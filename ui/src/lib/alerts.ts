// Pure helpers for the Smart Alerting queue: band vocabulary (order / labels / severity-token
// mapping for color reuse), priority-term formatting, and the actionable count that drives the
// Alerts tab badge. Dependency-free so it stays unit-testable.
import type { Alert, PriorityBand, ScoreTerm, Severity } from "../types";

/** Priority bands worst-first — the queue's display-order vocabulary. */
export const BAND_ORDER: PriorityBand[] = ["act_now", "investigate", "review", "log", "info"];

/** Human label per band. */
export const BAND_LABEL: Record<PriorityBand, string> = {
  act_now: "Act now",
  investigate: "Investigate",
  review: "Review",
  log: "Log",
  info: "Info",
};

/**
 * Band → severity token, so SeverityChip / sevColor can style band chips without any new
 * palette entries: act_now reuses the critical tint, investigate high, and so on.
 */
export const BAND_SEVERITY: Record<PriorityBand, Severity> = {
  act_now: "critical",
  investigate: "high",
  review: "medium",
  log: "low",
  info: "info",
};

/** Human label for a band, with the raw token as a fallback for unknown wire values. */
export function bandLabel(band: PriorityBand | string): string {
  return BAND_LABEL[band as PriorityBand] ?? String(band);
}

/** Worst-first rank (0 = act_now). Unknown tokens sort after every known band. */
export function bandRank(band: PriorityBand | string): number {
  const i = BAND_ORDER.indexOf(band as PriorityBand);
  return i === -1 ? BAND_ORDER.length : i;
}

/** Severity token used to color a band chip (falls back to "info" for unknown tokens). */
export function bandSeverity(band: PriorityBand | string): Severity {
  return BAND_SEVERITY[band as PriorityBand] ?? "info";
}

/** Render one priority-ledger term as "label (+N)" / "label (-N)" — the house `(±N)` idiom. */
export function formatTerm(t: ScoreTerm): string {
  return `${t.label} (${t.points >= 0 ? "+" : ""}${t.points})`;
}

/** Number of actionable alerts (band act_now or investigate) — the anti-noise badge count. */
export function actionableCount(alerts: Alert[]): number {
  return alerts.filter((a) => a.band === "act_now" || a.band === "investigate").length;
}
