import type { Severity } from "../types";
import { SEVERITY_META } from "./severity";

/** Read a CSS custom property off :root (for Recharts, which needs literal colors). */
export function cssVar(name: string, fallback = "#888"): string {
  if (typeof window === "undefined") return fallback;
  const v = getComputedStyle(document.documentElement)
    .getPropertyValue(name)
    .trim();
  return v || fallback;
}

/** Resolve the literal color for a severity level. */
export function severityColor(sev: Severity): string {
  return cssVar(SEVERITY_META[sev].cssVar);
}

/** Common chart palette resolved from CSS tokens. */
export function chartPalette() {
  return {
    grid: cssVar("--color-grid", "#1e2733"),
    axis: cssVar("--color-border", "#243042"),
    text: cssVar("--color-text-dim", "#94a3b8"),
    accent: cssVar("--color-accent", "#38bdf8"),
    sev: {
      critical: cssVar("--color-sev-critical", "#f43f5e"),
      high: cssVar("--color-sev-high", "#fb923c"),
      medium: cssVar("--color-sev-medium", "#fbbf24"),
      low: cssVar("--color-sev-low", "#2dd4bf"),
      info: cssVar("--color-sev-info", "#38bdf8"),
      none: cssVar("--color-sev-none", "#64748b"),
    },
  };
}
