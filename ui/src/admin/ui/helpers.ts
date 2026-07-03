// Pure, framework-free helpers for the admin UI kit. Kept out of the component
// files so the branchy bits (hashing, delta math, CSV escaping) are trivially
// unit-tested and stay comfortably inside the coverage gate.

/** Up to two uppercase initials, preferring a real name, falling back to email. */
export function initials(name: string | null | undefined, email?: string | null): string {
  const source = (name && name.trim()) || (email ? email.split("@")[0] : "") || "";
  const words = source.replace(/[._-]+/g, " ").trim().split(/\s+/).filter(Boolean);
  if (words.length === 0) return "?";
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  return (words[0][0] + words[words.length - 1][0]).toUpperCase();
}

// A small, fixed palette of solid backgrounds that all clear WCAG AA (>=4.5:1)
// against white text — so avatars read the same in light and dark themes without
// depending on the theme tokens.
const AVATAR_BGS = [
  "#6d5bd0", // violet
  "#2f6fed", // blue
  "#0f7a6b", // teal
  "#c0456b", // rose
  "#9a5b1b", // amber-brown
  "#4f52c9", // indigo
  "#2c7a5b", // green
  "#a24398", // magenta
] as const;

/** Deterministic avatar background for a seed (email/name). Stable across renders. */
export function avatarColor(seed: string | null | undefined): string {
  const s = seed ?? "";
  let hash = 0;
  for (let i = 0; i < s.length; i++) hash = (hash * 31 + s.charCodeAt(i)) | 0;
  return AVATAR_BGS[Math.abs(hash) % AVATAR_BGS.length];
}

export type TrendDir = "up" | "down" | "flat";
export interface Delta {
  /** Whole-number percent change, or null when it can't be computed honestly. */
  pct: number | null;
  dir: TrendDir;
}

/**
 * Percent change from `previous` to `current`, rounded to a whole number.
 * Returns pct=null when there is no honest basis (no prior data) rather than
 * fabricating a figure — matches the app's "never invent a metric" rule.
 */
export function pctDelta(current: number, previous: number): Delta {
  if (!Number.isFinite(current) || !Number.isFinite(previous)) return { pct: null, dir: "flat" };
  if (previous <= 0) {
    // No prior baseline: report direction only when something clearly appeared.
    if (current > 0) return { pct: null, dir: "up" };
    return { pct: 0, dir: "flat" };
  }
  const raw = ((current - previous) / previous) * 100;
  const pct = Math.round(raw);
  return { pct, dir: pct > 0 ? "up" : pct < 0 ? "down" : "flat" };
}

/**
 * Week-over-week delta from a daily-count series: sum of the most recent 7 days
 * vs the 7 before them. Needs >=8 points to have any prior week; otherwise null.
 */
export function weekOverWeek(counts: number[]): Delta {
  if (counts.length < 8) return { pct: null, dir: "flat" };
  const last7 = counts.slice(-7).reduce((a, b) => a + b, 0);
  const prev7 = counts.slice(-14, -7).reduce((a, b) => a + b, 0);
  return pctDelta(last7, prev7);
}

/** Clamp a numerator/denominator ratio to a 0–100 whole percent (0 when denom is 0). */
export function ratioPct(part: number, whole: number): number {
  if (!Number.isFinite(part) || !Number.isFinite(whole) || whole <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((part / whole) * 100)));
}

const csvCell = (v: unknown): string => {
  const s = v == null ? "" : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

/** Build an RFC-4180-ish CSV string from a header row + data rows. */
export function toCsv(headers: string[], rows: (string | number | null | undefined)[][]): string {
  const lines = [headers.map(csvCell).join(","), ...rows.map((r) => r.map(csvCell).join(","))];
  return lines.join("\r\n");
}
