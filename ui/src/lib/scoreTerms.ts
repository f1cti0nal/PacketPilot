import type { ScoreTerm } from "../types";
export type { ScoreTerm };

/** Additive terms + non-additive annotations (clamp/floor) parsed from IpThreat.evidence. */
export interface ParsedScore {
  terms: ScoreTerm[];
  notes: string[];
}

/** Trailing "(+45)" / "(-10)" / "(+0)" — a bare signed integer in parens at end of string. */
const TERM_RE = /\(([+-]?\d+)\)\s*$/;

/**
 * Parse the engine's score evidence strings into additive {label, points} terms and
 * non-additive notes (the `clamp:`/`floor:` lines, which carry no bare `(±N)`). Never throws;
 * any string without a trailing signed-integer paren becomes a note.
 */
export function parseScoreTerms(evidence: string[] | undefined): ParsedScore {
  const terms: ScoreTerm[] = [];
  const notes: string[] = [];
  for (const raw of evidence ?? []) {
    const entry = typeof raw === "string" ? raw : String(raw);
    const m = entry.match(TERM_RE);
    if (m) {
      terms.push({ label: entry.slice(0, m.index).trim(), points: parseInt(m[1], 10) });
    } else {
      notes.push(entry);
    }
  }
  return { terms, notes };
}
