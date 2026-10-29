// "Teach it once" — the analyst's suppression rule file, persisted in localStorage so a benign
// verdict taught on one capture applies to every later one. The stored value IS the shareable
// file format (`{ version, rules }`), so export/import is a straight download/upload and a team
// can keep the same JSON in git. Pure CRUD — mirrors annotations.ts (never throws; a quota/parse
// error degrades to "no rules"). A `packetpilot:suppressions` window event fires on every write.

import { useEffect, useState } from "react";
import type { SuppressionFile, SuppressionRule } from "../types";
import { scopedKey } from "./storageScope";

const SUPPRESSIONS_BASE = "packetpilot.suppressions.v1";
const suppressionsKey = () => scopedKey(SUPPRESSIONS_BASE);
export const SUPPRESSIONS_EVENT = "packetpilot:suppressions";

/** Days a newly taught rule stays active (matches the engine's DEFAULT_RULE_TTL_DAYS). */
export const DEFAULT_RULE_TTL_DAYS = 90;

export const SUPPRESSION_FILE_VERSION = 1;

const emptyFile = (): SuppressionFile => ({ version: SUPPRESSION_FILE_VERSION, rules: [] });

const isRule = (r: unknown): r is SuppressionRule =>
  !!r &&
  typeof r === "object" &&
  typeof (r as SuppressionRule).kind === "string" &&
  (r as SuppressionRule).kind.trim() !== "";

/**
 * Parse a suppression file's JSON text. Throws a readable error on anything that is not a
 * `{ rules: [...] }` object; individual malformed rules (no kind) are dropped. Missing ids and
 * reasons are filled with "" — the engine derives the id from the match fields on apply.
 */
export function parseSuppressionFile(text: string): SuppressionFile {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("Not a JSON file");
  }
  if (!parsed || typeof parsed !== "object" || !Array.isArray((parsed as SuppressionFile).rules)) {
    throw new Error('Not a suppression file: expected { "rules": [...] }');
  }
  const rules = (parsed as SuppressionFile).rules.filter(isRule).map((r) => ({
    ...r,
    id: typeof r.id === "string" ? r.id : "",
    reason: typeof r.reason === "string" ? r.reason : "",
  }));
  return { version: SUPPRESSION_FILE_VERSION, rules };
}

/** The stored rule file (an empty file when none / unreadable). */
export function loadSuppressions(): SuppressionFile {
  try {
    const raw = localStorage.getItem(suppressionsKey());
    if (!raw) return emptyFile();
    return parseSuppressionFile(raw);
  } catch {
    return emptyFile();
  }
}

function saveSuppressions(file: SuppressionFile): void {
  try {
    localStorage.setItem(suppressionsKey(), JSON.stringify(file));
  } catch {
    /* quota or serialization error: drop silently, like annotations.ts */
  }
  try {
    window.dispatchEvent(new CustomEvent(SUPPRESSIONS_EVENT));
  } catch {
    /* no window (SSR/test edge): ignore */
  }
}

/** Identity used for de-duplication: the engine id when present, else the match fields. */
function ruleKey(r: SuppressionRule): string {
  if (r.id) return r.id;
  return [r.kind, r.src ?? "*", r.dst ?? "*", r.dst_port ?? "*"].join("|");
}

/**
 * Append rules, keeping existing ones (and their metadata) on an id clash — the same merge the
 * CLI's `ppcap suppress add` does. Returns how many were actually added.
 */
export function addSuppressionRules(rules: SuppressionRule[]): number {
  const file = loadSuppressions();
  const have = new Set(file.rules.map(ruleKey));
  let added = 0;
  for (const r of rules) {
    const k = ruleKey(r);
    if (have.has(k)) continue;
    have.add(k);
    file.rules.push(r);
    added += 1;
  }
  if (added > 0) saveSuppressions(file);
  return added;
}

/**
 * Delete a rule: every stored rule with its id or the same match fields (so a rule the engine
 * normalized — e.g. an imported one without an id — still finds its stored original).
 */
export function removeSuppressionRule(rule: SuppressionRule): void {
  const file = loadSuppressions();
  const key = matchKey(rule);
  const next = file.rules.filter((r) => !((rule.id && r.id === rule.id) || matchKey(r) === key));
  if (next.length !== file.rules.length) saveSuppressions({ ...file, rules: next });
}

/** Merge an imported file into the stored one. Returns how many rules were new. */
export function importSuppressions(text: string): number {
  return addSuppressionRules(parseSuppressionFile(text).rules);
}

/** The stored file as pretty JSON — byte-compatible with `ppcap analyze --suppress`. */
export function exportSuppressions(): string {
  return `${JSON.stringify(loadSuppressions(), null, 2)}\n`;
}

/** `YYYY-MM-DD` (UTC) for a Date — the date form rule files use. */
export function ymd(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/** `YYYY-MM-DD` `days` after `d`. */
export function ymdPlusDays(d: Date, days: number): string {
  return ymd(new Date(d.getTime() + days * 86_400_000));
}

/** Whether a rule's `expires` date is before `today` (`YYYY-MM-DD`; `""` = nothing expires). */
export function isExpired(rule: SuppressionRule, today: string): boolean {
  return !!rule.expires && rule.expires < today;
}

const normHost = (h: string | undefined): string => {
  const t = (h ?? "").trim();
  return t === "" || t === "*" || t.toLowerCase() === "any" ? "*" : t;
};

/** The match fields, normalized the way the engine normalizes them (ids play no part). */
function matchKey(r: SuppressionRule): string {
  return [r.kind.trim().toLowerCase(), normHost(r.src), normHost(r.dst), r.dst_port ?? "*"].join("|");
}

/**
 * Signature of a rule set's effective, unexpired rules: the first rule per match key, in order,
 * with the provenance a suppression hit displays (reason, author, expiry). Comparing the stored
 * file's signature with the one a summary carries tells whether the summary's queue — and the
 * reasons shown on its suppressed findings — already reflect the stored rules.
 */
export function rulesSignature(rules: SuppressionRule[] | undefined, today: string): string {
  const seen = new Set<string>();
  const parts: string[] = [];
  for (const r of rules ?? []) {
    if (isExpired(r, today)) continue;
    const key = matchKey(r);
    if (seen.has(key)) continue;
    seen.add(key);
    parts.push(JSON.stringify([key, r.reason.trim(), r.author ?? "", r.expires ?? ""]));
  }
  return parts.join(",");
}

/** Live view of the stored rule file; re-reads on every write (any tab/component). */
export function useSuppressions(): SuppressionFile {
  const [file, setFile] = useState<SuppressionFile>(() => loadSuppressions());
  useEffect(() => {
    const reload = () => setFile(loadSuppressions());
    window.addEventListener(SUPPRESSIONS_EVENT, reload);
    window.addEventListener("storage", reload);
    return () => {
      window.removeEventListener(SUPPRESSIONS_EVENT, reload);
      window.removeEventListener("storage", reload);
    };
  }, []);
  return file;
}
