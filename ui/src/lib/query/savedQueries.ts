/**
 * Named, saved SQL queries for the Query console — localStorage-persisted,
 * mirroring lib/filterProfiles.ts (scoped key, validate-on-read, merge-by-name
 * import, never throws).
 */

import { scopedKey } from "../storageScope";

export interface SavedQuery {
  id: string;
  name: string;
  sql: string;
}

const SAVED_QUERIES_BASE = "packetpilot.savedQueries.v1";
const queriesKey = () => scopedKey(SAVED_QUERIES_BASE);

/** Read the saved queries; any parse error yields an empty list (never throws). */
export function listSavedQueries(): SavedQuery[] {
  try {
    const raw = localStorage.getItem(queriesKey());
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isSavedQuery);
  } catch {
    return [];
  }
}

function persist(list: SavedQuery[]): void {
  try {
    localStorage.setItem(queriesKey(), JSON.stringify(list));
  } catch {
    /* quota or serialization error: drop silently, like filterProfiles.ts */
  }
}

function isSavedQuery(v: unknown): v is SavedQuery {
  if (typeof v !== "object" || v === null) return false;
  const q = v as Record<string, unknown>;
  if (typeof q.name !== "string" || q.name.trim() === "") return false;
  if (typeof q.sql !== "string" || q.sql.trim() === "") return false;
  return true;
}

/** Upsert a query by trimmed name; returns the new list. Id is 1:1 with the name. */
export function saveQuery(name: string, sql: string): SavedQuery[] {
  const trimmed = name.trim();
  if (trimmed === "" || sql.trim() === "") return listSavedQueries();
  const list = listSavedQueries().filter((q) => q.name !== trimmed);
  list.push({ id: `sq_${trimmed}`, name: trimmed, sql });
  persist(list);
  return list;
}

export function removeSavedQuery(id: string): SavedQuery[] {
  const list = listSavedQueries().filter((q) => q.id !== id);
  persist(list);
  return list;
}

export function clearSavedQueries(): SavedQuery[] {
  try {
    localStorage.removeItem(queriesKey());
  } catch {
    /* ignore */
  }
  return [];
}

/** JSON for export (the full saved-query array). */
export function serializeSavedQueries(): string {
  return JSON.stringify(listSavedQueries(), null, 2);
}

/** Import queries from JSON: validate each entry, merge by name. Never throws. */
export function importSavedQueries(json: string): {
  ok: boolean;
  queries: SavedQuery[];
  message: string;
} {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return { ok: false, queries: listSavedQueries(), message: "Not valid JSON" };
  }
  if (!Array.isArray(parsed)) {
    return { ok: false, queries: listSavedQueries(), message: "Expected a JSON array of queries" };
  }
  const incoming = parsed.filter(isSavedQuery);
  if (incoming.length === 0) {
    return { ok: false, queries: listSavedQueries(), message: "No valid queries in file" };
  }
  const byName = new Map(listSavedQueries().map((q) => [q.name, q]));
  for (const q of incoming) byName.set(q.name, { ...q, id: `sq_${q.name}` });
  const merged = [...byName.values()];
  persist(merged);
  return {
    ok: true,
    queries: merged,
    message: `Imported ${incoming.length} quer${incoming.length === 1 ? "y" : "ies"}`,
  };
}
