import type { Severity } from "../types";

/** The persisted subset of FlowsView filter state. */
export interface FlowFilter {
  query: string;
  category: string;
  severity?: Severity;
  proto?: number;
}

/** A named, saved filter set. */
export interface FilterProfile {
  id: string;
  name: string;
  filter: FlowFilter;
}

const KEY = "packetpilot.filterProfiles.v1";

/** Read the saved profiles; any parse error yields an empty list (never throws). */
export function listProfiles(): FilterProfile[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isProfile);
  } catch {
    return [];
  }
}

function persist(list: FilterProfile[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(list));
  } catch {
    /* quota or serialization error: drop silently, like recent.ts */
  }
}

/** Validate an unknown value as a FilterProfile (name non-empty, filter shape sound). */
function isProfile(v: unknown): v is FilterProfile {
  if (typeof v !== "object" || v === null) return false;
  const p = v as Record<string, unknown>;
  if (typeof p.name !== "string" || p.name.trim() === "") return false;
  const fl = p.filter as Record<string, unknown> | undefined;
  if (typeof fl !== "object" || fl === null) return false;
  if (typeof fl.query !== "string" || typeof fl.category !== "string") return false;
  return true;
}

/** Upsert a profile by trimmed name; returns the new list. */
export function saveProfile(name: string, filter: FlowFilter): FilterProfile[] {
  const trimmed = name.trim();
  if (trimmed === "") return listProfiles();
  const list = listProfiles().filter((p) => p.name !== trimmed);
  // id is 1:1 with the (unique) name, NOT a lossy slug — slugging let 'DNS' and 'dns'
  // collide on one id, so removeProfile deleted both and React keys duplicated. Mirrors
  // ruleSets.ts (rs_<rawName>).
  list.push({ id: `fp_${trimmed}`, name: trimmed, filter });
  persist(list);
  return list;
}

export function removeProfile(id: string): FilterProfile[] {
  const list = listProfiles().filter((p) => p.id !== id);
  persist(list);
  return list;
}

export function clearProfiles(): FilterProfile[] {
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
  return [];
}

/** JSON for export (the full profile array). */
export function serializeProfiles(): string {
  return JSON.stringify(listProfiles(), null, 2);
}

/** Import profiles from JSON: validate each entry, merge by name into the store. Never throws. */
export function importProfiles(json: string): { ok: boolean; profiles: FilterProfile[]; message: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return { ok: false, profiles: listProfiles(), message: "Not valid JSON" };
  }
  if (!Array.isArray(parsed)) {
    return { ok: false, profiles: listProfiles(), message: "Expected a JSON array of profiles" };
  }
  const incoming = parsed.filter(isProfile);
  if (incoming.length === 0) {
    return { ok: false, profiles: listProfiles(), message: "No valid profiles in file" };
  }
  const byName = new Map(listProfiles().map((p) => [p.name, p]));
  for (const p of incoming) byName.set(p.name, p);
  const merged = [...byName.values()];
  persist(merged);
  return { ok: true, profiles: merged, message: `Imported ${incoming.length} profile${incoming.length === 1 ? "" : "s"}` };
}
