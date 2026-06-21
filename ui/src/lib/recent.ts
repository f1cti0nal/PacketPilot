// Persistence for the "Recent captures" feature.
//
// Two tiers, by size:
//   • localStorage  — the recent LIST plus each entry's cached AnalysisOutput (summary/
//     stats). Small and synchronous, so the Recent tab and an instant dashboard restore
//     need no async round-trip.
//   • IndexedDB     — the cached normalized FlowRow[] per entry (large; keyed by entry id).
//     Loaded on demand when a capture is reopened, so the flows table is restored without
//     re-running the engine.
//
// Everything is best-effort: a quota error or a private-mode block degrades to "no cache"
// rather than throwing into the UI.

import type { AnalysisOutput, FlowRow, RecentEntry, RecentOrigin, ReputationVerdict } from "../types";
import { basename } from "./format";

const RECENT_KEY = "packetpilot.recent.v1";
const MAX_RECENT = 12;

const DB_NAME = "packetpilot";
const DB_VERSION = 2;
const FLOWS_STORE = "flows";
const REPUTATION_STORE = "reputation";

// ---------------------------------------------------------------------------
// localStorage: the recent list (with cached summaries)
// ---------------------------------------------------------------------------

/** Read the recent list, newest first. Never throws; returns [] on any problem. */
export function listRecent(): RecentEntry[] {
  try {
    const raw = localStorage.getItem(RECENT_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    // Drop anything that doesn't look like an entry (older/corrupt shapes).
    return parsed.filter(
      (e): e is RecentEntry =>
        !!e && typeof e === "object" && typeof (e as RecentEntry).id === "string",
    );
  } catch {
    return [];
  }
}

function persist(list: RecentEntry[]): void {
  try {
    localStorage.setItem(RECENT_KEY, JSON.stringify(list));
  } catch {
    // Quota exceeded: drop the oldest entry and retry once. The cached summaries are the
    // heavy part, so shedding one usually frees enough room.
    if (list.length > 1) {
      try {
        localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, -1)));
      } catch {
        /* give up silently — persistence is best-effort */
      }
    }
  }
}

export interface RecordRecentInput {
  id: string;
  name: string;
  path?: string;
  sizeBytes: number;
  sha256?: string;
  origin: RecentOrigin;
  summary: AnalysisOutput;
  flowCount: number;
  flowsCached: boolean;
  /** Defaults to now. Injectable for tests. */
  analyzedAt?: number;
}

/**
 * Insert or refresh an entry and return the new list (newest first, capped at
 * {@link MAX_RECENT}). An existing entry with the same id is replaced and moved to the
 * front. Trimmed-off entries have their cached flows pruned from IndexedDB.
 */
export function recordRecent(input: RecordRecentInput): RecentEntry[] {
  const entry: RecentEntry = {
    id: input.id,
    name: input.name,
    path: input.path,
    sizeBytes: input.sizeBytes,
    sha256: input.sha256,
    analyzedAt: input.analyzedAt ?? Date.now(),
    engineVersion: input.summary.engine_version,
    origin: input.origin,
    summary: input.summary,
    flowCount: input.flowCount,
    flowsCached: input.flowsCached,
  };
  const prev = listRecent().filter((e) => e.id !== entry.id);
  const next = [entry, ...prev];
  const trimmed = next.slice(0, MAX_RECENT);
  // Prune flows of entries that fell off the end.
  for (const dropped of next.slice(MAX_RECENT)) void deleteFlows(dropped.id);
  persist(trimmed);
  return trimmed;
}

/** Remove one entry (and its cached flows). Returns the new list. */
export function removeRecent(id: string): RecentEntry[] {
  const next = listRecent().filter((e) => e.id !== id);
  persist(next);
  void deleteFlows(id);
  return next;
}

/** Clear the whole list and every cached flow set. */
export function clearRecent(): RecentEntry[] {
  try {
    localStorage.removeItem(RECENT_KEY);
  } catch {
    /* ignore */
  }
  void clearAllFlows();
  return [];
}

/** Build a stable id: prefer the source hash, else a name+size+time digest. */
export function entryId(opts: {
  sha256?: string;
  name: string;
  sizeBytes: number;
  analyzedAt?: number;
}): string {
  if (opts.sha256) return `sha256:${opts.sha256}`;
  return `f:${opts.name}:${opts.sizeBytes}:${opts.analyzedAt ?? Date.now()}`;
}

/** SHA-256 (lowercase hex) of bytes via WebCrypto; null if unavailable (e.g. insecure ctx). */
export async function sha256Hex(bytes: ArrayBuffer): Promise<string | null> {
  try {
    if (!globalThis.crypto?.subtle) return null;
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  } catch {
    return null;
  }
}

/** Convenience: derive the display name from a path or a dropped file name. */
export function displayName(pathOrName: string): string {
  return basename(pathOrName);
}

// ---------------------------------------------------------------------------
// IndexedDB: the per-entry cached flows
// ---------------------------------------------------------------------------

let dbPromise: Promise<IDBDatabase | null> | null = null;

function openDb(): Promise<IDBDatabase | null> {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve) => {
    try {
      if (typeof indexedDB === "undefined") return resolve(null);
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(FLOWS_STORE)) {
          db.createObjectStore(FLOWS_STORE);
        }
        if (!db.objectStoreNames.contains(REPUTATION_STORE)) {
          db.createObjectStore(REPUTATION_STORE);
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
      req.onblocked = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
  return dbPromise;
}

function tx(
  db: IDBDatabase,
  mode: IDBTransactionMode,
): IDBObjectStore {
  return db.transaction(FLOWS_STORE, mode).objectStore(FLOWS_STORE);
}

/** Cache the normalized flows for an entry. Best-effort; resolves false on failure. */
export async function putFlows(id: string, rows: FlowRow[]): Promise<boolean> {
  const db = await openDb();
  if (!db) return false;
  return new Promise((resolve) => {
    try {
      const store = tx(db, "readwrite");
      const req = store.put(rows, id);
      req.onsuccess = () => resolve(true);
      req.onerror = () => resolve(false);
    } catch {
      resolve(false);
    }
  });
}

/** Read an entry's cached flows, or null if none/unavailable. */
export async function getFlows(id: string): Promise<FlowRow[] | null> {
  const db = await openDb();
  if (!db) return null;
  return new Promise((resolve) => {
    try {
      const store = tx(db, "readonly");
      const req = store.get(id);
      req.onsuccess = () => resolve((req.result as FlowRow[] | undefined) ?? null);
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

export async function deleteFlows(id: string): Promise<void> {
  const db = await openDb();
  if (!db) return;
  await new Promise<void>((resolve) => {
    try {
      const req = tx(db, "readwrite").delete(id);
      req.onsuccess = () => resolve();
      req.onerror = () => resolve();
    } catch {
      resolve();
    }
  });
}

async function clearAllFlows(): Promise<void> {
  const db = await openDb();
  if (!db) return;
  await new Promise<void>((resolve) => {
    try {
      const req = tx(db, "readwrite").clear();
      req.onsuccess = () => resolve();
      req.onerror = () => resolve();
    } catch {
      resolve();
    }
  });
}

// ---------------------------------------------------------------------------
// IndexedDB: per-indicator reputation cache
// ---------------------------------------------------------------------------

function repKey(source: string, indicator: string): string {
  return `${source}|${indicator}`;
}

/** Cache a reputation verdict. Best-effort; resolves false on failure. */
export async function putReputation(
  source: string,
  indicator: string,
  verdict: ReputationVerdict,
): Promise<boolean> {
  const db = await openDb();
  if (!db) return false;
  return new Promise((resolve) => {
    try {
      const store = db.transaction(REPUTATION_STORE, "readwrite").objectStore(REPUTATION_STORE);
      const req = store.put(verdict, repKey(source, indicator));
      req.onsuccess = () => resolve(true);
      req.onerror = () => resolve(false);
    } catch {
      resolve(false);
    }
  });
}

/** Read a cached reputation verdict, or null if absent, expired, or unavailable. */
export async function getReputation(
  source: string,
  indicator: string,
  now: number,
  ttlSecs: number,
): Promise<ReputationVerdict | null> {
  const db = await openDb();
  if (!db) return null;
  return new Promise((resolve) => {
    try {
      const store = db.transaction(REPUTATION_STORE, "readonly").objectStore(REPUTATION_STORE);
      const req = store.get(repKey(source, indicator));
      req.onsuccess = () => {
        const v = req.result as ReputationVerdict | undefined;
        if (v && now - v.fetched_at <= ttlSecs) resolve(v);
        else resolve(null);
      };
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}
