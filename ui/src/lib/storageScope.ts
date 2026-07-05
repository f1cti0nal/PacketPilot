// Per-account namespacing for browser-local persistence.
//
// PacketPilot keeps capture analysis, recent captures, annotations, saved filters/rule sets and
// consent flags in localStorage + IndexedDB — all on the DEVICE, never the backend. But a browser
// profile is shared across accounts: sign out of account A and into account B on the same PC and,
// without namespacing, B reads A's stores (A's captures, A's analysis). That is a cross-account
// data leak.
//
// This module holds the CURRENT account scope. Storage modules derive their keys/DB names from it
// via `scopedKey`/`scopedDbName`, so each account gets an isolated namespace. `useSession` sets the
// scope from the signed-in user id (before <App/> mounts, since AppGate gates on an authed session)
// and clears it on sign-out. Offline / self-host / public-demo builds have no accounts → the single
// "anon" scope, which is still isolated from the orphaned pre-namespacing ("legacy") stores.

type Listener = () => void;

const ANON = "anon";
let scope = ANON;
const listeners = new Set<Listener>();

/** The current scope token (`u_<userId>` when signed in, else `anon`). */
export function getStorageScope(): string {
  return scope;
}

/**
 * Set the active account scope. Pass the signed-in user id, or null for signed-out/anon. Notifies
 * subscribers when it actually changes so live state (e.g. the Recent list) can reload under the
 * new namespace.
 */
export function setStorageScope(userId: string | null): void {
  const next = userId ? `u_${userId}` : ANON;
  if (next === scope) return;
  scope = next;
  for (const l of listeners) {
    try {
      l();
    } catch {
      /* a listener must not break scope propagation */
    }
  }
}

/** Subscribe to scope changes. Returns an unsubscribe fn. */
export function onStorageScopeChange(l: Listener): () => void {
  listeners.add(l);
  return () => {
    listeners.delete(l);
  };
}

/** A localStorage key namespaced to the current account: `<base>::<scope>`. */
export function scopedKey(base: string): string {
  return `${base}::${scope}`;
}

/** An IndexedDB database name namespaced to the current account: `<base>__<scope>`. */
export function scopedDbName(base: string): string {
  return `${base}__${scope}`;
}

// ---------------------------------------------------------------------------
// One-time cleanup of pre-namespacing ("legacy") stores.
//
// Before namespacing, everything lived under bare keys (`packetpilot.recent.v1`, the `packetpilot`
// IndexedDB, …). After this change nothing reads those bare names (every scope, including anon,
// appends a suffix), so that data is orphaned — but it's still the leaked data sitting on disk.
// Purge it once so a shared machine doesn't retain one account's captures. This is unavoidably
// destructive of pre-upgrade cached recents (they can't be attributed to an account), which is the
// privacy-safe outcome.
// ---------------------------------------------------------------------------

const LEGACY_LOCALSTORAGE_KEYS = [
  "packetpilot.recent.v1",
  "packetpilot.annotations.v1",
  "packetpilot.filterProfiles.v1",
  "packetpilot.ruleSets.v1",
  "pp.rep.consent",
  "pp.rep.domain-consent",
  "pp.rep.file-consent",
  "pp.ai.consent",
];
const LEGACY_DB_NAME = "packetpilot";
const LEGACY_PURGED_FLAG = "pp.legacyPurged.v1";

/** Best-effort, idempotent purge of the orphaned pre-namespacing stores. Safe to call on startup. */
export function purgeLegacyGlobalStores(): void {
  try {
    if (typeof localStorage === "undefined") return;
    if (localStorage.getItem(LEGACY_PURGED_FLAG) === "1") return;
    for (const k of LEGACY_LOCALSTORAGE_KEYS) {
      try {
        localStorage.removeItem(k);
      } catch {
        /* ignore */
      }
    }
    localStorage.setItem(LEGACY_PURGED_FLAG, "1");
  } catch {
    /* ignore */
  }
  try {
    if (typeof indexedDB !== "undefined") indexedDB.deleteDatabase(LEGACY_DB_NAME);
  } catch {
    /* ignore */
  }
}
