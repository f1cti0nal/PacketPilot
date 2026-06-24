// Per-host triage annotations (status + free-text note), persisted in localStorage per capture so
// an analyst's triage progress survives reloads. Pure CRUD — mirrors recent.ts / filterProfiles.ts
// (never throws; a quota/parse error degrades to "no annotations"). A `packetpilot:annotations`
// window event is dispatched on every write so any mounted `useAnnotation` re-reads.

/** Where a host sits in the analyst's triage workflow. */
export type TriageStatus = "new" | "investigating" | "cleared" | "escalated";

export const TRIAGE_STATUSES: TriageStatus[] = [
  "new",
  "investigating",
  "cleared",
  "escalated",
];

/** Display label + theme token per status. `new` is the implicit default (no badge). */
export const STATUS_META: Record<TriageStatus, { label: string; cssVar: string }> = {
  new: { label: "New", cssVar: "--color-text-faint" },
  investigating: { label: "Investigating", cssVar: "--color-accent" },
  cleared: { label: "Cleared", cssVar: "--color-sev-low" },
  escalated: { label: "Escalated", cssVar: "--color-sev-critical" },
};

export interface HostAnnotation {
  status: TriageStatus;
  note: string;
  /** Unix ms of the last edit. */
  updatedAt: number;
}

const KEY = "packetpilot.annotations.v1";
export const ANNOTATIONS_EVENT = "packetpilot:annotations";

/** `{ [captureKey]: { [ip]: HostAnnotation } }`. */
type Store = Record<string, Record<string, HostAnnotation>>;

function readStore(): Store {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as unknown;
    return parsed && typeof parsed === "object" ? (parsed as Store) : {};
  } catch {
    return {};
  }
}

function writeStore(store: Store): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(store));
  } catch {
    /* quota or serialization error: drop silently, like recent.ts */
  }
  try {
    window.dispatchEvent(new CustomEvent(ANNOTATIONS_EVENT));
  } catch {
    /* no window (SSR/test edge): ignore */
  }
}

const isStatus = (s: unknown): s is TriageStatus =>
  typeof s === "string" && (TRIAGE_STATUSES as string[]).includes(s);

/** The annotation for `(captureKey, ip)`, or `null` if none / untriaged. */
export function getAnnotation(captureKey: string, ip: string): HostAnnotation | null {
  const a = readStore()[captureKey]?.[ip];
  if (!a || !isStatus(a.status)) return null;
  return { status: a.status, note: typeof a.note === "string" ? a.note : "", updatedAt: a.updatedAt ?? 0 };
}

/** All annotations for a capture (`{ ip: HostAnnotation }`). */
export function annotationsForCapture(captureKey: string): Record<string, HostAnnotation> {
  return readStore()[captureKey] ?? {};
}

/**
 * Merge a status/note patch into `(captureKey, ip)`. An annotation that collapses back to the
 * default (`status: "new"` with an empty note) is removed entirely, so the store does not
 * accumulate no-op entries. Returns the resulting annotation (or `null` if cleared).
 */
export function setAnnotation(
  captureKey: string,
  ip: string,
  patch: Partial<Pick<HostAnnotation, "status" | "note">>,
  now: number = Date.now(),
): HostAnnotation | null {
  if (!captureKey || !ip) return null;
  const store = readStore();
  const forCapture = { ...(store[captureKey] ?? {}) };
  const prev = forCapture[ip];
  const status = patch.status ?? prev?.status ?? "new";
  const note = patch.note ?? prev?.note ?? "";

  if (status === "new" && note.trim() === "") {
    delete forCapture[ip];
    if (Object.keys(forCapture).length === 0) delete store[captureKey];
    else store[captureKey] = forCapture;
    writeStore(store);
    return null;
  }

  const next: HostAnnotation = { status, note, updatedAt: now };
  forCapture[ip] = next;
  store[captureKey] = forCapture;
  writeStore(store);
  return next;
}

/** Remove the annotation for `(captureKey, ip)`. */
export function clearAnnotation(captureKey: string, ip: string): void {
  setAnnotation(captureKey, ip, { status: "new", note: "" });
}
