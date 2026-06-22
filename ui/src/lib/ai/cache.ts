import type { AiSummaryEntry } from "../../types";
import { openDb } from "../recent";

const STORE = "ai_summaries";

export async function putAiSummary(captureId: string, text: string, model: string, now: number): Promise<boolean> {
  const db = await openDb();
  if (!db) return false;
  return new Promise((resolve) => {
    try {
      const store = db.transaction(STORE, "readwrite").objectStore(STORE);
      const entry: AiSummaryEntry = { text, model, cached_at: now };
      const req = store.put(entry, captureId);
      req.onsuccess = () => resolve(true);
      req.onerror = () => resolve(false);
    } catch { resolve(false); }
  });
}

export async function getAiSummary(captureId: string): Promise<AiSummaryEntry | null> {
  const db = await openDb();
  if (!db) return null;
  return new Promise((resolve) => {
    try {
      const store = db.transaction(STORE, "readonly").objectStore(STORE);
      const req = store.get(captureId);
      req.onsuccess = () => resolve((req.result as AiSummaryEntry | undefined) ?? null);
      req.onerror = () => resolve(null);
    } catch { resolve(null); }
  });
}

/** Stable per-capture cache key. `source_sha256` is empty for browser/WASM-analyzed captures
 * (the wasm pass doesn't hash), so fall back to the source path. */
export function captureKey(output: { source_sha256: string; source_path: string }): string {
  return output.source_sha256 || output.source_path || "capture";
}
