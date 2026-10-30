// Guided hunt playbooks — per-capture checklist progress and the team playbook file, persisted in
// localStorage. Progress is keyed by capture and alert id, so ticking a step on one capture never
// leaks into another. The team file is stored as the exact JSON a team keeps in git (the engine's
// `PlaybookFile`), so export/import is a straight download/upload and `ppcap playbook --playbooks`
// reads the same file. Never throws: a quota/parse error degrades to "no progress" / "built-ins".

import type { PlaybookProgress, PlaybookRun, PlaybookStep } from "../types";
import { scopedKey } from "./storageScope";

const PROGRESS_BASE = "packetpilot.playbooks.progress.v1";
const TEAM_BASE = "packetpilot.playbooks.team.v1";
export const TEAM_PLAYBOOKS_EVENT = "packetpilot:playbooks";

/** Captures whose progress is kept; the oldest is dropped past this. */
const MAX_CAPTURES = 50;

type ProgressStore = Record<string, { at: number; alerts: Record<string, PlaybookProgress> }>;

export const emptyProgress = (): PlaybookProgress => ({ done: [], notes: {} });

/** The progress key for a step (matches the engine's `step_key`). */
export function stepKey(run: PlaybookRun, step: PlaybookStep): string {
  return `${run.playbook_id}/${step.id}`;
}

function readStore(): ProgressStore {
  try {
    const raw = localStorage.getItem(scopedKey(PROGRESS_BASE));
    const parsed = raw ? (JSON.parse(raw) as unknown) : null;
    return parsed && typeof parsed === "object" ? (parsed as ProgressStore) : {};
  } catch {
    return {};
  }
}

function writeStore(store: ProgressStore): void {
  try {
    localStorage.setItem(scopedKey(PROGRESS_BASE), JSON.stringify(store));
  } catch {
    /* quota: drop silently */
  }
}

/** The analyst's progress on one alert of one capture. */
export function loadProgress(captureKey: string, alertId: string): PlaybookProgress {
  const p = readStore()[captureKey]?.alerts?.[alertId];
  if (!p) return emptyProgress();
  return {
    done: Array.isArray(p.done) ? p.done.filter((d) => typeof d === "string") : [],
    notes: p.notes && typeof p.notes === "object" ? p.notes : {},
  };
}

/** Save progress for one alert; the least recently touched captures are dropped past the cap. */
export function saveProgress(captureKey: string, alertId: string, progress: PlaybookProgress, now = Date.now()): void {
  const store = readStore();
  const entry = store[captureKey] ?? { at: now, alerts: {} };
  entry.at = now;
  entry.alerts = { ...entry.alerts, [alertId]: progress };
  store[captureKey] = entry;
  const keys = Object.keys(store).sort((a, b) => (store[b].at ?? 0) - (store[a].at ?? 0));
  for (const k of keys.slice(MAX_CAPTURES)) delete store[k];
  writeStore(store);
}

/** Tick or untick a step. */
export function toggleDone(progress: PlaybookProgress, key: string): PlaybookProgress {
  const done = progress.done.includes(key) ? progress.done.filter((d) => d !== key) : [...progress.done, key];
  return { ...progress, done };
}

/** Set (or clear, when blank) a step's note. */
export function setNote(progress: PlaybookProgress, key: string, text: string): PlaybookProgress {
  const notes = { ...progress.notes };
  if (text.trim() === "") delete notes[key];
  else notes[key] = text;
  return { ...progress, notes };
}

/** The stored team playbook file text, or null when only the built-ins are in use. */
export function loadTeamPlaybooks(): string | null {
  try {
    return localStorage.getItem(scopedKey(TEAM_BASE));
  } catch {
    return null;
  }
}

/** Store (or, with null, remove) the team playbook file. The caller validates it first. */
export function saveTeamPlaybooks(text: string | null): void {
  try {
    if (text === null) localStorage.removeItem(scopedKey(TEAM_BASE));
    else localStorage.setItem(scopedKey(TEAM_BASE), text);
  } catch {
    /* quota: drop silently */
  }
  try {
    window.dispatchEvent(new CustomEvent(TEAM_PLAYBOOKS_EVENT));
  } catch {
    /* no window: ignore */
  }
}
