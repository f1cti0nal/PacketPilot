// Browser-local persistence + learn/compare glue for Behavioral Baseline Learning.
//
// The baseline profile is a small JSON sidecar kept in localStorage (namespaced per account, on the
// DEVICE — nothing leaves the page, mirroring the local-first engine). Learning folds a completed
// analysis into it via the wasm engine; comparing re-runs the pure engine transform to fold
// `baseline_deviation` findings into an analysis output.

import type { AnalysisOutput, BaselineProfile } from "../types";
import { scopedKey } from "./storageScope";
import { buildBaselineViaWasm, compareToBaselineViaWasm } from "./wasmEngine";

const KEY = "packetpilot.baseline.v1";

/** Load the saved baseline profile, or `null` if none / unreadable. */
export function loadBaseline(): BaselineProfile | null {
  try {
    if (typeof localStorage === "undefined") return null;
    const raw = localStorage.getItem(scopedKey(KEY));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as BaselineProfile;
    return Array.isArray(parsed.hosts) ? parsed : null;
  } catch {
    return null;
  }
}

/** Persist the baseline profile (best-effort; quota / private-mode failures are swallowed). */
export function saveBaseline(profile: BaselineProfile): void {
  try {
    if (typeof localStorage === "undefined") return;
    localStorage.setItem(scopedKey(KEY), JSON.stringify(profile));
  } catch {
    /* ignore quota / private-mode failures */
  }
}

/** Delete the saved baseline (a clean reset — e.g. after a suspected poisoning). */
export function clearBaseline(): void {
  try {
    if (typeof localStorage === "undefined") return;
    localStorage.removeItem(scopedKey(KEY));
  } catch {
    /* ignore */
  }
}

/** Whether a baseline exists in local storage. */
export function hasBaseline(): boolean {
  return loadBaseline() !== null;
}

/**
 * Fold a completed analysis into the saved baseline (create-or-merge) and persist it. Returns the
 * updated profile. The capture must carry a snapshot (`output.baseline`) — otherwise the prior
 * profile is returned unchanged.
 */
export async function learnFromOutput(output: AnalysisOutput): Promise<BaselineProfile> {
  const prior = loadBaseline();
  const nowSecs = Math.floor(Date.now() / 1000);
  const updated = await buildBaselineViaWasm(output, prior, nowSecs);
  saveBaseline(updated);
  return updated;
}

/**
 * Compare a completed analysis against the saved baseline, returning an output with
 * `baseline_deviation` findings folded in. Returns the output unchanged when no baseline is saved.
 */
export async function compareWithBaseline(output: AnalysisOutput): Promise<AnalysisOutput> {
  const base = loadBaseline();
  if (!base) return output;
  return compareToBaselineViaWasm(output, base);
}

/**
 * Remove one host from the baseline (e.g. a host you now believe was compromised and don't want
 * treated as "normal"). Returns the updated profile, or `null` if there was no baseline.
 */
export function forgetHost(host: string): BaselineProfile | null {
  const base = loadBaseline();
  if (!base) return null;
  const next: BaselineProfile = { ...base, hosts: base.hosts.filter((h) => h.host !== host) };
  saveBaseline(next);
  return next;
}
