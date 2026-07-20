// AI consent flag, stored per-browser in localStorage. PacketPilot has no user accounts; the key
// still goes through storageScope (now a single "anon" namespace) so it stays isolated from any
// retired signed-in-era data. See lib/storageScope.
import { scopedKey } from "../storageScope";

export function aiConsentGiven(): boolean { return localStorage.getItem(scopedKey("pp.ai.consent")) === "1"; }
export function giveAiConsent(): void { localStorage.setItem(scopedKey("pp.ai.consent"), "1"); }

/**
 * DISTINCT consent class for the Query console's "Interpret" action: it sends
 * capture-derived RESULT ROWS (a capped preview) to the AI provider, which the
 * general AI consent above never authorizes. Never merge the two flags.
 */
export function aiResultsConsentGiven(): boolean { return localStorage.getItem(scopedKey("pp.ai.resultsConsent")) === "1"; }
export function giveAiResultsConsent(): void { localStorage.setItem(scopedKey("pp.ai.resultsConsent"), "1"); }
