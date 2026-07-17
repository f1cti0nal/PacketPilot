// AI consent flag, stored per-browser in localStorage. PacketPilot has no user accounts; the key
// still goes through storageScope (now a single "anon" namespace) so it stays isolated from any
// retired signed-in-era data. See lib/storageScope.
import { scopedKey } from "../storageScope";

export function aiConsentGiven(): boolean { return localStorage.getItem(scopedKey("pp.ai.consent")) === "1"; }
export function giveAiConsent(): void { localStorage.setItem(scopedKey("pp.ai.consent"), "1"); }
