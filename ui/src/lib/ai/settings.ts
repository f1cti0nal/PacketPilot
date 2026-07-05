// Namespaced to the signed-in account (storageScope) so AI consent isn't inherited across accounts.
import { scopedKey } from "../storageScope";

export function aiConsentGiven(): boolean { return localStorage.getItem(scopedKey("pp.ai.consent")) === "1"; }
export function giveAiConsent(): void { localStorage.setItem(scopedKey("pp.ai.consent"), "1"); }
