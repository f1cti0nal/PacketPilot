// Consent flags: stored in localStorage per-browser, namespaced to the signed-in account
// (storageScope) so one account never inherits another's authorization to send indicators offsite.
// Off by default. Enabled/config is read from admin rep_config via useAppSettings().rep.
import { scopedKey } from "../storageScope";

export function consentGiven(): boolean { return localStorage.getItem(scopedKey("pp.rep.consent")) === "1"; }
export function giveConsent(): void { localStorage.setItem(scopedKey("pp.rep.consent"), "1"); }

export function domainConsentGiven(): boolean { return localStorage.getItem(scopedKey("pp.rep.domain-consent")) === "1"; }
export function giveDomainConsent(): void { localStorage.setItem(scopedKey("pp.rep.domain-consent"), "1"); }

// Carved-file SHA-256 hashes are a distinct indicator class from domains, so they get their OWN
// consent — a domain-only "Proceed" must never silently authorize sending file hashes offsite.
export function fileConsentGiven(): boolean { return localStorage.getItem(scopedKey("pp.rep.file-consent")) === "1"; }
export function giveFileConsent(): void { localStorage.setItem(scopedKey("pp.rep.file-consent"), "1"); }
