// Consent flags: stored in localStorage per-browser (the user's own machine). Off by default.
// Enabled/config is now read from admin rep_config via useAppSettings().rep.
export function consentGiven(): boolean { return localStorage.getItem("pp.rep.consent") === "1"; }
export function giveConsent(): void { localStorage.setItem("pp.rep.consent", "1"); }

export function domainConsentGiven(): boolean { return localStorage.getItem("pp.rep.domain-consent") === "1"; }
export function giveDomainConsent(): void { localStorage.setItem("pp.rep.domain-consent", "1"); }
