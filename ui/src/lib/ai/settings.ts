export function aiConsentGiven(): boolean { return localStorage.getItem("pp.ai.consent") === "1"; }
export function giveAiConsent(): void { localStorage.setItem("pp.ai.consent", "1"); }
