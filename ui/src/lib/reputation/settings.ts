// Browser stores keys/proxy/flags in localStorage (the user's own machine). On desktop, KEYS go to
// the OS keychain via Tauri commands; enabled/consent stay in localStorage. Off by default.
const PROVIDERS = ["abuseipdb", "greynoise", "virustotal"] as const;
export type Provider = (typeof PROVIDERS)[number];

export { isTauri } from "../tauri-detect";

export function repEnabled(): boolean { return localStorage.getItem("pp.rep.enabled") === "1"; }
export function setRepEnabled(b: boolean): void { localStorage.setItem("pp.rep.enabled", b ? "1" : "0"); }
export function getProxyUrl(): string { return localStorage.getItem("pp.rep.proxyUrl") ?? ""; }
export function setProxyUrl(s: string): void { localStorage.setItem("pp.rep.proxyUrl", s); }
export function consentGiven(): boolean { return localStorage.getItem("pp.rep.consent") === "1"; }
export function giveConsent(): void { localStorage.setItem("pp.rep.consent", "1"); }

/** Browser-only key access. On desktop, keys live in the keychain — use the Tauri commands instead. */
export function getKey(provider: Provider): string { return localStorage.getItem(`pp.rep.key.${provider}`) ?? ""; }
export function setKey(provider: Provider, key: string): void { localStorage.setItem(`pp.rep.key.${provider}`, key); }
export function browserKeys(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const p of PROVIDERS) { const k = getKey(p); if (k) out[p] = k; }
  return out;
}
