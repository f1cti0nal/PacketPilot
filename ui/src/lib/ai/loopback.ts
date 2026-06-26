import { isTauri } from "../tauri-detect";

// The browser AI relay URL key (mirrors ai/settings.ts). Kept as a literal here so this module —
// imported by run.ts AND several components — has no dependency on the often-mocked settings module.
const PROXY_KEY = "pp.ai.proxyUrl";

/**
 * True ONLY for genuine loopback hosts, matched on the exact parsed hostname (never a prefix).
 *
 * Direct, relay-free browser egress is allowed only to loopback; a prefix match would let
 * `http://localhost.evil.com` / `http://127.0.0.1.attacker.io` masquerade as local and exfiltrate
 * the analysis summary + API key. Shared by `pickTransport` (transport selection) and `AiConsent`
 * (the "stays on this device" reassurance) so the two can never drift apart.
 */
export function isLoopbackUrl(url: string): boolean {
  try {
    const host = new URL(url).hostname.toLowerCase();
    return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
  } catch {
    return false; // unparseable → not local
  }
}

/**
 * UI guidance predicate: in the browser, a non-loopback ("cloud") endpoint with no relay configured
 * will fail at egress (a browser can't stream cross-origin to a provider without exposing the key).
 * Reads the proxy key directly (no `settings` import) so it works in every component test without
 * extra mocking. Desktop (Tauri) never needs a relay.
 */
export function aiNeedsRelay(baseUrl: string): boolean {
  if (isTauri()) return false;
  let proxy = "";
  try {
    proxy = (localStorage.getItem(PROXY_KEY) ?? "").trim();
  } catch {
    proxy = ""; // no storage (SSR/headless) → treat as unset
  }
  return proxy === "" && !isLoopbackUrl(baseUrl);
}
