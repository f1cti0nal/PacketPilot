// Google Analytics 4 (gtag.js) — opt-in, consent-gated, and fully inert unless
// VITE_GA_MEASUREMENT_ID is configured. This is the only third-party telemetry that touches
// the capture-analysis routes, so it is guarded twice:
//   (1) it no-ops when no measurement id is set (keeps CI, offline, self-host, and air-gapped
//       use clean — mirrors the `supabaseConfigured` pattern), and
//   (2) it loads and sends NOTHING to Google until the visitor explicitly grants consent
//       (hard opt-in; see ConsentBanner).
//
// PRIVACY INVARIANT: only allowlist-shaped route tokens (e.g. "/", "/app#flows") and standard
// gtag page metadata are ever sent. The app never places capture-derived data (IPs, hosts,
// hashes, payloads) in the URL, so a page path cannot carry it. Captures are never uploaded —
// GA sees site navigation only. Keep this true when adding routes.

const MEASUREMENT_ID = import.meta.env.VITE_GA_MEASUREMENT_ID;

/** True when a GA4 measurement id is configured at build time. When false, everything below no-ops. */
export const gaConfigured = Boolean(MEASUREMENT_ID);

const CONSENT_KEY = "packetpilot.analytics.consent.v1";
export type ConsentChoice = "granted" | "denied";

let loaded = false;
let lastPath: string | null = null;

type Gtag = (...args: unknown[]) => void;
declare global {
  interface Window {
    dataLayer?: unknown[];
    gtag?: Gtag;
  }
}

/** The visitor's stored consent choice, or null if they have not chosen yet. Failure-safe. */
export function getConsent(): ConsentChoice | null {
  try {
    const v = localStorage.getItem(CONSENT_KEY);
    return v === "granted" || v === "denied" ? v : null;
  } catch {
    return null;
  }
}

function storeConsent(choice: ConsentChoice): void {
  try {
    localStorage.setItem(CONSENT_KEY, choice);
  } catch {
    /* private mode / storage disabled — the choice simply won't persist across visits */
  }
}

/**
 * Load gtag.js and start GA. Idempotent, and a no-op unless a measurement id is configured AND
 * consent has been granted. Sends the entrance page view for the current URL.
 */
export function initGa(): void {
  if (loaded || !MEASUREMENT_ID || getConsent() !== "granted") return;
  if (typeof window === "undefined" || typeof document === "undefined") return;
  loaded = true;

  window.dataLayer = window.dataLayer || [];
  function gtag() {
    // gtag.js requires the raw `arguments` object on the dataLayer, not a normal array.
    // eslint-disable-next-line prefer-rest-params
    window.dataLayer!.push(arguments);
  }
  window.gtag = gtag as Gtag;

  const script = document.createElement("script");
  script.async = true;
  script.src = `https://www.googletagmanager.com/gtag/js?id=${MEASUREMENT_ID}`;
  document.head.appendChild(script);

  window.gtag("js", new Date());
  // We send one page_view per route ourselves (SPA hash tabs never trigger a document load),
  // so disable gtag's automatic initial page_view to avoid a duplicate.
  window.gtag("config", MEASUREMENT_ID, { send_page_view: false });

  gaPageView(window.location.pathname + window.location.hash);
}

/** Persist "granted" and start GA immediately (entrance page view included). */
export function grantConsent(): void {
  storeConsent("granted");
  initGa();
}

/** Persist "denied". GA is never loaded. */
export function denyConsent(): void {
  storeConsent("denied");
}

/** Start GA on a returning visit if a prior "granted" choice is stored. Call once at startup. */
export function initGaFromStoredConsent(): void {
  if (getConsent() === "granted") initGa();
}

/**
 * Send a GA4 page_view for an in-app route token. No-op until GA is loaded, and dedupes
 * consecutive identical paths (mirrors the first-party tracker).
 */
export function gaPageView(path: string): void {
  if (!loaded || !window.gtag || path === lastPath) return;
  lastPath = path;
  window.gtag("event", "page_view", {
    page_path: path,
    page_location: window.location.origin + path,
    page_title: document.title,
  });
}

/** Test-only: reset module state between cases. */
export function __resetGaForTests(): void {
  loaded = false;
  lastPath = null;
}
