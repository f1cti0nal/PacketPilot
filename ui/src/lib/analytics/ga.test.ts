import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Each test imports a FRESH copy of ./ga (via resetModules + dynamic import) so the module-level
// `gaConfigured` / `loaded` state re-evaluates against the stubbed env.

const CONSENT_KEY = "packetpilot.analytics.consent.v1";

type Entry = IArguments & { [i: number]: unknown };
const pageViews = () =>
  ((window.dataLayer ?? []) as Entry[]).filter((a) => a[0] === "event" && a[1] === "page_view");

beforeEach(() => {
  localStorage.clear();
  vi.resetModules();
  delete (window as unknown as { dataLayer?: unknown }).dataLayer;
  delete (window as unknown as { gtag?: unknown }).gtag;
  document.head.innerHTML = "";
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("ga — configured", () => {
  beforeEach(() => {
    vi.stubEnv("VITE_GA_MEASUREMENT_ID", "G-TEST123");
  });

  it("reports configured and starts with no stored consent", async () => {
    const ga = await import("./ga");
    expect(ga.gaConfigured).toBe(true);
    expect(ga.getConsent()).toBeNull();
  });

  it("is inert until consent is granted (no script, no gtag, no page views)", async () => {
    const ga = await import("./ga");
    ga.initGa();
    ga.gaPageView("/app#flows");
    expect(window.gtag).toBeUndefined();
    expect(document.head.querySelector('script[src*="googletagmanager"]')).toBeNull();
    expect(window.dataLayer).toBeUndefined();
  });

  it("loads gtag.js and sends the entrance page view after consent is granted", async () => {
    const ga = await import("./ga");
    ga.grantConsent();
    expect(ga.getConsent()).toBe("granted");
    expect(typeof window.gtag).toBe("function");
    const script = document.head.querySelector<HTMLScriptElement>('script[src*="googletagmanager.com/gtag/js"]');
    expect(script).not.toBeNull();
    expect(script!.src).toContain("G-TEST123");
    expect(pageViews()).toHaveLength(1);
  });

  it("sends a page view per route and dedupes consecutive identical paths", async () => {
    const ga = await import("./ga");
    ga.grantConsent(); // entrance page view = 1
    ga.gaPageView("/app#flows");
    ga.gaPageView("/app#flows"); // deduped
    ga.gaPageView("/app#findings");
    expect(pageViews()).toHaveLength(3);
  });

  it("never carries capture-shaped data — only the exact token it is given", async () => {
    const ga = await import("./ga");
    ga.grantConsent();
    ga.gaPageView("/app#flows");
    const last = pageViews().at(-1)!;
    const payload = last[2] as Record<string, unknown>;
    expect(payload.page_path).toBe("/app#flows");
  });

  it("resumes on a returning visit when consent was previously granted", async () => {
    localStorage.setItem(CONSENT_KEY, "granted");
    const ga = await import("./ga");
    ga.initGaFromStoredConsent();
    expect(typeof window.gtag).toBe("function");
    expect(pageViews()).toHaveLength(1);
  });

  it("never loads GA when the visitor declined", async () => {
    const ga = await import("./ga");
    ga.denyConsent();
    ga.initGaFromStoredConsent();
    ga.initGa();
    expect(ga.getConsent()).toBe("denied");
    expect(window.gtag).toBeUndefined();
  });
});

describe("ga — unconfigured (no measurement id)", () => {
  beforeEach(() => {
    vi.stubEnv("VITE_GA_MEASUREMENT_ID", "");
  });

  it("is fully inert even if consent is somehow granted", async () => {
    const ga = await import("./ga");
    expect(ga.gaConfigured).toBe(false);
    ga.grantConsent();
    ga.initGaFromStoredConsent();
    expect(window.gtag).toBeUndefined();
    expect(document.head.querySelector('script[src*="googletagmanager"]')).toBeNull();
  });
});
