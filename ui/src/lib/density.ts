// Layout density preference, persisted in localStorage. Pure helpers — mirrors theme.ts
// (never throws; a quota/parse error degrades to the comfortable default). A
// `packetpilot:density` window event is dispatched on every write so every mounted
// `useDensity` re-reads. The swap is a single `data-density` attribute on <html>:
// index.css redefines the --density-* spacing tokens under [data-density="compact"], so
// only the dashboard surfaces that reference those tokens tighten — text never changes.

export type Density = "comfortable" | "compact";

const KEY = "packetpilot.density.v1";
export const DENSITY_EVENT = "packetpilot:density";

const isDensity = (d: unknown): d is Density => d === "comfortable" || d === "compact";

/** The stored preference, or `null` if the user has never chosen one. */
export function getStoredDensity(): Density | null {
  try {
    const raw = localStorage.getItem(KEY);
    return isDensity(raw) ? raw : null;
  } catch {
    return null;
  }
}

/** The density to render: the stored preference, otherwise comfortable (the breathable default). */
export function resolveDensity(): Density {
  return getStoredDensity() ?? "comfortable";
}

/** Reflect `density` onto <html> via the `data-density` attribute. */
export function applyDensity(density: Density): void {
  try {
    document.documentElement.dataset.density = density;
  } catch {
    /* no document (SSR edge): ignore */
  }
}

/** Persist `density`, apply it, and notify every mounted `useDensity`. */
export function setDensity(density: Density): void {
  try {
    localStorage.setItem(KEY, density);
  } catch {
    /* quota/serialization error: drop silently, like theme.ts */
  }
  applyDensity(density);
  try {
    window.dispatchEvent(new CustomEvent(DENSITY_EVENT));
  } catch {
    /* no window (SSR/test edge): ignore */
  }
}
