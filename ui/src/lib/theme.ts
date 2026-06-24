// Light/dark theme preference, persisted in localStorage. Pure helpers — mirrors
// annotations.ts (never throws; a quota/parse error degrades to the default theme).
// A `packetpilot:theme` window event is dispatched on every write so every mounted
// `useTheme` re-reads. The actual swap is a single `data-theme` attribute on <html>:
// component code only references `var(--color-*)`, which index.css redefines under
// `[data-theme="light"]`, so nothing else has to change.

export type Theme = "light" | "dark";

const KEY = "packetpilot.theme.v1";
export const THEME_EVENT = "packetpilot:theme";

/** The media query consulted when the user has no stored preference. */
export const PREFERS_LIGHT = "(prefers-color-scheme: light)";

const isTheme = (t: unknown): t is Theme => t === "light" || t === "dark";

/** The stored preference, or `null` if the user has never chosen one. */
export function getStoredTheme(): Theme | null {
  try {
    const raw = localStorage.getItem(KEY);
    return isTheme(raw) ? raw : null;
  } catch {
    return null;
  }
}

/** Does the OS explicitly prefer a light UI? Defaults to `false` when unknown. */
function prefersLight(): boolean {
  try {
    return !!window.matchMedia?.(PREFERS_LIGHT).matches;
  } catch {
    return false;
  }
}

/**
 * The theme to render: the stored preference if set, otherwise the OS preference,
 * otherwise dark (the cockpit's brand default — light is opt-in via the OS or toggle).
 */
export function resolveTheme(): Theme {
  return getStoredTheme() ?? (prefersLight() ? "light" : "dark");
}

/** Reflect `theme` onto <html> (`data-theme` + the legacy `dark` class). */
export function applyTheme(theme: Theme): void {
  try {
    const el = document.documentElement;
    el.dataset.theme = theme;
    el.classList.toggle("dark", theme === "dark");
  } catch {
    /* no document (SSR edge): ignore */
  }
}

/** Persist `theme`, apply it, and notify every mounted `useTheme`. */
export function setTheme(theme: Theme): void {
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    /* quota/serialization error: drop silently, like annotations.ts */
  }
  applyTheme(theme);
  try {
    window.dispatchEvent(new CustomEvent(THEME_EVENT));
  } catch {
    /* no window (SSR/test edge): ignore */
  }
}
