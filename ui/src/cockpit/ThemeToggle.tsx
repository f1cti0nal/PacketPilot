import { useCallback, useEffect, useState } from "react";
import { Sun, Moon } from "lucide-react";
import {
  resolveTheme,
  applyTheme,
  setTheme,
  THEME_EVENT,
  PREFERS_LIGHT,
  type Theme,
} from "../lib/theme";

/**
 * The active theme plus a toggle, kept in sync across every mounted instance via the
 * `THEME_EVENT` window event (and cross-tab `storage` events). When the user has not made an
 * explicit choice, it also follows live OS `prefers-color-scheme` changes.
 */
export function useTheme(): readonly [Theme, () => void] {
  const [theme, setThemeState] = useState<Theme>(() => resolveTheme());

  useEffect(() => {
    const sync = () => setThemeState(resolveTheme());
    sync();
    let mql: MediaQueryList | undefined;
    try {
      mql = window.matchMedia?.(PREFERS_LIGHT);
    } catch {
      mql = undefined;
    }
    window.addEventListener(THEME_EVENT, sync);
    window.addEventListener("storage", sync);
    mql?.addEventListener?.("change", sync);
    return () => {
      window.removeEventListener(THEME_EVENT, sync);
      window.removeEventListener("storage", sync);
      mql?.removeEventListener?.("change", sync);
    };
  }, []);

  // Keep <html data-theme> truthful even if the pre-paint bootstrap never ran (e.g. tests).
  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const toggle = useCallback(() => {
    setTheme(resolveTheme() === "dark" ? "light" : "dark");
  }, []);

  return [theme, toggle] as const;
}

/** Sun/moon button that flips the global light/dark theme. */
export function ThemeToggle() {
  const [theme, toggle] = useTheme();
  const isDark = theme === "dark";
  return (
    <button
      type="button"
      data-component="ThemeToggle"
      onClick={toggle}
      aria-label={isDark ? "Switch to light theme" : "Switch to dark theme"}
      aria-pressed={!isDark}
      title={isDark ? "Switch to light theme" : "Switch to dark theme"}
      className="inline-flex items-center justify-center rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] p-1.5 text-[var(--color-text-faint)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text-dim)]"
    >
      {isDark ? <Sun size={14} aria-hidden /> : <Moon size={14} aria-hidden />}
    </button>
  );
}

export default ThemeToggle;
