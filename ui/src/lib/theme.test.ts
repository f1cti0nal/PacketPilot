import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  getStoredTheme,
  resolveTheme,
  applyTheme,
  setTheme,
  THEME_EVENT,
} from "./theme";

const realMatchMedia = window.matchMedia;

/** Stub matchMedia so `(prefers-color-scheme: light)` reports `light`. */
function stubPrefers(light: boolean) {
  window.matchMedia = ((query: string) =>
    ({
      matches: light && query.includes("light"),
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }) as unknown as MediaQueryList) as typeof window.matchMedia;
}

beforeEach(() => {
  localStorage.clear();
  delete document.documentElement.dataset.theme;
  document.documentElement.classList.remove("dark");
  stubPrefers(false);
});

afterEach(() => {
  window.matchMedia = realMatchMedia;
});

describe("getStoredTheme", () => {
  it("is null with nothing stored, reads a valid value, ignores garbage", () => {
    expect(getStoredTheme()).toBeNull();
    localStorage.setItem("packetpilot.theme.v1", "light");
    expect(getStoredTheme()).toBe("light");
    localStorage.setItem("packetpilot.theme.v1", "chartreuse");
    expect(getStoredTheme()).toBeNull();
  });
});

describe("resolveTheme", () => {
  it("prefers a stored choice over the OS preference", () => {
    stubPrefers(true);
    setTheme("dark");
    expect(resolveTheme()).toBe("dark");
  });

  it("falls back to the OS preference when nothing is stored", () => {
    stubPrefers(true);
    expect(resolveTheme()).toBe("light");
    stubPrefers(false);
    expect(resolveTheme()).toBe("dark");
  });

  it("defaults to dark when matchMedia throws", () => {
    window.matchMedia = (() => {
      throw new Error("no matchMedia");
    }) as unknown as typeof window.matchMedia;
    expect(resolveTheme()).toBe("dark");
  });
});

describe("applyTheme", () => {
  it("reflects the theme onto <html> data-theme and the dark class", () => {
    applyTheme("light");
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(document.documentElement.classList.contains("dark")).toBe(false);

    applyTheme("dark");
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });
});

describe("setTheme", () => {
  it("persists, applies, and dispatches the theme event", () => {
    const onEvent = vi.fn();
    window.addEventListener(THEME_EVENT, onEvent);
    setTheme("light");
    window.removeEventListener(THEME_EVENT, onEvent);

    expect(localStorage.getItem("packetpilot.theme.v1")).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(onEvent).toHaveBeenCalledTimes(1);
  });
});
