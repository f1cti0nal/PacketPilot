import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  getStoredDensity,
  resolveDensity,
  applyDensity,
  setDensity,
  DENSITY_EVENT,
} from "./density";

beforeEach(() => {
  localStorage.clear();
  delete document.documentElement.dataset.density;
});

describe("getStoredDensity", () => {
  it("is null with nothing stored, reads a valid value, ignores garbage", () => {
    expect(getStoredDensity()).toBeNull();
    localStorage.setItem("packetpilot.density.v1", "compact");
    expect(getStoredDensity()).toBe("compact");
    localStorage.setItem("packetpilot.density.v1", "snug");
    expect(getStoredDensity()).toBeNull();
  });
});

describe("resolveDensity", () => {
  it("prefers a stored choice, otherwise defaults to comfortable", () => {
    expect(resolveDensity()).toBe("comfortable");
    setDensity("compact");
    expect(resolveDensity()).toBe("compact");
  });
});

describe("applyDensity", () => {
  it("reflects the density onto <html> data-density", () => {
    applyDensity("compact");
    expect(document.documentElement.dataset.density).toBe("compact");
    applyDensity("comfortable");
    expect(document.documentElement.dataset.density).toBe("comfortable");
  });
});

describe("setDensity", () => {
  it("persists, applies, and dispatches the density event", () => {
    const onEvent = vi.fn();
    window.addEventListener(DENSITY_EVENT, onEvent);
    setDensity("compact");
    window.removeEventListener(DENSITY_EVENT, onEvent);

    expect(localStorage.getItem("packetpilot.density.v1")).toBe("compact");
    expect(document.documentElement.dataset.density).toBe("compact");
    expect(onEvent).toHaveBeenCalledTimes(1);
  });
});
