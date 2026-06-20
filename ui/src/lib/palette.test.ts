import { describe, it, expect } from "vitest";
import { cssVar, severityColor, chartPalette } from "./palette";

describe("cssVar", () => {
  it("returns the fallback when the CSS property is not defined (empty value)", () => {
    // jsdom does not have CSS custom properties populated, so getPropertyValue returns ""
    const result = cssVar("--nonexistent-var", "#fallback");
    expect(result).toBe("#fallback");
  });

  it("returns default fallback (#888) when no fallback argument is given", () => {
    const result = cssVar("--another-missing-var");
    expect(result).toBe("#888");
  });
});

describe("severityColor", () => {
  it("returns a string for each severity level", () => {
    const levels = ["critical", "high", "medium", "low", "info", "none"] as const;
    for (const sev of levels) {
      const color = severityColor(sev);
      expect(typeof color).toBe("string");
      expect(color.length).toBeGreaterThan(0);
    }
  });
});

describe("chartPalette", () => {
  it("returns an object with the expected keys", () => {
    const palette = chartPalette();
    expect(palette).toHaveProperty("grid");
    expect(palette).toHaveProperty("axis");
    expect(palette).toHaveProperty("text");
    expect(palette).toHaveProperty("accent");
    expect(palette).toHaveProperty("sev");
    expect(palette.sev).toHaveProperty("critical");
    expect(palette.sev).toHaveProperty("high");
    expect(palette.sev).toHaveProperty("medium");
    expect(palette.sev).toHaveProperty("low");
    expect(palette.sev).toHaveProperty("info");
    expect(palette.sev).toHaveProperty("none");
  });

  it("falls back to hardcoded colors when CSS vars are not set (jsdom)", () => {
    const palette = chartPalette();
    // When no CSS vars are set, all fallbacks should be non-empty strings
    expect(palette.accent).toBe("#38bdf8");
    expect(palette.sev.critical).toBe("#f43f5e");
  });
});
