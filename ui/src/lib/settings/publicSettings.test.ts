import { describe, expect, it } from "vitest";
import { parsePublicSettings, SETTINGS_DEFAULTS } from "./publicSettings";

describe("parsePublicSettings", () => {
  it("parses a valid banner", () => {
    const s = parsePublicSettings({ announcement_banner: { text: "Hi", severity: "warning", dismissible: false } });
    expect(s.announcement_banner).toEqual({ text: "Hi", severity: "warning", dismissible: false });
  });
  it("treats empty/blank text as no banner", () => {
    expect(parsePublicSettings({ announcement_banner: { text: "  ", severity: "info", dismissible: true } }).announcement_banner).toBeNull();
  });
  it("defaults a bad severity to info and dismissible to true", () => {
    const s = parsePublicSettings({ announcement_banner: { text: "x", severity: "boom" } });
    expect(s.announcement_banner).toEqual({ text: "x", severity: "info", dismissible: true });
  });
  it("returns defaults for junk/missing input without throwing", () => {
    expect(parsePublicSettings(null)).toEqual(SETTINGS_DEFAULTS);
    expect(parsePublicSettings({})).toEqual(SETTINGS_DEFAULTS);
    expect(parsePublicSettings("nope")).toEqual(SETTINGS_DEFAULTS);
  });
});
