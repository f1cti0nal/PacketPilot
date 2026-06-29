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

  describe("ai_config parsing", () => {
    it("parses a valid ai_config into ai", () => {
      const s = parsePublicSettings({
        ai_config: { enabled: true, provider: "openai", model: "gpt-4o" },
      });
      expect(s.ai).toEqual({ enabled: true, provider: "openai", model: "gpt-4o" });
    });
    it("enabled is false when ai_config.enabled is not exactly true", () => {
      expect(parsePublicSettings({ ai_config: { enabled: false, provider: "anthropic", model: "x" } }).ai.enabled).toBe(false);
      expect(parsePublicSettings({ ai_config: { enabled: 1, provider: "anthropic", model: "x" } }).ai.enabled).toBe(false);
      expect(parsePublicSettings({ ai_config: { enabled: "true", provider: "anthropic", model: "x" } }).ai.enabled).toBe(false);
    });
    it("falls back to default provider and model when missing or non-string", () => {
      const s = parsePublicSettings({ ai_config: { enabled: true } });
      expect(s.ai.provider).toBe("anthropic");
      expect(s.ai.model).toBe("claude-opus-4-8");
    });
    it("falls back to defaults when ai_config is missing", () => {
      const s = parsePublicSettings({});
      expect(s.ai).toEqual(SETTINGS_DEFAULTS.ai);
    });
    it("falls back to defaults when ai_config is junk (non-object)", () => {
      expect(parsePublicSettings({ ai_config: "bad" }).ai).toEqual(SETTINGS_DEFAULTS.ai);
      expect(parsePublicSettings({ ai_config: 42 }).ai).toEqual(SETTINGS_DEFAULTS.ai);
      expect(parsePublicSettings({ ai_config: null }).ai).toEqual(SETTINGS_DEFAULTS.ai);
    });
    it("ai defaults include enabled:false", () => {
      expect(SETTINGS_DEFAULTS.ai).toEqual({ enabled: false, provider: "anthropic", model: "claude-opus-4-8" });
    });
  });
});
