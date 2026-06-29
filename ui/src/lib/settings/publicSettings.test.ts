import { describe, expect, it } from "vitest";
import { parsePublicSettings, SETTINGS_DEFAULTS, type RepAppConfig } from "./publicSettings";

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

  describe("rep_config parsing", () => {
    it("parses a valid rep_config into rep", () => {
      const s = parsePublicSettings({
        rep_config: { enabled: true, domain_enabled: true, providers: ["abuseipdb", "virustotal"] },
      });
      expect(s.rep).toEqual<RepAppConfig>({ enabled: true, domain_enabled: true, providers: ["abuseipdb", "virustotal"] });
    });
    it("enabled and domain_enabled are false when not exactly true", () => {
      expect(parsePublicSettings({ rep_config: { enabled: false, domain_enabled: false, providers: [] } }).rep.enabled).toBe(false);
      expect(parsePublicSettings({ rep_config: { enabled: 1, domain_enabled: "true", providers: [] } }).rep.enabled).toBe(false);
      expect(parsePublicSettings({ rep_config: { enabled: 1, domain_enabled: "true", providers: [] } }).rep.domain_enabled).toBe(false);
    });
    it("filters providers to valid values only", () => {
      const s = parsePublicSettings({
        rep_config: { enabled: true, domain_enabled: false, providers: ["abuseipdb", "badprovider", "virustotal", 42] },
      });
      expect(s.rep.providers).toEqual(["abuseipdb", "virustotal"]);
    });
    it("falls back to defaults when rep_config is missing", () => {
      expect(parsePublicSettings({}).rep).toEqual(SETTINGS_DEFAULTS.rep);
    });
    it("falls back to defaults when rep_config is junk (non-object)", () => {
      expect(parsePublicSettings({ rep_config: "bad" }).rep).toEqual(SETTINGS_DEFAULTS.rep);
      expect(parsePublicSettings({ rep_config: 42 }).rep).toEqual(SETTINGS_DEFAULTS.rep);
      expect(parsePublicSettings({ rep_config: null }).rep).toEqual(SETTINGS_DEFAULTS.rep);
    });
    it("providers defaults to empty array when missing or non-array", () => {
      expect(parsePublicSettings({ rep_config: { enabled: true } }).rep.providers).toEqual([]);
      expect(parsePublicSettings({ rep_config: { enabled: true, providers: "abuseipdb" } }).rep.providers).toEqual([]);
    });
    it("rep defaults include enabled:false, domain_enabled:false, providers:[]", () => {
      expect(SETTINGS_DEFAULTS.rep).toEqual({ enabled: false, domain_enabled: false, providers: [] });
    });
  });
});
