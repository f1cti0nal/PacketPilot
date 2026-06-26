import { describe, it, expect, beforeEach } from "vitest";
import {
  getAiEnabled, setAiEnabled, getAiBaseUrl, setAiBaseUrl, getAiModel, setAiModel,
  getAiKey, setAiKey, aiConsentGiven, giveAiConsent, getAiConfig, AI_PRESETS,
  getProxyUrl, setProxyUrl,
} from "./settings";

describe("ai settings", () => {
  beforeEach(() => localStorage.clear());
  it("off by default; toggles", () => {
    expect(getAiEnabled()).toBe(false);
    setAiEnabled(true);
    expect(getAiEnabled()).toBe(true);
  });
  it("baseUrl / model / key round-trip", () => {
    setAiBaseUrl("https://api.openai.com/v1"); setAiModel("gpt-4o"); setAiKey("sk-x");
    expect(getAiBaseUrl()).toBe("https://api.openai.com/v1");
    expect(getAiModel()).toBe("gpt-4o");
    expect(getAiKey()).toBe("sk-x");
  });
  it("consent is sticky", () => {
    expect(aiConsentGiven()).toBe(false);
    giveAiConsent();
    expect(aiConsentGiven()).toBe(true);
  });
  it("getAiConfig assembles the stored values", () => {
    setAiEnabled(true); setAiBaseUrl("u"); setAiModel("m"); setAiKey("k");
    expect(getAiConfig()).toEqual({ enabled: true, baseUrl: "u", model: "m", apiKey: "k" });
  });
  it("the default preset is Anthropic + claude-opus-4-8", () => {
    expect(AI_PRESETS[0]).toMatchObject({ baseUrl: "https://api.anthropic.com/v1", model: "claude-opus-4-8" });
  });
  it("proxy URL is trimmed on read and write — whitespace never counts as a configured relay", () => {
    expect(getProxyUrl()).toBe(""); // unset
    setProxyUrl("   ");
    expect(getProxyUrl()).toBe(""); // whitespace-only → empty, so pickTransport won't take the proxy path
    setProxyUrl("  https://relay.example/ai  ");
    expect(getProxyUrl()).toBe("https://relay.example/ai"); // surrounding whitespace stripped
  });
});
