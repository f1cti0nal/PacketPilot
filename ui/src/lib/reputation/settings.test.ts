import { describe, it, expect, beforeEach } from "vitest";
import { repEnabled, setRepEnabled, getProxyUrl, setProxyUrl, consentGiven, giveConsent, getKey, setKey, browserKeys } from "./settings";

describe("reputation settings (browser/localStorage)", () => {
  beforeEach(() => localStorage.clear());
  it("enabled defaults off and toggles", () => {
    expect(repEnabled()).toBe(false);
    setRepEnabled(true);
    expect(repEnabled()).toBe(true);
  });
  it("proxy url round-trips", () => {
    setProxyUrl("https://proxy.example/relay");
    expect(getProxyUrl()).toBe("https://proxy.example/relay");
  });
  it("consent is sticky", () => {
    expect(consentGiven()).toBe(false);
    giveConsent();
    expect(consentGiven()).toBe(true);
  });

  describe("getKey / setKey", () => {
    it("returns empty string when not set", () => {
      expect(getKey("abuseipdb")).toBe("");
      expect(getKey("greynoise")).toBe("");
      expect(getKey("virustotal")).toBe("");
    });
    it("round-trips a key for each provider", () => {
      setKey("abuseipdb", "abuse-key-123");
      expect(getKey("abuseipdb")).toBe("abuse-key-123");

      setKey("greynoise", "gn-key-456");
      expect(getKey("greynoise")).toBe("gn-key-456");

      setKey("virustotal", "vt-key-789");
      expect(getKey("virustotal")).toBe("vt-key-789");
    });
    it("overwrites an existing key", () => {
      setKey("abuseipdb", "old-key");
      setKey("abuseipdb", "new-key");
      expect(getKey("abuseipdb")).toBe("new-key");
    });
  });

  describe("browserKeys", () => {
    it("returns empty object when no keys are set", () => {
      expect(browserKeys()).toEqual({});
    });
    it("returns only providers that have a key set", () => {
      setKey("abuseipdb", "k1");
      setKey("virustotal", "k2");
      const keys = browserKeys();
      expect(keys).toEqual({ abuseipdb: "k1", virustotal: "k2" });
      expect("greynoise" in keys).toBe(false);
    });
    it("returns all providers when all keys are set", () => {
      setKey("abuseipdb", "a");
      setKey("greynoise", "g");
      setKey("virustotal", "v");
      expect(browserKeys()).toEqual({ abuseipdb: "a", greynoise: "g", virustotal: "v" });
    });
  });
});
