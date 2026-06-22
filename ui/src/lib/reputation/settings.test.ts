import { describe, it, expect, beforeEach } from "vitest";
import { repEnabled, setRepEnabled, getProxyUrl, setProxyUrl, consentGiven, giveConsent, getKey, setKey, browserKeys, domainEnabled, setDomainEnabled, domainConsentGiven, giveDomainConsent } from "./settings";

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

describe("domain reputation settings", () => {
  beforeEach(() => localStorage.clear());
  it("defaults off and round-trips", () => {
    expect(domainEnabled()).toBe(false);
    expect(domainConsentGiven()).toBe(false);
    setDomainEnabled(true);
    expect(domainEnabled()).toBe(true);
    expect(localStorage.getItem("pp.rep.domain-enabled")).toBe("1");
    giveDomainConsent();
    expect(domainConsentGiven()).toBe(true);
  });
  it("is independent of the IP enable/consent keys", () => {
    localStorage.setItem("pp.rep.enabled", "1");
    localStorage.setItem("pp.rep.consent", "1");
    expect(domainEnabled()).toBe(false); // enabling IP rep does NOT enable domains
    expect(domainConsentGiven()).toBe(false);
  });
});
