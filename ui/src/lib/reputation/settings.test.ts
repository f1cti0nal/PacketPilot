import { describe, it, expect, beforeEach } from "vitest";
import { repEnabled, setRepEnabled, getProxyUrl, setProxyUrl, consentGiven, giveConsent } from "./settings";

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
});
