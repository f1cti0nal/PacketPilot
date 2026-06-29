import { describe, it, expect, beforeEach } from "vitest";
import { consentGiven, giveConsent, domainConsentGiven, giveDomainConsent } from "./settings";

describe("reputation consent flags (localStorage)", () => {
  beforeEach(() => localStorage.clear());

  it("consentGiven defaults false and is set by giveConsent", () => {
    expect(consentGiven()).toBe(false);
    giveConsent();
    expect(consentGiven()).toBe(true);
  });

  it("domainConsentGiven defaults false and is set by giveDomainConsent", () => {
    expect(domainConsentGiven()).toBe(false);
    giveDomainConsent();
    expect(domainConsentGiven()).toBe(true);
  });

  it("consent flags are independent of each other", () => {
    giveConsent();
    expect(consentGiven()).toBe(true);
    expect(domainConsentGiven()).toBe(false);
  });
});
