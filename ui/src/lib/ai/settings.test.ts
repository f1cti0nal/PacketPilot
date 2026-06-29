import { describe, it, expect, beforeEach } from "vitest";
import { aiConsentGiven, giveAiConsent } from "./settings";

describe("ai settings", () => {
  beforeEach(() => localStorage.clear());
  it("consent is sticky", () => {
    expect(aiConsentGiven()).toBe(false);
    giveAiConsent();
    expect(aiConsentGiven()).toBe(true);
  });
});
