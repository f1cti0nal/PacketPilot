import { describe, it, expect } from "vitest";
import { makeBudget, trySpend } from "./budget";

describe("makeBudget", () => {
  it("returns initial quotas for all providers", () => {
    const b = makeBudget();
    expect(b.abuseipdb).toBe(950);
    expect(b.greynoise).toBe(9);
    expect(b.virustotal).toBe(480);
  });

  it("each call returns a fresh independent budget", () => {
    const b1 = makeBudget();
    const b2 = makeBudget();
    trySpend(b1, "greynoise");
    expect(b1.greynoise).toBe(8);
    expect(b2.greynoise).toBe(9); // b2 unaffected
  });
});

describe("trySpend", () => {
  it("returns true and decrements while budget > 0", () => {
    const b = makeBudget();
    expect(trySpend(b, "greynoise")).toBe(true);
    expect(b.greynoise).toBe(8);
  });

  it("returns false (does not decrement below 0) when budget is exhausted", () => {
    const b = { greynoise: 1 };
    expect(trySpend(b, "greynoise")).toBe(true);  // last spend
    expect(b.greynoise).toBe(0);
    expect(trySpend(b, "greynoise")).toBe(false); // exhausted
    expect(b.greynoise).toBe(0);                  // not -1
  });

  it("returns false for an unknown provider (missing key defaults to 0)", () => {
    const b = makeBudget();
    expect(trySpend(b, "unknown-provider")).toBe(false);
  });

  it("exhausting greynoise (9 requests) then returns false", () => {
    const b = makeBudget();
    for (let i = 0; i < 9; i++) {
      expect(trySpend(b, "greynoise")).toBe(true);
    }
    expect(b.greynoise).toBe(0);
    expect(trySpend(b, "greynoise")).toBe(false);
  });
});
