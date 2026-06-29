import { describe, it, expect } from "vitest";
import { trialDaysLeft, isOnTrial } from "./trial";

const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();

describe("trial helpers", () => {
  it("trialDaysLeft rounds up remaining days; 0 when expired or absent", () => {
    expect(trialDaysLeft(null)).toBe(0);
    expect(trialDaysLeft(inDays(-1))).toBe(0);
    expect(trialDaysLeft(inDays(13.2))).toBe(14);
  });

  it("isOnTrial: only effective-pro + no billing + a future trial end", () => {
    expect(isOnTrial({ plan: "pro", hasBilling: false, trialEndsAt: inDays(5) })).toBe(true);
    // effective-free (expired) is not a trial
    expect(isOnTrial({ plan: "free", hasBilling: false, trialEndsAt: inDays(5) })).toBe(false);
    // a real billing relationship is not a trial
    expect(isOnTrial({ plan: "pro", hasBilling: true, trialEndsAt: inDays(5) })).toBe(false);
    // an admin comp (no trial end) is not a trial
    expect(isOnTrial({ plan: "pro", hasBilling: false, trialEndsAt: null })).toBe(false);
  });
});
