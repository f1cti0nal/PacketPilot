import { describe, expect, it } from "vitest";
import { paymentsSummary } from "./summary";

describe("paymentsSummary", () => {
  it("sums amount_cents for active subs only and tallies statuses", () => {
    const s = paymentsSummary([
      { status: "active", amount_cents: 1900 },
      { status: "active", amount_cents: 1900 },
      { status: "past_due", amount_cents: 1900 },
      { status: "canceled", amount_cents: 1900 },
      { status: "trialing", amount_cents: 1900 },
    ]);
    expect(s.activeMrrCents).toBe(3800);
    expect(s.activeCount).toBe(2);
    expect(s.statusCounts).toEqual({ active: 2, past_due: 1, canceled: 1, trialing: 1 });
  });

  it("returns zeros for an empty list", () => {
    expect(paymentsSummary([])).toEqual({ activeMrrCents: 0, activeCount: 0, statusCounts: {} });
  });
});
