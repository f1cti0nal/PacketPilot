import { describe, it, expect } from "vitest";
import { flowStats } from "./flowStats";
import { makeFlows } from "../test/fixtures";
import type { FlowCategory } from "../types";

describe("flowStats", () => {
  it("returns zeros for an empty set", () => {
    expect(flowStats([])).toEqual({ flows: 0, bytes: 0, packets: 0, iocs: 0, topCategories: [] });
  });

  it("sums bytes and packets across the rows", () => {
    const s = flowStats(makeFlows(5));
    // makeFlows: row0 bytesTotal 1,200,500; rows 1-4 = 1,500 each; pkts 10 each.
    expect(s.flows).toBe(5);
    expect(s.bytes).toBe(1_200_500 + 4 * 1_500);
    expect(s.packets).toBe(5 * 10);
  });

  it("counts only IOC-flagged flows", () => {
    const rows = makeFlows(3).map((r, i) => ({ ...r, ioc: i === 0 }));
    expect(flowStats(rows).iocs).toBe(1);
  });

  it("ranks top categories by flow count", () => {
    const rows = makeFlows(5).map((r, i) => ({
      ...r,
      category: (i < 3 ? "web" : "dns") as FlowCategory,
    }));
    const s = flowStats(rows);
    expect(s.topCategories[0]).toEqual({ category: "web", flows: 3 });
    expect(s.topCategories[1]).toEqual({ category: "dns", flows: 2 });
  });
});
