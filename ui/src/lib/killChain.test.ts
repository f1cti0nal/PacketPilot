import { describe, it, expect } from "vitest";
import { computeChainLayout, techniqueName } from "./killChain";
import { makeOutput } from "../test/fixtures";

const chain = () => makeOutput().summary.attack_chains![0];

describe("computeChainLayout", () => {
  it("places one lane per host and crosses lanes on a pivot", () => {
    const c = chain();
    const layout = computeChainLayout(c, { width: 800, laneHeight: 60 });
    expect(layout.lanes.map((l) => l.host)).toEqual(["10.13.37.7", "10.66.0.1"]);
    expect(layout.nodes).toHaveLength(c.steps.length);

    const yA = layout.nodes.find((n) => n.step.actor === "10.13.37.7")!.y;
    const yB = layout.nodes.find((n) => n.step.actor === "10.66.0.1")!.y;
    expect(yA).not.toBe(yB);

    const pivot = layout.arrows.find((a) => a.kind === "pivot");
    expect(pivot).toBeDefined();
    expect(pivot!.y1).not.toBe(pivot!.y2); // the pivot connector crosses lanes

    // x increases with time (first step is leftmost, last is rightmost).
    const byOrder = [...layout.nodes].sort((a, b) => a.order - b.order);
    expect(byOrder[0].x).toBeLessThan(byOrder[byOrder.length - 1].x);
  });

  it("degrades to even spacing when timestamps are missing", () => {
    const c = chain();
    c.steps.forEach((s) => (s.first_seen_ns = null));
    const xs = computeChainLayout(c).nodes.map((n) => n.x);
    expect(new Set(xs).size).toBe(xs.length); // all distinct — evenly spaced by order
  });
});

describe("techniqueName", () => {
  it("resolves known ids and echoes unknown ones", () => {
    expect(techniqueName("T1071")).toBe("Application Layer Protocol");
    expect(techniqueName("T1110")).toBe("Brute Force");
    expect(techniqueName("T9999")).toBe("T9999");
  });
});
