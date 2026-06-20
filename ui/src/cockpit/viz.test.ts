import { describe, it, expect } from "vitest";
import { clamp01, circumference, polarToCartesian, sparkline, protoSegments } from "./viz";
import { makeOutput } from "../test/fixtures";

describe("viz geometry", () => {
  it("clamp01 clamps", () => {
    expect(clamp01(-1)).toBe(0); expect(clamp01(2)).toBe(1); expect(clamp01(0.5)).toBe(0.5);
  });
  it("circumference = 2*pi*r", () => {
    expect(circumference(10)).toBeCloseTo(2 * Math.PI * 10);
  });
  it("polarToCartesian: 0deg is straight up", () => {
    const p = polarToCartesian(0, 0, 10, 0);
    expect(p.x).toBeCloseTo(0); expect(p.y).toBeCloseTo(-10);
  });
  it("sparkline returns empty for no values and a path for values", () => {
    expect(sparkline([], 80, 20).line).toBe("");
    expect(sparkline([1, 2, 3], 80, 20).line.startsWith("M")).toBe(true);
  });
});

describe("protoSegments", () => {
  it("is the leaf partition that sums to total_packets (no double-count)", () => {
    const o = makeOutput().summary;
    const segs = protoSegments(o.proto);
    // never includes the L4 parents tcp/udp
    expect(segs.find((s) => s.key === "tcp")).toBeUndefined();
    expect(segs.find((s) => s.key === "udp")).toBeUndefined();
    const sum = segs.reduce((a, s) => a + s.value, 0);
    expect(sum).toBe(o.total_packets);
  });
  it("filters zero-value segments", () => {
    const segs = protoSegments(makeOutput().summary.proto);
    expect(segs.every((s) => s.value > 0)).toBe(true);
  });
});
