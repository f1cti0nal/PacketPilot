import { describe, it, expect } from "vitest";
import { parseScoreTerms } from "./scoreTerms";

describe("parseScoreTerms", () => {
  it("parses a positive additive term", () => {
    expect(parseScoreTerms(["category c2 (+45)"])).toEqual({
      terms: [{ label: "category c2", points: 45 }],
      notes: [],
    });
  });

  it("parses a negative term", () => {
    const r = parseScoreTerms(["all-internal peers (-10)"]);
    expect(r.terms).toEqual([{ label: "all-internal peers", points: -10 }]);
  });

  it("routes clamp + floor lines to notes, not terms", () => {
    const r = parseScoreTerms([
      "category c2 (+45)",
      "ioc: endpoint ip on threat feed (+35)",
      "clamp: raw 105 -> 100",
      "floor: ioc + c2/anomalous forces Critical (>= 90)",
    ]);
    expect(r.terms.map((t) => t.points)).toEqual([45, 35]);
    expect(r.terms.map((t) => t.label)).toEqual([
      "category c2",
      "ioc: endpoint ip on threat feed",
    ]);
    expect(r.notes).toEqual([
      "clamp: raw 105 -> 100",
      "floor: ioc + c2/anomalous forces Critical (>= 90)",
    ]);
  });

  it("does not treat (>= 60) as a term", () => {
    const r = parseScoreTerms(["floor: ioc match forces High (>= 60)"]);
    expect(r.terms).toEqual([]);
    expect(r.notes).toEqual(["floor: ioc match forces High (>= 60)"]);
  });

  it("handles +0 and empty input", () => {
    expect(parseScoreTerms(["category unknown (+0)"]).terms).toEqual([
      { label: "category unknown", points: 0 },
    ]);
    expect(parseScoreTerms([])).toEqual({ terms: [], notes: [] });
  });

  it("a non-matching string becomes a note (never throws)", () => {
    const r = parseScoreTerms(["just a freeform note"]);
    expect(r.terms).toEqual([]);
    expect(r.notes).toEqual(["just a freeform note"]);
  });
});
