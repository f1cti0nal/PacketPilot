import { describe, it, expect } from "vitest";
import {
  BAND_ORDER,
  BAND_SEVERITY,
  actionableCount,
  bandLabel,
  bandRank,
  bandSeverity,
  formatTerm,
} from "./alerts";
import { makeOutput } from "../test/fixtures";
import type { Alert, PriorityBand } from "../types";

describe("band vocabulary", () => {
  it("BAND_ORDER is worst-first and covers every band exactly once", () => {
    expect(BAND_ORDER).toEqual(["act_now", "investigate", "review", "log", "info"]);
    expect(new Set(BAND_ORDER).size).toBe(BAND_ORDER.length);
  });

  it("bandLabel maps every band to its human label", () => {
    expect(bandLabel("act_now")).toBe("Act now");
    expect(bandLabel("investigate")).toBe("Investigate");
    expect(bandLabel("review")).toBe("Review");
    expect(bandLabel("log")).toBe("Log");
    expect(bandLabel("info")).toBe("Info");
  });

  it("bandLabel falls back to the raw token for unknown wire values", () => {
    expect(bandLabel("someday_new_band")).toBe("someday_new_band");
  });

  it("bandRank is strictly increasing along BAND_ORDER (0 = worst)", () => {
    const ranks = BAND_ORDER.map(bandRank);
    expect(ranks).toEqual([0, 1, 2, 3, 4]);
  });

  it("bandRank sorts unknown tokens after every known band", () => {
    expect(bandRank("someday_new_band")).toBe(BAND_ORDER.length);
  });

  it("bandSeverity maps bands onto the existing severity palette tokens", () => {
    expect(bandSeverity("act_now")).toBe("critical");
    expect(bandSeverity("investigate")).toBe("high");
    expect(bandSeverity("review")).toBe("medium");
    expect(bandSeverity("log")).toBe("low");
    expect(bandSeverity("info")).toBe("info");
    // unknown tokens degrade to the calm end of the palette rather than crashing
    expect(bandSeverity("someday_new_band")).toBe("info");
  });

  it("BAND_SEVERITY covers every band in BAND_ORDER", () => {
    for (const b of BAND_ORDER) expect(BAND_SEVERITY[b]).toBeTruthy();
  });
});

describe("formatTerm", () => {
  it("renders positive points with an explicit plus sign", () => {
    expect(formatTerm({ label: "base: attack-chain score", points: 87 })).toBe(
      "base: attack-chain score (+87)",
    );
  });

  it("renders negative points with the minus carried by the number", () => {
    expect(formatTerm({ label: "clamp: raw 112 -> 100", points: -12 })).toBe(
      "clamp: raw 112 -> 100 (-12)",
    );
  });

  it("renders zero as (+0)", () => {
    expect(formatTerm({ label: "confidence: 60%", points: 0 })).toBe("confidence: 60% (+0)");
  });
});

describe("actionableCount", () => {
  const withBand = (band: PriorityBand): Alert => {
    const base = makeOutput().summary.alerts![0];
    return { ...base, band };
  };

  it("counts only act_now and investigate bands", () => {
    const alerts = (["act_now", "investigate", "review", "log", "info"] as PriorityBand[]).map(withBand);
    expect(actionableCount(alerts)).toBe(2);
  });

  it("is 0 for an empty queue", () => {
    expect(actionableCount([])).toBe(0);
  });

  it("counts the fixture queue's single actionable alert", () => {
    // Fixture: one act_now chain alert + one review rollup.
    expect(actionableCount(makeOutput().summary.alerts ?? [])).toBe(1);
  });
});
