import { describe, it, expect } from "vitest";
import { forecastBand, breachesBand } from "./forecast";

describe("forecastBand", () => {
  it("returns empty arrays for an empty series", () => {
    const b = forecastBand([]);
    expect(b.forecast).toHaveLength(0);
    expect(b.upper).toHaveLength(0);
    expect(b.lower).toHaveLength(0);
  });

  it("keeps a steady series inside its own band (no breach)", () => {
    const values = new Array(30).fill(1_000_000);
    const band = forecastBand(values);
    // Warm-up aside, a flat series should never poke outside its band.
    for (let i = 8; i < values.length; i++) {
      expect(breachesBand(values[i], band, i)).toBe(false);
    }
  });

  it("flags a sudden spike as a breach above the upper band", () => {
    const values = new Array(30).fill(1_000_000);
    values[20] = 40_000_000;
    const band = forecastBand(values);
    expect(values[20]).toBeGreaterThan(band.upper[20]);
    expect(breachesBand(values[20], band, 20)).toBe(true);
  });

  it("bounds the band at zero (no negative lower)", () => {
    const values = [500, 500, 500, 500, 500, 500, 500, 500, 500, 500];
    const band = forecastBand(values);
    for (const lo of band.lower) expect(lo).toBeGreaterThanOrEqual(0);
  });

  it("is deterministic (same input => same band)", () => {
    const values = [1, 2, 3, 10, 4, 5, 6, 7, 8, 9, 100, 3, 2, 1];
    expect(forecastBand(values)).toEqual(forecastBand(values));
  });

  it("tracks a smooth linear ramp without flagging every bin", () => {
    const values = Array.from({ length: 30 }, (_, i) => 1_000_000 + i * 50_000);
    const band = forecastBand(values);
    let breaches = 0;
    for (let i = 10; i < values.length; i++) {
      if (breachesBand(values[i], band, i)) breaches++;
    }
    expect(breaches).toBe(0);
  });
});
