import { describe, expect, it } from "vitest";
import { avatarColor, initials, pctDelta, ratioPct, toCsv, weekOverWeek } from "./helpers";

describe("initials", () => {
  it("uses first + last initial of a full name", () => {
    expect(initials("Alice Smith")).toBe("AS");
  });
  it("takes two letters from a single-word name", () => {
    expect(initials("bob")).toBe("BO");
  });
  it("falls back to the email local part and splits on separators", () => {
    expect(initials(null, "jane.doe@x.com")).toBe("JD");
    expect(initials("", "single@x.com")).toBe("SI");
  });
  it("returns ? when there is nothing to work with", () => {
    expect(initials(null, null)).toBe("?");
    expect(initials("   ")).toBe("?");
  });
});

describe("avatarColor", () => {
  it("is deterministic for a seed", () => {
    expect(avatarColor("a@b.com")).toBe(avatarColor("a@b.com"));
  });
  it("returns a hex from the palette and handles empty seeds", () => {
    expect(avatarColor("x")).toMatch(/^#[0-9a-f]{6}$/);
    expect(avatarColor(null)).toMatch(/^#[0-9a-f]{6}$/);
  });
});

describe("pctDelta", () => {
  it("computes a positive change", () => {
    expect(pctDelta(110, 100)).toEqual({ pct: 10, dir: "up" });
  });
  it("computes a negative change", () => {
    expect(pctDelta(90, 100)).toEqual({ pct: -10, dir: "down" });
  });
  it("is flat when unchanged", () => {
    expect(pctDelta(100, 100)).toEqual({ pct: 0, dir: "flat" });
  });
  it("returns null pct (dir up) when there is no prior baseline but new activity", () => {
    expect(pctDelta(5, 0)).toEqual({ pct: null, dir: "up" });
  });
  it("is flat zero when both are zero", () => {
    expect(pctDelta(0, 0)).toEqual({ pct: 0, dir: "flat" });
  });
  it("guards non-finite inputs", () => {
    expect(pctDelta(NaN, 100)).toEqual({ pct: null, dir: "flat" });
  });
});

describe("weekOverWeek", () => {
  it("returns null when there is less than two weeks of data", () => {
    expect(weekOverWeek([1, 2, 3])).toEqual({ pct: null, dir: "flat" });
  });
  it("compares the last 7 days to the prior 7", () => {
    const counts = [1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2]; // prev7=7, last7=14
    expect(weekOverWeek(counts)).toEqual({ pct: 100, dir: "up" });
  });
});

describe("ratioPct", () => {
  it("computes a clamped whole percent", () => {
    expect(ratioPct(3, 10)).toBe(30);
    expect(ratioPct(0, 0)).toBe(0);
    expect(ratioPct(20, 10)).toBe(100);
  });
});

describe("toCsv", () => {
  it("escapes commas, quotes and newlines", () => {
    const csv = toCsv(["a", "b"], [["x,y", 'he said "hi"'], ["plain", null]]);
    expect(csv).toBe('a,b\r\n"x,y","he said ""hi"""\r\nplain,');
  });
});
