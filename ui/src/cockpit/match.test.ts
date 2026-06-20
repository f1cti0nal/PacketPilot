import { describe, it, expect } from "vitest";
import { fuzzyScore } from "./match";

describe("fuzzyScore", () => {
  it("returns null when not a subsequence", () => {
    expect(fuzzyScore("xyz", "10.0.0.1")).toBeNull();
  });
  it("returns 0 for empty query", () => {
    expect(fuzzyScore("", "anything")).toBe(0);
  });
  it("matches a subsequence", () => {
    expect(fuzzyScore("103", "10.13.37.7")).not.toBeNull();
  });
  it("is case-insensitive", () => {
    expect(fuzzyScore("FLOWS", "Go to Flows")).not.toBeNull();
  });
  it("ranks a prefix/contiguous match above a scattered one", () => {
    const prefix = fuzzyScore("flo", "Flows")!;
    const scattered = fuzzyScore("flo", "Foo lorem o")!;
    expect(prefix).toBeGreaterThan(scattered);
  });
});
