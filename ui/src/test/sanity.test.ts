import { describe, it, expect } from "vitest";
describe("harness", () => {
  it("runs and has jsdom", () => {
    expect(typeof document).toBe("object");
    expect(1 + 1).toBe(2);
  });
});
