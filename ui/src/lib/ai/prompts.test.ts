import { describe, it, expect } from "vitest";
import { SUMMARY_SYSTEM, CHAT_SYSTEM } from "./prompts";

describe("ai prompts", () => {
  it("ground the model in the provided summary only", () => {
    for (const p of [SUMMARY_SYSTEM, CHAT_SYSTEM]) {
      expect(p.toLowerCase()).toContain("summary");
      expect(p.toLowerCase()).toMatch(/only|do not invent|not in the/);
    }
    expect(CHAT_SYSTEM.toLowerCase()).toContain("question");
  });
});
