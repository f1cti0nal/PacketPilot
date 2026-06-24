import { describe, it, expect, beforeEach } from "vitest";
import { listRuleSets, saveRuleSet, removeRuleSet, clearRuleSets } from "./ruleSets";

describe("ruleSets", () => {
  beforeEach(() => localStorage.clear());

  it("saves and lists under the v1 key", () => {
    const r = saveRuleSet("c2.rules", "alert tcp any any -> any 443 (content:\"x\"; sid:1;)");
    expect(r.ok).toBe(true);
    expect(listRuleSets().map((s) => s.name)).toEqual(["c2.rules"]);
    expect(localStorage.getItem("packetpilot.ruleSets.v1")).toContain("c2.rules");
  });
  it("upserts by trimmed name (keeps one, updated text)", () => {
    saveRuleSet("set", "a"); saveRuleSet("set", "b");
    const list = listRuleSets();
    expect(list).toHaveLength(1);
    expect(list[0].text).toBe("b");
  });
  it("removes and clears", () => {
    const list = saveRuleSet("x", "a").sets;
    expect(removeRuleSet(list[0].id)).toHaveLength(0);
    saveRuleSet("y", "a"); expect(clearRuleSets()).toHaveLength(0);
  });
  it("rejects oversized text without saving or throwing", () => {
    const big = "x".repeat(256 * 1024 + 1);
    const r = saveRuleSet("big", big);
    expect(r.ok).toBe(false);
    expect(listRuleSets()).toHaveLength(0);
  });
  it("survives malformed storage without throwing", () => {
    localStorage.setItem("packetpilot.ruleSets.v1", "{ not json");
    expect(listRuleSets()).toEqual([]);
  });
});
