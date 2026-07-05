import { describe, it, expect, beforeEach } from "vitest";
import { listRuleSets, saveRuleSet, removeRuleSet, clearRuleSets } from "./ruleSets";
import { scopedKey } from "./storageScope";

describe("ruleSets", () => {
  beforeEach(() => localStorage.clear());

  it("saves and lists under the v1 key", () => {
    const r = saveRuleSet("c2.rules", "alert tcp any any -> any 443 (content:\"x\"; sid:1;)");
    expect(r.ok).toBe(true);
    expect(listRuleSets().map((s) => s.name)).toEqual(["c2.rules"]);
    expect(localStorage.getItem(scopedKey("packetpilot.ruleSets.v1"))).toContain("c2.rules");
  });

  it("gives distinct names distinct ids (no slug collision); removeRuleSet drops only one", () => {
    // "C2 Hunt" and "c2-hunt" would slug to the same value — assert they get distinct ids.
    const a = saveRuleSet("C2 Hunt", "alert tcp any any -> any 1 (content:\"a\"; sid:1;)").sets;
    saveRuleSet("c2-hunt", "alert tcp any any -> any 2 (content:\"b\"; sid:2;)");
    const ids = listRuleSets().map((s) => s.id);
    expect(new Set(ids).size).toBe(2); // distinct ids
    const remaining = removeRuleSet(a.find((s) => s.name === "C2 Hunt")!.id);
    expect(remaining.map((s) => s.name)).toEqual(["c2-hunt"]); // only "C2 Hunt" removed
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
    localStorage.setItem(scopedKey("packetpilot.ruleSets.v1"), "{ not json");
    expect(listRuleSets()).toEqual([]);
  });
});
