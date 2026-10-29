import { beforeEach, describe, expect, it } from "vitest";
import {
  addSuppressionRules,
  exportSuppressions,
  importSuppressions,
  isExpired,
  loadSuppressions,
  parseSuppressionFile,
  removeSuppressionRule,
  rulesSignature,
  ymd,
  ymdPlusDays,
} from "./suppressions";
import type { SuppressionRule } from "../types";

const r = (over: Partial<SuppressionRule> = {}): SuppressionRule => ({
  id: "sup:0000000000000001",
  kind: "missing_sni",
  src: "10.0.0.5",
  reason: "IoT hub",
  ...over,
});

describe("suppressions store", () => {
  beforeEach(() => localStorage.clear());

  it("starts empty and survives garbage in storage", () => {
    expect(loadSuppressions().rules).toEqual([]);
    localStorage.setItem("packetpilot.suppressions.v1::anon", "{not json");
    expect(loadSuppressions().rules).toEqual([]);
  });

  it("adds rules once by id and removes them by id or match fields", () => {
    expect(addSuppressionRules([r(), r()])).toBe(1);
    expect(addSuppressionRules([r()])).toBe(0);
    expect(addSuppressionRules([r({ id: "sup:0000000000000002", src: "10.0.0.6" })])).toBe(1);
    expect(loadSuppressions().rules).toHaveLength(2);
    // An engine-normalized copy with a different id still finds its stored original.
    removeSuppressionRule(r({ id: "sup:ffffffffffffffff", src: " 10.0.0.6 " }));
    expect(loadSuppressions().rules.map((x) => x.src)).toEqual(["10.0.0.5"]);
    removeSuppressionRule(r());
    expect(loadSuppressions().rules).toEqual([]);
  });

  it("exports the CLI file format and imports it back", () => {
    addSuppressionRules([r()]);
    const text = exportSuppressions();
    expect(JSON.parse(text)).toEqual({ version: 1, rules: [r()] });
    localStorage.clear();
    expect(importSuppressions(text)).toBe(1);
    expect(loadSuppressions().rules).toEqual([r()]);
  });

  it("rejects files that are not suppression files and drops kindless rules", () => {
    expect(() => parseSuppressionFile("nope")).toThrow("Not a JSON file");
    expect(() => parseSuppressionFile("[]")).toThrow(/expected/);
    const f = parseSuppressionFile('{"rules":[{"kind":"beacon"},{"src":"1.2.3.4"}]}');
    expect(f.rules).toEqual([{ kind: "beacon", id: "", reason: "" }]);
  });
});

describe("dates and signatures", () => {
  it("formats and offsets UTC dates", () => {
    const d = new Date("2026-10-29T02:40:00Z");
    expect(ymd(d)).toBe("2026-10-29");
    expect(ymdPlusDays(d, 90)).toBe("2027-01-27");
  });

  it("treats a rule as expired only after its last day", () => {
    expect(isExpired(r({ expires: "2026-10-28" }), "2026-10-29")).toBe(true);
    expect(isExpired(r({ expires: "2026-10-29" }), "2026-10-29")).toBe(false);
    expect(isExpired(r(), "2026-10-29")).toBe(false);
  });

  it("signature ignores ids, order, duplicates and expired rules, and normalizes wildcards", () => {
    const today = "2026-10-29";
    const a = [r(), r({ id: "", kind: "beacon", dst: "any" })];
    const b = [r({ id: "x", kind: "BEACON", dst: undefined }), r({ id: "y" }), r({ id: "z" })];
    expect(rulesSignature(a, today)).toBe(rulesSignature(b, today));
    expect(rulesSignature([r({ expires: "2026-01-01" })], today)).toBe("");
    expect(rulesSignature(undefined, today)).toBe("");
  });
});
