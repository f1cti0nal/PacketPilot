import { describe, it, expect } from "vitest";
import { pickRuleBase, type RuleBaseRef } from "./ruleBase";
import type { AnalysisOutput } from "../types";

// Minimal AnalysisOutput-ish stand-ins distinguishable by identity + a marker field.
const out = (marker: string): AnalysisOutput =>
  ({ summary: { findings: [], __marker: marker } } as unknown as AnalysisOutput);

describe("pickRuleBase", () => {
  it("snapshots the current output on the first apply for a capture", () => {
    const ref: RuleBaseRef = { current: null };
    const base0 = out("base");
    const got = pickRuleBase(ref, "cap-1", base0);
    expect(got).toBe(base0);
    expect(ref.current).toEqual({ key: "cap-1", data: base0 });
  });

  it("no-stacking: a second apply for the SAME capture reuses the original snapshot, not the rules-augmented output", () => {
    const ref: RuleBaseRef = { current: null };
    const base0 = out("base"); // pre-rules state (e.g. post-reputation)
    const first = pickRuleBase(ref, "cap-1", base0);
    expect(first).toBe(base0);

    // Simulate the displayed summary now carrying the first ruleset's findings.
    const augmented = out("augmented");
    const second = pickRuleBase(ref, "cap-1", augmented);
    // The second apply must run over the ORIGINAL base, not the augmented output.
    expect(second).toBe(base0);
    expect(second).not.toBe(augmented);
  });

  it("re-snapshots for a different capture key", () => {
    const ref: RuleBaseRef = { current: null };
    pickRuleBase(ref, "cap-1", out("a"));
    const b = out("b");
    const got = pickRuleBase(ref, "cap-2", b);
    expect(got).toBe(b);
    expect(ref.current).toEqual({ key: "cap-2", data: b });
  });
});
