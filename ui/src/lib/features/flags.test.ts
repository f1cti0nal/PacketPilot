import { describe, expect, it } from "vitest";
import { evaluateGate, DEFAULTS } from "./flags";

describe("evaluateGate", () => {
  it("off when disabled regardless of plan", () => {
    expect(evaluateGate({ enabled: false, plan_gate: null }, "pro")).toBe("off");
  });
  it("on when enabled and no plan gate", () => {
    expect(evaluateGate({ enabled: true, plan_gate: null }, "free")).toBe("on");
  });
  it("upsell when pro-gated and user is free", () => {
    expect(evaluateGate({ enabled: true, plan_gate: "pro" }, "free")).toBe("upsell");
  });
  it("on when pro-gated and user is pro", () => {
    expect(evaluateGate({ enabled: true, plan_gate: "pro" }, "pro")).toBe("on");
  });
  it("on when free-gated and user is free", () => {
    expect(evaluateGate({ enabled: true, plan_gate: "free" }, "free")).toBe("on");
  });
});

describe("DEFAULTS offline invariant", () => {
  it("ai_assist is on offline (plan_gate null)", () => {
    expect(evaluateGate(DEFAULTS.ai_assist, "free")).toBe("on");
  });
  it("pcap_export is on offline (plan_gate null, not pro-gated)", () => {
    expect(evaluateGate(DEFAULTS.pcap_export, "free")).toBe("on");
  });
  it("multi_capture_diff is on offline (plan_gate null, not pro-gated)", () => {
    expect(evaluateGate(DEFAULTS.multi_capture_diff, "free")).toBe("on");
  });
  it("reputation is on offline (plan_gate null — self-host/BYO keeps full function)", () => {
    expect(evaluateGate(DEFAULTS.reputation, "free")).toBe("on");
  });
  it("saved_rules is on offline (plan_gate null, not pro-gated)", () => {
    expect(evaluateGate(DEFAULTS.saved_rules, "free")).toBe("on");
  });
  it("DEFAULTS contains exactly the five expected keys", () => {
    expect(Object.keys(DEFAULTS).sort()).toEqual(
      ["ai_assist", "multi_capture_diff", "pcap_export", "reputation", "saved_rules"],
    );
  });
});
