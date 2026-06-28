import { describe, expect, it } from "vitest";
import { evaluateGate } from "./flags";

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
