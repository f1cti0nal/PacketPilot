export type FlagKey = "ai_assist";
export type FeatureGate = "on" | "off" | "upsell";
export interface FlagState {
  enabled: boolean;
  plan_gate: "free" | "pro" | null;
}

// The single source of OFFLINE truth. Core features are NOT in this map (they render
// unconditionally and are never flag-checked); only enhancement flags appear here, defaulting
// to the safe value that preserves full local function.
export const DEFAULTS: Record<FlagKey, FlagState> = {
  ai_assist: { enabled: true, plan_gate: null },
};

export function evaluateGate(flag: FlagState, plan: string): FeatureGate {
  if (!flag.enabled) return "off";
  if (flag.plan_gate === "pro" && plan !== "pro") return "upsell";
  return "on";
}
