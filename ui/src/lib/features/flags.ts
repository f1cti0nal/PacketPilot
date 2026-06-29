export type FlagKey = "ai_assist" | "pcap_export" | "multi_capture_diff";
export type FeatureGate = "on" | "off" | "upsell";
export interface FlagState {
  enabled: boolean;
  plan_gate: "free" | "pro" | null;
}

// The single source of OFFLINE truth. Core features are NOT in this map (they render
// unconditionally and are never flag-checked); only enhancement flags appear here, defaulting
// to the safe value that preserves full local function.
// INVARIANT: pcap_export and multi_capture_diff MUST default to plan_gate:null so that
// offline/anon users always get "on" (carve + compare are core local-analysis features).
export const DEFAULTS: Record<FlagKey, FlagState> = {
  ai_assist: { enabled: true, plan_gate: null },
  pcap_export: { enabled: true, plan_gate: null },
  multi_capture_diff: { enabled: true, plan_gate: null },
};

export function evaluateGate(flag: FlagState, plan: string): FeatureGate {
  if (!flag.enabled) return "off";
  if (flag.plan_gate === "pro" && plan !== "pro") return "upsell";
  return "on";
}
