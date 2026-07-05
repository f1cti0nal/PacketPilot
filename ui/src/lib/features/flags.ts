export type FlagKey = "ai_assist" | "pcap_export" | "multi_capture_diff" | "reputation" | "saved_rules";
export type FeatureGate = "on" | "off" | "upsell";
export interface FlagState {
  enabled: boolean;
  plan_gate: "free" | "pro" | null;
}

// The single source of OFFLINE truth. Core features are NOT in this map (they render
// unconditionally and are never flag-checked); only enhancement flags appear here, defaulting
// to the safe value that preserves full local function.
//
// INVARIANT: every DEFAULT is plan_gate:null so an offline / anon / self-hosted user always
// gets "on" — no PacketPilot plan gate ever bites without the hosted DB saying so. The actual
// Free/Pro split is configured in the hosted `feature_flags` table and only reaches authed
// hosted users via useFeatureFlags. The Pro features (ai_assist, reputation, saved_rules) are
// ADDITIONALLY enforced server-side (ai-proxy / reputation-proxy check plan) so a client that
// fails open to these DEFAULTS still cannot spend operator API keys as a free user.
export const DEFAULTS: Record<FlagKey, FlagState> = {
  ai_assist: { enabled: true, plan_gate: null },
  pcap_export: { enabled: true, plan_gate: null },
  multi_capture_diff: { enabled: true, plan_gate: null },
  reputation: { enabled: true, plan_gate: null },
  saved_rules: { enabled: true, plan_gate: null },
};

export function evaluateGate(flag: FlagState, plan: string): FeatureGate {
  if (!flag.enabled) return "off";
  if (flag.plan_gate === "pro" && plan !== "pro") return "upsell";
  return "on";
}
