import { useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../supabase";
import { DEFAULTS, evaluateGate, type FeatureGate, type FlagKey, type FlagState } from "./flags";

export function useFeatureFlags(authed: boolean, plan: string): { gate: (key: FlagKey) => FeatureGate } {
  const [flags, setFlags] = useState<Record<string, FlagState>>({});

  useEffect(() => {
    // Offline / anon / signed-out → fall back to DEFAULTS (clear any flags from a prior
    // authed session so signing out restores defaults without a reload).
    if (!supabaseConfigured || !supabase || !authed) {
      setFlags((f) => (Object.keys(f).length ? {} : f));
      return;
    }
    const client = supabase;
    let cancelled = false;
    void (async () => {
      try {
        const { data, error } = await client.from("feature_flags").select("key,enabled,plan_gate");
        if (error || !data || cancelled) return; // fail-open: keep DEFAULTS
        const next: Record<string, FlagState> = {};
        for (const r of data as { key: string; enabled: boolean; plan_gate: "free" | "pro" | null }[]) {
          next[r.key] = { enabled: !!r.enabled, plan_gate: r.plan_gate ?? null };
        }
        if (!cancelled) setFlags(next);
      } catch {
        /* fail-open: keep DEFAULTS */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [authed]);

  return { gate: (key: FlagKey) => evaluateGate(flags[key] ?? DEFAULTS[key], plan) };
}
