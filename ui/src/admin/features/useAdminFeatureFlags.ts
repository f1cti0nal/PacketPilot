import { useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../../lib/supabase";

export interface AdminFlag {
  key: string;
  description: string | null;
  enabled: boolean;
  plan_gate: "free" | "pro" | null;
  updated_at: string;
}
export type AdminFlagsState =
  | { status: "loading" }
  | { status: "error"; error: string }
  | { status: "ready"; flags: AdminFlag[] };

const COLS = "key,description,enabled,plan_gate,updated_at";

export function useAdminFeatureFlags(): { state: AdminFlagsState; reload: () => void } {
  const [state, setState] = useState<AdminFlagsState>({ status: "loading" });
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    if (!supabaseConfigured || !supabase) {
      setState({ status: "error", error: "Backend not configured" });
      return;
    }
    const client = supabase;
    let cancelled = false;
    void (async () => {
      try {
        const { data, error } = await client.from("feature_flags").select(COLS).order("key");
        if (error) throw new Error((error as { message?: string }).message ?? "Query failed");
        if (cancelled) return;
        setState({ status: "ready", flags: (data ?? []) as unknown as AdminFlag[] });
      } catch (e) {
        if (!cancelled) setState({ status: "error", error: e instanceof Error ? e.message : String(e) });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [nonce]);

  return { state, reload: () => setNonce((n) => n + 1) };
}

async function update(key: string, fields: Record<string, unknown>): Promise<{ ok: boolean; error?: string }> {
  if (!supabase) return { ok: false, error: "Backend not configured" };
  const { error } = await supabase.from("feature_flags").update(fields as never).eq("key", key);
  return error ? { ok: false, error: (error as { message?: string }).message ?? "Update failed" } : { ok: true };
}

export const setEnabled = (key: string, enabled: boolean) => update(key, { enabled });
export const setPlanGate = (key: string, plan_gate: "free" | "pro" | null) => update(key, { plan_gate });
export const setDescription = (key: string, description: string) => update(key, { description });

export async function createFlag(key: string, description: string): Promise<{ ok: boolean; error?: string }> {
  if (!supabase) return { ok: false, error: "Backend not configured" };
  const { error } = await supabase.from("feature_flags").insert({ key, description } as never);
  return error ? { ok: false, error: (error as { message?: string }).message ?? "Create failed" } : { ok: true };
}

export async function deleteFlag(key: string): Promise<{ ok: boolean; error?: string }> {
  if (!supabase) return { ok: false, error: "Backend not configured" };
  const { error } = await supabase.from("feature_flags").delete().eq("key", key);
  return error ? { ok: false, error: (error as { message?: string }).message ?? "Delete failed" } : { ok: true };
}
