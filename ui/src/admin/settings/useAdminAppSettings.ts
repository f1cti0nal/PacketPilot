import { useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../../lib/supabase";
import type { Json } from "../../lib/supabase/types";

export interface AdminSetting {
  key: string;
  value: Json;
  description: string | null;
  updated_at: string;
}
export type AdminSettingsState =
  | { status: "loading" }
  | { status: "error"; error: string }
  | { status: "ready"; settings: AdminSetting[] };

const COLS = "key,value,description,updated_at";

export function useAdminAppSettings(): { state: AdminSettingsState; reload: () => void } {
  const [state, setState] = useState<AdminSettingsState>({ status: "loading" });
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
        const { data, error } = await client.from("app_settings").select(COLS).order("key");
        if (error) throw new Error((error as { message?: string }).message ?? "Query failed");
        if (cancelled) return;
        setState({ status: "ready", settings: (data ?? []) as unknown as AdminSetting[] });
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

async function patch(key: string, fields: Record<string, unknown>): Promise<{ ok: boolean; error?: string }> {
  if (!supabase) return { ok: false, error: "Backend not configured" };
  const { error } = await supabase.from("app_settings").update(fields as never).eq("key", key);
  return error ? { ok: false, error: (error as { message?: string }).message ?? "Update failed" } : { ok: true };
}

export const updateValue = (key: string, value: Json) => patch(key, { value });
export const updateDescription = (key: string, description: string) => patch(key, { description });

export async function createSetting(key: string, description: string): Promise<{ ok: boolean; error?: string }> {
  if (!supabase) return { ok: false, error: "Backend not configured" };
  const { error } = await supabase.from("app_settings").insert({ key, description, value: {} } as never);
  return error ? { ok: false, error: (error as { message?: string }).message ?? "Create failed" } : { ok: true };
}

export async function deleteSetting(key: string): Promise<{ ok: boolean; error?: string }> {
  if (!supabase) return { ok: false, error: "Backend not configured" };
  const { error } = await supabase.from("app_settings").delete().eq("key", key);
  return error ? { ok: false, error: (error as { message?: string }).message ?? "Delete failed" } : { ok: true };
}
