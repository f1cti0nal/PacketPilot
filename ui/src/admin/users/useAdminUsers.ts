import { useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../../lib/supabase";

export interface AdminUser {
  id: string;
  email: string;
  full_name: string | null;
  plan: string;
  role: string;
  status: string;
  created_at: string;
}

export type AdminUsersState =
  | { status: "loading" }
  | { status: "error"; error: string }
  | { status: "ready"; users: AdminUser[] };

const COLS = "id,email,full_name,plan,role,status,created_at";

export function useAdminUsers(search: string): { state: AdminUsersState; reload: () => void } {
  const [state, setState] = useState<AdminUsersState>({ status: "loading" });
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
        let query = client.from("profiles").select(COLS);
        const term = search.trim();
        if (term) query = query.ilike("email", `%${term}%`);
        const { data, error } = await query.order("created_at", { ascending: false }).limit(100);
        if (error) throw new Error((error as { message?: string }).message ?? "Query failed");
        if (cancelled) return;
        setState({ status: "ready", users: (data ?? []) as AdminUser[] });
      } catch (e) {
        if (!cancelled) setState({ status: "error", error: e instanceof Error ? e.message : String(e) });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [search, nonce]);

  return { state, reload: () => setNonce((n) => n + 1) };
}

// Only these three columns are ever written here; constraining the keys keeps typos
// caught at the call site while the value-enum check is bypassed below.
type ProfileWritable = Partial<Record<"plan" | "role" | "status", string>>;

async function patch(id: string, fields: ProfileWritable): Promise<{ ok: boolean; error?: string }> {
  if (!supabase) return { ok: false, error: "Backend not configured" };
  // The typed client constrains plan/role/status to enum literals; our values are dynamic
  // strings, so cast through `never` to bypass only the literal check (keys stay checked).
  const { error } = await supabase.from("profiles").update(fields as never).eq("id", id);
  return error ? { ok: false, error: (error as { message?: string }).message ?? "Update failed" } : { ok: true };
}

export const setPlan = (id: string, plan: string) => patch(id, { plan });
export const setRole = (id: string, role: string) => patch(id, { role });
export const setStatus = (id: string, status: string) => patch(id, { status });
