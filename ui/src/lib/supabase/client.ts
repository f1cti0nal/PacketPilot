import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "./types";

const url = import.meta.env.VITE_SUPABASE_URL;
const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

/** True when both public Supabase env vars are present; the SPA is inert otherwise. */
export const supabaseConfigured: boolean = Boolean(url && anonKey);

/** Shared browser client (anon key, under the logged-in user's JWT). null when unconfigured. */
export const supabase: SupabaseClient<Database> | null = supabaseConfigured
  ? createClient<Database>(url as string, anonKey as string, {
      auth: { persistSession: true, autoRefreshToken: true },
    })
  : null;
