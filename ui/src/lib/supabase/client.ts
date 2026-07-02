import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "./types";

const url = import.meta.env.VITE_SUPABASE_URL;
const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

/** True when both public Supabase env vars are present; the SPA is inert otherwise. */
export const supabaseConfigured: boolean = Boolean(url && anonKey);

/**
 * Shared browser client. Identity is Supabase's own GoTrue session: PostgREST/Storage/
 * Functions automatically carry the signed-in user's access token, and fall back to the
 * anon key when signed out — so public/offline reads behave exactly like a logged-out
 * session. `persistSession` + `autoRefreshToken` keep the session across reloads and
 * refresh it silently; `detectSessionInUrl` completes the email-confirm / OAuth redirect.
 */
export const supabase: SupabaseClient<Database> | null = supabaseConfigured
  ? createClient<Database>(url as string, anonKey as string)
  : null;

/**
 * The current GoTrue access token (JWT) for manual authed fetches to Edge Functions
 * (the proxies), or null when signed out. getSession() reads the locally-persisted
 * session and refreshes if needed — no network round-trip on the happy path.
 */
export async function accessToken(): Promise<string | null> {
  if (!supabase) return null;
  const { data } = await supabase.auth.getSession();
  return data.session?.access_token ?? null;
}
