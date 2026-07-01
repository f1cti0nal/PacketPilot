import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "./types";
import { auth0IdToken } from "../../auth/auth0Client";

const url = import.meta.env.VITE_SUPABASE_URL;
const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

/** True when both public Supabase env vars are present; the SPA is inert otherwise. */
export const supabaseConfigured: boolean = Boolean(url && anonKey);

/**
 * Shared browser client. Identity comes from Auth0 (Third-Party Auth): `accessToken`
 * hands PostgREST/Storage/Functions the Auth0 ID token when signed in, and falls back
 * to the anon key when signed out — so public/offline reads behave exactly like a
 * logged-out Supabase session. Supabase Auth's own session is unused (persistSession
 * off), which is why the Data API trusts the Auth0 JWT instead.
 */
export const supabase: SupabaseClient<Database> | null = supabaseConfigured
  ? createClient<Database>(url as string, anonKey as string, {
      auth: { persistSession: false, autoRefreshToken: false },
      accessToken: async () => {
        // auth0IdToken() never throws (it self-heals to null), but guard anyway so a token
        // failure can NEVER break public/anon requests — they just fall back to the anon key,
        // exactly like a signed-out client.
        try {
          const token = await auth0IdToken();
          if (token) return token;
        } catch {
          /* fall through to anon */
        }
        return anonKey as string;
      },
    })
  : null;
