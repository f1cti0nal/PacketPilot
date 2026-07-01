import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "./types";
import { getAuth0 } from "../../auth/auth0Client";

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
        const c = await getAuth0();
        if (c) {
          try {
            if (await c.isAuthenticated()) {
              const claims = await c.getIdTokenClaims();
              if (claims?.__raw) return claims.__raw;
            }
          } catch {
            /* fall through to anon */
          }
        }
        // Logged-out requests use the anon key as the bearer, like a signed-out client.
        return anonKey as string;
      },
    })
  : null;
