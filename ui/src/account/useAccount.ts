import { useCallback, useEffect, useState } from "react";
import { supabase } from "../lib/supabase";

export interface AccountProfile {
  id: string;
  email: string;
  full_name: string | null;
  avatar_url: string | null;
  role: string;
  created_at: string;
}
export interface AccountSubscription {
  status: string;
  price_id: string | null;
  amount_cents: number | null;
  currency: string;
  current_period_end: string | null;
  cancel_at_period_end: boolean;
  stripe_customer_id: string | null;
}
export type AccountState =
  | { status: "loading" }
  | { status: "error"; error: string }
  | { status: "ready"; profile: AccountProfile; subscription: AccountSubscription | null };

/**
 * Loads the signed-in user's own profile + latest subscription row (both RLS-scoped
 * to the caller). The displayed email is taken from the auth user (always current);
 * `profiles.email` is kept in sync by the 0016 trigger for other surfaces.
 */
export function useAccount(): { state: AccountState; reload: () => void } {
  const [state, setState] = useState<AccountState>({ status: "loading" });
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    if (!supabase) {
      setState({ status: "error", error: "Accounts are unavailable" });
      return;
    }
    const client = supabase;
    let cancelled = false;
    setState({ status: "loading" });
    void (async () => {
      const { data: u } = await client.auth.getUser();
      const user = u.user;
      if (cancelled) return;
      if (!user) {
        setState({ status: "error", error: "You're not signed in" });
        return;
      }
      const prof = await client
        .from("profiles")
        .select("id,email,full_name,avatar_url,role,created_at")
        .eq("id", user.id)
        .single();
      if (cancelled) return;
      if (prof.error || !prof.data) {
        setState({ status: "error", error: prof.error?.message ?? "Couldn't load your profile" });
        return;
      }
      const sub = await client
        .from("subscriptions")
        .select("status,price_id,amount_cents,currency,current_period_end,cancel_at_period_end,stripe_customer_id")
        .eq("user_id", user.id)
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle();
      if (cancelled) return;
      const profile = { ...(prof.data as AccountProfile), email: user.email ?? (prof.data as AccountProfile).email };
      setState({ status: "ready", profile, subscription: (sub.data as AccountSubscription | null) ?? null });
    })();
    return () => {
      cancelled = true;
    };
  }, [tick]);

  return { state, reload };
}
