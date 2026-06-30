import { useCallback, useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../lib/supabase";

export interface UserProfile {
  email: string;
  full_name: string | null;
  /** Effective plan — already downgraded to "free" if a reverse-trial has expired. */
  plan: string;
  /** True only when a real Stripe customer exists (so "Manage billing" can open the portal).
   *  A Pro plan without one is an admin comp or an active trial — there's nothing to manage. */
  hasBilling: boolean;
  /** When the reverse-trial ends (ISO), or null if not on a trial. Use for "N days left". */
  trialEndsAt: string | null;
}

/** Third-party identity providers offered for one-click sign-in. */
export type OAuthProvider = "google" | "github";

export type SessionState =
  | { status: "loading" }
  | {
      status: "anon";
      signIn: (email: string, password: string) => Promise<{ ok: boolean; error?: string }>;
      signUp: (email: string, password: string) => Promise<{ ok: boolean; needsConfirm?: boolean; error?: string }>;
      /** Begin an OAuth redirect (Google/GitHub). On success the browser navigates away to the
       *  provider and back to `/app`, where the session is picked up — so the promise only resolves
       *  with `ok: false` when starting the redirect failed. */
      signInWithProvider: (provider: OAuthProvider) => Promise<{ ok: boolean; error?: string }>;
    }
  | { status: "authed"; email: string; profile: UserProfile; signOut: () => Promise<void> };

type Internal =
  | { status: "loading" }
  | { status: "anon" }
  | { status: "authed"; email: string; profile: UserProfile };

export function useSession(): SessionState {
  const [state, setState] = useState<Internal>(
    supabaseConfigured ? { status: "loading" } : { status: "anon" },
  );

  const signIn = useCallback(async (email: string, password: string) => {
    if (!supabase) return { ok: false, error: "Accounts are unavailable" };
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    return error ? { ok: false, error: error.message } : { ok: true };
  }, []);

  const signUp = useCallback(async (email: string, password: string) => {
    if (!supabase) return { ok: false, error: "Accounts are unavailable" };
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: { emailRedirectTo: `${window.location.origin}/app` },
    });
    if (error) return { ok: false, error: error.message };
    return { ok: true, needsConfirm: !data.session };
  }, []);

  const signInWithProvider = useCallback(async (provider: OAuthProvider) => {
    if (!supabase) return { ok: false, error: "Accounts are unavailable" };
    // Redirects to the provider, then back to /app where `detectSessionInUrl` (on by default, the
    // same mechanism the email-confirm link uses) exchanges the code and fires onAuthStateChange.
    const { error } = await supabase.auth.signInWithOAuth({
      provider,
      options: { redirectTo: `${window.location.origin}/app` },
    });
    return error ? { ok: false, error: error.message } : { ok: true };
  }, []);

  const signOut = useCallback(async () => {
    if (supabase) await supabase.auth.signOut();
  }, []);

  useEffect(() => {
    if (!supabaseConfigured || !supabase) {
      setState({ status: "anon" });
      return;
    }
    const client = supabase;
    let cancelled = false;

    const derive = async (session: { user?: { id: string; email?: string } } | null) => {
      if (!session?.user) {
        if (!cancelled) setState({ status: "anon" });
        return;
      }
      const email = session.user.email ?? "";
      // Profile (plan/name) + whether a real Stripe customer exists, in parallel. Both are
      // RLS-scoped to the caller's own row; supabase reads resolve (never throw) so Promise.all
      // is safe. A failed read just leaves the field at its safe default.
      const [{ data }, { data: sub }] = await Promise.all([
        client.from("profiles").select("email,full_name,plan,trial_ends_at").eq("id", session.user.id).single(),
        client
          .from("subscriptions")
          .select("stripe_customer_id")
          .eq("user_id", session.user.id)
          .not("stripe_customer_id", "is", null)
          .limit(1)
          .maybeSingle(),
      ]);
      if (cancelled) return;
      // Best-effort: a failed profile read still leaves the user authed (email from the
      // session, plan defaulting to free) rather than bouncing them out.
      const rawPlan = (data?.plan as string) ?? "free";
      const hasBilling = !!(sub as { stripe_customer_id?: string | null } | null)?.stripe_customer_id;
      const trialEndsAt = (data?.trial_ends_at as string | null) ?? null;
      // Reverse-trial: a Pro plan that is past its trial end with no real billing has effectively
      // lapsed — gate as free immediately (the pg_cron downgrade catches up in the DB).
      const trialExpired = !!trialEndsAt && Date.parse(trialEndsAt) < Date.now();
      const plan = rawPlan === "pro" && trialExpired && !hasBilling ? "free" : rawPlan;
      setState({
        status: "authed",
        email: (data?.email as string) ?? email,
        profile: {
          email: (data?.email as string) ?? email,
          full_name: (data?.full_name as string | null) ?? null,
          plan,
          hasBilling,
          trialEndsAt,
        },
      });
    };

    void client.auth.getSession().then(({ data }) => derive(data.session ?? null));
    const { data: sub } = client.auth.onAuthStateChange((_event, session) => void derive(session));
    return () => {
      cancelled = true;
      sub.subscription.unsubscribe();
    };
  }, []);

  switch (state.status) {
    case "loading":
      return { status: "loading" };
    case "anon":
      return { status: "anon", signIn, signUp, signInWithProvider };
    case "authed":
      return { status: "authed", email: state.email, profile: state.profile, signOut };
  }
}
