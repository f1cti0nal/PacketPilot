import { useCallback, useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../lib/supabase";

export interface UserProfile {
  email: string;
  full_name: string | null;
  plan: string;
  /** True only when a real Stripe customer exists (so "Manage billing" can open the portal).
   *  A Pro plan without one is an admin comp — there's nothing to manage. */
  hasBilling: boolean;
}

export type SessionState =
  | { status: "loading" }
  | {
      status: "anon";
      signIn: (email: string, password: string) => Promise<{ ok: boolean; error?: string }>;
      signUp: (email: string, password: string) => Promise<{ ok: boolean; needsConfirm?: boolean; error?: string }>;
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
        client.from("profiles").select("email,full_name,plan").eq("id", session.user.id).single(),
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
      setState({
        status: "authed",
        email: (data?.email as string) ?? email,
        profile: {
          email: (data?.email as string) ?? email,
          full_name: (data?.full_name as string | null) ?? null,
          plan: (data?.plan as string) ?? "free",
          hasBilling: !!(sub as { stripe_customer_id?: string | null } | null)?.stripe_customer_id,
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
      return { status: "anon", signIn, signUp };
    case "authed":
      return { status: "authed", email: state.email, profile: state.profile, signOut };
  }
}
