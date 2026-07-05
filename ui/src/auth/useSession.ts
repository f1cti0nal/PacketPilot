import { useCallback, useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../lib/supabase";
import { setStorageScope } from "../lib/storageScope";

export interface UserProfile {
  email: string;
  full_name: string | null;
  /** The account's plan: "free" or "pro". */
  plan: string;
  /** True only when a real Stripe customer exists (so "Manage billing" can open the portal).
   *  A Pro plan without one is an admin comp — there's nothing to manage. */
  hasBilling: boolean;
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
       *  provider and back to `redirectPath` (default `/app`), where the session is picked up — so
       *  the promise only resolves with `ok: false` when starting the redirect failed. Callers that
       *  need to resume work after sign-in (e.g. /pricing checkout) pass their own return path. */
      signInWithProvider: (provider: OAuthProvider, redirectPath?: string) => Promise<{ ok: boolean; error?: string }>;
      /** Resend the signup confirmation email (used by the "check your email" state). */
      resendVerification: (email: string) => Promise<{ ok: boolean; error?: string }>;
    }
  | {
      status: "authed";
      email: string;
      /** True once the account's email is confirmed (GoTrue `email_confirmed_at`). With
       *  "Confirm email" on, email/password sign-in without confirmation never yields a session,
       *  and OAuth emails are provider-verified — so this is a safety net for the /app gate. */
      emailVerified: boolean;
      profile: UserProfile;
      /** Resend the confirmation email to the signed-in address. */
      resendVerification: () => Promise<{ ok: boolean; error?: string }>;
      signOut: () => Promise<void>;
    };

type Internal =
  | { status: "loading" }
  | { status: "anon" }
  | { status: "authed"; email: string; emailVerified: boolean; profile: UserProfile };

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

  const signInWithProvider = useCallback(async (provider: OAuthProvider, redirectPath?: string) => {
    if (!supabase) return { ok: false, error: "Accounts are unavailable" };
    // Redirects to the provider, then back to `redirectPath` (default /app) where
    // `detectSessionInUrl` (on by default, the same mechanism the email-confirm link uses)
    // exchanges the code and fires onAuthStateChange. A caller mid-flow (e.g. /pricing checkout)
    // returns to its own page so it can pick up where the visitor left off.
    const { error } = await supabase.auth.signInWithOAuth({
      provider,
      options: { redirectTo: `${window.location.origin}${redirectPath ?? "/app"}` },
    });
    return error ? { ok: false, error: error.message } : { ok: true };
  }, []);

  const resendVerification = useCallback(async (email: string) => {
    if (!supabase) return { ok: false, error: "Accounts are unavailable" };
    const { error } = await supabase.auth.resend({
      type: "signup",
      email,
      options: { emailRedirectTo: `${window.location.origin}/app` },
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

    const derive = async (session: { user?: { id: string; email?: string; email_confirmed_at?: string | null } } | null) => {
      if (!session?.user) {
        // Signed-out: reset browser-local persistence to the anon namespace BEFORE any re-render,
        // so a signed-out view never reads the previous account's captures/annotations.
        setStorageScope(null);
        if (!cancelled) setState({ status: "anon" });
        return;
      }
      // Namespace all device-local stores to THIS account before reading the profile (and before
      // <App/> reads Recent) — the fix for cross-account capture leakage on a shared browser.
      setStorageScope(session.user.id);
      const email = session.user.email ?? "";
      const emailVerified = !!session.user.email_confirmed_at;
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
      const plan = (data?.plan as string) ?? "free";
      const hasBilling = !!(sub as { stripe_customer_id?: string | null } | null)?.stripe_customer_id;
      setState({
        status: "authed",
        email: (data?.email as string) ?? email,
        emailVerified,
        profile: {
          email: (data?.email as string) ?? email,
          full_name: (data?.full_name as string | null) ?? null,
          plan,
          hasBilling,
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
      return { status: "anon", signIn, signUp, signInWithProvider, resendVerification };
    case "authed":
      return {
        status: "authed",
        email: state.email,
        emailVerified: state.emailVerified,
        profile: state.profile,
        resendVerification: () => resendVerification(state.email),
        signOut,
      };
  }
}
