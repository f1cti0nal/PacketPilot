import { useCallback, useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../lib/supabase";
import {
  auth0Configured,
  auth0Login,
  auth0Logout,
  auth0User,
  completeAuth0RedirectIfPresent,
} from "./auth0Client";

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

export type SessionState =
  | { status: "loading" }
  | {
      status: "anon";
      /** Redirect to Auth0 Universal Login (pass `signUp` to open the sign-up screen).
       *  The browser navigates away and back, so this promise usually doesn't resolve here. */
      login: (opts?: { signUp?: boolean }) => Promise<void>;
    }
  | {
      status: "authed";
      email: string;
      /** True only when Auth0 reports the email as verified. The /app gate holds unverified
       *  accounts on a "verify your email" screen; feature-gating consumers can ignore it. */
      emailVerified: boolean;
      profile: UserProfile;
      signOut: () => Promise<void>;
    };

type Internal =
  | { status: "loading" }
  | { status: "anon" }
  | { status: "authed"; email: string; emailVerified: boolean; profile: UserProfile };

export function useSession(): SessionState {
  // Identity is available only when BOTH Supabase (data) and Auth0 (login) are configured.
  const identityReady = supabaseConfigured && auth0Configured;
  const [state, setState] = useState<Internal>(identityReady ? { status: "loading" } : { status: "anon" });

  const login = useCallback(async (opts?: { signUp?: boolean }) => {
    await auth0Login(opts);
  }, []);

  const signOut = useCallback(async () => {
    await auth0Logout();
  }, []);

  useEffect(() => {
    if (!identityReady || !supabase) {
      setState({ status: "anon" });
      return;
    }
    const client = supabase;
    let cancelled = false;

    void (async () => {
      // Complete an in-flight Universal Login redirect before checking the session.
      await completeAuth0RedirectIfPresent();
      const user = await auth0User();
      if (cancelled) return;
      if (!user?.sub) {
        setState({ status: "anon" });
        return;
      }
      const email = user.email ?? "";
      // Own profile row, resolved via the Auth0 subject claim (RLS scopes it to the caller).
      const { data } = await client
        .from("profiles")
        .select("id,email,full_name,plan,trial_ends_at")
        .eq("auth0_sub", user.sub)
        .maybeSingle();
      if (cancelled) return;
      // Whether a real Stripe customer exists (drives "Manage billing").
      let hasBilling = false;
      const pid = (data as { id?: string } | null)?.id;
      if (pid) {
        const { data: sub } = await client
          .from("subscriptions")
          .select("stripe_customer_id")
          .eq("user_id", pid)
          .not("stripe_customer_id", "is", null)
          .limit(1)
          .maybeSingle();
        hasBilling = !!(sub as { stripe_customer_id?: string | null } | null)?.stripe_customer_id;
      }
      if (cancelled) return;
      const rawPlan = (data?.plan as string) ?? "free";
      const trialEndsAt = (data?.trial_ends_at as string | null) ?? null;
      // Reverse-trial: a Pro plan past its trial end with no real billing has lapsed —
      // gate as free immediately (the pg_cron downgrade catches up in the DB).
      const trialExpired = !!trialEndsAt && Date.parse(trialEndsAt) < Date.now();
      const plan = rawPlan === "pro" && trialExpired && !hasBilling ? "free" : rawPlan;
      setState({
        status: "authed",
        email: (data?.email as string) ?? email,
        // Auth0 only sends `email_verified: true` once the account is confirmed; treat a
        // missing/false claim as unverified so the /app gate holds it back.
        emailVerified: user.email_verified === true,
        profile: {
          email: (data?.email as string) ?? email,
          full_name: (data?.full_name as string | null) ?? null,
          plan,
          hasBilling,
          trialEndsAt,
        },
      });
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  switch (state.status) {
    case "loading":
      return { status: "loading" };
    case "anon":
      return { status: "anon", login };
    case "authed":
      return {
        status: "authed",
        email: state.email,
        emailVerified: state.emailVerified,
        profile: state.profile,
        signOut,
      };
  }
}
