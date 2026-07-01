import { useCallback, useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../lib/supabase";
import { auth0Configured, auth0Login, auth0Logout, auth0User, completeAuth0RedirectIfPresent } from "../auth/auth0Client";

export interface AdminProfile {
  email: string;
  role: string;
  full_name: string | null;
}

export type AdminSession =
  | { status: "loading" }
  | { status: "unconfigured" }
  | { status: "anon"; login: () => Promise<void> }
  | { status: "forbidden"; email: string; signOut: () => Promise<void> }
  | { status: "admin"; email: string; profile: AdminProfile; signOut: () => Promise<void> };

type Internal =
  | { status: "loading" }
  | { status: "unconfigured" }
  | { status: "anon" }
  | { status: "forbidden"; email: string }
  | { status: "admin"; email: string; profile: AdminProfile };

export function useAdminSession(): AdminSession {
  // Both Supabase (data) and Auth0 (login) must be configured for the admin console.
  const identityReady = supabaseConfigured && auth0Configured;
  const [state, setState] = useState<Internal>(identityReady ? { status: "loading" } : { status: "unconfigured" });

  const login = useCallback(async () => {
    await auth0Login();
  }, []);

  const signOut = useCallback(async () => {
    await auth0Logout();
  }, []);

  useEffect(() => {
    if (!identityReady || !supabase) {
      setState({ status: "unconfigured" });
      return;
    }
    const client = supabase;
    let cancelled = false;

    void (async () => {
      await completeAuth0RedirectIfPresent();
      const user = await auth0User();
      if (cancelled) return;
      if (!user?.sub) {
        setState({ status: "anon" });
        return;
      }
      const email = user.email ?? "";
      const { data, error } = await client
        .from("profiles")
        .select("email,role,full_name")
        .eq("auth0_sub", user.sub)
        .maybeSingle();
      if (cancelled) return;
      if (error || !data || data.role !== "admin") {
        setState({ status: "forbidden", email: (data?.email as string) ?? email });
        return;
      }
      setState({
        status: "admin",
        email: (data.email as string) ?? email,
        profile: {
          email: (data.email as string) ?? email,
          role: data.role as string,
          full_name: (data.full_name as string | null) ?? null,
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
    case "unconfigured":
      return { status: "unconfigured" };
    case "anon":
      return { status: "anon", login };
    case "forbidden":
      return { status: "forbidden", email: state.email, signOut };
    case "admin":
      return { status: "admin", email: state.email, profile: state.profile, signOut };
  }
}
