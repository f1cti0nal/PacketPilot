import { useCallback, useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../lib/supabase";

export interface AdminProfile {
  email: string;
  role: string;
  full_name: string | null;
}

export type AdminSession =
  | { status: "loading" }
  | { status: "unconfigured" }
  | { status: "anon"; signIn: (email: string, password: string) => Promise<{ ok: boolean; error?: string }> }
  | { status: "forbidden"; email: string; signOut: () => Promise<void> }
  | { status: "admin"; email: string; profile: AdminProfile; signOut: () => Promise<void> };

type Internal =
  | { status: "loading" }
  | { status: "unconfigured" }
  | { status: "anon" }
  | { status: "forbidden"; email: string }
  | { status: "admin"; email: string; profile: AdminProfile };

export function useAdminSession(): AdminSession {
  const [state, setState] = useState<Internal>(
    supabaseConfigured ? { status: "loading" } : { status: "unconfigured" },
  );

  const signIn = useCallback(async (email: string, password: string) => {
    if (!supabase) return { ok: false, error: "Backend not configured" };
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    return error ? { ok: false, error: error.message } : { ok: true };
  }, []);

  const signOut = useCallback(async () => {
    if (supabase) await supabase.auth.signOut();
  }, []);

  useEffect(() => {
    if (!supabaseConfigured || !supabase) {
      setState({ status: "unconfigured" });
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
      const { data, error } = await client
        .from("profiles")
        .select("email,role,full_name")
        .eq("id", session.user.id)
        .single();
      if (cancelled) return;
      if (error || !data || data.role !== "admin") {
        setState({ status: "forbidden", email: (data?.email as string) ?? email });
        return;
      }
      setState({
        status: "admin",
        email: (data.email as string) ?? email,
        profile: { email: (data.email as string) ?? email, role: data.role as string, full_name: (data.full_name as string | null) ?? null },
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
    case "unconfigured":
      return { status: "unconfigured" };
    case "anon":
      return { status: "anon", signIn };
    case "forbidden":
      return { status: "forbidden", email: state.email, signOut };
    case "admin":
      return { status: "admin", email: state.email, profile: state.profile, signOut };
  }
}
