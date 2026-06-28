import { useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../lib/supabase";

export interface RecentUser {
  email: string;
  full_name: string | null;
  plan: string;
  status: string;
  created_at: string;
}
export interface DayPoint {
  day: string;
  count: number;
}
export interface DashboardStats {
  total_users: number;
  paid_users: number;
  free_users: number;
  active_today: number;
  mrr_cents: number;
  signups_7d: number;
}
export interface DashboardData {
  stats: DashboardStats;
  recentUsers: RecentUser[];
  signups: DayPoint[];
  subscriptions: DayPoint[];
}
export type AdminDashboardState =
  | { status: "loading" }
  | { status: "error"; error: string }
  | { status: "ready"; data: DashboardData };

const num = (v: unknown): number => {
  const n = Number(v ?? 0);
  return Number.isFinite(n) ? n : 0;
};

const toStats = (r: Record<string, unknown> | null): DashboardStats => ({
  total_users: num(r?.total_users),
  paid_users: num(r?.paid_users),
  free_users: num(r?.free_users),
  active_today: num(r?.active_today),
  mrr_cents: num(r?.mrr_cents),
  signups_7d: num(r?.signups_7d),
});

const toDays = (rows: unknown): DayPoint[] =>
  Array.isArray(rows)
    ? rows.map((r) => ({ day: String((r as { day: unknown }).day), count: num((r as { count: unknown }).count) }))
    : [];

export function useAdminDashboard(): AdminDashboardState {
  const [state, setState] = useState<AdminDashboardState>({ status: "loading" });

  useEffect(() => {
    if (!supabaseConfigured || !supabase) {
      setState({ status: "error", error: "Backend not configured" });
      return;
    }
    const client = supabase;
    let cancelled = false;
    void (async () => {
      try {
        const [stats, users, signups, subs] = await Promise.all([
          client.from("admin_dashboard_stats").select("*").single(),
          client
            .from("profiles")
            .select("email,full_name,plan,status,created_at")
            .order("created_at", { ascending: false })
            .limit(8),
          client.rpc("admin_signups_by_day", { days: 14 }),
          client.rpc("admin_subscriptions_by_day", { days: 14 }),
        ]);
        const firstErr = stats.error || users.error || signups.error || subs.error;
        if (firstErr) throw new Error((firstErr as { message?: string }).message ?? "Query failed");
        if (cancelled) return;
        setState({
          status: "ready",
          data: {
            stats: toStats(stats.data as Record<string, unknown> | null),
            recentUsers: (users.data ?? []) as RecentUser[],
            signups: toDays(signups.data),
            subscriptions: toDays(subs.data),
          },
        });
      } catch (e) {
        if (!cancelled) setState({ status: "error", error: e instanceof Error ? e.message : String(e) });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}
