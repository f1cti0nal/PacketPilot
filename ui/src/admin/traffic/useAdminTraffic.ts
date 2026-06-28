import { useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../../lib/supabase";
import type { DayPoint } from "../useAdminDashboard";

export interface TrafficStats {
  active_today: number;
  pageviews_today: number;
  authed_today: number;
  anon_today: number;
}
export interface TopPath {
  path: string;
  count: number;
}
export interface RecentEvent {
  path: string;
  signedIn: boolean;
  created_at: string;
}
export interface TrafficData {
  stats: TrafficStats;
  byDay: DayPoint[];
  topPaths: TopPath[];
  recent: RecentEvent[];
}
export type AdminTrafficState =
  | { status: "loading" }
  | { status: "error"; error: string }
  | { status: "ready"; data: TrafficData };

const num = (v: unknown): number => {
  const n = Number(v ?? 0);
  return Number.isFinite(n) ? n : 0;
};
const toStats = (r: Record<string, unknown> | null): TrafficStats => ({
  active_today: num(r?.active_today),
  pageviews_today: num(r?.pageviews_today),
  authed_today: num(r?.authed_today),
  anon_today: num(r?.anon_today),
});
const toDays = (rows: unknown): DayPoint[] =>
  Array.isArray(rows) ? rows.map((r) => ({ day: String((r as { day: unknown }).day), count: num((r as { count: unknown }).count) })) : [];
const toTop = (rows: unknown): TopPath[] =>
  Array.isArray(rows) ? rows.map((r) => ({ path: String((r as { path: unknown }).path), count: num((r as { count: unknown }).count) })) : [];
const toRecent = (rows: unknown): RecentEvent[] =>
  Array.isArray(rows)
    ? rows.map((r) => {
        const e = r as { path: unknown; user_id: unknown; created_at: unknown };
        return { path: String(e.path), signedIn: e.user_id != null, created_at: String(e.created_at) };
      })
    : [];

export function useAdminTraffic(): { state: AdminTrafficState; reload: () => void } {
  const [state, setState] = useState<AdminTrafficState>({ status: "loading" });
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    if (!supabaseConfigured || !supabase) {
      setState({ status: "error", error: "Backend not configured" });
      return;
    }
    const client = supabase;
    let cancelled = false;
    void (async () => {
      try {
        const [stats, byDay, top, recent] = await Promise.all([
          client.from("admin_traffic_stats").select("*").single(),
          client.rpc("admin_pageviews_by_day", { days: 14 }),
          client.rpc("admin_top_paths", { days: 7, lim: 10 }),
          client.from("analytics_events").select("path,user_id,created_at").order("created_at", { ascending: false }).limit(25),
        ]);
        const firstErr = stats.error || byDay.error || top.error || recent.error;
        if (firstErr) throw new Error((firstErr as { message?: string }).message ?? "Query failed");
        if (cancelled) return;
        setState({
          status: "ready",
          data: {
            stats: toStats(stats.data as Record<string, unknown> | null),
            byDay: toDays(byDay.data),
            topPaths: toTop(top.data),
            recent: toRecent(recent.data),
          },
        });
      } catch (e) {
        if (!cancelled) setState({ status: "error", error: e instanceof Error ? e.message : String(e) });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [nonce]);

  return { state, reload: () => setNonce((n) => n + 1) };
}
