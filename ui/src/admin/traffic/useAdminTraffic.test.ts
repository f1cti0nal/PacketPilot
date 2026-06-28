import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

let statsRes: { data: unknown; error: unknown } = { data: { active_today: 3, pageviews_today: 9, authed_today: 1, anon_today: 2 }, error: null };
let byDayRes: { data: unknown; error: unknown } = { data: [{ day: "2026-06-27", count: 5 }], error: null };
let topRes: { data: unknown; error: unknown } = { data: [{ path: "/app#flows", count: 7 }], error: null };
let recentRes: { data: unknown; error: unknown } = { data: [{ path: "/", user_id: null, created_at: "2026-06-28T00:00:00Z" }, { path: "/admin#users", user_id: "u1", created_at: "2026-06-28T00:01:00Z" }], error: null };

vi.mock("../../lib/supabase", () => {
  const recentQuery = () => {
    const q: Record<string, unknown> = {};
    q.select = () => q;
    q.order = () => q;
    q.limit = () => Promise.resolve(recentRes);
    return q;
  };
  return {
    supabase: {
      from: (t: string) =>
        t === "admin_traffic_stats"
          ? { select: () => ({ single: () => Promise.resolve(statsRes) }) }
          : recentQuery(),
      rpc: (name: string) => Promise.resolve(name === "admin_top_paths" ? topRes : byDayRes),
    },
    supabaseConfigured: true,
  };
});

import { useAdminTraffic } from "./useAdminTraffic";

beforeEach(() => {
  statsRes = { data: { active_today: 3, pageviews_today: 9, authed_today: 1, anon_today: 2 }, error: null };
  byDayRes = { data: [{ day: "2026-06-27", count: 5 }], error: null };
  topRes = { data: [{ path: "/app#flows", count: 7 }], error: null };
  recentRes = { data: [{ path: "/", user_id: null, created_at: "2026-06-28T00:00:00Z" }, { path: "/admin#users", user_id: "u1", created_at: "2026-06-28T00:01:00Z" }], error: null };
});

describe("useAdminTraffic", () => {
  it("maps stats, by-day, top paths, and recent (with derived signedIn)", async () => {
    const { result } = renderHook(() => useAdminTraffic());
    await waitFor(() => expect(result.current.state.status).toBe("ready"));
    if (result.current.state.status === "ready") {
      const d = result.current.state.data;
      expect(d.stats.active_today).toBe(3);
      expect(d.byDay).toHaveLength(1);
      expect(d.topPaths[0]).toEqual({ path: "/app#flows", count: 7 });
      expect(d.recent[0].signedIn).toBe(false);
      expect(d.recent[1].signedIn).toBe(true);
      expect(d.recent[1]).not.toHaveProperty("user_id");
    }
  });

  it("errors when a query fails", async () => {
    statsRes = { data: null, error: { message: "denied" } };
    const { result } = renderHook(() => useAdminTraffic());
    await waitFor(() => expect(result.current.state.status).toBe("error"));
    if (result.current.state.status === "error") expect(result.current.state.error).toBe("denied");
  });
});
