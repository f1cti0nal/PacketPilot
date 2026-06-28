import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

const h = {
  configured: true,
  results: {} as Record<string, { data: unknown; error: unknown }>,
};

vi.mock("../lib/supabase", () => ({
  get supabaseConfigured() {
    return h.configured;
  },
  supabase: {
    from: (table: string) => {
      const b: Record<string, unknown> = {};
      b.select = () => b;
      b.order = () => b;
      b.eq = () => b;
      b.single = () => Promise.resolve(h.results[`${table}:single`]);
      b.limit = () => Promise.resolve(h.results[`${table}:limit`]);
      return b;
    },
    rpc: (name: string) => Promise.resolve(h.results[`rpc:${name}`]),
  },
}));

import { useAdminDashboard } from "./useAdminDashboard";

beforeEach(() => {
  h.configured = true;
  h.results = {
    "admin_dashboard_stats:single": {
      data: { total_users: 5, paid_users: 3, free_users: 2, active_today: 108, mrr_cents: 5700, signups_7d: 3 },
      error: null,
    },
    "profiles:limit": {
      data: [{ email: "a@b.com", full_name: "A", plan: "pro", status: "active", created_at: "2026-06-25T00:00:00Z" }],
      error: null,
    },
    "rpc:admin_signups_by_day": { data: [{ day: "2026-06-27", count: 5 }], error: null },
    "rpc:admin_subscriptions_by_day": { data: [{ day: "2026-06-27", count: 3 }], error: null },
  };
});
afterEach(() => { vi.clearAllMocks(); });

describe("useAdminDashboard", () => {
  it("resolves to ready with coerced stats + arrays", async () => {
    const { result } = renderHook(() => useAdminDashboard());
    await waitFor(() => expect(result.current.status).toBe("ready"));
    if (result.current.status !== "ready") throw new Error("not ready");
    expect(result.current.data.stats.total_users).toBe(5);
    expect(result.current.data.stats.mrr_cents).toBe(5700);
    expect(result.current.data.recentUsers).toHaveLength(1);
    expect(result.current.data.signups[0]).toEqual({ day: "2026-06-27", count: 5 });
  });

  it("coerces bigint-as-string counts to numbers", async () => {
    h.results["admin_dashboard_stats:single"].data = {
      total_users: "5", paid_users: "3", free_users: "2", active_today: "108", mrr_cents: "5700", signups_7d: "3",
    };
    h.results["rpc:admin_signups_by_day"].data = [{ day: "2026-06-27", count: "5" }];
    const { result } = renderHook(() => useAdminDashboard());
    await waitFor(() => expect(result.current.status).toBe("ready"));
    if (result.current.status !== "ready") throw new Error("not ready");
    expect(result.current.data.stats.total_users).toBe(5);
    expect(result.current.data.signups[0].count).toBe(5);
  });

  it("errors when a query fails", async () => {
    h.results["rpc:admin_signups_by_day"] = { data: null, error: { message: "boom" } };
    const { result } = renderHook(() => useAdminDashboard());
    await waitFor(() => expect(result.current.status).toBe("error"));
  });

  it("errors when the backend is unconfigured", async () => {
    h.configured = false;
    const { result } = renderHook(() => useAdminDashboard());
    await waitFor(() => expect(result.current.status).toBe("error"));
  });
});
