import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

let result: { data: unknown; error: unknown } = { data: [], error: null };
const orderSpy = vi.fn();
const limitSpy = vi.fn();

vi.mock("../../lib/supabase", () => {
  const makeQuery = () => {
    const q: Record<string, unknown> = {};
    q.select = () => q;
    q.order = (...a: unknown[]) => { orderSpy(...a); return q; };
    q.limit = (...a: unknown[]) => { limitSpy(...a); return Promise.resolve(result); };
    return q;
  };
  return { supabase: { from: () => makeQuery() }, supabaseConfigured: true };
});

import { useAdminPayments } from "./useAdminPayments";

const ROWS = [
  { id: "s1", status: "active", amount_cents: 1900, currency: "usd", price_id: "price_1",
    current_period_end: "2026-07-20T00:00:00Z", cancel_at_period_end: false, created_at: "2026-06-20T00:00:00Z",
    stripe_subscription_id: "sub_1", stripe_customer_id: "cus_1", profiles: { email: "bob@x.com", full_name: "Bob" } },
  { id: "s2", status: "canceled", amount_cents: 1900, currency: "usd", price_id: "price_1",
    current_period_end: null, cancel_at_period_end: true, created_at: "2026-06-21T00:00:00Z",
    stripe_subscription_id: "sub_2", stripe_customer_id: "cus_2", profiles: [{ email: "al@x.com", full_name: "Al" }] },
];

beforeEach(() => {
  result = { data: ROWS, error: null };
  orderSpy.mockClear(); limitSpy.mockClear();
});

describe("useAdminPayments", () => {
  it("loads + flattens embedded profiles (object and array forms)", async () => {
    const { result: hook } = renderHook(() => useAdminPayments());
    await waitFor(() => expect(hook.current.state.status).toBe("ready"));
    if (hook.current.state.status === "ready") {
      expect(hook.current.state.payments).toHaveLength(2);
      expect(hook.current.state.payments[0].email).toBe("bob@x.com");
      expect(hook.current.state.payments[1].email).toBe("al@x.com");
      expect(hook.current.state.payments[1].cancel_at_period_end).toBe(true);
    }
    expect(orderSpy).toHaveBeenCalledWith("created_at", { ascending: false });
    expect(limitSpy).toHaveBeenCalledWith(100);
  });

  it("surfaces a query error", async () => {
    result = { data: null, error: { message: "boom" } };
    const { result: hook } = renderHook(() => useAdminPayments());
    await waitFor(() => expect(hook.current.state.status).toBe("error"));
    if (hook.current.state.status === "error") expect(hook.current.state.error).toBe("boom");
  });
});
