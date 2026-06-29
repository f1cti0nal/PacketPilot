import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

/* eslint-disable @typescript-eslint/no-explicit-any */
const sb: any = vi.hoisted(() => ({ rpc: vi.fn() }));
vi.mock("../lib/supabase", () => ({ supabase: sb }));
import { usePricing } from "./usePricing";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("usePricing", () => {
  it("reads get_pricing_status and exposes it", async () => {
    sb.rpc.mockResolvedValue({
      data: { annual_available: true, founder_available: true, founder_cap: 200, founder_remaining: 137 },
      error: null,
    });
    const { result } = renderHook(() => usePricing());
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(sb.rpc).toHaveBeenCalledWith("get_pricing_status");
    expect(result.current.status.founder_remaining).toBe(137);
    expect(result.current.status.annual_available).toBe(true);
  });

  it("falls back to safe defaults when the rpc fails", async () => {
    sb.rpc.mockRejectedValue(new Error("nope"));
    const { result } = renderHook(() => usePricing());
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.status.annual_available).toBe(false);
    expect(result.current.status.founder_available).toBe(false);
  });
});
