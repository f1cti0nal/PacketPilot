import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

let result: { data: unknown; error: unknown } = { data: [], error: null };
const selectSpy = vi.fn();
vi.mock("../supabase", () => ({
  supabase: { from: () => ({ select: (...a: unknown[]) => { selectSpy(...a); return Promise.resolve(result); } }) },
  supabaseConfigured: true,
}));

import { useFeatureFlags } from "./useFeatureFlags";

beforeEach(() => {
  result = { data: [], error: null };
  selectSpy.mockClear();
});

describe("useFeatureFlags", () => {
  it("returns DEFAULTS without fetching when not authed", () => {
    const { result: h } = renderHook(() => useFeatureFlags(false, "free"));
    expect(h.current.gate("ai_assist")).toBe("on");
    expect(selectSpy).not.toHaveBeenCalled();
  });

  it("reflects DB flags when authed (disabled → off)", async () => {
    result = { data: [{ key: "ai_assist", enabled: false, plan_gate: null }], error: null };
    const { result: h } = renderHook(() => useFeatureFlags(true, "free"));
    await waitFor(() => expect(h.current.gate("ai_assist")).toBe("off"));
    expect(selectSpy).toHaveBeenCalledWith("key,enabled,plan_gate");
  });

  it("evaluates a pro gate as upsell for free users", async () => {
    result = { data: [{ key: "ai_assist", enabled: true, plan_gate: "pro" }], error: null };
    const { result: h } = renderHook(() => useFeatureFlags(true, "free"));
    await waitFor(() => expect(h.current.gate("ai_assist")).toBe("upsell"));
  });

  it("fails open to DEFAULTS on query error", async () => {
    result = { data: null, error: { message: "boom" } };
    const { result: h } = renderHook(() => useFeatureFlags(true, "free"));
    await waitFor(() => expect(selectSpy).toHaveBeenCalled());
    expect(h.current.gate("ai_assist")).toBe("on");
  });
});
