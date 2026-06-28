import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

let rpcResult: { data: unknown; error: unknown } = { data: {}, error: null };
const rpcSpy = vi.fn();
vi.mock("../supabase", () => ({
  supabase: { rpc: (...a: unknown[]) => { rpcSpy(...a); return Promise.resolve(rpcResult); } },
  supabaseConfigured: true,
}));

import { useAppSettings } from "./useAppSettings";

beforeEach(() => {
  rpcResult = { data: {}, error: null };
  rpcSpy.mockClear();
});

describe("useAppSettings", () => {
  it("loads a banner from the public RPC", async () => {
    rpcResult = { data: { announcement_banner: { text: "Hi", severity: "info", dismissible: true } }, error: null };
    const { result } = renderHook(() => useAppSettings());
    await waitFor(() => expect(result.current.announcement_banner?.text).toBe("Hi"));
    expect(rpcSpy).toHaveBeenCalledWith("get_public_settings");
  });
  it("fails open to defaults on rpc error", async () => {
    rpcResult = { data: null, error: { message: "boom" } };
    const { result } = renderHook(() => useAppSettings());
    await waitFor(() => expect(rpcSpy).toHaveBeenCalled());
    expect(result.current.announcement_banner).toBeNull();
  });
});
