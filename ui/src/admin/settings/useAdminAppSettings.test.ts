import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

let listResult: { data: unknown; error: unknown } = { data: [], error: null };
let eqResult: { error: unknown } = { error: null };
const updateSpy = vi.fn();
const insertSpy = vi.fn();
const deleteSpy = vi.fn();
const eqSpy = vi.fn();
vi.mock("../../lib/supabase", () => {
  const q: Record<string, unknown> = {};
  q.select = () => q;
  q.order = () => Promise.resolve(listResult);
  q.update = (...a: unknown[]) => { updateSpy(...a); return { eq: (...b: unknown[]) => { eqSpy(...b); return Promise.resolve(eqResult); } }; };
  q.insert = (...a: unknown[]) => { insertSpy(...a); return Promise.resolve(eqResult); };
  q.delete = () => ({ eq: (...b: unknown[]) => { deleteSpy(...b); return Promise.resolve(eqResult); } });
  return { supabase: { from: () => q }, supabaseConfigured: true };
});

import { useAdminAppSettings, updateValue, updateDescription, createSetting, deleteSetting } from "./useAdminAppSettings";

const SAMPLE = [
  { key: "branding", value: { product_name: "PacketPilot" }, description: "Branding", updated_at: "2026-06-20T00:00:00Z" },
  { key: "announcement_banner", value: { text: "", severity: "info", dismissible: true }, description: "Banner", updated_at: "2026-06-21T00:00:00Z" },
];

beforeEach(() => {
  listResult = { data: SAMPLE, error: null };
  eqResult = { error: null };
  updateSpy.mockClear(); insertSpy.mockClear(); deleteSpy.mockClear(); eqSpy.mockClear();
});

describe("useAdminAppSettings", () => {
  it("loads settings", async () => {
    const { result } = renderHook(() => useAdminAppSettings());
    await waitFor(() => expect(result.current.state.status).toBe("ready"));
    if (result.current.state.status === "ready") expect(result.current.state.settings).toHaveLength(2);
  });
  it("errors on query failure", async () => {
    listResult = { data: null, error: { message: "boom" } };
    const { result } = renderHook(() => useAdminAppSettings());
    await waitFor(() => expect(result.current.state.status).toBe("error"));
    if (result.current.state.status === "error") expect(result.current.state.error).toBe("boom");
  });
  it("updateValue/updateDescription update by key", async () => {
    expect(await updateValue("branding", { product_name: "X" })).toEqual({ ok: true });
    expect(updateSpy).toHaveBeenCalledWith({ value: { product_name: "X" } });
    expect(eqSpy).toHaveBeenCalledWith("key", "branding");
    await updateDescription("branding", "d");
    expect(updateSpy).toHaveBeenCalledWith({ description: "d" });
  });
  it("createSetting inserts, deleteSetting deletes by key", async () => {
    expect(await createSetting("new_key", "desc")).toEqual({ ok: true });
    expect(insertSpy).toHaveBeenCalledWith({ key: "new_key", description: "desc", value: {} });
    expect(await deleteSetting("new_key")).toEqual({ ok: true });
    expect(deleteSpy).toHaveBeenCalledWith("key", "new_key");
  });
  it("returns the error message on a failed mutation", async () => {
    eqResult = { error: { message: "denied" } };
    expect(await updateValue("branding", {})).toEqual({ ok: false, error: "denied" });
  });
});
