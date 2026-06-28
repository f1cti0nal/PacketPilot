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

import { useAdminFeatureFlags, setEnabled, setPlanGate, setDescription, createFlag, deleteFlag } from "./useAdminFeatureFlags";

const SAMPLE = [
  { key: "ai_assist", description: "AI assist", enabled: true, plan_gate: null, updated_at: "2026-06-20T00:00:00Z" },
  { key: "pcap_export", description: "PCAP export", enabled: false, plan_gate: "pro", updated_at: "2026-06-21T00:00:00Z" },
];

beforeEach(() => {
  listResult = { data: SAMPLE, error: null };
  eqResult = { error: null };
  updateSpy.mockClear(); insertSpy.mockClear(); deleteSpy.mockClear(); eqSpy.mockClear();
});

describe("useAdminFeatureFlags", () => {
  it("loads flags into the ready state", async () => {
    const { result } = renderHook(() => useAdminFeatureFlags());
    await waitFor(() => expect(result.current.state.status).toBe("ready"));
    if (result.current.state.status === "ready") expect(result.current.state.flags).toHaveLength(2);
  });

  it("surfaces a query error", async () => {
    listResult = { data: null, error: { message: "boom" } };
    const { result } = renderHook(() => useAdminFeatureFlags());
    await waitFor(() => expect(result.current.state.status).toBe("error"));
    if (result.current.state.status === "error") expect(result.current.state.error).toBe("boom");
  });

  it("setEnabled/setPlanGate/setDescription update by key and return ok", async () => {
    expect(await setEnabled("ai_assist", false)).toEqual({ ok: true });
    expect(updateSpy).toHaveBeenCalledWith({ enabled: false });
    expect(eqSpy).toHaveBeenCalledWith("key", "ai_assist");
    await setPlanGate("ai_assist", "pro");
    expect(updateSpy).toHaveBeenCalledWith({ plan_gate: "pro" });
    await setDescription("ai_assist", "x");
    expect(updateSpy).toHaveBeenCalledWith({ description: "x" });
  });

  it("createFlag inserts and deleteFlag deletes by key", async () => {
    expect(await createFlag("new_flag", "desc")).toEqual({ ok: true });
    expect(insertSpy).toHaveBeenCalledWith({ key: "new_flag", description: "desc" });
    expect(await deleteFlag("new_flag")).toEqual({ ok: true });
    expect(deleteSpy).toHaveBeenCalledWith("key", "new_flag");
  });

  it("returns the error message on a failed mutation", async () => {
    eqResult = { error: { message: "denied" } };
    expect(await setEnabled("ai_assist", true)).toEqual({ ok: false, error: "denied" });
  });
});
