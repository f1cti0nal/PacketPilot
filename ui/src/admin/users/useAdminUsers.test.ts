import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

let usersResult: { data: unknown; error: unknown } = { data: [], error: null };
let eqResult: { error: unknown } = { error: null };
const ilikeSpy = vi.fn();
const orderSpy = vi.fn();
const updateSpy = vi.fn();
const eqSpy = vi.fn();

vi.mock("../../lib/supabase", () => {
  const makeQuery = () => {
    const q: Record<string, unknown> = {};
    q.select = () => q;
    q.ilike = (...a: unknown[]) => { ilikeSpy(...a); return q; };
    q.order = (...a: unknown[]) => { orderSpy(...a); return q; };
    q.limit = () => Promise.resolve(usersResult);
    q.update = (...a: unknown[]) => {
      updateSpy(...a);
      return { eq: (...b: unknown[]) => { eqSpy(...b); return Promise.resolve(eqResult); } };
    };
    return q;
  };
  return { supabase: { from: () => makeQuery() }, supabaseConfigured: true };
});

import { useAdminUsers, setPlan, setRole, setStatus } from "./useAdminUsers";

const SAMPLE = [
  { id: "u1", email: "alice@x.com", full_name: "Alice", plan: "free", role: "user", status: "active", created_at: "2026-06-20T00:00:00Z" },
  { id: "u2", email: "bob@x.com", full_name: "Bob", plan: "pro", role: "user", status: "active", created_at: "2026-06-21T00:00:00Z" },
];

beforeEach(() => {
  usersResult = { data: SAMPLE, error: null };
  eqResult = { error: null };
  ilikeSpy.mockClear(); orderSpy.mockClear(); updateSpy.mockClear(); eqSpy.mockClear();
});

describe("useAdminUsers", () => {
  it("loads users into the ready state, no filter when search is empty", async () => {
    const { result } = renderHook(() => useAdminUsers(""));
    await waitFor(() => expect(result.current.state.status).toBe("ready"));
    if (result.current.state.status === "ready") expect(result.current.state.users).toHaveLength(2);
    expect(ilikeSpy).not.toHaveBeenCalled();
  });

  it("applies an email ILIKE filter when search is non-empty", async () => {
    const { result } = renderHook(() => useAdminUsers("alice"));
    await waitFor(() => expect(result.current.state.status).toBe("ready"));
    expect(ilikeSpy).toHaveBeenCalledWith("email", "%alice%");
  });

  it("surfaces a query error", async () => {
    usersResult = { data: null, error: { message: "boom" } };
    const { result } = renderHook(() => useAdminUsers(""));
    await waitFor(() => expect(result.current.state.status).toBe("error"));
    if (result.current.state.status === "error") expect(result.current.state.error).toBe("boom");
  });

  it("setPlan issues update({plan}) + eq('id', id) and returns ok", async () => {
    const r = await setPlan("u1", "pro");
    expect(updateSpy).toHaveBeenCalledWith({ plan: "pro" });
    expect(eqSpy).toHaveBeenCalledWith("id", "u1");
    expect(r).toEqual({ ok: true });
  });

  it("setStatus/setRole return the error message on failure", async () => {
    eqResult = { error: { message: "denied" } };
    expect(await setStatus("u1", "blocked")).toEqual({ ok: false, error: "denied" });
    expect(await setRole("u2", "admin")).toEqual({ ok: false, error: "denied" });
  });
});
