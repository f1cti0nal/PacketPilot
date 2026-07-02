import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor, act } from "@testing-library/react";

const h = {
  configured: true,
  session: null as { user: { id: string; email?: string } } | null,
  getSession: vi.fn(),
  onAuthStateChange: vi.fn(),
  signInWithPassword: vi.fn(),
  signOut: vi.fn(),
  unsubscribe: vi.fn(),
  single: vi.fn(),
};

vi.mock("../lib/supabase", () => ({
  get supabaseConfigured() {
    return h.configured;
  },
  supabase: {
    auth: {
      getSession: (...a: unknown[]) => h.getSession(...a),
      onAuthStateChange: (...a: unknown[]) => h.onAuthStateChange(...a),
      signInWithPassword: (...a: unknown[]) => h.signInWithPassword(...a),
      signOut: (...a: unknown[]) => h.signOut(...a),
    },
    from: () => ({
      select: () => ({ eq: () => ({ maybeSingle: (...a: unknown[]) => h.single(...a) }) }),
    }),
  },
}));

import { useAdminSession } from "./useAdminSession";

const user = (id = "uuid-1", email = "a@b.com") => ({ id, email });

beforeEach(() => {
  h.configured = true;
  h.session = null;
  h.getSession.mockImplementation(async () => ({ data: { session: h.session } }));
  h.onAuthStateChange.mockReturnValue({ data: { subscription: { unsubscribe: h.unsubscribe } } });
  h.signInWithPassword.mockResolvedValue({ error: null });
  h.signOut.mockResolvedValue({ error: null });
  h.single.mockResolvedValue({ data: null, error: null });
});
afterEach(() => {
  vi.clearAllMocks();
});

describe("useAdminSession", () => {
  it("is unconfigured when Supabase is not configured (supabaseConfigured=false)", async () => {
    h.configured = false;
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("unconfigured"));
  });

  it("is anon when there is no session", async () => {
    h.session = null;
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
  });

  it("is admin when the signed-in user's profile role is admin", async () => {
    h.session = { user: user() };
    h.single.mockResolvedValue({ data: { email: "a@b.com", role: "admin", full_name: "A" }, error: null });
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("admin"));
  });

  it("is forbidden when the signed-in user's role is not admin", async () => {
    h.session = { user: user() };
    h.single.mockResolvedValue({ data: { email: "a@b.com", role: "user", full_name: "A" }, error: null });
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("forbidden"));
  });

  it("anon.signIn delegates to supabase.auth.signInWithPassword", async () => {
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
    await act(async () => {
      if (result.current.status === "anon") await result.current.signIn("a@b.com", "pw");
    });
    expect(h.signInWithPassword).toHaveBeenCalledWith({ email: "a@b.com", password: "pw" });
  });

  it("falls back to forbidden (never admin) when the role query errors", async () => {
    h.session = { user: user() };
    h.single.mockResolvedValue({ data: null, error: { message: "boom" } });
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("forbidden"));
  });
});
