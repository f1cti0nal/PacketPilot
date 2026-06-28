import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor, act } from "@testing-library/react";

const h = {
  configured: true,
  getSession: vi.fn(),
  signInWithPassword: vi.fn(),
  signOut: vi.fn(),
  onAuthStateChange: vi.fn(),
  single: vi.fn(),
};

vi.mock("../lib/supabase", () => ({
  get supabaseConfigured() {
    return h.configured;
  },
  supabase: {
    auth: {
      getSession: (...a: unknown[]) => h.getSession(...a),
      signInWithPassword: (...a: unknown[]) => h.signInWithPassword(...a),
      signOut: (...a: unknown[]) => h.signOut(...a),
      onAuthStateChange: (...a: unknown[]) => h.onAuthStateChange(...a),
    },
    from: () => ({
      select: () => ({ eq: () => ({ single: (...a: unknown[]) => h.single(...a) }) }),
    }),
  },
}));

import { useAdminSession } from "./useAdminSession";

beforeEach(() => {
  h.configured = true;
  h.getSession.mockResolvedValue({ data: { session: null } });
  h.onAuthStateChange.mockReturnValue({ data: { subscription: { unsubscribe: vi.fn() } } });
  h.signInWithPassword.mockResolvedValue({ data: {}, error: null });
  h.signOut.mockResolvedValue({ error: null });
  h.single.mockResolvedValue({ data: null, error: null });
});
afterEach(() => vi.clearAllMocks());

const session = (uid = "u1", email = "a@b.com") => ({ user: { id: uid, email } });

describe("useAdminSession", () => {
  it("is unconfigured when the client is not configured", async () => {
    h.configured = false;
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("unconfigured"));
  });

  it("is anon when there is no session", async () => {
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
  });

  it("is admin when the signed-in user's profile role is admin", async () => {
    h.getSession.mockResolvedValue({ data: { session: session() } });
    h.single.mockResolvedValue({ data: { email: "a@b.com", role: "admin", full_name: "A" }, error: null });
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("admin"));
  });

  it("is forbidden when the signed-in user's role is not admin", async () => {
    h.getSession.mockResolvedValue({ data: { session: session() } });
    h.single.mockResolvedValue({ data: { email: "a@b.com", role: "user", full_name: "A" }, error: null });
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("forbidden"));
  });

  it("anon.signIn delegates to supabase.auth.signInWithPassword", async () => {
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
    await act(async () => {
      if (result.current.status === "anon") await result.current.signIn("x@y.com", "pw");
    });
    expect(h.signInWithPassword).toHaveBeenCalledWith({ email: "x@y.com", password: "pw" });
  });
});
