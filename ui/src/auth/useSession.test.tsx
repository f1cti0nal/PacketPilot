import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor, act } from "@testing-library/react";

const h = {
  configured: true,
  getSession: vi.fn(),
  signInWithPassword: vi.fn(),
  signUp: vi.fn(),
  signOut: vi.fn(),
  onAuthStateChange: vi.fn(),
  single: vi.fn(),
  maybeSingle: vi.fn(),
};

vi.mock("../lib/supabase", () => ({
  get supabaseConfigured() {
    return h.configured;
  },
  supabase: {
    auth: {
      getSession: (...a: unknown[]) => h.getSession(...a),
      signInWithPassword: (...a: unknown[]) => h.signInWithPassword(...a),
      signUp: (...a: unknown[]) => h.signUp(...a),
      signOut: (...a: unknown[]) => h.signOut(...a),
      onAuthStateChange: (...a: unknown[]) => h.onAuthStateChange(...a),
    },
    from: () => ({
      select: () => ({
        eq: () => ({
          // profiles: .single(); subscriptions: .not().limit().maybeSingle()
          single: (...a: unknown[]) => h.single(...a),
          not: () => ({ limit: () => ({ maybeSingle: (...a: unknown[]) => h.maybeSingle(...a) }) }),
        }),
      }),
    }),
  },
}));

import { useSession } from "./useSession";

beforeEach(() => {
  h.configured = true;
  h.getSession.mockResolvedValue({ data: { session: null } });
  h.onAuthStateChange.mockReturnValue({ data: { subscription: { unsubscribe: vi.fn() } } });
  h.signInWithPassword.mockResolvedValue({ data: {}, error: null });
  h.signUp.mockResolvedValue({ data: { session: null }, error: null });
  h.signOut.mockResolvedValue({ error: null });
  h.single.mockResolvedValue({ data: { email: "a@b.com", full_name: "A", plan: "pro" }, error: null });
  h.maybeSingle.mockResolvedValue({ data: null, error: null });
});
afterEach(() => {
  vi.clearAllMocks();
});

const session = (uid = "u1", email = "a@b.com") => ({ user: { id: uid, email } });

describe("useSession", () => {
  it("is anon with no session", async () => {
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
  });

  it("is anon when unconfigured", async () => {
    h.configured = false;
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
  });

  it("is authed with the profile when a session exists", async () => {
    h.getSession.mockResolvedValue({ data: { session: session() } });
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("authed"));
    if (result.current.status !== "authed") throw new Error("not authed");
    expect(result.current.profile.plan).toBe("pro");
    expect(result.current.email).toBe("a@b.com");
    expect(result.current.profile.hasBilling).toBe(false); // no Stripe customer by default
  });

  it("sets hasBilling true when a Stripe customer exists", async () => {
    h.getSession.mockResolvedValue({ data: { session: session() } });
    h.maybeSingle.mockResolvedValue({ data: { stripe_customer_id: "cus_1" }, error: null });
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("authed"));
    if (result.current.status !== "authed") throw new Error("not authed");
    expect(result.current.profile.hasBilling).toBe(true);
  });

  it("keeps an active reverse-trial as Pro and exposes trialEndsAt", async () => {
    const t = new Date(Date.now() + 5 * 86_400_000).toISOString();
    h.getSession.mockResolvedValue({ data: { session: session() } });
    h.single.mockResolvedValue({ data: { email: "a@b.com", full_name: "A", plan: "pro", trial_ends_at: t }, error: null });
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("authed"));
    if (result.current.status !== "authed") throw new Error("not authed");
    expect(result.current.profile.plan).toBe("pro");
    expect(result.current.profile.trialEndsAt).toBe(t);
  });

  it("downgrades an expired trial to effective free", async () => {
    h.getSession.mockResolvedValue({ data: { session: session() } });
    h.single.mockResolvedValue({
      data: { email: "a@b.com", full_name: "A", plan: "pro", trial_ends_at: new Date(Date.now() - 1000).toISOString() },
      error: null,
    });
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("authed"));
    if (result.current.status !== "authed") throw new Error("not authed");
    expect(result.current.profile.plan).toBe("free");
  });

  it("signIn delegates to supabase.auth.signInWithPassword", async () => {
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
    await act(async () => {
      if (result.current.status === "anon") await result.current.signIn("x@y.com", "pw");
    });
    expect(h.signInWithPassword).toHaveBeenCalledWith({ email: "x@y.com", password: "pw" });
  });

  it("signUp passes emailRedirectTo and reports needsConfirm when no session is returned", async () => {
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
    let res: { ok: boolean; needsConfirm?: boolean } | undefined;
    await act(async () => {
      if (result.current.status === "anon") res = await result.current.signUp("x@y.com", "pw");
    });
    expect(h.signUp).toHaveBeenCalledWith({
      email: "x@y.com",
      password: "pw",
      options: { emailRedirectTo: expect.stringContaining("/app") },
    });
    expect(res).toEqual({ ok: true, needsConfirm: true });
  });

  it("re-derives on auth state change", async () => {
    let cb: ((e: string, s: unknown) => void) | undefined;
    h.onAuthStateChange.mockImplementation((fn: (e: string, s: unknown) => void) => {
      cb = fn;
      return { data: { subscription: { unsubscribe: vi.fn() } } };
    });
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
    await act(async () => {
      cb?.("SIGNED_IN", session());
    });
    await waitFor(() => expect(result.current.status).toBe("authed"));
  });
});
