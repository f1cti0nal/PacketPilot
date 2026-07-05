import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor, act } from "@testing-library/react";

/** GoTrue session shape the hook reads (session.user = { id, email, email_confirmed_at }). */
type FakeSession = { user: { id: string; email?: string; email_confirmed_at?: string | null } } | null;

// Hoisted, per-test-mutable holder. `configured` toggles supabaseConfigured; the rest back the
// fake supabase client so each test can steer session + row reads + delegate spies.
const h = {
  configured: true,
  session: null as FakeSession,
  profile: vi.fn(),
  sub: vi.fn(),
  signInWithPassword: vi.fn(),
  signUp: vi.fn(),
  signInWithOAuth: vi.fn(),
  signOut: vi.fn(),
  resend: vi.fn(),
};

vi.mock("../lib/supabase", () => ({
  get supabaseConfigured() {
    return h.configured;
  },
  supabase: {
    auth: {
      getSession: () => Promise.resolve({ data: { session: h.session } }),
      // Store nothing — no state-change events are emitted in these tests; just hand back the
      // unsubscribe shape the effect cleanup calls.
      onAuthStateChange: () => ({ data: { subscription: { unsubscribe: () => {} } } }),
      signInWithPassword: (...a: unknown[]) => h.signInWithPassword(...a),
      signUp: (...a: unknown[]) => h.signUp(...a),
      signInWithOAuth: (...a: unknown[]) => h.signInWithOAuth(...a),
      signOut: (...a: unknown[]) => h.signOut(...a),
      resend: (...a: unknown[]) => h.resend(...a),
    },
    from: (table: string) => ({
      select: () => ({
        eq: () => ({
          // profiles: .eq(id).single()
          single: (...a: unknown[]) => h.profile(...a),
          // subscriptions: .eq(user_id).not().limit().maybeSingle()
          not: () => ({ limit: () => ({ maybeSingle: (...a: unknown[]) => h.sub(...a) }) }),
        }),
      }),
      __table: table,
    }),
  },
}));

import { useSession } from "./useSession";

const session = (id = "u1", email = "a@b.com", emailConfirmedAt: string | null = null): FakeSession => ({
  user: { id, email, email_confirmed_at: emailConfirmedAt },
});

beforeEach(() => {
  h.configured = true;
  h.session = null;
  h.profile.mockResolvedValue({ data: { email: "a@b.com", full_name: "A", plan: "pro" }, error: null });
  h.sub.mockResolvedValue({ data: null, error: null });
  h.signInWithPassword.mockResolvedValue({ error: null });
  h.signUp.mockResolvedValue({ data: { session: null }, error: null });
  h.signInWithOAuth.mockResolvedValue({ error: null });
  h.signOut.mockResolvedValue({ error: null });
  h.resend.mockResolvedValue({ error: null });
});
afterEach(() => {
  vi.clearAllMocks();
});

describe("useSession", () => {
  it("is anon when there is no session", async () => {
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
  });

  it("is anon (never loading) when Supabase is unconfigured", async () => {
    h.configured = false;
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
  });

  it("is authed with the profile when a session exists", async () => {
    h.session = session();
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("authed"));
    if (result.current.status !== "authed") throw new Error("not authed");
    expect(result.current.profile.plan).toBe("pro");
    expect(result.current.email).toBe("a@b.com");
    expect(result.current.profile.hasBilling).toBe(false); // no Stripe customer by default
    expect(result.current.emailVerified).toBe(false); // email_confirmed_at absent → unverified
  });

  it("reports emailVerified true from email_confirmed_at", async () => {
    h.session = session("u1", "a@b.com", "2026-07-01T00:00:00Z");
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("authed"));
    if (result.current.status !== "authed") throw new Error("not authed");
    expect(result.current.emailVerified).toBe(true);
  });

  it("sets hasBilling true when a Stripe customer exists", async () => {
    h.session = session();
    h.sub.mockResolvedValue({ data: { stripe_customer_id: "cus_1" }, error: null });
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("authed"));
    if (result.current.status !== "authed") throw new Error("not authed");
    expect(result.current.profile.hasBilling).toBe(true);
  });

  it("signIn delegates to supabase.auth.signInWithPassword", async () => {
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
    let out: { ok: boolean; error?: string } | undefined;
    await act(async () => {
      if (result.current.status === "anon") out = await result.current.signIn("a@b.com", "pw");
    });
    expect(h.signInWithPassword).toHaveBeenCalledWith({ email: "a@b.com", password: "pw" });
    expect(out).toEqual({ ok: true });
  });

  it("signIn surfaces the error message on failure", async () => {
    h.signInWithPassword.mockResolvedValue({ error: { message: "bad creds" } });
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
    let out: { ok: boolean; error?: string } | undefined;
    await act(async () => {
      if (result.current.status === "anon") out = await result.current.signIn("a@b.com", "pw");
    });
    expect(out).toEqual({ ok: false, error: "bad creds" });
  });

  it("signUp delegates to supabase.auth.signUp and reports needsConfirm when no session", async () => {
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
    let out: { ok: boolean; needsConfirm?: boolean; error?: string } | undefined;
    await act(async () => {
      if (result.current.status === "anon") out = await result.current.signUp("a@b.com", "pw");
    });
    expect(h.signUp).toHaveBeenCalledWith(
      expect.objectContaining({ email: "a@b.com", password: "pw" }),
    );
    expect(out).toEqual({ ok: true, needsConfirm: true });
  });

  it("signUp reports needsConfirm false when a session is returned immediately", async () => {
    h.signUp.mockResolvedValue({ data: { session: { user: { id: "u1" } } }, error: null });
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
    let out: { ok: boolean; needsConfirm?: boolean; error?: string } | undefined;
    await act(async () => {
      if (result.current.status === "anon") out = await result.current.signUp("a@b.com", "pw");
    });
    expect(out).toEqual({ ok: true, needsConfirm: false });
  });

  it("signInWithProvider delegates to supabase.auth.signInWithOAuth", async () => {
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
    let out: { ok: boolean; error?: string } | undefined;
    await act(async () => {
      if (result.current.status === "anon") out = await result.current.signInWithProvider("google");
    });
    expect(h.signInWithOAuth).toHaveBeenCalledWith(
      expect.objectContaining({ provider: "google" }),
    );
    expect(out).toEqual({ ok: true });
  });

  it("signInWithProvider honors a custom return path (defaults to /app)", async () => {
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
    await act(async () => {
      if (result.current.status === "anon") await result.current.signInWithProvider("github", "/pricing");
    });
    expect(h.signInWithOAuth).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: "github",
        options: expect.objectContaining({ redirectTo: expect.stringContaining("/pricing") }),
      }),
    );
  });

  it("signOut delegates to supabase.auth.signOut", async () => {
    h.session = session();
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("authed"));
    await act(async () => {
      if (result.current.status === "authed") await result.current.signOut();
    });
    expect(h.signOut).toHaveBeenCalled();
  });
});
