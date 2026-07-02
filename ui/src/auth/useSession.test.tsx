import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor, act } from "@testing-library/react";

const h = {
  configured: true,
  auth0: true,
  auth0User: vi.fn(),
  auth0Login: vi.fn(),
  auth0Logout: vi.fn(),
  complete: vi.fn(),
  profile: vi.fn(),
  sub: vi.fn(),
};

vi.mock("../lib/supabase", () => ({
  get supabaseConfigured() {
    return h.configured;
  },
  supabase: {
    from: () => ({
      select: () => ({
        eq: () => ({
          // profiles: .eq(auth0_sub).maybeSingle(); subscriptions: .eq(user_id).not().limit().maybeSingle()
          maybeSingle: (...a: unknown[]) => h.profile(...a),
          not: () => ({ limit: () => ({ maybeSingle: (...a: unknown[]) => h.sub(...a) }) }),
        }),
      }),
    }),
  },
}));

vi.mock("./auth0Client", () => ({
  get auth0Configured() {
    return h.auth0;
  },
  auth0User: (...a: unknown[]) => h.auth0User(...a),
  auth0Login: (...a: unknown[]) => h.auth0Login(...a),
  auth0Logout: (...a: unknown[]) => h.auth0Logout(...a),
  completeAuth0RedirectIfPresent: (...a: unknown[]) => h.complete(...a),
}));

import { useSession } from "./useSession";

const user = (sub = "auth0|1", email = "a@b.com") => ({ sub, email });

beforeEach(() => {
  h.configured = true;
  h.auth0 = true;
  h.complete.mockResolvedValue(undefined);
  h.auth0User.mockResolvedValue(null);
  h.auth0Login.mockResolvedValue(undefined);
  h.auth0Logout.mockResolvedValue(undefined);
  h.profile.mockResolvedValue({ data: { id: "p1", email: "a@b.com", full_name: "A", plan: "pro" }, error: null });
  h.sub.mockResolvedValue({ data: null, error: null });
});
afterEach(() => {
  vi.clearAllMocks();
});

describe("useSession", () => {
  it("is anon with no Auth0 user", async () => {
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
  });

  it("is anon when Supabase is unconfigured", async () => {
    h.configured = false;
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
  });

  it("is anon when Auth0 is unconfigured", async () => {
    h.auth0 = false;
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
  });

  it("is authed with the profile when an Auth0 user exists", async () => {
    h.auth0User.mockResolvedValue(user());
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("authed"));
    if (result.current.status !== "authed") throw new Error("not authed");
    expect(result.current.profile.plan).toBe("pro");
    expect(result.current.email).toBe("a@b.com");
    expect(result.current.profile.hasBilling).toBe(false); // no Stripe customer by default
    expect(result.current.emailVerified).toBe(false); // claim absent → treated as unverified
  });

  it("reports emailVerified true only when Auth0 confirms the email", async () => {
    h.auth0User.mockResolvedValue({ sub: "auth0|1", email: "a@b.com", email_verified: true });
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("authed"));
    if (result.current.status !== "authed") throw new Error("not authed");
    expect(result.current.emailVerified).toBe(true);
  });

  it("resolves the profile via the Auth0 subject (completes any redirect first)", async () => {
    h.auth0User.mockResolvedValue(user());
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("authed"));
    expect(h.complete).toHaveBeenCalled();
  });

  it("sets hasBilling true when a Stripe customer exists", async () => {
    h.auth0User.mockResolvedValue(user());
    h.sub.mockResolvedValue({ data: { stripe_customer_id: "cus_1" }, error: null });
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("authed"));
    if (result.current.status !== "authed") throw new Error("not authed");
    expect(result.current.profile.hasBilling).toBe(true);
  });

  it("keeps an active reverse-trial as Pro and exposes trialEndsAt", async () => {
    const t = new Date(Date.now() + 5 * 86_400_000).toISOString();
    h.auth0User.mockResolvedValue(user());
    h.profile.mockResolvedValue({ data: { id: "p1", email: "a@b.com", full_name: "A", plan: "pro", trial_ends_at: t }, error: null });
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("authed"));
    if (result.current.status !== "authed") throw new Error("not authed");
    expect(result.current.profile.plan).toBe("pro");
    expect(result.current.profile.trialEndsAt).toBe(t);
  });

  it("downgrades an expired trial to effective free", async () => {
    h.auth0User.mockResolvedValue(user());
    h.profile.mockResolvedValue({
      data: { id: "p1", email: "a@b.com", full_name: "A", plan: "pro", trial_ends_at: new Date(Date.now() - 1000).toISOString() },
      error: null,
    });
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("authed"));
    if (result.current.status !== "authed") throw new Error("not authed");
    expect(result.current.profile.plan).toBe("free");
  });

  it("login delegates to Auth0 Universal Login", async () => {
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
    await act(async () => {
      if (result.current.status === "anon") await result.current.login();
    });
    expect(h.auth0Login).toHaveBeenCalledWith(undefined);
  });

  it("login passes the sign-up hint through", async () => {
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
    await act(async () => {
      if (result.current.status === "anon") await result.current.login({ signUp: true });
    });
    expect(h.auth0Login).toHaveBeenCalledWith({ signUp: true });
  });

  it("signOut delegates to Auth0 logout", async () => {
    h.auth0User.mockResolvedValue(user());
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("authed"));
    await act(async () => {
      if (result.current.status === "authed") await result.current.signOut();
    });
    expect(h.auth0Logout).toHaveBeenCalled();
  });
});
