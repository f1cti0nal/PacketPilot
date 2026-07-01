import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor, act } from "@testing-library/react";

const h = {
  configured: true,
  auth0: true,
  auth0User: vi.fn(),
  auth0Login: vi.fn(),
  auth0Logout: vi.fn(),
  complete: vi.fn(),
  single: vi.fn(),
};

vi.mock("../lib/supabase", () => ({
  get supabaseConfigured() {
    return h.configured;
  },
  supabase: {
    from: () => ({
      select: () => ({ eq: () => ({ maybeSingle: (...a: unknown[]) => h.single(...a) }) }),
    }),
  },
}));

vi.mock("../auth/auth0Client", () => ({
  get auth0Configured() {
    return h.auth0;
  },
  auth0User: (...a: unknown[]) => h.auth0User(...a),
  auth0Login: (...a: unknown[]) => h.auth0Login(...a),
  auth0Logout: (...a: unknown[]) => h.auth0Logout(...a),
  completeAuth0RedirectIfPresent: (...a: unknown[]) => h.complete(...a),
}));

import { useAdminSession } from "./useAdminSession";

const user = (sub = "auth0|1", email = "a@b.com") => ({ sub, email });

beforeEach(() => {
  h.configured = true;
  h.auth0 = true;
  h.complete.mockResolvedValue(undefined);
  h.auth0User.mockResolvedValue(null);
  h.auth0Login.mockResolvedValue(undefined);
  h.auth0Logout.mockResolvedValue(undefined);
  h.single.mockResolvedValue({ data: null, error: null });
});
afterEach(() => {
  vi.clearAllMocks();
});

describe("useAdminSession", () => {
  it("is unconfigured when Supabase is not configured", async () => {
    h.configured = false;
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("unconfigured"));
  });

  it("is unconfigured when Auth0 is not configured", async () => {
    h.auth0 = false;
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("unconfigured"));
  });

  it("is anon when there is no Auth0 user", async () => {
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
  });

  it("is admin when the signed-in user's profile role is admin", async () => {
    h.auth0User.mockResolvedValue(user());
    h.single.mockResolvedValue({ data: { email: "a@b.com", role: "admin", full_name: "A" }, error: null });
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("admin"));
  });

  it("is forbidden when the signed-in user's role is not admin", async () => {
    h.auth0User.mockResolvedValue(user());
    h.single.mockResolvedValue({ data: { email: "a@b.com", role: "user", full_name: "A" }, error: null });
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("forbidden"));
  });

  it("anon.login delegates to Auth0 Universal Login", async () => {
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
    await act(async () => {
      if (result.current.status === "anon") await result.current.login();
    });
    expect(h.auth0Login).toHaveBeenCalled();
  });

  it("falls back to forbidden (never admin) when the role query errors", async () => {
    h.auth0User.mockResolvedValue(user());
    h.single.mockResolvedValue({ data: null, error: { message: "boom" } });
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("forbidden"));
  });
});
