import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

/* eslint-disable @typescript-eslint/no-explicit-any */
const sb: any = vi.hoisted(() => ({ from: vi.fn() }));
vi.mock("../lib/supabase", () => ({ supabase: sb }));

const a0 = vi.hoisted(() => ({ auth0User: vi.fn() }));
vi.mock("../auth/auth0Client", () => ({ auth0User: (...args: unknown[]) => a0.auth0User(...args) }));

import { useAccount, type AccountState } from "./useAccount";

const profileChain = (data: unknown, error: unknown = null) => ({
  select: () => ({ eq: () => ({ maybeSingle: () => Promise.resolve({ data, error }) }) }),
});
const subChain = (data: unknown) => ({
  select: () => ({
    eq: () => ({ order: () => ({ limit: () => ({ maybeSingle: () => Promise.resolve({ data, error: null }) }) }) }),
  }),
});

beforeEach(() => {
  a0.auth0User.mockResolvedValue({ sub: "auth0|1", email: "new@x.com" });
  sb.from.mockImplementation((t: string) =>
    t === "profiles"
      ? profileChain({ id: "u1", email: "old@x.com", full_name: "Ada", avatar_url: null, role: "user", created_at: "2026-01-01" })
      : subChain({ status: "active", price_id: "p", amount_cents: 1900, currency: "usd", current_period_end: "2026-07-01", cancel_at_period_end: false, stripe_customer_id: "cus_1" }),
  );
});

const ready = (s: AccountState) => s as Extract<AccountState, { status: "ready" }>;

describe("useAccount", () => {
  it("loads the profile (auth email wins) + subscription", async () => {
    const { result } = renderHook(() => useAccount());
    await waitFor(() => expect(result.current.state.status).toBe("ready"));
    const s = ready(result.current.state);
    expect(s.profile.email).toBe("new@x.com");
    expect(s.profile.full_name).toBe("Ada");
    expect(s.subscription?.status).toBe("active");
  });

  it("returns null subscription when the user has none", async () => {
    sb.from.mockImplementation((t: string) =>
      t === "profiles"
        ? profileChain({ id: "u1", email: "a@x.com", full_name: null, avatar_url: null, role: "user", created_at: "2026-01-01" })
        : subChain(null),
    );
    const { result } = renderHook(() => useAccount());
    await waitFor(() => expect(result.current.state.status).toBe("ready"));
    expect(ready(result.current.state).subscription).toBeNull();
  });

  it("errors when the profile read fails", async () => {
    sb.from.mockImplementation(() => profileChain(null, { message: "denied" }));
    const { result } = renderHook(() => useAccount());
    await waitFor(() => expect(result.current.state.status).toBe("error"));
  });

  it("errors when not signed in", async () => {
    a0.auth0User.mockResolvedValue(null);
    const { result } = renderHook(() => useAccount());
    await waitFor(() => expect(result.current.state.status).toBe("error"));
  });
});
