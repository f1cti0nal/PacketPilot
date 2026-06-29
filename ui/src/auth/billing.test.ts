import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = {
  invoke: vi.fn(),
  refreshSession: vi.fn(),
};
vi.mock("../lib/supabase", () => ({
  supabase: {
    functions: { invoke: (...a: unknown[]) => h.invoke(...a) },
    auth: { refreshSession: (...a: unknown[]) => h.refreshSession(...a) },
  },
}));

import { startCheckout, openPortal, reconcileAfterCheckout } from "./billing";

const origUrl = window.location;

beforeEach(() => {
  h.invoke.mockResolvedValue({ data: { url: "https://stripe.test/cs" }, error: null });
  h.refreshSession.mockResolvedValue({ data: {}, error: null });
  // jsdom: make location.assign + search/pathname stubbable
  Object.defineProperty(window, "location", {
    writable: true,
    value: { assign: vi.fn(), search: "", pathname: "/app", href: "http://localhost/app" },
  });
  window.history.replaceState = vi.fn();
});
afterEach(() => {
  vi.clearAllMocks();
  Object.defineProperty(window, "location", { writable: true, value: origUrl });
});

describe("billing", () => {
  it("startCheckout invokes the checkout function with the plan and redirects", async () => {
    const res = await startCheckout("annual");
    expect(h.invoke).toHaveBeenCalledWith("create-checkout-session", { body: { plan: "annual" } });
    expect(window.location.assign).toHaveBeenCalledWith("https://stripe.test/cs");
    expect(res.ok).toBe(true);
  });

  it("startCheckout defaults to the monthly plan", async () => {
    await startCheckout();
    expect(h.invoke).toHaveBeenCalledWith("create-checkout-session", { body: { plan: "monthly" } });
  });

  it("openPortal invokes the portal function and redirects", async () => {
    await openPortal();
    expect(h.invoke).toHaveBeenCalledWith("create-portal-session");
    expect(window.location.assign).toHaveBeenCalledWith("https://stripe.test/cs");
  });

  it("surfaces an error when invoke fails", async () => {
    h.invoke.mockResolvedValue({ data: null, error: { message: "boom" } });
    const res = await startCheckout();
    expect(res).toEqual({ ok: false, error: "boom" });
    expect(window.location.assign).not.toHaveBeenCalled();
  });

  it("surfaces the function's JSON error body over the generic non-2xx message", async () => {
    // supabase-js wraps a non-2xx as FunctionsHttpError: generic .message + the
    // unconsumed Response on .context whose body carries the real reason.
    h.invoke.mockResolvedValue({
      data: null,
      error: {
        message: "Edge Function returned a non-2xx status code",
        context: { json: async () => ({ error: "No billing account yet" }) },
      },
    });
    const res = await openPortal();
    expect(res).toEqual({ ok: false, error: "No billing account yet" });
    expect(window.location.assign).not.toHaveBeenCalled();
  });

  it("falls back to the generic message when the error body has no usable reason", async () => {
    h.invoke.mockResolvedValue({
      data: null,
      error: {
        message: "Edge Function returned a non-2xx status code",
        context: {
          json: async () => {
            throw new Error("not json");
          },
        },
      },
    });
    const res = await openPortal();
    expect(res).toEqual({ ok: false, error: "Edge Function returned a non-2xx status code" });
  });

  it("reconcileAfterCheckout refreshes + strips the param only on checkout=success", async () => {
    window.location.search = "?checkout=success&x=1";
    await reconcileAfterCheckout();
    expect(h.refreshSession).toHaveBeenCalled();
    expect(window.history.replaceState).toHaveBeenCalled();
  });

  it("reconcileAfterCheckout does nothing without checkout=success", async () => {
    window.location.search = "?x=1";
    await reconcileAfterCheckout();
    expect(h.refreshSession).not.toHaveBeenCalled();
  });
});
