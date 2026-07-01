import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const sb = vi.hoisted(() => ({
  from: vi.fn(),
  storage: { from: vi.fn() },
  functions: { invoke: vi.fn() },
}));
vi.mock("../lib/supabase", () => ({ supabase: sb }));

const auth0 = vi.hoisted(() => ({
  auth0Logout: vi.fn(),
  auth0SendPasswordReset: vi.fn(),
}));
vi.mock("../auth/auth0Client", () => ({
  auth0Logout: (...a: unknown[]) => auth0.auth0Logout(...a),
  auth0SendPasswordReset: (...a: unknown[]) => auth0.auth0SendPasswordReset(...a),
}));

import * as api from "./api";

const upd = vi.fn();
beforeEach(() => {
  upd.mockResolvedValue({ error: null });
  sb.from.mockReturnValue({ update: (v: unknown) => ({ eq: (_c: string, _id: string) => upd(v) }) });
  sb.functions.invoke.mockResolvedValue({ data: { ok: true }, error: null });
  sb.storage.from.mockReturnValue({
    upload: vi.fn().mockResolvedValue({ error: null }),
    getPublicUrl: vi.fn().mockReturnValue({ data: { publicUrl: "https://cdn/x.png" } }),
  });
  auth0.auth0Logout.mockResolvedValue(undefined);
  auth0.auth0SendPasswordReset.mockResolvedValue({ ok: true });
});
afterEach(() => {
  vi.clearAllMocks();
});

describe("account api", () => {
  it("updateName trims + updates full_name", async () => {
    expect(await api.updateName("u1", "  Ada  ")).toEqual({ ok: true });
    expect(upd).toHaveBeenCalledWith({ full_name: "Ada" });
  });

  it("updateName stores null for an empty name", async () => {
    await api.updateName("u1", "   ");
    expect(upd).toHaveBeenCalledWith({ full_name: null });
  });

  it("uploadAvatar rejects a wrong type before uploading", async () => {
    const f = new File(["x"], "a.gif", { type: "image/gif" });
    const r = await api.uploadAvatar("u1", f);
    expect(r.ok).toBe(false);
    expect(sb.storage.from).not.toHaveBeenCalled();
  });

  it("uploadAvatar rejects oversized files before uploading", async () => {
    const big = new File([new Uint8Array(2 * 1024 * 1024 + 1)], "a.png", { type: "image/png" });
    const r = await api.uploadAvatar("u1", big);
    expect(r.ok).toBe(false);
    expect(sb.storage.from).not.toHaveBeenCalled();
  });

  it("uploadAvatar stores the file + sets avatar_url", async () => {
    const f = new File(["x"], "a.png", { type: "image/png" });
    const r = await api.uploadAvatar("u1", f);
    expect(r).toMatchObject({ ok: true, url: "https://cdn/x.png" });
    expect(upd).toHaveBeenCalledWith({ avatar_url: "https://cdn/x.png" });
  });

  it("removeAvatar clears avatar_url", async () => {
    await api.removeAvatar("u1");
    expect(upd).toHaveBeenCalledWith({ avatar_url: null });
  });

  it("sendPasswordReset delegates to Auth0", async () => {
    expect(await api.sendPasswordReset("a@b.c")).toEqual({ ok: true });
    expect(auth0.auth0SendPasswordReset).toHaveBeenCalledWith("a@b.c");
  });

  it("signOutEverywhere ends the Auth0 session", async () => {
    expect(await api.signOutEverywhere()).toEqual({ ok: true });
    expect(auth0.auth0Logout).toHaveBeenCalled();
  });

  it("deleteAccount invokes the function and succeeds", async () => {
    expect(await api.deleteAccount()).toEqual({ ok: true });
    expect(sb.functions.invoke).toHaveBeenCalledWith("delete-account");
  });

  it("deleteAccount surfaces the function's JSON error body", async () => {
    sb.functions.invoke.mockResolvedValue({
      data: null,
      error: { message: "non-2xx", context: { json: async () => ({ error: "Active subscription" }) } },
    });
    expect(await api.deleteAccount()).toEqual({ ok: false, error: "Active subscription" });
  });
});
