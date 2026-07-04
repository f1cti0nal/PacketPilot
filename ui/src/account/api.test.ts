import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const sb = vi.hoisted(() => ({
  from: vi.fn(),
  storage: { from: vi.fn() },
  functions: { invoke: vi.fn() },
  auth: { resetPasswordForEmail: vi.fn(), updateUser: vi.fn(), signOut: vi.fn() },
}));
vi.mock("../lib/supabase", () => ({ supabase: sb }));

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
  sb.auth.resetPasswordForEmail.mockResolvedValue({ error: null });
  sb.auth.updateUser.mockResolvedValue({ error: null });
  sb.auth.signOut.mockResolvedValue({ error: null });
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

  it("sendPasswordReset emails a reset link", async () => {
    expect(await api.sendPasswordReset("a@b.c")).toEqual({ ok: true });
    expect(sb.auth.resetPasswordForEmail).toHaveBeenCalledWith("a@b.c", expect.any(Object));
  });

  it("updatePassword sets a new password for the signed-in user", async () => {
    expect(await api.updatePassword("hunter2pass")).toEqual({ ok: true });
    expect(sb.auth.updateUser).toHaveBeenCalledWith({ password: "hunter2pass" });
  });

  it("updatePassword surfaces the auth error message", async () => {
    sb.auth.updateUser.mockResolvedValue({ error: { message: "Password too weak" } });
    expect(await api.updatePassword("weak")).toEqual({ ok: false, error: "Password too weak" });
  });

  it("signOutEverywhere ends the Supabase session", async () => {
    expect(await api.signOutEverywhere()).toEqual({ ok: true });
    expect(sb.auth.signOut).toHaveBeenCalled();
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
