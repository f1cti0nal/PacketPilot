import { supabase } from "../lib/supabase";

type Result = { ok: boolean; error?: string };
const NO_BACKEND: Result = { ok: false, error: "Accounts are unavailable" };

const AVATAR_TYPES = ["image/png", "image/jpeg", "image/webp"];
const AVATAR_MAX_BYTES = 2 * 1024 * 1024;

/** Read a failed invoke's real `{error}` body (mirrors auth/billing.ts). */
async function invokeErr(error: { message?: string; context?: unknown } | null): Promise<string> {
  const fallback = error?.message ?? "Something went wrong";
  const ctx = error?.context as { json?: () => Promise<unknown> } | undefined;
  if (!ctx || typeof ctx.json !== "function") return fallback;
  try {
    const body = (await ctx.json()) as { error?: string } | null;
    return body?.error?.trim() || fallback;
  } catch {
    return fallback;
  }
}

export async function updateName(uid: string, fullName: string): Promise<Result> {
  if (!supabase) return NO_BACKEND;
  const name = fullName.trim();
  const { error } = await supabase.from("profiles").update({ full_name: name || null }).eq("id", uid);
  return error ? { ok: false, error: error.message } : { ok: true };
}

export async function uploadAvatar(uid: string, file: File): Promise<Result & { url?: string }> {
  if (!supabase) return NO_BACKEND;
  if (!AVATAR_TYPES.includes(file.type)) return { ok: false, error: "Use a PNG, JPEG, or WebP image" };
  if (file.size > AVATAR_MAX_BYTES) return { ok: false, error: "Image must be 2 MB or smaller" };
  const ext = file.type === "image/png" ? "png" : file.type === "image/webp" ? "webp" : "jpg";
  const path = `${uid}/avatar-${Date.now()}.${ext}`;
  const up = await supabase.storage.from("avatars").upload(path, file, { upsert: true, contentType: file.type });
  if (up.error) return { ok: false, error: up.error.message };
  const url = supabase.storage.from("avatars").getPublicUrl(path).data.publicUrl;
  const { error } = await supabase.from("profiles").update({ avatar_url: url }).eq("id", uid);
  return error ? { ok: false, error: error.message } : { ok: true, url };
}

export async function removeAvatar(uid: string): Promise<Result> {
  if (!supabase) return NO_BACKEND;
  const { error } = await supabase.from("profiles").update({ avatar_url: null }).eq("id", uid);
  return error ? { ok: false, error: error.message } : { ok: true };
}

export async function changePassword(email: string, current: string, next: string): Promise<Result> {
  if (!supabase) return NO_BACKEND;
  if (next.length < 8) return { ok: false, error: "Password must be at least 8 characters" };
  const reauth = await supabase.auth.signInWithPassword({ email, password: current });
  if (reauth.error) return { ok: false, error: "Current password is incorrect" };
  const { error } = await supabase.auth.updateUser({ password: next });
  return error ? { ok: false, error: error.message } : { ok: true };
}

export async function changeEmail(next: string): Promise<Result> {
  if (!supabase) return NO_BACKEND;
  const { error } = await supabase.auth.updateUser({ email: next.trim() });
  return error ? { ok: false, error: error.message } : { ok: true };
}

export async function signOutEverywhere(): Promise<Result> {
  if (!supabase) return NO_BACKEND;
  const { error } = await supabase.auth.signOut({ scope: "global" });
  return error ? { ok: false, error: error.message } : { ok: true };
}

export async function deleteAccount(): Promise<Result> {
  if (!supabase) return NO_BACKEND;
  const { error } = await supabase.functions.invoke("delete-account");
  if (error) return { ok: false, error: await invokeErr(error) };
  return { ok: true };
}
