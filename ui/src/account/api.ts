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

/** Email the user a secure link to set a new password (Supabase recovery flow). The link lands on
 *  /account, where the signed-in recovery session can set a new password via `updatePassword`. */
export async function sendPasswordReset(email: string): Promise<Result> {
  if (!supabase) return NO_BACKEND;
  const redirectTo = typeof window !== "undefined" ? `${window.location.origin}/account` : undefined;
  const { error } = await supabase.auth.resetPasswordForEmail(email, { redirectTo });
  return error ? { ok: false, error: error.message } : { ok: true };
}

/** Set a new password for the signed-in user. Works for any provider — including an OAuth-only
 *  account (Google/GitHub) adding a password so it can also sign in with email. */
export async function updatePassword(newPassword: string): Promise<Result> {
  if (!supabase) return NO_BACKEND;
  const { error } = await supabase.auth.updateUser({ password: newPassword });
  return error ? { ok: false, error: error.message } : { ok: true };
}

/** End the Supabase session on this device. */
export async function signOutEverywhere(): Promise<Result> {
  if (!supabase) return NO_BACKEND;
  const { error } = await supabase.auth.signOut();
  return error ? { ok: false, error: error.message } : { ok: true };
}

export async function deleteAccount(): Promise<Result> {
  if (!supabase) return NO_BACKEND;
  const { error } = await supabase.functions.invoke("delete-account");
  if (error) return { ok: false, error: await invokeErr(error) };
  // The account and its GoTrue auth user are gone server-side; discard the now-orphaned local
  // session so a cached JWT can't re-enter /app until it expires. Local scope only — the user no
  // longer exists, so there's nothing to sign out server-side. Best-effort: the caller redirects
  // away regardless.
  try {
    await supabase.auth.signOut({ scope: "local" });
  } catch {
    /* ignore — deletion already succeeded */
  }
  return { ok: true };
}
