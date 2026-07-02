import { supabase } from "../lib/supabase";

/**
 * Pull the human-readable reason out of a failed `functions.invoke`.
 *
 * On a non-2xx response supabase-js surfaces a `FunctionsHttpError` whose
 * `.message` is the generic "Edge Function returned a non-2xx status code".
 * The function's real `{ error }` body lives on the unconsumed `Response`
 * hanging off `error.context`, so read that first and only fall back to the
 * generic message (or a network/relay error message) when it isn't there.
 */
async function readInvokeError(error: { message?: string; context?: unknown } | null): Promise<string> {
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

/** Which paid plan a checkout targets (resolved to a Stripe price server-side). */
export type PlanChoice = "monthly" | "annual" | "founder";

async function invokeRedirect(
  name: string,
  body?: Record<string, unknown>,
): Promise<{ ok: boolean; error?: string }> {
  if (!supabase) return { ok: false, error: "Accounts are unavailable" };
  const { data, error } = body
    ? await supabase.functions.invoke(name, { body })
    : await supabase.functions.invoke(name);
  if (error) return { ok: false, error: await readInvokeError(error) };
  const url = (data as { url?: string } | null)?.url;
  if (!url) return { ok: false, error: "No redirect URL returned" };
  window.location.assign(url);
  return { ok: true };
}

/** Start a Stripe Checkout for the chosen Pro plan (redirects to Stripe). */
export const startCheckout = (plan: PlanChoice = "monthly"): Promise<{ ok: boolean; error?: string }> =>
  invokeRedirect("create-checkout-session", { plan });

/** Open the Stripe Billing Portal (manage/cancel; redirects to Stripe). */
export const openPortal = (): Promise<{ ok: boolean; error?: string }> =>
  invokeRedirect("create-portal-session");

/** After returning from Checkout with ?checkout=success, strip the query param and reload
 *  so useSession re-derives the webhook-updated plan from the DB (the plan lives in
 *  profiles/subscriptions, not the session token, so a fresh load is what refreshes it). */
export async function reconcileAfterCheckout(): Promise<void> {
  if (typeof window === "undefined") return;
  const params = new URLSearchParams(window.location.search);
  if (params.get("checkout") !== "success") return;
  params.delete("checkout");
  const qs = params.toString();
  window.history.replaceState({}, "", window.location.pathname + (qs ? `?${qs}` : ""));
  window.location.reload();
}
