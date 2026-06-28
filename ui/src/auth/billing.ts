import { supabase } from "../lib/supabase";

async function invokeRedirect(name: string): Promise<{ ok: boolean; error?: string }> {
  if (!supabase) return { ok: false, error: "Accounts are unavailable" };
  const { data, error } = await supabase.functions.invoke(name);
  if (error) return { ok: false, error: error.message };
  const url = (data as { url?: string } | null)?.url;
  if (!url) return { ok: false, error: "No redirect URL returned" };
  window.location.assign(url);
  return { ok: true };
}

/** Start a Stripe Checkout for the Pro subscription (redirects to Stripe). */
export const startCheckout = (): Promise<{ ok: boolean; error?: string }> =>
  invokeRedirect("create-checkout-session");

/** Open the Stripe Billing Portal (manage/cancel; redirects to Stripe). */
export const openPortal = (): Promise<{ ok: boolean; error?: string }> =>
  invokeRedirect("create-portal-session");

/** After returning from Checkout with ?checkout=success, refresh the session so the
 *  webhook-updated plan is re-derived, then strip the query param. */
export async function reconcileAfterCheckout(): Promise<void> {
  if (typeof window === "undefined") return;
  const params = new URLSearchParams(window.location.search);
  if (params.get("checkout") !== "success") return;
  if (supabase) await supabase.auth.refreshSession();
  params.delete("checkout");
  const qs = params.toString();
  window.history.replaceState({}, "", window.location.pathname + (qs ? `?${qs}` : ""));
}
