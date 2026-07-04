import Stripe from "npm:stripe@^17";
import { createClient } from "jsr:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const url = Deno.env.get("SUPABASE_URL")!;
    const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    // Auth: require a logged-in user (Supabase GoTrue access token). user.id == profiles.id.
    const authz = req.headers.get("Authorization") ?? "";
    const token = authz.startsWith("Bearer ") ? authz.slice(7).trim() : "";
    const { data: userData } = token ? await admin.auth.getUser(token) : { data: { user: null } };
    const user = userData?.user;
    if (!user) return json({ error: "Unauthorized" }, 401);

    // Best-effort: cancel EVERY Stripe subscription on record so a deleted account stops billing.
    // A churned user (subscribe → cancel → re-subscribe) holds multiple subscription rows, so
    // cancelling a single arbitrary row could leave the genuinely-active subscription billing a
    // gone account. Cancelling every known id guarantees the live one is stopped; cancelling an
    // already-cancelled sub is a harmless no-op we swallow per id.
    const { data: subs } = await admin
      .from("subscriptions")
      .select("stripe_subscription_id")
      .eq("user_id", user.id)
      .not("stripe_subscription_id", "is", null);
    const subIds = [...new Set((subs ?? []).map((s) => s.stripe_subscription_id as string).filter(Boolean))];
    const stripeKey = Deno.env.get("STRIPE_SECRET_KEY");
    if (stripeKey && subIds.length) {
      const stripe = new Stripe(stripeKey);
      for (const id of subIds) {
        try {
          await stripe.subscriptions.cancel(id);
        } catch (_) {
          // Never block account deletion on a Stripe error for one subscription.
        }
      }
    }

    // Delete the internal profile (cascades subscriptions), then the auth identity so the
    // email can be re-registered. Best-effort on the auth user — the profile is already gone.
    const del = await admin.from("profiles").delete().eq("id", user.id);
    if (del.error) return json({ error: del.error.message }, 400);
    try {
      await admin.auth.admin.deleteUser(user.id);
    } catch (_) {
      // Never block account deletion on an auth-admin error.
    }
    return json({ ok: true });
  } catch (e) {
    return json({ error: String((e as Error)?.message ?? e) }, 400);
  }
});
