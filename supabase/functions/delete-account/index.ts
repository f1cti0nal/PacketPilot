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
    const authHeader = req.headers.get("Authorization") ?? "";
    const userClient = createClient(url, Deno.env.get("SUPABASE_ANON_KEY")!, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: { user }, error: uerr } = await userClient.auth.getUser();
    if (uerr || !user) return json({ error: "Unauthorized" }, 401);

    const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    // Best-effort: cancel the live Stripe subscription so a deleted account stops billing.
    const { data: sub } = await admin
      .from("subscriptions")
      .select("stripe_subscription_id")
      .eq("user_id", user.id)
      .not("stripe_subscription_id", "is", null)
      .limit(1)
      .maybeSingle();
    const subId = sub?.stripe_subscription_id as string | undefined;
    const stripeKey = Deno.env.get("STRIPE_SECRET_KEY");
    if (subId && stripeKey) {
      try {
        await new Stripe(stripeKey).subscriptions.cancel(subId);
      } catch (_) {
        // Never block account deletion on a Stripe error.
      }
    }

    const del = await admin.auth.admin.deleteUser(user.id);
    if (del.error) return json({ error: del.error.message }, 400);
    return json({ ok: true });
  } catch (e) {
    return json({ error: String((e as Error)?.message ?? e) }, 400);
  }
});
