import Stripe from "npm:stripe@^17";
import { createClient } from "jsr:@supabase/supabase-js@2";
import { verifyAuth0, resolveProfileId } from "../_shared/auth0.ts";

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
    const identity = await verifyAuth0(req);
    if (!identity) return json({ error: "Unauthorized" }, 401);

    const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    const profile = await resolveProfileId(admin, identity.sub);
    if (!profile) return json({ error: "Unauthorized" }, 401);
    const { data: existing } = await admin
      .from("subscriptions")
      .select("stripe_customer_id")
      .eq("user_id", profile.id)
      .not("stripe_customer_id", "is", null)
      .limit(1)
      .maybeSingle();
    const customerId = existing?.stripe_customer_id as string | undefined;
    if (!customerId) return json({ error: "No billing account yet" }, 400);

    const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!);
    const origin = req.headers.get("origin") ?? "https://packet-pilot.vercel.app";
    const session = await stripe.billingPortal.sessions.create({ customer: customerId, return_url: `${origin}/app` });
    return json({ url: session.url });
  } catch (e) {
    return json({ error: String((e as Error)?.message ?? e) }, 400);
  }
});
