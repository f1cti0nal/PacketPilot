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

type Plan = "monthly" | "annual" | "founder";
const PLANS: Plan[] = ["monthly", "annual", "founder"];

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const url = Deno.env.get("SUPABASE_URL")!;
    const identity = await verifyAuth0(req);
    if (!identity) return json({ error: "Unauthorized" }, 401);

    // Which plan? Default monthly (back-compat: an empty/legacy body → monthly).
    const body = await req.json().catch(() => ({}));
    const plan: Plan = PLANS.includes(body?.plan) ? body.plan : "monthly";

    const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    const profile = await resolveProfileId(admin, identity.sub);
    if (!profile) return json({ error: "Unauthorized" }, 401);
    const userEmail = profile.email ?? identity.email ?? undefined;

    // Per-user rate limit (abuse guard on checkout-session creation). Fail OPEN on error.
    try {
      const { data: ok } = await admin.rpc("check_rate_limit", { p_key: "checkout:" + identity.sub, p_max: 10, p_window_seconds: 60 });
      if (ok === false) return json({ error: "rate limit exceeded, slow down" }, 429);
    } catch { /* fail open */ }

    // Resolve the Stripe price id from the admin-editable pricing config. Monthly falls back
    // to the STRIPE_PRICE_PRO env var so the original single-price setup keeps working.
    const { data: settingRow } = await admin
      .from("app_settings")
      .select("value")
      .eq("key", "pricing")
      .maybeSingle();
    const pricing = (settingRow?.value ?? {}) as Record<string, string | number | null>;
    const priceId =
      plan === "annual"
        ? (pricing.annual_price_id as string | null)
        : plan === "founder"
          ? (pricing.founder_price_id as string | null)
          : ((pricing.monthly_price_id as string | null) ?? Deno.env.get("STRIPE_PRICE_PRO") ?? null);
    if (!priceId) return json({ error: "That plan isn't available yet." }, 400);

    // Founder is a capped, limited offer — enforce the cap server-side so it can't be oversold.
    if (plan === "founder") {
      const cap = Number(pricing.founder_cap ?? 200) || 200;
      const { count } = await admin
        .from("subscriptions")
        .select("id", { count: "exact", head: true })
        .eq("price_id", priceId)
        .in("status", ["active", "trialing"]);
      if ((count ?? 0) >= cap) return json({ error: "Founder seats are sold out." }, 400);
    }

    const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!);

    const { data: existing } = await admin
      .from("subscriptions")
      .select("stripe_customer_id")
      .eq("user_id", profile.id)
      .not("stripe_customer_id", "is", null)
      .limit(1)
      .maybeSingle();
    let customerId = existing?.stripe_customer_id as string | undefined;
    if (!customerId) {
      // No mirrored customer yet (e.g. a never-completed prior checkout). Search Stripe by the
      // canonical key so we reuse an existing customer instead of orphaning a duplicate.
      const found = await stripe.customers.search({
        query: `metadata['supabase_user_id']:'${profile.id}'`,
        limit: 1,
      });
      customerId = found.data[0]?.id;
    }
    if (!customerId) {
      // Idempotency key keyed on the user makes two concurrent first-time checkouts converge on
      // ONE customer (Stripe dedupes by key for 24h) — closes the customer-dedup race (I-3).
      const customer = await stripe.customers.create(
        { email: userEmail, metadata: { supabase_user_id: profile.id } },
        { idempotencyKey: `customer_${profile.id}` },
      );
      customerId = customer.id;
    }

    const origin = req.headers.get("origin") ?? "https://packetpilot.app";
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer: customerId,
      line_items: [{ price: priceId, quantity: 1 }],
      client_reference_id: profile.id,
      success_url: `${origin}/app?checkout=success`,
      cancel_url: `${origin}/pricing?checkout=cancel`,
    });
    return json({ url: session.url });
  } catch (e) {
    return json({ error: String((e as Error)?.message ?? e) }, 400);
  }
});
