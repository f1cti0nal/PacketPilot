import Stripe from "npm:stripe@^17";
import { createClient } from "jsr:@supabase/supabase-js@2";

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
    const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    // Auth: require a logged-in user (Supabase GoTrue access token). user.id == profiles.id.
    const authz = req.headers.get("Authorization") ?? "";
    const token = authz.startsWith("Bearer ") ? authz.slice(7).trim() : "";
    const { data: userData } = token ? await admin.auth.getUser(token) : { data: { user: null } };
    const user = userData?.user;
    if (!user) return json({ error: "Unauthorized" }, 401);

    // Which plan? Default monthly (back-compat: an empty/legacy body → monthly).
    const body = await req.json().catch(() => ({}));
    const plan: Plan = PLANS.includes(body?.plan) ? body.plan : "monthly";

    const userEmail = user.email ?? undefined;

    // Per-user rate limit (abuse guard on checkout-session creation). Fail OPEN on error.
    try {
      const { data: ok } = await admin.rpc("check_rate_limit", { p_key: "checkout:" + user.id, p_max: 10, p_window_seconds: 60 });
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

    // Founder is a capped, limited offer — reserve a seat ATOMICALLY before creating the Checkout
    // session. Counting confirmed subscriptions here can't bound the offer, because those rows are
    // only written by the webhook AFTER payment: a concurrent pre-webhook burst would all pass a
    // naive "count < cap" and oversell. claim_founder_seat() serializes claimers and holds the
    // seat for a short window. Fail CLOSED on any error so a capped offer is never oversold.
    if (plan === "founder") {
      const cap = Number(pricing.founder_cap ?? 200) || 200;
      const { data: claimed, error: claimErr } = await admin.rpc("claim_founder_seat", {
        p_user_id: user.id,
        p_price_id: priceId,
        p_cap: cap,
      });
      if (claimErr) return json({ error: "Couldn't reserve a founder seat. Please try again." }, 400);
      if (claimed !== true) return json({ error: "Founder seats are sold out." }, 400);
    }

    const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!);

    const { data: existing } = await admin
      .from("subscriptions")
      .select("stripe_customer_id")
      .eq("user_id", user.id)
      .not("stripe_customer_id", "is", null)
      .limit(1)
      .maybeSingle();
    let customerId = existing?.stripe_customer_id as string | undefined;
    if (!customerId) {
      // No mirrored customer yet (e.g. a never-completed prior checkout). Search Stripe by the
      // canonical key so we reuse an existing customer instead of orphaning a duplicate.
      const found = await stripe.customers.search({
        query: `metadata['supabase_user_id']:'${user.id}'`,
        limit: 1,
      });
      customerId = found.data[0]?.id;
    }
    if (!customerId) {
      // Idempotency key keyed on the user makes two concurrent first-time checkouts converge on
      // ONE customer (Stripe dedupes by key for 24h) — closes the customer-dedup race (I-3).
      const customer = await stripe.customers.create(
        { email: userEmail, metadata: { supabase_user_id: user.id } },
        { idempotencyKey: `customer_${user.id}` },
      );
      customerId = customer.id;
    }

    const origin = req.headers.get("origin") ?? "https://packetpilot.app";
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer: customerId,
      line_items: [{ price: priceId, quantity: 1 }],
      client_reference_id: user.id,
      success_url: `${origin}/app?checkout=success`,
      cancel_url: `${origin}/pricing?checkout=cancel`,
    });
    return json({ url: session.url });
  } catch (e) {
    return json({ error: String((e as Error)?.message ?? e) }, 400);
  }
});
