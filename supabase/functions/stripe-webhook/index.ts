import Stripe from "npm:stripe@^17";
import { createClient } from "jsr:@supabase/supabase-js@2";

const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!);
const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
const cryptoProvider = Stripe.createSubtleCryptoProvider();

function planForStatus(status: string): "free" | "pro" {
  return status === "active" || status === "trialing" ? "pro" : "free";
}

Deno.serve(async (req) => {
  const sig = req.headers.get("stripe-signature");
  const body = await req.text();
  let event: Stripe.Event;
  try {
    event = await stripe.webhooks.constructEventAsync(
      body, sig ?? "", Deno.env.get("STRIPE_WEBHOOK_SECRET")!, undefined, cryptoProvider,
    );
  } catch (e) {
    return new Response(`Bad signature: ${String((e as Error)?.message ?? e)}`, { status: 400 });
  }

  try {
    const handled = ["checkout.session.completed", "customer.subscription.updated", "customer.subscription.deleted"];
    if (handled.includes(event.type)) {
      let sub: Stripe.Subscription;
      // Prefer the user id baked into the (Stripe-signed) Checkout session.
      let userId: string | null = null;
      if (event.type === "checkout.session.completed") {
        const s = event.data.object as Stripe.Checkout.Session;
        userId = (s.client_reference_id as string | null) ?? null;
        if (!s.subscription) return new Response("ok (no subscription on session)", { status: 200 });
        sub = await stripe.subscriptions.retrieve(s.subscription as string);
      } else {
        sub = event.data.object as Stripe.Subscription;
      }
      const customerId = sub.customer as string;

      // Fall back to the existing row, then the customer's metadata, if no client_reference_id.
      if (!userId) {
        const { data: existing } = await admin
          .from("subscriptions").select("user_id").eq("stripe_customer_id", customerId).limit(1).maybeSingle();
        userId = (existing?.user_id as string | undefined) ?? null;
      }
      if (!userId) {
        const customer = (await stripe.customers.retrieve(customerId)) as Stripe.Customer;
        userId = (customer.metadata?.supabase_user_id as string | undefined) ?? null;
      }

      if (!userId) {
        // Don't 500 (Stripe would retry forever); ack but log so it surfaces in get_logs.
        console.error(`stripe-webhook: unresolved user for customer ${customerId} (sub ${sub.id}, ${event.type})`);
        return new Response("ok (unresolved user)", { status: 200 });
      }

      {
        const item = sub.items.data[0];
        // current_period_end moved from the subscription to the item in recent Stripe
        // API versions; read the item first, fall back to the (older) subscription field.
        const periodEnd =
          (item as { current_period_end?: number } | undefined)?.current_period_end ??
          (sub as { current_period_end?: number }).current_period_end ?? null;
        await admin.from("subscriptions").upsert(
          {
            user_id: userId,
            stripe_customer_id: customerId,
            stripe_subscription_id: sub.id,
            price_id: item?.price?.id ?? null,
            status: sub.status,
            amount_cents: item?.price?.unit_amount ?? null,
            currency: item?.price?.currency ?? "usd",
            current_period_end: periodEnd ? new Date(periodEnd * 1000).toISOString() : null,
            cancel_at_period_end: sub.cancel_at_period_end ?? false,
          },
          { onConflict: "stripe_subscription_id" },
        );
        await admin.from("profiles").update({ plan: planForStatus(sub.status) }).eq("id", userId);
      }
    }
    return new Response("ok", { status: 200 });
  } catch (e) {
    return new Response(`Handler error: ${String((e as Error)?.message ?? e)}`, { status: 500 });
  }
});
