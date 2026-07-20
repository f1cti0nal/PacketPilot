// create-checkout-session: TOMBSTONE. PacketPilot no longer sells subscriptions — the product
// is free for everyone with no accounts. This function is kept deployed (rather than deleted)
// so any stale client or bookmarked caller gets a clear, permanent "gone" instead of a
// confusing gateway 404. Existing subscriptions are managed directly in Stripe by the operator;
// stripe-webhook stays deployed to keep their records consistent until they are wound down.

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve((req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  return new Response(
    JSON.stringify({ error: "PacketPilot is now free for everyone — there is nothing to purchase." }),
    { status: 410, headers: { ...cors, "Content-Type": "application/json" } },
  );
});
