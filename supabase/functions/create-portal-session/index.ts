// create-portal-session: TOMBSTONE. PacketPilot no longer has user accounts or an in-app
// billing surface — the product is free for everyone. Kept deployed so any stale client gets
// a clear, permanent "gone" instead of a confusing gateway 404. The operator manages the
// remaining legacy subscriptions directly in the Stripe dashboard.

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve((req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  return new Response(
    JSON.stringify({ error: "PacketPilot is now free for everyone — there is no billing to manage. Contact support about a legacy subscription." }),
    { status: 410, headers: { ...cors, "Content-Type": "application/json" } },
  );
});
