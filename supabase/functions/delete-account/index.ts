// delete-account: TOMBSTONE. PacketPilot no longer has user accounts, so there is nothing to
// self-serve delete. Kept deployed so any stale client gets a clear, permanent "gone" instead
// of a confusing gateway 404. Legacy account data from the retired signed-in era is deleted by
// the operator on request (see the privacy policy).

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve((req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  return new Response(
    JSON.stringify({ error: "PacketPilot no longer has user accounts. Email support to have legacy account data deleted." }),
    { status: 410, headers: { ...cors, "Content-Type": "application/json" } },
  );
});
