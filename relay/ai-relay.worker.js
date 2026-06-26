// PacketPilot — browser AI streaming relay (Cloudflare Worker).
//
// Zero-infra, free-tier, public HTTPS — good when PacketPilot is deployed (not just localhost).
//   npm create cloudflare@latest my-relay   # or `wrangler init`
//   # replace src with this file, then:
//   wrangler deploy
//   # set vars/secrets:
//   wrangler secret put AI_API_KEY          # optional — keeps the key off the browser
//   #   ALLOW_ORIGIN can be a plain var in wrangler.toml (your app's exact origin)
//   # then: Settings → AI Analyst → Proxy URL = https://<your-worker>.workers.dev
//
// Same contract as relay/ai-relay.mjs: POST { url, headers, method, body } → upstream, body streamed back.

export default {
  async fetch(request, env) {
    const origin = env.ALLOW_ORIGIN ?? "*";
    const cors = {
      "access-control-allow-origin": origin,
      "access-control-allow-methods": "POST, OPTIONS",
      "access-control-allow-headers": "content-type",
      ...(origin !== "*" ? { vary: "origin" } : {}),
    };

    // CORS preflight (sent because the browser POSTs application/json).
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (request.method !== "POST") return new Response("POST only", { status: 405, headers: cors });

    let payload;
    try {
      payload = await request.json();
    } catch {
      return new Response("invalid JSON body", { status: 400, headers: cors });
    }
    const { url, headers = {}, method = "POST", body } = payload;
    if (typeof url !== "string" || !/^https?:\/\//i.test(url)) {
      return new Response("missing or invalid 'url'", { status: 400, headers: cors });
    }

    // Optional hardening: inject the key server-side (leave the Settings API Key field blank).
    const upstreamHeaders = { ...headers };
    if (env.AI_API_KEY) upstreamHeaders.authorization = `Bearer ${env.AI_API_KEY}`;

    let upstream;
    try {
      upstream = await fetch(url, { method, headers: upstreamHeaders, body });
    } catch (e) {
      return new Response(`upstream fetch failed: ${e?.message ?? e}`, { status: 502, headers: cors });
    }

    // Workers stream the upstream body through to the client automatically.
    return new Response(upstream.body, {
      status: upstream.status,
      headers: {
        ...cors,
        "content-type": upstream.headers.get("content-type") ?? "text/event-stream",
        "cache-control": "no-cache",
      },
    });
  },
};
