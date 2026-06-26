// PacketPilot — browser AI streaming relay (zero-dependency Node ≥ 18).
//
//   node relay/ai-relay.mjs
//   # then in PacketPilot: Settings → AI Analyst → Proxy URL = http://localhost:8788
//
// Why this exists: a browser can't call a cloud LLM provider directly — the provider doesn't send
// CORS headers, and your API key would be exposed to the page. This tiny relay (run on YOUR machine)
// receives the browser's request, opens the upstream provider request, and streams the
// text/event-stream response back. The CLI and desktop apps are not browser-sandboxed and need no relay.
//
// Contract (what PacketPilot's browser build POSTs here):
//   POST {this relay}    content-type: application/json
//   { "url": "<provider>/chat/completions", "headers": {...}, "method": "POST",
//     "body": "<chat-completions JSON>", "stream": true }
// The relay forwards to `url` with `headers`+`body` and pipes the response body back verbatim.
//
// Env vars:
//   PORT          listen port (default 8788)
//   ALLOW_ORIGIN  CORS origin to allow (default "*"; set to your app's exact origin to lock it down,
//                 e.g. ALLOW_ORIGIN=https://packetpilot.example)
//   AI_API_KEY    optional: if set, the relay INJECTS this as the Authorization bearer so the key
//                 never lives in the browser — leave Settings → AI Analyst → API Key blank.

import http from "node:http";

const PORT = Number(process.env.PORT ?? 8788);
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN ?? "*";
const SERVER_KEY = process.env.AI_API_KEY ?? "";

function setCors(res) {
  res.setHeader("access-control-allow-origin", ALLOW_ORIGIN);
  res.setHeader("access-control-allow-methods", "POST, OPTIONS");
  // content-type MUST be allowed: the browser POSTs application/json, which triggers a preflight.
  res.setHeader("access-control-allow-headers", "content-type");
  res.setHeader("access-control-max-age", "86400");
  if (ALLOW_ORIGIN !== "*") res.setHeader("vary", "origin");
}

const server = http.createServer(async (req, res) => {
  setCors(res);

  // CORS preflight — the step the naive relay forgets. Must answer OPTIONS with the headers above.
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }
  if (req.method !== "POST") {
    res.writeHead(405);
    res.end("POST only");
    return;
  }

  let payload;
  try {
    payload = JSON.parse(await readBody(req));
  } catch {
    res.writeHead(400);
    res.end("invalid JSON body");
    return;
  }

  const { url, headers = {}, method = "POST", body } = payload;
  // Only proxy to absolute http(s) upstreams; never let the relay be aimed at internal services.
  if (typeof url !== "string" || !/^https?:\/\//i.test(url)) {
    res.writeHead(400);
    res.end("missing or invalid 'url'");
    return;
  }

  // Optional hardening: inject the key server-side so it never lives in the browser.
  const upstreamHeaders = { ...headers };
  if (SERVER_KEY) upstreamHeaders.authorization = `Bearer ${SERVER_KEY}`;

  let upstream;
  try {
    upstream = await fetch(url, { method, headers: upstreamHeaders, body });
  } catch (e) {
    res.writeHead(502);
    res.end(`upstream fetch failed: ${e?.message ?? e}`);
    return;
  }

  // Forward the real upstream status (so a 401/429 surfaces in the app, not a fake 200).
  res.writeHead(upstream.status, {
    "content-type": upstream.headers.get("content-type") ?? "text/event-stream",
    "cache-control": "no-cache",
  });
  if (!upstream.body) {
    res.end();
    return;
  }
  // Stream the SSE body back chunk-by-chunk — do NOT buffer, or tokens won't arrive live.
  try {
    for await (const chunk of upstream.body) res.write(chunk);
  } catch {
    /* client disconnected mid-stream */
  }
  res.end();
});

server.listen(PORT, () => {
  console.log(`PacketPilot AI relay → http://localhost:${PORT}  (allow-origin: ${ALLOW_ORIGIN}${SERVER_KEY ? ", server-side key" : ""})`);
});

function readBody(req) {
  return new Promise((resolve, reject) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => resolve(b));
    req.on("error", reject);
  });
}
