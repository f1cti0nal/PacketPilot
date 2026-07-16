// reputation-proxy: public relay for threat-intel reputation lookups. Injects the operator's
// provider key (env secret) for an ALLOWLISTED provider host + path prefix only, then forwards
// a GET. PacketPilot is free for everyone with no accounts, so there is no auth or plan check;
// the operator's provider keys are protected by (1) an Origin allowlist, (2) the host + path
// allowlist below (SSRF / key-scope guard), (3) per-IP and global rate limits, and (4) the
// admin kill-switch (rep_config.enabled).
import { createClient, type SupabaseClient } from "jsr:@supabase/supabase-js@2";

// Origins allowed to call this proxy from a browser. Non-browser callers (no Origin header)
// are allowed through but stay subject to the rate limits. Override with ALLOWED_ORIGINS.
const ALLOWED_ORIGINS = (Deno.env.get("ALLOWED_ORIGINS") ?? "https://packetpilot.app")
  .split(",").map((s) => s.trim()).filter(Boolean);

// SSRF/key-exfil guard: the operator key is injected ONLY for these exact hosts, and only for
// requests whose path starts with one of the allowlisted prefixes — so an anonymous caller can
// only reach the reputation-lookup endpoints, not arbitrary (e.g. account/quota) GETs on the host.
const PROVIDER: Record<string, { env: string; header: string; paths: string[] }> = {
  "api.abuseipdb.com": { env: "ABUSEIPDB_KEY", header: "Key", paths: ["/api/v2/check"] },
  "www.virustotal.com": { env: "VIRUSTOTAL_KEY", header: "x-apikey", paths: ["/api/v3/ip_addresses/", "/api/v3/domains/", "/api/v3/files/"] },
  "api.greynoise.io": { env: "GREYNOISE_KEY", header: "key", paths: ["/v3/community/"] },
};

function corsHeaders(req: Request): Record<string, string> {
  const origin = req.headers.get("Origin");
  const allow = !origin || ALLOWED_ORIGINS.includes(origin) ? (origin ?? "*") : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
}

function originBlocked(req: Request): boolean {
  const origin = req.headers.get("Origin");
  return !!origin && !ALLOWED_ORIGINS.includes(origin);
}

function json(body: unknown, status: number, req: Request): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders(req), "content-type": "application/json" } });
}

/** The client IP as seen by the trusted edge. Prefer platform-set single-value headers; fall
 *  back to the LAST hop of x-forwarded-for (appended by the trusted proxy), NEVER the first
 *  (client-supplied, forgeable). Absent/unparseable → one shared bucket. */
function clientIp(req: Request): string {
  const direct = req.headers.get("cf-connecting-ip") ?? req.headers.get("x-real-ip");
  if (direct && direct.trim()) return direct.trim();
  const hops = (req.headers.get("x-forwarded-for") ?? "").split(",").map((h) => h.trim()).filter(Boolean);
  return hops.length ? hops[hops.length - 1] : "shared";
}

/** True while under the cap. Fails OPEN on RPC error but LOGS it (the limiter is the only guard). */
async function underLimit(admin: SupabaseClient, key: string, max: number, windowSeconds: number): Promise<boolean> {
  try {
    const { data, error } = await admin.rpc("check_rate_limit", { p_key: key, p_max: max, p_window_seconds: windowSeconds });
    if (error) {
      console.error("reputation-proxy rate-limit rpc error:", error.message);
      return true;
    }
    return data !== false;
  } catch (e) {
    console.error("reputation-proxy rate-limit rpc threw:", e);
    return true;
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders(req) });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405, req);
  if (originBlocked(req)) return json({ error: "origin not allowed" }, 403, req);

  const url = Deno.env.get("SUPABASE_URL")!;
  const serviceRole = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

  const admin = createClient(url, serviceRole);
  // Rate limits — the only guard on the operator's provider keys now that access is anonymous.
  // Per-IP first (short-circuit), then the global backstop, so a client's rejected requests
  // don't also drain the shared global window.
  const ip = clientIp(req);
  if (!(await underLimit(admin, "rep:ip:" + ip, 120, 60))) {
    return json({ error: "rate limit exceeded, slow down" }, 429, req);
  }
  if (!(await underLimit(admin, "rep:global", 3000, 1800))) {
    return json({ error: "reputation lookups are busy right now, try again shortly" }, 429, req);
  }

  const { data: row } = await admin.from("app_settings").select("value").eq("key", "rep_config").single();
  const cfg = (row?.value ?? {}) as { enabled?: boolean };
  if (!cfg.enabled) return json({ error: "reputation is not configured" }, 503, req);

  let target: string;
  let headers: Record<string, string>;
  try {
    const b = await req.json();
    target = String(b.url ?? "");
    headers = (b.headers && typeof b.headers === "object") ? b.headers : {};
  } catch {
    return json({ error: "bad request" }, 400, req);
  }

  let host = "";
  let path = "";
  try {
    const u = new URL(target);
    if (u.protocol !== "https:") return json({ error: "https only" }, 400, req);
    host = u.hostname; // hostname (no port) — exact allowlist match
    path = u.pathname;
  } catch {
    return json({ error: "bad url" }, 400, req);
  }
  const provider = PROVIDER[host];
  if (!provider) return json({ error: "host not allowed" }, 400, req); // SSRF guard (host)
  if (!provider.paths.some((p) => path.startsWith(p))) return json({ error: "path not allowed" }, 400, req); // SSRF guard (path)

  const key = Deno.env.get(provider.env) ?? "";
  if (!key) return json({ status: 0, body: "" }, 200, req); // unconfigured provider → adapter maps to "unavailable"

  // Forward a GET with the injected provider key + ONLY an allowlisted Accept header (never the
  // client's other headers — so the user's JWT or any injected header can't ride upstream).
  // redirect:"manual" prevents a 3xx from carrying the key to a redirect target.
  const fwdHeaders: Record<string, string> = { [provider.header]: key };
  if (typeof headers["Accept"] === "string") fwdHeaders["Accept"] = headers["Accept"];
  const upstream = await fetch(target, { method: "GET", headers: fwdHeaders, redirect: "manual" });
  const body = await upstream.text();
  return json({ status: upstream.status, body }, 200, req);
});
