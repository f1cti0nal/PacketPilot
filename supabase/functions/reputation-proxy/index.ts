// reputation-proxy: authenticated relay for threat-intel reputation lookups. Injects the operator's
// provider key (env secret) for an ALLOWLISTED provider host only, then forwards a GET.
import { createClient } from "jsr:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

// SSRF/key-exfil guard: the operator key is injected ONLY for these exact hosts.
const PROVIDER: Record<string, { env: string; header: string }> = {
  "api.abuseipdb.com": { env: "ABUSEIPDB_KEY", header: "Key" },
  "www.virustotal.com": { env: "VIRUSTOTAL_KEY", header: "x-apikey" },
  "api.greynoise.io": { env: "GREYNOISE_KEY", header: "key" },
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...cors, "content-type": "application/json" } });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  const url = Deno.env.get("SUPABASE_URL")!;
  const serviceRole = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

  const admin = createClient(url, serviceRole);
  // Auth: require a logged-in user (Supabase GoTrue access token).
  const authz = req.headers.get("Authorization") ?? "";
  const token = authz.startsWith("Bearer ") ? authz.slice(7).trim() : "";
  const { data: userData } = token ? await admin.auth.getUser(token) : { data: { user: null } };
  const user = userData?.user;
  if (!user) return json({ error: "unauthorized" }, 401);
  // Per-user rate limit — protect the operator's provider keys from abuse. Fail OPEN on error.
  try {
    const { data: ok } = await admin.rpc("check_rate_limit", { p_key: "rep:" + user.id, p_max: 120, p_window_seconds: 60 });
    if (ok === false) return json({ error: "rate limit exceeded, slow down" }, 429);
  } catch { /* fail open */ }
  const { data: row } = await admin.from("app_settings").select("value").eq("key", "rep_config").single();
  const cfg = (row?.value ?? {}) as { enabled?: boolean };
  if (!cfg.enabled) return json({ error: "reputation is not configured" }, 503);

  let target: string;
  let headers: Record<string, string>;
  try {
    const b = await req.json();
    target = String(b.url ?? "");
    headers = (b.headers && typeof b.headers === "object") ? b.headers : {};
  } catch {
    return json({ error: "bad request" }, 400);
  }

  let host = "";
  try {
    const u = new URL(target);
    if (u.protocol !== "https:") return json({ error: "https only" }, 400);
    host = u.hostname; // hostname (no port) — exact allowlist match
  } catch {
    return json({ error: "bad url" }, 400);
  }
  const provider = PROVIDER[host];
  if (!provider) return json({ error: "host not allowed" }, 400); // SSRF guard

  const key = Deno.env.get(provider.env) ?? "";
  if (!key) return json({ status: 0, body: "" }); // unconfigured provider → adapter maps to "unavailable"

  // Forward a GET with the injected provider key + ONLY an allowlisted Accept header (never the
  // client's other headers — so the user's JWT or any injected header can't ride upstream).
  // redirect:"manual" prevents a 3xx from carrying the key to a redirect target.
  const fwdHeaders: Record<string, string> = { [provider.header]: key };
  if (typeof headers["Accept"] === "string") fwdHeaders["Accept"] = headers["Accept"];
  const upstream = await fetch(target, { method: "GET", headers: fwdHeaders, redirect: "manual" });
  const body = await upstream.text();
  return json({ status: upstream.status, body });
});
