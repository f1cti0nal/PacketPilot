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
  const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
  const serviceRole = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

  const userClient = createClient(url, anon, { global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } } });
  const { data: { user } } = await userClient.auth.getUser();
  if (!user) return json({ error: "unauthorized" }, 401);

  const admin = createClient(url, serviceRole);
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
    host = u.host;
  } catch {
    return json({ error: "bad url" }, 400);
  }
  const provider = PROVIDER[host];
  if (!provider) return json({ error: "host not allowed" }, 400); // SSRF guard

  const key = Deno.env.get(provider.env) ?? "";
  if (!key) return json({ status: 0, body: "" }); // unconfigured provider → adapter maps to "unavailable"

  // Forward a GET with the client's (non-key) headers + the injected provider key.
  const fwdHeaders: Record<string, string> = { ...headers, [provider.header]: key };
  delete fwdHeaders.authorization; // never forward the user's Supabase JWT upstream
  const upstream = await fetch(target, { method: "GET", headers: fwdHeaders });
  const body = await upstream.text();
  return json({ status: upstream.status, body });
});
