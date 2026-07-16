// ai-proxy: public LLM proxy. Uses the operator's AI_API_KEY (env) + admin-managed
// ai_config (provider/model). Streams the upstream completion back to the browser.
// PacketPilot is free for everyone with no accounts, so there is no auth or plan check;
// the operator's key is protected by per-IP and global rate limits plus the admin
// kill-switch (ai_config.enabled).
import { createClient } from "jsr:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const PROVIDER_BASE: Record<string, string> = {
  anthropic: "https://api.anthropic.com/v1",
  openai: "https://api.openai.com/v1",
  openrouter: "https://openrouter.ai/api/v1",
  ollama: "http://localhost:11434/v1",
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...cors, "content-type": "application/json" } });
}

/** First hop of x-forwarded-for — the client IP as seen by the edge runtime. */
function clientIp(req: Request): string {
  const fwd = req.headers.get("x-forwarded-for") ?? "";
  const first = fwd.split(",")[0]?.trim();
  return first || "unknown";
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  const url = Deno.env.get("SUPABASE_URL")!;
  const serviceRole = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const aiKey = Deno.env.get("AI_API_KEY") ?? "";

  const admin = createClient(url, serviceRole);
  // Rate limits — the only guard on the operator's AI key now that access is anonymous.
  // Per-IP to stop a single client hammering, plus a GLOBAL backstop so a distributed
  // caller can't drain the key either. Fail OPEN on error so a rate-limit hiccup never
  // breaks the feature.
  try {
    const [{ data: ipOk }, { data: globalOk }] = await Promise.all([
      admin.rpc("check_rate_limit", { p_key: "ai:ip:" + clientIp(req), p_max: 20, p_window_seconds: 60 }),
      admin.rpc("check_rate_limit", { p_key: "ai:global", p_max: 300, p_window_seconds: 1800 }),
    ]);
    if (ipOk === false || globalOk === false) return json({ error: "rate limit exceeded, slow down" }, 429);
  } catch { /* fail open */ }

  // Admin-managed config (service-role read; app_settings is admin-RLS, so bypass via service role).
  const { data: row } = await admin.from("app_settings").select("value").eq("key", "ai_config").single();
  const cfg = (row?.value ?? {}) as { enabled?: boolean; provider?: string; model?: string };
  if (!cfg.enabled || !aiKey) return json({ error: "AI is not configured" }, 503);

  const baseUrl = (Deno.env.get("AI_BASE_URL") || PROVIDER_BASE[cfg.provider ?? "anthropic"] || PROVIDER_BASE.anthropic).replace(/\/$/, "");
  const model = cfg.model ?? "claude-opus-4-8";

  let messages: unknown;
  try {
    ({ messages } = await req.json());
  } catch {
    return json({ error: "bad request" }, 400);
  }
  if (!Array.isArray(messages) || messages.length === 0 || messages.length > 40) {
    return json({ error: "bad messages" }, 400);
  }
  // Per-element shape check — each message must be {role: system|user|assistant, content: string}.
  const ROLES = new Set(["system", "user", "assistant"]);
  for (const m of messages as unknown[]) {
    const mm = m as { role?: unknown; content?: unknown };
    if (!mm || typeof mm !== "object" || !ROLES.has(mm.role as string) || typeof mm.content !== "string") {
      return json({ error: "bad messages" }, 400);
    }
  }

  const upstream = await fetch(`${baseUrl}/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json", Authorization: `Bearer ${aiKey}` },
    body: JSON.stringify({ model, messages, stream: true }),
    redirect: "manual", // a 3xx must not carry the operator key to a redirect target
  });
  if (!upstream.ok || !upstream.body) {
    return json({ error: "ai upstream error", status: upstream.status }, 502);
  }
  // Stream the SSE straight back.
  return new Response(upstream.body, {
    status: 200,
    headers: { ...cors, "content-type": "text/event-stream", "cache-control": "no-cache" },
  });
});
