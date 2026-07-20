// ai-proxy: public LLM proxy. Uses the operator's AI_API_KEY (env) + admin-managed
// ai_config (provider/model). Streams the upstream completion back to the browser.
// PacketPilot is free for everyone with no accounts, so there is no auth or plan check;
// the operator's key is protected by (1) an Origin allowlist so third-party sites can't use
// it as a free backend, (2) per-IP and global rate limits, (3) a request-size cap plus an
// upstream max_tokens so a single call can't be arbitrarily expensive, and (4) the admin
// kill-switch (ai_config.enabled).
import { createClient, type SupabaseClient } from "jsr:@supabase/supabase-js@2";

// Origins allowed to call this proxy from a browser. Non-browser callers (no Origin header)
// are allowed through but stay subject to the rate limits. Override with a comma-separated
// ALLOWED_ORIGINS env for self-host / preview deployments.
const ALLOWED_ORIGINS = (Deno.env.get("ALLOWED_ORIGINS") ?? "https://packetpilot.app")
  .split(",").map((s) => s.trim()).filter(Boolean);

const PROVIDER_BASE: Record<string, string> = {
  anthropic: "https://api.anthropic.com/v1",
  openai: "https://api.openai.com/v1",
  openrouter: "https://openrouter.ai/api/v1",
  ollama: "http://localhost:11434/v1",
};

/** Largest total message-content payload accepted (bytes). The AI works from a derived summary,
 *  which is small; anything larger is abuse of an anonymous, operator-funded endpoint. */
const MAX_CONTENT_BYTES = 128 * 1024;
/** Upstream completion cap so no single call can run up an unbounded bill. A malformed
 *  AI_MAX_TOKENS must not reach the provider as NaN or a fraction — providers type
 *  max_tokens as a positive integer and reject anything else (a silent 400 → 502). */
const MAX_TOKENS_RAW = Math.floor(Number(Deno.env.get("AI_MAX_TOKENS") ?? "2048"));
const MAX_TOKENS = Number.isFinite(MAX_TOKENS_RAW) && MAX_TOKENS_RAW > 0 ? MAX_TOKENS_RAW : 2048;

/** CORS headers for a given request Origin — echoes the origin when allowed (or when the caller
 *  sends none), so preflight and the actual response agree. */
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

/** True when a browser caller's Origin is not on the allowlist. A missing Origin (non-browser
 *  caller) is allowed through — it can't be an embedded-in-someone-else's-site attack, and it
 *  still faces the rate limits. */
function originBlocked(req: Request): boolean {
  const origin = req.headers.get("Origin");
  return !!origin && !ALLOWED_ORIGINS.includes(origin);
}

function json(body: unknown, status: number, req: Request): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders(req), "content-type": "application/json" } });
}

/** The client IP as seen by the trusted edge. Prefer platform-set single-value headers; fall
 *  back to the LAST hop of x-forwarded-for (the entry appended by the trusted proxy), NEVER the
 *  first — the first is client-supplied and forgeable. Absent/unparseable → one shared bucket. */
function clientIp(req: Request): string {
  const direct = req.headers.get("cf-connecting-ip") ?? req.headers.get("x-real-ip");
  if (direct && direct.trim()) return direct.trim();
  const hops = (req.headers.get("x-forwarded-for") ?? "").split(",").map((h) => h.trim()).filter(Boolean);
  return hops.length ? hops[hops.length - 1] : "shared";
}

/** True while under the cap. Fails OPEN on RPC error so a limiter hiccup doesn't break the
 *  feature — but LOGS it, since the limiter is the only guard on the operator's key. */
async function underLimit(admin: SupabaseClient, key: string, max: number, windowSeconds: number): Promise<boolean> {
  try {
    const { data, error } = await admin.rpc("check_rate_limit", { p_key: key, p_max: max, p_window_seconds: windowSeconds });
    if (error) {
      console.error("ai-proxy rate-limit rpc error:", error.message);
      return true; // fail open, but visible in the function logs
    }
    return data !== false;
  } catch (e) {
    console.error("ai-proxy rate-limit rpc threw:", e);
    return true; // fail open
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders(req) });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405, req);
  if (originBlocked(req)) return json({ error: "origin not allowed" }, 403, req);

  const url = Deno.env.get("SUPABASE_URL")!;
  const serviceRole = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const aiKey = Deno.env.get("AI_API_KEY") ?? "";

  const admin = createClient(url, serviceRole);
  // Rate limits — the only guard on the operator's AI key now that access is anonymous. Check
  // the per-IP bucket FIRST and short-circuit; only count against the global backstop once the
  // per-IP check passes, so a single client's rejected requests can't also burn the shared
  // global window. Per-IP stops one client hammering; the global cap bounds total key spend.
  const ip = clientIp(req);
  if (!(await underLimit(admin, "ai:ip:" + ip, 20, 60))) {
    return json({ error: "rate limit exceeded, slow down" }, 429, req);
  }
  if (!(await underLimit(admin, "ai:global", 300, 1800))) {
    return json({ error: "the AI analyst is busy right now, try again shortly" }, 429, req);
  }

  // Admin-managed config (service-role read; app_settings is admin-RLS, so bypass via service role).
  const { data: row } = await admin.from("app_settings").select("value").eq("key", "ai_config").single();
  const cfg = (row?.value ?? {}) as { enabled?: boolean; provider?: string; model?: string };
  if (!cfg.enabled || !aiKey) return json({ error: "AI is not configured" }, 503, req);

  const baseUrl = (Deno.env.get("AI_BASE_URL") || PROVIDER_BASE[cfg.provider ?? "anthropic"] || PROVIDER_BASE.anthropic).replace(/\/$/, "");
  const model = cfg.model ?? "claude-opus-4-8";

  let messages: unknown;
  try {
    ({ messages } = await req.json());
  } catch {
    return json({ error: "bad request" }, 400, req);
  }
  if (!Array.isArray(messages) || messages.length === 0 || messages.length > 40) {
    return json({ error: "bad messages" }, 400, req);
  }
  // Per-element shape check — each message must be {role: system|user|assistant, content: string}.
  const ROLES = new Set(["system", "user", "assistant"]);
  let totalBytes = 0;
  for (const m of messages as unknown[]) {
    const mm = m as { role?: unknown; content?: unknown };
    if (!mm || typeof mm !== "object" || !ROLES.has(mm.role as string) || typeof mm.content !== "string") {
      return json({ error: "bad messages" }, 400, req);
    }
    totalBytes += (mm.content as string).length;
  }
  // Size cap — bounds per-request cost on the anonymous endpoint (the AI works from a small
  // derived summary; a multi-MB prompt is abuse, not a real analysis).
  if (totalBytes > MAX_CONTENT_BYTES) return json({ error: "request too large" }, 413, req);

  const upstream = await fetch(`${baseUrl}/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json", Authorization: `Bearer ${aiKey}` },
    body: JSON.stringify({ model, messages, stream: true, max_tokens: MAX_TOKENS }),
    redirect: "manual", // a 3xx must not carry the operator key to a redirect target
  });
  if (!upstream.ok || !upstream.body) {
    // Log WHY before collapsing to 502 — a bare status hides root causes that need different
    // fixes: a delisted model (404, e.g. a retired OpenRouter alpha), a revoked key (401),
    // or provider rate limiting (429). The provider's error body names the culprit.
    const detail = (await upstream.text().catch(() => "")).slice(0, 500);
    console.error(
      `ai-proxy upstream error ${upstream.status} (provider=${cfg.provider ?? "anthropic"} model=${model}): ${detail}`,
    );
    return json({ error: "ai upstream error", status: upstream.status }, 502, req);
  }
  // Stream the SSE straight back.
  return new Response(upstream.body, {
    status: 200,
    headers: { ...corsHeaders(req), "content-type": "text/event-stream", "cache-control": "no-cache" },
  });
});
