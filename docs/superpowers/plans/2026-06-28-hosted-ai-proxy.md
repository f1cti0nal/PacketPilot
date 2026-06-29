# Hosted AI Proxy (Slice 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Route the AI Analyst (summary + chat) through an authed `ai-proxy` Edge Function that uses the operator's LLM key (a server secret) + admin-managed provider/model; remove all AI config from `/app`; let the admin manage `ai_config`; surface `AI_API_KEY` read-only in Environment.

**Architecture:** A new Deno `ai-proxy` function authenticates the caller, reads `ai_config` (service-role) + `AI_API_KEY` (env), and streams the LLM SSE back. The browser sends only `{ messages }` via `runViaProxy`. The Phase-9 `app_settings` + `get_public_settings` carry the non-secret AI config; the Phase-8 `ai_assist` flag still gates visibility.

**Tech Stack:** Deno Edge Function (streaming), React 18 + TS, Phase-0 Supabase client, Vitest. Supabase MCP for the migration + function deploy.

## Global Constraints

- **No LLM key/base-URL in the browser.** The key is the `AI_API_KEY` Edge secret; the proxy adds `Authorization` server-side. `ai_config` (enabled/provider/model) is non-secret and is the only AI config the client sees.
- **AI requires a logged-in user** (`ai-proxy` does `getUser` → 401) and `ai_config.enabled`; otherwise the app does not offer AI (no key entry anywhere, all surfaces incl. desktop).
- **Offline/core unaffected:** capture analysis is unchanged + fully client-side; AI is additive.
- **Consent kept**, copy updated to the server path. **No new SPA deps.** Migration is `0014`.
- **Per-task gate:** `npx tsc -b`; final task `npm run test:coverage` (≥80/70) + `npm run build`. UI cmds from `D:\Project\PacketPilot\ui`.

---

### Task 1: Migration `0014` + `ai-proxy` Edge Function (controller-run via MCP)

**Files:** Create `supabase/migrations/0014_ai_config.sql`, `supabase/functions/ai-proxy/index.ts`; Modify `ui/src/lib/supabase/types.ts` (regen if needed).

- [ ] **Step 1: Write `0014_ai_config.sql`**
```sql
-- Non-secret AI config the admin manages; the API key is a server secret (AI_API_KEY).
insert into public.app_settings (key, value, description) values
  ('ai_config', '{"enabled":false,"provider":"anthropic","model":"claude-opus-4-8"}'::jsonb,
   'AI Analyst configuration (provider/model). The API key is a server secret (see Environment).')
on conflict (key) do nothing;

-- Expose ai_config to the app (non-secret) by adding it to the public whitelist.
create or replace function public.get_public_settings()
returns jsonb language sql stable security definer set search_path = '' as $$
  select coalesce(jsonb_object_agg(key, value), '{}'::jsonb)
  from public.app_settings
  where key in ('announcement_banner', 'support_contact_email', 'pro_plan_price_display', 'ai_config');
$$;
grant execute on function public.get_public_settings() to anon, authenticated;
```

- [ ] **Step 2: Apply (MCP `apply_migration`, name `ai_config`).** Then `select public.get_public_settings();` → includes `ai_config`. Advisors: unchanged (get_public_settings WARN already intentional).

- [ ] **Step 3: Write `supabase/functions/ai-proxy/index.ts`** (self-contained Deno; mirrors the Stripe functions' init/CORS):
```ts
// ai-proxy: authenticated LLM proxy. Uses the operator's AI_API_KEY (env) + admin-managed
// ai_config (provider/model). Streams the upstream completion back to the browser.
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

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  const url = Deno.env.get("SUPABASE_URL")!;
  const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
  const serviceRole = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const aiKey = Deno.env.get("AI_API_KEY") ?? "";

  // Auth: require a logged-in user.
  const authHeader = req.headers.get("Authorization") ?? "";
  const userClient = createClient(url, anon, { global: { headers: { Authorization: authHeader } } });
  const { data: { user } } = await userClient.auth.getUser();
  if (!user) return json({ error: "unauthorized" }, 401);

  // Admin-managed config (service-role read; app_settings is admin-RLS, so bypass via service role).
  const admin = createClient(url, serviceRole);
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

  const upstream = await fetch(`${baseUrl}/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json", Authorization: `Bearer ${aiKey}` },
    body: JSON.stringify({ model, messages, stream: true }),
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
```

- [ ] **Step 4: Deploy (MCP `deploy_edge_function`, project brkztcfhmrjjnbjzycie, name `ai-proxy`, `verify_jwt: true`).** Expected: deployed ACTIVE. (`SUPABASE_URL`/`ANON_KEY`/`SERVICE_ROLE_KEY` are auto-injected. `AI_API_KEY` + optional `AI_BASE_URL` are operator-set later.)

- [ ] **Step 5: Verify the gates (controller, no key yet):** an unauthenticated POST → 401; (after the app is wired + the operator sets the key, the full stream is verified at deploy time). Regenerate types if the RPC shape changed (it didn't — still `Json`); otherwise no types change.

- [ ] **Step 6: Commit**
```bash
cd "D:/Project/PacketPilot" && git add supabase/migrations/0014_ai_config.sql supabase/functions/ai-proxy/index.ts && git commit -m "feat(ai): ai-proxy Edge Function + ai_config public read (0014)"
```

---

### Task 2: App AI config read (`publicSettings.ai` + `useAppSettings`)

**Files:** Modify `ui/src/lib/settings/publicSettings.ts` (+ test), `ui/src/lib/settings/useAppSettings.ts` (test already covers the rpc path).

**Interfaces:** Produces `interface AiAppConfig { enabled: boolean; provider: string; model: string }`; `PublicSettings` gains `ai: AiAppConfig`; `SETTINGS_DEFAULTS.ai = { enabled: false, provider: "anthropic", model: "claude-opus-4-8" }`.

- [ ] **Step 1: Extend `publicSettings.test.ts`** — add cases: a valid `ai_config` parses into `ai`; missing → defaults (`enabled:false`); junk → defaults. (Keep the existing banner cases.)
- [ ] **Step 2: Extend `publicSettings.ts`:**
```ts
export interface AiAppConfig { enabled: boolean; provider: string; model: string }
export interface PublicSettings { announcement_banner: AnnouncementBanner | null; ai: AiAppConfig }
export const SETTINGS_DEFAULTS: PublicSettings = {
  announcement_banner: null,
  ai: { enabled: false, provider: "anthropic", model: "claude-opus-4-8" },
};
// in parsePublicSettings, after computing banner:
//   const a = obj.ai_config && typeof obj.ai_config === "object" ? obj.ai_config as Record<string,unknown> : {};
//   const ai: AiAppConfig = {
//     enabled: a.enabled === true,
//     provider: typeof a.provider === "string" ? a.provider : "anthropic",
//     model: typeof a.model === "string" && a.model ? a.model : "claude-opus-4-8",
//   };
//   return { announcement_banner: banner, ai };
```
- [ ] **Step 3:** `useAppSettings` needs no logic change (it already returns `parsePublicSettings(data)`); its test stays green (returns `ai` defaults when the rpc data lacks `ai_config`). Run `cd "D:/Project/PacketPilot/ui" && npx vitest run src/lib/settings && npx tsc -b` → green.
- [ ] **Step 4: Commit** `feat(ai): read admin ai_config in useAppSettings`.

---

### Task 3: `proxyClient` + `run.ts` rewire

**Files:** Create `ui/src/lib/ai/proxyClient.ts` (+ test); Modify `ui/src/lib/ai/run.ts` (+ its test); remove the now-dead browser transports.

- [ ] **Step 1: Write `proxyClient.test.ts`** — mock `../supabase` (`supabase.auth.getSession` → a session with `access_token`; a global `fetch` mock returning a streamed `ReadableStream` of SSE text). Assert: POSTs to `…/functions/v1/ai-proxy` with the bearer + `{ messages }`; streams deltas to `onToken`; returns the full text; non-OK → throws "AI request failed".
- [ ] **Step 2: Write `proxyClient.ts`:**
```ts
import { supabase } from "../supabase";
import { SseAccumulator } from "./sse";
import type { AiMessage } from "./client";

const FN_URL = `${import.meta.env.VITE_SUPABASE_URL ?? ""}/functions/v1/ai-proxy`;

/** Send messages to the ai-proxy Edge Function and stream the completion back. */
export async function runViaProxy(messages: AiMessage[], onToken: (t: string) => void): Promise<string> {
  if (!supabase) throw new Error("AI is unavailable.");
  const { data } = await supabase.auth.getSession();
  const token = data.session?.access_token;
  if (!token) throw new Error("Sign in to use the AI Analyst.");
  const resp = await fetch(FN_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      apikey: import.meta.env.VITE_SUPABASE_ANON_KEY ?? "",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ messages }),
  });
  if (!resp.ok || !resp.body) {
    throw new Error(resp.status === 503 ? "AI is not enabled." : `AI request failed (${resp.status}).`);
  }
  const reader = resp.body.getReader();
  const dec = new TextDecoder();
  const acc = new SseAccumulator();
  let full = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    for (const delta of acc.push(dec.decode(value, { stream: true }))) {
      full += delta;
      onToken(delta);
    }
  }
  return full;
}
```
- [ ] **Step 3: Rewire `run.ts`** — keep `buildContext`, prompts, `AiMessage`. Change the public functions to:
```ts
import type { AnalysisOutput } from "../../types";
import { buildContext } from "./context";
import { SUMMARY_SYSTEM, CHAT_SYSTEM } from "./prompts";
import type { AiMessage } from "./client";
import { runViaProxy } from "./proxyClient";

export async function generateSummary(output: AnalysisOutput, onToken: (t: string) => void): Promise<string> {
  return runViaProxy(
    [{ role: "system", content: SUMMARY_SYSTEM }, { role: "user", content: buildContext(output) }],
    onToken,
  );
}

export async function askChat(output: AnalysisOutput, history: AiMessage[], question: string, onToken: (t: string) => void): Promise<string> {
  return runViaProxy(
    [{ role: "system", content: `${CHAT_SYSTEM}\n\n${buildContext(output)}` }, ...history.slice(-8), { role: "user", content: question }],
    onToken,
  );
}
```
Delete from `run.ts`: `pickTransport`, `tauriTransport`, `isAbsoluteHttpUrl`, the transport imports, the `SseAccumulator` re-export. Update `run.test.ts` to the new `(output, onToken)` / `(output, history, question, onToken)` signatures (mock `./proxyClient`'s `runViaProxy`, assert it's called with the built messages).
- [ ] **Step 4: Remove dead code** — delete `ui/src/lib/ai/transport.ts` and `ui/src/lib/ai/client.ts`'s `chatCompletion` (keep `AiMessage` — move it into `proxyClient.ts` or a small `messages.ts` if removing client.ts entirely; simplest: keep `client.ts` exporting only `export interface AiMessage {…}`). Remove `lib/ai/loopback.ts` usages in components (Task 4). Fix any imports. `npx tsc -b` must pass — resolve every dangling import.
- [ ] **Step 5: Run** `cd "D:/Project/PacketPilot/ui" && npx vitest run src/lib/ai && npx tsc -b` → proxyClient + run tests green; tsc 0.
- [ ] **Step 6: Commit** `feat(ai): route AI summary/chat through the ai-proxy (drop client transports)`.

---

### Task 4: AI components + consent rewire

**Files:** Modify `ui/src/cockpit/AiSummaryCard.tsx`, `ui/src/cockpit/AiChatPanel.tsx`, `ui/src/cockpit/AiConsent.tsx` (+ their tests).

- [ ] **Step 1: `AiConsent.tsx`** — change props to `{ model: string; onProceed; onCancel }` (drop `baseUrl`, `isLoopbackUrl`/`aiNeedsRelay`, the `needsRelay` block, the `local` line). Body copy: "Your capture's **derived summary** — severity counts, top incidents, threat IPs (with evidence), and contacted domains (never raw packets, payloads, or the capture file) — will be sent **via PacketPilot's servers** to the AI provider (model **{model}**) to generate this." Keep the dialog a11y + buttons. Update its test (if any) to the new prop.
- [ ] **Step 2: `AiSummaryCard.tsx`** — props gain `model: string` (the admin model, for the cache + consent display). Replace `getAiConfig`/`getAiEnabled`/`aiNeedsRelay`/`cfg.baseUrl`:
  - `doRun`: `const full = await generateSummary(output, (t) => {…})` (no cfg); `await putAiSummary(captureId, full, model, …)`.
  - `run`: drop the `getAiEnabled()` check (availability is gated by the parent now — the card only renders when AI is available); keep the consent gate (`aiConsentGiven`).
  - Remove the `needsRelay` warning block. `<AiConsent model={model} …>`.
  - Update `AiSummaryCard.test.tsx`: pass `model="claude-opus-4-8"`, mock `../lib/ai/run`'s `generateSummary`, drop relay assertions.
- [ ] **Step 3: `AiChatPanel.tsx`** — props gain `model: string`. `runSend`: `await askChat(output, msgs, q, (t) => {…})` (no cfg). Drop `getAiEnabled`/`getAiConfig`/`aiNeedsRelay`/`needsRelay`; keep consent gate. `<AiConsent model={model} …>`. Update its test accordingly.
- [ ] **Step 4: Run** `cd "D:/Project/PacketPilot/ui" && npx vitest run src/cockpit/AiSummaryCard.test.tsx src/cockpit/AiChatPanel.test.tsx src/cockpit/AiConsent.test.tsx && npx tsc -b` → green.
- [ ] **Step 5: Commit** `feat(ai): AI card/chat/consent use admin model + server proxy (no local config)`.

---

### Task 5: App gating + remove the AI settings section

**Files:** Modify `ui/src/App.tsx`, `ui/src/components/Dashboard.tsx` (pass model), `ui/src/cockpit/SettingsDialog.tsx` (+ test).

- [ ] **Step 1: `App.tsx`** — `const appSettings = useAppSettings();` already gives `announcement_banner` + now `ai`. Compute AI availability:
```tsx
  const aiOn = session.status === "authed" && appSettings.ai.enabled && aiGate === "on"; // aiGate from Phase 8
  const aiModel = appSettings.ai.model;
```
  - Chat button (the `onOpenAiChat` line): gate on `aiOn` instead of `aiGate === "on"`.
  - `<Dashboard … aiGate={aiOn ? "on" : aiGate} aiModel={aiModel} />` (so the upsell still shows when `aiGate==='upsell'` and AI isn't otherwise on; off when not enabled/authed).
  - `<AiChatPanel … model={aiModel} />`.
- [ ] **Step 2: `Dashboard.tsx`** — add `aiModel?: string` prop (default `""`); pass `model={aiModel}` to `<AiSummaryCard>`. (Existing `aiGate` 3-way render stays; the card renders when `aiGate==='on'`.)
- [ ] **Step 3: `SettingsDialog.tsx`** — delete the entire **AI** `<section>` (enable/preset/baseUrl/model/key/proxy) + its state, handlers, imports from `lib/ai/settings`. Keep the **Reputation** section unchanged. Update `SettingsDialog.test.tsx`: remove AI-section assertions; assert the AI fields are gone + the reputation section remains.
- [ ] **Step 4: Full gate.** `cd "D:/Project/PacketPilot/ui" && npx tsc -b && npm run test:coverage && npm run build` → tsc 0; all tests pass, exit 0, coverage ≥ 80/70; build ✓. Fix any dangling AI-settings imports (e.g. App.test, Dashboard.aiGate.test) so the suite is green.
- [ ] **Step 5: Commit** `feat(ai): gate AI on admin config + login; remove AI settings from /app`.

---

### Task 6: Admin `ai_config` editor + Environment key

**Files:** Modify `ui/src/admin/settings/settingMeta.ts`, `ui/src/admin/settings/SettingsView.tsx` (+ test), `ui/src/admin/environment/EnvironmentView.tsx` (+ test).

- [ ] **Step 1: `settingMeta.ts`** — `settingKind`: return `"ai"` for `key === "ai_config"`, else the existing logic.
- [ ] **Step 2: `SettingsView.tsx`** — add an `AiConfigEditor` (mirrors `BannerEditor`): an `enabled` checkbox, a `provider` `<select>` (anthropic/openai/openrouter/ollama), a `model` text input → `updateValue("ai_config", { enabled, provider, model })`; a muted note "API key is set as a server secret (Environment)." Route `settingKind(s.key)==="ai"` → `<AiConfigEditor>`. Add a SettingsView test case for the AI editor (changing the model calls `updateValue("ai_config", …)`).
- [ ] **Step 3: `EnvironmentView.tsx`** — add to `SERVER_SECRETS`: `{ name: "AI_API_KEY", location: "Supabase → Edge Function secrets", usedBy: "ai-proxy" }`. Update the EnvironmentView test to expect `AI_API_KEY` in the server-secrets table.
- [ ] **Step 4: Full gate** (tsc + test:coverage + build) → green.
- [ ] **Step 5: Commit** `feat(admin): ai_config editor + AI_API_KEY in Environment`.

---

## After all tasks

- **Final whole-branch review** (opus): the SECRET-SAFETY invariant (no LLM key/base-URL in the browser; `ai-proxy` adds it server-side; Environment names-only); AI gated on authed + ai_config.enabled + the ai_assist flag; the proxy streams + auth (401/503); offline/core unaffected (app fully renders unconfigured, AI simply absent); consent copy reflects the server path; no dead/leaky transport code remains; test hygiene.
- **Deploy/browser smoke (with the operator):** operator sets the `AI_API_KEY` Edge secret (Supabase dashboard) + enables `ai_config` in /admin → Settings (provider/model); an authed user generates an AI summary streamed via the proxy; `/app` Settings has no AI section; Environment lists `AI_API_KEY`. (Same hand-off as Stripe Phase 2.)
- **finishing-a-development-branch**: verify suite → merge options.

## Self-review notes

- **Spec coverage:** migration + proxy fn (Task 1); app reads ai_config (Task 2); proxyClient + run rewire (Task 3); components + consent (Task 4); gating + settings removal (Task 5); admin editor + env (Task 6). All spec sections covered.
- **Type consistency:** `AiAppConfig`/`PublicSettings.ai`/`SETTINGS_DEFAULTS.ai` (Task 2) consumed in App/Dashboard/components (Tasks 4-5); `runViaProxy(messages,onToken)` (Task 3) consumed by `generateSummary`/`askChat`; `AiMessage` retained for the chat panel + run; `AiConsent({model})` + `AiSummaryCard({model})` + `AiChatPanel({model})` consistent.
- **Dead-code:** Task 3 removes `transport.ts` + `chatCompletion`; Task 4-5 remove `loopback`/`aiNeedsRelay`/local-config usages — the implementer must resolve every import so `tsc -b` passes.
- **Operator dependency:** the end-to-end stream needs `AI_API_KEY` + `ai_config.enabled`, verified at the deploy hand-off (like Stripe); the code tasks gate cleanly without it (401/503 → AI absent).
