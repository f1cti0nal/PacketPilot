# PacketPilot — Hosted AI Proxy (Slice 1 of "Admin-managed AI & APIs") — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-28
**Branch:** `feat/hosted-ai-proxy`
**Context:** Slice 1 of 2 (AI first; reputation is Slice 2). Follows the completed 0–9 SaaS roadmap.

## Context

Today the AI Analyst is **BYO-key, client-side**: the user enters an LLM base URL / model / API key + a relay URL in the `/app` Settings dialog (`SettingsDialog.tsx`), stored in `localStorage` (`pp.ai.*`) / OS keychain; calls go *browser → the user's relay → the provider* (`lib/ai/run.ts` `pickTransport` → `proxyTransport`/`directTransport`/`tauriTransport`). Keys + data never touch our backend.

The user wants AI to be **admin-managed and operator-funded**: the admin manages the non-secret config; the operator's LLM key is a server secret; AI calls route through a **server-side proxy**; and **all AI settings are removed from `/app`**.

Decisions locked with the user:
- **Server proxy, operator key, full removal.** A new authed Edge Function holds the key; end users configure nothing.
- **Requires a logged-in user** (anon visitors can't spend the operator's key).
- **Privacy tradeoff accepted:** the AI's *derived summary* + chat messages now transit our backend to the provider. (Raw capture analysis stays 100% client-side; only the already-derived AI context leaves, as it did before — now via our server instead of the user's relay.)
- **AI becomes backend-dependent:** offline/local and desktop (no backend) no longer get cloud AI through this path. AI stays an enhancement; the Phase-8 `ai_assist` flag still gates its visibility (and can plan-gate it).

## Goal

Route AI summary + chat through a `ai-proxy` Edge Function that authenticates the caller and uses the operator's LLM key (a server secret) + admin-managed provider/model; remove the AI section from the `/app` Settings dialog; let the admin manage AI config in `/admin → Settings`; surface the AI key in the Environment checklist. No LLM key or base URL ever in the browser.

## Invariants preserved

- **No secret in/through the browser:** the LLM key is an Edge Function secret (operator-set, never in the bundle/`app_settings`/admin UI); the proxy adds `Authorization` server-side. The Environment view lists `AI_API_KEY` names-only.
- **Core analysis untouched + offline-safe:** capture parsing/findings/flows are unchanged and fully client-side. When the backend is absent/AI disabled, the app simply doesn't offer AI (additive; no break).
- **Consent preserved + updated:** the existing AI consent gate stays; its copy now states the derived summary is sent *via PacketPilot's servers* to `<provider/model>`.
- **No new SPA deps.**

## Architecture

```
supabase/migrations/0014_ai_config.sql      # seed ai_config row + whitelist it in get_public_settings
supabase/functions/ai-proxy/index.ts        # authed; operator key + admin model; streams the LLM response
ui/src/lib/ai/
  proxyClient.ts    # runViaProxy(messages, onToken): fetch ai-proxy with the user JWT, stream SSE back
  settings.ts       # drop the AI run path's local key/baseUrl/proxy reads; keep only the consent flag
  run.ts            # generateSummary/askChat → runViaProxy (server decides model/key); no client transports
ui/src/lib/settings/publicSettings.ts + useAppSettings.ts   # also parse `ai` config (enabled, model, provider)
ui/src/cockpit/
  SettingsDialog.tsx  # REMOVE the entire AI section (reputation section stays for Slice 2)
  AiConsent.tsx       # copy update (server path); AiSummaryCard/AiChatPanel gate on the new availability
ui/src/admin/settings/settingMeta.ts + SettingsView.tsx   # typed editor for `ai_config`
ui/src/admin/environment/EnvironmentView.tsx              # add AI_API_KEY to the server-secret checklist
```

## Backend — `0014` + `ai-proxy`

**Migration `0014_ai_config.sql`:**
- Seed `app_settings`: `('ai_config', '{"enabled":false,"provider":"anthropic","model":"claude-opus-4-8"}'::jsonb, 'AI Analyst configuration (provider/model; the API key is a server secret)')` `ON CONFLICT DO NOTHING`. (Disabled by default until the operator sets the key.)
- Recreate `get_public_settings()` adding `'ai_config'` to the whitelist `IN (…)` so the app reads enabled/provider/model (all non-secret). (Same SECURITY DEFINER + grant; the audit/stamp triggers from 0013 already cover writes.)

**Edge Function `ai-proxy/index.ts`** (self-contained Deno, mirrors the Stripe-function pattern):
- CORS preflight; POST only.
- **Auth:** read the `Authorization` bearer; `createClient(URL, ANON_KEY, { global headers }).auth.getUser()` → 401 if no user.
- Read `ai_config` via a **service-role** client (`provider`, `model`, `enabled`); map provider→base URL (anthropic/openai/openrouter/ollama, or `AI_BASE_URL` override). If `!enabled` or no `AI_API_KEY` → 503 `{ error: "AI is not configured" }`.
- Body: `{ messages: {role,content}[] }` (the system+context the client built). Guard size/shape.
- Build the OpenAI-compatible request `{ model, messages, stream: true }`, POST to `${baseUrl}/chat/completions` with `Authorization: Bearer ${AI_API_KEY}`, and **stream the upstream body straight back** (`return new Response(upstream.body, { headers: text/event-stream })`). Non-2xx upstream → a clean error status.
- Secrets (operator-set, Supabase dashboard): `AI_API_KEY` (required), `AI_BASE_URL` (optional override). `verify_jwt`: the function does its own `getUser`, so deploy with `verify_jwt=false` and gate inside (consistent control), OR `verify_jwt=true` — pick the form that streams cleanly; document it.

## App — proxy client + run rewire + settings removal

- **`proxyClient.ts`** `runViaProxy(messages, onToken): Promise<string>` — `fetch(${SUPABASE_URL}/functions/v1/ai-proxy, { method:POST, headers:{ Authorization: Bearer <session access_token>, apikey: <anon>, content-type }, body: JSON.stringify({ messages }) })`; on non-OK throw a friendly error; stream the body through the existing `SseAccumulator` → `onToken`. Returns the full text.
- **`run.ts`**: `generateSummary`/`askChat` build the same messages, then call `runViaProxy(messages, onToken)` (the server owns model/key/baseUrl). Delete `pickTransport`/`proxyTransport`/`directTransport`/`tauriTransport` from the browser AI path (and their `settings` reads). (Keep `buildContext`, prompts, `SseAccumulator`, `client.ts` SSE parsing reused by the proxy client.)
- **`settings.ts`**: remove `getAiBaseUrl/setAiBaseUrl/getAiModel/setAiModel/getAiKey/setAiKey/getProxyUrl/setProxyUrl/getAiConfig` usage from the run path; keep `aiConsentGiven/giveAiConsent`. The app's AI *availability* (enabled + model for display) comes from `useAppSettings().ai`.
- **`useAppSettings`/`publicSettings`**: extend `PublicSettings` with `ai: { enabled: boolean; provider: string; model: string }` parsed from `get_public_settings().ai_config` (defaults `{enabled:false,...}`). 
- **AI availability gate** (AiSummaryCard + AiChatPanel + the `onOpenAiChat` wiring): offer AI only when `supabaseConfigured && session.status==='authed' && appSettings.ai.enabled` AND the Phase-8 `ai_assist` gate is `on`. Otherwise hide (no key entry anywhere).
- **`AiConsent.tsx`**: copy → "Your capture's *derived summary* will be sent via PacketPilot to the AI provider (`<model>`) to generate this. Raw packets are never sent." (no relay/local wording). Keep the consent flag.
- **`SettingsDialog.tsx`**: delete the AI `<section>` (enable/preset/baseUrl/model/key/proxy) and its state/handlers. The Reputation section stays untouched (Slice 2).

## Admin — `ai_config` editor

- **`settingMeta.ts`**: `ai_config` → `kind: "ai"`. 
- **`SettingsView.tsx`**: an `AiConfigEditor` (mirrors the banner editor) — `enabled` checkbox, `provider` select (anthropic/openai/openrouter/ollama), `model` text → `updateValue("ai_config", { enabled, provider, model })`. (Other keys keep banner/json editors.)
- The KEY is never here — a helper note: "The API key is a server secret (Environment)."

## Environment — AI key checklist

- Add to `SERVER_SECRETS` in `EnvironmentView.tsx`: `{ name: "AI_API_KEY", location: "Supabase → Edge Function secrets", usedBy: "ai-proxy" }` (and `AI_BASE_URL` optional). Names-only, "Server-managed", no value.

## Data flow & error handling

Authed user with AI enabled clicks Generate / sends chat → consent gate → `runViaProxy(messages)` → `ai-proxy` (authed; reads admin model + operator key) → streams the LLM SSE back → tokens render. Not logged in / AI disabled / backend absent → AI is not offered (no error surface). Upstream/key errors → a friendly inline "AI request failed" (no secret leaked). The operator sets `AI_API_KEY` + enables `ai_config` to turn it on.

## Testing

- **`ai-proxy`** — live/integration (Deno, no in-repo harness): with `AI_API_KEY` set + `ai_config.enabled`, an authed call streams a completion; unauth → 401; disabled/no key → 503. (Verified at deploy time with the operator, like Stripe.)
- **`proxyClient`** (mock fetch): posts `{ messages }` with the bearer; streams chunks to `onToken`; non-OK → throws.
- **`run.ts`**: `generateSummary`/`askChat` call `runViaProxy` with the right messages (system+context, history slice).
- **`publicSettings`/`useAppSettings`**: parse `ai_config` → `ai` (enabled/provider/model); defaults when absent; offline → defaults (disabled), no rpc.
- **AI availability**: AiSummaryCard/AiChatPanel hidden when not authed / disabled / flag off; shown + calls proxy when on. Consent copy asserts the server-path wording.
- **`SettingsDialog`**: AI section gone; reputation section still present; existing tests updated.
- **admin `AiConfigEditor`**: edits provider/model/enabled → `updateValue("ai_config", …)`.
- **EnvironmentView**: `AI_API_KEY` listed as server-managed, no value.
- Gate: full suite green, coverage ≥ 80/70, `tsc -b` + build clean, exits 0. Types regenerated for the (unchanged-shape) RPC if needed.
- **Browser smoke** (with the operator): operator sets `AI_API_KEY` + enables `ai_config`; an authed user generates an AI summary streamed via the proxy; the `/app` Settings dialog has no AI section; Environment lists the key.

## Out of scope (Slice 2 / later)

The reputation proxy (AbuseIPDB/GreyNoise/VirusTotal) — Slice 2 mirrors this design. Per-user AI usage quotas/billing; multiple operator keys; desktop (Tauri) native AI; model/usage analytics.

## File manifest

**Create:** `supabase/migrations/0014_ai_config.sql`, `supabase/functions/ai-proxy/index.ts`, `ui/src/lib/ai/proxyClient.ts` (+ test).
**Modify:** `ui/src/lib/ai/run.ts` (+ test), `ui/src/lib/ai/settings.ts`, `ui/src/lib/settings/publicSettings.ts` + `useAppSettings.ts` (+ tests), `ui/src/cockpit/SettingsDialog.tsx` (+ test), `ui/src/cockpit/AiConsent.tsx`, `ui/src/cockpit/AiSummaryCard.tsx` + `AiChatPanel.tsx` (+ tests), `ui/src/admin/settings/settingMeta.ts` + `SettingsView.tsx` (+ tests), `ui/src/admin/environment/EnvironmentView.tsx` (+ test), `ui/src/lib/supabase/types.ts` (if RPC regen needed). Delete dead AI transport code paths in `run.ts`/`transport.ts` no longer used by the browser.
**Operator (deploy-time):** set `AI_API_KEY` (+ optional `AI_BASE_URL`) Edge secrets; I deploy `ai-proxy`.
**No reputation change (Slice 2). No engine/WASM change. No new SPA deps.**
