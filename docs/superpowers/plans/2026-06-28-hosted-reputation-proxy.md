# Hosted Reputation Proxy (Slice 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Route reputation lookups (AbuseIPDB/GreyNoise/VirusTotal) through an authed `reputation-proxy` Edge Function that injects the operator's keys for an allowlisted provider host only; admin manages `rep_config`; remove reputation (and the now-empty Settings dialog) from `/app`; list the 3 keys read-only in Environment.

**Architecture:** Mirrors the merged Slice-1 AI proxy. The orchestrator/adapters/caching stay client-side; only the key-injection + egress move into the Edge Function, which validates the URL host against a fixed provider allowlist (SSRF/key-exfil guard). The Phase-9 `app_settings`/`get_public_settings` carry the non-secret `rep_config`.

**Tech Stack:** Deno Edge Function, React 18 + TS, Vitest. Supabase MCP for migration + deploy.

## Global Constraints

- **No provider key in the browser.** Keys are Edge secrets; the proxy injects them ONLY for an allowlisted host (`api.abuseipdb.com`/`www.virustotal.com`/`api.greynoise.io`); any other host → 400 (SSRF guard). Client sends `{url, headers}` (public IPs/domains only).
- **Reputation requires login + `rep_config.enabled`** (domains also need `domain_enabled`); otherwise not performed. Core/offline analysis unaffected.
- **Consent kept**, copy → server path. **No new SPA deps.** Migration is `0015`.
- **Per-task gate:** `npx tsc -b`; final task `npm run test:coverage` (≥80/70) + `npm run build`. UI cmds from `D:\Project\PacketPilot\ui`.

---

### Task 1: Migration `0015` + `reputation-proxy` Edge Function (controller-run via MCP)

**Files:** Create `supabase/migrations/0015_rep_config.sql`, `supabase/functions/reputation-proxy/index.ts`; Modify `ui/src/lib/supabase/types.ts` (regen if needed).

- [ ] **Step 1: `0015_rep_config.sql`**
```sql
insert into public.app_settings (key, value, description) values
  ('rep_config', '{"enabled":false,"domain_enabled":false,"providers":[]}'::jsonb,
   'Threat-intel reputation config (enabled providers). API keys are server secrets (see Environment).')
on conflict (key) do nothing;

create or replace function public.get_public_settings()
returns jsonb language sql stable security definer set search_path = '' as $$
  select coalesce(jsonb_object_agg(key, value), '{}'::jsonb)
  from public.app_settings
  where key in ('announcement_banner', 'support_contact_email', 'pro_plan_price_display', 'ai_config', 'rep_config');
$$;
grant execute on function public.get_public_settings() to anon, authenticated;
```

- [ ] **Step 2: Apply (MCP `apply_migration`, name `rep_config`).** `select public.get_public_settings();` includes `rep_config`. Advisors unchanged.

- [ ] **Step 3: `supabase/functions/reputation-proxy/index.ts`** (authed Deno; mirrors ai-proxy):
```ts
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
```

- [ ] **Step 4: Deploy (MCP `deploy_edge_function`, name `reputation-proxy`, `verify_jwt: true`).** Expected: ACTIVE.

- [ ] **Step 5: Verify the SSRF guard + auth (controller):** an unauth POST → 401 (gateway); (with the operator's keys, the allowlisted path is verified at deploy). Regenerate types only if the RPC shape changed (it didn't).

- [ ] **Step 6: Commit** `feat(rep): reputation-proxy Edge Function + rep_config public read (0015)`.

---

### Task 2: App `rep_config` read (`publicSettings.rep` + `useAppSettings`)

**Files:** Modify `ui/src/lib/settings/publicSettings.ts` (+ test).

- [ ] Add `interface RepAppConfig { enabled: boolean; domain_enabled: boolean; providers: string[] }`; `PublicSettings` gains `rep: RepAppConfig`; `SETTINGS_DEFAULTS.rep = { enabled:false, domain_enabled:false, providers:[] }`. In `parsePublicSettings`, parse `obj.rep_config` defensively: `enabled === true`, `domain_enabled === true`, `providers` = the array filtered to `["abuseipdb","greynoise","virustotal"]`. Add test cases (valid → parsed; junk/missing → defaults; providers filtered). `useAppSettings` needs no change. Run `npx vitest run src/lib/settings && npx tsc -b` → green.
- [ ] **Commit** `feat(rep): read admin rep_config in useAppSettings`.

---

### Task 3: edge http + adapters + orchestrator

**Files:** Create `ui/src/lib/reputation/edgeHttp.ts` (+ test); Modify `abuseipdb.ts`/`virustotal.ts`/`greynoise.ts` (drop `key` param), `orchestrator.ts` (provider list), `settings.ts` (drop keys/proxy), and their tests; the `http.ts` `proxyHttp` is now unused (delete it; keep `HttpGet`/`HttpResult`/`unavailable`).

- [ ] **Step 1: `edgeHttp.ts`** (mirrors `proxyClient`): 
```ts
import { supabase } from "../supabase";
import type { HttpGet } from "./http";

const FN_URL = `${import.meta.env.VITE_SUPABASE_URL ?? ""}/functions/v1/reputation-proxy`;

/** HttpGet that relays {url,headers} through the authed reputation-proxy (the key is injected server-side). */
export function edgeRepHttp(): HttpGet {
  return async (url, headers) => {
    if (!supabase) return { status: 0, body: "" };
    const { data } = await supabase.auth.getSession();
    const token = data.session?.access_token;
    if (!token) return { status: 0, body: "" };
    try {
      const resp = await fetch(FN_URL, {
        method: "POST",
        headers: { "content-type": "application/json", apikey: import.meta.env.VITE_SUPABASE_ANON_KEY ?? "", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ url, headers }),
      });
      if (!resp.ok) return { status: resp.status, body: "" };
      const d = await resp.json();
      return { status: Number(d.status) || 0, body: typeof d.body === "string" ? d.body : "" };
    } catch {
      return { status: 0, body: "" };
    }
  };
}
```
Test (mock supabase + fetch): posts `{url,headers}` with the bearer; maps `{status,body}`; no session → `{status:0,body:""}`.
- [ ] **Step 2: Adapters** — drop the `key` parameter from `abuseipdbVerdict(http, ip, now)`, `greynoiseVerdict(http, ip, now)`, `virustotalVerdictIp(http, ip, now)`, `virustotalVerdictDomain(http, domain, now)`. Build the URL + non-key headers (e.g. `{ Accept: "application/json" }` for abuseipdb; `{}` for VT/GreyNoise — the proxy injects the key header). The `parse()` logic is unchanged. Update their tests (the existing `http` mock no longer receives a key; assertions drop the key).
- [ ] **Step 3: `orchestrator.ts`** — change `lookupReputation(http, ips, providers: string[], now)` and `lookupDomainReputation(http, hosts, now)`: build the provider list from `providers` (intersect with `["abuseipdb","greynoise","virustotal"]`), no key check; call the new keyless adapter fns. VT-domain runs when the caller invokes it (gated by `domain_enabled` + `"virustotal"` ∈ providers in App). Keep caching (`getReputation`/`putReputation`) + budget. Drop the `RepKeys` interface. Update `orchestrator.test.ts` to pass `providers` instead of `keys`.
- [ ] **Step 4: `settings.ts` (reputation)** — remove `getKey`/`setKey`/`browserKeys`/`getProxyUrl`/`setProxyUrl` and the `PROVIDERS`/`Provider` exports if now unused (grep). KEEP `consentGiven`/`giveConsent`/`domainConsentGiven`/`giveDomainConsent`. Remove `repEnabled`/`setRepEnabled`/`domainEnabled`/`setDomainEnabled` IF nothing else uses them (App will read enabled from `useAppSettings().rep`); else keep minimal. Delete `proxyHttp` from `http.ts`. Update `settings.test.ts`.
- [ ] **Step 5:** `npx tsc -b` — resolve every dangling import (App.tsx still uses old orchestrator/proxyHttp/browserKeys — that's Task 4; if removing them breaks App, leave App's calls referencing valid symbols and report, OR keep the removed-symbol shims minimal until Task 4). Aim to commit a state where `npx vitest run src/lib/reputation` passes; note any tsc errors deferred to Task 4. Run `npx vitest run src/lib/reputation src/lib/settings`.
- [ ] **Step 6: Commit** `feat(rep): route reputation through the reputation-proxy (keyless adapters)`.

---

### Task 4: App run rewire + consent copy + remove the Settings dialog

**Files:** Modify `ui/src/App.tsx`, `ui/src/cockpit/ReputationConsent.tsx`, `ui/src/cockpit/DomainConsent.tsx`, `ui/src/components/layout/AppShell.tsx`, `ui/src/cockpit/CommandBar.tsx`; DELETE `ui/src/cockpit/SettingsDialog.tsx` + `SettingsDialog.test.tsx` + `SettingsDialog.tauri.test.tsx`; Modify `ui/src/test/a11y.test.tsx`.

- [ ] **Step 1: `App.tsx` run paths** — read `const rep = appSettings.rep;` (from `useAppSettings()`):
  - `runReputation`: gate `if (session.status !== "authed" || !rep.enabled) return;`; build public IPs as today; `verdicts = await lookupReputation(edgeRepHttp(), ips, rep.providers, now)` (drop the `IS_TAURI` branch + `proxyHttp`/`browserKeys`/`getProxyUrl`).
  - `triggerReputationGate`: gate on `rep.enabled`; the consent dialog providers = `rep.providers`.
  - `runDomainReputation`: gate `if (!rep.domain_enabled || !rep.providers.includes("virustotal")) return;`; `lookupDomainReputation(edgeRepHttp(), hosts, now)` (drop Tauri + key).
  - Remove the now-unused imports (`proxyHttp`, `browserKeys`, `getProxyUrl`, `getKey`, `repEnabled`, `domainEnabled`, IS_TAURI rep usage). Keep `consentGiven`/`giveConsent`/etc.
- [ ] **Step 2: Consent dialogs** — `ReputationConsent`: copy → "{ipCount} public IP{s} will be sent **via PacketPilot's servers** to {providers.join(', ')}. Internal IPs, payloads, and the capture itself never leave this device." `DomainConsent`: analogous server-path copy. Update their tests if any.
- [ ] **Step 3: Remove the Settings dialog** (both AI + reputation sections are now gone, so the dialog is empty):
  - DELETE `ui/src/cockpit/SettingsDialog.tsx`, `SettingsDialog.test.tsx`, `SettingsDialog.tauri.test.tsx`.
  - `App.tsx`: remove the `SettingsDialog` import (line 70), `settingsOpen` state (172), the `onOpenSettings={…}` prop (691), and the `{settingsOpen && <SettingsDialog/>}` render (779-781).
  - `AppShell.tsx`: remove the `onOpenSettings` prop (71, 125, 303).
  - `CommandBar.tsx`: remove the settings gear button (207-211) + the `onOpenSettings` prop (44, 68).
  - `a11y.test.tsx`: remove the `SettingsDialog` import + its a11y test (11, 76-77).
- [ ] **Step 4:** `npx tsc -b` → resolve every dangling import. Run `cd "D:/Project/PacketPilot/ui" && npx vitest run src/App.test.tsx src/cockpit src/components/layout` → green (update any App.test/AppShell test that referenced the settings button).
- [ ] **Step 5: Commit** `feat(rep): gate reputation on admin config + login; remove the /app Settings dialog`.

---

### Task 5: Admin `rep_config` editor + Environment keys + full gate

**Files:** Modify `ui/src/admin/settings/settingMeta.ts`, `ui/src/admin/settings/SettingsView.tsx` (+ test), `ui/src/admin/environment/EnvironmentView.tsx` (+ test).

- [ ] **Step 1: `settingMeta.ts`** — `settingKind` returns `"rep"` for `rep_config`, else existing.
- [ ] **Step 2: `SettingsView.tsx`** — a `RepConfigEditor` (mirrors `AiConfigEditor`): `enabled` + `domain_enabled` checkboxes + a providers row of 3 checkboxes (abuseipdb/greynoise/virustotal) → `updateValue("rep_config", { enabled, domain_enabled, providers })`; note "API keys are server secrets (Environment)." Route `settingKind(s.key)==="rep"` → `<RepConfigEditor>`. Add a SettingsView test (toggling a provider calls `updateValue("rep_config", …)`).
- [ ] **Step 3: `EnvironmentView.tsx`** — add to `SERVER_SECRETS`: `ABUSEIPDB_KEY`, `GREYNOISE_KEY`, `VIRUSTOTAL_KEY` (location "Supabase → Edge Function secrets", usedBy "reputation-proxy"). Update its test.
- [ ] **Step 4: Full gate.** `cd "D:/Project/PacketPilot/ui" && npx tsc -b && npm run test:coverage && npm run build` → tsc 0; all pass, exit 0, coverage ≥ 80/70; build ✓. Fix any dangling refs.
- [ ] **Step 5: Commit** `feat(admin): rep_config editor + reputation keys in Environment`.

---

## After all tasks

- **Final whole-branch review** (opus): SECRET-SAFETY (no provider key in the browser; the proxy's SSRF host-allowlist + key injection; client cannot exfiltrate a key to an arbitrary host; Environment names-only); reputation gated on authed + rep_config.enabled; offline/core unaffected; consent copy reflects the server path; no dead/leaky relay code; test hygiene.
- **Deploy/browser smoke (operator):** set `ABUSEIPDB_KEY`/`GREYNOISE_KEY`/`VIRUSTOTAL_KEY` Edge secrets + enable `rep_config` (+ providers) in /admin; an authed capture enriches via the proxy; `/app` has no Settings dialog; Environment lists the 3 keys.
- **finishing-a-development-branch**: verify suite → merge options.

## Self-review notes

- **Spec coverage:** migration + proxy (Task 1); app reads rep_config (Task 2); edgeHttp + keyless adapters + orchestrator (Task 3); App rewire + consent + Settings-dialog removal (Task 4); admin editor + env (Task 5). All covered.
- **Type consistency:** `RepAppConfig`/`PublicSettings.rep`/`SETTINGS_DEFAULTS.rep` (Task 2) consumed in App (Task 4); `edgeRepHttp(): HttpGet` (Task 3) consumed by App; the keyless adapter signatures (Task 3) consumed by the orchestrator; `lookupReputation(http, ips, providers, now)` consistent across Tasks 3-4.
- **SSRF guard is the load-bearing security control** — the proxy injects a key ONLY for the 3 allowlisted hosts; the final review must confirm a non-allowlisted host gets 400 with no key forwarded.
