# PacketPilot — Hosted Reputation Proxy (Slice 2 of "Admin-managed AI & APIs") — Design Spec

**Status:** approved design (mirrors the approved Slice-1 model), pre-plan
**Date:** 2026-06-28
**Branch:** `feat/hosted-reputation-proxy`
**Context:** Slice 2 of 2. Slice 1 (AI) is merged. Same locked decisions: **server proxy + operator keys, full removal, requires login**; the privacy tradeoff (public IPs/domains transit our backend to the provider) was accepted.

## Context

Reputation today is **BYO-key, client-side** (`SettingsDialog.tsx` Reputation section; keys in `localStorage` `pp.rep.key.{provider}` / OS keychain; a user relay `pp.rep.proxyUrl`). The orchestrator (`lib/reputation/orchestrator.ts`) queries AbuseIPDB / GreyNoise / VirusTotal per public IP (+ VT per public domain) through `proxyHttp(proxyUrl): HttpGet` which relays `{url, headers}` → `{status, body}`. The adapters (`abuseipdb.ts`/`virustotal.ts`/`greynoise.ts`) build the provider URL + put the key in a header + parse the JSON.

Slice 2 makes reputation **admin-managed + operator-funded**, mirroring Slice 1's AI proxy.

## Goal

Route reputation lookups through an authed `reputation-proxy` Edge Function that injects the operator's provider keys (server secrets) for an **allowlisted provider host only**; the admin manages `rep_config` (enabled / domain_enabled / providers) in `/admin → Settings`; the reputation section is removed from `/app` (and the now-empty Settings dialog removed); the three keys are surfaced read-only in Environment.

## Invariants preserved

- **No provider key in the browser:** keys are Edge secrets; the proxy injects them server-side **only for an allowlisted provider host** (SSRF/key-exfil guard — the client supplies an `{url, headers}`, and the function rejects any host not in the fixed provider allowlist).
- **Core/offline unaffected:** capture analysis is client-side; reputation is an enhancement, offered only when `supabaseConfigured && authed && rep_config.enabled` (+ `domain_enabled` for domains). The orchestrator's caching (IndexedDB) + budget stay client-side.
- **Consent kept**, copy updated to the server path. **No new SPA deps.** Migration is `0015`.

## Architecture

```
supabase/migrations/0015_rep_config.sql      # seed rep_config + whitelist it in get_public_settings
supabase/functions/reputation-proxy/index.ts # authed; host-allowlist + inject operator key; relay GET → {status, body}
ui/src/lib/reputation/
  edgeHttp.ts       # edgeRepHttp(): HttpGet that POSTs {url,headers} to reputation-proxy with the user JWT
  settings.ts       # drop browser keys/proxy; keep only the enabled/consent reads the app still needs (or move config to useAppSettings)
  abuseipdb.ts / virustotal.ts / greynoise.ts   # drop the `key` param (the proxy injects it server-side)
  orchestrator.ts   # provider selection from rep_config.providers (not browserKeys)
ui/src/lib/settings/publicSettings.ts + useAppSettings.ts   # parse `rep_config` → rep { enabled, domain_enabled, providers }
ui/src/App.tsx       # runReputation/runDomainReputation use rep_config + edgeRepHttp; drop the Tauri rep path; gate on authed+enabled
ui/src/cockpit/ReputationConsent.tsx + DomainConsent.tsx   # copy → server path
ui/src/cockpit/SettingsDialog.tsx   # reputation section removed → dialog now empty → DELETE it + its open button/state
ui/src/admin/settings/settingMeta.ts + SettingsView.tsx   # typed editor for rep_config
ui/src/admin/environment/EnvironmentView.tsx              # add ABUSEIPDB_KEY/GREYNOISE_KEY/VIRUSTOTAL_KEY
```

## Backend — `0015` + `reputation-proxy`

**Migration `0015_rep_config.sql`:** seed `('rep_config', '{"enabled":false,"domain_enabled":false,"providers":[]}'::jsonb, 'Threat-intel reputation config (enabled providers). API keys are server secrets.')` `ON CONFLICT DO NOTHING`; recreate `get_public_settings()` adding `'rep_config'` to the whitelist.

**`reputation-proxy/index.ts`** (authed Deno; mirrors `ai-proxy`):
- CORS; POST; `getUser` → 401.
- Read `rep_config` (service-role); `!enabled` → 503.
- Body `{ url: string, headers?: Record<string,string> }`. **SSRF guard:** `const host = new URL(url).host;` look it up in a **fixed allowlist** map; reject (400) if not present:
  ```ts
  const PROVIDER: Record<string, { env: string; header: string }> = {
    "api.abuseipdb.com": { env: "ABUSEIPDB_KEY", header: "Key" },
    "www.virustotal.com": { env: "VIRUSTOTAL_KEY", header: "x-apikey" },
    "api.greynoise.io": { env: "GREYNOISE_KEY", header: "key" },
  };
  ```
  Require `url` to be `https:`. Inject the operator key: `headers[provider.header] = Deno.env.get(provider.env)`; if that env key is missing → return `{status: 0, body: ""}` (the adapter maps that to an `unavailable` verdict). Forward a **GET** to `url` with the (client `Accept` etc. + injected key) headers; return `{ status, body }` JSON.
- Secrets (operator-set): `ABUSEIPDB_KEY`, `GREYNOISE_KEY`, `VIRUSTOTAL_KEY`.

## App — edge http + adapters + orchestrator + run rewire

- **`edgeHttp.ts`** `edgeRepHttp(): HttpGet` — `(url, headers) =>` POST `${SUPABASE_URL}/functions/v1/reputation-proxy` with the user JWT + `{ url, headers }`; parse `{status, body}` (mirrors `proxyHttp`'s return shape exactly, so the orchestrator/adapters are unchanged except the key).
- **Adapters** (`abuseipdb`/`virustotal`/`greynoise`): drop the `key` parameter — they build the URL + non-key headers (`Accept`, etc.) and call `http(url, headers)`; the proxy injects the key. (Parsing unchanged.)
- **`orchestrator.ts`**: `lookupReputation(http, ips, providers, now)` and `lookupDomainReputation(http, hosts, now)` — take the enabled `providers: string[]` (from `rep_config`) instead of `RepKeys`; build the provider list from `providers` (no key check). VT-domain runs when `"virustotal"` ∈ providers (+ `domain_enabled`).
- **`App.tsx`**: `runReputation` — gate on `repCfg.enabled` + `authed`; `verdicts = await lookupReputation(edgeRepHttp(), ips, repCfg.providers, now)` (drop `proxyHttp`/`browserKeys`/the Tauri `reputation_lookup` branch). `runDomainReputation` — gate on `repCfg.domain_enabled`; `lookupDomainReputation(edgeRepHttp(), hosts, now)`. The consent dialog names `repCfg.providers`.
- **`settings.ts` (reputation)**: remove `getKey/setKey/browserKeys/getProxyUrl/setProxyUrl/getProxyUrl`; the app reads enabled/providers from `useAppSettings().rep`. Keep `consentGiven/giveConsent/domainConsentGiven/giveDomainConsent` (still local per-user acknowledgments). `repEnabled()`/`domainEnabled()` now derive from `rep_config` (or the component reads `useAppSettings().rep`).
- **Consent dialogs** (`ReputationConsent`, `DomainConsent`): copy → "public IPs/domains are sent **via PacketPilot's servers** to the configured providers (`<providers>`)" — drop relay/keychain wording.
- **`SettingsDialog.tsx`**: with both AI (Slice 1) and reputation (Slice 2) sections gone, the dialog is empty → **delete it** and the gear button / `settingsOpen` state / `onOpenSettings` wiring that opens it.

## App config read — `publicSettings.rep`

Extend `PublicSettings` with `rep: { enabled: boolean; domain_enabled: boolean; providers: string[] }`; `SETTINGS_DEFAULTS.rep = { enabled:false, domain_enabled:false, providers:[] }`; `parsePublicSettings` parses `rep_config` defensively (providers filtered to the known three). Offline → defaults (reputation off).

## Admin + Environment

- **`settingMeta.ts`**: `rep_config` → `kind: "rep"`. **`SettingsView.tsx`**: a `RepConfigEditor` (mirrors the AI editor): `enabled` + `domain_enabled` checkboxes + a providers multi-checkbox (abuseipdb/greynoise/virustotal) → `updateValue("rep_config", {…})`; note "keys are server secrets (Environment)."
- **`EnvironmentView.tsx`**: add `ABUSEIPDB_KEY`, `GREYNOISE_KEY`, `VIRUSTOTAL_KEY` (location "Supabase → Edge Function secrets", usedBy "reputation-proxy") to `SERVER_SECRETS`.

## Testing

- **`reputation-proxy`** — live at deploy: an allowlisted-host GET with the env key set returns `{status,body}`; a non-allowlisted host → 400 (SSRF guard); unauth → 401; disabled → 503. (Verified with the operator's keys, like Stripe/AI.)
- **`edgeHttp`** (mock fetch + supabase session): posts `{url,headers}` with the bearer; returns `{status,body}`; no session → an `unavailable`-mapping result.
- **adapters**: build the right URL + parse `{status,body}` into verdicts (key param gone) — keep the existing parse tests, drop key assertions.
- **orchestrator**: provider selection from `providers`; cache-first; budget; domain path. (Existing tests adapted.)
- **publicSettings/useAppSettings**: parse `rep_config` → `rep`; defaults; offline → defaults.
- **App run paths**: gated on authed + rep_config.enabled/domain_enabled; call `lookupReputation`/`lookupDomainReputation` via `edgeRepHttp`; not authed/disabled → no call.
- **consent dialogs**: server-path copy; still gate egress.
- **SettingsDialog removed**: the dialog + its tests deleted; the open-settings affordance gone; AppShell/command-palette references cleaned. **admin RepConfigEditor**; **EnvironmentView** lists the 3 keys.
- Gate: full suite green, coverage ≥ 80/70, `tsc -b` + build clean, exits 0. Resolve all dangling imports from the removed settings/keys/Tauri code.
- **Browser smoke (with the operator):** operator sets the 3 keys + enables `rep_config` (+ providers) in /admin; an authed user's capture enriches with reputation via the proxy; `/app` has no Settings dialog; Environment lists the keys.

## Out of scope

Desktop (Tauri) native reputation (removed, like AI); server-side reputation caching/quota (kept client-side for now); new providers; the deferred AI message-validation chip (separate).

## File manifest

**Create:** `supabase/migrations/0015_rep_config.sql`, `supabase/functions/reputation-proxy/index.ts`, `ui/src/lib/reputation/edgeHttp.ts` (+ test).
**Modify:** `ui/src/lib/reputation/{settings,orchestrator,abuseipdb,virustotal,greynoise}.ts` (+ tests), `ui/src/lib/settings/publicSettings.ts` + `useAppSettings.ts` (+ tests), `ui/src/App.tsx` (run paths + remove Settings dialog wiring), `ui/src/cockpit/ReputationConsent.tsx` + `DomainConsent.tsx`, **delete** `ui/src/cockpit/SettingsDialog.tsx` (+ its tests + the gear button), `ui/src/admin/settings/settingMeta.ts` + `SettingsView.tsx` (+ test), `ui/src/admin/environment/EnvironmentView.tsx` (+ test), `ui/src/lib/supabase/types.ts` (if RPC regen).
**Operator (deploy-time):** set `ABUSEIPDB_KEY`/`GREYNOISE_KEY`/`VIRUSTOTAL_KEY` Edge secrets; I deploy `reputation-proxy`.
**No engine/WASM change. No new SPA deps.**
