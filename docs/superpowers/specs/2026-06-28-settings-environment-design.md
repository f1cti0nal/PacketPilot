# PacketPilot SaaS — Settings + Environment (Phase 9, FINAL) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-28
**Branch:** `feat/settings-environment`
**Sub-project:** 9 of 9 (final) — PacketPilot SaaS platform (depends on Phase 0 + Phase 3 + Phase 8 patterns)

## Context

The final phase. Phases 0–8 are merged + deployed. The `/admin` **Settings** (id `settings`) and **Environment** (id `env`) sections (both `sections.ts`, phase 9) fall through to the placeholder. This phase adds an admin `app_settings` manager, a read-only secret-safe Environment view, and closes the loop by wiring **one** app-read setting: a site-wide announcement banner.

Decisions locked with the user:
- **Scope: + announcement-banner read loop.** Admin CRUD + read-only Environment, plus the app reads an `announcement_banner` setting and shows it to all users. This requires a narrow public-read path (a whitelist RPC).
- **Value editor: hybrid** — a typed control for the known `announcement_banner` shape; a validated raw-JSON textarea for every other key.

**Grounded in code (Phase-9 understand workflow):**
- `app_settings`: `key (PK text), value (jsonb default '{}'), description, updated_at, updated_by (FK→profiles)`. A `set_updated_at` trigger (0002), but **no stamp/audit triggers yet**. Seeded: `branding` = `{"product_name":"PacketPilot"}`, `limits` = `{"max_upload_mb":64}`.
- **CRITICAL: `app_settings` RLS is admin-only and total** (`for all to authenticated using is_admin() with check is_admin()`) — **no public SELECT**. So a normal/anon client SELECT returns 0 rows. The banner read loop therefore needs a deliberate public-read path, NOT a client SELECT.
- Env: the browser only ever sees `VITE_SUPABASE_URL` + `VITE_SUPABASE_ANON_KEY` (`client.ts:4-5`). The real secrets (`STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_PRO`, `SUPABASE_SERVICE_ROLE_KEY`) are read only via `Deno.env.get` inside the Edge Functions — **unreadable from the SPA by construction**.
- Reuse the Phase-8 pattern: `useAdminFeatureFlags`/`FeatureFlagsView` + the `0012` stamp+audit triggers. Next migration is **`0013`**.

## Goal

Let an admin manage app-wide config (`app_settings`) — audited + attributed — see a read-only, **secret-safe** Environment overview, and publish a site-wide announcement banner that all users (incl. anonymous) see, while the app stays fully functional offline via safe defaults and **no real secret is ever read or written from the browser**.

## Invariants preserved

- **HARD: no secret in/through the browser.** The Environment view shows only public `VITE_*` vars (masked) + a **static names-and-locations checklist** of server secrets labeled "server-managed, not visible here" — never values, never a fetched Set/Missing. No new `VITE_*` var is added. No write path to env.
- **HARD: offline = full function.** `useAppSettings` fails open to hardcoded `SETTINGS_DEFAULTS` (banner default = none) when the backend is absent/errors; the banner is additive and never blocks the app or local analysis.
- **Narrow public read:** the banner read path is a SECURITY-DEFINER RPC returning ONLY whitelisted non-secret keys — it never exposes the admin `app_settings` table.
- **Admin writes RLS-gated + audited:** existing `app_settings` admin RLS; `updated_by` server-stamped; every change → `audit_log` (0013). `key` immutable in the UI.
- **No capture data to the backend; no new SPA deps.**

## Architecture

```
supabase/migrations/0013_app_settings.sql
  # app_settings_stamp() BEFORE + app_settings_audit() AFTER triggers (SECURITY DEFINER, revoke)
  # get_public_settings() SECURITY DEFINER RPC → whitelisted non-secret keys (anon+authed EXECUTE)
  # seed announcement_banner row (empty/off) ON CONFLICT DO NOTHING
ui/src/admin/settings/
  useAdminAppSettings.ts   # list + updateValue/updateDescription/createSetting/deleteSetting
  settingMeta.ts           # known-key registry (banner = typed; else raw JSON)
  SettingsView.tsx         # table; banner→typed editor, others→validated raw-JSON
ui/src/admin/environment/
  EnvironmentView.tsx      # read-only: public vars (masked) + server-secret checklist + settings mirror
  envMask.ts               # maskValue() helpers (pure)
ui/src/lib/settings/
  publicSettings.ts        # types + SETTINGS_DEFAULTS + parsePublicSettings()
  useAppSettings.ts        # rpc('get_public_settings'); fail-open to DEFAULTS
ui/src/cockpit/AnnouncementBanner.tsx   # renders the banner (severity color, dismiss→sessionStorage)
ui/src/App.tsx                          # useAppSettings → <AnnouncementBanner> at the app root
ui/src/admin/AdminShell.tsx             # route settings → SettingsView, env → EnvironmentView
```

## Backend — `0013`

1. **Stamp + audit triggers** (copy `0012` for `app_settings`): `app_settings_stamp()` BEFORE INSERT/UPDATE sets `new.updated_by := auth.uid()`; `app_settings_audit()` AFTER INSERT/UPDATE/DELETE writes `audit_log` (`action` `app_setting.create|update|delete`, `target = key`, `meta` = changed `value`/`description`). Both SECURITY DEFINER, `search_path=''`, EXECUTE revoked from public/anon/authenticated. (No RLS change — admin CRUD already gated.)
2. **Public-read RPC:**
```sql
create or replace function public.get_public_settings()
returns jsonb language sql stable security definer set search_path = '' as $$
  select coalesce(jsonb_object_agg(key, value), '{}'::jsonb)
  from public.app_settings
  where key in ('announcement_banner', 'support_contact_email', 'pro_plan_price_display');
$$;
grant execute on function public.get_public_settings() to anon, authenticated;
```
Returns ONLY the 3 whitelisted non-secret keys, so opening banner reads never exposes the admin table. (It intentionally is anon-executable — a benign, expected advisor WARN, same class as the existing `is_admin` one.)
3. **Seed the banner key** (so it's editable + the app has a defined value): `insert into public.app_settings (key, value, description) values ('announcement_banner', '{"text":"","severity":"info","dismissible":true}'::jsonb, 'Site-wide announcement banner') on conflict (key) do nothing;` Empty `text` ⇒ nothing shown.

Regenerate `types.ts` for the new RPC and commit.

## App read loop — `publicSettings.ts` + `useAppSettings.ts` + `AnnouncementBanner.tsx`

```ts
export interface AnnouncementBanner { text: string; severity: "info" | "warning" | "critical"; dismissible: boolean }
export interface PublicSettings { announcement_banner: AnnouncementBanner | null }
export const SETTINGS_DEFAULTS: PublicSettings = { announcement_banner: null };
export function parsePublicSettings(raw: unknown): PublicSettings; // safe: validates shape, ignores junk
```
`useAppSettings(): PublicSettings` — `SETTINGS_DEFAULTS` initially; in a `useEffect` guarded by `if (!supabaseConfigured || !supabase) return;`, call `supabase.rpc("get_public_settings")`, `parsePublicSettings(data)` on success, **fail open** to DEFAULTS on error/empty. Never blocks render; works for anon (the RPC is public).

`AnnouncementBanner({ banner })`: renders nothing when `banner` is null or `text` is empty. Otherwise a full-width strip; severity → token color (`info`→accent, `warning`→sev-medium, `critical`→sev-critical); when `dismissible`, an X that records a `sessionStorage` dismissal keyed by a hash of the text (a new announcement re-shows).

`App.tsx`: `const { announcement_banner } = useAppSettings();` render `<AnnouncementBanner banner={announcement_banner} />` at the very top of the app's returned tree (above the shell / home), so it appears on `/app` for all users incl. anonymous.

## Admin Settings — `useAdminAppSettings` + `settingMeta` + `SettingsView`

`useAdminAppSettings(): { state, reload }` (loading|error|ready{settings}) — `app_settings.select("key,value,description,updated_at").order("key")`; `AdminSetting { key; value: Json; description: string | null; updated_at: string }`. Mutators (RLS admin-gated): `updateValue(key, value: Json)`, `updateDescription(key, string)`, `createSetting(key, description)`, `deleteSetting(key)` → `{ ok, error? }`.

`settingMeta.ts`: a tiny registry — `announcement_banner` → `kind: "banner"`; every other key → `kind: "json"` (default). (Extensible later.)

`SettingsView.tsx`: a `.pp-table` — **Key** (mono, immutable), **Value** (kind-driven editor), **Description** (inline), **Updated**, Delete; + an Add-setting row. The `run()`+reload+`role="alert"` pattern from `FeatureFlagsView`.
- **banner** kind → a typed editor: text input + severity `<select>` (info/warning/critical) + dismissible checkbox → builds `{text,severity,dismissible}` and calls `updateValue` on change/blur.
- **json** kind → a `<textarea>` showing `JSON.stringify(value, null, 2)`; on blur/save, `JSON.parse` with a try/catch → on success `updateValue`, on parse error an inline "Invalid JSON" message (no write). This safely covers `branding`, `limits`, and any future/unknown key.

Wire `AdminShell`: `active === "settings"` → `<SettingsView />` (+ stub + route test).

## Environment view — `EnvironmentView` + `envMask`

Strictly read-only (no inputs/mutators/writes). Three sections:
1. **Public app config** — `VITE_SUPABASE_URL` + `VITE_SUPABASE_ANON_KEY` from `import.meta.env`: name, Configured/Missing chip (`Boolean(value)`), and a **masked** value (`maskValue`: URL → `scheme + first ~12 chars + "…"`; key → `first 6 + "…" + last 4`). Public-by-design, so a masked hint leaks nothing.
2. **Server secrets** — a **hardcoded static** array (`STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_PRO`, `SUPABASE_SERVICE_ROLE_KEY`) with `location` ("Supabase → Edge Function secrets") + dependent functions, status label **"Server-managed"** — **no value column, no fetch**. The browser cannot and must not query these.
3. **App settings (read-only mirror)** — reuse `useAdminAppSettings` to list current rows (key, compact value preview, description, updated_at) for troubleshooting; zero edit affordances. Inside the admin RLS boundary.

`envMask.ts`: pure `maskValue(kind, value)` helpers (unit-tested).

## Data flow & error handling

Admin opens Settings → admin-RLS read → table; an edit → `app_settings` write (RLS admin) → stamp + audit triggers → reload. App load → `useAppSettings` calls the public RPC → banner (or DEFAULTS offline/error). Environment view reads only `import.meta.env` (sections 1-2, no network) + the admin-gated settings mirror (section 3). No path reads a server secret; no path writes env.

## Testing

- **`publicSettings.ts`**: `parsePublicSettings` — valid banner → typed object; missing/empty/malformed → `announcement_banner: null` (never throws).
- **`useAppSettings`** (mock supabase): unconfigured → DEFAULTS, no rpc; configured → rpc → parsed banner; rpc error → DEFAULTS (fail-open).
- **`AnnouncementBanner`**: null/empty text → renders nothing; set → renders text + severity; dismissible → X dismisses (sessionStorage).
- **`envMask.ts`**: URL + key masking (prefix/suffix, never the full value); empty → "Missing".
- **`EnvironmentView`**: renders the 3 sections; server-secret rows show names + "Server-managed" and NO value; never renders a full secret.
- **`useAdminAppSettings`**: ready maps rows; `updateValue`/`updateDescription`/`createSetting`/`deleteSetting` call the right ops; ok/error.
- **`SettingsView`**: renders a row per setting; the banner row uses the typed editor and updates the value; a json-kind row rejects invalid JSON (no write, shows message) and accepts valid; add/delete; empty/error/alert.
- **`AdminShell.test`**: stub + route tests for `#settings` and `#env`.
- **App offline test:** `useAppSettings` returns DEFAULTS (no banner) with `supabaseConfigured=false`; App renders fully.
- **Live (MCP):** apply `0013`; `select get_public_settings()` returns the whitelisted keys; update `announcement_banner` → `audit_log` row + `updated_by`; advisors → only the intended `get_public_settings` anon-executable WARN, no new ERROR.
- Gate: full suite green, coverage ≥ 80/70, `tsc -b` clean, build ✓, exits 0. Types regenerated for the RPC.
- **Browser smoke** (controller, best-effort): /admin → Settings → set the announcement banner text → it appears atop /app (incl. signed-out); /admin → Environment shows masked public vars + the server-secret checklist (no values); confirm `audit_log`.

## Out of scope (later)

Wiring the other candidate settings (support email in error screens, pro-price display in the upsell, signup_enabled gate); per-setting JSON-schema validation; an in-app audit-log viewer; a live "Test connection"/secret-presence probe (would require a server endpoint and risks the secret-safety line); editing env vars from the UI (requires a deploy — explicitly never in the browser).

## File manifest

**Create:** `supabase/migrations/0013_app_settings.sql`; `ui/src/lib/settings/{publicSettings.ts,useAppSettings.ts}` (+ tests); `ui/src/cockpit/AnnouncementBanner.tsx` (+ test); `ui/src/admin/settings/{useAdminAppSettings.ts,settingMeta.ts,SettingsView.tsx}` (+ tests); `ui/src/admin/environment/{EnvironmentView.tsx,envMask.ts}` (+ tests).
**Modify:** `ui/src/App.tsx` (banner), `ui/src/admin/AdminShell.tsx` (+ `AdminShell.test.tsx`) — routes `settings` + `env`; `ui/src/lib/supabase/types.ts` (regenerated for the RPC).
**No RLS change. No Edge Function. No engine/WASM/Tauri change. No new SPA deps.**
