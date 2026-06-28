# PacketPilot SaaS — Live Traffic + Analytics Ingestion (Phase 7) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-28
**Branch:** `feat/live-traffic`
**Sub-project:** 7 of the PacketPilot SaaS platform (depends on Phase 0 + Phase 3)

## Context

Phase 7 of the SaaS pivot. Phases 0–6 are merged + deployed. The `/admin` **Live Traffic** section (`sections.ts` id `traffic`, Activity icon) currently falls through to the placeholder. This phase adds **lightweight first-party web analytics**: ingest page-view events into the existing `analytics_events` table and surface them in an admin Live Traffic view.

Decisions locked with the user:
- **Ingestion: direct client-insert, no geo.** A single allowlist-enforcing tracker inserts via the anon key, gated by tightened RLS; no Edge Function; `country` stays NULL (no server IP lookup).
- **Scope: all surfaces, anon + authed.** Track the marketing landing (`/`), the triage app tabs (`/app#…`), and the admin sections (`/admin#…`), for both anonymous and signed-in visitors.

**Grounded in code (Phase-7 understand workflow):**
- `analytics_events` (migration `0001_init.sql`): `id bigint identity, session_id text NOT NULL, path text NOT NULL, referrer text, user_id uuid FK→profiles.id, country text, user_agent text, created_at timestamptz default now()`. Indexes on `created_at`, `session_id`, `user_id`. **Write-once** (no UPDATE policy).
- RLS today: `analytics_insert_any` (anon+authenticated, `WITH CHECK (true)` — the Phase-0 carry-forward to fix), `analytics_select_admin` (is_admin), `analytics_delete_admin` (is_admin).
- **Nothing writes the table today**; the only reader is `admin_dashboard_stats.active_today = COUNT(DISTINCT session_id)` over 24h. 200 seed rows exist.
- The admin view mirrors the Phase-4/5/6 pattern: a `Promise.all` hook over a view + by-day RPC, the recharts wrappers (`SignupsAreaChart`/`SubscriptionsBarChart`), and SECURITY-INVOKER zero-filled `generate_series` by-day RPCs (`0008_dashboard_rpcs.sql`).
- App tabs: `dashboard, flows, findings, recent, compare`. Admin sections: `dashboard, users, payments, traffic, features, settings, env`. `useSession` does **not** expose the auth uid → the tracker reads it from `supabase.auth.getSession()` (auth state, never capture state).

## Goal

Collect benign page-view analytics across all surfaces (only canonical route tokens; never any capture data), tighten the analytics insert RLS, and give admins a Live Traffic view (active users, page-views over time, top paths, recent events) whose `active_today` agrees with the dashboard.

## Invariants preserved

- **HARD privacy boundary:** captured packet data / analysis results NEVER touch the backend. Events carry ONLY a canonical route token, a per-tab-session UUID, and (if signed in) the auth uid. The tracker has no import path to capture/flow/summary state; a closed route allowlist drops anything else; a DB `WITH CHECK` backstops it.
- **Single ingestion path:** every insert to `analytics_events` goes through one module (`track.ts`), enforced by a unit test asserting `.from("analytics_events")` appears in exactly that file.
- **No secret in the SPA; no Edge Function.** Direct anon-key insert, RLS-gated. Service-role seed inserts bypass RLS (unaffected).
- **Dashboard consistency:** Live Traffic `active_today` uses the SAME definition as `admin_dashboard_stats`.
- **Engine/`/app` analysis untouched; no new SPA deps** (uses `crypto.randomUUID`, `sessionStorage`, the existing supabase client + recharts).

## Architecture

```
supabase/migrations/
  0010_analytics_ingest_hardening.sql   # split insert RLS (anon/authed) + path allowlist + forbid referrer/UA/country + rate trigger
  0011_traffic_read.sql                 # admin_traffic_stats view + admin_pageviews_by_day(days) + admin_top_paths(days,lim) RPCs (SECURITY INVOKER)
ui/src/lib/analytics/
  track.ts        # ROUTES allowlist + trackPageView(path): sessionStorage UUID + supabase.auth uid + fire-and-forget insert
ui/src/landing/Landing.tsx     # trackPageView("/") on mount
ui/src/App.tsx                 # trackPageView(`/app#${tab}`) on mount + tab change
ui/src/admin/AdminShell.tsx    # trackPageView(`/admin#${active}`) on mount + section change
ui/src/admin/traffic/
  useAdminTraffic.ts   # Promise.all(view + 2 RPCs + recent events) → state
  TrafficView.tsx      # KPI strip + pageviews-by-day area chart + top-paths table + recent-events table
```

**Tech stack:** React 18 + TS, the Phase-0 Supabase client, recharts (existing), Tailwind tokens, Vitest + RTL. Supabase MCP for the two migrations.

## Ingestion — `0010` + `track.ts`

**Migration `0010_analytics_ingest_hardening.sql`** (replaces the `WITH CHECK (true)` carry-forward):
```sql
drop policy if exists analytics_insert_any on public.analytics_events;

-- Canonical-path + privacy guard shared by both roles: only the route allowlist shape,
-- and the public roles may NOT write referrer / user_agent / country (kept NULL).
-- (Service-role seed inserts bypass RLS, so existing/seeded rows are unaffected.)
create policy analytics_insert_anon on public.analytics_events
  for insert to anon
  with check (
    user_id is null
    and length(path) <= 32
    and (path = '/' or path ~ '^/(app|admin)#[a-z]+$')
    and referrer is null and user_agent is null and country is null
  );

create policy analytics_insert_authenticated on public.analytics_events
  for insert to authenticated
  with check (
    (user_id is null or user_id = (select auth.uid()))
    and length(path) <= 32
    and (path = '/' or path ~ '^/(app|admin)#[a-z]+$')
    and referrer is null and user_agent is null and country is null
  );

-- Per-session burst cap (accidental render-loop / abuse backstop). SECURITY DEFINER so it
-- can count rows the anon role can't SELECT; search_path pinned; EXECUTE revoked (trigger-only).
create or replace function public.analytics_rate_limit()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if (select count(*) from public.analytics_events
        where session_id = new.session_id and created_at > now() - interval '1 minute') >= 60 then
    raise exception 'analytics rate limit exceeded for session';
  end if;
  return new;
end;
$$;
revoke execute on function public.analytics_rate_limit() from public, anon, authenticated;

drop trigger if exists analytics_rate_limit on public.analytics_events;
create trigger analytics_rate_limit
before insert on public.analytics_events
for each row execute function public.analytics_rate_limit();
```

**`ui/src/lib/analytics/track.ts`** — the ONLY inserter:
```ts
const ROUTES = new Set<string>([
  "/",
  "/app#dashboard", "/app#flows", "/app#findings", "/app#recent", "/app#compare",
  "/admin#dashboard", "/admin#users", "/admin#payments", "/admin#traffic",
  "/admin#features", "/admin#settings", "/admin#env",
]);
```
- `sessionId()`: read/create a `crypto.randomUUID()` in `sessionStorage["pp_sid"]` (per-tab-session; rotates per tab).
- `trackPageView(path: string)`: drop if `!ROUTES.has(path)` or `path === lastPath` (dedupe consecutive); if `!supabase`, return; else read `supabase.auth.getSession()` (cached auth state — NOT capture state) for `user_id`, then `void supabase.from("analytics_events").insert({ path, session_id, user_id }).then(noop, noop)` — fire-and-forget, failure-silent, no `created_at` (server default). `referrer`/`user_agent`/`country` are never set.
- It imports only `supabase` (auth + insert). It must not import App/summary/flows/recent/IndexedDB/reputation modules.

**Wiring (one `useEffect` each):** `Landing` → `trackPageView("/")` on mount; `App` → `trackPageView(\`/app#\${tab}\`)` keyed on `tab`; `AdminShell` → `trackPageView(\`/admin#\${active}\`)` keyed on `active`.

**Drift guard:** a unit test asserts `ROUTES` contains `\`/admin#\${id}\`` for every `ADMIN_SECTIONS` id and `\`/app#\${tab}\`` for every app `TabId` — so adding a tab/section without extending `ROUTES` (which would silently stop tracking) fails CI. The DB regex backstop needs no per-token update (it matches the shape).

## Read side — `0011` + `useAdminTraffic` + `TrafficView`

**Migration `0011_traffic_read.sql`** (all SECURITY INVOKER, `search_path=''`, so the caller's `analytics_select_admin` RLS applies — admins only):
- `admin_traffic_stats` view (single row): `active_today = count(distinct session_id) where created_at > now()-'24h'` (identical to `admin_dashboard_stats`), `pageviews_today = count(*) same window`, `authed_today = count(distinct session_id) where user_id is not null`, `anon_today = count(distinct session_id) where user_id is null`.
- `admin_pageviews_by_day(days int)` → `(day date, count bigint)` zero-filled via `generate_series`, mirroring `admin_signups_by_day`.
- `admin_top_paths(days int, lim int)` → `(path text, count bigint)` grouped, desc, limited.

**`ui/src/admin/traffic/useAdminTraffic.ts`:** `loading | error | ready{ stats, byDay, topPaths, recent }`. One `Promise.all`: `.from("admin_traffic_stats").select("*").single()`, `.rpc("admin_pageviews_by_day",{days:14})`, `.rpc("admin_top_paths",{days:7,lim:10})`, and `.from("analytics_events").select("path,user_id,created_at").order("created_at",{ascending:false}).limit(25)` (recent). `reload()` nonce. Same shape/guards as `useAdminDashboard`. Recent rows expose a derived `signedIn = user_id != null` boolean only — never the uid/email.

**`ui/src/admin/traffic/TrafficView.tsx`:** KPI strip (Active users today, Page views today, Signed-in / Anonymous) → reuse the `Kpi`/`money`-free count tiles; a "Page views (14d)" `Card` with `SignupsAreaChart` over `byDay`; a "Top paths (7d)" `.pp-table` (path, count); a "Recent activity" `.pp-table` (time, path, Signed-in? yes/no). Loading/error/empty states. Wire `AdminShell`: `active === "traffic"` → `<TrafficView />`.

## Data flow & privacy

Navigation fires `trackPageView(token)` → allowlist check → `{token, sid, uid?}` inserted (RLS: anon→uid null, authed→own uid, path∈shape, no referrer/UA/country; burst-capped). Admin opens Live Traffic → RLS-gated reads of the view/RPCs/recent → charts + tables. No capture data can enter an event (no import path + allowlist + DB check); the admin view echoes no identity (only a signed-in boolean + aggregate counts). Tracking is fire-and-forget and failure-silent, so a rejected/failed insert never affects navigation.

## Testing

- **`track.ts`** (mock `../supabase`): inserts only allowlisted paths (drops `/app/secret`, `/?q=1.2.3.4`, capture-shaped strings); dedupes consecutive identical tokens; builds `{path, session_id, user_id}` with the sessionStorage UUID and the auth uid (mock `auth.getSession`), null uid when signed out; never sets referrer/user_agent/country/created_at; no-ops when `supabase` is null; swallows insert rejection. **Drift test:** `ROUTES` covers every `ADMIN_SECTIONS` id and every app `TabId`. **Single-inserter test:** a repo grep asserts `.from("analytics_events")` appears only in `track.ts`.
- **Wiring** (`Landing`/`App`/`AdminShell`): mock `track.ts`; assert `trackPageView` called with `/`, `/app#<tab>` on tab change, `/admin#<section>` on section change.
- **`useAdminTraffic`** (mock supabase): ready maps the view + both RPCs + recent (with `signedIn` derived); error + reload; unconfigured → error.
- **`TrafficView`**: renders KPIs, the area chart (vi.mock recharts ResponsiveContainer), top-paths + recent tables (`within(table)`), signed-in boolean (not uid), empty/error.
- **Live (MCP):** apply `0010` + `0011`; verify an allowlisted insert succeeds and a non-allowlisted/forbidden-field insert is rejected (as anon); verify the view/RPCs return; `get_advisors` security → no new ERROR; the rate trigger function's advisory is cleared by the revoke.
- Gate: full suite green, coverage ≥ 80/70, `tsc -b` clean, `npm run build` ✓, coverage run exits 0. Types regenerated after `0011` (new view/RPCs).
- **Browser smoke** (controller, best-effort): navigate `/` → `/app` tabs → `/admin` sections, confirm rows land in `analytics_events` (via `execute_sql`), then open Live Traffic and confirm the KPIs/chart/tables populate.

## Out of scope (later)

Geo/country breakdown (needs an Edge Function or GeoIP); per-user journey/session replay; event types beyond page-views (clicks, conversions); real-time streaming; retention/cohort analysis; tightening for high-volume abuse (signed-token ingest); the `analytics_delete_admin` UI (pruning).

## File manifest

**Create:** `supabase/migrations/0010_analytics_ingest_hardening.sql`, `supabase/migrations/0011_traffic_read.sql`, `ui/src/lib/analytics/track.ts` (+ test + drift/single-inserter tests), `ui/src/admin/traffic/useAdminTraffic.ts` (+ test), `ui/src/admin/traffic/TrafficView.tsx` (+ test).
**Modify:** `ui/src/landing/Landing.tsx`, `ui/src/App.tsx`, `ui/src/admin/AdminShell.tsx` (+ `AdminShell.test.tsx`) — tracker call sites + the `traffic` route; `ui/src/lib/supabase/types.ts` (regenerated for the new view/RPCs).
**No engine/WASM/Tauri change. No `/app` analysis change. No Edge Function. No new SPA deps.**
