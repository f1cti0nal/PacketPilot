# PacketPilot SaaS — Admin Dashboard (Phase 4) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-27
**Branch:** `feat/admin-dashboard`
**Sub-project:** 4 of the PacketPilot SaaS platform (depends on Phase 0 + Phase 3)

## Context

Phase 4 of the SaaS pivot (roadmap in `2026-06-27-saas-backend-foundation-design.md`). Phases 0 (Supabase backend) and 3 (admin shell + auth gate) are merged to `main`. The admin shell already routes `dashboard → ui/src/admin/views/AdminDashboard.tsx`, which is currently a placeholder. This phase replaces that placeholder with the real overview screen from the reference mockup — KPI cards, two charts, and a recent-users table — sourced entirely from the live schema.

Decisions locked with the user:
- **Time-series via SQL aggregate RPCs** (admin-gated, scalable), not client-side grouping.
- **System Health = real "Operational"/"Degraded" status** derived from load success — no fabricated percentage (PacketPilot has a past bug from fabricated quantified claims).
- **Recent-users table is read-only**; View/Block/manage actions belong to Phase 5 (Users).

## Goal

Render the admin dashboard with real data: 6 KPI cards + a System Health status card, a "Daily New Users" area chart, a "New Subscriptions" bar chart, and a read-only recent-users table — with loading/error states — all behind the existing admin gate.

## Invariants preserved

No change to `/app`, the WASM engine, or the analysis path. No change to the admin shell/auth/routing (Phase 3). Security stays server-side: the new RPCs are `SECURITY INVOKER` so the caller's RLS applies (admins see all rows; a non-admin only their own — no leak), and `admin_dashboard_stats` is already admin-only via RLS. No new dependencies (`recharts` is already a dep).

## Architecture

```
supabase/migrations/0008_dashboard_rpcs.sql   # admin_signups_by_day, admin_subscriptions_by_day
ui/src/admin/useAdminDashboard.ts             # one hook: parallel fetch → loading|ready|error
ui/src/admin/dashboard/
  AdminDashboard.tsx        # replaces views/AdminDashboard.tsx placeholder; orchestrates hook + layout
  KpiCards.tsx              # 6 StatTile KPIs + SystemHealthCard
  SignupsAreaChart.tsx      # recharts AreaChart (Daily New Users)
  SubscriptionsBarChart.tsx # recharts BarChart (New Subscriptions)
  RecentUsersTable.tsx      # .pp-table read-only table
  format.ts                 # money (cents→$) + date helpers for the dashboard
ui/src/admin/views/AdminDashboard.tsx   # DELETED (re-exported/moved to dashboard/)
ui/src/admin/AdminShell.tsx             # update the dashboard import path
```

**Tech stack:** React 18 + TS, `@supabase/supabase-js` (Phase-0 client), `recharts` (existing), Tailwind + `index.css` tokens + `cockpit/primitives` (`Card`, `StatTile`). Vitest + RTL. No new deps.

## Backend — `0008_dashboard_rpcs.sql`

Two functions returning a **continuous** daily series (zero-filled days) so charts render smoothly. `SECURITY INVOKER` (RLS applies to the caller), `stable`, `set search_path = ''`, fully-qualified names.

```sql
create or replace function public.admin_signups_by_day(days integer default 14)
returns table(day date, count bigint)
language sql stable security invoker set search_path = ''
as $$
  select d::date as day, count(p.id) as count
  from generate_series((now() - ((greatest(days,1) - 1) || ' days')::interval)::date, now()::date, interval '1 day') as d
  left join public.profiles p on p.created_at::date = d::date
  group by d order by d;
$$;

create or replace function public.admin_subscriptions_by_day(days integer default 14)
returns table(day date, count bigint)
language sql stable security invoker set search_path = ''
as $$
  select d::date as day, count(s.id) as count
  from generate_series((now() - ((greatest(days,1) - 1) || ' days')::interval)::date, now()::date, interval '1 day') as d
  left join public.subscriptions s on s.created_at::date = d::date and s.status = 'active'
  group by d order by d;
$$;
```

Notes: SECURITY INVOKER avoids the `*_security_definer_function_executable` advisor warnings while RLS still gates the data. A non-admin calling these via RPC sees only their own rows (partial counts) — acceptable, no leak. The dashboard always calls them in an admin context.

## Data hook — `useAdminDashboard.ts`

```ts
export interface RecentUser { email: string; full_name: string | null; plan: string; status: string; created_at: string }
export interface DayPoint { day: string; count: number }
export interface DashboardStats {
  total_users: number; paid_users: number; free_users: number;
  active_today: number; mrr_cents: number; signups_7d: number;
}
export interface DashboardData {
  stats: DashboardStats; recentUsers: RecentUser[]; signups: DayPoint[]; subscriptions: DayPoint[];
}
export type AdminDashboardState =
  | { status: "loading" } | { status: "error"; error: string } | { status: "ready"; data: DashboardData };
export function useAdminDashboard(): AdminDashboardState;
```
On mount (guarded by a cancelled flag): `Promise.all` of the four queries via the Phase-0 `supabase` client (stats `.single()`, recent users `.order(created_at desc).limit(8)`, the two `rpc()` calls with `{ days: 14 }`). Any rejected query → `error`. If `!supabaseConfigured` → `error` with a config message (the admin gate already prevents reaching here unconfigured, but the hook stays defensive). Numbers from the view may arrive as `number` or stringy `bigint`; the hook coerces via `Number(...)`.

## Components

- **`AdminDashboard.tsx`** (replaces the placeholder): calls the hook; `loading` → `LoadingState`, `error` → `ErrorState` (existing components), `ready` → the grid: KPI row, charts row (2-up, stacks on narrow), recent-users table. Wrapped in `Card`s for each panel, matching the shell.
- **`KpiCards.tsx`**: 6 `StatTile`s (Total Users, Paid, Free, Active Today, Revenue = `$${(mrr_cents/100).toLocaleString()}`, New 7d) + `SystemHealthCard` (a `StatTile`-styled card showing "Operational" in `--color-sev-low` or "Degraded" in `--color-sev-high`; Phase 4 always renders inside the `ready` branch so it reads Operational, but the prop is driven by state so an error path could show Degraded later).
- **`SignupsAreaChart.tsx`** / **`SubscriptionsBarChart.tsx`**: recharts inside `ResponsiveContainer`, `CartesianGrid`/`XAxis`/`YAxis` tokenized exactly like `components/triage/TimelineChart.tsx`; X = day (formatted `MM-DD`), Y = count; accent fill for area, `--color-accent` bars; empty-data fallback message.
- **`RecentUsersTable.tsx`**: `.pp-table` table; columns Name (`full_name` or email local-part), Email, Plan (a `Tag`/chip), Status (chip; active/suspended/blocked colored), Joined (`created_at` → `YYYY-MM-DD`). Read-only.
- **`format.ts`**: `money(cents)`, `shortDay(iso)`, `joinedDate(iso)` pure helpers (unit-tested).

## Data flow & error handling

Mount → hook fires 4 parallel queries → `ready` with data or `error` (message surfaced via `ErrorState`, with no PII beyond what an admin already sees). Coercion guards against bigint-as-string. Charts render the zero-filled series (always 14 points). The recent-users query is RLS-gated (admin sees all). No mutations in this phase.

## Testing

- **`format.ts`**: `money(5700)==="$57"` (and thousands separator), `joinedDate`/`shortDay` formatting.
- **`useAdminDashboard`** (mock `../lib/supabase`): resolves → `ready` with coerced stats + arrays; a rejected query → `error`; bigint-string coercion.
- **`KpiCards`**: renders the 6 labels + formatted values; SystemHealthCard shows "Operational" for ready / "Degraded" for the degraded prop.
- **Charts**: render with a small series → the card title + a chart container present (recharts SVG internals/colors not asserted — jsdom limitation, consistent with existing `ProtocolSunburst`/sunburst tests); empty series → fallback text.
- **`RecentUsersTable`**: renders a row per user with name/email/plan/status/joined; scope row asserts with `within(table)`.
- **`AdminDashboard`**: loading → status spinner; error → error message; ready → KPIs + both chart titles + table present (hook mocked).
- **`AdminShell.test`** (updated): mock `./dashboard/AdminDashboard` to a stub so the shell test never hits Supabase; change the "defaults to the dashboard" assertion from the old placeholder copy to the stub's marker. The other shell tests (nav, hash, sign-out, toggles) are unchanged.
- **Live (MCP):** call both RPCs against the seed → `admin_signups_by_day` returns 14 rows summing to 5; `admin_subscriptions_by_day` sums to 3; `get_advisors` security has no new ERROR and no new definer-executable warnings.
- Gate: full suite green, coverage ≥ 80/70, `npx tsc -b` clean, `npm run build` passes, browser smoke (login → dashboard shows Total Users 5, Revenue $57, etc.).

## Out of scope (later phases)

User mutations / View / Block / role changes (Phase 5); payments/invoice detail (Phase 6); live-traffic deep dive + real ingestion (Phase 7); feature flags (8); settings/env (9); real uptime monitoring for System Health; date-range pickers / CSV export of the dashboard.

## File manifest

**Create:** `supabase/migrations/0008_dashboard_rpcs.sql`, `ui/src/admin/useAdminDashboard.ts`, `ui/src/admin/dashboard/{AdminDashboard,KpiCards,SignupsAreaChart,SubscriptionsBarChart,RecentUsersTable,format}.tsx|ts` (+ co-located tests).
**Modify:** `ui/src/admin/AdminShell.tsx` (import `AdminDashboard` from `./dashboard/AdminDashboard`), `ui/src/admin/AdminShell.test.tsx` (mock `./dashboard/AdminDashboard` to a stub + update the dashboard-default assertion off the old placeholder copy, keeping the shell test data-fetch-free).
**Delete:** `ui/src/admin/views/AdminDashboard.tsx` (placeholder superseded) + its reference; keep `views/Placeholder.tsx` for the other sections.
**No `/app`, engine, WASM, or admin-shell/auth change. No new deps.**
