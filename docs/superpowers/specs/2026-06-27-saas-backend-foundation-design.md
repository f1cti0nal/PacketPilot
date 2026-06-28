# PacketPilot SaaS — Backend Foundation (Phase 0) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-27
**Branch:** `feat/saas-backend-foundation`
**Sub-project:** 0 of the PacketPilot SaaS platform (see Roadmap below)

## Context: this is one sub-project of a platform

The user asked for a non-public **admin panel** (live web traffic, app features, payments, users, admin settings, environment variables), referencing two SaaS-dashboard mockups. PacketPilot is today a 100% client-side, privacy-first packet-analysis tool: static SPA on Vercel (`packet-pilot.vercel.app`), Rust→WASM engine in the browser, **no server, DB, accounts, or payments**. Routing is a one-line `window.location.pathname` branch in `ui/src/main.tsx` (`/` → Landing, `/app` → App).

Decisions locked with the user:
- **Full real SaaS backend** (not a mock UI).
- **Add real end-user accounts + Stripe billing to the product**, and the admin panel manages those real users/subscriptions.
- **Stack: Supabase** (Postgres + Auth + RLS + Edge Functions + Storage).
- **Build order: admin-visible early** — Phase 0 (this spec) → 3 (admin shell) → 4 (dashboard) → 1 (accounts) → 2 (billing) → 5–9.
- **Admin gating: role-gated `/admin` route**, enforced server-side by RLS (UI hiding is cosmetic).
- **Plans: Free + Pro.**
- **First admin: bootstrap the user's own account** (`profiles.role = 'admin'`).

This spec covers **Phase 0 only** (backend foundation). Each later phase gets its own spec → plan → build cycle.

### Roadmap (for context; not built here)
| # | Sub-project | Depends on |
|---|---|---|
| **0** | **Backend foundation (this spec)** | — |
| 1 | End-user accounts (signup/login, profile, plan, gate `/app`) | 0 |
| 2 | Billing (Stripe checkout/portal + webhook Edge Function → subscription state) | 0,1 |
| 3 | Admin foundation (admin role + non-public `/admin` + admin shell/nav) | 0,1 |
| 4 | Admin dashboard overview (KPI cards + traffic/conversion charts + recent users) | 0,3 (renders over Phase-0 seed data; Phase 2 later swaps seed → real revenue) |
| 5 | Admin: Users (search, change plan, suspend/block) | 3,1 |
| 6 | Admin: Payments (subscriptions, invoices, revenue, refunds via Stripe) | 3,2 |
| 7 | Live web traffic (visitor analytics ingestion + view) | 3 |
| 8 | App features (feature-flag management) | 3 |
| 9 | Admin settings + Env vars (app config; deployment env read-only/masked) | 3 |

## Goal

Stand up the Supabase backend, database schema, security model (RLS), auth scaffolding, typed client, and migration/secrets workflow that **every later phase builds on** — and seed enough data that the Phase 4 admin dashboard renders against real tables. **No UI is built in this phase.**

## Invariant preserved

The backend handles **accounts, billing, and analytics only**. Captured packet data still **never leaves the browser** — the Rust→WASM analysis path (`ui/src/lib/wasmEngine.ts`, `ui/src/lib/data.ts`) and the privacy gates (reputation/AI consent) are untouched. No capture bytes, flows, or summaries are sent to Supabase.

## Architecture

A new top-level `supabase/` directory holds the schema (SQL migrations as source of truth), seed data, and a placeholder `functions/` dir (Edge Functions arrive in Phase 2). The SPA gains a thin typed Supabase client under `ui/src/lib/supabase/`. The existing app is otherwise unchanged in Phase 0 — no routing, no auth UI, no gating yet.

```
supabase/
  config.toml                 # Supabase CLI project config (project ref + local stack ports)
  migrations/
    0001_init.sql             # enums, tables, indexes
    0002_rls.sql              # enable RLS + policies + is_admin() helper
    0003_triggers.sql         # auth.users → profiles trigger; updated_at triggers; profiles privilege-escalation guard
    0004_views.sql            # admin_dashboard_stats view
    0005_bootstrap_admin.sql  # set the user's account to role='admin' (idempotent, by email)
  seed.sql                    # demo profiles/subscriptions/analytics/flags for the dashboard
  functions/                  # (empty placeholder; Stripe webhook lands here in Phase 2)
  .gitignore                  # ignore .branches/.temp
ui/src/lib/supabase/
  client.ts                   # browser client (anon key); single shared instance
  types.ts                    # generated DB types (committed)
  index.ts                    # re-exports
```

**Tech stack:** Supabase (Postgres 17), `@supabase/supabase-js` v2 (new dep in `ui/`), Supabase CLI for local dev + types, Supabase MCP for applying migrations to the cloud project. Frontend unchanged (React 18 + Vite + TS).

## Provisioning (performed at implementation time, after spec approval)

1. **Create project** `packetpilot` in org `f1cti0nal's Org` (`vuybamipvuuewqobdtin`), region us-east-1. Confirmed cost **$0/mo** (re-confirm via `get_cost` immediately before `create_project`; if the free-project slot is unavailable because `prismpath` + `nexus` already occupy the org's free tier, pause/confirm with the user rather than incurring cost).
2. **Capture credentials:** project URL + anon (publishable) key via `get_project_url` / `get_publishable_keys`. These are **public** and safe in the SPA bundle.
3. **Wire env:**
   - Local: `ui/.env.local` (gitignored) — `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY`.
   - Vercel: same two as project env vars (so the deployed build connects).
   - `ui/.env.example` (committed) documents the two vars.
4. **Service-role / Stripe secrets are NOT set in Phase 0** — they only exist inside Edge Functions starting Phase 2, never in the SPA or repo.

## Data model (`0001_init.sql`)

Defined in full now to avoid re-scheming later, even though most columns are first *used* in later phases.

**Enums**
- `user_plan`: `free`, `pro` (extensible).
- `user_role`: `user`, `admin`.
- `user_status`: `active`, `suspended`, `blocked`.
- `subscription_status`: `trialing`, `active`, `past_due`, `canceled`, `incomplete`, `incomplete_expired`, `unpaid`, `paused` (mirrors Stripe).

**Tables**
- `profiles` (1:1 with `auth.users`)
  - `id uuid PK references auth.users(id) on delete cascade`
  - `email text not null`, `full_name text`, `avatar_url text`
  - `plan user_plan not null default 'free'`
  - `role user_role not null default 'user'`
  - `status user_status not null default 'active'`
  - `created_at timestamptz not null default now()`, `updated_at timestamptz not null default now()`
- `subscriptions` (Stripe mirror; written by webhooks in Phase 2)
  - `id uuid PK default gen_random_uuid()`
  - `user_id uuid not null references profiles(id) on delete cascade`
  - `stripe_customer_id text`, `stripe_subscription_id text unique`, `price_id text`
  - `status subscription_status not null`
  - `amount_cents integer`, `currency text not null default 'usd'` (denormalized from the Stripe price by the webhook; lets the dashboard compute MRR without a price lookup)
  - `current_period_end timestamptz`, `cancel_at_period_end boolean not null default false`
  - `created_at`, `updated_at`
  - index on `user_id`
- `feature_flags`
  - `key text PK`, `description text`, `enabled boolean not null default false`
  - `plan_gate user_plan` (nullable — null = available to all plans)
  - `updated_at timestamptz not null default now()`, `updated_by uuid references profiles(id)`
- `app_settings`
  - `key text PK`, `value jsonb not null default '{}'`, `description text`
  - `updated_at`, `updated_by uuid references profiles(id)`
- `analytics_events`
  - `id bigint generated always as identity PK`
  - `session_id text not null`, `path text not null`, `referrer text`
  - `user_id uuid references profiles(id) on delete set null`
  - `country text`, `user_agent text`
  - `created_at timestamptz not null default now()`
  - indexes on `created_at`, `session_id`
- `audit_log`
  - `id bigint generated always as identity PK`
  - `actor_id uuid references profiles(id)`, `action text not null`, `target text`
  - `meta jsonb not null default '{}'`, `created_at timestamptz not null default now()`
  - index on `created_at`

**View (`0004_views.sql`)** — `admin_dashboard_stats` (single-row rollup for Phase 4): `total_users`, `paid_users`, `free_users`, `active_today` (distinct `analytics_events.session_id` in last 24h), `mrr_cents` (sum of `amount_cents` over subscriptions where `status='active'`), `signups_7d`. Implemented as a view; revisit as a materialized view in Phase 7 if needed. Marked `security_invoker = true` so RLS applies to the caller (admin-only reads still gated by the underlying tables' policies).

## Auth & roles

- Supabase Auth enabled, **email/password** provider (OAuth deferred to Phase 1+). Email confirmation ON (configurable).
- **Profile auto-creation:** trigger on `auth.users` insert (`0003_triggers.sql`) creates a matching `profiles` row (`email` copied, `plan='free'`, `role='user'`, `status='active'`). `SECURITY DEFINER`, owned by a privileged role, search_path pinned.
- **`updated_at`:** a generic `set_updated_at()` trigger on the mutable tables.
- **Admin role** = `profiles.role = 'admin'`. RLS policies call a `public.is_admin()` helper: `SECURITY DEFINER`, returns whether `auth.uid()`'s profile has `role='admin'`, `search_path = ''`, fully-qualified names (avoids the recursive-RLS pitfall of selecting `profiles` inside a `profiles` policy).
- **Bootstrap (`0005_bootstrap_admin.sql`):** idempotent `update profiles set role='admin' where email = '<admin email>'`. The admin signs up first; this migration (or a one-off `execute_sql`) promotes them. Admin email confirmed with the user at implementation time (default: the user's identity).

## Row-Level Security (`0002_rls.sql`)

RLS **enabled on every table**. The SPA only ever uses the **anon key under a logged-in user's JWT**, so policies are the real boundary.

| Table | select | insert | update | delete |
|---|---|---|---|---|
| `profiles` | own row OR `is_admin()` | (trigger only) | own row (non-privileged cols) OR `is_admin()` | `is_admin()` |
| `subscriptions` | own (`user_id = auth.uid()`) OR `is_admin()` | service-role only | service-role only | service-role only |
| `feature_flags` | authenticated read | `is_admin()` | `is_admin()` | `is_admin()` |
| `app_settings` | `is_admin()` | `is_admin()` | `is_admin()` | `is_admin()` |
| `analytics_events` | `is_admin()` | anon/authenticated insert (ingestion) | — | `is_admin()` |
| `audit_log` | `is_admin()` | `is_admin()` (or service-role) | — | — |

Notes:
- A user must **not** be able to change their own `role`/`plan`/`status` (privilege escalation). **Chosen approach:** a `BEFORE UPDATE` trigger on `profiles` that raises when those columns change **and** `auth.uid() is not null` **and** `not is_admin()`. The `auth.uid() is null` carve-out lets service-role/migration contexts (seeding, admin bootstrap, Phase-2 webhooks) set roles/plans; admins can too; only authenticated non-admins are blocked. More robust than column-scoped `WITH CHECK`, and keeps the self-update policy simple (own row, authenticated).
- `analytics_events` insert is intentionally open to anonymous visitors (that's how page views are recorded in Phase 7), but **read is admin-only** so visitor data isn't exposed.

## Migration & types workflow

- SQL migration files in `supabase/migrations/` are the **source of truth**, committed to git (mirrors the project's "commit the WASM artifact" discipline).
- Applied to the cloud project via the Supabase MCP `apply_migration` (one call per file, named) — or `supabase db push` with the CLI. Local stack (`supabase start`) optional for dev; not required since the MCP applies to the cloud dev project directly.
- After migrations, **regenerate `ui/src/lib/supabase/types.ts`** (`generate_typescript_types`) and commit it. The client is typed via `createClient<Database>()`.

## The Supabase client (`ui/src/lib/supabase/client.ts`)

A single shared `createClient<Database>(url, anonKey, { auth: { persistSession: true, autoRefreshToken: true } })`. Reads `import.meta.env.VITE_SUPABASE_URL` / `VITE_SUPABASE_ANON_KEY`. If either is missing, exports a clearly-flagged "unconfigured" state (a `supabaseConfigured` boolean) so the existing app keeps working locally without the env vars — Phase 0 introduces the client but does not require it at runtime for the current packet-analysis flows. Vitest mocks this module.

## Phase 9 "environment variables" — design note (not built here)

The Phase 9 admin "env vars" surface will manage **app-level config rows in `app_settings`** and display real **deployment** env vars **read-only / masked**. It will **not** write real deployment secrets from the browser (that would be a serious security hole). The `app_settings` table here anticipates that. Recorded now so the schema is right; full design in the Phase 9 spec.

## Data flow & error handling

Phase 0 has no user-facing flow. Correctness is defined by: migrations apply idempotently; the profile trigger fires on signup; RLS denies cross-tenant and anonymous reads; the typed client builds and connects. All client access in later phases goes through `ui/src/lib/supabase/`. Missing env → `supabaseConfigured === false`, no throw, existing app unaffected.

## Testing / definition of done

- **Migrations:** apply cleanly to a fresh project (and are individually idempotent where claimed). `list_migrations` shows all five.
- **Schema:** `list_tables` shows the six tables + enums + the view.
- **RLS simulations** (via `execute_sql` with `set local role`/JWT claims, or integration tests):
  - anon cannot `select` from `analytics_events`, `audit_log`, `app_settings`, others' `profiles`.
  - a non-admin user can read/update only their own `profiles` row and **cannot** change their own `role`/`plan`/`status`.
  - a non-admin can read only their own `subscriptions`.
  - an admin can read all `profiles`/`subscriptions`/`analytics_events`/`audit_log`.
- **Trigger:** inserting an `auth.users` row creates a `profiles` row with sane defaults.
- **Advisors:** `get_advisors` (security) and (performance) return **no errors** (warnings triaged/justified).
- **Client:** `ui` builds with the new dep; a mocked-client unit test verifies `supabaseConfigured` toggles on env presence; existing `npm run test:coverage` stays green at the 80/70 gate; `npm run build` (tsc + vite) passes.
- **Bootstrap:** the admin account ends up with `role='admin'`.
- **Seed:** demo data present so Phase 4 has something to render.

## Out of scope (later phases / explicitly not now)

- Any UI: signup/login, `/admin` route, admin shell, dashboard, the reference-image screens (Phases 1, 3, 4+).
- Stripe / Edge Functions / webhooks (Phase 2).
- Real analytics ingestion wiring from the SPA (Phase 7) — Phase 0 only defines the table + seeds demo rows.
- OAuth providers, email templates branding, password-reset UX (Phase 1+).
- Feature-flag enforcement in the product, settings UI, env-vars UI (Phases 8–9).
- Local Docker stack as a hard requirement (optional convenience only).

## File manifest

**Create:** `supabase/config.toml`, `supabase/.gitignore`, `supabase/migrations/0001_init.sql`, `0002_rls.sql`, `0003_triggers.sql`, `0004_views.sql`, `0005_bootstrap_admin.sql`, `supabase/seed.sql`, `ui/src/lib/supabase/client.ts`, `ui/src/lib/supabase/types.ts` (generated), `ui/src/lib/supabase/index.ts`, `ui/.env.example`, plus a co-located client unit test.
**Modify:** `ui/package.json` (+`@supabase/supabase-js`), `ui/.gitignore` (ensure `.env.local` ignored), root `.gitignore` if needed.
**No engine/WASM/Tauri change.** **No change to the existing packet-analysis runtime.**
