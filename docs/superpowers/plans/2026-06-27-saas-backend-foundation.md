# PacketPilot SaaS Backend Foundation (Phase 0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the Supabase backend (project, schema, RLS security model, auth scaffolding, dashboard rollup view, seed data, and a typed browser client) that every later SaaS phase builds on — with no user-facing UI.

**Architecture:** A new top-level `supabase/` directory holds SQL migrations (source of truth, applied to the cloud project via the Supabase MCP) plus seed scripts. The SPA gains a thin typed client under `ui/src/lib/supabase/` that is inert until env vars are present, so the existing packet-analysis app is unaffected. Security is enforced by Postgres RLS keyed on a `profiles.role` admin flag, not by the UI.

**Tech Stack:** Supabase (Postgres 17, Auth, RLS), `@supabase/supabase-js` v2, Supabase MCP (`create_project`, `apply_migration`, `execute_sql`, `generate_typescript_types`, `get_advisors`, `get_project_url`, `get_publishable_keys`), Node (seed script), React 18 + Vite + TypeScript + Vitest (unchanged).

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-06-27-saas-backend-foundation-design.md`. Branch: `feat/saas-backend-foundation` (already created).
- **Privacy invariant preserved:** the backend handles accounts/billing/analytics only. Captured packet data NEVER leaves the browser; do not touch the Rust→WASM analysis path (`ui/src/lib/wasmEngine.ts`, `ui/src/lib/data.ts`) or its consent gates.
- **Secrets:** only the **public** `VITE_SUPABASE_URL` + `VITE_SUPABASE_ANON_KEY` may appear in the SPA/repo (`.env.example` documents them; `.env.local` is gitignored). Service-role and Stripe keys must NEVER enter the bundle or git — they are passed to the seed script via the operator's local shell env only.
- **Migrations are the source of truth**, committed under `supabase/migrations/`, applied via MCP `apply_migration` (one named call per file). Generated `types.ts` is committed (mirrors the project's "commit the WASM artifact" rule).
- **Postgres 17**, all functions `security definer` with `set search_path = ''` and fully-qualified names. **RLS enabled on every table.**
- **UI gates:** `npm run test:coverage` must stay green at the **80/70** coverage gate; `npm run build` (tsc + vite) must pass. Run UI commands from inside `ui/`. No new runtime UI behavior.
- **Cost gate:** before `create_project`, re-confirm $0 via `get_cost`; if the org's free-project slot is unavailable, STOP and ask the user rather than incurring cost.
- **Plans:** Free + Pro. **Admin email** (for bootstrap) is confirmed with the user at execution; default `ravi.dholariya@icloud.com`.
- **Migration file order** (apply order) intentionally puts functions before the RLS policies that call them: `0001_init` → `0002_functions` → `0003_rls` → `0004_views` → `0005_bootstrap_admin`.

---

### Task 1: Provision the Supabase project + repo scaffolding + env wiring

**Files:**
- Create: `supabase/config.toml`
- Create: `supabase/.gitignore`
- Create: `supabase/functions/.gitkeep`
- Create: `ui/.env.example`
- Modify: `ui/.gitignore` (ensure `.env*.local` ignored — verify; add if missing)

**Interfaces:**
- Produces: a live Supabase project (`ref`, URL, anon key) used by all later tasks; the committed `supabase/` scaffolding; documented env var names `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY`.

- [ ] **Step 1: Re-confirm cost (MCP)**

Call `get_cost` with `type: "project"`, `organization_id: "vuybamipvuuewqobdtin"`.
Expected: `{"amount":0,...}`. If non-zero or a slot error → STOP and ask the user.

- [ ] **Step 2: Create the project (MCP)**

Call `create_project` with `name: "packetpilot"`, `organization_id: "vuybamipvuuewqobdtin"`, `region: "us-east-1"`, `confirm_cost_id` from the cost confirmation. Wait until `get_project` (or `list_projects`) shows `status: "ACTIVE_HEALTHY"`.

- [ ] **Step 3: Capture credentials (MCP)**

Call `get_project_url` and `get_publishable_keys` for the new project ref. Record the URL + anon key for Step 6 / later tasks. (These are public.)

- [ ] **Step 4: Write `supabase/config.toml`**

```toml
# Supabase CLI config. The cloud project is the source of truth for Phase 0;
# the local Docker stack is optional and not required to apply migrations
# (the Supabase MCP applies them to the cloud project directly).
project_id = "REPLACE_WITH_PROJECT_REF"

[db]
major_version = 17
```

- [ ] **Step 5: Write `supabase/.gitignore` and `supabase/functions/.gitkeep`**

`supabase/.gitignore`:
```gitignore
.branches
.temp
.env
```
`supabase/functions/.gitkeep`: empty file (keeps the dir; Edge Functions arrive in Phase 2).

- [ ] **Step 6: Write `ui/.env.example`**

```dotenv
# Supabase (public, safe to expose in the browser bundle).
# Copy to ui/.env.local and fill in from the Supabase project settings.
VITE_SUPABASE_URL=
VITE_SUPABASE_ANON_KEY=
```

- [ ] **Step 7: Ensure `.env.local` is gitignored**

Read `ui/.gitignore`. If it does not already ignore local env files, append:
```gitignore
# local env
.env
.env.local
.env.*.local
```
Then create `ui/.env.local` (NOT committed) with the real URL + anon key from Step 3.

- [ ] **Step 8: Verify**

Run from `ui/`: `git check-ignore .env.local` → expected: prints `.env.local` (it is ignored).
Confirm `git status` does NOT list `.env.local`.

- [ ] **Step 9: Commit**

```bash
git add supabase/config.toml supabase/.gitignore supabase/functions/.gitkeep ui/.env.example ui/.gitignore
git commit -m "feat(saas): provision Supabase project + repo scaffolding"
```

---

### Task 2: Core schema migration (enums, tables, indexes)

**Files:**
- Create: `supabase/migrations/0001_init.sql`

**Interfaces:**
- Produces tables `public.profiles`, `public.subscriptions`, `public.feature_flags`, `public.app_settings`, `public.analytics_events`, `public.audit_log`; enums `user_plan`, `user_role`, `user_status`, `subscription_status`. Later tasks reference these exact names/columns.

- [ ] **Step 1: Write `supabase/migrations/0001_init.sql`**

```sql
-- Enums
create type public.user_plan as enum ('free', 'pro');
create type public.user_role as enum ('user', 'admin');
create type public.user_status as enum ('active', 'suspended', 'blocked');
create type public.subscription_status as enum (
  'trialing', 'active', 'past_due', 'canceled',
  'incomplete', 'incomplete_expired', 'unpaid', 'paused'
);

-- profiles: 1:1 with auth.users
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  full_name text,
  avatar_url text,
  plan public.user_plan not null default 'free',
  role public.user_role not null default 'user',
  status public.user_status not null default 'active',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- subscriptions: Stripe mirror (written by webhooks in Phase 2)
create table public.subscriptions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  stripe_customer_id text,
  stripe_subscription_id text unique,
  price_id text,
  status public.subscription_status not null,
  amount_cents integer,
  currency text not null default 'usd',
  current_period_end timestamptz,
  cancel_at_period_end boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index subscriptions_user_id_idx on public.subscriptions(user_id);

-- feature_flags
create table public.feature_flags (
  key text primary key,
  description text,
  enabled boolean not null default false,
  plan_gate public.user_plan,
  updated_at timestamptz not null default now(),
  updated_by uuid references public.profiles(id)
);

-- app_settings
create table public.app_settings (
  key text primary key,
  value jsonb not null default '{}'::jsonb,
  description text,
  updated_at timestamptz not null default now(),
  updated_by uuid references public.profiles(id)
);

-- analytics_events
create table public.analytics_events (
  id bigint generated always as identity primary key,
  session_id text not null,
  path text not null,
  referrer text,
  user_id uuid references public.profiles(id) on delete set null,
  country text,
  user_agent text,
  created_at timestamptz not null default now()
);
create index analytics_events_created_at_idx on public.analytics_events(created_at);
create index analytics_events_session_idx on public.analytics_events(session_id);

-- audit_log
create table public.audit_log (
  id bigint generated always as identity primary key,
  actor_id uuid references public.profiles(id),
  action text not null,
  target text,
  meta jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index audit_log_created_at_idx on public.audit_log(created_at);
```

- [ ] **Step 2: Apply the migration (MCP)**

Call `apply_migration` with `name: "0001_init"` and the file's SQL.
Expected: success, no error.

- [ ] **Step 3: Verify schema (MCP)**

Call `list_tables` (schemas: `["public"]`).
Expected: the six tables present with the columns above. Spot-check `subscriptions` has `amount_cents` + `currency`.

- [ ] **Step 4: Commit**

```bash
git add supabase/migrations/0001_init.sql
git commit -m "feat(saas): core schema (profiles, subscriptions, flags, settings, analytics, audit)"
```

---

### Task 3: Functions & triggers (is_admin, updated_at, new-user, privilege guard)

**Files:**
- Create: `supabase/migrations/0002_functions.sql`

**Interfaces:**
- Consumes: tables/enums from Task 2.
- Produces: `public.is_admin() returns boolean` (used by Task 3's RLS), `public.handle_new_user()` (auto-creates a profile on signup), `public.set_updated_at()`, `public.guard_profile_privileged_columns()`, and their triggers.

- [ ] **Step 1: Write `supabase/migrations/0002_functions.sql`**

```sql
-- Admin check used by RLS policies. SECURITY DEFINER + pinned search_path avoids
-- the recursive-RLS trap of selecting profiles inside a profiles policy.
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = ''
stable
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'admin'
  );
$$;

-- Auto-create a profile row when an auth user is created.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email, full_name, avatar_url)
  values (
    new.id,
    new.email,
    new.raw_user_meta_data ->> 'full_name',
    new.raw_user_meta_data ->> 'avatar_url'
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

-- Generic updated_at maintenance.
create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger set_updated_at_profiles      before update on public.profiles      for each row execute function public.set_updated_at();
create trigger set_updated_at_subscriptions before update on public.subscriptions for each row execute function public.set_updated_at();
create trigger set_updated_at_feature_flags before update on public.feature_flags for each row execute function public.set_updated_at();
create trigger set_updated_at_app_settings  before update on public.app_settings  for each row execute function public.set_updated_at();

-- Privilege-escalation guard: an authenticated NON-admin may not change role/plan/status.
-- The auth.uid() IS NULL carve-out lets service-role/migration contexts (seeding,
-- admin bootstrap, Phase-2 webhooks) set these columns; admins may too.
create or replace function public.guard_profile_privileged_columns()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if (new.role   is distinct from old.role
      or new.plan   is distinct from old.plan
      or new.status is distinct from old.status)
     and auth.uid() is not null
     and not public.is_admin()
  then
    raise exception 'not authorized to change role/plan/status';
  end if;
  return new;
end;
$$;

create trigger guard_profile_privileged_columns
before update on public.profiles
for each row execute function public.guard_profile_privileged_columns();
```

- [ ] **Step 2: Apply the migration (MCP)**

Call `apply_migration` with `name: "0002_functions"`.
Expected: success.

- [ ] **Step 3: Verify functions exist (MCP)**

Call `execute_sql`:
```sql
select proname from pg_proc
where pronamespace = 'public'::regnamespace
  and proname in ('is_admin','handle_new_user','set_updated_at','guard_profile_privileged_columns')
order by proname;
```
Expected 4 rows. (Behavioral verification of `handle_new_user` happens in Task 7 when real auth users are created.)

- [ ] **Step 4: Commit**

```bash
git add supabase/migrations/0002_functions.sql
git commit -m "feat(saas): is_admin + new-user/updated_at/privilege-guard triggers"
```

---

### Task 4: Row-Level Security policies

**Files:**
- Create: `supabase/migrations/0003_rls.sql`

**Interfaces:**
- Consumes: `public.is_admin()` (Task 3), all tables (Task 2).
- Produces: RLS enabled + policies per the spec's access matrix.

- [ ] **Step 1: Write `supabase/migrations/0003_rls.sql`**

```sql
alter table public.profiles         enable row level security;
alter table public.subscriptions    enable row level security;
alter table public.feature_flags    enable row level security;
alter table public.app_settings     enable row level security;
alter table public.analytics_events enable row level security;
alter table public.audit_log        enable row level security;

-- profiles: own row or admin (read/update); admin delete; inserts only via the trigger (no policy).
create policy profiles_select_self_or_admin on public.profiles
  for select to authenticated using (id = auth.uid() or public.is_admin());
create policy profiles_update_self_or_admin on public.profiles
  for update to authenticated using (id = auth.uid() or public.is_admin())
  with check (id = auth.uid() or public.is_admin());
create policy profiles_delete_admin on public.profiles
  for delete to authenticated using (public.is_admin());

-- subscriptions: user reads own; admin reads all; writes are service-role only
-- (service-role bypasses RLS, so no write policy is needed).
create policy subscriptions_select_self_or_admin on public.subscriptions
  for select to authenticated using (user_id = auth.uid() or public.is_admin());

-- feature_flags: authenticated read; admin write.
create policy feature_flags_select_authenticated on public.feature_flags
  for select to authenticated using (true);
create policy feature_flags_write_admin on public.feature_flags
  for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- app_settings: admin only.
create policy app_settings_admin on public.app_settings
  for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- analytics_events: anon/authenticated may INSERT (page-view ingestion); read is admin-only.
create policy analytics_insert_any on public.analytics_events
  for insert to anon, authenticated with check (true);
create policy analytics_select_admin on public.analytics_events
  for select to authenticated using (public.is_admin());
create policy analytics_delete_admin on public.analytics_events
  for delete to authenticated using (public.is_admin());

-- audit_log: admin read + admin insert.
create policy audit_select_admin on public.audit_log
  for select to authenticated using (public.is_admin());
create policy audit_insert_admin on public.audit_log
  for insert to authenticated with check (public.is_admin());
```

- [ ] **Step 2: Apply the migration (MCP)**

Call `apply_migration` with `name: "0003_rls"`.
Expected: success.

- [ ] **Step 3: Verify RLS enabled + policy count (MCP)**

Call `execute_sql`:
```sql
select relname, relrowsecurity
from pg_class
where relnamespace = 'public'::regnamespace
  and relname in ('profiles','subscriptions','feature_flags','app_settings','analytics_events','audit_log')
order by relname;
```
Expected: `relrowsecurity = true` for all six. (Behavioral checks in Task 8.)

- [ ] **Step 4: Run the security advisor (MCP)**

Call `get_advisors` with `type: "security"`.
Expected: no ERROR-level findings about these tables (e.g. "RLS disabled"). Triage/justify any warnings.

- [ ] **Step 5: Commit**

```bash
git add supabase/migrations/0003_rls.sql
git commit -m "feat(saas): RLS policies for all tables"
```

---

### Task 5: Admin dashboard rollup view

**Files:**
- Create: `supabase/migrations/0004_views.sql`

**Interfaces:**
- Consumes: tables from Task 2; RLS from Task 4.
- Produces: `public.admin_dashboard_stats` (single-row view) read by Phase 4. Columns: `total_users, paid_users, free_users, active_today, mrr_cents, signups_7d`.

- [ ] **Step 1: Write `supabase/migrations/0004_views.sql`**

```sql
-- security_invoker => the caller's RLS applies to the underlying tables, so this
-- view returns correct totals only for admins (who can read all rows). Phase 4
-- calls it from an admin context only.
create view public.admin_dashboard_stats
with (security_invoker = true) as
select
  (select count(*) from public.profiles)                              as total_users,
  (select count(*) from public.profiles where plan = 'pro')           as paid_users,
  (select count(*) from public.profiles where plan = 'free')          as free_users,
  (select count(distinct session_id) from public.analytics_events
     where created_at >= now() - interval '24 hours')                 as active_today,
  (select coalesce(sum(amount_cents), 0) from public.subscriptions
     where status = 'active')                                         as mrr_cents,
  (select count(*) from public.profiles
     where created_at >= now() - interval '7 days')                   as signups_7d;
```

- [ ] **Step 2: Apply the migration (MCP)**

Call `apply_migration` with `name: "0004_views"`.
Expected: success.

- [ ] **Step 3: Verify the view queries (MCP)**

Call `execute_sql`: `select * from public.admin_dashboard_stats;`
Expected: one row, all zeros (no data yet). No error.

- [ ] **Step 4: Commit**

```bash
git add supabase/migrations/0004_views.sql
git commit -m "feat(saas): admin_dashboard_stats rollup view"
```

---

### Task 6: Typed Supabase browser client + env typing + unit test

**Files:**
- Create: `ui/src/lib/supabase/client.ts`
- Create: `ui/src/lib/supabase/index.ts`
- Create: `ui/src/lib/supabase/types.ts` (generated)
- Create: `ui/src/lib/supabase/client.test.ts`
- Modify: `ui/src/vite-env.d.ts` (augment `ImportMetaEnv`)
- Modify: `ui/package.json` (+`@supabase/supabase-js`)

**Interfaces:**
- Consumes: schema (Tasks 2–5) for generated types.
- Produces: `supabase: SupabaseClient<Database> | null`, `supabaseConfigured: boolean`, and the `Database` type — the import surface every later UI phase uses.

- [ ] **Step 1: Add the dependency**

Run from `ui/`: `npm install @supabase/supabase-js@^2`
Expected: `package.json` + `package-lock.json` updated.

- [ ] **Step 2: Generate DB types (MCP) → `ui/src/lib/supabase/types.ts`**

Call `generate_typescript_types` for the project; write the returned TypeScript to `ui/src/lib/supabase/types.ts`. It must export a `Database` type. Do not hand-edit (regenerate when the schema changes).

- [ ] **Step 3: Augment `ui/src/vite-env.d.ts`**

Append (keep the existing `/// <reference types="vite/client" />`):
```ts
interface ImportMetaEnv {
  readonly VITE_SUPABASE_URL?: string;
  readonly VITE_SUPABASE_ANON_KEY?: string;
}
interface ImportMeta {
  readonly env: ImportMetaEnv;
}
```

- [ ] **Step 4: Write the failing test `ui/src/lib/supabase/client.test.ts`**

```ts
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

describe("supabase client", () => {
  beforeEach(() => vi.resetModules());
  afterEach(() => vi.unstubAllEnvs());

  it("is unconfigured when env vars are missing", async () => {
    vi.stubEnv("VITE_SUPABASE_URL", "");
    vi.stubEnv("VITE_SUPABASE_ANON_KEY", "");
    const mod = await import("./client");
    expect(mod.supabaseConfigured).toBe(false);
    expect(mod.supabase).toBeNull();
  });

  it("creates a client when env vars are present", async () => {
    vi.stubEnv("VITE_SUPABASE_URL", "https://demo.supabase.co");
    vi.stubEnv("VITE_SUPABASE_ANON_KEY", "anon-key");
    const mod = await import("./client");
    expect(mod.supabaseConfigured).toBe(true);
    expect(mod.supabase).not.toBeNull();
  });
});
```

- [ ] **Step 5: Run test to verify it fails**

Run from `ui/`: `npx vitest run src/lib/supabase/client.test.ts`
Expected: FAIL — `Cannot find module './client'`.

- [ ] **Step 6: Write `ui/src/lib/supabase/client.ts`**

```ts
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "./types";

const url = import.meta.env.VITE_SUPABASE_URL;
const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

/** True when both public Supabase env vars are present; the SPA is inert otherwise. */
export const supabaseConfigured: boolean = Boolean(url && anonKey);

/** Shared browser client (anon key, under the logged-in user's JWT). null when unconfigured. */
export const supabase: SupabaseClient<Database> | null = supabaseConfigured
  ? createClient<Database>(url as string, anonKey as string, {
      auth: { persistSession: true, autoRefreshToken: true },
    })
  : null;
```

- [ ] **Step 7: Write `ui/src/lib/supabase/index.ts`**

```ts
export { supabase, supabaseConfigured } from "./client";
export type { Database } from "./types";
```

- [ ] **Step 8: Run test to verify it passes**

Run from `ui/`: `npx vitest run src/lib/supabase/client.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 9: Verify typecheck + build + full coverage**

Run from `ui/`:
- `npm run typecheck` → expected: no errors.
- `npm run build` → expected: tsc + vite succeed.
- `npm run test:coverage` → expected: all tests pass, coverage ≥ 80/70.

- [ ] **Step 10: Commit**

```bash
git add ui/src/lib/supabase ui/src/vite-env.d.ts ui/package.json ui/package-lock.json
git commit -m "feat(saas): typed Supabase browser client + env typing + tests"
```

---

### Task 7: Seed data + admin bootstrap

**Files:**
- Create: `supabase/seed.sql` (feature flags, app settings, anonymous analytics)
- Create: `supabase/seed.mjs` (demo auth users → profiles → subscriptions, via service-role)
- Create: `supabase/migrations/0005_bootstrap_admin.sql`
- Modify: `supabase/README.md` (new) documenting how to run the seed

**Interfaces:**
- Consumes: all prior tasks (tables, triggers, the new-user trigger, the privilege-guard carve-out).
- Produces: demo data so Phase 4's `admin_dashboard_stats` is non-zero; an idempotent admin-bootstrap migration.

- [ ] **Step 1: Write `supabase/seed.sql`**

```sql
insert into public.feature_flags (key, description, enabled, plan_gate) values
  ('ai_assist',          'AI analyst assistant',        true, null),
  ('reputation',         'IP/domain reputation lookups',true, null),
  ('pcap_export',        'PCAP carving/export',         true, 'pro'),
  ('multi_capture_diff', 'Compare two captures',        true, 'pro')
on conflict (key) do nothing;

insert into public.app_settings (key, value, description) values
  ('branding', '{"product_name":"PacketPilot"}'::jsonb, 'Product branding'),
  ('limits',   '{"max_upload_mb":64}'::jsonb,           'Client upload limits (informational)')
on conflict (key) do nothing;

-- Anonymous demo traffic so the dashboard's "active today" + traffic chart render.
insert into public.analytics_events (session_id, path, referrer, country, user_agent, created_at)
select
  'demo-' || g,
  (array['/','/app','/app/flows','/app/findings'])[1 + (g % 4)],
  null,
  (array['US','DE','GB','IN'])[1 + (g % 4)],
  'seed',
  now() - ((g % 48) || ' hours')::interval
from generate_series(1, 200) as g;
```

- [ ] **Step 2: Apply `seed.sql` (MCP)**

Call `execute_sql` with the contents of `supabase/seed.sql`.
Expected: success; `select count(*) from public.analytics_events;` → 200; `select count(*) from public.feature_flags;` → 4.

- [ ] **Step 3: Write `supabase/seed.mjs`**

```js
// Demo users for the admin dashboard. Run locally with service-role creds:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... node supabase/seed.mjs
// Idempotent: re-running skips users that already exist. Service-role bypasses RLS.
import { createClient } from "@supabase/supabase-js";
import { randomUUID } from "node:crypto";

const url = process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
if (!url || !serviceKey) {
  console.error("Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in your shell env.");
  process.exit(1);
}
const admin = createClient(url, serviceKey, { auth: { persistSession: false } });

const DEMO = [
  { email: "demo+alice@packetpilot.test",   name: "Alice Smith",    plan: "pro"  },
  { email: "demo+bob@packetpilot.test",     name: "Bob Johnson",    plan: "free" },
  { email: "demo+carol@packetpilot.test",   name: "Carol Williams", plan: "pro"  },
  { email: "demo+dave@packetpilot.test",    name: "Dave Brown",     plan: "free" },
  { email: "demo+erin@packetpilot.test",    name: "Erin Davis",     plan: "pro"  },
];

const { data: existing } = await admin.auth.admin.listUsers({ perPage: 1000 });
const byEmail = new Map((existing?.users ?? []).map((u) => [u.email, u.id]));

for (const u of DEMO) {
  let id = byEmail.get(u.email);
  if (!id) {
    const { data, error } = await admin.auth.admin.createUser({
      email: u.email,
      email_confirm: true,
      password: randomUUID(),
      user_metadata: { full_name: u.name },
    });
    if (error) { console.error(u.email, error.message); continue; }
    id = data.user.id; // the on-insert trigger created the profile
  }
  await admin.from("profiles").update({ plan: u.plan, full_name: u.name }).eq("id", id);
  if (u.plan === "pro") {
    await admin.from("subscriptions").upsert(
      {
        user_id: id,
        status: "active",
        amount_cents: 1900,
        currency: "usd",
        stripe_customer_id: "cus_demo_" + id.slice(0, 8),
        stripe_subscription_id: "sub_demo_" + id.slice(0, 8),
        price_id: "price_demo_pro",
        current_period_end: new Date(Date.now() + 30 * 864e5).toISOString(),
      },
      { onConflict: "stripe_subscription_id" },
    );
  }
}
console.log("Seed complete.");
```

- [ ] **Step 4: Run the demo-user seed (local shell)**

From the repo root, with the operator's service-role key (from Supabase project settings, NEVER committed):
```bash
SUPABASE_URL="<project url>" SUPABASE_SERVICE_ROLE_KEY="<service role key>" node supabase/seed.mjs
```
Expected: `Seed complete.`

- [ ] **Step 5: Verify seed + trigger behavior (MCP)**

Call `execute_sql`:
```sql
select count(*) as profiles from public.profiles;          -- expect 5
select count(*) as pro from public.profiles where plan='pro'; -- expect 3
select * from public.admin_dashboard_stats;                -- total_users=5, paid_users=3, mrr_cents=5700, active_today>0
```
The non-zero `profiles` count confirms `handle_new_user` fired on user creation.

- [ ] **Step 6: Write `supabase/migrations/0005_bootstrap_admin.sql`**

```sql
-- Promote the operator's account to admin. Idempotent; a no-op until that account
-- signs up (Phase 1/3). Runs in a migration/service context (auth.uid() is null),
-- so the privilege guard's carve-out permits the role change.
-- Replace the email with the confirmed admin email at execution time.
update public.profiles
set role = 'admin'
where email = 'ravi.dholariya@icloud.com';
```

- [ ] **Step 7: Apply the bootstrap migration (MCP)**

Call `apply_migration` with `name: "0005_bootstrap_admin"`.
Expected: success (0 rows updated now — the admin account doesn't exist yet; that's fine).

- [ ] **Step 8: Write `supabase/README.md`**

```markdown
# PacketPilot Supabase backend

Cloud project `packetpilot` is the source of truth. Migrations in `migrations/`
are applied in numeric order (via the Supabase MCP or `supabase db push`).

## Seeding demo data
1. `execute_sql` (or psql) the contents of `seed.sql` (flags/settings/analytics).
2. Run the demo-user seed with service-role creds (never commit them):
   `SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... node seed.mjs`

## Admin
`0005_bootstrap_admin.sql` promotes the configured email to `role='admin'` once
that account exists. Confirm the email before applying.

## Secrets
Only `VITE_SUPABASE_URL` + `VITE_SUPABASE_ANON_KEY` (public) belong in the app.
Service-role and Stripe keys live only in Edge Function secrets (Phase 2+).
```

- [ ] **Step 9: Commit**

```bash
git add supabase/seed.sql supabase/seed.mjs supabase/migrations/0005_bootstrap_admin.sql supabase/README.md
git commit -m "feat(saas): seed demo data + idempotent admin bootstrap"
```

---

### Task 8: RLS behavioral verification + advisors (definition of done)

**Files:**
- Create: `supabase/tests/rls_checks.sql` (documents the verification queries)

**Interfaces:**
- Consumes: seeded data (Task 7), RLS (Task 4).
- Produces: documented, passing RLS simulations — the security definition of done.

- [ ] **Step 1: Capture two seeded UUIDs (MCP)**

Call `execute_sql`:
```sql
select id, email, role from public.profiles order by email;
```
Pick a non-admin id (e.g. `demo+bob@…`). For the admin path, temporarily promote one demo user for the test (revert after), since the real admin account doesn't exist yet:
```sql
update public.profiles set role='admin' where email='demo+alice@packetpilot.test';
```

- [ ] **Step 2: Write `supabase/tests/rls_checks.sql`**

```sql
-- Replace <NON_ADMIN_UUID> / <ADMIN_UUID> with seeded profile ids before running.
-- Each block assumes a role + JWT claims, then asserts visibility, and rolls back.

-- (a) Non-admin: sees only own profile, no analytics.
begin;
  set local role authenticated;
  set local "request.jwt.claims" = '{"sub":"<NON_ADMIN_UUID>","role":"authenticated"}';
  select 'non_admin_profiles' as check, count(*) from public.profiles;          -- expect 1
  select 'non_admin_analytics' as check, count(*) from public.analytics_events; -- expect 0
  select 'non_admin_settings' as check, count(*) from public.app_settings;      -- expect 0
rollback;

-- (b) Admin: sees all profiles + analytics.
begin;
  set local role authenticated;
  set local "request.jwt.claims" = '{"sub":"<ADMIN_UUID>","role":"authenticated"}';
  select 'admin_profiles' as check, count(*) from public.profiles;          -- expect 5
  select 'admin_analytics' as check, count(*) from public.analytics_events; -- expect 200
rollback;

-- (c) Anon: blocked from reading profiles.
begin;
  set local role anon;
  select 'anon_profiles' as check, count(*) from public.profiles; -- expect 0
rollback;

-- (d) Anon: CAN insert an analytics event (ingestion path).
begin;
  set local role anon;
  insert into public.analytics_events (session_id, path) values ('rls-test', '/'); -- expect success
rollback;

-- (e) Privilege escalation blocked: non-admin cannot self-promote.
begin;
  set local role authenticated;
  set local "request.jwt.claims" = '{"sub":"<NON_ADMIN_UUID>","role":"authenticated"}';
  update public.profiles set role='admin' where id = '<NON_ADMIN_UUID>'; -- expect ERROR
rollback;
```

- [ ] **Step 3: Run each block (MCP) and confirm expectations**

`execute_sql` blocks (a)–(d) and confirm the counts/success above. For (e), run it and confirm it raises `not authorized to change role/plan/status` (an error here is the PASS condition).

- [ ] **Step 4: Revert the temporary admin promotion (MCP)**

```sql
update public.profiles set role='user' where email='demo+alice@packetpilot.test';
```

- [ ] **Step 5: Final advisors (MCP)**

Call `get_advisors` `type: "security"` and `type: "performance"`.
Expected: no ERROR-level findings. Note/justify any remaining warnings in the commit message.

- [ ] **Step 6: Commit**

```bash
git add supabase/tests/rls_checks.sql
git commit -m "test(saas): RLS behavioral verification queries"
```

---

## Self-Review

**1. Spec coverage:**
- Provisioning + env wiring → Task 1. ✅
- Repo structure (`supabase/`, `ui/src/lib/supabase/`) → Tasks 1, 6. ✅
- Data model (6 tables + enums, incl. `amount_cents`/`currency`) → Task 2. ✅
- Auth/roles (is_admin, profile trigger, bootstrap) → Tasks 3, 7. ✅
- Privilege-escalation guard (with `auth.uid() is null` carve-out) → Task 3; verified Task 8(e). ✅
- RLS matrix (all six tables) → Task 4; verified Task 8. ✅
- `admin_dashboard_stats` view (security_invoker, MRR from amount_cents) → Task 5. ✅
- Migration/types workflow (committed SQL, generated `types.ts`) → Tasks 2–6. ✅
- Typed client with `supabaseConfigured` no-throw fallback → Task 6. ✅
- Seed data for the dashboard → Task 7. ✅
- DoD (migrations apply, RLS sims pass, advisors clean, build+coverage green) → Tasks 6, 8. ✅
- Phase 9 env-vars note → design-only, no Phase-0 task needed (schema `app_settings` exists). ✅

**2. Placeholder scan:** The only intentional fill-ins are real execution-time values — the project ref in `config.toml` (Step 1.4), the admin email in `0005` (confirmed default given), and the UUIDs in `rls_checks.sql` (captured in Step 8.1). `types.ts` is a generated artifact (command given), not a placeholder. No "TBD/handle edge cases/similar to Task N".

**3. Type consistency:** `supabase`/`supabaseConfigured`/`Database` names are consistent across `client.ts`, `index.ts`, and the test. SQL identifiers (`is_admin`, `handle_new_user`, `guard_profile_privileged_columns`, `set_updated_at`, `admin_dashboard_stats`, column names) are consistent across migrations, seed, and checks. `amount_cents` used in schema (Task 2), view (Task 5), and seed (Task 7).

## Execution Handoff

(See message.)
