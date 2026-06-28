# PacketPilot Supabase backend

Cloud project `packetpilot` (ref `brkztcfhmrjjnbjzycie`, us-east-1) is the source of
truth. Migrations in `migrations/` are applied in numeric order (via the Supabase
MCP `apply_migration` or `supabase db push`). A fresh replay of the committed
migrations reproduces the live schema, RLS, functions, and the dashboard view.

## Migrations (apply order)
- `0001_init` — enums + tables (profiles, subscriptions, feature_flags, app_settings, analytics_events, audit_log) + indexes.
- `0002_functions` — `is_admin()`, `handle_new_user()` (+ auth.users trigger), `set_updated_at()` (+ triggers), `guard_profile_privileged_columns()` (+ trigger).
- `0003_rls` — RLS enabled on every table + access policies.
- `0004_harden_functions` + `0004b_harden_functions_public` — revoke direct EXECUTE on the trigger functions from public/anon/authenticated; pin `set_updated_at` search_path.
- `0005_views` — `admin_dashboard_stats` rollup view (`security_invoker`).
- `0006_bootstrap_admin` — promote the operator's account to `role='admin'` (no-op until that account exists).

## Seeding demo data
`seed.sql` is SQL-only and needs no service-role key. Apply it via the Supabase MCP
`execute_sql`, `supabase db reset` (runs it automatically), or psql. It creates demo
`auth.users` (the trigger creates their profiles), sets plans + subscriptions, and
seeds feature flags, app settings, and anonymous analytics so the admin dashboard
renders realistic numbers. It is idempotent and **non-production** (demo logins share
one password).

## Admin
`0006_bootstrap_admin.sql` promotes the configured email to `role='admin'`. Because a
migration runs once, if the admin account is created later, re-run the same `update`
via `execute_sql` (or promote from the admin Users view once it exists).

## Secrets
Only `VITE_SUPABASE_URL` + `VITE_SUPABASE_ANON_KEY` (public) belong in the app
(`ui/.env.local`, untracked; documented in `ui/.env.example`). The service-role key
and Stripe keys live only in Edge Function secrets (added in the billing phase) —
never in the repo or the SPA bundle.
