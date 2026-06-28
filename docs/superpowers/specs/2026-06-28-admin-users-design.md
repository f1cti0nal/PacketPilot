# PacketPilot SaaS — Admin Users Management (Phase 5) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-28
**Branch:** `feat/admin-users`
**Sub-project:** 5 of the PacketPilot SaaS platform (depends on Phase 0 + Phase 3)

## Context

Phase 5 of the SaaS pivot. Phases 0 (backend), 1 (accounts), 2 (billing), 3 (admin shell), 4 (admin dashboard) are merged + deployed. The `/admin` **Users** section is currently a "coming soon" placeholder; this phase makes it a real management table.

Decisions locked with the user:
- **Actions: plan + status + role.** Change plan (free/pro), status (active/suspended/blocked), and role (user/admin), with self-protection (an admin can't demote their own role).
- **Audit: a server-side trigger** records every role/plan/status change to `audit_log`.

**Security note (no new write path):** the Phase-0 `profiles` RLS update policy is `self-or-admin`, and the privilege-escalation guard (`guard_profile_privileged_columns`) blocks changes to role/plan/status only when `auth.uid() is not null AND not is_admin()`. So an **admin** editing any user's privileged columns is permitted; a non-admin is blocked. Mutations are therefore secure **RLS-gated client writes** — no Edge Function needed.

## Goal

Let an admin search the user base and change any user's plan, role, or status from the `/admin` Users table, with their own admin role protected from self-demotion, and every change recorded in `audit_log`.

## Invariants preserved

- **Privacy / engine untouched.** No change to `/app`, the WASM path, or capture handling. This is admin-only UI + one audit trigger.
- **Security boundary stays server-side.** Mutations are gated by the existing RLS + guard; the audit trigger is `SECURITY DEFINER` and tamper-proof. Non-admins can neither read others' profiles nor change privileged columns.
- **No new SPA deps.** Reuses the Phase-0 `supabase` client, `cockpit/primitives`, the `.pp-table` styling, and severity tokens.

## Architecture

```
supabase/migrations/0009_audit_profile_changes.sql   # SECURITY DEFINER trigger → audit_log
ui/src/admin/users/
  useAdminUsers.ts     # list hook (search) + setPlan/setRole/setStatus mutators
  UsersView.tsx        # search box + .pp-table with per-row plan/role/status selects
ui/src/admin/AdminShell.tsx   # route active==="users" → <UsersView adminEmail={email} />
```

(Next migration number is `0009` — `0008_dashboard_rpcs` is the latest applied.)

**Tech stack:** React 18 + TS, the Phase-0 Supabase client, Tailwind + `index.css` tokens (`.pp-table`, severity colors), `cockpit/primitives`. Vitest + RTL. Supabase MCP for the migration.

## Backend — `0009_audit_profile_changes.sql`

```sql
-- Record admin edits to a user's privileged columns. SECURITY DEFINER so it always
-- writes regardless of the actor's RLS; search_path pinned. actor_id is auth.uid()
-- (the admin), or null for service-role/migration changes.
create or replace function public.audit_profile_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  changes jsonb := '{}'::jsonb;
begin
  if new.role is distinct from old.role then
    changes := changes || jsonb_build_object('role', jsonb_build_object('old', old.role::text, 'new', new.role::text));
  end if;
  if new.plan is distinct from old.plan then
    changes := changes || jsonb_build_object('plan', jsonb_build_object('old', old.plan::text, 'new', new.plan::text));
  end if;
  if new.status is distinct from old.status then
    changes := changes || jsonb_build_object('status', jsonb_build_object('old', old.status::text, 'new', new.status::text));
  end if;
  if changes <> '{}'::jsonb then
    insert into public.audit_log (actor_id, action, target, meta)
    values (auth.uid(), 'profile.update', new.id::text, changes);
  end if;
  return new;
end;
$$;

create trigger audit_profile_change
after update on public.profiles
for each row execute function public.audit_profile_change();
```

## Data layer — `useAdminUsers.ts`

```ts
export interface AdminUser {
  id: string; email: string; full_name: string | null;
  plan: string; role: string; status: string; created_at: string;
}
export type AdminUsersState =
  | { status: "loading" } | { status: "error"; error: string }
  | { status: "ready"; users: AdminUser[] };

export function useAdminUsers(search: string): { state: AdminUsersState; reload: () => void };
export function setPlan(id: string, plan: string): Promise<{ ok: boolean; error?: string }>;
export function setRole(id: string, role: string): Promise<{ ok: boolean; error?: string }>;
export function setStatus(id: string, status: string): Promise<{ ok: boolean; error?: string }>;
```
The hook fetches `profiles.select("id,email,full_name,plan,role,status,created_at")`, applies `.ilike("email", \`%${search}%\`)` when `search` is non-empty, `.order("created_at", { ascending: false }).limit(100)`. It re-runs on `search` change and on `reload()` (a bump-counter). `!supabaseConfigured` → `error`. The mutators call `supabase.from("profiles").update(patch).eq("id", id)` and return `{ ok, error? }` from the result's `error`.

## UI — `UsersView.tsx`

Props: `{ adminEmail: string }`. Holds `search` state (controlled input, filters as you type) and a row-level `error` line. Renders:
- A search input ("Search by email…").
- `loading` → `LoadingState`; `error` → `ErrorState`; `ready` with 0 → "No users match."; else a `.pp-table`:
  - **Name** (full_name or email local-part), **Email**, **Plan** (`<select>` free/pro), **Role** (`<select>` user/admin), **Status** (`<select>` active/suspended/blocked colored via severity tokens), **Joined** (`created_at` date).
  - Each `<select>` `onChange` → the matching mutator → on `ok` `reload()`, on failure set the inline error.
  - **Self-protection:** when `row.email === adminEmail`, the **Role** select is `disabled` (prevents self-demotion/lockout; the admin gate is role-based). Plan/Status remain editable on self (not lockout-causing).
- A small `role="alert"` error line above/below the table on a failed mutation.

Helpers (date formatting) reuse the dashboard's `joinedDate` (or an inline `slice(0,10)`).

## Wiring — `AdminShell.tsx`

```tsx
{active === "dashboard" ? (
  <AdminDashboard />
) : active === "users" ? (
  <UsersView adminEmail={email} />
) : (
  <Placeholder title={title} phase={section?.phase ?? 0} />
)}
```
The Users nav item already exists in `sections.ts`. `email` is already a prop of `AdminShell`.

## Data flow & error handling

Admin opens Users → `useAdminUsers("")` lists all (newest first, ≤100). Typing filters by email. Changing a select → mutator → RLS/guard permit it (admin) → DB update → the trigger logs to `audit_log` → `reload()` refreshes the row. A blocked/failed update surfaces inline (e.g., a non-admin would get an RLS error, but only admins reach this view). Self-row role select disabled so an admin can't strand themselves. No throws cross the view boundary (admin `ErrorBoundary` remains the backstop).

## Testing

- **`useAdminUsers`** (mock `../lib/supabase`): `ready` with users; search applies `.ilike` on email; `reload` re-fetches; unconfigured → error. `setPlan`/`setRole`/`setStatus` call `update(...).eq("id", …)` with the right patch and return `{ ok }` / `{ ok:false, error }`.
- **`UsersView`**: renders a row per user (assert with `within(table)`); changing the Plan select calls `setPlan` then reloads; the self-row (`adminEmail` match) Role select is `disabled`; empty + error states; a failed mutation shows the alert.
- **`AdminShell.test`** (updated): mock `./users/UsersView` to a stub (mirroring the existing `./dashboard/AdminDashboard` mock) so the shell test stays data-free; the "switches content … Users" test now asserts the stub marker (not the old "coming in phase 5" placeholder copy) + `hash === "#users"`. Other shell tests unchanged.
- **Live (MCP):** apply `0009`; update a demo user's plan via `execute_sql` and confirm an `audit_log` row appears with the old→new meta; `get_advisors` security shows no new ERROR.
- Gate: full UI suite green, coverage ≥ 80/70, `npx tsc -b` clean, `npm run build` passes.
- **Browser smoke:** sign in as admin → `/admin` → Users → the table lists all accounts (incl. Bob = pro); change a demo user's plan/role/status → reflected on reload; verify the `audit_log` rows via `execute_sql`.

## Out of scope (later)

Bulk actions; a user-detail drawer; pagination beyond the 100 cap (search narrows instead); an audit-log *viewer* UI (data is captured; surfacing it is a later add); inviting/creating/deleting users; per-action confirmation modals (selects are the affordance); the Payments admin view (Phase 6).

## File manifest

**Create:** `supabase/migrations/0009_audit_profile_changes.sql`, `ui/src/admin/users/useAdminUsers.ts` (+ test), `ui/src/admin/users/UsersView.tsx` (+ test).
**Modify:** `ui/src/admin/AdminShell.tsx` (route `users` → `UsersView`), `ui/src/admin/AdminShell.test.tsx` (mock `./users/UsersView` stub + update the Users-switch assertion).
**No engine/WASM/Tauri change. No `/app` change. No new SPA deps.**
