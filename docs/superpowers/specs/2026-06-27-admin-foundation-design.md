# PacketPilot SaaS — Admin Foundation (Phase 3) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-27
**Branch:** `feat/admin-foundation`
**Sub-project:** 3 of the PacketPilot SaaS platform (depends on Phase 0)

## Context

Sub-project 3 of the SaaS platform (see `2026-06-27-saas-backend-foundation-design.md` for the roadmap). Phase 0 (Supabase backend: schema, RLS, auth scaffolding, typed client) is merged. Build order is **admin-visible-early** — this phase delivers the non-public admin **shell + login + role gate**; Phase 4 fills the real dashboard, 5–9 the other sections.

Decisions locked with the user:
- **Non-public `/admin`** route, role-gated; the real boundary is server-side RLS (Phase 0).
- **Admin login** = Supabase Auth email/password → gate on `profiles.role = 'admin'`.
- **First admin** = `ravi.dholariya@icloud.com`, created with a temporary password (shared privately) + `role='admin'`.
- **Look** = reuse PacketPilot's existing design system (tokens, `cockpit/primitives`, theme + density) with the reference images' **left-sidebar + top-bar** layout.
- **Shell scope** = full nav now; Dashboard route renders (placeholder), the other six sections render an on-brand "Coming soon" placeholder.

## Goal

Stand up a non-public, role-gated admin area at `/admin` with a working admin login and the sidebar/top-bar shell, on PacketPilot's design system — navigable end-to-end, with real section content deferred to later phases.

## Invariants preserved

- **Packet-analysis privacy invariant** untouched: no change to `/app`, the WASM engine, or the analysis path.
- **Admin code is isolated**: `AdminApp` is `React.lazy`-loaded so admin code is a separate chunk, not bundled into the public landing/`/app` entry.
- **Security is server-side**: RLS already restricts admin-only tables to admins. The route/UI gate is defense-in-UX, not the boundary.

## Architecture

```
ui/src/main.tsx            # add /admin branch → lazy <AdminApp/>
ui/src/admin/
  AdminApp.tsx             # session gate: loading → AdminLogin (anon/forbidden) → AdminShell (admin)
  useAdminSession.ts       # hook over the Phase-0 supabase client; resolves loading|anon|forbidden|admin
  AdminLogin.tsx           # email/password form (+ forbidden + not-configured states)
  AdminShell.tsx           # left sidebar + top bar + content; in-app section state
  Sidebar.tsx              # brand + nav items + collapse
  AdminTopBar.tsx          # section title + profile menu (email, sign out) + Theme/Density toggles
  sections.ts              # nav config: { id, label, icon } for the 7 sections
  views/
    AdminDashboard.tsx     # Phase-3 placeholder (Phase 4 fills real KPIs)
    Placeholder.tsx        # shared "Coming soon — Phase N" panel
vercel.json                # add /admin rewrites
```

**Tech stack:** React 18 + Vite + TS, `@supabase/supabase-js` (Phase 0 client), `lucide-react` (icons, already a dep), Tailwind + the existing `--color-*` tokens / `.t-*` utilities / `cockpit/primitives` (`Card`, `StatTile`, `SectionHeader`, `Tag`). Vitest + RTL for tests. No new deps.

## Routing & entry (`main.tsx`, `vercel.json`)

`main.tsx` currently branches `/` → `Landing`, `/app` → `App`. Add:
```ts
const isAdmin = path === "/admin" || path.startsWith("/admin/");
```
Render order: `isAdmin ? <Suspense fallback={<LoadingState/>}><AdminApp/></Suspense> : isApp ? <App/> : <Landing/>`. `AdminApp` is `const AdminApp = React.lazy(() => import("./admin/AdminApp"))`. The `ErrorBoundary` wraps all branches as today.

`vercel.json` rewrites gain (mirroring `/app`):
```json
{ "source": "/admin", "destination": "/" },
{ "source": "/admin/(.*)", "destination": "/" }
```

## Auth & gate

`useAdminSession()` returns:
```ts
type AdminSession =
  | { status: "loading" }
  | { status: "unconfigured" }                          // supabaseConfigured === false
  | { status: "anon"; signIn; error? }                  // no session
  | { status: "forbidden"; email: string; signOut }     // signed in, role !== 'admin'
  | { status: "admin"; email: string; profile; signOut };
```
Behavior: if `!supabaseConfigured` → `unconfigured`. Else `supabase.auth.getSession()`; with a session, `supabase.from("profiles").select("email,role,full_name").eq("id", uid).single()` → `admin` when `role==='admin'`, else `forbidden`; no session → `anon`. Subscribe via `supabase.auth.onAuthStateChange` and re-derive; unsubscribe on unmount. `signIn(email,password)` calls `supabase.auth.signInWithPassword`; `signOut()` calls `supabase.auth.signOut()`.

`AdminApp` switches on status: `loading` → `LoadingState`; `unconfigured`/`anon`/`forbidden` → `AdminLogin` (forbidden variant shows "This account is not an administrator." + Sign out; unconfigured shows a config notice); `admin` → `AdminShell`.

## The shell (`AdminShell`)

Reuses tokens + primitives; mirrors `AppShell`'s structure but sidebar-nav instead of top-tabs.
- **Sidebar** (`Sidebar.tsx`): brand wordmark; nav buttons from `sections.ts` (active styling via `--color-accent`/`--color-surface-2`); collapsible (icon-only) on a toggle and below a width breakpoint.
- **Top bar** (`AdminTopBar.tsx`): active section title; right side = `ThemeToggle` + `DensityToggle` + a profile menu (admin email + "Sign out").
- **Content:** active section held in `useState` (mirrors `App`'s `tab`), **initialized from and synced to `location.hash`** (e.g. `#users`) so refresh/deep-link preserves the section; an unknown/empty hash falls back to `dashboard`. `Dashboard` → `AdminDashboard` (placeholder); the rest → `Placeholder` with the section name + "coming in Phase N".
- **Responsive:** sidebar collapses to icons under the breakpoint. Full mobile drawer is deferred (YAGNI for Phase 3).

`sections.ts`:
```ts
export const ADMIN_SECTIONS = [
  { id: "dashboard", label: "Dashboard",     icon: LayoutDashboard, phase: 4 },
  { id: "users",     label: "Users",         icon: Users,           phase: 5 },
  { id: "payments",  label: "Payments",      icon: CreditCard,      phase: 6 },
  { id: "traffic",   label: "Live Traffic",  icon: Activity,        phase: 7 },
  { id: "features",  label: "App Features",  icon: ToggleRight,     phase: 8 },
  { id: "settings",  label: "Settings",      icon: Settings,        phase: 9 },
  { id: "env",       label: "Environment",   icon: KeyRound,        phase: 9 },
] as const;
export type AdminSectionId = (typeof ADMIN_SECTIONS)[number]["id"];
```

## Data flow & error handling

Login submit → `signInWithPassword` → on success the auth-change subscription re-derives the session (role re-checked). Sign-in errors surface inline in `AdminLogin`. A signed-in non-admin lands on `forbidden` (RLS already denies them admin data even if they reached the shell). Network/role-query failure → treat as `forbidden` with a retry/sign-out affordance (never silently grant admin). `unconfigured` keeps the area inert with a clear notice. No throws cross the `AdminApp` boundary (wrapped by `ErrorBoundary`).

## First admin establishment (implementation step, not a migration)

At execution, create the auth user for `ravi.dholariya@icloud.com` via `execute_sql` (same `auth.users` insert pattern as `seed.sql`) with a strong **temporary** password, then `update profiles set role='admin'`. The temp password is shared privately with the user; password-reset UX arrives in Phase 1. Deployed `/admin` additionally requires the Vercel env vars (`VITE_SUPABASE_URL`/`VITE_SUPABASE_ANON_KEY`) to be set; until then it shows the `unconfigured` notice.

## Testing

- **`useAdminSession`** (supabase mocked): `unconfigured` when `supabaseConfigured` false; `anon` with no session; `admin` with session + `role:'admin'`; `forbidden` with session + `role:'user'`; re-derivation on `onAuthStateChange`.
- **`AdminLogin`**: submit calls `signInWithPassword` with the entered creds; an error message renders; forbidden variant shows the not-admin copy + sign-out; unconfigured variant shows the notice.
- **`AdminShell`**: renders all 7 nav items; clicking a section switches content; Dashboard shows the placeholder; sign-out calls `signOut`; Theme/Density toggles present.
- **`AdminApp`** (gate): renders `AdminLogin` for anon/forbidden, `AdminShell` for admin, `LoadingState` for loading.
- Coverage gate ≥ 80/70; `npm run build` + full suite green. Mock `ui/src/lib/supabase` in tests.

## Out of scope (later phases)

Real Users (5), Payments (6), Live Traffic (7), App Features (8), Settings + Env Vars (9); the real KPI dashboard (4); full mobile drawer; OAuth / password-reset / signup UX (Phase 1); admin audit-log writes (a later cross-cutting add).

## File manifest

**Create:** `ui/src/admin/AdminApp.tsx`, `useAdminSession.ts`, `AdminLogin.tsx`, `AdminShell.tsx`, `Sidebar.tsx`, `AdminTopBar.tsx`, `sections.ts`, `views/AdminDashboard.tsx`, `views/Placeholder.tsx` (+ co-located tests).
**Modify:** `ui/src/main.tsx` (the `/admin` lazy branch), `vercel.json` (rewrites).
**Reuse:** `cockpit/primitives`, `cockpit/ThemeToggle`, `cockpit/DensityToggle`, `components/state/LoadingState`, `lib/supabase`, `index.css` tokens. **No `/app`, engine, or WASM change. No new deps.**
