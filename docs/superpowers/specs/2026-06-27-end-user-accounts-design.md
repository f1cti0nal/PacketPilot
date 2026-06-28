# PacketPilot SaaS — End-User Accounts (Phase 1) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-27
**Branch:** `feat/end-user-accounts`
**Sub-project:** 1 of the PacketPilot SaaS platform (depends on Phase 0)

## Context

Phase 1 of the SaaS pivot (roadmap in `2026-06-27-saas-backend-foundation-design.md`). Phases 0 (Supabase backend), 3 (admin shell), 4 (admin dashboard) are merged + deployed. This phase adds **optional** end-user accounts to the consumer app at `/app`.

Decisions locked with the user:
- **Opt-in / additive auth.** Anonymous users keep FULL access to core local analysis (the product's privacy-first, no-signup identity is preserved). Login is optional; signing in attaches a profile + plan and is the foundation for Pro features gated later (Phase 8). **Phase 1 hard-gates nothing.**
- **Email confirmation ON.** Signup → "check your email" → confirm → log in. Built-in Supabase email for now; production-grade SMTP is a later ops task.
- Email/password only (OAuth deferred); password reset deferred (see Out of scope).

**Phase 1 is frontend-only.** The Phase-0 backend already provides everything: Supabase Auth, the `handle_new_user` trigger that creates a `profiles` row on signup (plan defaults to `free`), and RLS letting a user read/update their own profile. No migration is needed.

## Goal

Let a visitor optionally sign up / log in / log out on `/app`, keep a session across reloads, and see their account (email + plan) — via an account menu in the shell and an auth modal — without changing or gating any existing functionality.

## Invariants preserved

- **Privacy / local-first:** the WASM analysis path (`lib/wasmEngine.ts`, `lib/data.ts`) and all capture handling are untouched. No capture data is ever associated with an account. Anonymous use stays 100% functional.
- **No backend/schema change** (no migration). Reuses Phase-0 auth + `profiles` trigger + RLS.
- **No change to `/admin` or the engine.** The admin `useAdminSession` is left as-is (a parallel, admin-role-gated hook); this phase adds a separate end-user `useSession` to avoid coupling consumer code to admin concerns (small, intentional duplication — different responsibilities).

## Architecture

```
ui/src/auth/
  useSession.ts        # end-user session hook over the Phase-0 supabase client
  AuthDialog.tsx       # modal: Sign in / Sign up / confirm-pending / errors
  AccountMenu.tsx      # CommandBar control: Sign in (anon) | email+plan+Sign out (authed)
ui/src/App.tsx         # owns the session + AuthDialog open-state; renders <AccountMenu/>
ui/src/cockpit/CommandBar.tsx   # new `accountMenu?: ReactNode` slot (mirrors `rulesMenu`)
ui/src/components/layout/AppShell.tsx  # threads `accountMenu` through to CommandBar
```

**Tech stack:** React 18 + TS, `@supabase/supabase-js` (Phase-0 client `ui/src/lib/supabase`), `lib/useDialogA11y` (Escape + focus-trap), Tailwind + `index.css` tokens + `lucide-react`. Vitest + RTL. No new deps, no engine/WASM/Tauri change.

## Session hook — `useSession.ts`

```ts
export interface UserProfile { email: string; full_name: string | null; plan: string }
export type SessionState =
  | { status: "loading" }
  | { status: "anon"; signIn: (email: string, password: string) => Promise<{ ok: boolean; error?: string }>;
      signUp: (email: string, password: string) => Promise<{ ok: boolean; needsConfirm?: boolean; error?: string }> }
  | { status: "authed"; email: string; profile: UserProfile; signOut: () => Promise<void> };
export function useSession(): SessionState;
```
On mount: if `!supabaseConfigured` → stay `anon` (auth simply unavailable; the app still works — additive). Else `getSession()`; with a session, load `profiles` (email, full_name, plan) → `authed`; without → `anon`. Subscribe to `onAuthStateChange` and re-derive; unsubscribe on unmount; cancelled-flag guard. `signIn` → `supabase.auth.signInWithPassword`. `signUp` → `supabase.auth.signUp({ email, password, options: { emailRedirectTo: \`${location.origin}/app\` } })`; returns `needsConfirm: true` when Supabase returns a user without an active session (confirmation required). `signOut` → `supabase.auth.signOut()`.

## Auth modal — `AuthDialog.tsx`

Props: `{ session: Extract<SessionState, { status: "anon" }>; onClose: () => void }`. Internal `mode` state: `signin | signup | confirm`. Email + password fields; submit calls `session.signIn`/`signUp`; a signup that returns `needsConfirm` switches to the `confirm` panel ("We sent a confirmation link to <email> — click it to finish, then sign in."). A toggle link swaps signin↔signup. Inline `role="alert"` errors. `useDialogA11y` for Escape/focus-trap; `role="dialog" aria-modal="true"`.

## Account control — `AccountMenu.tsx`

Props: `{ session: SessionState; onOpenAuth: () => void }`.
- `loading` → a tiny disabled spinner (or nothing).
- `anon` → a "Sign in" button → `onOpenAuth()`.
- `authed` → a dropdown button (email, truncated) with `aria-haspopup`/`aria-expanded`; panel shows the email, a plan chip (Free/Pro), and "Sign out" (a plain account popover — NOT `role="menu"`, matching the admin AccountMenu fix; outside-click + Escape close). Always rendered (visible on mobile).

## Wiring

- `CommandBar` gains `accountMenu?: ReactNode`, rendered in the right action cluster (always-visible region, before/after ThemeToggle). `AppShell` adds an `accountMenu?: ReactNode` prop passed straight to `CommandBar`.
- `App.tsx`: `const session = useSession();` + `const [authOpen, setAuthOpen] = useState(false)`; passes `accountMenu={<AccountMenu session={session} onOpenAuth={() => setAuthOpen(true)} />}` to `AppShell`; renders `{authOpen && session.status === "anon" && <AuthDialog session={session} onClose={() => setAuthOpen(false)} />}` alongside the other modals. (When the user becomes `authed`, `authOpen` is moot — the dialog only renders for `anon`.)
- `client.ts` already enables `persistSession` + `autoRefreshToken`; supabase-js's default `detectSessionInUrl` completes the email-confirm redirect on load. No client change.

## Supabase config (ops, not code — flagged)

In the Supabase dashboard: add the Site URL + redirect allowlist entries (`http://localhost:5180/app` for dev, `https://packet-pilot.vercel.app/app` for prod) so confirmation links return to `/app`. Built-in email is rate-limited/test-grade; configure custom SMTP for production delivery. These are dashboard settings; the code passes `emailRedirectTo` accordingly.

## Data flow & error handling

Sign up → `auth.signUp` → (Phase-0 trigger creates the `profiles` row, plan `free`) → confirm-pending panel. Confirm link → returns to `/app`, supabase-js establishes the session → `onAuthStateChange` → `authed`. Sign in → password grant → `authed`. Sign out → `anon`. All auth errors surface inline in the dialog; a failed `profiles` fetch after a valid session leaves the user `authed` with a best-effort profile (email from the session, plan defaulting to `free`) rather than logging them out. No throws cross the dialog/menu boundary (App's `ErrorBoundary` remains the backstop). Missing env → `anon`, app unaffected.

## Testing

- **`useSession`** (mock `../lib/supabase`): `anon` when no session / unconfigured; `authed` with session + profile; `signIn`/`signUp`/`signOut` delegate to `supabase.auth` with the right args (incl. `emailRedirectTo`); `signUp` → `needsConfirm` when no session returned; re-derive on `onAuthStateChange`.
- **`AuthDialog`**: signin submit calls `signIn`; signup submit calls `signUp`; a `needsConfirm` result shows the confirm panel with the email; error renders in an alert; the signin↔signup toggle works; Escape closes.
- **`AccountMenu`**: `anon` shows "Sign in" → `onOpenAuth`; `authed` shows email + plan chip + "Sign out" → `signOut`.
- **App/CommandBar**: the account menu renders in the shell; opening the dialog from the anon menu (light integration; the rest is unit-covered).
- Gate: full suite green, coverage ≥ 80/70, `npx tsc -b` clean, `npm run build` passes.
- **Browser smoke:** sign in with the existing confirmed demo account `demo+alice@packetpilot.test` / `DemoPass!23` → the account menu shows authed (email + Pro plan); reload preserves the session; sign out returns to anon. (Verifies the authed path without needing email delivery.)

## Out of scope (follow-ups / later phases)

Password reset ("forgot password" — email-based; the likely next add); OAuth (Google/GitHub); plan upgrade / Stripe checkout (Phase 2); cloud-saving captures or any capture↔account association (deliberately never — privacy); feature/plan gating (Phase 8); a dedicated account/settings page (the menu suffices for now); production SMTP (ops).

## File manifest

**Create:** `ui/src/auth/useSession.ts`, `ui/src/auth/AuthDialog.tsx`, `ui/src/auth/AccountMenu.tsx` (+ co-located tests).
**Modify:** `ui/src/cockpit/CommandBar.tsx` (`accountMenu` slot), `ui/src/components/layout/AppShell.tsx` (thread the slot), `ui/src/App.tsx` (session + AuthDialog + render AccountMenu) + the co-located AppShell test if the new prop needs coverage.
**No migration. No engine/WASM/Tauri change. No new deps. `/admin` untouched.**
