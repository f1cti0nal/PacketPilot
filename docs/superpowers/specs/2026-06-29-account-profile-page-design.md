# PacketPilot — Account / Profile Page — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-29
**Branch:** `feat/account-profile-page`
**Relation:** post-SaaS-roadmap feature. Builds on Phase 1 (accounts), Phase 2 (Stripe billing), Phase 3 (admin route pattern). Self-service counterpart to the admin Users view.

## Context

Today a signed-in user's only self-service surface is the small account-menu popover (email, plan chip, Upgrade/Manage billing, Sign out). There is no place to edit their profile, manage security, or see their subscription in detail. This feature adds a dedicated **`/account` page** covering everything a user needs to know and manage about their own account.

Decisions locked with the user:
- **Form factor:** a standalone full-page **`/account` route** (not a modal), mirroring the lazy `/admin` route. The existing account-menu popover gains a **"Profile & account"** item that navigates there (that popover is the "popup" launch point).
- **Editing:** display name **and** avatar (avatar requires a new Storage bucket).
- **Security actions:** change password, change email, sign out of all devices, **and** delete account (self-service, irreversible).
- **Billing depth:** full subscription details (status, renewal/cancel date, price, cancel-at-period-end) read from the user's own `subscriptions` row, plus Manage billing / Upgrade.

**Security note (resolved during design):** the broad `UPDATE` grants on `profiles` are safe — `guard_profile_privileged_columns` (BEFORE UPDATE trigger, `0002_functions.sql`) already blocks a non-admin from changing `role`/`plan`/`status`, and it is **deployed + enabled** in production (verified via `pg_trigger`). The edit form writes only `full_name`/`avatar_url` (permitted) and RLS scopes it to the user's own row. **No guard work is needed.**

## Goal

Give an authenticated user a single page to view and manage their account: identity (avatar, name, email, role, member-since), security (password, email, global sign-out, account deletion), plan & billing (real subscription detail + Stripe actions), and app preferences (theme, density). Anonymous users who navigate to `/account` are bounced to `/app`.

## Invariants preserved

- **Privacy / local-first:** the page touches only account + subscription data. The WASM analysis path and capture handling are untouched; no capture data is associated with the account. Anonymous use of `/app` stays fully functional.
- **Secrets never in the SPA:** account deletion runs through an authed Edge Function with the service-role key; the browser never sees a secret. The optional Stripe cancel-on-delete uses the existing `STRIPE_SECRET_KEY` Edge secret.
- **Privilege guard intact:** self-service edits never touch `plan`/`role`/`status`; the existing trigger remains the enforcement boundary.
- **No engine/WASM/Tauri change. No admin change. No new SPA deps** (Storage + auth + functions are all already in `@supabase/supabase-js`).

## Architecture

```
supabase/
  migrations/0016_account_avatars.sql   # avatars Storage bucket + RLS policies; profiles.email sync trigger
  functions/delete-account/index.ts     # authed; best-effort Stripe cancel + auth.admin.deleteUser(self)
ui/src/
  lib/route.ts                          # add "account" to Route + resolveRoute
  main.tsx                              # branch route==="account" → <AccountApp/> (lazy)
  account/
    AccountApp.tsx                      # lazy route shell: header + session gate (loading/anon/authed)
    AccountPage.tsx                     # lays out the four section cards
    useAccount.ts                       # loads full profile + own subscription; reload()
    api.ts                              # updateName, uploadAvatar, removeAvatar, changePassword,
                                        #   changeEmail, signOutEverywhere, deleteAccount → {ok,error?}
    sections/
      AccountSection.tsx                # avatar (upload/replace/remove), name (edit), email, role, joined
      SecuritySection.tsx              # password, email, sign-out-all, delete-account (typed confirm)
      BillingSection.tsx               # plan + subscription detail + Manage/Upgrade (reuses billing.ts)
      PreferencesSection.tsx           # ThemeToggle + DensityToggle as labeled settings
  auth/AccountMenu.tsx                  # add "Profile & account" item (authed) → navigates to /account
vercel.json                            # add /account + /account/(.*) rewrites → /
```

**Tech stack:** React + design tokens + `lucide-react`; `@supabase/supabase-js` (auth, `from('profiles'/'subscriptions')`, Storage, `functions.invoke`); existing `useDialogA11y` for any confirm sub-dialogs; existing `ThemeToggle`/`DensityToggle`; existing `billing.ts` (`startCheckout`/`openPortal`). Edge Function in Deno. Vitest + RTL for the UI.

## Routing & shell

- `lib/route.ts`: `Route` gains `"account"`; `resolveRoute` returns `"account"` for `/account` and `/account/...` (added **before** the `/app` check; same trailing-slash handling).
- `main.tsx`: `const AccountApp = React.lazy(() => import("./account/AccountApp"))`; branch `route === "account"` → `<Suspense fallback={<LoadingState label="Loading account…"/>}><AccountApp/></Suspense>` (mirrors `AdminApp`).
- `vercel.json`: add `{ "source": "/account", "destination": "/" }` and `{ "source": "/account/(.*)", "destination": "/" }` so the SPA loads and branches here on a hard nav.
- **`AccountApp`** owns its own light shell (brand wordmark, a "← Back to app" link to `/app`, and `ThemeToggle`). It uses `useSession()`: `loading` → `LoadingState`; `anon` → effect that `window.location.assign("/app")` (no account to show); `authed` → `<AccountPage session=… />`. Navigation between routes is a full pathname nav (`window.location.assign`), consistent with how `/admin` is reached — there is no SPA router.

## Data layer

- **`useAccount(session)`** — on mount (and `reload()`), reads the user's full profile `select("id,email,full_name,avatar_url,role,created_at")` from `profiles` (RLS: own row) and their latest `subscriptions` row `select("status,price_id,amount_cents,currency,current_period_end,cancel_at_period_end,stripe_customer_id,created_at").eq("user_id", id).order("created_at",{ascending:false}).limit(1).maybeSingle()` (RLS: own row). Returns `{ status: "loading"|"error"|"ready", profile, subscription, reload }`. The displayed **email is read from the authenticated user** (`auth.getUser()`), which is always current; the `0016` email-sync trigger keeps `profiles.email` consistent for the admin/analytics surfaces.
- **`api.ts`** — thin, each returns `{ ok: boolean; error?: string }`, all guarded by `if (!supabase) return {ok:false,error:"Accounts are unavailable"}`:
  - `updateName(name)` → `profiles.update({ full_name }).eq("id", uid)`.
  - `uploadAvatar(file)` → `storage.from("avatars").upload(\`${uid}/${crypto.randomUUID()}.<ext>\`, file, { upsert:true })`, then `getPublicUrl`, then `profiles.update({ avatar_url })`. Client-side validate type (png/jpeg/webp) + size (≤ 2 MB). `removeAvatar()` clears `avatar_url` (and best-effort deletes the object).
  - `changePassword(current, next)` → re-auth `signInWithPassword({ email, password: current })` to prove identity, then `auth.updateUser({ password: next })`.
  - `changeEmail(next)` → `auth.updateUser({ email: next })` (Supabase sends a confirmation link to the new address; surface "check your email").
  - `signOutEverywhere()` → `auth.signOut({ scope: "global" })` then redirect to `/app`.
  - `deleteAccount()` → `supabase.functions.invoke("delete-account")`; on success `auth.signOut()` + redirect to `/`. Reads the function's error body via the same `error.context.json()` pattern fixed in `billing.ts`.

## Edge Function — `delete-account`

Authed (JWT verification ON). Mirrors `create-portal-session` init. Steps: resolve the caller via `createClient(URL, ANON_KEY, { global:{ headers:{ Authorization } } }).auth.getUser()` → 401 if none. With the **service-role** client, look up the user's `subscriptions.stripe_subscription_id`; if present and `STRIPE_SECRET_KEY` is set, **best-effort** `stripe.subscriptions.cancel(id)` (swallow errors — never block deletion on Stripe). Then `admin.auth.admin.deleteUser(user.id)`. The FK cascades (`auth.users → profiles → subscriptions`, both `on delete cascade`) remove the DB rows automatically. Return `{ ok: true }` / `{ error }` with a clear status. Deployed with `verify_jwt: true`.

> Cancelling the Stripe subscription matters: deleting only the DB user would leave an active Stripe subscription billing a now-deleted account.

## Migration — `0016_account_avatars.sql`

- **Avatars bucket:** `insert into storage.buckets (id, name, public) values ('avatars','avatars',true) on conflict do nothing;` (public read so `avatar_url` renders without signed URLs).
- **Storage RLS** (on `storage.objects`, bucket `avatars`, path convention `\<uid\>/file`): public `select`; `insert`/`update`/`delete` to `authenticated` only when `bucket_id='avatars' and (storage.foldername(name))[1] = auth.uid()::text` — a user can only write within their own `\<uid\>/` folder.
- **Email sync:** `after update of email on auth.users` trigger → `update public.profiles set email = new.email where id = new.id` (keeps `profiles.email` consistent after a confirmed email change; SECURITY DEFINER, pinned `search_path`, revoked from anon/authenticated like the other trigger fns). Display still sources the auth email, but this keeps the admin Users view + analytics correct.

## UI sections (the page)

A single scrollable column of `.card` sections (reusing the app's tokens/primitives), each with a heading + helper text:
1. **Account** — round avatar with hover "Change"/"Remove" (file input), inline-editable display name (pencil → input + Save/Cancel), read-only email, a role badge (`user`/`admin`), and "Member since {joinedDate}".
2. **Security** — three stacked actions opening small inline forms/confirels: **Change password** (current + new + confirm), **Change email** (new email → "check your email" notice), **Sign out of all devices** (confirm → `signOutEverywhere`). Then a separated **Danger zone**: **Delete account** — requires typing the email to enable the button (reuses `useDialogA11y` if a modal confirm is used), then `deleteAccount()`.
3. **Plan & Billing** — plan badge; if a subscription exists: status pill, price (`amount_cents`/`currency`), renewal/cancel date (`current_period_end` + `cancel_at_period_end` → "renews"/"cancels on"); actions: **Manage billing** (`openPortal`, pro) or **Upgrade to Pro** (`startCheckout`, free). Surfaces invoke errors inline (already correct via the `billing.ts` fix). "No billing account yet" is shown gracefully for comped pros.
4. **Preferences** — **Theme** (`ThemeToggle`) and **Density** (`DensityToggle`) presented as labeled rows. These already persist to `localStorage` globally.

Each mutating action: a busy state, an inline `role="alert"` error line on failure, and a transient success confirmation; `reload()` after profile/avatar changes.

## Error handling & edge cases

- Avatar: reject wrong type/oversize client-side with a clear message; surface Storage errors inline.
- Password: wrong current password → surface the re-auth error; don't call `updateUser`.
- Email change is async (confirmation link) — the UI states that explicitly; no optimistic email swap.
- Delete: irreversible; gated behind typed-email confirmation; on success the session ends and the user lands on the marketing page.
- `supabase` unconfigured (offline build) → `AccountApp` shows the anon redirect path; the page never assumes a backend beyond what `useSession` already guards.

## Testing

- **Unit (Vitest + RTL):** `route.ts` (`/account` → `"account"`, and `/account/x`, trailing slash, and that `/administrator`/`/app` are unaffected); `useAccount` (mock supabase reads → ready/error shapes; subscription `maybeSingle`); `api.ts` (mock auth/storage/functions — each path's success + error, password re-auth gate, avatar type/size guard, deleteAccount reads error body); each **section** component (render + primary interaction with mocked api); `AccountApp` gate (loading/anon-redirect/authed); `AccountMenu` shows "Profile & account" only when authed and points at `/account`. Coverage ≥ 80/70.
- **Backend (live, no Deno harness in-repo):** verify via MCP `execute_sql` that the `avatars` bucket + 4 storage policies + email-sync trigger exist; smoke-test `delete-account` on a throwaway user (row cascade confirmed; Stripe cancel best-effort). Reviewed for correctness.
- **Gate:** UI suite green, coverage ≥ 80/70, `npx tsc -b` + `npm run build` clean, Playwright e2e + axe AA green for the new route (nav from account menu, section presence, dark+light contrast).

## Out of scope (later / not now)

Two-factor / MFA; active-session listing (supabase-js exposes no client-side session list); avatar cropping/resizing; notification or email preferences; data-export ("download my data"); connected-accounts/OAuth; multiple paid tiers; in-app invoice history (the Stripe portal already covers invoices/receipts).

## File manifest

**Create:** `supabase/migrations/0016_account_avatars.sql`; `supabase/functions/delete-account/index.ts`; `ui/src/account/{AccountApp,AccountPage,useAccount,api}.tsx|ts` (+ tests); `ui/src/account/sections/{Account,Security,Billing,Preferences}Section.tsx` (+ tests).
**Modify:** `ui/src/lib/route.ts` (+ test), `ui/src/main.tsx` (lazy branch), `ui/src/auth/AccountMenu.tsx` (+ test) — add the "Profile & account" item, `vercel.json` (rewrites).
**No engine/WASM/Tauri change. No admin change. No new SPA deps. No guard-trigger work (already deployed).**
