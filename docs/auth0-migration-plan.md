# Auth0 migration plan — Auth0 as primary IdP via Supabase Third-Party Auth

**Status:** planned, not yet started
**Decision date:** 2026-06-30
**Driver:** Standardize on Auth0 as the organization's primary identity provider (Rules/MFA/Organizations), replacing Supabase Auth for end-user login.

## Decisions locked in

| Fork | Choice | Rationale |
|------|--------|-----------|
| Integration mechanism | **Supabase Third-Party Auth** (Auth0 is a first-class provider) | Supabase trusts Auth0-issued JWTs directly — no user-DB migration, no JWT forging. |
| Identity binding | **Keep internal `uuid` PK, add `profiles.auth0_sub`** | `subscriptions.user_id`, Stripe metadata, and `audit_log` keep the stable UUID unchanged. Lowest blast radius. |
| Cutover | **Big-bang replace** | Only 6 users, all `free`, all email/password, 1 real Stripe link. Coexistence machinery isn't worth it. |

## Live footprint (measured 2026-06-30)

- 6 users, all `free` plan, 1 admin (`ravi.dholariya@icloud.com`).
- All 6 are email/password. **0** OAuth-linked identities (Google/GitHub buttons never used).
- 4 `subscriptions` rows; **1** has a `stripe_customer_id`.

Only the admin row and the one Stripe-linked row *must* retain their UUID. Both are matched by **email** on first Auth0 login, so no pre-migration data backfill is required — `auth0_sub` self-populates.

## Why Auth0's `sub` forces the schema change

Supabase's own `sub` claim is a UUID; `auth.uid()` casts `sub` to `uuid`. Auth0 subs look like `auth0|abc123` / `google-oauth2|123` — **not** UUIDs — so `auth.uid()` returns null under Auth0. Every policy that uses `auth.uid()` must resolve identity from `auth.jwt() ->> 'sub'` instead. We centralize that in one helper (`current_profile_id()`) so policies stay readable.

## Key technical facts (verified against Supabase docs)

- The frontend passes Auth0's **ID token** (`getIdTokenClaims().__raw`) to the Supabase client via the `accessToken` option — the ID token reliably carries custom claims.
- Auth0 must issue **RS256** (asymmetric) JWTs with a `kid` header. (SPA default.)
- Every JWT sent to Supabase must carry the custom claim `role: "authenticated"` — injected by an Auth0 Post-Login Action.
- Supabase Auth **cannot be disabled**; it simply goes unused for login. That's fine and is our rollback safety net.
- Pricing: **$0.00325 per Third-Party MAU** beyond plan quota (negligible at 6 users).

---

## Division of labor

**You (dashboard / secrets — I cannot do these):**
1. Create an Auth0 tenant + a **Single Page Application**. Record Domain + Client ID.
2. Allowed Callback URLs / Logout URLs / Web Origins: `https://packet-pilot.vercel.app/app`, `http://localhost:5173/app` (dev).
3. Create a **Post-Login Action** (code below) and set its Action Secret `SUPABASE_SERVICE_ROLE_KEY`. (Server-side in Auth0 — never reaches the browser, so the "no server secret in browser" invariant holds.)
4. Supabase Dashboard → Authentication → **Third-Party Auth** → add Auth0 (tenant domain).
5. (Optional) Configure Google/GitHub as **social connections in Auth0** if you still want social login (it now lives in Auth0, not Supabase).
6. Set env: Vercel `VITE_AUTH0_DOMAIN`, `VITE_AUTH0_CLIENT_ID`; Edge Function secrets `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`.
7. (For `delete-account`) Create an Auth0 **M2M app** with `delete:users` and set `AUTH0_MGMT_CLIENT_ID` / `AUTH0_MGMT_CLIENT_SECRET` as Edge secrets — or defer Auth0-side user deletion.

**Me (code — on a feature branch, parameterized by the env above so it can be written before your tenant exists):**
- New migration `0019_auth0_thirdparty.sql`.
- Frontend auth rewrite (`auth0-spa-js` + Supabase `accessToken` wiring).
- Edge Function JWT verifier (JWKS/`jose`).
- Test updates + this doc's runbook.

---

## Phase 1 — Database (`supabase/migrations/0019_auth0_thirdparty.sql`)

```sql
-- 1. Add the Auth0 identity column; drop the auth.users FK (new Auth0 users have no auth.users row).
alter table public.profiles add column if not exists auth0_sub text unique;
alter table public.profiles drop constraint if exists profiles_id_fkey;
-- id keeps `default gen_random_uuid()` so brand-new Auth0 users get a fresh internal UUID.

-- 2. Central identity resolver: Auth0 sub -> internal profile UUID.
create or replace function public.current_profile_id()
returns uuid language sql stable security definer set search_path = '' as $$
  select id from public.profiles where auth0_sub = (auth.jwt() ->> 'sub');
$$;

-- 3. is_admin() now resolves through auth0_sub.
create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.profiles
    where auth0_sub = (auth.jwt() ->> 'sub') and role = 'admin'
  );
$$;

-- 4. Rewrite all policies: auth.uid() -> (select public.current_profile_id()).
--    (profiles, subscriptions, feature_flags, app_settings, analytics_events, audit_log)
--    e.g.:
--    create policy profiles_select_self_or_admin on public.profiles
--      for select to authenticated
--      using (id = (select public.current_profile_id()) or (select public.is_admin()));

-- 5. Server-side provisioning RPC, called by the Auth0 Action (service_role only).
create or replace function public.provision_profile(
  p_sub text, p_email text, p_full_name text default null, p_avatar text default null
) returns void language plpgsql security definer set search_path = '' as $$
begin
  update public.profiles
     set auth0_sub = p_sub,
         full_name = coalesce(full_name, p_full_name),
         avatar_url = coalesce(avatar_url, p_avatar),
         updated_at = now()
   where lower(email) = lower(p_email) and auth0_sub is null;
  if not found then
    insert into public.profiles (id, email, full_name, avatar_url, auth0_sub)
    values (gen_random_uuid(), p_email, p_full_name, p_avatar, p_sub)
    on conflict (auth0_sub) do nothing;
  end if;
end;
$$;
revoke all on function public.provision_profile(text,text,text,text) from public, anon, authenticated;
grant execute on function public.provision_profile(text,text,text,text) to service_role;

-- 6. Retire the auth.users triggers (they only fired for Supabase-Auth-created users).
drop trigger if exists on_auth_user_created on auth.users;
drop trigger if exists on_auth_user_email_changed on auth.users;
```

> **Down-migration:** restore the `auth.uid()` policy bodies from `0003_rls.sql` / `0007_perf_rls.sql`, re-add `profiles_id_fkey`, drop `auth0_sub` + helpers. Keep this recoverable — do not delete the old policy SQL.

Files touched: new migration only. Old policies in `0003_rls.sql` / `0007_perf_rls.sql` are superseded by `create policy` re-definitions (drop-then-create inside the new migration).

## Phase 2 — Auth0 Post-Login Action

```js
// Auth0 Action — "Provision Supabase profile + role claim" (Login flow)
const SUPABASE_URL = "https://brkztcfhmrjjnbjzycie.supabase.co";
exports.onExecutePostLogin = async (event, api) => {
  // Supabase requires this exact claim on the token it receives (the ID token).
  api.idToken.setCustomClaim("role", "authenticated");
  api.accessToken.setCustomClaim("role", "authenticated");

  // Server-side profile provisioning (secret never touches the browser).
  await fetch(`${SUPABASE_URL}/rest/v1/rpc/provision_profile`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      apikey: event.secrets.SUPABASE_SERVICE_ROLE_KEY,
      authorization: `Bearer ${event.secrets.SUPABASE_SERVICE_ROLE_KEY}`,
    },
    body: JSON.stringify({
      p_sub: event.user.user_id,
      p_email: event.user.email,
      p_full_name: event.user.name ?? null,
      p_avatar: event.user.picture ?? null,
    }),
  });
};
```

## Phase 3 — Frontend (`ui/src/…`)

- **Add** `@auth0/auth0-spa-js`. New `ui/src/auth/auth0Client.ts` (createAuth0Client with domain/clientId + `cacheLocation: "localstorage"`).
- **`ui/src/lib/supabase/client.ts`** — add the token bridge:
  ```ts
  createClient(url, anonKey, {
    accessToken: async () => (await auth0.getIdTokenClaims())?.__raw ?? "",
  })
  ```
  Keep `supabaseConfigured` semantics; anon/offline path unchanged.
- **`ui/src/auth/useSession.ts`** — replace `signInWithPassword` / `signUp` / `signInWithOAuth` and the `onAuthStateChange` listener with Auth0: `loginWithRedirect()`, `handleRedirectCallback()`, `isAuthenticated()`, `getUser()`, `logout()`. The `authed` branch still fetches `profiles` + `subscriptions` by resolved id — unchanged query shape.
- **`ui/src/auth/AuthDialog.tsx`** — collapses to a single "Sign in" that calls Auth0 Universal Login (social + password + MFA handled by Auth0). Far less UI to maintain.
- **`ui/src/lib/reputation/edgeHttp.ts`** and **`ui/src/lib/ai/proxyClient.ts`** — replace `supabase.auth.getSession().access_token` with the Auth0 ID token (or route through `supabase.functions.invoke`, which will use the configured `accessToken`).
- **`ui/src/vite-env.d.ts`** — add `VITE_AUTH0_DOMAIN`, `VITE_AUTH0_CLIENT_ID`.
- **Invariants preserved:** offline/anon → `anon` session exactly as today (Auth0 unconfigured or offline ⇒ no user); Auth0 clientId is public (PKCE), no browser secret; capture never touches backend (untouched).

## Phase 4 — Edge Functions (`supabase/functions/…`)

- **New shared `_shared/auth0.ts`** — verify the Auth0 JWT with `jose` against `https://<AUTH0_DOMAIN>/.well-known/jwks.json`; check `iss`, `aud` (= client id, since we verify the ID token), `exp`; return `sub`.
- Replace `userClient.auth.getUser()` in **ai-proxy, reputation-proxy, create-checkout-session, create-portal-session, delete-account** with `verifyAuth0(req)` → resolve internal user via `select … from profiles where auth0_sub = sub` (service role).
- **create-checkout-session** keeps writing the **internal UUID** into Stripe metadata (`supabase_user_id`) — unchanged, because we kept UUID identity. Existing Stripe link stays valid.
- **stripe-webhook** — unchanged (no user JWT; resolves by Stripe metadata UUID).
- **delete-account** — delete profile + cancel Stripe as today; additionally call Auth0 Management API to delete the Auth0 user (needs the M2M secret; otherwise leave a TODO + manual step).

## Phase 5 — Tests & verification

- Update Vitest suites that mock `supabase.auth` (`useSession`, `AuthDialog`, `AccountMenu`, admin session) to mock the Auth0 client instead. Run `npm test` + `npx tsc -b` from `ui/`.
- Local can't fully E2E without a live tenant — verify **typecheck**, **anon/offline path**, and unit-level session states.
- Post-setup smoke (with your Auth0 tenant live): login → `auth0_sub` set on your existing row → RLS reads your own data → `/admin` visible → reputation/AI proxies authorize → checkout + portal work → delete-account.
- Run `get_advisors(security)` after the migration to catch any policy left without proper coverage.

## Phase 6 — Cutover

1. Merge to `main` only after the smoke test passes on a preview/branch.
2. Import the 6 emails into Auth0; send password-setup invites (or let each reset via Auth0). OAuth users would just re-link by email — but there are none.
3. Flip Vercel env to point at Auth0; deploy. First login of each user provisions `auth0_sub`.

## Rollback

Supabase Auth is still enabled and all user rows keep their UUID. Revert = redeploy the previous frontend + apply the down-migration (restore `auth.uid()` policies, re-add `profiles_id_fkey`, drop `auth0_sub`). No data is destroyed at any step.
