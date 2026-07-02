# Auth0 migration plan — Auth0 as primary IdP via Supabase Third-Party Auth

**Status:** ✅ COMPLETED — cut over to production 2026-07-01 (see "Cutover — completed" at the end).
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
  // p_email_verified GATES legacy-account linking: provision_profile will only bind this
  // Auth0 sub to an existing profile with the same email when the address is verified —
  // otherwise an attacker could register an unverified identity using someone else's email
  // (e.g. the admin's) and take over that account.
  const resp = await fetch(`${SUPABASE_URL}/rest/v1/rpc/provision_profile`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      apikey: event.secrets.SUPABASE_SERVICE_ROLE_KEY,
      authorization: `Bearer ${event.secrets.SUPABASE_SERVICE_ROLE_KEY}`,
    },
    body: JSON.stringify({
      p_sub: event.user.user_id,
      p_email: event.user.email,
      p_email_verified: event.user.email_verified === true,
      p_full_name: event.user.name ?? null,
      p_avatar: event.user.picture ?? null,
    }),
  });
  // Fail the login rather than admit a session with no profile (which would leave the user
  // signed in but unable to see their own data). This fires when the email is already tied to
  // another identity — configure Auth0 account-linking (below) so it effectively never does.
  if (!resp.ok) {
    api.access.deny("We couldn't finish setting up your account. If you signed up before, use your original login method, or contact support.");
  }
};
```

**Required Auth0 tenant settings (security):**
- **Account Linking** — enable automatic linking of accounts that share a *verified* email (Auth0 "Account Link" extension or a Link-by-email Action). Otherwise the same person signing in via a second connection (e.g. Google then GitHub) gets a **different `sub`** and `provision_profile` refuses to fork a duplicate → they'd be denied. One human must map to one `sub`.
- **Legacy import** — when importing the existing users, set `email_verified: true` on them (bulk import supports it) so their first Auth0 login can link to their existing profile by email. OAuth (Google/GitHub) logins are verified by the provider automatically.
- **Email changes** — `profiles.email` is no longer auto-synced (the `auth.users` email trigger is retired). If you need it current on admin/audit surfaces, add a Post-User-Update Action (or re-provision) that updates `profiles.email`. *(Follow-up; not blocking.)*

## Phase 3 — Frontend (`ui/src/…`)

- **Add** `@auth0/auth0-spa-js`. New `ui/src/auth/auth0Client.ts` (createAuth0Client with domain/clientId + `cacheLocation: "localstorage"`).
- **`ui/src/lib/supabase/client.ts`** — add the token bridge via `accessToken`, returning the Auth0 ID token when signed in and the **anon key** when not (so public/offline reads behave like a signed-out client). The token helper calls `getTokenSilently()` before `getIdTokenClaims()` so a long-open tab refreshes instead of sending an expired token, and every failure path falls back to the anon key (a token error must never break anon requests). Keep `supabaseConfigured` semantics; anon/offline path unchanged.
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

## Cutover — completed (2026-07-01)

Sequence used (kept the live app working during the Vercel build; a failed build would have been a no-op):
1. Merged `feat/auth0-thirdparty` → `main` → Vercel built the Auth0 UI (old app kept serving, `0019` not yet applied).
2. Waited for the deploy to go **READY** (aliased to `packetpilot.app`), then applied `0019` via the Supabase MCP.
3. Redeployed the 5 authed edge functions with **`verify_jwt=false`** and the Auth0 JWKS verifier **inlined** into each `index.ts` (the deploy bundler's handling of the `../_shared/auth0.ts` relative import was unreliable, so inline to avoid a cold-start import failure).
4. Verified server-side: `auth0_sub` column + `current_profile_id()` + `provision_profile(5 args)` present, `profiles_id_fkey` dropped, policies recreated; and the deployed JS bundle contains the Auth0 domain + client id (Vercel env baked in).

**Tenant:** `dev-z7p2u0ds62xilshu.us.auth0.com`, SPA client `aEaW25tXlwSHWM4HRQrx5xqHq08De8sm`.

### ⚠️ The gotcha that cost the most time — the Post-Login Action

Symptom: login succeeded but the app said **"not an administrator"** / showed the user as unprovisioned. Root cause: the **Auth0 Post-Login Action was missing**, so:
- the **ID token had no `role: authenticated` claim** → Supabase mapped the request to the **anon** role → every RLS `to authenticated` read returned **200 but empty**; and
- `provision_profile` was never called (no such call in the API logs — only `get_public_settings`), so no profile linked to the Auth0 `sub`.

Diagnosis that nailed it: the API logs showed `GET /rest/v1/profiles?auth0_sub=eq.google-oauth2|… → 200` (empty) and **zero `rpc/provision_profile` calls**. Manually setting `auth0_sub` in the DB did **not** fix it — proof the block was the missing role claim (anon), not the missing row.

Checklist so this never recurs:
- The Action must set the claim on the **ID token** (`api.idToken.setCustomClaim("role","authenticated")`) — the SPA sends the **ID token** to Supabase, not the access token.
- The Action must call `provision_profile` (with `p_email_verified`).
- Creating + **Deploy**ing the Action is not enough — it must be **added to the post-login Trigger flow** (drag in + Apply).
- After deploying, the user must **fully log out and log back in** — a silent refresh (`getTokenSilently`) does **not** re-run login-flow Actions, so the claim won't appear until a fresh interactive login.

### Admins & follow-ups
- Admins: `ravidholariya3992@gmail.com` (Google, linked) + `ravi.dholariya@icloud.com` (auto-links on next login). New admin = insert a `profiles` row with `role='admin'` + `auth0_sub` null; it links by verified email on first login.
- Optional, not blocking: enable Auth0 **Account Linking** (one human → one `sub`); add `AUTH0_MGMT_*` M2M secret so `delete-account` also deletes the Auth0 user; re-add Vercel **Speed Insights** (dropped by this deploy — it was a bot promote never merged to `main`).

## Admin isolation (MFA + subdomain)

### A. Require MFA for admins (Auth0 Post-Login Action)

The admin role lives in Supabase (`profiles.role`), so the Action looks it up by the linked
`auth0_sub` and enforces MFA when the user is an admin. **Replace your existing post-login
Action code with this** (it keeps the role-claim + provisioning), then in Auth0 **Security →
Multi-factor Auth enable at least one factor** (e.g. One-Time Password / authenticator app) or
admins will have nothing to enroll.

```js
const SUPABASE_URL = "https://brkztcfhmrjjnbjzycie.supabase.co";
exports.onExecutePostLogin = async (event, api) => {
  api.idToken.setCustomClaim("role", "authenticated");
  api.accessToken.setCustomClaim("role", "authenticated");

  const KEY = event.secrets.SUPABASE_SERVICE_ROLE_KEY;
  const h = { apikey: KEY, authorization: `Bearer ${KEY}` };

  const resp = await fetch(`${SUPABASE_URL}/rest/v1/rpc/provision_profile`, {
    method: "POST",
    headers: { ...h, "content-type": "application/json" },
    body: JSON.stringify({
      p_sub: event.user.user_id,
      p_email: event.user.email,
      p_email_verified: event.user.email_verified === true,
      p_full_name: event.user.name ?? null,
      p_avatar: event.user.picture ?? null,
    }),
  });
  if (!resp.ok) { api.access.deny("Could not finish account setup. Contact support."); return; }

  // Require MFA for admins. Role is looked up by the now-linked auth0_sub. Fail-open on a
  // lookup error (so a Supabase blip can't lock anyone out) — admins keep MFA once linked.
  try {
    const r = await fetch(
      `${SUPABASE_URL}/rest/v1/profiles?select=role&auth0_sub=eq.${encodeURIComponent(event.user.user_id)}`,
      { headers: h },
    );
    const rows = await r.json();
    if (Array.isArray(rows) && rows[0] && rows[0].role === "admin") {
      api.multifactor.enable("any", { allowRememberBrowser: true });
    }
  } catch (_) { /* don't block login on a role-lookup error */ }
};
```

### B. Dedicated admin subdomain (`admin.packetpilot.app`)

Code side is live: `resolveRouteFor(hostname, pathname)` renders the admin app for **any path on
an `admin.` host**, and the whole admin subdomain is `noindex` (host-conditioned header in
`vercel.json`). Setup:
1. **DNS**: add `admin` CNAME → `cname.vercel-dns.com` (or per Vercel's instructions).
2. **Vercel**: Project → Domains → add `admin.packetpilot.app`.
3. **Auth0**: add `https://admin.packetpilot.app` (and `/app`) to the app's **Allowed Callback
   URLs / Logout URLs / Web Origins** (the admin console runs Auth0 login on that origin).
4. Verify `https://admin.packetpilot.app` loads the admin panel and login works.
5. **Then tell me** and I'll flip `/admin` on the public domain to **redirect** to the subdomain
   (completing the isolation without a lockout window). Deploying that redirect before the
   subdomain resolves would break admin access, so it's a deliberate second step.

✅ **Done 2026-07-01.** Steps 1–4 verified live (DNS on Vercel nameservers, cert, host-conditioned
noindex on every path, Auth0 callback/logout allowlists probed directly, console renders clean
under CSP in a real browser). Step 5 shipped as a host-scoped 307 in `vercel.json` — scoped to
`packetpilot.app` so preview/branch hostnames keep serving `/admin`, and temporary (not 308) so
a revert can't be defeated by browser redirect caches.
