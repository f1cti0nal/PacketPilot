-- Revert Auth0 third-party auth (0019) back to Supabase native GoTrue auth.
--
-- Strategy: redefine current_profile_id() as a thin shim over auth.uid(). Under native
-- GoTrue the JWT `sub` IS the profile uuid again, so auth.uid() = profiles.id. Because
-- every RLS policy and every audit/stamp function resolves identity through
-- current_profile_id(), the shim reverts all 7 policies + 5 audit functions with NO
-- policy-body edits. Only is_admin() and the privilege-escalation guard read the raw
-- JWT `sub` claim directly, so those two functions plus the two auth.users triggers
-- (which 0019 dropped) need explicit restoration.
--
-- Apply this in lockstep with the native-auth frontend + edge-function deploy (cutover).
-- A half-state where the app sends GoTrue tokens but this migration hasn't landed (or
-- vice versa) yields empty RLS reads that look like a full outage.
--
-- KEPT for a clean rollback window (dropped in a later follow-up, NOT here):
--   * profiles.auth0_sub column + profiles_auth0_sub_key index — the Auth0<->profile
--     binding and our rollback key; native users simply leave it null.
--   * public.provision_profile(...) — now unused (no Auth0 Action calls it), retained
--     so a rollback needs no function redefinition.
--   * profiles.id default gen_random_uuid() + the dropped profiles_id_fkey (0019) —
--     left as-is; handle_new_user supplies id = new.id explicitly, so native signups
--     still get profiles.id == auth.users.id. Re-adding the FK is optional post-cutover
--     hardening, done only after 1:1 id parity is verified.

-- ── 1. Identity resolver: back to native auth.uid() ──────────────────────────
-- auth.uid() reads the per-request JWT claims (not the function's role), so a
-- SECURITY DEFINER shim still returns the CALLER's uid — same contract is_admin()
-- has relied on since 0002. Keeping the function means the policies/audit fns that
-- call current_profile_id() need no change.
create or replace function public.current_profile_id()
returns uuid
language sql
security definer
set search_path = ''
stable
as $$
  select auth.uid();
$$;
-- Re-assert least privilege: `create or replace` can reset the ACL to the default
-- PUBLIC grant (this bit the 0019 pass — see 0020). Evaluated under the caller's role.
revoke execute on function public.current_profile_id() from public, anon;
grant execute on function public.current_profile_id() to authenticated;

-- ── 2. is_admin(): resolve the admin via auth.uid() (reverts 0019 → 0002) ────
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
-- Must stay executable by `authenticated` (every RLS policy calls it), not anon/public.
revoke execute on function public.is_admin() from public, anon;
grant execute on function public.is_admin() to authenticated;

-- ── 3. CRITICAL: privilege-escalation guard back to auth.uid() (reverts 0019) ─
-- profiles_update_self_or_admin lets a user update their OWN row, so this trigger is
-- the only thing stopping a non-admin from setting role='admin' on themselves. Under
-- native auth a real user carries a non-null auth.uid(); service-role/cron (seeding,
-- webhooks, expire_trials) carry null and are allowed through. This MUST land in the
-- same migration as the identity flip — never a partial apply.
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
revoke execute on function public.guard_profile_privileged_columns() from public, anon, authenticated;

-- ── 4. Restore the auth.users triggers (0019 dropped them) ───────────────────
-- Native signups INSERT into auth.users; these recreate the profile and keep email in
-- sync. The functions are unchanged: handle_new_user (0018 reverse-trial) inserts
-- id = new.id with `on conflict (id) do nothing` and NEVER links by email — a new
-- signup can't adopt an existing profile, so there is no email-takeover surface.
-- sync_profile_email (0016) mirrors a confirmed email change onto profiles.
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

drop trigger if exists on_auth_user_email_changed on auth.users;
create trigger on_auth_user_email_changed
  after update of email on auth.users
  for each row execute function public.sync_profile_email();
