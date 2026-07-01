-- Auth0 as the primary IdP via Supabase Third-Party Auth.
--
-- Identity binding: keep the internal profiles.id (uuid) stable and add auth0_sub.
-- Resolve identity from the Auth0 subject claim (auth.jwt()->>'sub') instead of
-- auth.uid(), because Auth0 subs (e.g. 'auth0|abc', 'google-oauth2|123') are NOT
-- UUIDs, so auth.uid() (which casts sub to uuid) returns NULL under Auth0.
--
-- DO NOT apply this to a live database that is still serving Supabase-Auth logins:
-- it swaps every policy over to auth0_sub resolution, which only works once the app
-- is issuing Auth0 tokens. Apply at cutover (or on a Supabase branch for testing),
-- together with the Auth0 frontend + the Third-Party Auth integration.

-- ── 1. Schema: add auth0_sub, decouple profiles from auth.users ──────────────
alter table public.profiles add column if not exists auth0_sub text;
create unique index if not exists profiles_auth0_sub_key on public.profiles(auth0_sub);

-- Brand-new Auth0 users have no auth.users row, so the FK must go and id needs its
-- own default (previously it was always supplied from auth.users.id by the trigger).
alter table public.profiles drop constraint if exists profiles_id_fkey;
alter table public.profiles alter column id set default gen_random_uuid();

-- ── 2. Identity resolver: Auth0 sub -> internal profile uuid ─────────────────
-- Mirrors is_admin()'s SECURITY DEFINER + pinned search_path so it can read profiles
-- from inside a profiles policy without tripping recursive RLS.
create or replace function public.current_profile_id()
returns uuid
language sql
security definer
set search_path = ''
stable
as $$
  select id from public.profiles where auth0_sub = (auth.jwt() ->> 'sub');
$$;
-- Evaluated by RLS under the calling user's role, like is_admin().
revoke execute on function public.current_profile_id() from public, anon;
grant execute on function public.current_profile_id() to authenticated;

-- ── 3. is_admin(): resolve the admin via auth0_sub ──────────────────────────
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = ''
stable
as $$
  select exists (
    select 1 from public.profiles
    where auth0_sub = (auth.jwt() ->> 'sub') and role = 'admin'
  );
$$;

-- ── 4. Policies that embedded auth.uid() literally ──────────────────────────
-- (is_admin()-only policies need no change; their new definition flows through.)

-- profiles: own row or admin (read/update)
drop policy if exists profiles_select_self_or_admin on public.profiles;
create policy profiles_select_self_or_admin on public.profiles
  for select to authenticated
  using (id = (select public.current_profile_id()) or (select public.is_admin()));
drop policy if exists profiles_update_self_or_admin on public.profiles;
create policy profiles_update_self_or_admin on public.profiles
  for update to authenticated
  using (id = (select public.current_profile_id()) or (select public.is_admin()))
  with check (id = (select public.current_profile_id()) or (select public.is_admin()));

-- subscriptions: user reads own; admin reads all
drop policy if exists subscriptions_select_self_or_admin on public.subscriptions;
create policy subscriptions_select_self_or_admin on public.subscriptions
  for select to authenticated
  using (user_id = (select public.current_profile_id()) or (select public.is_admin()));

-- analytics: authenticated insert may only attribute rows to itself
drop policy if exists analytics_insert_authenticated on public.analytics_events;
create policy analytics_insert_authenticated on public.analytics_events
  for insert to authenticated
  with check (
    (user_id is null or user_id = (select public.current_profile_id()))
    and length(path) <= 32
    and (path = '/' or path ~ '^/(app|admin)#[a-z]+$')
    and referrer is null and user_agent is null and country is null
  );

-- ── 5. CRITICAL: privilege-escalation guard carve-out ───────────────────────
-- Under Auth0 auth.uid() is ALWAYS null, so the old `auth.uid() is not null` gate
-- would never fire — and since profiles_update lets a user update their own row, any
-- authenticated user could set role='admin' on themselves. Gate on the Auth0 subject
-- claim instead: real users carry a sub; service-role/cron (which legitimately change
-- role/plan/status) carry none.
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
     and (auth.jwt() ->> 'sub') is not null
     and not public.is_admin()
  then
    raise exception 'not authorized to change role/plan/status';
  end if;
  return new;
end;
$$;

-- ── 6. Actor attribution: auth.uid() -> current_profile_id() in audit/stamp fns ─
-- Same bodies as 0009/0012/0013, only the actor expression changes so audit rows and
-- updated_by keep pointing at the acting admin's internal profile id under Auth0.
create or replace function public.audit_profile_change()
returns trigger language plpgsql security definer set search_path = '' as $$
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
    values (public.current_profile_id(), 'profile.update', new.id::text, changes);
  end if;
  return new;
end;
$$;
revoke execute on function public.audit_profile_change() from public, anon, authenticated;

create or replace function public.feature_flags_stamp()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  new.updated_by := public.current_profile_id();
  return new;
end;
$$;
revoke execute on function public.feature_flags_stamp() from public, anon, authenticated;

create or replace function public.feature_flags_audit()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  changes jsonb := '{}'::jsonb;
begin
  if tg_op = 'DELETE' then
    insert into public.audit_log (actor_id, action, target, meta)
    values (public.current_profile_id(), 'feature_flag.delete', old.key,
      jsonb_build_object('enabled', old.enabled, 'plan_gate', old.plan_gate::text));
    return old;
  elsif tg_op = 'INSERT' then
    insert into public.audit_log (actor_id, action, target, meta)
    values (public.current_profile_id(), 'feature_flag.create', new.key,
      jsonb_build_object('enabled', new.enabled, 'plan_gate', new.plan_gate::text, 'description', new.description));
    return new;
  else
    if new.enabled is distinct from old.enabled then
      changes := changes || jsonb_build_object('enabled', jsonb_build_object('old', old.enabled, 'new', new.enabled));
    end if;
    if new.plan_gate is distinct from old.plan_gate then
      changes := changes || jsonb_build_object('plan_gate', jsonb_build_object('old', old.plan_gate::text, 'new', new.plan_gate::text));
    end if;
    if new.description is distinct from old.description then
      changes := changes || jsonb_build_object('description', jsonb_build_object('old', old.description, 'new', new.description));
    end if;
    if changes <> '{}'::jsonb then
      insert into public.audit_log (actor_id, action, target, meta)
      values (public.current_profile_id(), 'feature_flag.update', new.key, changes);
    end if;
    return new;
  end if;
end;
$$;
revoke execute on function public.feature_flags_audit() from public, anon, authenticated;

create or replace function public.app_settings_stamp()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  new.updated_by := public.current_profile_id();
  return new;
end;
$$;
revoke execute on function public.app_settings_stamp() from public, anon, authenticated;

create or replace function public.app_settings_audit()
returns trigger language plpgsql security definer set search_path = '' as $$
declare changes jsonb := '{}'::jsonb;
begin
  if tg_op = 'DELETE' then
    insert into public.audit_log (actor_id, action, target, meta)
    values (public.current_profile_id(), 'app_setting.delete', old.key, jsonb_build_object('value', old.value));
    return old;
  elsif tg_op = 'INSERT' then
    insert into public.audit_log (actor_id, action, target, meta)
    values (public.current_profile_id(), 'app_setting.create', new.key, jsonb_build_object('value', new.value, 'description', new.description));
    return new;
  else
    if new.value is distinct from old.value then
      changes := changes || jsonb_build_object('value', jsonb_build_object('old', old.value, 'new', new.value));
    end if;
    if new.description is distinct from old.description then
      changes := changes || jsonb_build_object('description', jsonb_build_object('old', old.description, 'new', new.description));
    end if;
    if changes <> '{}'::jsonb then
      insert into public.audit_log (actor_id, action, target, meta)
      values (public.current_profile_id(), 'app_setting.update', new.key, changes);
    end if;
    return new;
  end if;
end;
$$;
revoke execute on function public.app_settings_audit() from public, anon, authenticated;

-- ── 7. Storage (avatars): owner folder keyed by internal profile id ─────────
-- The frontend now uploads under "<profile.id>/...". auth.uid() would be null.
drop policy if exists "avatars owner insert" on storage.objects;
create policy "avatars owner insert" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select public.current_profile_id())::text);
drop policy if exists "avatars owner update" on storage.objects;
create policy "avatars owner update" on storage.objects
  for update to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select public.current_profile_id())::text)
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select public.current_profile_id())::text);
drop policy if exists "avatars owner delete" on storage.objects;
create policy "avatars owner delete" on storage.objects
  for delete to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select public.current_profile_id())::text);

-- ── 8. Server-side provisioning RPC (called by the Auth0 Post-Login Action) ─
-- Links a legacy profile by email on first Auth0 login, or creates a new profile
-- (mirroring the reverse-trial in handle_new_user / 0018). Service-role only.
create or replace function public.provision_profile(
  p_sub text,
  p_email text,
  p_email_verified boolean default false,
  p_full_name text default null,
  p_avatar text default null
) returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_target uuid;
begin
  if p_sub is null or p_email is null then
    raise exception 'provision_profile requires sub and email';
  end if;
  -- Idempotent: already provisioned for this Auth0 identity.
  if exists (select 1 from public.profiles where auth0_sub = p_sub) then
    return;
  end if;
  -- Link a pre-existing (Supabase-Auth-era) profile by email ONLY when Auth0 has
  -- VERIFIED the address. Without this gate an attacker could register an unverified
  -- Auth0 identity using someone else's email (e.g. the admin's) and bind their own sub
  -- to that profile — an account/privilege-escalation takeover. Only the real owner can
  -- pass email verification. Target exactly one unclaimed row (oldest) so duplicate legacy
  -- emails can't raise a unique-violation on auth0_sub and lock the user out.
  if p_email_verified then
    -- FOR UPDATE locks the chosen row: a concurrent provision for the same email blocks,
    -- then re-evaluates the `auth0_sub is null` qual against the now-claimed row, finds no
    -- match, and falls through to the duplicate-email raise instead of overwriting the link.
    select id into v_target
    from public.profiles
    where lower(email) = lower(p_email) and auth0_sub is null
    order by created_at
    limit 1
    for update;
    if v_target is not null then
      update public.profiles
         set auth0_sub  = p_sub,
             full_name  = coalesce(full_name, p_full_name),
             avatar_url = coalesce(avatar_url, p_avatar)
       where id = v_target;
      return;
    end if;
  end if;
  -- Never fork a second profile for an email that already belongs to one (prevents
  -- duplicate accounts + repeat free trials when the same person signs in via another
  -- connection, and prevents an unverified identity shadowing an existing account).
  -- Configure Auth0 account-linking so one human maps to one sub and this never fires.
  if exists (select 1 from public.profiles where lower(email) = lower(p_email)) then
    raise exception 'email already associated with an account';
  end if;
  -- Brand-new signup: 14-day Pro reverse-trial (matches handle_new_user, 0018).
  insert into public.profiles (email, full_name, avatar_url, auth0_sub, plan, trial_ends_at)
  values (p_email, p_full_name, p_avatar, p_sub, 'pro', now() + interval '14 days')
  on conflict (auth0_sub) do nothing;
end;
$$;
revoke all on function public.provision_profile(text, text, boolean, text, text) from public, anon, authenticated;
grant execute on function public.provision_profile(text, text, boolean, text, text) to service_role;

-- ── 9. Retire the auth.users triggers ───────────────────────────────────────
-- Auth0 users never create an auth.users row, so these never fire again. The
-- functions themselves are left in place (harmless, EXECUTE already revoked) so a
-- rollback that restores the triggers needs no function redefinition.
drop trigger if exists on_auth_user_created on auth.users;
drop trigger if exists on_auth_user_email_changed on auth.users;
