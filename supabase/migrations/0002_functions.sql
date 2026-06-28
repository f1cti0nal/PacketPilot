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
