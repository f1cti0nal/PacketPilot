-- Remove the reverse-trial entirely. New signups now start on the FREE plan (not a 14-day Pro
-- trial), and the product has only two plans: Free and Pro. Existing active trials are converted
-- to Free (none had converted to a paid subscription). The `trial_ends_at` column is retained
-- (nullable, now always null) to avoid a destructive schema change; nothing reads it anymore.

-- 1. New signups start on Free, with no trial.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email, full_name, avatar_url, plan)
  values (
    new.id,
    new.email,
    new.raw_user_meta_data ->> 'full_name',
    new.raw_user_meta_data ->> 'avatar_url',
    'free'
  )
  on conflict (id) do nothing;
  return new;
end;
$$;
-- Trigger-only; keep it off the public API (mirrors 0020). create-or-replace preserves grants,
-- but re-assert to be explicit.
revoke execute on function public.handle_new_user() from public, anon, authenticated;

-- 2. Retire the trial-expiry cron + function — there are no trials left to expire.
do $$
begin
  perform cron.unschedule('expire-trials');
exception
  when others then null;
end
$$;
drop function if exists public.expire_trials();

-- 3. Convert the existing active trials to Free (none converted to a paid subscription). Any
--    trial date lingering on a paid account is simply cleared — the concept no longer exists.
update public.profiles p
set plan = 'free', trial_ends_at = null
where p.trial_ends_at is not null
  and not exists (
    select 1 from public.subscriptions s
    where s.user_id = p.id and s.status in ('active', 'trialing')
  );
update public.profiles set trial_ends_at = null where trial_ends_at is not null;
