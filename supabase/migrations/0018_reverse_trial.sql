-- Reverse-trial: every NEW signup gets 14 days of Pro (no card), then auto-downgrades to Free
-- unless they convert to a paid subscription. Existing users are untouched (null trial).

alter table public.profiles add column if not exists trial_ends_at timestamptz;

-- New profiles start on a 14-day Pro trial.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email, full_name, avatar_url, plan, trial_ends_at)
  values (
    new.id,
    new.email,
    new.raw_user_meta_data ->> 'full_name',
    new.raw_user_meta_data ->> 'avatar_url',
    'pro',
    now() + interval '14 days'
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

-- Downgrade expired trials that never converted. SECURITY DEFINER + auth.uid() is null in the
-- cron context, so the privileged-column guard (0002) allows the plan change.
create or replace function public.expire_trials()
returns void
language sql
security definer
set search_path = ''
as $$
  update public.profiles p
  set plan = 'free', trial_ends_at = null
  where p.plan = 'pro'
    and p.trial_ends_at is not null
    and p.trial_ends_at < now()
    and not exists (
      select 1 from public.subscriptions s
      where s.user_id = p.id and s.status in ('active', 'trialing')
    );
$$;
revoke execute on function public.expire_trials() from anon, authenticated;

-- Run the downgrade every 30 minutes (client-side effective-plan handles the instant UI gate;
-- this keeps profiles.plan truthful for admin metrics).
create extension if not exists pg_cron;
do $$
begin
  perform cron.unschedule('expire-trials');
exception
  when others then null;
end
$$;
select cron.schedule('expire-trials', '*/30 * * * *', 'select public.expire_trials();');
