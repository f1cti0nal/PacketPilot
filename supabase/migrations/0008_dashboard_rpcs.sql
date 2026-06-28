-- Admin dashboard time-series. SECURITY INVOKER => the caller's RLS applies
-- (admins see all rows; a non-admin only their own — no leak), which also avoids
-- the security-definer-executable advisor warnings. Zero-filled via generate_series
-- so charts render a continuous range.
create or replace function public.admin_signups_by_day(days integer default 14)
returns table(day date, count bigint)
language sql stable security invoker set search_path = ''
as $$
  select d::date as day, count(p.id) as count
  from generate_series(
    (now() - ((greatest(days, 1) - 1) || ' days')::interval)::date, now()::date, interval '1 day'
  ) as d
  left join public.profiles p on p.created_at::date = d::date
  group by d order by d;
$$;

create or replace function public.admin_subscriptions_by_day(days integer default 14)
returns table(day date, count bigint)
language sql stable security invoker set search_path = ''
as $$
  select d::date as day, count(s.id) as count
  from generate_series(
    (now() - ((greatest(days, 1) - 1) || ' days')::interval)::date, now()::date, interval '1 day'
  ) as d
  left join public.subscriptions s on s.created_at::date = d::date and s.status = 'active'
  group by d order by d;
$$;
