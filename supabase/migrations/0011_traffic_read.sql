-- Admin Live Traffic reads. SECURITY INVOKER so the caller's analytics_select_admin RLS
-- applies (admins only); search_path pinned.
create or replace view public.admin_traffic_stats
with (security_invoker = true) as
select
  count(distinct session_id) filter (where created_at >= now() - interval '24 hours') as active_today,
  count(*) filter (where created_at >= now() - interval '24 hours') as pageviews_today,
  count(distinct session_id) filter (where created_at >= now() - interval '24 hours' and user_id is not null) as authed_today,
  count(distinct session_id) filter (where created_at >= now() - interval '24 hours' and user_id is null) as anon_today
from public.analytics_events;

create or replace function public.admin_pageviews_by_day(days integer)
returns table(day date, count bigint)
language sql stable security invoker set search_path = '' as $$
  select d::date as day, count(e.id) as count
  from generate_series((current_date - (greatest(days, 1) - 1)), current_date, interval '1 day') as d
  left join public.analytics_events e
    on e.created_at >= d and e.created_at < d + interval '1 day'
  group by d order by d
$$;

create or replace function public.admin_top_paths(days integer, lim integer)
returns table(path text, count bigint)
language sql stable security invoker set search_path = '' as $$
  select e.path, count(*) as count
  from public.analytics_events e
  where e.created_at > now() - make_interval(days => greatest(days, 1))
  group by e.path order by count(*) desc, e.path
  limit greatest(lim, 1)
$$;
