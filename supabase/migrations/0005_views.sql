-- security_invoker => the caller's RLS applies to the underlying tables, so this
-- view returns correct totals only for admins (who can read all rows). A later
-- admin dashboard phase calls it from an admin context only.
create view public.admin_dashboard_stats
with (security_invoker = true) as
select
  (select count(*) from public.profiles)                              as total_users,
  (select count(*) from public.profiles where plan = 'pro')           as paid_users,
  (select count(*) from public.profiles where plan = 'free')          as free_users,
  (select count(distinct session_id) from public.analytics_events
     where created_at >= now() - interval '24 hours')                 as active_today,
  (select coalesce(sum(amount_cents), 0) from public.subscriptions
     where status = 'active')                                         as mrr_cents,
  (select count(*) from public.profiles
     where created_at >= now() - interval '7 days')                   as signups_7d;
