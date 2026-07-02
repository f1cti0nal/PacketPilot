-- 0023 revoked admin-RPC EXECUTE from `anon`, but these functions carry the default PUBLIC
-- EXECUTE grant, so anon still inherited EXECUTE via PUBLIC. Revoke from PUBLIC (also drops it
-- from anon + authenticated), then re-grant to `authenticated` so the admin dashboard (an
-- authenticated admin; RLS gates the data) can still call them. Anon can no longer reach them.
revoke execute on function public.admin_signups_by_day(integer) from public;
revoke execute on function public.admin_subscriptions_by_day(integer) from public;
revoke execute on function public.admin_pageviews_by_day(integer) from public;
revoke execute on function public.admin_top_paths(integer, integer) from public;

grant execute on function public.admin_signups_by_day(integer) to authenticated;
grant execute on function public.admin_subscriptions_by_day(integer) to authenticated;
grant execute on function public.admin_pageviews_by_day(integer) to authenticated;
grant execute on function public.admin_top_paths(integer, integer) to authenticated;
