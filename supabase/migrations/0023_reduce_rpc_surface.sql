-- Attack-surface reduction (post-Auth0-cutover hardening).
-- The admin analytics RPCs are SECURITY INVOKER over security_invoker views, so RLS already
-- zeroes their output for non-admins (verified: an anon caller reads all-zero KPIs). But they
-- were still EXECUTE-able by the anon role over /rest/v1/rpc for no reason. Revoke anon EXECUTE
-- (the admin dashboard calls them as an authenticated admin; RLS stays the data boundary).
revoke execute on function public.admin_signups_by_day(integer) from anon;
revoke execute on function public.admin_subscriptions_by_day(integer) from anon;
revoke execute on function public.admin_pageviews_by_day(integer) from anon;
revoke execute on function public.admin_top_paths(integer, integer) from anon;

-- set_updated_at() is a trigger function; it runs in the trigger context regardless of grants,
-- so nothing legitimately calls it over the Data API. Remove it from the exposed RPC surface.
revoke execute on function public.set_updated_at() from public, anon, authenticated;
