-- Security hardening from the post-Auth0-migration advisor pass.

-- 1. Least-privilege on SECURITY DEFINER functions that were reachable over the PostgREST
--    RPC surface by anon/public. 0019's `create or replace` reset some ACLs to the default
--    PUBLIC grant, and earlier revokes targeted anon/authenticated but not PUBLIC (so anon
--    inherited EXECUTE via PUBLIC). These are cron-/trigger-only and must not be callable.
revoke execute on function public.expire_trials() from public, anon, authenticated;
revoke execute on function public.sync_profile_email() from public, anon, authenticated;
revoke execute on function public.handle_new_user() from public, anon, authenticated;

-- is_admin() MUST stay executable by `authenticated` (every RLS policy calls it under the
-- caller's role) — but not by anon/public.
revoke execute on function public.is_admin() from public, anon;
grant execute on function public.is_admin() to authenticated;

-- 2. Public `avatars` bucket: object URLs are served by the storage CDN without RLS, so the
--    broad SELECT policy only enabled clients to LIST every file (leaking profile ids). Drop
--    it — avatar_url rendering (public URLs) is unaffected; owner insert/update/delete remain.
drop policy if exists "avatars public read" on storage.objects;
