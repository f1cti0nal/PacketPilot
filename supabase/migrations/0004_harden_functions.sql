-- Hardening (addresses security-advisor findings from the RLS task):
-- handle_new_user and guard_profile_privileged_columns are TRIGGER functions,
-- invoked by the trigger path only. They must not be exposed on the PostgREST
-- RPC surface, so revoke direct EXECUTE from all roles including PUBLIC
-- (PostgreSQL grants EXECUTE to PUBLIC by default; both named-role and PUBLIC
-- revokes are required to fully close the RPC surface).
-- is_admin() intentionally KEEPS execute for authenticated: every RLS policy
-- evaluates it under the calling user's role.
revoke execute on function public.handle_new_user() from public, anon, authenticated;
revoke execute on function public.guard_profile_privileged_columns() from public, anon, authenticated;

-- Clear the mutable-search_path advisory on the trigger-only updated_at helper.
-- It only sets new.updated_at = now(); pinning search_path is safe (now() is in pg_catalog).
alter function public.set_updated_at() set search_path = '';
