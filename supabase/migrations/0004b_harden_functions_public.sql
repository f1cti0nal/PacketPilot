-- The previous revoke targeted named roles, but PUBLIC still held EXECUTE
-- (the default PostgreSQL grant). Revoke from PUBLIC to fully close the RPC surface.
revoke execute on function public.handle_new_user() from public;
revoke execute on function public.guard_profile_privileged_columns() from public;
