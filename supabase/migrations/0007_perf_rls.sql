-- Performance hardening of the RLS layer (addresses advisor findings auth_rls_initplan
-- + multiple_permissive_policies + unindexed_foreign_keys). Behaviour is unchanged;
-- only evaluation cost and policy shape change. Re-verified with the RLS simulations.

-- 1. Wrap auth.uid()/is_admin() in scalar subselects so the planner evaluates them
--    ONCE per query instead of once per row (auth_rls_initplan).
drop policy profiles_select_self_or_admin on public.profiles;
create policy profiles_select_self_or_admin on public.profiles
  for select to authenticated
  using (id = (select auth.uid()) or (select public.is_admin()));

drop policy profiles_update_self_or_admin on public.profiles;
create policy profiles_update_self_or_admin on public.profiles
  for update to authenticated
  using (id = (select auth.uid()) or (select public.is_admin()))
  with check (id = (select auth.uid()) or (select public.is_admin()));

drop policy profiles_delete_admin on public.profiles;
create policy profiles_delete_admin on public.profiles
  for delete to authenticated
  using ((select public.is_admin()));

drop policy subscriptions_select_self_or_admin on public.subscriptions;
create policy subscriptions_select_self_or_admin on public.subscriptions
  for select to authenticated
  using (user_id = (select auth.uid()) or (select public.is_admin()));

-- 2. feature_flags: split the FOR ALL admin policy into insert/update/delete so it no
--    longer overlaps the authenticated SELECT policy (multiple_permissive_policies).
drop policy feature_flags_write_admin on public.feature_flags;
create policy feature_flags_insert_admin on public.feature_flags
  for insert to authenticated with check ((select public.is_admin()));
create policy feature_flags_update_admin on public.feature_flags
  for update to authenticated using ((select public.is_admin())) with check ((select public.is_admin()));
create policy feature_flags_delete_admin on public.feature_flags
  for delete to authenticated using ((select public.is_admin()));

-- 3. Wrap is_admin() in the remaining admin-only policies too (consistency + initplan).
drop policy app_settings_admin on public.app_settings;
create policy app_settings_admin on public.app_settings
  for all to authenticated using ((select public.is_admin())) with check ((select public.is_admin()));

drop policy analytics_select_admin on public.analytics_events;
create policy analytics_select_admin on public.analytics_events
  for select to authenticated using ((select public.is_admin()));
drop policy analytics_delete_admin on public.analytics_events;
create policy analytics_delete_admin on public.analytics_events
  for delete to authenticated using ((select public.is_admin()));

drop policy audit_select_admin on public.audit_log;
create policy audit_select_admin on public.audit_log
  for select to authenticated using ((select public.is_admin()));
drop policy audit_insert_admin on public.audit_log;
create policy audit_insert_admin on public.audit_log
  for insert to authenticated with check ((select public.is_admin()));

-- 4. Covering indexes for the foreign keys flagged by the linter (unindexed_foreign_keys).
create index if not exists analytics_events_user_id_idx on public.analytics_events(user_id);
create index if not exists app_settings_updated_by_idx  on public.app_settings(updated_by);
create index if not exists audit_log_actor_id_idx        on public.audit_log(actor_id);
create index if not exists feature_flags_updated_by_idx  on public.feature_flags(updated_by);
