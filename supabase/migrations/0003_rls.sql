alter table public.profiles         enable row level security;
alter table public.subscriptions    enable row level security;
alter table public.feature_flags    enable row level security;
alter table public.app_settings     enable row level security;
alter table public.analytics_events enable row level security;
alter table public.audit_log        enable row level security;

-- profiles: own row or admin (read/update); admin delete; inserts only via the trigger (no policy).
create policy profiles_select_self_or_admin on public.profiles
  for select to authenticated using (id = auth.uid() or public.is_admin());
create policy profiles_update_self_or_admin on public.profiles
  for update to authenticated using (id = auth.uid() or public.is_admin())
  with check (id = auth.uid() or public.is_admin());
create policy profiles_delete_admin on public.profiles
  for delete to authenticated using (public.is_admin());

-- subscriptions: user reads own; admin reads all; writes are service-role only
-- (service-role bypasses RLS, so no write policy is needed).
create policy subscriptions_select_self_or_admin on public.subscriptions
  for select to authenticated using (user_id = auth.uid() or public.is_admin());

-- feature_flags: authenticated read; admin write.
create policy feature_flags_select_authenticated on public.feature_flags
  for select to authenticated using (true);
create policy feature_flags_write_admin on public.feature_flags
  for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- app_settings: admin only.
create policy app_settings_admin on public.app_settings
  for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- analytics_events: anon/authenticated may INSERT (page-view ingestion); read is admin-only.
create policy analytics_insert_any on public.analytics_events
  for insert to anon, authenticated with check (true);
create policy analytics_select_admin on public.analytics_events
  for select to authenticated using (public.is_admin());
create policy analytics_delete_admin on public.analytics_events
  for delete to authenticated using (public.is_admin());

-- audit_log: admin read + admin insert.
create policy audit_select_admin on public.audit_log
  for select to authenticated using (public.is_admin());
create policy audit_insert_admin on public.audit_log
  for insert to authenticated with check (public.is_admin());
