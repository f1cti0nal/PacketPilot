-- Non-secret reputation config the admin manages; the provider API keys are server secrets.
insert into public.app_settings (key, value, description) values
  ('rep_config', '{"enabled":false,"domain_enabled":false,"providers":[]}'::jsonb,
   'Threat-intel reputation config (enabled providers). API keys are server secrets (see Environment).')
on conflict (key) do nothing;

-- Expose rep_config to the app (non-secret) by adding it to the public whitelist.
create or replace function public.get_public_settings()
returns jsonb language sql stable security definer set search_path = '' as $$
  select coalesce(jsonb_object_agg(key, value), '{}'::jsonb)
  from public.app_settings
  where key in ('announcement_banner', 'support_contact_email', 'pro_plan_price_display', 'ai_config', 'rep_config');
$$;
grant execute on function public.get_public_settings() to anon, authenticated;
