-- Non-secret AI config the admin manages; the API key is a server secret (AI_API_KEY).
insert into public.app_settings (key, value, description) values
  ('ai_config', '{"enabled":false,"provider":"anthropic","model":"claude-opus-4-8"}'::jsonb,
   'AI Analyst configuration (provider/model). The API key is a server secret (see Environment).')
on conflict (key) do nothing;

-- Expose ai_config to the app (non-secret) by adding it to the public whitelist.
create or replace function public.get_public_settings()
returns jsonb language sql stable security definer set search_path = '' as $$
  select coalesce(jsonb_object_agg(key, value), '{}'::jsonb)
  from public.app_settings
  where key in ('announcement_banner', 'support_contact_email', 'pro_plan_price_display', 'ai_config');
$$;
grant execute on function public.get_public_settings() to anon, authenticated;
