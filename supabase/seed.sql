-- PacketPilot demo seed data (NON-PRODUCTION).
-- Idempotent: re-running skips rows that already exist. Apply via the Supabase MCP
-- execute_sql, `supabase db reset` (which runs this file), or psql. Requires the
-- pgcrypto functions crypt()/gen_salt() (available by default on Supabase).
--
-- We seed real auth.users so the on_auth_user_created trigger creates their
-- profiles; this gives the admin dashboard (later phase) realistic data without a
-- service-role key. These are demo logins (all share the password below) — never
-- use this file against a production project.

-- 1. Demo end users. The trigger public.handle_new_user() creates a matching
--    public.profiles row from the email + raw_user_meta_data.full_name.
insert into auth.users
  (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
   raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
   confirmation_token, email_change, email_change_token_new, recovery_token)
select
  '00000000-0000-0000-0000-000000000000', gen_random_uuid(), 'authenticated', 'authenticated',
  d.email, crypt('DemoPass!23', gen_salt('bf')), now(),
  '{"provider":"email","providers":["email"]}'::jsonb,
  jsonb_build_object('full_name', d.full_name), now(), now(),
  '', '', '', ''
from (values
  ('demo+alice@packetpilot.test','Alice Smith'),
  ('demo+bob@packetpilot.test','Bob Johnson'),
  ('demo+carol@packetpilot.test','Carol Williams'),
  ('demo+dave@packetpilot.test','Dave Brown'),
  ('demo+erin@packetpilot.test','Erin Davis')
) as d(email, full_name)
where not exists (select 1 from auth.users u where u.email = d.email);

-- 2. Plans + a realistic signup spread (created_at). auth.uid() is null in this
--    seed/migration context, so the profiles privilege guard permits the update.
update public.profiles p
set plan = d.plan::public.user_plan,
    created_at = now() - (d.age_days || ' days')::interval
from (values
  ('demo+alice@packetpilot.test','pro', 2),
  ('demo+bob@packetpilot.test','free', 9),
  ('demo+carol@packetpilot.test','pro', 1),
  ('demo+dave@packetpilot.test','free', 20),
  ('demo+erin@packetpilot.test','pro', 4)
) as d(email, plan, age_days)
where p.email = d.email;

-- 3. Active subscriptions for the Pro users (Phase 2 webhooks replace this).
insert into public.subscriptions
  (user_id, stripe_customer_id, stripe_subscription_id, price_id, status, amount_cents, currency, current_period_end)
select p.id,
  'cus_demo_' || left(p.id::text, 8),
  'sub_demo_' || left(p.id::text, 8),
  'price_demo_pro', 'active', 1900, 'usd', now() + interval '30 days'
from public.profiles p
where p.plan = 'pro'
  and not exists (select 1 from public.subscriptions s where s.user_id = p.id);

-- 4. Feature flags.
insert into public.feature_flags (key, description, enabled, plan_gate) values
  ('ai_assist',          'AI analyst assistant',        true, null),
  ('reputation',         'IP/domain reputation lookups',true, null),
  ('pcap_export',        'PCAP carving/export',         true, 'pro'),
  ('multi_capture_diff', 'Compare two captures',        true, 'pro')
on conflict (key) do nothing;

-- 5. App settings.
insert into public.app_settings (key, value, description) values
  ('branding', '{"product_name":"PacketPilot"}'::jsonb, 'Product branding'),
  ('limits',   '{"max_upload_mb":64}'::jsonb,           'Client upload limits (informational)')
on conflict (key) do nothing;

-- 6. Anonymous demo traffic (200 events over 48h) so the dashboard's
--    "active today" + traffic views render.
insert into public.analytics_events (session_id, path, referrer, country, user_agent, created_at)
select
  'demo-' || g,
  (array['/','/app','/app/flows','/app/findings'])[1 + (g % 4)],
  null,
  (array['US','DE','GB','IN'])[1 + (g % 4)],
  'seed',
  now() - ((g % 48) || ' hours')::interval
from generate_series(1, 200) as g
where not exists (select 1 from public.analytics_events e where e.user_agent = 'seed');
