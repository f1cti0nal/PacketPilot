-- RLS behavioral verification for the PacketPilot backend foundation.
-- Run against the DEV project AFTER applying all migrations + seed.sql (it needs the
-- demo users). Each block assumes a role + JWT claims, asserts visibility, then ROLLS
-- BACK so nothing persists. The admin block promotes a demo user inside its transaction
-- and rolls that back too. Resolves user ids by demo email, so it is runnable as-is.
--
-- Last verified after migration 0007 (controller, project brkztcfhmrjjnbjzycie):
--   (a) non-admin: profiles=1, analytics=0, app_settings=0, feature_flags=4
--   (b) admin:     profiles=5, analytics=200
--   (c) anon:      profiles=0, feature_flags=0
--   (d) anon insert: 1 row (rolled back)
--   (e) escalation: ERROR "not authorized to change role/plan/status"

-- (a) Non-admin sees only their own profile; restricted tables return 0; flags readable.
begin;
  select set_config('request.jwt.claims',
    json_build_object('sub', (select id from public.profiles where email='demo+bob@packetpilot.test'),
                      'role','authenticated')::text, true);
  set local role authenticated;
  select 'a:non_admin_profiles'  as check, count(*) from public.profiles;          -- expect 1
  select 'a:non_admin_analytics' as check, count(*) from public.analytics_events;  -- expect 0
  select 'a:non_admin_settings'  as check, count(*) from public.app_settings;      -- expect 0
  select 'a:non_admin_flags'     as check, count(*) from public.feature_flags;     -- expect 4 (authenticated read)
rollback;

-- (b) Admin sees all profiles + analytics (promotion rolled back).
begin;
  update public.profiles set role='admin' where email='demo+alice@packetpilot.test';
  select set_config('request.jwt.claims',
    json_build_object('sub', (select id from public.profiles where email='demo+alice@packetpilot.test'),
                      'role','authenticated')::text, true);
  set local role authenticated;
  select 'b:admin_profiles'  as check, count(*) from public.profiles;          -- expect all (e.g. 5)
  select 'b:admin_analytics' as check, count(*) from public.analytics_events;  -- expect >0 (e.g. 200)
rollback;

-- (c) Anon is blocked from reading restricted/authenticated-only tables.
begin;
  set local role anon;
  select 'c:anon_profiles' as check, count(*) from public.profiles;       -- expect 0
  select 'c:anon_flags'    as check, count(*) from public.feature_flags;  -- expect 0 (select is authenticated-only)
rollback;

-- (d) Anon CAN insert an analytics event (page-view ingestion path).
begin;
  set local role anon;
  insert into public.analytics_events (session_id, path) values ('rls-test', '/');  -- expect success
  reset role;
  select 'd:anon_insert_rows' as check, count(*) from public.analytics_events where session_id='rls-test'; -- expect 1
rollback;

-- (e) Privilege escalation is blocked: a non-admin self-promoting raises an exception.
begin;
  select set_config('request.jwt.claims',
    json_build_object('sub', (select id from public.profiles where email='demo+bob@packetpilot.test'),
                      'role','authenticated')::text, true);
  set local role authenticated;
  update public.profiles set role='admin'
    where id = (select id from public.profiles where email='demo+bob@packetpilot.test');
  -- expect ERROR: not authorized to change role/plan/status
rollback;
