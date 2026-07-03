-- Final Auth0 teardown. The Auth0 tenant + Supabase Third-Party Auth trust + edge/Vercel AUTH0_*
-- secrets have been removed and native GoTrue auth is confirmed, so the rollback scaffolding is
-- no longer needed. Drop the last dead Auth0-era artifacts.
--
-- KEPT: current_profile_id() — under native auth it returns auth.uid() and every RLS policy +
-- audit/stamp function resolves identity through it, so it is the LIVE identity resolver, not
-- Auth0 cruft. (Only provision_profile referenced auth0_sub; verified before this drop.)

drop function if exists public.provision_profile(text, text, boolean, text, text);
drop index if exists public.profiles_auth0_sub_key;
alter table public.profiles drop column if exists auth0_sub;
