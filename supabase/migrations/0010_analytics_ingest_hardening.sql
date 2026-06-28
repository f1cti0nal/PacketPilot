drop policy if exists analytics_insert_any on public.analytics_events;

-- Canonical-path + privacy guard shared by both roles: only the route allowlist shape,
-- and the public roles may NOT write referrer / user_agent / country (kept NULL).
-- (Service-role seed inserts bypass RLS, so existing/seeded rows are unaffected.)
create policy analytics_insert_anon on public.analytics_events
  for insert to anon
  with check (
    user_id is null
    and length(path) <= 32
    and (path = '/' or path ~ '^/(app|admin)#[a-z]+$')
    and referrer is null and user_agent is null and country is null
  );

create policy analytics_insert_authenticated on public.analytics_events
  for insert to authenticated
  with check (
    (user_id is null or user_id = (select auth.uid()))
    and length(path) <= 32
    and (path = '/' or path ~ '^/(app|admin)#[a-z]+$')
    and referrer is null and user_agent is null and country is null
  );

-- Per-session burst cap (accidental render-loop / abuse backstop). SECURITY DEFINER so it
-- can count rows the anon role can't SELECT; search_path pinned; EXECUTE revoked (trigger-only).
create or replace function public.analytics_rate_limit()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if (select count(*) from public.analytics_events
        where session_id = new.session_id and created_at > now() - interval '1 minute') >= 60 then
    raise exception 'analytics rate limit exceeded for session';
  end if;
  return new;
end;
$$;
revoke execute on function public.analytics_rate_limit() from public, anon, authenticated;

drop trigger if exists analytics_rate_limit on public.analytics_events;
create trigger analytics_rate_limit
before insert on public.analytics_events
for each row execute function public.analytics_rate_limit();
