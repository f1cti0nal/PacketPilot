-- Server-side per-user rate limiting for the operator-funded Edge Function proxies
-- (ai-proxy, reputation-proxy). Without this, one authenticated account can hammer the
-- proxies and drain the operator's AI / AbuseIPDB / VirusTotal / GreyNoise keys.

-- Fixed-window counter keyed by "<fn>:<auth0_sub>". Service-role only; RLS on (no policies)
-- so it's never reachable over the Data API.
create table if not exists public.rate_limits (
  key text not null,
  window_start timestamptz not null,
  count integer not null default 0,
  primary key (key, window_start)
);
alter table public.rate_limits enable row level security;

-- Atomically bump the caller's counter for the current window; returns true while under the
-- cap. SECURITY DEFINER so the Edge Function (service role) can call it; not granted to the
-- API roles.
create or replace function public.check_rate_limit(p_key text, p_max integer, p_window_seconds integer)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_window timestamptz := to_timestamp(floor(extract(epoch from now()) / p_window_seconds) * p_window_seconds);
  v_count integer;
begin
  insert into public.rate_limits (key, window_start, count)
  values (p_key, v_window, 1)
  on conflict (key, window_start) do update set count = public.rate_limits.count + 1
  returning count into v_count;
  return v_count <= p_max;
end;
$$;
revoke all on function public.check_rate_limit(text, integer, integer) from public, anon, authenticated;
grant execute on function public.check_rate_limit(text, integer, integer) to service_role;

-- Reap old windows so the table stays tiny.
create or replace function public.cleanup_rate_limits()
returns void language sql security definer set search_path = '' as $$
  delete from public.rate_limits where window_start < now() - interval '1 hour';
$$;
revoke all on function public.cleanup_rate_limits() from public, anon, authenticated;

create extension if not exists pg_cron;
do $$ begin perform cron.unschedule('cleanup-rate-limits'); exception when others then null; end $$;
select cron.schedule('cleanup-rate-limits', '*/15 * * * *', 'select public.cleanup_rate_limits();');
