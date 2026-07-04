-- Fix the Founder-cap TOCTOU oversell. The Founder tier is a hard-capped, limited offer, but the
-- cap was enforced in create-checkout-session by COUNTING confirmed subscription rows — and those
-- rows are only written by stripe-webhook AFTER payment. So a concurrent burst of buyers all pass
-- "count < cap" during the pre-webhook window and oversell the offer (a classic time-of-check /
-- time-of-use race). This adds an ATOMIC seat reservation claimed BEFORE Checkout is created.

-- Short-lived seat holds. Service-role only (RLS on, no policies) — never reachable over the API.
create table if not exists public.founder_reservations (
  user_id uuid primary key references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now()
);
alter table public.founder_reservations enable row level security;

-- Atomically claim a Founder seat for p_user_id if the offer isn't full. Returns true if the
-- caller now holds a seat (a fresh/refreshed reservation, or an already-confirmed Founder
-- subscription), false if sold out. SECURITY DEFINER so the Edge Function (service role) can call
-- it; not granted to API roles. A transaction-scoped advisory lock serializes concurrent claimers
-- so the count-then-insert is atomic and two callers can't both read "count < cap".
create or replace function public.claim_founder_seat(p_user_id uuid, p_price_id text, p_cap integer)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_taken integer;
begin
  perform pg_advisory_xact_lock(hashtext('pp_founder_seat'));

  -- Already a confirmed Founder subscriber? They hold their seat; let them proceed idempotently
  -- (e.g. a retried checkout) without consuming another, and drop any stale hold.
  if exists (
    select 1 from public.subscriptions s
    where s.user_id = p_user_id
      and s.price_id = p_price_id
      and s.status in ('active', 'trialing')
  ) then
    delete from public.founder_reservations where user_id = p_user_id;
    return true;
  end if;

  -- Seats taken (excluding this caller, who is about to (re)claim) = confirmed Founder subs +
  -- fresh outstanding reservations, minus any reserver who has since become a confirmed Founder
  -- subscriber (so a hold never double-counts a buyer).
  select
    (select count(*) from public.subscriptions s
       where s.price_id = p_price_id and s.status in ('active', 'trialing'))
    + (select count(*) from public.founder_reservations r
         where r.user_id <> p_user_id
           and r.created_at > now() - interval '20 minutes'
           and not exists (
             select 1 from public.subscriptions s2
             where s2.user_id = r.user_id
               and s2.price_id = p_price_id
               and s2.status in ('active', 'trialing')
           ))
  into v_taken;

  if v_taken >= p_cap then
    return false;
  end if;

  insert into public.founder_reservations (user_id, created_at)
  values (p_user_id, now())
  on conflict (user_id) do update set created_at = now();
  return true;
end;
$$;
revoke all on function public.claim_founder_seat(uuid, text, integer) from public, anon, authenticated;
grant execute on function public.claim_founder_seat(uuid, text, integer) to service_role;

-- Make the public seat counter reservation-aware so it never advertises a seat the gate above
-- would then refuse. Mirrors 0017 but counts confirmed subs + fresh, not-yet-confirmed holds.
create or replace function public.get_pricing_status()
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v jsonb;
  cap int;
  fid text;
  taken int := 0;
begin
  select value into v from public.app_settings where key = 'pricing';
  v := coalesce(v, '{}'::jsonb);
  cap := coalesce(nullif(v->>'founder_cap','')::int, 200);
  fid := v->>'founder_price_id';
  if fid is not null then
    select
      (select count(*) from public.subscriptions
         where price_id = fid and status in ('active', 'trialing'))
      + (select count(*) from public.founder_reservations r
           where r.created_at > now() - interval '20 minutes'
             and not exists (
               select 1 from public.subscriptions s
               where s.user_id = r.user_id and s.price_id = fid and s.status in ('active', 'trialing')
             ))
    into taken;
  end if;
  return jsonb_build_object(
    'annual_available', (v->>'annual_price_id') is not null,
    'founder_available', fid is not null,
    'founder_cap', cap,
    'founder_remaining', greatest(0, cap - taken)
  );
end;
$$;
grant execute on function public.get_pricing_status() to anon, authenticated;

-- Reap expired reservations so the table stays tiny.
create or replace function public.cleanup_founder_reservations()
returns void language sql security definer set search_path = '' as $$
  delete from public.founder_reservations where created_at < now() - interval '1 hour';
$$;
revoke all on function public.cleanup_founder_reservations() from public, anon, authenticated;

create extension if not exists pg_cron;
do $$ begin perform cron.unschedule('cleanup-founder-reservations'); exception when others then null; end $$;
select cron.schedule('cleanup-founder-reservations', '*/30 * * * *', 'select public.cleanup_founder_reservations();');
