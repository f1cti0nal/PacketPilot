-- Billing v2: multi-price (monthly / annual / founder) + a public Founder-seat counter.
-- Price IDs live in an admin-editable app_settings row (no redeploy to change prices);
-- monthly falls back to the STRIPE_PRICE_PRO env var in the Edge Function for back-compat.

insert into public.app_settings (key, value, description) values (
  'pricing',
  '{"monthly_price_id":null,"annual_price_id":null,"founder_price_id":null,"founder_cap":200}'::jsonb,
  'Stripe price IDs per plan + Founder seat cap (set the live price IDs here after creating them in Stripe)'
) on conflict (key) do nothing;

-- Public, secret-safe pricing status: which paid plans are available + live Founder seats
-- remaining. Never returns the raw Stripe price IDs (checkout resolves those server-side).
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
    select count(*) into taken
      from public.subscriptions
      where price_id = fid and status in ('active', 'trialing');
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
