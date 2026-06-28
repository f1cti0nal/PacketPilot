# Stripe billing Edge Functions

Three functions sync Stripe ⇄ the app:
- `create-checkout-session` (JWT required) — starts a Pro Checkout.
- `create-portal-session` (JWT required) — opens the Billing Portal.
- `stripe-webhook` (JWT OFF — Stripe-signed) — upserts `subscriptions` + sets `profiles.plan`.

## Setup (test mode)
1. Stripe: create a Pro product with a $19/month recurring price; note the price id (`price_…`).
2. Set Edge Function secrets (Supabase dashboard → Edge Functions → Secrets, or `supabase secrets set`):
   `STRIPE_SECRET_KEY=sk_test_…`, `STRIPE_PRICE_PRO=price_…`, `STRIPE_WEBHOOK_SECRET=whsec_…`.
   (`SUPABASE_URL` / `SUPABASE_ANON_KEY` / `SUPABASE_SERVICE_ROLE_KEY` are auto-injected.)
3. Deploy all three (Supabase MCP `deploy_edge_function` or `supabase functions deploy`); webhook with `--no-verify-jwt`.
4. Stripe → Developers → Webhooks: add the deployed `stripe-webhook` URL; subscribe to
   `checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted`; copy the signing secret into `STRIPE_WEBHOOK_SECRET`.

## Verify
Upgrade in-app with test card 4242 4242 4242 4242 → `profiles.plan` becomes `pro`; cancel in the portal → `free`.
