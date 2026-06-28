# PacketPilot SaaS — Stripe Billing (Phase 2) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-28
**Branch:** `feat/stripe-billing`
**Sub-project:** 2 of the PacketPilot SaaS platform (depends on Phase 0 + Phase 1)

## Context

Phase 2 of the SaaS pivot. Phases 0 (backend), 1 (accounts), 3 (admin shell), 4 (admin dashboard) are merged + deployed. This phase makes the **Pro plan real**: paid subscriptions via Stripe, with the `subscriptions` table + `profiles.plan` kept in sync by a webhook.

Decisions locked with the user:
- **Real Stripe (test mode) keys provided at execution** — the user creates the account/price/webhook; the agent writes + deploys the code and runs a live test checkout.
- **Pro = a single recurring price, $19/month** (test mode).
- **Lapse policy: revert to `free` immediately** when the subscription status is not `active`/`trialing`.
- Email/account is required to subscribe (no anonymous billing).

**No new DB migration** — the Phase-0 `subscriptions` table already has the needed columns (`user_id`, `stripe_customer_id`, `stripe_subscription_id`, `price_id`, `status`, `amount_cents`, `currency`, `current_period_end`, `cancel_at_period_end`) and `profiles.plan` exists. The work is Edge Functions + a small UI client + Stripe setup.

## Goal

Let an authenticated free user upgrade to Pro via Stripe Checkout, manage/cancel via the Stripe Billing Portal, and have their `profiles.plan` + `subscriptions` row reflect the live Stripe state through a signature-verified webhook.

## Invariants preserved

- **Privacy / local-first:** billing touches only account + subscription data. The WASM analysis path and capture handling are untouched; no capture data is associated with billing. Anonymous use stays fully functional (just no Pro).
- **Secrets never in the SPA:** `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_PRO`, and the service-role key live only in Supabase Edge Function secrets. The browser only ever calls our Edge Functions (authed) — it never sees a Stripe secret. (Stripe Checkout is a hosted redirect, so even the publishable key is unnecessary client-side.)
- **Stripe is the source of truth;** our tables mirror it via the webhook. The DB is never the authority on subscription state.
- **No engine/WASM/Tauri/admin change. No new SPA deps** (Stripe SDK is a Deno import inside Edge Functions only).

## Architecture

```
supabase/functions/
  _shared/
    cors.ts            # shared CORS headers + preflight helper
    stripe.ts          # Stripe client init (npm:stripe) + SubtleCrypto provider
    supabaseAdmin.ts   # service-role client factory (for webhook DB writes)
    plan.ts            # pure planForStatus(status): "free" | "pro"
  create-checkout-session/index.ts
  create-portal-session/index.ts
  stripe-webhook/index.ts
ui/src/auth/
  billing.ts           # startCheckout() / openPortal() over supabase.functions.invoke
  AccountMenu.tsx       # add "Upgrade to Pro" (free) / "Manage billing" (pro)
```

**Tech stack:** Supabase Edge Functions (Deno runtime, `Deno.serve`, `npm:stripe@^17`), the Phase-0 Supabase client + `supabase.functions.invoke` in the SPA, React + tokens + `lucide-react`. Vitest for the UI bits. Stripe (test mode).

## Edge Functions

All three: handle CORS preflight (`OPTIONS`), JSON, and return clear errors.

- **`create-checkout-session`** — requires a logged-in user (reads the `Authorization` bearer; `createClient(URL, ANON_KEY, { global: { headers: { Authorization } } }).auth.getUser()`). Looks up the user's `subscriptions.stripe_customer_id`; if none, `stripe.customers.create({ email, metadata: { supabase_user_id } })` and remembers it. Creates `stripe.checkout.sessions.create({ mode: "subscription", customer, line_items: [{ price: STRIPE_PRICE_PRO, quantity: 1 }], client_reference_id: user.id, success_url: \`${origin}/app?checkout=success\`, cancel_url: \`${origin}/app?checkout=cancel\` })`. Returns `{ url }`.
- **`create-portal-session`** — requires a logged-in user; resolves their `stripe_customer_id`; `stripe.billingPortal.sessions.create({ customer, return_url: \`${origin}/app\` })`. Returns `{ url }`. If the user has no customer yet, returns a 400 the UI surfaces.
- **`stripe-webhook`** — **no JWT** (Stripe calls it); verifies the signature with `await stripe.webhooks.constructEventAsync(rawBody, sig, STRIPE_WEBHOOK_SECRET, undefined, Stripe.createSubtleCryptoProvider())` (Deno requires the async variant + SubtleCrypto provider). Handles `checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted`: fetches the subscription, resolves the Supabase `user_id` (via the customer's `metadata.supabase_user_id` or the existing `subscriptions` row), then **with the service-role client** upserts the `subscriptions` row (status, price_id, amount_cents = price.unit_amount, currency, current_period_end, cancel_at_period_end, stripe_subscription_id) keyed on `stripe_subscription_id`, and sets `profiles.plan = planForStatus(status)`. Returns `200` quickly; unknown event types are acked and ignored. Idempotent (re-delivered events converge to the same state).

`_shared/plan.ts`:
```ts
export function planForStatus(status: string): "free" | "pro" {
  return status === "active" || status === "trialing" ? "pro" : "free";
}
```

## UI

- **`ui/src/auth/billing.ts`** — `startCheckout()` invokes `create-checkout-session` and does `window.location.assign(data.url)`; `openPortal()` likewise for the portal. Both return a `{ ok, error? }` so the menu can surface failures. Use `supabase.functions.invoke(name)` (it attaches the auth header automatically). Also `reconcileAfterCheckout()`: when `location.search` contains `checkout=success`, call `supabase.auth.refreshSession()` (which fires `onAuthStateChange` → `useSession` re-derives the now-`pro` profile) and strip the `checkout` query param from the URL. Called once from `App` on mount.
- **`AccountMenu.tsx`** (authed popover) gains: when `plan !== "pro"` → an **"Upgrade to Pro"** item → `startCheckout()`; when `plan === "pro"` → a **"Manage billing"** item → `openPortal()`. A transient busy/error line. Anonymous users are unchanged (Sign in only). On returning from Checkout with `?checkout=success`, the session's `profiles.plan` will already be `pro` once the webhook has run (the app re-reads it on auth refresh; a brief poll/refresh is acceptable — see Data flow).

## Secrets & Stripe-dashboard setup (execution-time runbook)

Performed with the user at execution (the agent cannot create a Stripe account):
1. **User:** create a Stripe account (test mode), create a **Pro** product with a **$19/month recurring price**, copy the **price id** (`price_...`) and the **test secret key** (`sk_test_...`).
2. **Agent:** deploy the three Edge Functions (Supabase MCP `deploy_edge_function`).
3. **User:** in Stripe → Developers → Webhooks, add an endpoint pointing at the deployed `stripe-webhook` URL, subscribe it to `checkout.session.completed` + `customer.subscription.updated` + `customer.subscription.deleted`, copy the **signing secret** (`whsec_...`).
4. **Agent/User:** set Edge Function secrets `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_PRO`, `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_URL` (Supabase dashboard → Edge Functions → Secrets, or `supabase secrets set`). The webhook function is configured with **JWT verification OFF** (Stripe can't send a Supabase JWT); the other two keep JWT verification ON.

## Data flow & error handling

Upgrade: account menu → `create-checkout-session` → redirect to Stripe → user pays (test card `4242…`) → Stripe fires `checkout.session.completed` → webhook upserts `subscriptions` + sets `profiles.plan='pro'` → user redirected to `/app?checkout=success` → `reconcileAfterCheckout()` calls `refreshSession()`, re-deriving the now-`pro` profile so the account menu updates (if the webhook is momentarily behind, a manual reload reconciles; test-mode webhooks are near-instant). Cancel via portal → `customer.subscription.updated`/`deleted` → webhook sets `plan='free'`. Webhook errors return non-2xx so Stripe retries; signature-failures return 400 and are logged. Function auth failures return 401. The UI surfaces invoke errors inline and never exposes secrets.

## Testing

- **Unit (Vitest):** `billing.ts` — `startCheckout`/`openPortal` invoke the right function and redirect to the returned URL, and surface an error when invoke fails; `reconcileAfterCheckout` calls `refreshSession` only when `checkout=success` is present and strips the param (mock `supabase` + stub `window.location`). `AccountMenu` — free authed shows "Upgrade to Pro" → calls startCheckout; pro authed shows "Manage billing" → calls openPortal.
- **Live (the meaningful test for the Edge Functions + the `planForStatus` mapping — no Deno harness in-repo):** real test checkout end-to-end (free → Upgrade → pay 4242 → returns Pro, `profiles.plan='pro'`); cancel in the portal → reverts to `free`; a Stripe **test webhook event** (or CLI `stripe trigger`) confirms signature verification + DB sync; verify the `subscriptions` row + `profiles.plan` via MCP `execute_sql`.
- Gate: UI suite green, coverage ≥ 80/70, `npx tsc -b` + `npm run build` clean. (Edge Functions are Deno; excluded from the Vitest/tsc UI build — they deploy via Supabase.)

## Out of scope (later / not now)

Proration & tier changes, annual pricing, tax/VAT, dunning/recovery emails, multiple paid tiers, coupon/trials UX, the admin Payments view (Phase 6 — read/refund/invoices), invoice history in-app, and production (live-mode) Stripe keys + going live (an ops step after test-mode validation).

## File manifest

**Create:** `supabase/functions/_shared/{cors,stripe,supabaseAdmin,plan}.ts`, `supabase/functions/create-checkout-session/index.ts`, `supabase/functions/create-portal-session/index.ts`, `supabase/functions/stripe-webhook/index.ts`, `ui/src/auth/billing.ts` (+ `billing.test.ts`), `supabase/functions/README.md` (the runbook). (`_shared/plan.ts` is a named Deno-side helper verified live, not via Vitest.)
**Modify:** `ui/src/auth/AccountMenu.tsx` (Upgrade/Manage items) + its test; `ui/src/App.tsx` (call `reconcileAfterCheckout()` on mount).
**No migration. No engine/WASM/Tauri/admin change. No new SPA deps.**
