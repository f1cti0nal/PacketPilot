# Stripe Go-Live Runbook

**For:** PacketPilot founder flipping billing from TEST → LIVE.
**Outcome:** Real cards charged, `checkout.session.completed` → `profiles.plan='pro'` → `subscriptions` row populated; cancel via portal → reverts to `'free'`.

**What is already built (do NOT re-code):**
- Three deployed Edge Functions: `create-checkout-session` (JWT ON), `create-portal-session` (JWT ON), `stripe-webhook` (JWT OFF — Stripe can't send a Supabase JWT).
- The webhook handles exactly: `checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted`. It upserts `public.subscriptions` (on conflict `stripe_subscription_id`) and sets `profiles.plan` to `pro` when status is `active`/`trialing`, else `free`.
- Checkout uses **one** price from the `STRIPE_PRICE_PRO` secret. Success URL `…/app?checkout=success`, cancel URL `…/app?checkout=cancel` (origin auto-detected, falls back to `https://packet-pilot.vercel.app`).
- Secrets the functions read: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_PRO`, plus `SUPABASE_URL` / `SUPABASE_ANON_KEY` / `SUPABASE_SERVICE_ROLE_KEY` (these last three already exist for the project — do not touch them).

> Throughout, `<project-ref>` is your Supabase project ref (the subdomain in your project URL, e.g. `abcd1234`). Your webhook URL is:
> **`https://<project-ref>.supabase.co/functions/v1/stripe-webhook`**

> ⚠️ **The #1 go-live mistake:** mixing TEST and LIVE keys. Everything below must be done with the Stripe Dashboard toggled to **LIVE mode** (top-right of the Dashboard / top-left of the sidebar — the "Test mode" switch must be **OFF**). A `sk_live_…` secret key and a `whsec_…` from a **test**-mode webhook will silently fail. Live keys start `sk_live_` / `pk_live_`; test keys start `sk_test_` / `pk_test_`.

---

## Step 0 — Pre-flight (one-time account readiness)

- [ ] In Stripe → **Settings → Business / Account**, complete business profile, bank account for payouts, and identity verification. **You cannot accept live charges until the account is "activated."** Check Dashboard home for any "Activate payments" / "Complete your profile" banner and clear it.
- [ ] Confirm the **same** Stripe account owns your existing test setup (so test learnings carry over).
- [ ] Have access to the **Supabase Dashboard** for project `<project-ref>` (you'll set Edge Function secrets there).

---

## Step 1 — Create the LIVE Product, Prices, and copy LIVE API keys

Toggle the Dashboard to **LIVE mode** first.

### 1a. Product + prices
- [ ] **Products → Add product.**
  - Name: `PacketPilot Pro`
  - Description: short, customer-facing (e.g. "Pro plan — full analysis, AI assist, reputation, exports").
- [ ] Add the **monthly** price:
  - Pricing model: **Standard / Recurring**, Amount **$19.00**, Billing period **Monthly**, Currency **USD**.
  - Save. **Copy its price ID** → record as `PRICE_PRO_MONTHLY = price_live_…`.
- [ ] On the **same product**, **+ Add another price** → **annual**:
  - Amount **$190.00**, Billing period **Yearly**, USD. Save. **Copy** → `PRICE_PRO_ANNUAL = price_live_…`.
- [ ] On the **same product**, **+ Add another price** → **Founder annual**:
  - Amount **$149.00**, Billing period **Yearly**, USD.
  - Optional: nickname it "Founder" so it's obvious in the Dashboard. Save. **Copy** → `PRICE_PRO_FOUNDER = price_live_…`.

> 📌 Record all three IDs somewhere safe. They look like `price_1Q…`. The product can carry many prices; each price is a distinct ID.

> ⚠️ **Single-price reality (read this now):** the deployed `create-checkout-session` hard-codes **one** price from `STRIPE_PRICE_PRO`. So **only the price you put in that secret will actually be sold** at launch. Monthly $19 is the recommended default. Annual and Founder will exist in Stripe but are **not reachable from the app** until the small code change in **Appendix A** ships. If you only need to go live with one plan today, that's fine — set `STRIPE_PRICE_PRO = PRICE_PRO_MONTHLY` and treat annual/founder as a fast follow.

### 1b. API keys
- [ ] **Developers → API keys** (still in LIVE mode):
  - **Copy the Secret key** → record `sk_live_…`. (Click "Reveal." This is shown once-ish — if you lose it, roll a new one.)
  - **Copy the Publishable key** → record `pk_live_…`.

> The SPA calls Stripe **only via the Edge Functions** (`supabase.functions.invoke` → redirect to the Stripe-hosted checkout URL). It does **not** use the publishable key in a client `Stripe()` call today, so `pk_live_…` is not strictly required for the flow to work — but copy it anyway so it's on record.

---

## Step 2 — Create the LIVE webhook endpoint

Still in **LIVE mode**.

- [ ] **Developers → Webhooks → Add endpoint.**
- [ ] **Endpoint URL:** `https://<project-ref>.supabase.co/functions/v1/stripe-webhook`
- [ ] **API version:** accept the default (your account's current version). The function reads the period end from both the new (item-level) and old (subscription-level) field, so either works.
- [ ] **Select events to listen to** → add exactly these three:
  - `checkout.session.completed`
  - `customer.subscription.updated`
  - `customer.subscription.deleted`
- [ ] **Add endpoint.**
- [ ] Open the endpoint → **Signing secret → Reveal** → **copy** → record `whsec_…`.

> ⚠️ This secret is **per endpoint and per mode**. The test-mode endpoint's secret will NOT validate live events. Make sure you copied the secret from the **LIVE** endpoint you just made.

---

## Step 3 — Set the LIVE Edge Function secrets in Supabase

In **Supabase Dashboard → Project `<project-ref>` → Edge Functions → Secrets** (a.k.a. "Manage secrets"), set/overwrite these three. (CLI alternative shown below.)

- [ ] `STRIPE_SECRET_KEY` = `sk_live_…`  (from Step 1b)
- [ ] `STRIPE_WEBHOOK_SECRET` = `whsec_…`  (from Step 2, the LIVE endpoint)
- [ ] `STRIPE_PRICE_PRO` = `price_live_…`  (from Step 1a — use **`PRICE_PRO_MONTHLY`** unless you've shipped Appendix A)

Leave `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY` **as-is** (already correct for the project).

CLI equivalent (run from the repo root; replace placeholders):
```bash
supabase secrets set \
  STRIPE_SECRET_KEY=sk_live_xxx \
  STRIPE_WEBHOOK_SECRET=whsec_xxx \
  STRIPE_PRICE_PRO=price_live_xxx \
  --project-ref <project-ref>
# Verify the names are present (values are masked):
supabase secrets list --project-ref <project-ref>
```

> ⚠️ **Whitespace bug:** when pasting into the Dashboard secret fields, ensure no trailing space/newline. A stray newline on `STRIPE_WEBHOOK_SECRET` is a classic cause of a **400 "Bad signature"** at the webhook.

> 🧾 **Follow-up flag (multi-price):** because `STRIPE_PRICE_PRO` is a single value, annual/founder pricing is **not selectable** until you ship the code change in **Appendix A**. Track that as a separate task; it is **not** required to start collecting money on the monthly plan.

---

## Step 4 — Redeploy the functions and confirm the JWT flags

Secret changes apply to already-running functions, but **redeploy to be certain** the live config is picked up and to re-assert the JWT flags.

```bash
# From the repo root (supabase/functions/* exists here):
supabase functions deploy create-checkout-session --project-ref <project-ref>
supabase functions deploy create-portal-session   --project-ref <project-ref>

# CRITICAL: the webhook MUST stay JWT-OFF — Stripe cannot send a Supabase JWT.
supabase functions deploy stripe-webhook --no-verify-jwt --project-ref <project-ref>
```

- [ ] Confirm in **Supabase → Edge Functions → `stripe-webhook` → Details** that **"Verify JWT" / "Enforce JWT" is OFF** (`verify_jwt = false`).
- [ ] Confirm `create-checkout-session` and `create-portal-session` keep **Verify JWT = ON** (they authenticate the calling user from the Authorization header).

> If `stripe-webhook` is accidentally deployed with JWT **on**, every Stripe delivery returns **401** and **no plan ever flips**. The fix is the `--no-verify-jwt` redeploy above.

> If you use Dashboard-only deploys (no CLI), there's a per-function **"Enforce JWT verification"** toggle — set it **off for `stripe-webhook` only**.

---

## Step 5 — Configure the Stripe Billing/Customer Portal (LIVE)

The app's `create-portal-session` sends customers to Stripe's **hosted** Billing Portal. Its capabilities are controlled by Dashboard settings, **separately per mode** — so configure it in LIVE.

- [ ] **Settings → Billing → Customer portal** (LIVE mode).
- [ ] **Cancellations:** allow customers to **cancel subscriptions** → choose **at end of billing period** (this maps to `cancel_at_period_end`, which the webhook mirrors; the portal `customer.subscription.updated` event keeps the row in sync, and the final `…deleted` reverts the plan).
- [ ] **Payment methods:** allow customers to **update payment method**.
- [ ] **Plan changes (switch plan):** if you want self-serve plan switching, enable **"Customers can switch plans"** and add the Pro product's prices (monthly / annual / founder) to the allowed list. *(Even without Appendix A, the portal can switch plans because it operates directly on the Stripe subscription; the webhook's `customer.subscription.updated` handler will mirror the new `price_id`.)*
- [ ] **Business information / links:** set your support email, terms, and privacy URLs (shown in the portal).
- [ ] **Save.**

---

## Step 6 — End-to-end LIVE test (real card or test clock)

Do this **once** before announcing. Two options:

**Option A — real card (recommended, truest signal).** Use a real personal card; you can refund yourself in Step 6f. Monthly $19 minimizes the float.
**Option B — Stripe Test Clock** in LIVE mode (Billing → Test clocks) to simulate without a real charge — more setup; use if you can't spare a charge.

Pick one and run the full loop:

### 6a. Subscribe
- [ ] Log in to the **live** app (https://packet-pilot.vercel.app/app, or your domain) as a real test account whose email you control.
- [ ] Click the **Upgrade**/subscribe action → it calls `create-checkout-session` → you're redirected to a Stripe **Checkout** page showing **$19.00 / month**.
- [ ] Complete payment. You should land back on **`/app?checkout=success`**.

> ⚠️ If Checkout shows the **wrong amount or a test banner**, you're on the wrong price/mode → re-check Step 3 `STRIPE_PRICE_PRO` and that you're truly in LIVE.

### 6b. Confirm the webhook fired
- [ ] **Stripe → Developers → Webhooks → your live endpoint → Events** (or the **Events** tab): the `checkout.session.completed` and a `customer.subscription.updated`/`created` delivery should show **HTTP 200**.
- [ ] If any show **400** → signature mismatch (`STRIPE_WEBHOOK_SECRET` wrong / has whitespace, or it's the test secret). If **401** → webhook got deployed with JWT on (redo Step 4). Stripe's **"Resend"** button re-delivers after you fix it.
- [ ] Cross-check function logs:
  ```bash
  supabase functions logs stripe-webhook --project-ref <project-ref>
  ```
  No `Bad signature`, no `Handler error`, no `unresolved user` lines.

### 6c. Confirm `profiles.plan` flipped to `pro`
Run in **Supabase → SQL Editor** (replace the email):
```sql
select id, email, plan, updated_at
from public.profiles
where email = 'YOUR_TEST_EMAIL';
-- expect: plan = 'pro'
```

### 6d. Confirm the `subscriptions` row populated
```sql
select user_id, status, price_id, amount_cents, currency,
       current_period_end, cancel_at_period_end, stripe_customer_id, stripe_subscription_id
from public.subscriptions
where user_id = (select id from public.profiles where email = 'YOUR_TEST_EMAIL');
-- expect: status='active', price_id = your live PRICE_PRO_MONTHLY,
--         amount_cents=1900, currency='usd', stripe_*_id populated, current_period_end ~1 month out
```
- [ ] (Optional UI check) In **`/admin`**, the user/payment views should reflect the new Pro subscriber.

### 6e. Open the Billing Portal
- [ ] In the app, open **Manage billing** → calls `create-portal-session` → redirects to the Stripe-hosted portal.
- [ ] Confirm you can see: update payment method, cancel, and (if enabled) switch plan.

> If you get **"No billing account yet" (400)**, the `subscriptions` row for this user has no `stripe_customer_id` — means checkout/webhook didn't complete. Re-check 6b–6d.

### 6f. Cancel → confirm revert to `free`
- [ ] In the portal, **cancel** the subscription.
  - If you chose **cancel immediately**: Stripe fires `customer.subscription.deleted` → webhook sets `profiles.plan='free'` right away.
  - If **cancel at period end**: Stripe fires `customer.subscription.updated` with `cancel_at_period_end=true` (plan **stays `pro`** until the period ends — this is correct). To verify the full revert now, either cancel immediately, or use a **Test Clock** to advance past `current_period_end`, at which point `…deleted` fires and the plan flips to `free`.
- [ ] Re-run the 6c query → `plan = 'free'` once the cancellation is effective.
- [ ] Re-run the 6d query → `status = 'canceled'` (and `cancel_at_period_end=true` in the period-end case).
- [ ] **Refund yourself:** Stripe → Payments → the test charge → **Refund** (full).

✅ A clean pass = subscribe→pro→row populated→portal→cancel→free, with all webhook deliveries at 200.

---

## Step 7 — Production hardening (fraud, receipts, tax)

All in **LIVE mode**:

- [ ] **Disable test artifacts in prod:** ensure the live app/Vercel env points at the live Supabase project, and that no `sk_test_`/`whsec_…test` values linger in the live Edge Function secrets (re-list with `supabase secrets list`). Delete the **test** webhook endpoint only if you no longer use test mode (optional; usually keep it for future testing).
- [ ] **Stripe Radar (fraud):** Settings → Radar — Radar is on by default for card payments; review/enable recommended rules (block high-risk, require CVC/postal). For a SaaS at this price point the default ruleset is fine; consider enabling **3D Secure when required**.
- [ ] **Email receipts:** Settings → **Customer emails** → turn ON **"Successful payments"** receipts (and optionally "Refunds"). Set the public-facing business name/email so receipts look legit.
- [ ] **Failed-payment / dunning emails:** Settings → **Billing → Subscriptions and emails** → enable retries + customer emails for failed payments (reduces involuntary churn). Note: `past_due`/`unpaid` map to `plan='free'` via the webhook, so dunning directly affects access.
- [ ] **Tax (note, not blocking):** if you must collect sales tax/VAT, enable **Stripe Tax** (Settings → Tax) and add `automatic_tax: { enabled: true }` to the Checkout session in `create-checkout-session` (Appendix A area) plus register your tax origin. **This is a code + registration change — schedule it; do not block launch on it** unless you have a legal obligation today.

---

## Step 8 — "You are LIVE" checklist + common gotchas

**Final go/no-go:**
- [ ] Dashboard is in **LIVE mode** and account is **activated** for payments.
- [ ] LIVE product + 3 prices exist; the **selling** price ID is in `STRIPE_PRICE_PRO`.
- [ ] LIVE webhook endpoint exists at `https://<project-ref>.supabase.co/functions/v1/stripe-webhook` with the 3 events, delivering **200**.
- [ ] `STRIPE_SECRET_KEY=sk_live_…`, `STRIPE_WEBHOOK_SECRET=whsec_…`(live), `STRIPE_PRICE_PRO=price_live_…` set in Supabase secrets.
- [ ] `stripe-webhook` deployed with **verify_jwt = false**; other two with **verify_jwt = true**.
- [ ] Portal configured (cancel / update card / switch plan).
- [ ] Full E2E pass: subscribe → `pro` → row populated → portal → cancel → `free`.
- [ ] Receipts on, Radar on, dunning on.
- [ ] You refunded your own live test charge.

**Common gotchas (symptom → cause → fix):**

| Symptom | Cause | Fix |
|---|---|---|
| Webhook deliveries show **400 Bad signature** | `STRIPE_WEBHOOK_SECRET` wrong, has trailing whitespace/newline, or is the **test** endpoint's secret | Re-copy the **live** endpoint's signing secret, paste clean, re-set secret, redeploy webhook, **Resend** the event |
| Webhook deliveries show **401** | `stripe-webhook` deployed with JWT verification **on** | Redeploy with `--no-verify-jwt`; confirm toggle off in Dashboard |
| Checkout opens but shows a **"TEST MODE" banner** / wrong amount | `STRIPE_SECRET_KEY` is `sk_test_…`, or `STRIPE_PRICE_PRO` is a test price | Set live secret key + live price ID; redeploy `create-checkout-session` |
| Payment succeeds but **plan never flips** | Webhook not receiving/200-ing, or wrong project | Check Stripe **Events** + `supabase functions logs stripe-webhook`; verify endpoint URL uses the **correct `<project-ref>`** |
| `subscriptions` row never appears | Same as above, or `client_reference_id` not resolving | Webhook falls back to row → customer `metadata.supabase_user_id`; if you see `unresolved user` in logs, the customer lacks that metadata — created outside the app's checkout |
| Portal returns **"No billing account yet" (400)** | User has no `subscriptions.stripe_customer_id` (never completed a live checkout) | Have them subscribe first; the customer is created during checkout |
| Lands on a **broken success/cancel page** | App origin differs from the hardcoded fallback | Functions use `req.headers.get("origin")`; if the SPA is on a custom domain it's auto-handled. Only the **fallback** is `https://packet-pilot.vercel.app` — verify your live domain sets `Origin` (browsers do). URLs are `/app?checkout=success` and `/app?checkout=cancel`. |
| Live publishable key "missing" worry | The current flow doesn't use `pk_live_` client-side (redirect-only) | No action needed; keep it on record for future Stripe.js use |

---

## Appendix A — Follow-up: let checkout pick a price (annual / founder)

**Why:** `create-checkout-session/index.ts` line 57 hard-codes a single env price:
```ts
line_items: [{ price: Deno.env.get("STRIPE_PRICE_PRO")!, quantity: 1 }],
```
So today only the `STRIPE_PRICE_PRO` plan is purchasable. To sell monthly **and** annual **and** founder, make a small change (not required for launch):

1. Add live price IDs as secrets, e.g. `STRIPE_PRICE_PRO_ANNUAL`, `STRIPE_PRICE_PRO_FOUNDER` (keep `STRIPE_PRICE_PRO` as the monthly default).
2. Accept a `plan`/`price` selector in the request body and **allowlist-map** it to a price ID server-side (never accept a raw price ID from the client — that lets a caller pick an arbitrary price). Default to `STRIPE_PRICE_PRO` when absent. Sketch:
   ```ts
   const { plan } = await req.json().catch(() => ({ plan: "monthly" }));
   const PRICES: Record<string, string | undefined> = {
     monthly: Deno.env.get("STRIPE_PRICE_PRO"),
     annual:  Deno.env.get("STRIPE_PRICE_PRO_ANNUAL"),
     founder: Deno.env.get("STRIPE_PRICE_PRO_FOUNDER"),
   };
   const price = PRICES[plan] ?? PRICES.monthly;
   if (!price) return json({ error: "Unknown plan" }, 400);
   // line_items: [{ price, quantity: 1 }]
   ```
3. Update the SPA `startCheckout` call (`ui/src/auth/billing.ts`, `invokeRedirect("create-checkout-session")`) to pass the chosen `plan` in the invoke body, and add plan options to the pricing UI.
4. The **webhook needs no change** — it already records whatever `price_id`/`amount_cents` Stripe reports per subscription item.
5. Redeploy `create-checkout-session`; add a Checkout test for each plan to your E2E loop (Step 6).

(If you also tackle **Stripe Tax** from Step 7, add `automatic_tax: { enabled: true }` to the same `checkout.sessions.create` call in this function.)

---

**Reference paths (for whoever ships Appendix A):**
- `D:\Project\PacketPilot\supabase\functions\create-checkout-session\index.ts` (single-price line 57; success/cancel URLs lines 59-60)
- `D:\Project\PacketPilot\supabase\functions\create-portal-session\index.ts`
- `D:\Project\PacketPilot\supabase\functions\stripe-webhook\index.ts` (handled events line 25; upsert + plan flip lines 64-78)
- `D:\Project\PacketPilot\supabase\migrations\0001_init.sql` (`profiles.plan`, `subscriptions` schema)
- `D:\Project\PacketPilot\ui\src\auth\billing.ts` (SPA invoke + `?checkout=success` reconcile)
- `D:\Project\PacketPilot\ui\src\admin\environment\EnvironmentView.tsx` (secret-name reference list)