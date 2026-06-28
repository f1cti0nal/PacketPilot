# Stripe Billing (Phase 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Pro plan real — Stripe Checkout to subscribe, Billing Portal to manage/cancel, and a signature-verified webhook that syncs Stripe state into `subscriptions` + `profiles.plan`.

**Architecture:** Three self-contained Supabase Edge Functions (Deno) handle Stripe; a small `billing.ts` UI client invokes them and redirects; the account menu gains Upgrade/Manage. The webhook is the only writer of subscription state (service-role), keeping Stripe as the source of truth. No DB migration (Phase-0 `subscriptions` + `profiles.plan` already fit).

**Tech Stack:** Supabase Edge Functions (Deno, `npm:stripe@^17`, `jsr:@supabase/supabase-js@2`), `supabase.functions.invoke` in the SPA, React + tokens. Vitest for UI. Stripe test mode.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-06-28-stripe-billing-design.md`. Branch `feat/stripe-billing` (created). Supabase project_id `brkztcfhmrjjnbjzycie`.
- **Secrets only in Edge Function env** (`STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_PRO`) — NEVER in the SPA/repo. Supabase auto-injects `SUPABASE_URL`/`SUPABASE_ANON_KEY`/`SUPABASE_SERVICE_ROLE_KEY` into functions (no need to set those).
- **No migration. No engine/WASM/Tauri/admin change. No new SPA deps.** Pro = a single $19/mo recurring price. Lapse → `plan='free'` immediately (`active`/`trialing` → `pro`, else `free`).
- **Edge Functions are self-contained** single `index.ts` files (inline CORS/init) for single-file MCP deploy; they are Deno (excluded from the Vitest/tsc UI build) and verified LIVE.
- **UI gates:** per UI task run `npx vitest run <file>` AND `npx tsc -b`; coverage ≥ 80/70; `npm run build` passes. Run npm/npx from `ui/`. Mock `../lib/supabase` in tests.
- The webhook function deploys with **`verify_jwt: false`** (Stripe can't send a Supabase JWT); the other two with `verify_jwt: true`.

---

### Task 1: Billing UI client (`billing.ts`)

**Files:**
- Create: `ui/src/auth/billing.ts`
- Test: `ui/src/auth/billing.test.ts`

**Interfaces:**
- Consumes: `supabase` from `../lib/supabase`.
- Produces: `startCheckout(): Promise<{ ok: boolean; error?: string }>`, `openPortal(): Promise<{ ok: boolean; error?: string }>`, `reconcileAfterCheckout(): Promise<void>`.

- [ ] **Step 1: Write the failing test** `ui/src/auth/billing.test.ts`

```ts
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = {
  invoke: vi.fn(),
  refreshSession: vi.fn(),
};
vi.mock("../lib/supabase", () => ({
  supabase: {
    functions: { invoke: (...a: unknown[]) => h.invoke(...a) },
    auth: { refreshSession: (...a: unknown[]) => h.refreshSession(...a) },
  },
}));

import { startCheckout, openPortal, reconcileAfterCheckout } from "./billing";

const origUrl = window.location;

beforeEach(() => {
  h.invoke.mockResolvedValue({ data: { url: "https://stripe.test/cs" }, error: null });
  h.refreshSession.mockResolvedValue({ data: {}, error: null });
  // jsdom: make location.assign + search/pathname stubbable
  Object.defineProperty(window, "location", {
    writable: true,
    value: { assign: vi.fn(), search: "", pathname: "/app", href: "http://localhost/app" },
  });
  window.history.replaceState = vi.fn();
});
afterEach(() => {
  vi.clearAllMocks();
  Object.defineProperty(window, "location", { writable: true, value: origUrl });
});

describe("billing", () => {
  it("startCheckout invokes the checkout function and redirects to the url", async () => {
    const res = await startCheckout();
    expect(h.invoke).toHaveBeenCalledWith("create-checkout-session");
    expect(window.location.assign).toHaveBeenCalledWith("https://stripe.test/cs");
    expect(res.ok).toBe(true);
  });

  it("openPortal invokes the portal function and redirects", async () => {
    await openPortal();
    expect(h.invoke).toHaveBeenCalledWith("create-portal-session");
    expect(window.location.assign).toHaveBeenCalledWith("https://stripe.test/cs");
  });

  it("surfaces an error when invoke fails", async () => {
    h.invoke.mockResolvedValue({ data: null, error: { message: "boom" } });
    const res = await startCheckout();
    expect(res).toEqual({ ok: false, error: "boom" });
    expect(window.location.assign).not.toHaveBeenCalled();
  });

  it("reconcileAfterCheckout refreshes + strips the param only on checkout=success", async () => {
    window.location.search = "?checkout=success&x=1";
    await reconcileAfterCheckout();
    expect(h.refreshSession).toHaveBeenCalled();
    expect(window.history.replaceState).toHaveBeenCalled();
  });

  it("reconcileAfterCheckout does nothing without checkout=success", async () => {
    window.location.search = "?x=1";
    await reconcileAfterCheckout();
    expect(h.refreshSession).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run it, verify FAIL** — `npx vitest run src/auth/billing.test.ts` → cannot resolve ./billing.

- [ ] **Step 3: Implement** `ui/src/auth/billing.ts`

```ts
import { supabase } from "../lib/supabase";

async function invokeRedirect(name: string): Promise<{ ok: boolean; error?: string }> {
  if (!supabase) return { ok: false, error: "Accounts are unavailable" };
  const { data, error } = await supabase.functions.invoke(name);
  if (error) return { ok: false, error: error.message };
  const url = (data as { url?: string } | null)?.url;
  if (!url) return { ok: false, error: "No redirect URL returned" };
  window.location.assign(url);
  return { ok: true };
}

/** Start a Stripe Checkout for the Pro subscription (redirects to Stripe). */
export const startCheckout = (): Promise<{ ok: boolean; error?: string }> =>
  invokeRedirect("create-checkout-session");

/** Open the Stripe Billing Portal (manage/cancel; redirects to Stripe). */
export const openPortal = (): Promise<{ ok: boolean; error?: string }> =>
  invokeRedirect("create-portal-session");

/** After returning from Checkout with ?checkout=success, refresh the session so the
 *  webhook-updated plan is re-derived, then strip the query param. */
export async function reconcileAfterCheckout(): Promise<void> {
  if (typeof window === "undefined") return;
  const params = new URLSearchParams(window.location.search);
  if (params.get("checkout") !== "success") return;
  if (supabase) await supabase.auth.refreshSession();
  params.delete("checkout");
  const qs = params.toString();
  window.history.replaceState({}, "", window.location.pathname + (qs ? `?${qs}` : ""));
}
```

- [ ] **Step 4: Run it (PASS) + typecheck** — `npx vitest run src/auth/billing.test.ts` → 5 pass; `npx tsc -b` → 0.

- [ ] **Step 5: Commit**

```bash
git add ui/src/auth/billing.ts ui/src/auth/billing.test.ts
git commit -m "feat(billing): UI client (startCheckout/openPortal/reconcileAfterCheckout)"
```

---

### Task 2: Account menu Upgrade/Manage + App reconcile

**Files:**
- Modify: `ui/src/auth/AccountMenu.tsx` (add Upgrade/Manage items)
- Modify: `ui/src/auth/AccountMenu.test.tsx` (assert the items)
- Modify: `ui/src/App.tsx` (call `reconcileAfterCheckout()` on mount)

**Interfaces:**
- Consumes: `startCheckout`, `openPortal`, `reconcileAfterCheckout` from `./billing`.

- [ ] **Step 1: Add tests to** `ui/src/auth/AccountMenu.test.tsx`

At the top, mock billing:
```tsx
import { vi } from "vitest";
const billing = { startCheckout: vi.fn().mockResolvedValue({ ok: true }), openPortal: vi.fn().mockResolvedValue({ ok: true }) };
vi.mock("./billing", () => ({ startCheckout: () => billing.startCheckout(), openPortal: () => billing.openPortal() }));
```
Add two tests inside the existing `describe`:
```tsx
  it("free authed user can upgrade to Pro", async () => {
    render(
      <AccountMenu
        session={{ status: "authed", email: "a@b.com", profile: { email: "a@b.com", full_name: "A", plan: "free" }, signOut: vi.fn() }}
        onOpenAuth={vi.fn()}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: /account menu/i }));
    await userEvent.click(screen.getByRole("button", { name: /upgrade to pro/i }));
    expect(billing.startCheckout).toHaveBeenCalled();
  });

  it("pro authed user can manage billing", async () => {
    render(
      <AccountMenu
        session={{ status: "authed", email: "a@b.com", profile: { email: "a@b.com", full_name: "A", plan: "pro" }, signOut: vi.fn() }}
        onOpenAuth={vi.fn()}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: /account menu/i }));
    await userEvent.click(screen.getByRole("button", { name: /manage billing/i }));
    expect(billing.openPortal).toHaveBeenCalled();
  });
```
(Ensure `userEvent` + `screen` are imported — they already are from Task-3 of Phase 1.)

- [ ] **Step 2: Run it, verify FAIL** — `npx vitest run src/auth/AccountMenu.test.tsx` → the two new tests fail (no Upgrade/Manage buttons).

- [ ] **Step 3: Implement** — in `ui/src/auth/AccountMenu.tsx`, import the helpers and add the items to the authed popover.

Add the import near the top:
```tsx
import { startCheckout, openPortal } from "./billing";
```
Inside the authed popover panel (the `{open && (<div ...>)}` block), between the plan chip block and the "Sign out" button, insert:
```tsx
          {session.profile.plan === "pro" ? (
            <button
              type="button"
              onClick={() => void openPortal()}
              className="w-full rounded-[var(--r-micro)] px-2 py-1.5 text-left text-sm text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]"
            >
              Manage billing
            </button>
          ) : (
            <button
              type="button"
              onClick={() => void startCheckout()}
              className="w-full rounded-[var(--r-micro)] px-2 py-1.5 text-left text-sm text-[var(--color-accent-strong)] hover:bg-[var(--color-surface-2)]"
            >
              Upgrade to Pro
            </button>
          )}
```

- [ ] **Step 4: Run it (PASS)** — `npx vitest run src/auth/AccountMenu.test.tsx` → all pass (4).

- [ ] **Step 5: Wire `reconcileAfterCheckout` in `ui/src/App.tsx`**

Add the import:
```tsx
import { reconcileAfterCheckout } from "./auth/billing";
```
Add an effect near the other top-level effects in `App()`:
```tsx
  // After returning from Stripe Checkout, refresh the session so the upgraded plan shows.
  useEffect(() => {
    void reconcileAfterCheckout();
  }, []);
```

- [ ] **Step 6: Verify suite + types + build + coverage**

From `ui/`: `npx tsc -b` (0); `npx vitest run src/auth src/App.test.tsx` (pass); `npm run build` (ok); `npm run test:coverage` (≥ 80/70 — report the "All files" line). If `App.test.tsx` breaks because `reconcileAfterCheckout` touches `supabase`, it is a no-op when `checkout=success` is absent (default test URL), so no mock should be needed; if it is, mock `./auth/billing`'s `reconcileAfterCheckout` to a noop in App.test.

- [ ] **Step 7: Commit**

```bash
git add ui/src/auth/AccountMenu.tsx ui/src/auth/AccountMenu.test.tsx ui/src/App.tsx
git commit -m "feat(billing): account menu Upgrade/Manage + post-checkout reconcile"
```

---

### Task 3: Author the Stripe Edge Functions (Deno)

**Files:**
- Create: `supabase/functions/create-checkout-session/index.ts`
- Create: `supabase/functions/create-portal-session/index.ts`
- Create: `supabase/functions/stripe-webhook/index.ts`
- Create: `supabase/functions/README.md` (runbook)

**Interfaces:** HTTP functions invoked by the SPA (`create-checkout-session`, `create-portal-session`) and by Stripe (`stripe-webhook`). No Vitest (Deno) — reviewed for correctness, verified live in Tasks 4–5.

- [ ] **Step 1: Write `supabase/functions/create-checkout-session/index.ts`**

```ts
import Stripe from "npm:stripe@^17";
import { createClient } from "jsr:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const url = Deno.env.get("SUPABASE_URL")!;
    const authHeader = req.headers.get("Authorization") ?? "";
    const userClient = createClient(url, Deno.env.get("SUPABASE_ANON_KEY")!, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: { user }, error: uerr } = await userClient.auth.getUser();
    if (uerr || !user) return json({ error: "Unauthorized" }, 401);

    const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!);

    const { data: existing } = await admin
      .from("subscriptions")
      .select("stripe_customer_id")
      .eq("user_id", user.id)
      .not("stripe_customer_id", "is", null)
      .limit(1)
      .maybeSingle();
    let customerId = existing?.stripe_customer_id as string | undefined;
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: user.email ?? undefined,
        metadata: { supabase_user_id: user.id },
      });
      customerId = customer.id;
    }

    const origin = req.headers.get("origin") ?? "https://packet-pilot.vercel.app";
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer: customerId,
      line_items: [{ price: Deno.env.get("STRIPE_PRICE_PRO")!, quantity: 1 }],
      client_reference_id: user.id,
      success_url: `${origin}/app?checkout=success`,
      cancel_url: `${origin}/app?checkout=cancel`,
    });
    return json({ url: session.url });
  } catch (e) {
    return json({ error: String((e as Error)?.message ?? e) }, 400);
  }
});
```

- [ ] **Step 2: Write `supabase/functions/create-portal-session/index.ts`**

```ts
import Stripe from "npm:stripe@^17";
import { createClient } from "jsr:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const url = Deno.env.get("SUPABASE_URL")!;
    const authHeader = req.headers.get("Authorization") ?? "";
    const userClient = createClient(url, Deno.env.get("SUPABASE_ANON_KEY")!, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: { user }, error: uerr } = await userClient.auth.getUser();
    if (uerr || !user) return json({ error: "Unauthorized" }, 401);

    const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    const { data: existing } = await admin
      .from("subscriptions")
      .select("stripe_customer_id")
      .eq("user_id", user.id)
      .not("stripe_customer_id", "is", null)
      .limit(1)
      .maybeSingle();
    const customerId = existing?.stripe_customer_id as string | undefined;
    if (!customerId) return json({ error: "No billing account yet" }, 400);

    const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!);
    const origin = req.headers.get("origin") ?? "https://packet-pilot.vercel.app";
    const session = await stripe.billingPortal.sessions.create({ customer: customerId, return_url: `${origin}/app` });
    return json({ url: session.url });
  } catch (e) {
    return json({ error: String((e as Error)?.message ?? e) }, 400);
  }
});
```

- [ ] **Step 3: Write `supabase/functions/stripe-webhook/index.ts`**

```ts
import Stripe from "npm:stripe@^17";
import { createClient } from "jsr:@supabase/supabase-js@2";

const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!);
const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
const cryptoProvider = Stripe.createSubtleCryptoProvider();

function planForStatus(status: string): "free" | "pro" {
  return status === "active" || status === "trialing" ? "pro" : "free";
}

Deno.serve(async (req) => {
  const sig = req.headers.get("stripe-signature");
  const body = await req.text();
  let event: Stripe.Event;
  try {
    event = await stripe.webhooks.constructEventAsync(
      body, sig ?? "", Deno.env.get("STRIPE_WEBHOOK_SECRET")!, undefined, cryptoProvider,
    );
  } catch (e) {
    return new Response(`Bad signature: ${String((e as Error)?.message ?? e)}`, { status: 400 });
  }

  try {
    const handled = ["checkout.session.completed", "customer.subscription.updated", "customer.subscription.deleted"];
    if (handled.includes(event.type)) {
      let sub: Stripe.Subscription;
      if (event.type === "checkout.session.completed") {
        const s = event.data.object as Stripe.Checkout.Session;
        sub = await stripe.subscriptions.retrieve(s.subscription as string);
      } else {
        sub = event.data.object as Stripe.Subscription;
      }
      const customerId = sub.customer as string;

      let userId: string | null = null;
      const { data: existing } = await admin
        .from("subscriptions").select("user_id").eq("stripe_customer_id", customerId).limit(1).maybeSingle();
      userId = (existing?.user_id as string | undefined) ?? null;
      if (!userId) {
        const customer = (await stripe.customers.retrieve(customerId)) as Stripe.Customer;
        userId = (customer.metadata?.supabase_user_id as string | undefined) ?? null;
      }

      if (userId) {
        const item = sub.items.data[0];
        await admin.from("subscriptions").upsert(
          {
            user_id: userId,
            stripe_customer_id: customerId,
            stripe_subscription_id: sub.id,
            price_id: item?.price?.id ?? null,
            status: sub.status,
            amount_cents: item?.price?.unit_amount ?? null,
            currency: item?.price?.currency ?? "usd",
            current_period_end: sub.current_period_end ? new Date(sub.current_period_end * 1000).toISOString() : null,
            cancel_at_period_end: sub.cancel_at_period_end ?? false,
          },
          { onConflict: "stripe_subscription_id" },
        );
        await admin.from("profiles").update({ plan: planForStatus(sub.status) }).eq("id", userId);
      }
    }
    return new Response("ok", { status: 200 });
  } catch (e) {
    return new Response(`Handler error: ${String((e as Error)?.message ?? e)}`, { status: 500 });
  }
});
```

- [ ] **Step 4: Write `supabase/functions/README.md`** (the runbook)

```markdown
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
```

- [ ] **Step 5: Commit** (no deploy yet — that's Task 4)

```bash
git add supabase/functions/create-checkout-session supabase/functions/create-portal-session supabase/functions/stripe-webhook supabase/functions/README.md
git commit -m "feat(billing): Stripe Edge Functions (checkout, portal, webhook)"
```

---

### Task 4: Provision Stripe + deploy + secrets (controller + user; live)

**Files:** none (operational). Requires the user's Stripe account.

- [ ] **Step 1: Collect inputs from the user** — `sk_test_…` (test secret key) and a **$19/month Pro price id** (`price_…`). (Ask the user to create the product/price in the Stripe test dashboard if not already.)

- [ ] **Step 2: Deploy the two authed functions (controller, Supabase MCP)** — `deploy_edge_function` for `create-checkout-session` and `create-portal-session` (`project_id: brkztcfhmrjjnbjzycie`, `entrypoint_path: "index.ts"`, `verify_jwt: true`, `files: [{ name: "index.ts", content: <the file> }]`).

- [ ] **Step 3: Deploy the webhook (controller)** — `deploy_edge_function` for `stripe-webhook` with **`verify_jwt: false`**. Note its public URL: `https://brkztcfhmrjjnbjzycie.supabase.co/functions/v1/stripe-webhook`.

- [ ] **Step 4: User registers the webhook in Stripe** — Developers → Webhooks → add endpoint = the URL above; events `checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted`; copy the signing secret `whsec_…`.

- [ ] **Step 5: Set the secrets** — set `STRIPE_SECRET_KEY`, `STRIPE_PRICE_PRO`, `STRIPE_WEBHOOK_SECRET` as Edge Function secrets (Supabase dashboard → Edge Functions → Secrets, or `supabase secrets set --project-ref brkztcfhmrjjnbjzycie ...`). Confirm `list_edge_functions` shows the three functions deployed.

- [ ] **Step 6: No commit** (operational).

---

### Task 5: Live end-to-end verification (controller + user)

**Files:** none (operational).

- [ ] **Step 1: Upgrade flow** — in the running app (or the deployed site), sign in as a free account, open the account menu → "Upgrade to Pro" → complete Stripe Checkout with test card `4242 4242 4242 4242` (any future expiry/CVC) → land back on `/app?checkout=success`.

- [ ] **Step 2: Verify the sync (MCP `execute_sql`)**
```sql
select p.email, p.plan, s.status, s.amount_cents, s.stripe_subscription_id
from public.profiles p join public.subscriptions s on s.user_id = p.id
where p.email = '<the test account email>';
```
Expected: `plan = pro`, `status = active`, `amount_cents = 1900`.

- [ ] **Step 3: Manage/cancel flow** — account menu → "Manage billing" → Stripe portal → cancel the subscription → confirm the webhook fires and `profiles.plan` returns to `free` (re-run the query; `status` becomes `canceled`, `plan = free`).

- [ ] **Step 4: Check function logs if anything fails** — Supabase MCP `get_logs` (service `edge-function`) to debug signature/handler errors.

- [ ] **Step 5: No commit** (operational).

---

## Self-Review

**1. Spec coverage:**
- `create-checkout-session` / `create-portal-session` / `stripe-webhook` (auth, customer resolve, signature verify, upsert + plan set) → Task 3. ✅
- `planForStatus` (active/trialing→pro else free) → Task 3 (inline, live-verified). ✅
- `billing.ts` (startCheckout/openPortal/reconcileAfterCheckout) → Task 1. ✅
- AccountMenu Upgrade/Manage + App reconcile → Task 2. ✅
- Secrets only in Edge env; webhook verify_jwt false → Global Constraints + Task 4. ✅
- Live verification (checkout→pro, cancel→free, DB check) → Task 5. ✅
- No migration / privacy / no SPA deps → Global Constraints + file scope. ✅
- Runbook (Stripe dashboard steps) → Task 3 README + Task 4. ✅

**2. Placeholder scan:** No "TBD/handle errors/similar to Task N". `<the file>` / `<test account email>` / `sk_test_…` are runtime values supplied at execution, not code placeholders. All code steps are complete.

**3. Type consistency:** `startCheckout`/`openPortal`/`reconcileAfterCheckout` signatures match between `billing.ts` (Task 1), its test, `AccountMenu` (Task 2), and `App` (Task 2). The webhook upsert columns match the Phase-0 `subscriptions` schema (verified in types.ts: stripe_customer_id, stripe_subscription_id, price_id, status, amount_cents, currency, current_period_end, cancel_at_period_end, user_id). `planForStatus` returns the `user_plan` enum values.

## Execution Handoff

(See message.)
