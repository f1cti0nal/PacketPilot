# PacketPilot SaaS — Admin Payments View (Phase 6) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-28
**Branch:** `feat/admin-payments`
**Sub-project:** 6 of the PacketPilot SaaS platform (depends on Phase 0 + Phase 2 + Phase 3)

## Context

Phase 6 of the SaaS pivot. Phases 0–5 are merged + deployed. The `/admin` **Payments** section (`sections.ts`, CreditCard icon, already declared) currently falls through to the placeholder; this phase makes it a real, **read-only** view of who is paying.

Decision locked with the user: **read-only, mirror data only** (the recommended "Slice A"). No live Stripe calls, no billing actions, **no new Edge Function**. Live invoice/charge drill-down and refund/cancel actions are an explicit future slice and are out of scope here.

**Grounded in code (from the Phase-6 understand workflow):**
- The `subscriptions` table (migration `0001_init.sql`) has 11 columns kept in sync by the Stripe webhook: `id, user_id (FK→profiles.id), stripe_customer_id, stripe_subscription_id, price_id, status (8-value subscription_status enum), amount_cents, currency, current_period_end, cancel_at_period_end, created_at, updated_at`.
- Admin reads of `subscriptions` **and** `profiles` are already RLS-allowed (`user_id = auth.uid() OR public.is_admin()`), so the email join needs no schema change.
- The dashboard already computes MRR as `SUM(amount_cents) WHERE status='active'` (`admin_dashboard_stats` view) and formats with `money(cents)` (`ui/src/admin/dashboard/format.ts`).
- `subscriptions` has **no email column** → the read must embed `profiles(email,full_name)` via the FK.
- **No invoices/charges/refunds/payment methods are stored locally** — confirmed absent — which is exactly why richer detail is a later slice, not this one.

## Goal

Give an admin a Payments view at `/admin` → Payments: a searchable table of every subscription (who's paying, amount, status, renewal/cancel state) plus an "Active MRR" KPI strip whose number matches the dashboard by construction. Pure read; no mutations; no Stripe calls.

## Invariants preserved

- **No new write path, no Edge Function, no migration.** Reads are RLS-gated admin SELECTs on existing tables.
- **Secrets stay server-side.** The browser makes no Stripe call; the Stripe secret is never in scope.
- **Numerically consistent with the dashboard:** the headline Active MRR is read from the **same `admin_dashboard_stats.mrr_cents`** the dashboard uses (single source of truth), formatted with the SAME `money()` helper — so it matches at any scale, independent of the ≤100-row page. (If that view read fails, the hook falls back to summing the fetched page's active rows.) Page-derived secondary counts are honestly captioned "latest 100" when the page is capped.
- **Privacy/engine untouched:** no `/app`, WASM, or capture change. No new SPA deps.

## Architecture

```
ui/src/admin/payments/
  useAdminPayments.ts   # hook: subscriptions + embedded profiles(email,full_name) → AdminPayment[]
  summary.ts            # pure paymentsSummary(): Active MRR + counts + status breakdown
  PaymentsView.tsx      # KPI strip + client-side search + .pp-table; read-only
ui/src/admin/AdminShell.tsx   # route active==="payments" → <PaymentsView />
```

**Tech stack:** React 18 + TS, the Phase-0 Supabase typed client, Tailwind + `index.css` tokens (`.pp-table`, severity colors), Vitest + RTL. Mirrors the Phase-5 Users pattern exactly.

## Data layer — `useAdminPayments.ts`

```ts
export interface AdminPayment {
  id: string;
  email: string | null;
  full_name: string | null;
  status: string;
  amount_cents: number;
  currency: string;
  price_id: string | null;
  current_period_end: string | null;
  cancel_at_period_end: boolean;
  created_at: string;
  stripe_subscription_id: string | null;
  stripe_customer_id: string | null;
}
export type AdminPaymentsState =
  | { status: "loading" } | { status: "error"; error: string }
  | { status: "ready"; payments: AdminPayment[] };
export function useAdminPayments(): { state: AdminPaymentsState; reload: () => void };
```
Queries `subscriptions` with `.select("id,status,amount_cents,currency,price_id,current_period_end,cancel_at_period_end,created_at,stripe_subscription_id,stripe_customer_id,profiles(email,full_name)")`, `.order("created_at", { ascending: false }).limit(100)`. The embedded `profiles` (a to-one FK) may come back as an object or a one-element array; the hook flattens it (`Array.isArray(p) ? p[0] : p`) into `email`/`full_name`. `!supabaseConfigured` → error; query error → error; `reload()` is a nonce bump. Same loading/error/ready + cancelled-guard shape as `useAdminUsers`.

## Summary helper — `summary.ts`

```ts
export interface PaymentsSummary {
  activeMrrCents: number;   // SUM(amount_cents) where status === "active"
  activeCount: number;      // status === "active"
  statusCounts: Record<string, number>; // every status → count
}
export function paymentsSummary(payments: AdminPayment[]): PaymentsSummary;
```
Pure and unit-tested. `activeMrrCents` is computed **only** over `status === "active"` rows so it equals the dashboard's MRR. (Note: the dashboard counts *paid users* by `profiles.plan='pro'`, a different metric — the Payments view presents subscription truth via `status`, and must not imply the two are the same number.)

## UI — `PaymentsView.tsx`

Read-only. No `adminEmail` prop (no self-protection needed). Holds local `search` state.
- **KPI strip** (reuse `Card`/`money()`): Active MRR (`money(activeMrrCents)`), Active subscriptions count, and a small status breakdown (e.g. trialing / past_due / canceled counts) from `paymentsSummary`.
- A **Refresh** button (calls `reload()`) and a muted caption "Reflects the latest Stripe sync" — honest about mirror freshness; the view is never presented as real-time.
- A **search** input filtering the loaded rows client-side by email/full_name (the ≤100-row cap makes server-side search unnecessary; documented).
- `loading` → `LoadingState`; `error` → `ErrorState title="Couldn't load payments"`; ready + 0 → "No subscriptions yet." / "No matches." ; else a `.pp-table`:
  - **User** (email, with `full_name` as a secondary line; falls back to `email.split("@")[0]` then the user id).
  - **Amount** — `money(amount_cents)` (+ uppercase currency only when any row's currency ≠ "usd"). No fabricated plan-name column (price_id→name is not stored; amount conveys the tier; `price_id` shown in the row `title`).
  - **Status** — the 8-value enum as a colored chip via a `STATUS_COLOR` map: `active`/`trialing` → `--color-sev-low`; `past_due`/`unpaid` → `--color-sev-medium`; `canceled`/`incomplete`/`incomplete_expired`/`paused` → `--color-text-dim` (neutral). Mirrors `RecentUsersTable`'s pattern.
  - **Renews / Cancels** — `joinedDate(current_period_end)`, with a "Cancels at period end" badge when `cancel_at_period_end`.
  - **Created** — `joinedDate(created_at)`.

## Wiring — `AdminShell.tsx`

```tsx
{active === "dashboard" ? (
  <AdminDashboard />
) : active === "users" ? (
  <UsersView adminEmail={email} />
) : active === "payments" ? (
  <PaymentsView />
) : (
  <Placeholder title={title} phase={section?.phase ?? 0} />
)}
```
`sections.ts` already declares `payments`; no change there.

## Data flow & error handling

Admin opens Payments → `useAdminPayments()` SELECTs subscriptions+profiles (RLS lets admins read all) → rows flattened to `AdminPayment[]` → `paymentsSummary` drives the KPI strip → `.pp-table` renders. Typing filters client-side. Refresh re-fetches. Query/RLS errors surface via `ErrorState`. No mutations, so no write-error path; no throws cross the admin `ErrorBoundary`.

## Testing

- **`summary.ts`**: `paymentsSummary` sums `amount_cents` for `status==="active"` only (ignores trialing/past_due/canceled in MRR), counts active, and tallies `statusCounts`; empty input → zeros.
- **`useAdminPayments`** (mock `../../lib/supabase`): ready maps rows incl. flattening the embedded `profiles` in BOTH object and one-element-array forms into `email`/`full_name`; query error → error; `reload` re-fetches; unconfigured → error. Mirrors the `useAdminUsers` chain-mock convention (`select→order→limit`).
- **`PaymentsView`**: renders a row per subscription (`within(table)`); the KPI strip shows the active MRR via `money()`; client-side search narrows rows; a `cancel_at_period_end` row shows the "Cancels at period end" badge; status chip present; empty + error states.
- **`AdminShell.test`**: add a `vi.mock("./payments/PaymentsView", …)` stub and a test that navigating to Payments renders it + `hash === "#payments"` (mirrors the Phase-5 Users stub pattern; existing tests unchanged).
- Gate: full UI suite green, coverage ≥ 80/70, `npx tsc -b` clean, `npm run build` ✓, the coverage run exits 0.
- **Browser smoke** (controller, best-effort): the deployed/local app already has real subscription data (e.g. Bob = active $19). Confirm the Payments table lists it and Active MRR matches the dashboard. (Full admin click-through depends on the admin password the user holds.)

## Out of scope (future "Slice B")

Live Stripe drill-down (invoices/charges/payment methods via a new admin-gated `admin-billing` Edge Function); cancel-at-period-end and refund actions (real money movement, refund policy, double-confirm, audit); CSV/export of payments; per-row detail flyout; price_id→plan-name configuration. These each require the Stripe secret server-side and are a deliberate, separately-approved slice.

## File manifest

**Create:** `ui/src/admin/payments/useAdminPayments.ts` (+ test), `ui/src/admin/payments/summary.ts` (+ test), `ui/src/admin/payments/PaymentsView.tsx` (+ test).
**Modify:** `ui/src/admin/AdminShell.tsx` (route `payments` → `PaymentsView`), `ui/src/admin/AdminShell.test.tsx` (mock `./payments/PaymentsView` + a Payments-route test).
**No migration. No Edge Function. No engine/WASM/Tauri change. No `/app` change. No new SPA deps.**
