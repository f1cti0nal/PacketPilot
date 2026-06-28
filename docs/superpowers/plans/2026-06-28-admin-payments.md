# Admin Payments View (Phase 6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A read-only `/admin` → Payments view over the local `subscriptions` mirror (joined to `profiles` for email) with an Active-MRR KPI strip that matches the dashboard.

**Architecture:** A `paymentsSummary` pure helper computes Active MRR + counts. A `useAdminPayments` hook SELECTs `subscriptions` with an embedded `profiles(email,full_name)` join (RLS already allows admin reads) and flattens it to `AdminPayment[]`. A `PaymentsView` renders the KPI strip + client-side search + `.pp-table`. `AdminShell` routes the (already-declared) `payments` section to it. No migration, no Edge Function, no Stripe call.

**Tech Stack:** React 18 + TS, the Phase-0 Supabase typed client, Tailwind + `index.css` tokens, Vitest + RTL. Mirrors the Phase-5 Users pattern.

## Global Constraints

- **Read-only. No mutation, no Edge Function, no migration, no Stripe API call.** Reads are RLS-gated admin SELECTs on existing tables (`subscriptions` + embedded `profiles`).
- **MRR consistency:** Active MRR = `SUM(amount_cents)` over rows where `status === "active"` ONLY, formatted with the existing `money()` (`ui/src/admin/dashboard/format.ts`). Must equal the dashboard's MRR.
- **Email via the FK join:** `subscriptions` has no email column — embed `profiles(email,full_name)`; the embedded to-one may arrive as an object OR a one-element array — flatten both.
- **Honesty:** the view reflects the last webhook sync; include a Refresh button and a "Reflects the latest Stripe sync" caption. Never present it as real-time.
- **No fabricated plan-name column** (price_id→name is not stored): show `money(amount_cents)`; expose `price_id` only via the row `title`.
- **Privacy/engine untouched; no new SPA deps.**
- **Per-task gate:** `npx tsc -b` (Vitest skips typecheck). Final task runs `npm run test:coverage` (≥ 80 stmts / 70 branches) + `npm run build`. All UI commands from `D:\Project\PacketPilot\ui`.

---

### Task 1: `paymentsSummary` pure helper

**Files:**
- Create: `ui/src/admin/payments/summary.ts`
- Test: `ui/src/admin/payments/summary.test.ts`

**Interfaces:**
- Consumes: nothing from other tasks. `paymentsSummary` accepts a minimal structural type (`status` + `amount_cents`), so it has **no dependency** on the hook module. `AdminPayment` (Task 2) satisfies this shape, so `PaymentsView` passes `AdminPayment[]` directly.
- Produces: `interface PaymentLike { status: string; amount_cents: number }`; `interface PaymentsSummary { activeMrrCents: number; activeCount: number; statusCounts: Record<string, number> }`; `paymentsSummary(payments: readonly PaymentLike[]): PaymentsSummary`.

- [ ] **Step 1: Write the failing test**

`ui/src/admin/payments/summary.test.ts`:
```ts
import { describe, expect, it } from "vitest";
import { paymentsSummary } from "./summary";

describe("paymentsSummary", () => {
  it("sums amount_cents for active subs only and tallies statuses", () => {
    const s = paymentsSummary([
      { status: "active", amount_cents: 1900 },
      { status: "active", amount_cents: 1900 },
      { status: "past_due", amount_cents: 1900 },
      { status: "canceled", amount_cents: 1900 },
      { status: "trialing", amount_cents: 1900 },
    ]);
    expect(s.activeMrrCents).toBe(3800);
    expect(s.activeCount).toBe(2);
    expect(s.statusCounts).toEqual({ active: 2, past_due: 1, canceled: 1, trialing: 1 });
  });

  it("returns zeros for an empty list", () => {
    expect(paymentsSummary([])).toEqual({ activeMrrCents: 0, activeCount: 0, statusCounts: {} });
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/payments/summary.test.ts`
Expected: FAIL (cannot resolve `./summary`).

- [ ] **Step 3: Write the implementation**

`ui/src/admin/payments/summary.ts`:
```ts
/** Minimal shape paymentsSummary needs; AdminPayment satisfies it. */
export interface PaymentLike {
  status: string;
  amount_cents: number;
}

export interface PaymentsSummary {
  activeMrrCents: number;
  activeCount: number;
  statusCounts: Record<string, number>;
}

export function paymentsSummary(payments: readonly PaymentLike[]): PaymentsSummary {
  let activeMrrCents = 0;
  let activeCount = 0;
  const statusCounts: Record<string, number> = {};
  for (const p of payments) {
    statusCounts[p.status] = (statusCounts[p.status] ?? 0) + 1;
    if (p.status === "active") {
      activeMrrCents += p.amount_cents;
      activeCount += 1;
    }
  }
  return { activeMrrCents, activeCount, statusCounts };
}
```

- [ ] **Step 4: Verify pass + typecheck**

Run: `cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/payments/summary.test.ts && npx tsc -b`
Expected: 2/2 PASS; tsc exit 0.

- [ ] **Step 5: Commit**

```bash
cd "D:/Project/PacketPilot" && git add ui/src/admin/payments/summary.ts ui/src/admin/payments/summary.test.ts && git commit -m "feat(admin): paymentsSummary helper (active MRR + status counts)"
```

---

### Task 2: `useAdminPayments` hook

**Files:**
- Create: `ui/src/admin/payments/useAdminPayments.ts`
- Test: `ui/src/admin/payments/useAdminPayments.test.ts`

**Interfaces:**
- Consumes: `supabase`, `supabaseConfigured` from `../../lib/supabase`.
- Produces:
  - `interface AdminPayment { id: string; email: string | null; full_name: string | null; status: string; amount_cents: number; currency: string; price_id: string | null; current_period_end: string | null; cancel_at_period_end: boolean; created_at: string; stripe_subscription_id: string | null; stripe_customer_id: string | null }`
  - `type AdminPaymentsState = { status: "loading" } | { status: "error"; error: string } | { status: "ready"; payments: AdminPayment[] }`
  - `useAdminPayments(): { state: AdminPaymentsState; reload: () => void }`

- [ ] **Step 1: Write the failing test**

`ui/src/admin/payments/useAdminPayments.test.ts`:
```ts
import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

let result: { data: unknown; error: unknown } = { data: [], error: null };
const orderSpy = vi.fn();
const limitSpy = vi.fn();

vi.mock("../../lib/supabase", () => {
  const makeQuery = () => {
    const q: Record<string, unknown> = {};
    q.select = () => q;
    q.order = (...a: unknown[]) => { orderSpy(...a); return q; };
    q.limit = (...a: unknown[]) => { limitSpy(...a); return Promise.resolve(result); };
    return q;
  };
  return { supabase: { from: () => makeQuery() }, supabaseConfigured: true };
});

import { useAdminPayments } from "./useAdminPayments";

const ROWS = [
  { id: "s1", status: "active", amount_cents: 1900, currency: "usd", price_id: "price_1",
    current_period_end: "2026-07-20T00:00:00Z", cancel_at_period_end: false, created_at: "2026-06-20T00:00:00Z",
    stripe_subscription_id: "sub_1", stripe_customer_id: "cus_1", profiles: { email: "bob@x.com", full_name: "Bob" } },
  { id: "s2", status: "canceled", amount_cents: 1900, currency: "usd", price_id: "price_1",
    current_period_end: null, cancel_at_period_end: true, created_at: "2026-06-21T00:00:00Z",
    stripe_subscription_id: "sub_2", stripe_customer_id: "cus_2", profiles: [{ email: "al@x.com", full_name: "Al" }] },
];

beforeEach(() => {
  result = { data: ROWS, error: null };
  orderSpy.mockClear(); limitSpy.mockClear();
});

describe("useAdminPayments", () => {
  it("loads + flattens embedded profiles (object and array forms)", async () => {
    const { result: hook } = renderHook(() => useAdminPayments());
    await waitFor(() => expect(hook.current.state.status).toBe("ready"));
    if (hook.current.state.status === "ready") {
      expect(hook.current.state.payments).toHaveLength(2);
      expect(hook.current.state.payments[0].email).toBe("bob@x.com");
      expect(hook.current.state.payments[1].email).toBe("al@x.com");
      expect(hook.current.state.payments[1].cancel_at_period_end).toBe(true);
    }
    expect(orderSpy).toHaveBeenCalledWith("created_at", { ascending: false });
    expect(limitSpy).toHaveBeenCalledWith(100);
  });

  it("surfaces a query error", async () => {
    result = { data: null, error: { message: "boom" } };
    const { result: hook } = renderHook(() => useAdminPayments());
    await waitFor(() => expect(hook.current.state.status).toBe("error"));
    if (hook.current.state.status === "error") expect(hook.current.state.error).toBe("boom");
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/payments/useAdminPayments.test.ts`
Expected: FAIL (cannot resolve `./useAdminPayments`).

- [ ] **Step 3: Write the implementation**

`ui/src/admin/payments/useAdminPayments.ts`:
```ts
import { useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../../lib/supabase";

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
  | { status: "loading" }
  | { status: "error"; error: string }
  | { status: "ready"; payments: AdminPayment[] };

const SEL =
  "id,status,amount_cents,currency,price_id,current_period_end,cancel_at_period_end,created_at,stripe_subscription_id,stripe_customer_id,profiles(email,full_name)";

interface RawProfile {
  email: string | null;
  full_name: string | null;
}
interface RawRow {
  id: string;
  status: string;
  amount_cents: number | null;
  currency: string | null;
  price_id: string | null;
  current_period_end: string | null;
  cancel_at_period_end: boolean | null;
  created_at: string;
  stripe_subscription_id: string | null;
  stripe_customer_id: string | null;
  profiles: RawProfile | RawProfile[] | null;
}

function toPayment(r: RawRow): AdminPayment {
  const p = Array.isArray(r.profiles) ? r.profiles[0] : r.profiles;
  return {
    id: r.id,
    email: p?.email ?? null,
    full_name: p?.full_name ?? null,
    status: r.status,
    amount_cents: r.amount_cents ?? 0,
    currency: r.currency ?? "usd",
    price_id: r.price_id,
    current_period_end: r.current_period_end,
    cancel_at_period_end: r.cancel_at_period_end ?? false,
    created_at: r.created_at,
    stripe_subscription_id: r.stripe_subscription_id,
    stripe_customer_id: r.stripe_customer_id,
  };
}

export function useAdminPayments(): { state: AdminPaymentsState; reload: () => void } {
  const [state, setState] = useState<AdminPaymentsState>({ status: "loading" });
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    if (!supabaseConfigured || !supabase) {
      setState({ status: "error", error: "Backend not configured" });
      return;
    }
    const client = supabase;
    let cancelled = false;
    void (async () => {
      try {
        const { data, error } = await client
          .from("subscriptions")
          .select(SEL)
          .order("created_at", { ascending: false })
          .limit(100);
        if (error) throw new Error((error as { message?: string }).message ?? "Query failed");
        if (cancelled) return;
        const payments = ((data ?? []) as unknown as RawRow[]).map(toPayment);
        setState({ status: "ready", payments });
      } catch (e) {
        if (!cancelled) setState({ status: "error", error: e instanceof Error ? e.message : String(e) });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [nonce]);

  return { state, reload: () => setNonce((n) => n + 1) };
}
```

- [ ] **Step 4: Verify pass + typecheck**

Run: `cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/payments/useAdminPayments.test.ts && npx tsc -b`
Expected: 2/2 PASS; tsc exit 0.

- [ ] **Step 5: Commit**

```bash
cd "D:/Project/PacketPilot" && git add ui/src/admin/payments/useAdminPayments.ts ui/src/admin/payments/useAdminPayments.test.ts && git commit -m "feat(admin): useAdminPayments hook (subscriptions + profiles join)"
```

---

### Task 3: `PaymentsView` component

**Files:**
- Create: `ui/src/admin/payments/PaymentsView.tsx`
- Test: `ui/src/admin/payments/PaymentsView.test.tsx`

**Interfaces:**
- Consumes: `useAdminPayments`, `type AdminPayment` from `./useAdminPayments`; `paymentsSummary` from `./summary`; `LoadingState`, `ErrorState`; `joinedDate`, `money` from `../dashboard/format`.
- Produces: `export function PaymentsView()` (no props) (also `export default`).

- [ ] **Step 1: Write the failing test**

`ui/src/admin/payments/PaymentsView.test.tsx`:
```tsx
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const hookState = vi.fn();
const reload = vi.fn();
vi.mock("./useAdminPayments", () => ({ useAdminPayments: () => ({ state: hookState(), reload }) }));

import { PaymentsView } from "./PaymentsView";

const PAYMENTS = [
  { id: "s1", email: "bob@x.com", full_name: "Bob", status: "active", amount_cents: 1900, currency: "usd",
    price_id: "price_1", current_period_end: "2026-07-20T00:00:00Z", cancel_at_period_end: false,
    created_at: "2026-06-20T00:00:00Z", stripe_subscription_id: "sub_1", stripe_customer_id: "cus_1" },
  { id: "s2", email: "al@x.com", full_name: "Al", status: "canceled", amount_cents: 1900, currency: "usd",
    price_id: "price_1", current_period_end: null, cancel_at_period_end: true,
    created_at: "2026-06-21T00:00:00Z", stripe_subscription_id: "sub_2", stripe_customer_id: "cus_2" },
];

beforeEach(() => {
  hookState.mockReturnValue({ status: "ready", payments: PAYMENTS });
  reload.mockClear();
});

describe("PaymentsView", () => {
  it("renders a row per subscription and an Active-MRR/active-count KPI strip", () => {
    render(<PaymentsView />);
    const table = screen.getByRole("table");
    expect(within(table).getByText("bob@x.com")).toBeInTheDocument();
    expect(within(table).getByText("al@x.com")).toBeInTheDocument();
    expect(screen.getByText("Active MRR").parentElement).toHaveTextContent("$19");
    expect(screen.getByText("Active subs").parentElement).toHaveTextContent("1");
  });

  it("shows a Cancels-at-period-end badge", () => {
    render(<PaymentsView />);
    expect(screen.getByText(/cancels at period end/i)).toBeInTheDocument();
  });

  it("filters rows client-side by email", async () => {
    render(<PaymentsView />);
    await userEvent.type(screen.getByRole("searchbox", { name: /search payments/i }), "bob");
    const table = screen.getByRole("table");
    expect(within(table).getByText("bob@x.com")).toBeInTheDocument();
    expect(within(table).queryByText("al@x.com")).not.toBeInTheDocument();
  });

  it("Refresh triggers a reload", async () => {
    render(<PaymentsView />);
    await userEvent.click(screen.getByRole("button", { name: /refresh/i }));
    expect(reload).toHaveBeenCalled();
  });

  it("renders the empty and error states", () => {
    hookState.mockReturnValue({ status: "ready", payments: [] });
    const { rerender } = render(<PaymentsView />);
    expect(screen.getByText(/no subscriptions yet/i)).toBeInTheDocument();
    hookState.mockReturnValue({ status: "error", error: "backend down" });
    rerender(<PaymentsView />);
    expect(screen.getByText(/backend down/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/payments/PaymentsView.test.tsx`
Expected: FAIL (cannot resolve `./PaymentsView`).

- [ ] **Step 3: Write the implementation**

`ui/src/admin/payments/PaymentsView.tsx`:
```tsx
import { useMemo, useState } from "react";
import { LoadingState } from "../../components/state/LoadingState";
import { ErrorState } from "../../components/state/ErrorState";
import { joinedDate, money } from "../dashboard/format";
import { useAdminPayments, type AdminPayment } from "./useAdminPayments";
import { paymentsSummary } from "./summary";

const STATUS_COLOR: Record<string, string> = {
  active: "var(--color-sev-low)",
  trialing: "var(--color-sev-low)",
  past_due: "var(--color-sev-medium)",
  unpaid: "var(--color-sev-medium)",
  canceled: "var(--color-text-dim)",
  incomplete: "var(--color-text-dim)",
  incomplete_expired: "var(--color-text-dim)",
  paused: "var(--color-text-dim)",
};

export function PaymentsView() {
  const { state, reload } = useAdminPayments();
  const [search, setSearch] = useState("");

  const payments = state.status === "ready" ? state.payments : [];
  const summary = useMemo(() => paymentsSummary(payments), [payments]);
  const anyNonUsd = payments.some((p) => p.currency !== "usd");
  const term = search.trim().toLowerCase();
  const rows = term
    ? payments.filter(
        (p) => (p.email ?? "").toLowerCase().includes(term) || (p.full_name ?? "").toLowerCase().includes(term),
      )
    : payments;

  return (
    <div className="flex flex-col gap-[var(--density-gap)]">
      <div className="flex flex-wrap items-end gap-3">
        <Kpi label="Active MRR" value={money(summary.activeMrrCents)} />
        <Kpi label="Active subs" value={String(summary.activeCount)} />
        <Kpi label="Past due" value={String(summary.statusCounts.past_due ?? 0)} />
        <Kpi label="Canceled" value={String(summary.statusCounts.canceled ?? 0)} />
        <button
          type="button"
          onClick={reload}
          className="ml-auto rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-xs text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
        >
          Refresh
        </button>
      </div>
      <input
        type="search"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Search by email…"
        aria-label="Search payments by email"
        className="w-full max-w-sm rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-sm text-[var(--color-text)] placeholder:text-[var(--color-text-dim)]"
      />
      {state.status === "loading" ? (
        <LoadingState label="Loading payments…" />
      ) : state.status === "error" ? (
        <ErrorState title="Couldn't load payments" message={state.error} />
      ) : rows.length === 0 ? (
        <p className="text-sm text-[var(--color-text-dim)]">
          {payments.length === 0 ? "No subscriptions yet." : "No matches."}
        </p>
      ) : (
        <table className="pp-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Amount</th>
              <th>Status</th>
              <th>Renews</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => (
              <PaymentRow key={p.id} p={p} showCurrency={anyNonUsd} />
            ))}
          </tbody>
        </table>
      )}
      <p className="t-tag text-[var(--color-text-dim)]">Reflects the latest Stripe sync.</p>
    </div>
  );
}

function PaymentRow({ p, showCurrency }: { p: AdminPayment; showCurrency: boolean }) {
  const color = STATUS_COLOR[p.status] ?? "var(--color-text-dim)";
  return (
    <tr title={p.price_id ?? undefined}>
      <td>
        <div>{p.email ?? p.id}</div>
        {p.full_name && <div className="t-tag text-[var(--color-text-dim)]">{p.full_name}</div>}
      </td>
      <td className="font-mono-num">
        {money(p.amount_cents)}
        {showCurrency && <span className="ml-1 t-tag uppercase text-[var(--color-text-dim)]">{p.currency}</span>}
      </td>
      <td>
        <span className="inline-flex items-center gap-1.5 t-tag uppercase" style={{ color }}>
          <span aria-hidden className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
          {p.status}
        </span>
      </td>
      <td className="font-mono-num text-[var(--color-text-dim)]">
        {p.current_period_end ? joinedDate(p.current_period_end) : "—"}
        {p.cancel_at_period_end && (
          <span className="ml-1.5 inline-flex items-center rounded-[var(--r-chip)] border border-[var(--color-border)] px-1.5 py-0.5 t-tag uppercase text-[var(--color-sev-medium)]">
            Cancels at period end
          </span>
        )}
      </td>
      <td className="font-mono-num text-[var(--color-text-dim)]">{joinedDate(p.created_at)}</td>
    </tr>
  );
}

function Kpi({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2">
      <div className="t-tag uppercase text-[var(--color-text-dim)]">{label}</div>
      <div className="font-mono-num text-lg text-[var(--color-text)]">{value}</div>
    </div>
  );
}

export default PaymentsView;
```

- [ ] **Step 4: Verify pass + typecheck**

Run: `cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/payments/PaymentsView.test.tsx && npx tsc -b`
Expected: 5/5 PASS; tsc exit 0.

- [ ] **Step 5: Commit**

```bash
cd "D:/Project/PacketPilot" && git add ui/src/admin/payments/PaymentsView.tsx ui/src/admin/payments/PaymentsView.test.tsx && git commit -m "feat(admin): PaymentsView read-only subscriptions table + MRR strip"
```

---

### Task 4: Wire `AdminShell` + update its test + full gate

**Files:**
- Modify: `ui/src/admin/AdminShell.tsx` (route `payments` → `PaymentsView`)
- Modify: `ui/src/admin/AdminShell.test.tsx` (mock `./payments/PaymentsView`; add a Payments-route test)

**Interfaces:**
- Consumes: `PaymentsView` from `./payments/PaymentsView`.

- [ ] **Step 1: Update the shell test (RED)**

In `ui/src/admin/AdminShell.test.tsx`, add after the existing `vi.mock("./users/UsersView", …)` line:
```tsx
vi.mock("./payments/PaymentsView", () => ({ PaymentsView: () => <div>PAYMENTS_STUB</div> }));
```
And add this test inside the `describe("AdminShell", …)` block (e.g. after the Users-switch test):
```tsx
  it("routes the Payments section to the payments view", async () => {
    render(<AdminShell email="a@b.com" onSignOut={vi.fn()} />);
    await userEvent.click(within(screen.getByRole("navigation")).getByRole("button", { name: "Payments" }));
    expect(screen.getByText("PAYMENTS_STUB")).toBeInTheDocument();
    expect(window.location.hash).toBe("#payments");
  });
```

- [ ] **Step 2: Run the shell test to verify it fails**

Run: `cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/AdminShell.test.tsx`
Expected: FAIL — "PAYMENTS_STUB" not found (shell still renders the placeholder for `payments`).

- [ ] **Step 3: Wire the route in `AdminShell.tsx`**

Add after the `import { UsersView } from "./users/UsersView";` line:
```tsx
import { PaymentsView } from "./payments/PaymentsView";
```
Replace the content-routing block:
```tsx
          {active === "dashboard" ? (
            <AdminDashboard />
          ) : active === "users" ? (
            <UsersView adminEmail={email} />
          ) : (
            <Placeholder title={title} phase={section?.phase ?? 0} />
          )}
```
with:
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

- [ ] **Step 4: Verify the shell test passes**

Run: `cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/AdminShell.test.tsx`
Expected: 5/5 PASS.

- [ ] **Step 5: Full gate**

Run, in order:
1. `cd "D:/Project/PacketPilot/ui" && npx tsc -b` → exit 0.
2. `cd "D:/Project/PacketPilot/ui" && npm run test:coverage` → all files pass, EXIT CODE 0 (no "Unhandled Errors"), coverage ≥ 80 stmts / 70 branches. Report the Test Files/Tests totals + "All files" line + exit code.
3. `cd "D:/Project/PacketPilot/ui" && npm run build` → "✓ built" (the chunk-size warning is pre-existing/fine).

If the coverage run is non-zero or reports unhandled errors despite tests passing, investigate — do not ignore.

- [ ] **Step 6: Commit**

```bash
cd "D:/Project/PacketPilot" && git add ui/src/admin/AdminShell.tsx ui/src/admin/AdminShell.test.tsx && git commit -m "feat(admin): route the Payments section to the payments view"
```

---

## After all tasks

- **Final whole-branch review** (most capable model): diff from `git merge-base main HEAD` to `HEAD`. Focus: MRR computed active-only + via `money()` (matches dashboard); the embedded-profiles flatten handles object & array; read-only (no mutation/secret/Stripe call); the stale-mirror honesty (Refresh + caption); test hygiene; consistency with the Phase-5 pattern.
- **Browser smoke** (controller, best-effort): real subscription data exists (Bob = active $19). Confirm Payments lists it and Active MRR matches the dashboard. (Full admin click-through depends on the admin password the user holds.)
- **finishing-a-development-branch**: verify the suite, then present merge options.

## Self-review notes

- **Spec coverage:** summary helper (Task 1); hook with FK join + flatten (Task 2); PaymentsView table + MRR strip + search + states + cancel badge + refresh + caption (Task 3); AdminShell wiring + test (Task 4); MRR-consistency, email-join, honesty, no-fabricated-plan all realized in the code. All spec sections map to a task.
- **Type consistency:** `AdminPayment`/`AdminPaymentsState`/`useAdminPayments()` defined in Task 2; `PaymentLike`/`PaymentsSummary`/`paymentsSummary` in Task 1 (no cross-task import — structural `PaymentLike`, which `AdminPayment` satisfies); both consumed by `PaymentsView` (Task 3); `PaymentsView` consumed by `AdminShell` (Task 4). Field names (`amount_cents`, `cancel_at_period_end`, `current_period_end`, `status`) consistent across tasks and match the verified `subscriptions` columns.
- **No placeholders:** every code/test step carries full content and exact commands.
- **No task ordering coupling:** each task is independently buildable/testable — Task 1 no longer imports the hook module.
