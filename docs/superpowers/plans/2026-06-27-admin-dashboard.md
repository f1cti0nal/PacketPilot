# Admin Dashboard (Phase 4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the admin Dashboard placeholder with the real overview — 6 KPI cards + a System Health status, a "Daily New Users" area chart, a "New Subscriptions" bar chart, and a read-only recent-users table — sourced from the live Supabase schema.

**Architecture:** Two admin-gated `SECURITY INVOKER` SQL RPCs return zero-filled daily series; a `useAdminDashboard` hook parallel-fetches the `admin_dashboard_stats` view, recent profiles, and the two series; focused presentational components (KPI cards, two recharts charts, a `.pp-table` table) render it; `AdminDashboard` orchestrates with loading/error states. The admin shell's dashboard import is repointed and its test is mocked to stay data-free.

**Tech Stack:** React 18 + TS, `@supabase/supabase-js` (Phase-0 client `ui/src/lib/supabase`), `recharts` (existing dep), Tailwind + `index.css` tokens + `cockpit/primitives` (`Card`, `StatTile`). Vitest + RTL. Supabase MCP for the migration. No new deps.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-06-27-admin-dashboard-design.md`. Branch `feat/admin-dashboard` (created). Supabase project_id `brkztcfhmrjjnbjzycie`.
- **No new dependencies.** Reuse `cockpit/primitives` (`Card`, `StatTile`), `components/state/{LoadingState,ErrorState}` (`ErrorState` prop is `message`), `lib/supabase` (`supabase`, `supabaseConfigured`), `lib/cn`. Charts follow the `components/triage/TimelineChart.tsx` recharts pattern.
- **No change to `/app`, the engine, the WASM path, or the Phase-3 admin shell/auth/routing** — except repointing the dashboard import in `AdminShell.tsx` and updating `AdminShell.test.tsx`.
- **Tokens only** (`var(--color-*)`, `.t-*`, `--r-*`, `--density-*`); no hardcoded hex. Read is admin-gated by RLS (the real boundary). RPCs are `SECURITY INVOKER` with `set search_path = ''`.
- **Honesty:** System Health shows a real "Operational"/"Degraded" status (derived from load success), never a fabricated number.
- **Per task, run BOTH** `npx vitest run <file>` AND `npx tsc -b` (vitest uses esbuild and does NOT typecheck — Phase 3 lost time to this). Run npm/npx from inside `ui/`. Coverage gate ≥ 80 statements / 70 branches; `npm run build` must pass.

---

### Task 1: Dashboard time-series RPCs (`0008_dashboard_rpcs.sql`)

**Files:**
- Create: `supabase/migrations/0008_dashboard_rpcs.sql`

**Interfaces:**
- Produces RPCs `admin_signups_by_day(days int)` and `admin_subscriptions_by_day(days int)`, each returning `(day date, count bigint)`, called later via `supabase.rpc(...)`.

- [ ] **Step 1: Write `supabase/migrations/0008_dashboard_rpcs.sql`**

```sql
-- Admin dashboard time-series. SECURITY INVOKER => the caller's RLS applies
-- (admins see all rows; a non-admin only their own — no leak), which also avoids
-- the security-definer-executable advisor warnings. Zero-filled via generate_series
-- so charts render a continuous range.
create or replace function public.admin_signups_by_day(days integer default 14)
returns table(day date, count bigint)
language sql stable security invoker set search_path = ''
as $$
  select d::date as day, count(p.id) as count
  from generate_series(
    (now() - ((greatest(days, 1) - 1) || ' days')::interval)::date, now()::date, interval '1 day'
  ) as d
  left join public.profiles p on p.created_at::date = d::date
  group by d order by d;
$$;

create or replace function public.admin_subscriptions_by_day(days integer default 14)
returns table(day date, count bigint)
language sql stable security invoker set search_path = ''
as $$
  select d::date as day, count(s.id) as count
  from generate_series(
    (now() - ((greatest(days, 1) - 1) || ' days')::interval)::date, now()::date, interval '1 day'
  ) as d
  left join public.subscriptions s on s.created_at::date = d::date and s.status = 'active'
  group by d order by d;
$$;
```

- [ ] **Step 2: Apply via MCP**

Load: `ToolSearch` `select:mcp__5e476b51-5277-4187-9e6f-dba89c611b2f__apply_migration,mcp__5e476b51-5277-4187-9e6f-dba89c611b2f__execute_sql,mcp__5e476b51-5277-4187-9e6f-dba89c611b2f__get_advisors`
Call `apply_migration` (`project_id: brkztcfhmrjjnbjzycie`, `name: 0008_dashboard_rpcs`, `query`: the SQL above). Expected: success.

- [ ] **Step 3: Verify against seed via MCP**

`execute_sql`:
```sql
select (select sum(count) from public.admin_signups_by_day(14)) as signups_14d,
       (select sum(count) from public.admin_subscriptions_by_day(14)) as subs_14d,
       (select count(*) from public.admin_signups_by_day(14)) as signup_rows;
```
Expected: `signups_14d = 5` (the 5 demo users created within 14d), `subs_14d = 3`, `signup_rows = 14`. Capture output.

- [ ] **Step 4: Security advisor**

`get_advisors` `type: security`. Expected: NO new ERROR and NO `*_security_definer_function_executable` warnings for the two new functions (they are SECURITY INVOKER). Note any pre-existing warnings unchanged.

- [ ] **Step 5: Commit**

```bash
git add supabase/migrations/0008_dashboard_rpcs.sql
git commit -m "feat(admin): dashboard time-series RPCs (signups/subscriptions by day)"
```

---

### Task 2: Dashboard formatters (`format.ts`)

**Files:**
- Create: `ui/src/admin/dashboard/format.ts`
- Test: `ui/src/admin/dashboard/format.test.ts`

**Interfaces:**
- Produces: `money(cents: number): string`, `joinedDate(iso: string): string`, `shortDay(iso: string): string`.

- [ ] **Step 1: Write the failing test** `ui/src/admin/dashboard/format.test.ts`

```ts
import { describe, expect, it } from "vitest";
import { money, joinedDate, shortDay } from "./format";

describe("dashboard format helpers", () => {
  it("money: cents → whole-dollar string with separators", () => {
    expect(money(0)).toBe("$0");
    expect(money(5700)).toBe("$57");
    expect(money(199900)).toBe("$1,999");
  });
  it("joinedDate: ISO timestamp → YYYY-MM-DD", () => {
    expect(joinedDate("2026-06-25T12:30:00Z")).toBe("2026-06-25");
  });
  it("shortDay: YYYY-MM-DD → MM-DD", () => {
    expect(shortDay("2026-06-27")).toBe("06-27");
  });
});
```

- [ ] **Step 2: Run it, verify FAIL**

`npx vitest run src/admin/dashboard/format.test.ts` → FAIL (cannot resolve ./format).

- [ ] **Step 3: Implement** `ui/src/admin/dashboard/format.ts`

```ts
/** Stripe-style cents → a whole-dollar display string, e.g. 5700 → "$57". */
export function money(cents: number): string {
  return "$" + Math.round(cents / 100).toLocaleString("en-US");
}

/** ISO timestamp → calendar date "YYYY-MM-DD". */
export function joinedDate(iso: string): string {
  return iso.slice(0, 10);
}

/** A "YYYY-MM-DD" day key → compact "MM-DD" axis label. */
export function shortDay(iso: string): string {
  return iso.slice(5, 10);
}
```

- [ ] **Step 4: Run it (PASS) + typecheck**

`npx vitest run src/admin/dashboard/format.test.ts` → PASS (3). Then `npx tsc -b` → exit 0.

- [ ] **Step 5: Commit**

```bash
git add ui/src/admin/dashboard/format.ts ui/src/admin/dashboard/format.test.ts
git commit -m "feat(admin): dashboard money/date formatters"
```

---

### Task 3: Dashboard data hook (`useAdminDashboard`)

**Files:**
- Create: `ui/src/admin/useAdminDashboard.ts`
- Test: `ui/src/admin/useAdminDashboard.test.tsx`

**Interfaces:**
- Consumes: `supabase`, `supabaseConfigured`.
- Produces (later components depend on these exact shapes):
  - `interface RecentUser { email: string; full_name: string | null; plan: string; status: string; created_at: string }`
  - `interface DayPoint { day: string; count: number }`
  - `interface DashboardStats { total_users: number; paid_users: number; free_users: number; active_today: number; mrr_cents: number; signups_7d: number }`
  - `interface DashboardData { stats: DashboardStats; recentUsers: RecentUser[]; signups: DayPoint[]; subscriptions: DayPoint[] }`
  - `type AdminDashboardState = { status: "loading" } | { status: "error"; error: string } | { status: "ready"; data: DashboardData }`
  - `function useAdminDashboard(): AdminDashboardState`

- [ ] **Step 1: Write the failing test** `ui/src/admin/useAdminDashboard.test.tsx`

```tsx
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

const h = {
  configured: true,
  results: {} as Record<string, { data: unknown; error: unknown }>,
};

vi.mock("../lib/supabase", () => ({
  get supabaseConfigured() {
    return h.configured;
  },
  supabase: {
    from: (table: string) => {
      const b: Record<string, unknown> = {};
      b.select = () => b;
      b.order = () => b;
      b.eq = () => b;
      b.single = () => Promise.resolve(h.results[`${table}:single`]);
      b.limit = () => Promise.resolve(h.results[`${table}:limit`]);
      return b;
    },
    rpc: (name: string) => Promise.resolve(h.results[`rpc:${name}`]),
  },
}));

import { useAdminDashboard } from "./useAdminDashboard";

beforeEach(() => {
  h.configured = true;
  h.results = {
    "admin_dashboard_stats:single": {
      data: { total_users: 5, paid_users: 3, free_users: 2, active_today: 108, mrr_cents: 5700, signups_7d: 3 },
      error: null,
    },
    "profiles:limit": {
      data: [{ email: "a@b.com", full_name: "A", plan: "pro", status: "active", created_at: "2026-06-25T00:00:00Z" }],
      error: null,
    },
    "rpc:admin_signups_by_day": { data: [{ day: "2026-06-27", count: 5 }], error: null },
    "rpc:admin_subscriptions_by_day": { data: [{ day: "2026-06-27", count: 3 }], error: null },
  };
});
afterEach(() => vi.clearAllMocks());

describe("useAdminDashboard", () => {
  it("resolves to ready with coerced stats + arrays", async () => {
    const { result } = renderHook(() => useAdminDashboard());
    await waitFor(() => expect(result.current.status).toBe("ready"));
    if (result.current.status !== "ready") throw new Error("not ready");
    expect(result.current.data.stats.total_users).toBe(5);
    expect(result.current.data.stats.mrr_cents).toBe(5700);
    expect(result.current.data.recentUsers).toHaveLength(1);
    expect(result.current.data.signups[0]).toEqual({ day: "2026-06-27", count: 5 });
  });

  it("coerces bigint-as-string counts to numbers", async () => {
    h.results["admin_dashboard_stats:single"].data = {
      total_users: "5", paid_users: "3", free_users: "2", active_today: "108", mrr_cents: "5700", signups_7d: "3",
    };
    h.results["rpc:admin_signups_by_day"].data = [{ day: "2026-06-27", count: "5" }];
    const { result } = renderHook(() => useAdminDashboard());
    await waitFor(() => expect(result.current.status).toBe("ready"));
    if (result.current.status !== "ready") throw new Error("not ready");
    expect(result.current.data.stats.total_users).toBe(5);
    expect(result.current.data.signups[0].count).toBe(5);
  });

  it("errors when a query fails", async () => {
    h.results["rpc:admin_signups_by_day"] = { data: null, error: { message: "boom" } };
    const { result } = renderHook(() => useAdminDashboard());
    await waitFor(() => expect(result.current.status).toBe("error"));
  });

  it("errors when the backend is unconfigured", async () => {
    h.configured = false;
    const { result } = renderHook(() => useAdminDashboard());
    await waitFor(() => expect(result.current.status).toBe("error"));
  });
});
```

- [ ] **Step 2: Run it, verify FAIL**

`npx vitest run src/admin/useAdminDashboard.test.tsx` → FAIL (cannot resolve ./useAdminDashboard).

- [ ] **Step 3: Implement** `ui/src/admin/useAdminDashboard.ts`

```ts
import { useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../lib/supabase";

export interface RecentUser {
  email: string;
  full_name: string | null;
  plan: string;
  status: string;
  created_at: string;
}
export interface DayPoint {
  day: string;
  count: number;
}
export interface DashboardStats {
  total_users: number;
  paid_users: number;
  free_users: number;
  active_today: number;
  mrr_cents: number;
  signups_7d: number;
}
export interface DashboardData {
  stats: DashboardStats;
  recentUsers: RecentUser[];
  signups: DayPoint[];
  subscriptions: DayPoint[];
}
export type AdminDashboardState =
  | { status: "loading" }
  | { status: "error"; error: string }
  | { status: "ready"; data: DashboardData };

const num = (v: unknown): number => {
  const n = Number(v ?? 0);
  return Number.isFinite(n) ? n : 0;
};

const toStats = (r: Record<string, unknown> | null): DashboardStats => ({
  total_users: num(r?.total_users),
  paid_users: num(r?.paid_users),
  free_users: num(r?.free_users),
  active_today: num(r?.active_today),
  mrr_cents: num(r?.mrr_cents),
  signups_7d: num(r?.signups_7d),
});

const toDays = (rows: unknown): DayPoint[] =>
  Array.isArray(rows)
    ? rows.map((r) => ({ day: String((r as { day: unknown }).day), count: num((r as { count: unknown }).count) }))
    : [];

export function useAdminDashboard(): AdminDashboardState {
  const [state, setState] = useState<AdminDashboardState>({ status: "loading" });

  useEffect(() => {
    if (!supabaseConfigured || !supabase) {
      setState({ status: "error", error: "Backend not configured" });
      return;
    }
    const client = supabase;
    let cancelled = false;
    void (async () => {
      try {
        const [stats, users, signups, subs] = await Promise.all([
          client.from("admin_dashboard_stats").select("*").single(),
          client
            .from("profiles")
            .select("email,full_name,plan,status,created_at")
            .order("created_at", { ascending: false })
            .limit(8),
          client.rpc("admin_signups_by_day", { days: 14 }),
          client.rpc("admin_subscriptions_by_day", { days: 14 }),
        ]);
        const firstErr = stats.error || users.error || signups.error || subs.error;
        if (firstErr) throw new Error((firstErr as { message?: string }).message ?? "Query failed");
        if (cancelled) return;
        setState({
          status: "ready",
          data: {
            stats: toStats(stats.data as Record<string, unknown> | null),
            recentUsers: (users.data ?? []) as RecentUser[],
            signups: toDays(signups.data),
            subscriptions: toDays(subs.data),
          },
        });
      } catch (e) {
        if (!cancelled) setState({ status: "error", error: e instanceof Error ? e.message : String(e) });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}
```

- [ ] **Step 4: Run it (PASS) + typecheck**

`npx vitest run src/admin/useAdminDashboard.test.tsx` → PASS (4). `npx tsc -b` → exit 0.

- [ ] **Step 5: Commit**

```bash
git add ui/src/admin/useAdminDashboard.ts ui/src/admin/useAdminDashboard.test.tsx
git commit -m "feat(admin): useAdminDashboard data hook (stats + recent users + series)"
```

---

### Task 4: KPI cards + System Health (`KpiCards`)

**Files:**
- Create: `ui/src/admin/dashboard/KpiCards.tsx`
- Test: `ui/src/admin/dashboard/KpiCards.test.tsx`

**Interfaces:**
- Consumes: `StatTile`, `money`, `DashboardStats`.
- Produces: `function KpiCards({ stats, healthy }: { stats: DashboardStats; healthy: boolean }): JSX.Element`; `function SystemHealthCard({ healthy }: { healthy: boolean }): JSX.Element`.

- [ ] **Step 1: Write the failing test** `ui/src/admin/dashboard/KpiCards.test.tsx`

```tsx
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { KpiCards, SystemHealthCard } from "./KpiCards";

const stats = { total_users: 5, paid_users: 3, free_users: 2, active_today: 108, mrr_cents: 5700, signups_7d: 3 };

describe("KpiCards", () => {
  it("renders the six KPIs with formatted values", () => {
    render(<KpiCards stats={stats} healthy={true} />);
    expect(screen.getByText("Total Users")).toBeInTheDocument();
    expect(screen.getByText("Revenue (MRR)")).toBeInTheDocument();
    expect(screen.getByText("$57")).toBeInTheDocument();
    expect(screen.getByText("108")).toBeInTheDocument();
  });
  it("System Health reflects the healthy flag", () => {
    const { rerender } = render(<SystemHealthCard healthy={true} />);
    expect(screen.getByText("Operational")).toBeInTheDocument();
    rerender(<SystemHealthCard healthy={false} />);
    expect(screen.getByText("Degraded")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run it, verify FAIL**

`npx vitest run src/admin/dashboard/KpiCards.test.tsx` → FAIL (cannot resolve ./KpiCards).

- [ ] **Step 3: Implement** `ui/src/admin/dashboard/KpiCards.tsx`

```tsx
import { StatTile } from "../../cockpit/primitives";
import type { DashboardStats } from "../useAdminDashboard";
import { money } from "./format";

/** Real System Health: "Operational" when the dashboard loaded, "Degraded" otherwise.
 *  No fabricated uptime number. */
export function SystemHealthCard({ healthy }: { healthy: boolean }) {
  const color = healthy ? "var(--color-sev-low)" : "var(--color-sev-high)";
  return (
    <div className="rounded-[var(--r-tile)] bg-[var(--color-surface-2)] px-3 py-2.5">
      <div className="t-label text-[var(--color-text-dim)]">System Health</div>
      <div className="mt-0.5 text-[var(--fs-display)] font-medium leading-none" style={{ color }}>
        {healthy ? "Operational" : "Degraded"}
      </div>
      <div className="mt-1 t-tag text-[var(--color-text-faint)]">
        {healthy ? "All systems normal" : "Check connectivity"}
      </div>
    </div>
  );
}

export function KpiCards({ stats, healthy }: { stats: DashboardStats; healthy: boolean }) {
  return (
    <div className="grid grid-cols-2 gap-[var(--density-gap-sm)] sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7">
      <StatTile label="Total Users" value={stats.total_users.toLocaleString()} />
      <StatTile label="Paid Users" value={stats.paid_users.toLocaleString()} accent />
      <StatTile label="Free Users" value={stats.free_users.toLocaleString()} />
      <StatTile label="Active Today" value={stats.active_today.toLocaleString()} />
      <StatTile label="Revenue (MRR)" value={money(stats.mrr_cents)} />
      <StatTile label="New (7d)" value={stats.signups_7d.toLocaleString()} />
      <SystemHealthCard healthy={healthy} />
    </div>
  );
}

export default KpiCards;
```

- [ ] **Step 4: Run it (PASS) + typecheck**

`npx vitest run src/admin/dashboard/KpiCards.test.tsx` → PASS (2). `npx tsc -b` → exit 0.

- [ ] **Step 5: Commit**

```bash
git add ui/src/admin/dashboard/KpiCards.tsx ui/src/admin/dashboard/KpiCards.test.tsx
git commit -m "feat(admin): dashboard KPI cards + System Health status"
```

---

### Task 5: Charts (`SignupsAreaChart`, `SubscriptionsBarChart`)

**Files:**
- Create: `ui/src/admin/dashboard/SignupsAreaChart.tsx`
- Create: `ui/src/admin/dashboard/SubscriptionsBarChart.tsx`
- Test: `ui/src/admin/dashboard/charts.test.tsx`

**Interfaces:**
- Consumes: `recharts`, `DayPoint`, `shortDay`.
- Produces: `function SignupsAreaChart({ data }: { data: DayPoint[] }): JSX.Element`; `function SubscriptionsBarChart({ data }: { data: DayPoint[] }): JSX.Element`.

- [ ] **Step 1: Write the failing test** `ui/src/admin/dashboard/charts.test.tsx`

```tsx
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { SignupsAreaChart } from "./SignupsAreaChart";
import { SubscriptionsBarChart } from "./SubscriptionsBarChart";

const data = [
  { day: "2026-06-26", count: 2 },
  { day: "2026-06-27", count: 3 },
];

describe("dashboard charts", () => {
  it("area chart renders its container with data", () => {
    const { container } = render(<SignupsAreaChart data={data} />);
    expect(container.querySelector('[data-component="SignupsAreaChart"]')).toBeInTheDocument();
  });
  it("bar chart renders its container with data", () => {
    const { container } = render(<SubscriptionsBarChart data={data} />);
    expect(container.querySelector('[data-component="SubscriptionsBarChart"]')).toBeInTheDocument();
  });
  it("show an empty-state message when there is no data", () => {
    render(<SignupsAreaChart data={[]} />);
    expect(screen.getByText(/no data/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run it, verify FAIL**

`npx vitest run src/admin/dashboard/charts.test.tsx` → FAIL (cannot resolve the chart modules).

- [ ] **Step 3: Implement** `ui/src/admin/dashboard/SignupsAreaChart.tsx`

```tsx
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { DayPoint } from "../useAdminDashboard";
import { shortDay } from "./format";

const ACCENT = "var(--color-accent)";

export function SignupsAreaChart({ data }: { data: DayPoint[] }) {
  if (data.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center text-sm text-[var(--color-text-faint)]">No data</div>
    );
  }
  return (
    <div data-component="SignupsAreaChart" className="h-48 w-full text-[var(--color-text-dim)]">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 12, bottom: 4, left: 4 }}>
          <defs>
            <linearGradient id="signups-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={ACCENT} stopOpacity={0.35} />
              <stop offset="100%" stopColor={ACCENT} stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="var(--color-grid)" strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="day" tickFormatter={shortDay} tick={{ fill: "var(--color-text-faint)", fontSize: 11 }} stroke="var(--color-border)" minTickGap={24} tickMargin={8} />
          <YAxis width={32} allowDecimals={false} tick={{ fill: "var(--color-text-faint)", fontSize: 11 }} stroke="var(--color-border)" />
          <Tooltip
            cursor={{ stroke: ACCENT, strokeOpacity: 0.4 }}
            contentStyle={{ background: "var(--color-surface-2)", border: "1px solid var(--color-border)", borderRadius: 8, fontSize: 12 }}
          />
          <Area type="monotone" dataKey="count" name="New users" stroke={ACCENT} strokeWidth={1.75} fill="url(#signups-fill)" isAnimationActive={false} dot={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

export default SignupsAreaChart;
```

- [ ] **Step 4: Implement** `ui/src/admin/dashboard/SubscriptionsBarChart.tsx`

```tsx
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { DayPoint } from "../useAdminDashboard";
import { shortDay } from "./format";

const ACCENT = "var(--color-accent)";

export function SubscriptionsBarChart({ data }: { data: DayPoint[] }) {
  if (data.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center text-sm text-[var(--color-text-faint)]">No data</div>
    );
  }
  return (
    <div data-component="SubscriptionsBarChart" className="h-48 w-full text-[var(--color-text-dim)]">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 12, bottom: 4, left: 4 }}>
          <CartesianGrid stroke="var(--color-grid)" strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="day" tickFormatter={shortDay} tick={{ fill: "var(--color-text-faint)", fontSize: 11 }} stroke="var(--color-border)" minTickGap={24} tickMargin={8} />
          <YAxis width={32} allowDecimals={false} tick={{ fill: "var(--color-text-faint)", fontSize: 11 }} stroke="var(--color-border)" />
          <Tooltip
            cursor={{ fill: "var(--color-surface-2)", fillOpacity: 0.5 }}
            contentStyle={{ background: "var(--color-surface-2)", border: "1px solid var(--color-border)", borderRadius: 8, fontSize: 12 }}
          />
          <Bar dataKey="count" name="New subscriptions" fill={ACCENT} radius={[2, 2, 0, 0]} isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export default SubscriptionsBarChart;
```

- [ ] **Step 5: Run it (PASS) + typecheck**

`npx vitest run src/admin/dashboard/charts.test.tsx` → PASS (3). `npx tsc -b` → exit 0. (recharts logs a jsdom width/height warning — harmless; we assert only the container/fallback, not SVG internals.)

- [ ] **Step 6: Commit**

```bash
git add ui/src/admin/dashboard/SignupsAreaChart.tsx ui/src/admin/dashboard/SubscriptionsBarChart.tsx ui/src/admin/dashboard/charts.test.tsx
git commit -m "feat(admin): dashboard signups area + subscriptions bar charts"
```

---

### Task 6: Recent users table (`RecentUsersTable`)

**Files:**
- Create: `ui/src/admin/dashboard/RecentUsersTable.tsx`
- Test: `ui/src/admin/dashboard/RecentUsersTable.test.tsx`

**Interfaces:**
- Consumes: `RecentUser`, `joinedDate`.
- Produces: `function RecentUsersTable({ users }: { users: RecentUser[] }): JSX.Element`.

- [ ] **Step 1: Write the failing test** `ui/src/admin/dashboard/RecentUsersTable.test.tsx`

```tsx
import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { RecentUsersTable } from "./RecentUsersTable";

const users = [
  { email: "alice@x.com", full_name: "Alice", plan: "pro", status: "active", created_at: "2026-06-25T00:00:00Z" },
  { email: "bob@x.com", full_name: null, plan: "free", status: "suspended", created_at: "2026-06-20T00:00:00Z" },
];

describe("RecentUsersTable", () => {
  it("renders a row per user with name/email/plan/status/joined", () => {
    render(<RecentUsersTable users={users} />);
    const table = screen.getByRole("table");
    expect(within(table).getByText("Alice")).toBeInTheDocument();
    expect(within(table).getByText("bob")).toBeInTheDocument(); // falls back to email local-part
    expect(within(table).getByText("alice@x.com")).toBeInTheDocument();
    expect(within(table).getByText("2026-06-25")).toBeInTheDocument();
    expect(within(table).getAllByRole("row")).toHaveLength(3); // header + 2
  });
  it("shows an empty state when there are no users", () => {
    render(<RecentUsersTable users={[]} />);
    expect(screen.getByText(/no users yet/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run it, verify FAIL**

`npx vitest run src/admin/dashboard/RecentUsersTable.test.tsx` → FAIL (cannot resolve ./RecentUsersTable).

- [ ] **Step 3: Implement** `ui/src/admin/dashboard/RecentUsersTable.tsx`

```tsx
import type { RecentUser } from "../useAdminDashboard";
import { joinedDate } from "./format";

const STATUS_COLOR: Record<string, string> = {
  active: "var(--color-sev-low)",
  suspended: "var(--color-sev-medium)",
  blocked: "var(--color-sev-critical)",
};

export function RecentUsersTable({ users }: { users: RecentUser[] }) {
  if (users.length === 0) {
    return <p className="text-sm text-[var(--color-text-dim)]">No users yet.</p>;
  }
  return (
    <table className="pp-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Email</th>
          <th>Plan</th>
          <th>Status</th>
          <th>Joined</th>
        </tr>
      </thead>
      <tbody>
        {users.map((u) => {
          const color = STATUS_COLOR[u.status] ?? "var(--color-text-dim)";
          return (
            <tr key={u.email}>
              <td>{u.full_name ?? u.email.split("@")[0]}</td>
              <td className="text-[var(--color-text-dim)]">{u.email}</td>
              <td>
                <span className="inline-flex items-center rounded-[var(--r-chip)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-1.5 py-0.5 t-tag uppercase text-[var(--color-text-dim)]">
                  {u.plan}
                </span>
              </td>
              <td>
                <span className="inline-flex items-center gap-1.5 t-tag uppercase" style={{ color }}>
                  <span aria-hidden className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
                  {u.status}
                </span>
              </td>
              <td className="font-mono-num text-[var(--color-text-dim)]">{joinedDate(u.created_at)}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

export default RecentUsersTable;
```

- [ ] **Step 4: Run it (PASS) + typecheck**

`npx vitest run src/admin/dashboard/RecentUsersTable.test.tsx` → PASS (2). `npx tsc -b` → exit 0.

- [ ] **Step 5: Commit**

```bash
git add ui/src/admin/dashboard/RecentUsersTable.tsx ui/src/admin/dashboard/RecentUsersTable.test.tsx
git commit -m "feat(admin): read-only recent-users table"
```

---

### Task 7: Compose `AdminDashboard` + wire shell + full verification

**Files:**
- Create: `ui/src/admin/dashboard/AdminDashboard.tsx`
- Create: `ui/src/admin/dashboard/AdminDashboard.test.tsx`
- Modify: `ui/src/admin/AdminShell.tsx` (import path)
- Modify: `ui/src/admin/AdminShell.test.tsx` (mock + assertion)
- Delete: `ui/src/admin/views/AdminDashboard.tsx`

**Interfaces:**
- Consumes: `useAdminDashboard`, `KpiCards`, `SignupsAreaChart`, `SubscriptionsBarChart`, `RecentUsersTable`, `Card`, `LoadingState`, `ErrorState`.
- Produces: `default export function AdminDashboard()` consumed by `AdminShell`.

- [ ] **Step 1: Write the failing test** `ui/src/admin/dashboard/AdminDashboard.test.tsx`

```tsx
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";

const mockState = vi.fn();
vi.mock("../useAdminDashboard", () => ({ useAdminDashboard: () => mockState() }));

import AdminDashboard from "./AdminDashboard";

const ready = {
  status: "ready",
  data: {
    stats: { total_users: 5, paid_users: 3, free_users: 2, active_today: 108, mrr_cents: 5700, signups_7d: 3 },
    recentUsers: [{ email: "a@b.com", full_name: "A", plan: "pro", status: "active", created_at: "2026-06-25T00:00:00Z" }],
    signups: [{ day: "2026-06-27", count: 5 }],
    subscriptions: [{ day: "2026-06-27", count: 3 }],
  },
};

describe("AdminDashboard", () => {
  it("shows the loading state while loading", () => {
    mockState.mockReturnValue({ status: "loading" });
    render(<AdminDashboard />);
    expect(screen.getByRole("status")).toBeInTheDocument();
  });
  it("shows the error message on error", () => {
    mockState.mockReturnValue({ status: "error", error: "boom" });
    render(<AdminDashboard />);
    expect(screen.getByText(/boom/i)).toBeInTheDocument();
  });
  it("renders KPIs, both chart cards, and the table when ready", () => {
    mockState.mockReturnValue(ready);
    render(<AdminDashboard />);
    expect(screen.getByText("Total Users")).toBeInTheDocument();
    expect(screen.getByText("Daily New Users")).toBeInTheDocument();
    expect(screen.getByText("New Subscriptions")).toBeInTheDocument();
    expect(screen.getByText("Recent Users")).toBeInTheDocument();
    expect(screen.getByText("Operational")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run it, verify FAIL**

`npx vitest run src/admin/dashboard/AdminDashboard.test.tsx` → FAIL (cannot resolve ./AdminDashboard).

- [ ] **Step 3: Implement** `ui/src/admin/dashboard/AdminDashboard.tsx`

```tsx
import { Card } from "../../cockpit/primitives";
import { LoadingState } from "../../components/state/LoadingState";
import { ErrorState } from "../../components/state/ErrorState";
import { useAdminDashboard } from "../useAdminDashboard";
import { KpiCards } from "./KpiCards";
import { SignupsAreaChart } from "./SignupsAreaChart";
import { SubscriptionsBarChart } from "./SubscriptionsBarChart";
import { RecentUsersTable } from "./RecentUsersTable";

export function AdminDashboard() {
  const state = useAdminDashboard();
  if (state.status === "loading") return <LoadingState label="Loading dashboard…" />;
  if (state.status === "error") return <ErrorState message={state.error} />;
  const { stats, recentUsers, signups, subscriptions } = state.data;
  return (
    <div className="flex flex-col gap-[var(--density-gap)]">
      <KpiCards stats={stats} healthy={true} />
      <div className="grid gap-[var(--density-gap)] lg:grid-cols-2">
        <Card title="Daily New Users">
          <SignupsAreaChart data={signups} />
        </Card>
        <Card title="New Subscriptions">
          <SubscriptionsBarChart data={subscriptions} />
        </Card>
      </div>
      <Card title="Recent Users">
        <RecentUsersTable users={recentUsers} />
      </Card>
    </div>
  );
}

export default AdminDashboard;
```

- [ ] **Step 4: Run it (PASS)**

`npx vitest run src/admin/dashboard/AdminDashboard.test.tsx` → PASS (3).

- [ ] **Step 5: Repoint the shell import** in `ui/src/admin/AdminShell.tsx`

Change the import line:
```tsx
import { AdminDashboard } from "./views/AdminDashboard";
```
to:
```tsx
import { AdminDashboard } from "./dashboard/AdminDashboard";
```
(Leave `import { Placeholder } from "./views/Placeholder";` unchanged.)

- [ ] **Step 6: Delete the placeholder** `ui/src/admin/views/AdminDashboard.tsx`

```bash
git rm ui/src/admin/views/AdminDashboard.tsx
```

- [ ] **Step 7: Update `ui/src/admin/AdminShell.test.tsx`** so the shell test stays data-free

Add this mock near the top (after the existing imports, before `describe`):
```tsx
vi.mock("./dashboard/AdminDashboard", () => ({ AdminDashboard: () => <div>DASHBOARD_STUB</div> }));
```
Then in the first test ("renders all seven nav items and defaults to the dashboard"), replace the line:
```tsx
    expect(screen.getByText(/overview metrics arrive in phase 4/i)).toBeInTheDocument();
```
with:
```tsx
    expect(screen.getByText("DASHBOARD_STUB")).toBeInTheDocument();
```
(The other AdminShell tests — nav switch, sign-out, toggles — are unchanged; the "Users" switch test still asserts the Phase-5 placeholder copy, which is unaffected.)

- [ ] **Step 8: Full verification**

From `ui/`:
- `npx tsc -b` → exit 0 (no dangling import to the deleted file).
- `npx vitest run src/admin` → all admin tests pass (incl. the updated AdminShell test).
- `npm run build` → tsc + vite succeed.
- `npm run test:coverage` → full suite green; coverage ≥ 80/70. Report the "All files" line.

- [ ] **Step 9: Commit**

```bash
git add ui/src/admin/dashboard/AdminDashboard.tsx ui/src/admin/dashboard/AdminDashboard.test.tsx ui/src/admin/AdminShell.tsx ui/src/admin/AdminShell.test.tsx
git commit -m "feat(admin): real dashboard (KPIs + charts + recent users); wire shell"
```

---

### Task 8: Browser smoke test (controller)

**Files:** none (operational).

- [ ] **Step 1: Run the dashboard in a real browser**

Ensure the dev server is running (preview tools). Navigate to `/admin`, sign in as `ravi.dholariya@icloud.com`, and confirm the dashboard renders real data: **Total Users 5, Paid 3, Free 2, Revenue $57, New (7d) 3, System Health Operational**, both chart cards present, and the recent-users table lists the demo users. Check `preview_console_logs` (errors) + `preview_network` (failed) are clean. Capture a snapshot as proof.

- [ ] **Step 2: No commit** (operational).

---

## Self-Review

**1. Spec coverage:**
- RPCs (signups/subscriptions by day, SECURITY INVOKER, search_path) → Task 1. ✅
- Money/date formatters → Task 2. ✅
- `useAdminDashboard` (parallel fetch, coercion, loading/ready/error, unconfigured guard) → Task 3. ✅
- 6 KPI cards + real System Health → Task 4. ✅
- Area + bar charts (tokenized, empty-state) → Task 5. ✅
- Read-only recent-users `.pp-table` → Task 6. ✅
- `AdminDashboard` composition + shell wiring + placeholder deletion + AdminShell.test update → Task 7. ✅
- Live RPC verification + browser smoke → Tasks 1, 8. ✅
- No `/app`/engine/shell-auth change; tokens-only; no new deps → enforced per task + Global Constraints. ✅

**2. Placeholder scan:** No "TBD/handle errors/similar to Task N". `DASHBOARD_STUB`/`No data`/`No users yet` are intentional literals. Every code step has complete code.

**3. Type consistency:** `DashboardStats`/`DayPoint`/`RecentUser`/`DashboardData`/`AdminDashboardState` defined in Task 3 and consumed unchanged in Tasks 4–7. `KpiCards({stats,healthy})`, `SystemHealthCard({healthy})`, `SignupsAreaChart/SubscriptionsBarChart({data})`, `RecentUsersTable({users})` signatures match their call sites in Task 7. `money`/`joinedDate`/`shortDay` (Task 2) used consistently. `AdminDashboard` default-exported (Task 7) and imported named in `AdminShell` (both named + default exist). RPC names match between Task 1 SQL and Task 3 `rpc(...)` calls.

## Execution Handoff

(See message.)
