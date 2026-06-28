# Live Traffic + Analytics Ingestion (Phase 7) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collect benign page-view analytics across all surfaces through one allowlist-enforcing tracker (never any capture data), tighten the analytics insert RLS, and add an admin Live Traffic view.

**Architecture:** A single `track.ts` inserts `{canonical-path, session-uuid, auth-uid?}` rows directly (anon key, RLS-gated); migration `0010` replaces the `WITH CHECK (true)` policy with role-split + path-allowlist policies + a per-session rate trigger. Migration `0011` adds SECURITY-INVOKER read RPCs/view; a `useAdminTraffic` hook + `TrafficView` render them, reusing the dashboard's recharts wrappers.

**Tech Stack:** React 18 + TS, Phase-0 Supabase client, recharts (existing), Tailwind tokens, Vitest + RTL. Supabase MCP for migrations 0010/0011.

## Global Constraints

- **HARD privacy boundary:** events carry ONLY a canonical route token, a `sessionStorage` UUID, and (if signed in) the auth uid read from `supabase.auth`. The tracker imports ONLY `../supabase` — never App/summary/flows/recent/IndexedDB/reputation. Off-allowlist paths are dropped; the DB `WITH CHECK` backstops the shape and forbids `referrer`/`user_agent`/`country` from the public roles.
- **Single inserter:** `.from("analytics_events").insert(` appears in exactly one file — `track.ts` (a test enforces it).
- **No Edge Function, no secret in the SPA, no new SPA deps** (`crypto.randomUUID`, `sessionStorage` are platform).
- **Dashboard consistency:** Live Traffic `active_today` = `COUNT(DISTINCT session_id)` over 24h — identical to `admin_dashboard_stats`.
- **SQL functions:** SECURITY INVOKER for read RPCs/view; the rate trigger is SECURITY DEFINER + `search_path=''` + EXECUTE revoked (mirrors the Phase-5 audit trigger).
- **Migration numbering:** `0010` then `0011` (`0009` is the latest applied).
- **Canonical tokens (13):** `/`, `/app#{dashboard,flows,findings,recent,compare}`, `/admin#{dashboard,users,payments,traffic,features,settings,env}`.
- **Per-task gate:** `npx tsc -b` (Vitest skips typecheck). Final task runs `npm run test:coverage` (≥80/70) + `npm run build`. All UI commands from `D:\Project\PacketPilot\ui`.

---

### Task 1: Migration `0010` — analytics ingest hardening (controller-run via MCP)

Executed by the controller (live DB + MCP): write the file, apply, verify RLS accept/reject as `anon`, check advisors, commit.

**Files:** Create `supabase/migrations/0010_analytics_ingest_hardening.sql`

- [ ] **Step 1: Write the migration file** — exact SQL from the spec's "Ingestion — `0010`" block (drop `analytics_insert_any`; create `analytics_insert_anon` + `analytics_insert_authenticated` with the path-allowlist/forbid-fields WITH CHECK; create `analytics_rate_limit()` SECURITY DEFINER + revoke + trigger).

- [ ] **Step 2: Apply (MCP `apply_migration`, name `analytics_ingest_hardening`).** Expected: success.

- [ ] **Step 3: Verify RLS accept/reject as `anon` (MCP `execute_sql`, each in its own tx so the rollback discards test rows):**
  - Allowed: `begin; set local role anon; insert into public.analytics_events (session_id, path) values ('t-ok','/app#flows'); rollback;` → succeeds.
  - Rejected (off-allowlist): `begin; set local role anon; insert into public.analytics_events (session_id, path) values ('t-bad','/app/secret/10.0.0.1'); rollback;` → RLS error (new row violates WITH CHECK).
  - Rejected (forbidden field): `begin; set local role anon; insert into public.analytics_events (session_id, path, user_agent) values ('t-ua','/','Mozilla/5.0'); rollback;` → RLS error.
  - Rejected (anon with user_id): `begin; set local role anon; insert into public.analytics_events (session_id, path, user_id) values ('t-uid','/','00000000-0000-0000-0000-000000000000'); rollback;` → RLS error.

- [ ] **Step 4: Advisors (MCP `get_advisors` type=security).** Expected: no new ERROR; `analytics_rate_limit` not flagged as publicly-executable (the revoke clears it). The pre-existing `analytics_insert_any` "RLS always true" WARN should be GONE (policy dropped).

- [ ] **Step 5: Commit**
```bash
cd "D:/Project/PacketPilot" && git add supabase/migrations/0010_analytics_ingest_hardening.sql && git commit -m "feat(db): tighten analytics insert RLS + per-session rate trigger (0010)"
```

---

### Task 2: `track.ts` tracker + tests (+ `TAB_IDS` single-source)

**Files:**
- Modify: `ui/src/types.ts` (add `TAB_IDS`, derive `TabId` from it)
- Create: `ui/src/lib/analytics/track.ts`
- Test: `ui/src/lib/analytics/track.test.ts`, `ui/src/lib/analytics/track.drift.test.ts`, `ui/src/lib/analytics/track.singleInserter.test.ts`

**Interfaces:**
- Consumes: `supabase` from `../supabase`; `TAB_IDS` from `../../types`; `ADMIN_SECTIONS` from `../../admin/sections`.
- Produces: `trackPageView(path: string): void`; `__resetTrackerForTests(): void`.

- [ ] **Step 1: Make `TabId` a single source.** In `ui/src/types.ts`, replace `export type TabId = "dashboard" | "flows" | "findings" | "recent" | "compare";` with:
```ts
export const TAB_IDS = ["dashboard", "flows", "findings", "recent", "compare"] as const;
export type TabId = (typeof TAB_IDS)[number];
```
Run `cd "D:/Project/PacketPilot/ui" && npx tsc -b` → expect exit 0 (the union is identical; existing imports of `TabId` are unaffected).

- [ ] **Step 2: Write the failing tracker test**

`ui/src/lib/analytics/track.test.ts`:
```ts
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const insert = vi.fn(() => ({ then: (res: () => void) => { res(); return Promise.resolve(); } }));
const from = vi.fn(() => ({ insert }));
const getSession = vi.fn(() => Promise.resolve({ data: { session: { user: { id: "u-1" } } } }));
vi.mock("../supabase", () => ({ supabase: { from: (...a: unknown[]) => from(...a), auth: { getSession: () => getSession() } } }));

import { trackPageView, __resetTrackerForTests } from "./track";

beforeEach(() => {
  __resetTrackerForTests();
  sessionStorage.clear();
  from.mockClear(); insert.mockClear();
  getSession.mockResolvedValue({ data: { session: { user: { id: "u-1" } } } });
});
afterEach(() => {
  vi.restoreAllMocks();
});

const flush = () => new Promise((r) => setTimeout(r, 0));

describe("trackPageView", () => {
  it("inserts an allowlisted token with a session id and the auth uid", async () => {
    trackPageView("/app#flows");
    await flush();
    expect(from).toHaveBeenCalledWith("analytics_events");
    const payload = insert.mock.calls[0][0] as Record<string, unknown>;
    expect(payload.path).toBe("/app#flows");
    expect(typeof payload.session_id).toBe("string");
    expect((payload.session_id as string).length).toBeGreaterThan(10);
    expect(payload.user_id).toBe("u-1");
    expect(payload).not.toHaveProperty("referrer");
    expect(payload).not.toHaveProperty("user_agent");
    expect(payload).not.toHaveProperty("country");
    expect(payload).not.toHaveProperty("created_at");
  });

  it("sends user_id null when signed out", async () => {
    getSession.mockResolvedValue({ data: { session: null } });
    trackPageView("/");
    await flush();
    expect((insert.mock.calls[0][0] as Record<string, unknown>).user_id).toBeNull();
  });

  it("drops non-allowlisted paths (capture-shaped, query, unknown)", async () => {
    trackPageView("/app/secret/10.0.0.1");
    trackPageView("/?host=evil.com");
    trackPageView("/admin#nope");
    await flush();
    expect(insert).not.toHaveBeenCalled();
  });

  it("dedupes consecutive identical tokens but re-fires after a change", async () => {
    trackPageView("/app#flows");
    trackPageView("/app#flows");
    await flush();
    expect(insert).toHaveBeenCalledTimes(1);
    trackPageView("/app#recent");
    await flush();
    expect(insert).toHaveBeenCalledTimes(2);
  });

  it("reuses one sessionStorage id across calls", async () => {
    trackPageView("/app#flows");
    trackPageView("/app#recent");
    await flush();
    const a = (insert.mock.calls[0][0] as { session_id: string }).session_id;
    const b = (insert.mock.calls[1][0] as { session_id: string }).session_id;
    expect(a).toBe(b);
    expect(sessionStorage.getItem("pp_sid")).toBe(a);
  });
});
```

- [ ] **Step 3: Run it to verify it fails** — `cd "D:/Project/PacketPilot/ui" && npx vitest run src/lib/analytics/track.test.ts` → FAIL (cannot resolve `./track`).

- [ ] **Step 4: Write `ui/src/lib/analytics/track.ts`**
```ts
import { supabase } from "../supabase";

// The ONLY paths ever sent. Adding an app tab or admin section requires extending this
// (track.drift.test enforces it). Off-list paths are dropped, so a path can never carry
// an IP, host, SNI, hash, or query string.
const ROUTES = new Set<string>([
  "/",
  "/app#dashboard",
  "/app#flows",
  "/app#findings",
  "/app#recent",
  "/app#compare",
  "/admin#dashboard",
  "/admin#users",
  "/admin#payments",
  "/admin#traffic",
  "/admin#features",
  "/admin#settings",
  "/admin#env",
]);

const SID_KEY = "pp_sid";
let lastPath: string | null = null;
const noop = () => {};

function sessionId(): string {
  try {
    let sid = sessionStorage.getItem(SID_KEY);
    if (!sid) {
      sid = crypto.randomUUID();
      sessionStorage.setItem(SID_KEY, sid);
    }
    return sid;
  } catch {
    return crypto.randomUUID();
  }
}

/**
 * Record a page view for an allowlisted canonical route token. Fire-and-forget,
 * failure-silent, and incapable of carrying capture data (off-list paths are dropped).
 * Reads only the auth session from supabase — never any capture/analysis state.
 */
export function trackPageView(path: string): void {
  if (!ROUTES.has(path) || path === lastPath) return;
  lastPath = path;
  const client = supabase;
  if (!client) return;
  const session_id = sessionId();
  void client.auth.getSession().then(({ data }) => {
    void client
      .from("analytics_events")
      .insert({ path, session_id, user_id: data.session?.user?.id ?? null })
      .then(noop, noop);
  }, noop);
}

/** Test-only: reset the consecutive-dedupe guard between cases. */
export function __resetTrackerForTests(): void {
  lastPath = null;
}
```

- [ ] **Step 5: Run the tracker test + tsc** — `cd "D:/Project/PacketPilot/ui" && npx vitest run src/lib/analytics/track.test.ts && npx tsc -b` → 5/5 PASS; tsc 0.

- [ ] **Step 6: Write the drift + single-inserter tests**

`ui/src/lib/analytics/track.drift.test.ts`:
```ts
import { describe, expect, it } from "vitest";
import { TAB_IDS } from "../../types";
import { ADMIN_SECTIONS } from "../../admin/sections";
import { ROUTES_FOR_TESTS } from "./track";

describe("tracker route allowlist drift guard", () => {
  it("covers every app tab and admin section", () => {
    for (const t of TAB_IDS) expect(ROUTES_FOR_TESTS.has(`/app#${t}`)).toBe(true);
    for (const s of ADMIN_SECTIONS) expect(ROUTES_FOR_TESTS.has(`/admin#${s.id}`)).toBe(true);
    expect(ROUTES_FOR_TESTS.has("/")).toBe(true);
  });
});
```
This requires `track.ts` to also export the set for tests. Add to `track.ts` (after the `ROUTES` definition):
```ts
/** Test-only view of the allowlist for the drift guard. */
export const ROUTES_FOR_TESTS: ReadonlySet<string> = ROUTES;
```

`ui/src/lib/analytics/track.singleInserter.test.ts`:
```ts
import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

// Walk ui/src and assert that an INSERT into analytics_events appears in exactly one
// non-test source file: the tracker. This is the privacy single-inserter invariant.
function sourceFiles(dir: string, acc: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const s = statSync(p);
    if (s.isDirectory()) {
      if (name !== "node_modules") sourceFiles(p, acc);
    } else if (/\.(ts|tsx)$/.test(name) && !/\.test\.(ts|tsx)$/.test(name)) {
      acc.push(p);
    }
  }
  return acc;
}

describe("analytics single-inserter invariant", () => {
  it("only track.ts inserts into analytics_events", () => {
    const root = join(process.cwd(), "src");
    const offenders = sourceFiles(root).filter((f) => {
      const normalized = readFileSync(f, "utf8").replace(/\s+/g, "");
      return /\.from\(["']analytics_events["']\)\.insert\(/.test(normalized);
    });
    expect(offenders.map((f) => f.replace(/\\/g, "/")).filter((f) => !f.endsWith("/lib/analytics/track.ts"))).toEqual([]);
  });
});
```

- [ ] **Step 7: Run the new tests + tsc** — `cd "D:/Project/PacketPilot/ui" && npx vitest run src/lib/analytics && npx tsc -b` → drift 1/1, single-inserter 1/1, tracker 5/5 PASS; tsc 0.

- [ ] **Step 8: Commit**
```bash
cd "D:/Project/PacketPilot" && git add ui/src/types.ts ui/src/lib/analytics/ && git commit -m "feat(analytics): allowlist-enforcing trackPageView + drift/single-inserter guards"
```

---

### Task 3: Wire the tracker into the three surfaces

**Files:**
- Modify: `ui/src/landing/Landing.tsx` (+ Test: `ui/src/landing/Landing.test.tsx`)
- Modify: `ui/src/App.tsx`
- Modify: `ui/src/admin/AdminShell.tsx`

**Interfaces:** Consumes `trackPageView` from `../lib/analytics/track` (Landing/App) and `../../lib/analytics/track` (AdminShell).

- [ ] **Step 1: Landing test (RED)**

`ui/src/landing/Landing.test.tsx`:
```tsx
import { describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";

const track = vi.fn();
vi.mock("../lib/analytics/track", () => ({ trackPageView: (p: string) => track(p) }));
vi.mock("./landing.html?raw", () => ({ default: "<div>landing</div>" }));

import { Landing } from "./Landing";

describe("Landing", () => {
  it("tracks the landing page view on mount", () => {
    render(<Landing />);
    expect(track).toHaveBeenCalledWith("/");
  });
});
```
Run → FAIL.

- [ ] **Step 2: Wire Landing** — `ui/src/landing/Landing.tsx`:
```tsx
import { useEffect } from "react";
import landingHtml from "./landing.html?raw";
import { trackPageView } from "../lib/analytics/track";

// ... keep the existing block comment ...
export function Landing() {
  useEffect(() => {
    trackPageView("/");
  }, []);
  return <div dangerouslySetInnerHTML={{ __html: landingHtml }} />;
}

export default Landing;
```
Run `cd "D:/Project/PacketPilot/ui" && npx vitest run src/landing/Landing.test.tsx` → PASS.

- [ ] **Step 3: Wire App tab tracking.** In `ui/src/App.tsx`, add the import `import { trackPageView } from "./lib/analytics/track";` and, near the other effects (after `const [tab, setTab] = useState<TabId>("dashboard");` and the existing effects), add:
```tsx
  useEffect(() => {
    trackPageView(`/app#${tab}`);
  }, [tab]);
```
(`useEffect` is already imported in App.tsx.) This fires on mount (`dashboard`) and every tab change.

- [ ] **Step 4: Wire AdminShell section tracking.** In `ui/src/admin/AdminShell.tsx`, add `import { trackPageView } from "../../lib/analytics/track";` and, after the existing `hashchange` effect, add:
```tsx
  useEffect(() => {
    trackPageView(`/admin#${active}`);
  }, [active]);
```

- [ ] **Step 5: Verify wiring + the App/AdminShell suites still pass + tsc.** Run:
`cd "D:/Project/PacketPilot/ui" && npx vitest run src/landing/Landing.test.tsx src/App.test.tsx src/admin/AdminShell.test.tsx && npx tsc -b`
Expected: all PASS; tsc 0. (App.test/AdminShell.test don't assert tracking; they must still pass with the new effect — the real `track.ts` no-ops under the test's unconfigured/mocked supabase, and AdminShell.test already mocks nothing for track — if either suite errors because the real tracker runs, add `vi.mock("../lib/analytics/track", () => ({ trackPageView: () => {} }))` to that test file's top, matching its relative path.)

- [ ] **Step 6: Commit**
```bash
cd "D:/Project/PacketPilot" && git add ui/src/landing/ ui/src/App.tsx ui/src/admin/AdminShell.tsx && git commit -m "feat(analytics): track page views on landing, app tabs, and admin sections"
```

---

### Task 4: Migration `0011` — traffic read RPCs + view (controller-run via MCP)

Controller-run: write the file, apply, verify the view/RPCs return, regenerate types, advisors, commit.

**Files:** Create `supabase/migrations/0011_traffic_read.sql`; Modify `ui/src/lib/supabase/types.ts` (regenerated)

- [ ] **Step 1: Write `supabase/migrations/0011_traffic_read.sql`**
```sql
-- Admin Live Traffic reads. SECURITY INVOKER so the caller's analytics_select_admin RLS
-- applies (admins only); search_path pinned.
create or replace view public.admin_traffic_stats
with (security_invoker = true) as
select
  count(distinct session_id) filter (where created_at > now() - interval '24 hours') as active_today,
  count(*) filter (where created_at > now() - interval '24 hours') as pageviews_today,
  count(distinct session_id) filter (where created_at > now() - interval '24 hours' and user_id is not null) as authed_today,
  count(distinct session_id) filter (where created_at > now() - interval '24 hours' and user_id is null) as anon_today
from public.analytics_events;

create or replace function public.admin_pageviews_by_day(days integer)
returns table(day date, count bigint)
language sql stable security invoker set search_path = '' as $$
  select d::date as day, count(e.id) as count
  from generate_series((current_date - (greatest(days, 1) - 1)), current_date, interval '1 day') as d
  left join public.analytics_events e
    on e.created_at >= d and e.created_at < d + interval '1 day'
  group by d order by d
$$;

create or replace function public.admin_top_paths(days integer, lim integer)
returns table(path text, count bigint)
language sql stable security invoker set search_path = '' as $$
  select e.path, count(*) as count
  from public.analytics_events e
  where e.created_at > now() - make_interval(days => greatest(days, 1))
  group by e.path order by count(*) desc, e.path
  limit greatest(lim, 1)
$$;
```

- [ ] **Step 2: Apply (MCP `apply_migration`, name `traffic_read`).** Expected: success.

- [ ] **Step 3: Verify (MCP `execute_sql`):**
  - `select * from public.admin_traffic_stats;` → one row (counts; ≥0, reflecting seed rows).
  - `select * from public.admin_pageviews_by_day(14);` → 14 zero-filled rows.
  - `select * from public.admin_top_paths(7, 10);` → up to 10 rows (path, count).

- [ ] **Step 4: Regenerate types (MCP `generate_typescript_types`)** and overwrite `ui/src/lib/supabase/types.ts` with the result. Run `cd "D:/Project/PacketPilot/ui" && npx tsc -b` → exit 0.

- [ ] **Step 5: Advisors (MCP `get_advisors` type=security).** Expected: no new ERROR. (SECURITY INVOKER views/functions are not flagged like DEFINER ones.)

- [ ] **Step 6: Commit**
```bash
cd "D:/Project/PacketPilot" && git add supabase/migrations/0011_traffic_read.sql ui/src/lib/supabase/types.ts && git commit -m "feat(db): admin Live Traffic read RPCs + admin_traffic_stats view (0011)"
```

---

### Task 5: `useAdminTraffic` hook

**Files:** Create `ui/src/admin/traffic/useAdminTraffic.ts`; Test `ui/src/admin/traffic/useAdminTraffic.test.ts`

**Interfaces:**
- Consumes: `supabase`, `supabaseConfigured` from `../../lib/supabase`; `type DayPoint` from `../useAdminDashboard`.
- Produces:
  - `interface TrafficStats { active_today: number; pageviews_today: number; authed_today: number; anon_today: number }`
  - `interface TopPath { path: string; count: number }`
  - `interface RecentEvent { path: string; signedIn: boolean; created_at: string }`
  - `interface TrafficData { stats: TrafficStats; byDay: DayPoint[]; topPaths: TopPath[]; recent: RecentEvent[] }`
  - `type AdminTrafficState = {status:"loading"} | {status:"error";error:string} | {status:"ready";data:TrafficData}`
  - `useAdminTraffic(): { state: AdminTrafficState; reload: () => void }`

- [ ] **Step 1: Write the failing test**

`ui/src/admin/traffic/useAdminTraffic.test.ts`:
```ts
import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

let statsRes: { data: unknown; error: unknown } = { data: { active_today: 3, pageviews_today: 9, authed_today: 1, anon_today: 2 }, error: null };
let byDayRes: { data: unknown; error: unknown } = { data: [{ day: "2026-06-27", count: 5 }], error: null };
let topRes: { data: unknown; error: unknown } = { data: [{ path: "/app#flows", count: 7 }], error: null };
let recentRes: { data: unknown; error: unknown } = { data: [{ path: "/", user_id: null, created_at: "2026-06-28T00:00:00Z" }, { path: "/admin#users", user_id: "u1", created_at: "2026-06-28T00:01:00Z" }], error: null };

vi.mock("../../lib/supabase", () => {
  const recentQuery = () => {
    const q: Record<string, unknown> = {};
    q.select = () => q;
    q.order = () => q;
    q.limit = () => Promise.resolve(recentRes);
    return q;
  };
  return {
    supabase: {
      from: (t: string) =>
        t === "admin_traffic_stats"
          ? { select: () => ({ single: () => Promise.resolve(statsRes) }) }
          : recentQuery(),
      rpc: (name: string) => Promise.resolve(name === "admin_top_paths" ? topRes : byDayRes),
    },
    supabaseConfigured: true,
  };
});

import { useAdminTraffic } from "./useAdminTraffic";

beforeEach(() => {
  statsRes = { data: { active_today: 3, pageviews_today: 9, authed_today: 1, anon_today: 2 }, error: null };
  byDayRes = { data: [{ day: "2026-06-27", count: 5 }], error: null };
  topRes = { data: [{ path: "/app#flows", count: 7 }], error: null };
  recentRes = { data: [{ path: "/", user_id: null, created_at: "2026-06-28T00:00:00Z" }, { path: "/admin#users", user_id: "u1", created_at: "2026-06-28T00:01:00Z" }], error: null };
});

describe("useAdminTraffic", () => {
  it("maps stats, by-day, top paths, and recent (with derived signedIn)", async () => {
    const { result } = renderHook(() => useAdminTraffic());
    await waitFor(() => expect(result.current.state.status).toBe("ready"));
    if (result.current.state.status === "ready") {
      const d = result.current.state.data;
      expect(d.stats.active_today).toBe(3);
      expect(d.byDay).toHaveLength(1);
      expect(d.topPaths[0]).toEqual({ path: "/app#flows", count: 7 });
      expect(d.recent[0].signedIn).toBe(false);
      expect(d.recent[1].signedIn).toBe(true);
      expect(d.recent[1]).not.toHaveProperty("user_id");
    }
  });

  it("errors when a query fails", async () => {
    statsRes = { data: null, error: { message: "denied" } };
    const { result } = renderHook(() => useAdminTraffic());
    await waitFor(() => expect(result.current.state.status).toBe("error"));
    if (result.current.state.status === "error") expect(result.current.state.error).toBe("denied");
  });
});
```

- [ ] **Step 2: Run it → FAIL** (`cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/traffic/useAdminTraffic.test.ts`).

- [ ] **Step 3: Write `ui/src/admin/traffic/useAdminTraffic.ts`**
```ts
import { useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../../lib/supabase";
import type { DayPoint } from "../useAdminDashboard";

export interface TrafficStats {
  active_today: number;
  pageviews_today: number;
  authed_today: number;
  anon_today: number;
}
export interface TopPath {
  path: string;
  count: number;
}
export interface RecentEvent {
  path: string;
  signedIn: boolean;
  created_at: string;
}
export interface TrafficData {
  stats: TrafficStats;
  byDay: DayPoint[];
  topPaths: TopPath[];
  recent: RecentEvent[];
}
export type AdminTrafficState =
  | { status: "loading" }
  | { status: "error"; error: string }
  | { status: "ready"; data: TrafficData };

const num = (v: unknown): number => {
  const n = Number(v ?? 0);
  return Number.isFinite(n) ? n : 0;
};
const toStats = (r: Record<string, unknown> | null): TrafficStats => ({
  active_today: num(r?.active_today),
  pageviews_today: num(r?.pageviews_today),
  authed_today: num(r?.authed_today),
  anon_today: num(r?.anon_today),
});
const toDays = (rows: unknown): DayPoint[] =>
  Array.isArray(rows) ? rows.map((r) => ({ day: String((r as { day: unknown }).day), count: num((r as { count: unknown }).count) })) : [];
const toTop = (rows: unknown): TopPath[] =>
  Array.isArray(rows) ? rows.map((r) => ({ path: String((r as { path: unknown }).path), count: num((r as { count: unknown }).count) })) : [];
const toRecent = (rows: unknown): RecentEvent[] =>
  Array.isArray(rows)
    ? rows.map((r) => {
        const e = r as { path: unknown; user_id: unknown; created_at: unknown };
        return { path: String(e.path), signedIn: e.user_id != null, created_at: String(e.created_at) };
      })
    : [];

export function useAdminTraffic(): { state: AdminTrafficState; reload: () => void } {
  const [state, setState] = useState<AdminTrafficState>({ status: "loading" });
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
        const [stats, byDay, top, recent] = await Promise.all([
          client.from("admin_traffic_stats").select("*").single(),
          client.rpc("admin_pageviews_by_day", { days: 14 }),
          client.rpc("admin_top_paths", { days: 7, lim: 10 }),
          client.from("analytics_events").select("path,user_id,created_at").order("created_at", { ascending: false }).limit(25),
        ]);
        const firstErr = stats.error || byDay.error || top.error || recent.error;
        if (firstErr) throw new Error((firstErr as { message?: string }).message ?? "Query failed");
        if (cancelled) return;
        setState({
          status: "ready",
          data: {
            stats: toStats(stats.data as Record<string, unknown> | null),
            byDay: toDays(byDay.data),
            topPaths: toTop(top.data),
            recent: toRecent(recent.data),
          },
        });
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

- [ ] **Step 4: Run test + tsc** — `cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/traffic/useAdminTraffic.test.ts && npx tsc -b` → 2/2 PASS; tsc 0.

- [ ] **Step 5: Commit**
```bash
cd "D:/Project/PacketPilot" && git add ui/src/admin/traffic/useAdminTraffic.ts ui/src/admin/traffic/useAdminTraffic.test.ts && git commit -m "feat(admin): useAdminTraffic hook (stats + by-day + top paths + recent)"
```

---

### Task 6: `TrafficView` + wire `AdminShell` + full gate

**Files:**
- Create: `ui/src/admin/traffic/TrafficView.tsx`; Test `ui/src/admin/traffic/TrafficView.test.tsx`
- Modify: `ui/src/admin/AdminShell.tsx` (route `traffic` → `TrafficView`), `ui/src/admin/AdminShell.test.tsx`

**Interfaces:** Consumes `useAdminTraffic` + types from `./useAdminTraffic`; `Card` from `../../cockpit/primitives`; `SignupsAreaChart` from `../dashboard/SignupsAreaChart`; `LoadingState`/`ErrorState`; `joinedDate` from `../dashboard/format`. Produces `export function TrafficView()`.

- [ ] **Step 1: Write the failing view test**

`ui/src/admin/traffic/TrafficView.test.tsx`:
```tsx
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { render, screen, within } from "@testing-library/react";

const hookState = vi.fn();
vi.mock("./useAdminTraffic", () => ({ useAdminTraffic: () => ({ state: hookState(), reload: vi.fn() }) }));
vi.mock("recharts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("recharts")>();
  return { ...actual, ResponsiveContainer: ({ children }: { children: ReactNode }) => <div>{children}</div> };
});

import { TrafficView } from "./TrafficView";

const ready = {
  status: "ready",
  data: {
    stats: { active_today: 3, pageviews_today: 9, authed_today: 1, anon_today: 2 },
    byDay: [{ day: "2026-06-27", count: 5 }],
    topPaths: [{ path: "/app#flows", count: 7 }],
    recent: [{ path: "/admin#users", signedIn: true, created_at: "2026-06-28T00:01:00Z" }],
  },
};

beforeEach(() => hookState.mockReturnValue(ready));

describe("TrafficView", () => {
  it("renders the KPI strip, top paths, and recent activity", () => {
    render(<TrafficView />);
    expect(screen.getByText("Active users today").parentElement).toHaveTextContent("3");
    const tables = screen.getAllByRole("table");
    expect(within(tables[0]).getByText("/app#flows")).toBeInTheDocument();
    expect(within(tables[1]).getByText("/admin#users")).toBeInTheDocument();
    expect(within(tables[1]).getByText(/yes/i)).toBeInTheDocument();
  });

  it("shows the loading and error states", () => {
    hookState.mockReturnValue({ status: "loading" });
    const { rerender } = render(<TrafficView />);
    expect(screen.getByRole("status")).toBeInTheDocument();
    hookState.mockReturnValue({ status: "error", error: "denied" });
    rerender(<TrafficView />);
    expect(screen.getByText(/denied/i)).toBeInTheDocument();
  });

  it("renders empty states when there is no traffic", () => {
    hookState.mockReturnValue({ status: "ready", data: { stats: { active_today: 0, pageviews_today: 0, authed_today: 0, anon_today: 0 }, byDay: [], topPaths: [], recent: [] } });
    render(<TrafficView />);
    expect(screen.getByText(/no traffic yet/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run it → FAIL.**

- [ ] **Step 3: Write `ui/src/admin/traffic/TrafficView.tsx`**
```tsx
import { Card } from "../../cockpit/primitives";
import { LoadingState } from "../../components/state/LoadingState";
import { ErrorState } from "../../components/state/ErrorState";
import { SignupsAreaChart } from "../dashboard/SignupsAreaChart";
import { joinedDate } from "../dashboard/format";
import { useAdminTraffic, type RecentEvent, type TopPath } from "./useAdminTraffic";

function Kpi({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2">
      <div className="t-tag uppercase text-[var(--color-text-dim)]">{label}</div>
      <div className="font-mono-num text-lg text-[var(--color-text)]">{value}</div>
    </div>
  );
}

export function TrafficView() {
  const { state } = useAdminTraffic();
  if (state.status === "loading") return <LoadingState label="Loading traffic…" />;
  if (state.status === "error") return <ErrorState title="Couldn't load traffic" message={state.error} />;
  const { stats, byDay, topPaths, recent } = state.data;
  const empty = stats.pageviews_today === 0 && byDay.every((d) => d.count === 0) && topPaths.length === 0 && recent.length === 0;

  return (
    <div className="flex flex-col gap-[var(--density-gap)]">
      <div className="flex flex-wrap items-end gap-3">
        <Kpi label="Active users today" value={String(stats.active_today)} />
        <Kpi label="Page views today" value={String(stats.pageviews_today)} />
        <Kpi label="Signed-in" value={String(stats.authed_today)} />
        <Kpi label="Anonymous" value={String(stats.anon_today)} />
      </div>
      {empty ? (
        <p className="text-sm text-[var(--color-text-dim)]">No traffic yet.</p>
      ) : (
        <>
          <Card title="Page views (14d)">
            <SignupsAreaChart data={byDay} />
          </Card>
          <div className="grid gap-[var(--density-gap)] lg:grid-cols-2">
            <Card title="Top paths (7d)">
              <TopPathsTable rows={topPaths} />
            </Card>
            <Card title="Recent activity">
              <RecentTable rows={recent} />
            </Card>
          </div>
        </>
      )}
    </div>
  );
}

function TopPathsTable({ rows }: { rows: TopPath[] }) {
  if (rows.length === 0) return <p className="text-sm text-[var(--color-text-dim)]">No paths yet.</p>;
  return (
    <table className="pp-table">
      <thead>
        <tr>
          <th>Path</th>
          <th>Views</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.path}>
            <td className="font-mono-num">{r.path}</td>
            <td className="font-mono-num">{r.count}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RecentTable({ rows }: { rows: RecentEvent[] }) {
  if (rows.length === 0) return <p className="text-sm text-[var(--color-text-dim)]">No recent activity.</p>;
  return (
    <table className="pp-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Path</th>
          <th>Signed in?</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={`${r.created_at}-${i}`}>
            <td className="font-mono-num text-[var(--color-text-dim)]">{joinedDate(r.created_at)}</td>
            <td className="font-mono-num">{r.path}</td>
            <td className="t-tag uppercase text-[var(--color-text-dim)]">{r.signedIn ? "Yes" : "No"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default TrafficView;
```

- [ ] **Step 4: Run the view test → PASS** (`cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/traffic/TrafficView.test.tsx`). Then tsc.

- [ ] **Step 5: Wire AdminShell + its test.** In `ui/src/admin/AdminShell.test.tsx`, add after the payments mock: `vi.mock("./traffic/TrafficView", () => ({ TrafficView: () => <div>TRAFFIC_STUB</div> }));` and add a test:
```tsx
  it("routes the Live Traffic section to the traffic view", async () => {
    render(<AdminShell email="a@b.com" onSignOut={vi.fn()} />);
    await userEvent.click(within(screen.getByRole("navigation")).getByRole("button", { name: "Live Traffic" }));
    expect(screen.getByText("TRAFFIC_STUB")).toBeInTheDocument();
    expect(window.location.hash).toBe("#traffic");
  });
```
In `ui/src/admin/AdminShell.tsx`, add `import { TrafficView } from "./traffic/TrafficView";` and a branch:
```tsx
          ) : active === "payments" ? (
            <PaymentsView />
          ) : active === "traffic" ? (
            <TrafficView />
          ) : (
```

- [ ] **Step 6: Full gate.** Run, in order:
1. `cd "D:/Project/PacketPilot/ui" && npx tsc -b` → exit 0.
2. `cd "D:/Project/PacketPilot/ui" && npm run test:coverage` → all pass, EXIT 0 (no unhandled errors), coverage ≥ 80/70. Report Test Files/Tests totals + "All files" line + exit code.
3. `cd "D:/Project/PacketPilot/ui" && npm run build` → "✓ built".

- [ ] **Step 7: Commit**
```bash
cd "D:/Project/PacketPilot" && git add ui/src/admin/traffic/TrafficView.tsx ui/src/admin/traffic/TrafficView.test.tsx ui/src/admin/AdminShell.tsx ui/src/admin/AdminShell.test.tsx && git commit -m "feat(admin): Live Traffic view (KPIs + page-views chart + top paths + recent)"
```

---

## After all tasks

- **Final whole-branch review** (most capable model): diff from `git merge-base main HEAD` to `HEAD`. Focus: the privacy single-inserter + allowlist (can any capture data reach an event?); the RLS WITH CHECK correctness (anon→uid null, path shape, forbid referrer/UA/country) + the rate trigger (SECURITY DEFINER, revoked); `active_today` identical to the dashboard; the SECURITY INVOKER read RPCs; recent-events exposes only a signedIn boolean; test hygiene (incl. the drift + single-inserter guards); consistency with the Phase-4/5/6 patterns.
- **Browser smoke** (controller, best-effort): navigate `/` → `/app` tabs → `/admin` sections; `execute_sql` to confirm rows landed in `analytics_events` with canonical tokens; open Live Traffic and confirm KPIs/chart/tables populate (seed rows already give it data).
- **finishing-a-development-branch**: verify the suite, then present merge options.

## Self-review notes

- **Spec coverage:** RLS hardening + rate trigger (Task 1); tracker + allowlist + drift + single-inserter (Task 2); wiring all three surfaces (Task 3); read RPCs/view + types (Task 4); hook (Task 5); view + AdminShell wiring + gate (Task 6). Every spec section maps to a task.
- **Type consistency:** `TAB_IDS`/`TabId` (Task 2) feed the drift test; `trackPageView` (Task 2) consumed in Task 3; `TrafficStats`/`TopPath`/`RecentEvent`/`TrafficData`/`useAdminTraffic` (Task 5) consumed by `TrafficView` (Task 6); `DayPoint` reused from `useAdminDashboard`; `SignupsAreaChart` prop is `DayPoint[]` (matches `byDay`).
- **No placeholders:** every code/test step is complete; migration SQL is given in full (Task 1 references the spec's identical block, Task 4 inline).
- **Privacy invariant is testable:** the single-inserter test (filesystem scan) + the allowlist-drop test + the no-extra-fields assertions concretely enforce "no capture data in events."
