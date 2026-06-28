# Admin Users Management (Phase 5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the `/admin` Users placeholder into a real management table — search users and change their plan/role/status, with self-demotion protection, every change audited server-side.

**Architecture:** One `SECURITY DEFINER` Postgres trigger logs role/plan/status changes to `audit_log`. A `useAdminUsers` hook lists profiles (email search) and exposes `setPlan`/`setRole`/`setStatus` mutators that are plain RLS-gated client writes (the Phase-0 guard already restricts those columns to admins). A `UsersView` component renders the table with per-row `<select>`s; `AdminShell` routes the Users section to it.

**Tech Stack:** React 18 + TS, the Phase-0 Supabase typed client, Tailwind + `index.css` tokens (`.pp-table`, severity colors), Vitest + RTL. Supabase MCP for the migration.

## Global Constraints

- **No new write path / no Edge Function.** Mutations are `supabase.from("profiles").update(...).eq("id", id)`; the Phase-0 RLS update policy (`self-or-admin`) + the `guard_profile_privileged_columns` trigger already permit admins and block non-admins. Copy verbatim: the guard blocks role/plan/status changes only when `auth.uid() is not null AND not is_admin()`.
- **Privacy / engine untouched.** No change to `/app`, the WASM path, or capture handling.
- **No new SPA dependencies.** Reuse `../../lib/supabase`, `../../components/state/*`, `../dashboard/format`, `.pp-table`, severity tokens.
- **Migration numbering:** next file is `0009_…` (`0008_dashboard_rpcs` is the latest applied).
- **SQL functions:** `SECURITY DEFINER` + `set search_path = ''` (the repo convention; advisors gate on it).
- **Self-protection:** an admin's own row (`row.email === adminEmail`) has its **Role** select disabled.
- **Per-task gate:** run `npx tsc -b` (Vitest does not typecheck). Final task also runs `npm run test:coverage` (≥ 80 statements / 70 branches) and `npm run build`. All UI commands run from `D:\Project\PacketPilot\ui`.

---

### Task 1: Audit-trigger migration (`0009`) — controller-run via Supabase MCP

This task is executed by the controller (live DB + MCP), not a code subagent: write the migration file, apply it, verify the trigger fires, check advisors, commit.

**Files:**
- Create: `supabase/migrations/0009_audit_profile_changes.sql`

**Interfaces:**
- Produces: a trigger `audit_profile_change` on `public.profiles` that inserts into `public.audit_log(actor_id, action, target, meta)` on role/plan/status change. No TS-visible schema change (no `types.ts` regen needed — `audit_log` already exists in the Phase-0 types).

- [ ] **Step 1: Write the migration file**

`supabase/migrations/0009_audit_profile_changes.sql`:
```sql
-- Record admin edits to a user's privileged columns. SECURITY DEFINER so it always
-- writes regardless of the actor's RLS; search_path pinned. actor_id is auth.uid()
-- (the admin), or null for service-role/migration changes.
create or replace function public.audit_profile_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  changes jsonb := '{}'::jsonb;
begin
  if new.role is distinct from old.role then
    changes := changes || jsonb_build_object('role', jsonb_build_object('old', old.role::text, 'new', new.role::text));
  end if;
  if new.plan is distinct from old.plan then
    changes := changes || jsonb_build_object('plan', jsonb_build_object('old', old.plan::text, 'new', new.plan::text));
  end if;
  if new.status is distinct from old.status then
    changes := changes || jsonb_build_object('status', jsonb_build_object('old', old.status::text, 'new', new.status::text));
  end if;
  if changes <> '{}'::jsonb then
    insert into public.audit_log (actor_id, action, target, meta)
    values (auth.uid(), 'profile.update', new.id::text, changes);
  end if;
  return new;
end;
$$;

drop trigger if exists audit_profile_change on public.profiles;
create trigger audit_profile_change
after update on public.profiles
for each row execute function public.audit_profile_change();
```

- [ ] **Step 2: Apply the migration (MCP)**

Use `apply_migration` (project `brkztcfhmrjjnbjzycie`, name `audit_profile_changes`) with the file body. Expected: success, no error.

- [ ] **Step 3: Verify the trigger fires (MCP `execute_sql`)**

Run (one statement at a time):
```sql
update public.profiles set status = 'suspended' where email = 'demo+alice@example.com';
select action, target, meta from public.audit_log order by created_at desc limit 1;
```
Expected: one row, `action='profile.update'`, `meta = {"status": {"old": "active", "new": "suspended"}}`.
Then revert and confirm a second audit row:
```sql
update public.profiles set status = 'active' where email = 'demo+alice@example.com';
select count(*) from public.audit_log where action = 'profile.update';
```
Expected: count ≥ 2; alice's status back to `active`.

- [ ] **Step 4: Security advisors (MCP `get_advisors` type=security)**

Expected: no new ERROR-level advisory attributable to `audit_profile_change` (the `SECURITY DEFINER` + `search_path=''` pattern is clean).

- [ ] **Step 5: Commit**

```bash
cd "D:/Project/PacketPilot"
git add supabase/migrations/0009_audit_profile_changes.sql
git commit -m "feat(db): audit trigger logging profile role/plan/status changes (0009)"
```

---

### Task 2: `useAdminUsers` hook + mutators

**Files:**
- Create: `ui/src/admin/users/useAdminUsers.ts`
- Test: `ui/src/admin/users/useAdminUsers.test.ts`

**Interfaces:**
- Consumes: `supabase`, `supabaseConfigured` from `../../lib/supabase` (the Phase-0 client; `supabase` is `null` until env is set).
- Produces:
  - `interface AdminUser { id: string; email: string; full_name: string | null; plan: string; role: string; status: string; created_at: string }`
  - `type AdminUsersState = { status: "loading" } | { status: "error"; error: string } | { status: "ready"; users: AdminUser[] }`
  - `useAdminUsers(search: string): { state: AdminUsersState; reload: () => void }`
  - `setPlan(id, plan)`, `setRole(id, role)`, `setStatus(id, status)` → `Promise<{ ok: boolean; error?: string }>`

- [ ] **Step 1: Write the failing test**

`ui/src/admin/users/useAdminUsers.test.ts`:
```ts
import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

let usersResult: { data: unknown; error: unknown } = { data: [], error: null };
let eqResult: { error: unknown } = { error: null };
const ilikeSpy = vi.fn();
const orderSpy = vi.fn();
const updateSpy = vi.fn();
const eqSpy = vi.fn();

vi.mock("../../lib/supabase", () => {
  const makeQuery = () => {
    const q: Record<string, unknown> = {};
    q.select = () => q;
    q.ilike = (...a: unknown[]) => { ilikeSpy(...a); return q; };
    q.order = (...a: unknown[]) => { orderSpy(...a); return q; };
    q.limit = () => Promise.resolve(usersResult);
    q.update = (...a: unknown[]) => {
      updateSpy(...a);
      return { eq: (...b: unknown[]) => { eqSpy(...b); return Promise.resolve(eqResult); } };
    };
    return q;
  };
  return { supabase: { from: () => makeQuery() }, supabaseConfigured: true };
});

import { useAdminUsers, setPlan, setRole, setStatus } from "./useAdminUsers";

const SAMPLE = [
  { id: "u1", email: "alice@x.com", full_name: "Alice", plan: "free", role: "user", status: "active", created_at: "2026-06-20T00:00:00Z" },
  { id: "u2", email: "bob@x.com", full_name: "Bob", plan: "pro", role: "user", status: "active", created_at: "2026-06-21T00:00:00Z" },
];

beforeEach(() => {
  usersResult = { data: SAMPLE, error: null };
  eqResult = { error: null };
  ilikeSpy.mockClear(); orderSpy.mockClear(); updateSpy.mockClear(); eqSpy.mockClear();
});

describe("useAdminUsers", () => {
  it("loads users into the ready state, no filter when search is empty", async () => {
    const { result } = renderHook(() => useAdminUsers(""));
    await waitFor(() => expect(result.current.state.status).toBe("ready"));
    if (result.current.state.status === "ready") expect(result.current.state.users).toHaveLength(2);
    expect(ilikeSpy).not.toHaveBeenCalled();
  });

  it("applies an email ILIKE filter when search is non-empty", async () => {
    const { result } = renderHook(() => useAdminUsers("alice"));
    await waitFor(() => expect(result.current.state.status).toBe("ready"));
    expect(ilikeSpy).toHaveBeenCalledWith("email", "%alice%");
  });

  it("surfaces a query error", async () => {
    usersResult = { data: null, error: { message: "boom" } };
    const { result } = renderHook(() => useAdminUsers(""));
    await waitFor(() => expect(result.current.state.status).toBe("error"));
    if (result.current.state.status === "error") expect(result.current.state.error).toBe("boom");
  });

  it("setPlan issues update({plan}) + eq('id', id) and returns ok", async () => {
    const r = await setPlan("u1", "pro");
    expect(updateSpy).toHaveBeenCalledWith({ plan: "pro" });
    expect(eqSpy).toHaveBeenCalledWith("id", "u1");
    expect(r).toEqual({ ok: true });
  });

  it("setStatus/setRole return the error message on failure", async () => {
    eqResult = { error: { message: "denied" } };
    expect(await setStatus("u1", "blocked")).toEqual({ ok: false, error: "denied" });
    expect(await setRole("u2", "admin")).toEqual({ ok: false, error: "denied" });
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/users/useAdminUsers.test.ts`
Expected: FAIL — cannot resolve `./useAdminUsers`.

- [ ] **Step 3: Write the implementation**

`ui/src/admin/users/useAdminUsers.ts`:
```ts
import { useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../../lib/supabase";

export interface AdminUser {
  id: string;
  email: string;
  full_name: string | null;
  plan: string;
  role: string;
  status: string;
  created_at: string;
}

export type AdminUsersState =
  | { status: "loading" }
  | { status: "error"; error: string }
  | { status: "ready"; users: AdminUser[] };

const COLS = "id,email,full_name,plan,role,status,created_at";

export function useAdminUsers(search: string): { state: AdminUsersState; reload: () => void } {
  const [state, setState] = useState<AdminUsersState>({ status: "loading" });
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
        let query = client.from("profiles").select(COLS);
        const term = search.trim();
        if (term) query = query.ilike("email", `%${term}%`);
        const { data, error } = await query.order("created_at", { ascending: false }).limit(100);
        if (error) throw new Error((error as { message?: string }).message ?? "Query failed");
        if (cancelled) return;
        setState({ status: "ready", users: (data ?? []) as AdminUser[] });
      } catch (e) {
        if (!cancelled) setState({ status: "error", error: e instanceof Error ? e.message : String(e) });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [search, nonce]);

  return { state, reload: () => setNonce((n) => n + 1) };
}

async function patch(id: string, fields: Record<string, string>): Promise<{ ok: boolean; error?: string }> {
  if (!supabase) return { ok: false, error: "Backend not configured" };
  const { error } = await supabase.from("profiles").update(fields).eq("id", id);
  return error ? { ok: false, error: (error as { message?: string }).message ?? "Update failed" } : { ok: true };
}

export const setPlan = (id: string, plan: string) => patch(id, { plan });
export const setRole = (id: string, role: string) => patch(id, { role });
export const setStatus = (id: string, status: string) => patch(id, { status });
```

If `tsc` complains that the subset-`select` row type is not assignable to `AdminUser[]`, change the cast to `as unknown as AdminUser[]` (the dashboard hook casts directly; match whichever compiles).

- [ ] **Step 4: Run the test + typecheck**

Run: `cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/users/useAdminUsers.test.ts && npx tsc -b`
Expected: 5/5 PASS; tsc exit 0.

- [ ] **Step 5: Commit**

```bash
cd "D:/Project/PacketPilot"
git add ui/src/admin/users/useAdminUsers.ts ui/src/admin/users/useAdminUsers.test.ts
git commit -m "feat(admin): useAdminUsers hook + plan/role/status mutators"
```

---

### Task 3: `UsersView` component

**Files:**
- Create: `ui/src/admin/users/UsersView.tsx`
- Test: `ui/src/admin/users/UsersView.test.tsx`

**Interfaces:**
- Consumes: `useAdminUsers`, `setPlan`, `setRole`, `setStatus`, `type AdminUser` from `./useAdminUsers`; `LoadingState` from `../../components/state/LoadingState`; `ErrorState` from `../../components/state/ErrorState`; `joinedDate` from `../dashboard/format`.
- Produces: `export function UsersView({ adminEmail }: { adminEmail: string })` (also `export default`).

- [ ] **Step 1: Write the failing test**

`ui/src/admin/users/UsersView.test.tsx`:
```tsx
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const hookState = vi.fn();
const reload = vi.fn();
const setPlan = vi.fn();
const setRole = vi.fn();
const setStatus = vi.fn();
vi.mock("./useAdminUsers", () => ({
  useAdminUsers: () => ({ state: hookState(), reload }),
  setPlan: (...a: unknown[]) => setPlan(...a),
  setRole: (...a: unknown[]) => setRole(...a),
  setStatus: (...a: unknown[]) => setStatus(...a),
}));

import { UsersView } from "./UsersView";

const USERS = [
  { id: "u1", email: "alice@x.com", full_name: "Alice", plan: "free", role: "user", status: "active", created_at: "2026-06-20T00:00:00Z" },
  { id: "me", email: "admin@x.com", full_name: "Admin", plan: "pro", role: "admin", status: "active", created_at: "2026-06-21T00:00:00Z" },
];

beforeEach(() => {
  hookState.mockReturnValue({ status: "ready", users: USERS });
  reload.mockClear(); setPlan.mockReset(); setRole.mockReset(); setStatus.mockReset();
  setPlan.mockResolvedValue({ ok: true });
  setRole.mockResolvedValue({ ok: true });
  setStatus.mockResolvedValue({ ok: true });
});

describe("UsersView", () => {
  it("renders a row per user", () => {
    render(<UsersView adminEmail="admin@x.com" />);
    const table = screen.getByRole("table");
    expect(within(table).getByText("alice@x.com")).toBeInTheDocument();
    expect(within(table).getByText("admin@x.com")).toBeInTheDocument();
  });

  it("changing a user's plan calls setPlan then reloads", async () => {
    render(<UsersView adminEmail="admin@x.com" />);
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Plan for alice@x.com" }), "pro");
    expect(setPlan).toHaveBeenCalledWith("u1", "pro");
    await waitFor(() => expect(reload).toHaveBeenCalled());
  });

  it("disables the Role select on the admin's own row", () => {
    render(<UsersView adminEmail="admin@x.com" />);
    expect(screen.getByRole("combobox", { name: "Role for admin@x.com" })).toBeDisabled();
    expect(screen.getByRole("combobox", { name: "Role for alice@x.com" })).toBeEnabled();
  });

  it("shows an alert when a mutation fails", async () => {
    setPlan.mockResolvedValue({ ok: false, error: "denied" });
    render(<UsersView adminEmail="admin@x.com" />);
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Plan for alice@x.com" }), "pro");
    expect(await screen.findByRole("alert")).toHaveTextContent("denied");
  });

  it("renders the empty state when no users match", () => {
    hookState.mockReturnValue({ status: "ready", users: [] });
    render(<UsersView adminEmail="admin@x.com" />);
    expect(screen.getByText(/no users match/i)).toBeInTheDocument();
  });

  it("renders the error state", () => {
    hookState.mockReturnValue({ status: "error", error: "backend down" });
    render(<UsersView adminEmail="admin@x.com" />);
    expect(screen.getByText(/backend down/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/users/UsersView.test.tsx`
Expected: FAIL — cannot resolve `./UsersView`.

- [ ] **Step 3: Write the implementation**

`ui/src/admin/users/UsersView.tsx`:
```tsx
import { useState } from "react";
import { LoadingState } from "../../components/state/LoadingState";
import { ErrorState } from "../../components/state/ErrorState";
import { joinedDate } from "../dashboard/format";
import { useAdminUsers, setPlan, setRole, setStatus, type AdminUser } from "./useAdminUsers";

const STATUS_COLOR: Record<string, string> = {
  active: "var(--color-sev-low)",
  suspended: "var(--color-sev-medium)",
  blocked: "var(--color-sev-critical)",
};

const PLANS = ["free", "pro"];
const ROLES = ["user", "admin"];
const STATUSES = ["active", "suspended", "blocked"];

type Mutator = () => Promise<{ ok: boolean; error?: string }>;

export function UsersView({ adminEmail }: { adminEmail: string }) {
  const [search, setSearch] = useState("");
  const [error, setError] = useState<string | null>(null);
  const { state, reload } = useAdminUsers(search);

  const run = async (fn: Mutator) => {
    setError(null);
    const r = await fn();
    if (r.ok) reload();
    else setError(r.error ?? "Update failed");
  };

  return (
    <div className="flex flex-col gap-[var(--density-gap)]">
      <input
        type="search"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Search by email…"
        aria-label="Search users by email"
        className="w-full max-w-sm rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-sm text-[var(--color-text)] placeholder:text-[var(--color-text-dim)]"
      />
      {error && (
        <p role="alert" className="t-tag text-[var(--color-sev-critical)]">
          {error}
        </p>
      )}
      {state.status === "loading" ? (
        <LoadingState label="Loading users…" />
      ) : state.status === "error" ? (
        <ErrorState title="Couldn't load users" message={state.error} />
      ) : state.users.length === 0 ? (
        <p className="text-sm text-[var(--color-text-dim)]">No users match.</p>
      ) : (
        <table className="pp-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Plan</th>
              <th>Role</th>
              <th>Status</th>
              <th>Joined</th>
            </tr>
          </thead>
          <tbody>
            {state.users.map((u) => (
              <UserRow key={u.id} u={u} isSelf={u.email === adminEmail} run={run} />
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function UserRow({ u, isSelf, run }: { u: AdminUser; isSelf: boolean; run: (fn: Mutator) => void }) {
  const color = STATUS_COLOR[u.status] ?? "var(--color-text-dim)";
  return (
    <tr>
      <td>{u.full_name ?? u.email.split("@")[0]}</td>
      <td className="text-[var(--color-text-dim)]">{u.email}</td>
      <td>
        <RowSelect label={`Plan for ${u.email}`} value={u.plan} options={PLANS} onChange={(v) => run(() => setPlan(u.id, v))} />
      </td>
      <td>
        <RowSelect label={`Role for ${u.email}`} value={u.role} options={ROLES} disabled={isSelf} onChange={(v) => run(() => setRole(u.id, v))} />
      </td>
      <td>
        <span aria-hidden className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full align-middle" style={{ background: color }} />
        <RowSelect label={`Status for ${u.email}`} value={u.status} options={STATUSES} onChange={(v) => run(() => setStatus(u.id, v))} />
      </td>
      <td className="font-mono-num text-[var(--color-text-dim)]">{joinedDate(u.created_at)}</td>
    </tr>
  );
}

function RowSelect({
  label,
  value,
  options,
  onChange,
  disabled,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (v: string) => void;
  disabled?: boolean;
}) {
  return (
    <select
      aria-label={label}
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value)}
      className="rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-1.5 py-0.5 t-tag uppercase text-[var(--color-text-dim)] disabled:opacity-60"
    >
      {options.map((o) => (
        <option key={o} value={o}>
          {o}
        </option>
      ))}
    </select>
  );
}

export default UsersView;
```

- [ ] **Step 4: Run the test + typecheck**

Run: `cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/users/UsersView.test.tsx && npx tsc -b`
Expected: 6/6 PASS; tsc exit 0.

- [ ] **Step 5: Commit**

```bash
cd "D:/Project/PacketPilot"
git add ui/src/admin/users/UsersView.tsx ui/src/admin/users/UsersView.test.tsx
git commit -m "feat(admin): UsersView management table (plan/role/status selects)"
```

---

### Task 4: Wire `AdminShell` + update its test + full gate

**Files:**
- Modify: `ui/src/admin/AdminShell.tsx` (route `users` → `UsersView`)
- Modify: `ui/src/admin/AdminShell.test.tsx` (mock `./users/UsersView`; update the Users-switch assertion)

**Interfaces:**
- Consumes: `UsersView` from `./users/UsersView`; `email` is already an `AdminShell` prop.

- [ ] **Step 1: Update the shell test (failing)**

In `ui/src/admin/AdminShell.test.tsx`, add the mock next to the existing dashboard mock (after line 6):
```tsx
vi.mock("./users/UsersView", () => ({ UsersView: () => <div>USERS_STUB</div> }));
```
And change the Users-switch assertion (currently `expect(screen.getByText(/coming in phase 5/i))...`) to:
```tsx
    await userEvent.click(within(screen.getByRole("navigation")).getByRole("button", { name: "Users" }));
    expect(screen.getByText("USERS_STUB")).toBeInTheDocument();
    expect(window.location.hash).toBe("#users");
```

- [ ] **Step 2: Run the shell test to verify it fails**

Run: `cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/AdminShell.test.tsx`
Expected: FAIL — "USERS_STUB" not found (shell still renders the placeholder).

- [ ] **Step 3: Wire the route in `AdminShell.tsx`**

Add the import after line 5 (`import { Placeholder } ...`):
```tsx
import { UsersView } from "./users/UsersView";
```
Replace the content-routing block (lines 40-44) with:
```tsx
          {active === "dashboard" ? (
            <AdminDashboard />
          ) : active === "users" ? (
            <UsersView adminEmail={email} />
          ) : (
            <Placeholder title={title} phase={section?.phase ?? 0} />
          )}
```

- [ ] **Step 4: Run the shell test to verify it passes**

Run: `cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/AdminShell.test.tsx`
Expected: 4/4 PASS.

- [ ] **Step 5: Full gate**

Run: `cd "D:/Project/PacketPilot/ui" && npx tsc -b && npm run test:coverage && npm run build`
Expected: tsc exit 0; full suite green with the new tests; coverage ≥ 80 statements / 70 branches; build "✓ built". Confirm the run's exit code is 0 (no unhandled errors).

- [ ] **Step 6: Commit**

```bash
cd "D:/Project/PacketPilot"
git add ui/src/admin/AdminShell.tsx ui/src/admin/AdminShell.test.tsx
git commit -m "feat(admin): route the Users section to the management table"
```

---

## After all tasks

- **Final whole-branch review** (most capable model): the diff from `git merge-base main HEAD` to `HEAD`. Focus: the audit trigger (`SECURITY DEFINER`/`search_path`), that mutations rely on the existing RLS/guard (admin-only) with no new write path, self-protection on the Role select, and test hygiene.
- **Browser smoke** (controller): sign in as admin → `/admin` → Users → the table lists all accounts (incl. Bob = pro); change a demo user's plan/role/status → reflected on reload; `execute_sql` confirms the `audit_log` rows. Revert any demo changes.
- **finishing-a-development-branch**: verify the suite, then present merge options.

## Self-review notes

- **Spec coverage:** audit trigger (Task 1); hook + mutators (Task 2); UsersView table, search, per-row selects, self-protection, states, alert (Task 3); AdminShell wiring + test (Task 4); live audit verify + browser smoke (After-all). All spec sections map to a task.
- **Type consistency:** `AdminUser`, `AdminUsersState`, `useAdminUsers(search) → { state, reload }`, `setPlan/setRole/setStatus(id, value) → {ok,error?}` are defined in Task 2 and consumed verbatim in Task 3; `UsersView({ adminEmail })` defined in Task 3 and consumed in Task 4.
- **No placeholders:** every code/test step carries full content and exact commands.
