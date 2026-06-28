# Admin Foundation (Phase 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a non-public, role-gated `/admin` area with a Supabase email/password login and the sidebar/top-bar admin shell (full nav with placeholders), built on PacketPilot's existing design system.

**Architecture:** A third `main.tsx` route (`/admin`) lazy-loads `AdminApp`, which uses a `useAdminSession` hook over the Phase-0 Supabase client to gate: loading → login (anon/forbidden/unconfigured) → `AdminShell` (admin). The shell is a left sidebar + top bar reusing existing tokens/primitives, with section content switched by in-app state synced to `location.hash`. Real section data is deferred to later phases.

**Tech Stack:** React 18 + Vite + TypeScript, `@supabase/supabase-js` (Phase-0 client at `ui/src/lib/supabase`), `lucide-react` (icons, existing dep), Tailwind + `index.css` tokens + `cockpit/primitives`. Vitest + React Testing Library.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-06-27-admin-foundation-design.md`. Branch: `feat/admin-foundation` (already created).
- **No new dependencies.** Reuse `cockpit/primitives` (`Card`, `StatTile`, `SectionHeader`), `cockpit/ThemeToggle` (`ThemeToggle`), `cockpit/DensityToggle` (`DensityToggle`), `components/state/LoadingState` (prop `label?`), and `lib/supabase` (`supabase`, `supabaseConfigured`).
- **Do NOT touch `/app`, the WASM engine, the analysis path, or any existing component.** Only `main.tsx` and `vercel.json` are modified; everything else is new under `ui/src/admin/` (+ `ui/src/lib/route.ts`).
- **Security boundary is RLS** (Phase 0); the route/UI gate is defense-in-UX. `AdminApp` is `React.lazy`-loaded (separate chunk, out of the public bundle).
- **Styling:** semantic tokens only (`var(--color-*)`, `.t-*` utilities, `--r-*` radii). No hardcoded hex. Light/dark + density inherited from the global system.
- **Run `npm`/`npx` from inside `ui/`.** Coverage gate ≥ 80 statements / 70 branches; `npm run build` (tsc + vite) must pass. Mock `../lib/supabase` (or `../../lib/supabase`) in tests — never hit the network.
- **TDD:** failing test first, then implementation. Frequent commits.

---

### Task 1: Admin session hook (`useAdminSession`)

**Files:**
- Create: `ui/src/admin/useAdminSession.ts`
- Test: `ui/src/admin/useAdminSession.test.tsx`

**Interfaces:**
- Consumes: `supabase`, `supabaseConfigured` from `../lib/supabase`.
- Produces:
  - `interface AdminProfile { email: string; role: string; full_name: string | null }`
  - `type AdminSession = { status: "loading" } | { status: "unconfigured" } | { status: "anon"; signIn: (email: string, password: string) => Promise<{ ok: boolean; error?: string }> } | { status: "forbidden"; email: string; signOut: () => Promise<void> } | { status: "admin"; email: string; profile: AdminProfile; signOut: () => Promise<void> }`
  - `function useAdminSession(): AdminSession`

- [ ] **Step 1: Write the failing test** `ui/src/admin/useAdminSession.test.tsx`

```tsx
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor, act } from "@testing-library/react";

// Mutable mock handles, reset per test.
const h = {
  configured: true,
  getSession: vi.fn(),
  signInWithPassword: vi.fn(),
  signOut: vi.fn(),
  onAuthStateChange: vi.fn(),
  single: vi.fn(),
};

vi.mock("../lib/supabase", () => ({
  get supabaseConfigured() {
    return h.configured;
  },
  supabase: {
    auth: {
      getSession: (...a: unknown[]) => h.getSession(...a),
      signInWithPassword: (...a: unknown[]) => h.signInWithPassword(...a),
      signOut: (...a: unknown[]) => h.signOut(...a),
      onAuthStateChange: (...a: unknown[]) => h.onAuthStateChange(...a),
    },
    from: () => ({
      select: () => ({ eq: () => ({ single: (...a: unknown[]) => h.single(...a) }) }),
    }),
  },
}));

import { useAdminSession } from "./useAdminSession";

beforeEach(() => {
  h.configured = true;
  h.getSession.mockResolvedValue({ data: { session: null } });
  h.onAuthStateChange.mockReturnValue({ data: { subscription: { unsubscribe: vi.fn() } } });
  h.signInWithPassword.mockResolvedValue({ data: {}, error: null });
  h.signOut.mockResolvedValue({ error: null });
  h.single.mockResolvedValue({ data: null, error: null });
});
afterEach(() => vi.clearAllMocks());

const session = (uid = "u1", email = "a@b.com") => ({ user: { id: uid, email } });

describe("useAdminSession", () => {
  it("is unconfigured when the client is not configured", async () => {
    h.configured = false;
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("unconfigured"));
  });

  it("is anon when there is no session", async () => {
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
  });

  it("is admin when the signed-in user's profile role is admin", async () => {
    h.getSession.mockResolvedValue({ data: { session: session() } });
    h.single.mockResolvedValue({ data: { email: "a@b.com", role: "admin", full_name: "A" }, error: null });
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("admin"));
  });

  it("is forbidden when the signed-in user's role is not admin", async () => {
    h.getSession.mockResolvedValue({ data: { session: session() } });
    h.single.mockResolvedValue({ data: { email: "a@b.com", role: "user", full_name: "A" }, error: null });
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("forbidden"));
  });

  it("anon.signIn delegates to supabase.auth.signInWithPassword", async () => {
    const { result } = renderHook(() => useAdminSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
    await act(async () => {
      if (result.current.status === "anon") await result.current.signIn("x@y.com", "pw");
    });
    expect(h.signInWithPassword).toHaveBeenCalledWith({ email: "x@y.com", password: "pw" });
  });
});
```

- [ ] **Step 2: Run the test, verify it FAILS**

Run (from `ui/`): `npx vitest run src/admin/useAdminSession.test.tsx`
Expected: FAIL — cannot resolve `./useAdminSession`.

- [ ] **Step 3: Implement** `ui/src/admin/useAdminSession.ts`

```ts
import { useCallback, useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../lib/supabase";

export interface AdminProfile {
  email: string;
  role: string;
  full_name: string | null;
}

export type AdminSession =
  | { status: "loading" }
  | { status: "unconfigured" }
  | { status: "anon"; signIn: (email: string, password: string) => Promise<{ ok: boolean; error?: string }> }
  | { status: "forbidden"; email: string; signOut: () => Promise<void> }
  | { status: "admin"; email: string; profile: AdminProfile; signOut: () => Promise<void> };

type Internal =
  | { status: "loading" }
  | { status: "unconfigured" }
  | { status: "anon" }
  | { status: "forbidden"; email: string }
  | { status: "admin"; email: string; profile: AdminProfile };

export function useAdminSession(): AdminSession {
  const [state, setState] = useState<Internal>(
    supabaseConfigured ? { status: "loading" } : { status: "unconfigured" },
  );

  const signIn = useCallback(async (email: string, password: string) => {
    if (!supabase) return { ok: false, error: "Backend not configured" };
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    return error ? { ok: false, error: error.message } : { ok: true };
  }, []);

  const signOut = useCallback(async () => {
    if (supabase) await supabase.auth.signOut();
  }, []);

  useEffect(() => {
    if (!supabaseConfigured || !supabase) {
      setState({ status: "unconfigured" });
      return;
    }
    const client = supabase;
    let cancelled = false;

    const derive = async (session: { user?: { id: string; email?: string } } | null) => {
      if (!session?.user) {
        if (!cancelled) setState({ status: "anon" });
        return;
      }
      const email = session.user.email ?? "";
      const { data, error } = await client
        .from("profiles")
        .select("email,role,full_name")
        .eq("id", session.user.id)
        .single();
      if (cancelled) return;
      if (error || !data || data.role !== "admin") {
        setState({ status: "forbidden", email: (data?.email as string) ?? email });
        return;
      }
      setState({
        status: "admin",
        email: (data.email as string) ?? email,
        profile: { email: (data.email as string) ?? email, role: data.role as string, full_name: (data.full_name as string | null) ?? null },
      });
    };

    void client.auth.getSession().then(({ data }) => derive(data.session ?? null));
    const { data: sub } = client.auth.onAuthStateChange((_event, session) => void derive(session));
    return () => {
      cancelled = true;
      sub.subscription.unsubscribe();
    };
  }, []);

  switch (state.status) {
    case "loading":
      return { status: "loading" };
    case "unconfigured":
      return { status: "unconfigured" };
    case "anon":
      return { status: "anon", signIn };
    case "forbidden":
      return { status: "forbidden", email: state.email, signOut };
    case "admin":
      return { status: "admin", email: state.email, profile: state.profile, signOut };
  }
}
```

- [ ] **Step 4: Run the test, verify it PASSES**

Run (from `ui/`): `npx vitest run src/admin/useAdminSession.test.tsx`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add ui/src/admin/useAdminSession.ts ui/src/admin/useAdminSession.test.tsx
git commit -m "feat(admin): useAdminSession gate hook over the Supabase client"
```

---

### Task 2: Login surface (`AdminLogin`)

**Files:**
- Create: `ui/src/admin/AdminLogin.tsx`
- Test: `ui/src/admin/AdminLogin.test.tsx`

**Interfaces:**
- Consumes: `AdminSession` from `./useAdminSession` (the non-admin, non-loading variants).
- Produces: `function AdminLogin({ session }: { session: Extract<AdminSession, { status: "anon" | "forbidden" | "unconfigured" }> }): JSX.Element`

- [ ] **Step 1: Write the failing test** `ui/src/admin/AdminLogin.test.tsx`

```tsx
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AdminLogin } from "./AdminLogin";

describe("AdminLogin", () => {
  it("submits entered credentials via session.signIn", async () => {
    const signIn = vi.fn().mockResolvedValue({ ok: true });
    render(<AdminLogin session={{ status: "anon", signIn }} />);
    await userEvent.type(screen.getByLabelText(/email/i), "a@b.com");
    await userEvent.type(screen.getByLabelText(/password/i), "secret");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(signIn).toHaveBeenCalledWith("a@b.com", "secret");
  });

  it("shows the error returned by signIn", async () => {
    const signIn = vi.fn().mockResolvedValue({ ok: false, error: "Invalid login credentials" });
    render(<AdminLogin session={{ status: "anon", signIn }} />);
    await userEvent.type(screen.getByLabelText(/email/i), "a@b.com");
    await userEvent.type(screen.getByLabelText(/password/i), "bad");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(await screen.findByText(/invalid login credentials/i)).toBeInTheDocument();
  });

  it("forbidden variant shows a not-admin message and a sign-out button", async () => {
    const signOut = vi.fn().mockResolvedValue(undefined);
    render(<AdminLogin session={{ status: "forbidden", email: "u@b.com", signOut }} />);
    expect(screen.getByText(/not an administrator/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /sign out/i }));
    expect(signOut).toHaveBeenCalled();
  });

  it("unconfigured variant shows a configuration notice", () => {
    render(<AdminLogin session={{ status: "unconfigured" }} />);
    expect(screen.getByText(/not configured/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run the test, verify it FAILS**

Run (from `ui/`): `npx vitest run src/admin/AdminLogin.test.tsx`
Expected: FAIL — cannot resolve `./AdminLogin`.

- [ ] **Step 3: Implement** `ui/src/admin/AdminLogin.tsx`

```tsx
import { useState, type FormEvent } from "react";
import { ShieldCheck } from "lucide-react";
import type { AdminSession } from "./useAdminSession";

type LoginSession = Extract<AdminSession, { status: "anon" | "forbidden" | "unconfigured" }>;

/** Centered card used for every pre-shell admin state. */
function Frame({ children }: { children: React.ReactNode }) {
  return (
    <div className="app-bg flex h-full min-h-0 items-center justify-center px-6 py-12 text-[var(--color-text)]">
      <section className="card w-full max-w-sm p-6 shadow-[var(--sh-hero)]">
        <div className="mb-4 flex items-center gap-2">
          <ShieldCheck size={18} className="text-[var(--color-accent)]" aria-hidden />
          <h1 className="t-title text-[var(--color-text)]">PacketPilot Admin</h1>
        </div>
        {children}
      </section>
    </div>
  );
}

export function AdminLogin({ session }: { session: LoginSession }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (session.status === "unconfigured") {
    return (
      <Frame>
        <p className="text-sm text-[var(--color-text-dim)]">
          The admin backend is not configured. Set <code>VITE_SUPABASE_URL</code> and{" "}
          <code>VITE_SUPABASE_ANON_KEY</code>, then reload.
        </p>
      </Frame>
    );
  }

  if (session.status === "forbidden") {
    return (
      <Frame>
        <p className="text-sm text-[var(--color-text-dim)]">
          You are signed in as <span className="text-[var(--color-text)]">{session.email}</span>, but this account is{" "}
          <strong className="text-[var(--color-text)]">not an administrator</strong>.
        </p>
        <button
          type="button"
          onClick={() => void session.signOut()}
          className="mt-4 inline-flex items-center justify-center rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-sm text-[var(--color-text-dim)] hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]"
        >
          Sign out
        </button>
      </Frame>
    );
  }

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    const res = await session.signIn(email, password);
    if (!res.ok) setError(res.error ?? "Sign-in failed");
    setBusy(false);
  };

  return (
    <Frame>
      <form onSubmit={onSubmit} className="flex flex-col gap-3">
        <label className="flex flex-col gap-1 text-sm">
          <span className="t-label text-[var(--color-text-dim)]">Email</span>
          <input
            type="email"
            autoComplete="username"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-[var(--color-text)] outline-none focus:border-[var(--color-accent)]"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="t-label text-[var(--color-text-dim)]">Password</span>
          <input
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-[var(--color-text)] outline-none focus:border-[var(--color-accent)]"
          />
        </label>
        {error && (
          <p role="alert" className="t-tag text-[var(--color-sev-critical)]">
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={busy}
          className="mt-1 inline-flex items-center justify-center rounded-[var(--r-tile)] bg-[var(--color-accent-deep)] px-3 py-1.5 text-sm font-medium text-[var(--color-on-accent)] disabled:opacity-60"
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </Frame>
  );
}

export default AdminLogin;
```

- [ ] **Step 4: Run the test, verify it PASSES**

Run (from `ui/`): `npx vitest run src/admin/AdminLogin.test.tsx`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add ui/src/admin/AdminLogin.tsx ui/src/admin/AdminLogin.test.tsx
git commit -m "feat(admin): login surface (anon/forbidden/unconfigured states)"
```

---

### Task 3: Nav config + placeholder views

**Files:**
- Create: `ui/src/admin/sections.ts`
- Create: `ui/src/admin/views/Placeholder.tsx`
- Create: `ui/src/admin/views/AdminDashboard.tsx`
- Test: `ui/src/admin/views/Placeholder.test.tsx`

**Interfaces:**
- Produces:
  - `ADMIN_SECTIONS` (readonly array of `{ id, label, icon, phase }`) and `type AdminSectionId`.
  - `function Placeholder({ title, phase }: { title: string; phase: number }): JSX.Element`
  - `function AdminDashboard(): JSX.Element`

- [ ] **Step 1: Write the failing test** `ui/src/admin/views/Placeholder.test.tsx`

```tsx
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Placeholder } from "./Placeholder";
import { ADMIN_SECTIONS } from "../sections";

describe("admin sections + Placeholder", () => {
  it("defines the seven admin sections with unique ids", () => {
    const ids = ADMIN_SECTIONS.map((s) => s.id);
    expect(ids).toEqual(["dashboard", "users", "payments", "traffic", "features", "settings", "env"]);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("renders a coming-soon placeholder naming the section and phase", () => {
    render(<Placeholder title="Users" phase={5} />);
    expect(screen.getByText("Users")).toBeInTheDocument();
    expect(screen.getByText(/phase 5/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run the test, verify it FAILS**

Run (from `ui/`): `npx vitest run src/admin/views/Placeholder.test.tsx`
Expected: FAIL — cannot resolve `./Placeholder` / `../sections`.

- [ ] **Step 3: Implement `ui/src/admin/sections.ts`**

```ts
import { LayoutDashboard, Users, CreditCard, Activity, ToggleRight, Settings, KeyRound, type LucideIcon } from "lucide-react";

export interface AdminSection {
  id: string;
  label: string;
  icon: LucideIcon;
  phase: number;
}

export const ADMIN_SECTIONS = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard, phase: 4 },
  { id: "users", label: "Users", icon: Users, phase: 5 },
  { id: "payments", label: "Payments", icon: CreditCard, phase: 6 },
  { id: "traffic", label: "Live Traffic", icon: Activity, phase: 7 },
  { id: "features", label: "App Features", icon: ToggleRight, phase: 8 },
  { id: "settings", label: "Settings", icon: Settings, phase: 9 },
  { id: "env", label: "Environment", icon: KeyRound, phase: 9 },
] as const satisfies readonly AdminSection[];

export type AdminSectionId = (typeof ADMIN_SECTIONS)[number]["id"];

export function sectionById(id: string): (typeof ADMIN_SECTIONS)[number] | undefined {
  return ADMIN_SECTIONS.find((s) => s.id === id);
}
```

- [ ] **Step 4: Implement `ui/src/admin/views/Placeholder.tsx`**

```tsx
import { Card } from "../../cockpit/primitives";

/** On-brand "coming soon" panel for sections not yet built. */
export function Placeholder({ title, phase }: { title: string; phase: number }) {
  return (
    <Card title={title}>
      <p className="text-sm text-[var(--color-text-dim)]">
        This section is coming in Phase {phase}.
      </p>
    </Card>
  );
}

export default Placeholder;
```

- [ ] **Step 5: Implement `ui/src/admin/views/AdminDashboard.tsx`**

```tsx
import { Card } from "../../cockpit/primitives";

/** Phase-3 placeholder for the admin dashboard. Phase 4 replaces this with the
 *  real KPI cards + charts sourced from public.admin_dashboard_stats. */
export function AdminDashboard() {
  return (
    <Card title="Dashboard">
      <p className="text-sm text-[var(--color-text-dim)]">
        Overview metrics arrive in Phase 4 (users, active today, revenue, system health).
      </p>
    </Card>
  );
}

export default AdminDashboard;
```

- [ ] **Step 6: Run the test, verify it PASSES**

Run (from `ui/`): `npx vitest run src/admin/views/Placeholder.test.tsx`
Expected: PASS (2 tests).

- [ ] **Step 7: Commit**

```bash
git add ui/src/admin/sections.ts ui/src/admin/views
git commit -m "feat(admin): nav config + placeholder/dashboard views"
```

---

### Task 4: Admin shell (sidebar + top bar + content)

**Files:**
- Create: `ui/src/admin/Sidebar.tsx`
- Create: `ui/src/admin/AdminTopBar.tsx`
- Create: `ui/src/admin/AdminShell.tsx`
- Test: `ui/src/admin/AdminShell.test.tsx`

**Interfaces:**
- Consumes: `ADMIN_SECTIONS`, `AdminSectionId`, `sectionById` from `./sections`; `Placeholder`, `AdminDashboard` views; `ThemeToggle`, `DensityToggle`.
- Produces:
  - `function Sidebar({ active, onSelect, collapsed, onToggleCollapse }: { active: AdminSectionId; onSelect: (id: AdminSectionId) => void; collapsed: boolean; onToggleCollapse: () => void }): JSX.Element`
  - `function AdminTopBar({ title, email, onSignOut }: { title: string; email: string; onSignOut: () => Promise<void> }): JSX.Element`
  - `function AdminShell({ email, onSignOut }: { email: string; onSignOut: () => Promise<void> }): JSX.Element`

- [ ] **Step 1: Write the failing test** `ui/src/admin/AdminShell.test.tsx`

```tsx
import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AdminShell } from "./AdminShell";

afterEach(() => {
  window.location.hash = "";
});

describe("AdminShell", () => {
  it("renders all seven nav items and defaults to the dashboard", () => {
    render(<AdminShell email="a@b.com" onSignOut={vi.fn()} />);
    const nav = screen.getByRole("navigation");
    for (const label of ["Dashboard", "Users", "Payments", "Live Traffic", "App Features", "Settings", "Environment"]) {
      expect(within(nav).getByRole("button", { name: label })).toBeInTheDocument();
    }
    expect(screen.getByText(/overview metrics arrive in phase 4/i)).toBeInTheDocument();
  });

  it("switches content when a nav item is clicked and reflects it in the hash", async () => {
    render(<AdminShell email="a@b.com" onSignOut={vi.fn()} />);
    await userEvent.click(within(screen.getByRole("navigation")).getByRole("button", { name: "Users" }));
    expect(screen.getByText(/coming in phase 5/i)).toBeInTheDocument();
    expect(window.location.hash).toBe("#users");
  });

  it("signs out from the profile menu", async () => {
    const onSignOut = vi.fn().mockResolvedValue(undefined);
    render(<AdminShell email="a@b.com" onSignOut={onSignOut} />);
    await userEvent.click(screen.getByRole("button", { name: /account menu/i }));
    await userEvent.click(screen.getByRole("button", { name: /sign out/i }));
    expect(onSignOut).toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run the test, verify it FAILS**

Run (from `ui/`): `npx vitest run src/admin/AdminShell.test.tsx`
Expected: FAIL — cannot resolve `./AdminShell`.

- [ ] **Step 3: Implement `ui/src/admin/Sidebar.tsx`**

```tsx
import { PanelLeftClose, PanelLeft, ShieldCheck } from "lucide-react";
import { cn } from "../lib/cn";
import { ADMIN_SECTIONS, type AdminSectionId } from "./sections";

export function Sidebar({
  active,
  onSelect,
  collapsed,
  onToggleCollapse,
}: {
  active: AdminSectionId;
  onSelect: (id: AdminSectionId) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
}) {
  return (
    <aside
      className={cn(
        "flex shrink-0 flex-col border-r border-[var(--color-border)] bg-[var(--color-surface-1)] transition-[width]",
        collapsed ? "w-16" : "w-56",
      )}
    >
      <div className="flex h-12 items-center gap-2 px-3">
        <ShieldCheck size={18} className="shrink-0 text-[var(--color-accent)]" aria-hidden />
        {!collapsed && <span className="t-title text-[var(--color-text)]">Admin</span>}
      </div>
      <nav aria-label="Admin sections" className="flex flex-1 flex-col gap-0.5 px-2 py-2">
        {ADMIN_SECTIONS.map((s) => {
          const Icon = s.icon;
          const isActive = s.id === active;
          return (
            <button
              key={s.id}
              type="button"
              aria-label={s.label}
              aria-current={isActive ? "page" : undefined}
              title={collapsed ? s.label : undefined}
              onClick={() => onSelect(s.id as AdminSectionId)}
              className={cn(
                "flex items-center gap-2.5 rounded-[var(--r-tile)] px-2.5 py-2 text-sm transition-colors",
                isActive
                  ? "bg-[var(--color-surface-2)] text-[var(--color-text)]"
                  : "text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]",
              )}
            >
              <Icon size={16} aria-hidden className="shrink-0" />
              {!collapsed && <span className="truncate">{s.label}</span>}
            </button>
          );
        })}
      </nav>
      <button
        type="button"
        onClick={onToggleCollapse}
        aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        className="m-2 inline-flex items-center justify-center rounded-[var(--r-tile)] border border-[var(--color-border)] p-1.5 text-[var(--color-text-faint)] hover:text-[var(--color-text-dim)]"
      >
        {collapsed ? <PanelLeft size={14} aria-hidden /> : <PanelLeftClose size={14} aria-hidden />}
      </button>
    </aside>
  );
}

export default Sidebar;
```

- [ ] **Step 4: Implement `ui/src/admin/AdminTopBar.tsx`**

```tsx
import { useEffect, useRef, useState } from "react";
import { ChevronDown } from "lucide-react";
import { ThemeToggle } from "../cockpit/ThemeToggle";
import { DensityToggle } from "../cockpit/DensityToggle";

export function AdminTopBar({
  title,
  email,
  onSignOut,
}: {
  title: string;
  email: string;
  onSignOut: () => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  return (
    <header className="flex h-12 shrink-0 items-center justify-between border-b border-[var(--color-border)] bg-[var(--color-surface-1)] px-4">
      <h1 className="t-title text-[var(--color-text)]">{title}</h1>
      <div className="flex items-center gap-2">
        <ThemeToggle />
        <DensityToggle />
        <div ref={ref} className="relative">
          <button
            type="button"
            aria-label="Account menu"
            aria-expanded={open}
            onClick={() => setOpen((o) => !o)}
            className="flex items-center gap-1.5 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1 text-sm text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
          >
            <span className="max-w-[12rem] truncate">{email}</span>
            <ChevronDown size={14} aria-hidden />
          </button>
          {open && (
            <div
              role="menu"
              className="absolute right-0 z-10 mt-1 w-40 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-1 shadow-[var(--sh-float)]"
            >
              <button
                type="button"
                role="menuitem"
                onClick={() => void onSignOut()}
                className="w-full rounded-[var(--r-micro)] px-2 py-1.5 text-left text-sm text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]"
              >
                Sign out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

export default AdminTopBar;
```

- [ ] **Step 5: Implement `ui/src/admin/AdminShell.tsx`**

```tsx
import { useEffect, useState } from "react";
import { Sidebar } from "./Sidebar";
import { AdminTopBar } from "./AdminTopBar";
import { AdminDashboard } from "./views/AdminDashboard";
import { Placeholder } from "./views/Placeholder";
import { ADMIN_SECTIONS, sectionById, type AdminSectionId } from "./sections";

const VALID = new Set(ADMIN_SECTIONS.map((s) => s.id));

function sectionFromHash(): AdminSectionId {
  const id = window.location.hash.replace(/^#/, "");
  return (VALID.has(id) ? id : "dashboard") as AdminSectionId;
}

export function AdminShell({ email, onSignOut }: { email: string; onSignOut: () => Promise<void> }) {
  const [active, setActive] = useState<AdminSectionId>(() => sectionFromHash());
  const [collapsed, setCollapsed] = useState(false);

  // Keep state in sync with browser back/forward hash changes.
  useEffect(() => {
    const onHash = () => setActive(sectionFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const select = (id: AdminSectionId) => {
    setActive(id);
    if (window.location.hash !== `#${id}`) window.location.hash = id;
  };

  const section = sectionById(active);
  const title = section?.label ?? "Dashboard";

  return (
    <div className="flex h-full min-h-0 bg-bg text-[var(--color-text)]">
      <Sidebar active={active} onSelect={select} collapsed={collapsed} onToggleCollapse={() => setCollapsed((c) => !c)} />
      <div className="flex min-h-0 flex-1 flex-col">
        <AdminTopBar title={title} email={email} onSignOut={onSignOut} />
        <main className="min-h-0 flex-1 overflow-y-auto p-4">
          {active === "dashboard" ? (
            <AdminDashboard />
          ) : (
            <Placeholder title={title} phase={section?.phase ?? 0} />
          )}
        </main>
      </div>
    </div>
  );
}

export default AdminShell;
```

- [ ] **Step 6: Run the test, verify it PASSES**

Run (from `ui/`): `npx vitest run src/admin/AdminShell.test.tsx`
Expected: PASS (3 tests).

- [ ] **Step 7: Commit**

```bash
git add ui/src/admin/Sidebar.tsx ui/src/admin/AdminTopBar.tsx ui/src/admin/AdminShell.tsx ui/src/admin/AdminShell.test.tsx
git commit -m "feat(admin): sidebar + top bar + shell with hash-routed sections"
```

---

### Task 5: `AdminApp` gate composition

**Files:**
- Create: `ui/src/admin/AdminApp.tsx`
- Test: `ui/src/admin/AdminApp.test.tsx`

**Interfaces:**
- Consumes: `useAdminSession`, `AdminLogin`, `AdminShell`, `LoadingState`.
- Produces: `default export function AdminApp(): JSX.Element` (default export required by `React.lazy`).

- [ ] **Step 1: Write the failing test** `ui/src/admin/AdminApp.test.tsx`

```tsx
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";

const mockSession = vi.fn();
vi.mock("./useAdminSession", () => ({ useAdminSession: () => mockSession() }));
// Keep the shell/login light so this test targets the gate only.
vi.mock("./AdminShell", () => ({ AdminShell: () => <div>SHELL</div> }));
vi.mock("./AdminLogin", () => ({ AdminLogin: (p: { session: { status: string } }) => <div>LOGIN:{p.session.status}</div> }));

import AdminApp from "./AdminApp";

describe("AdminApp gate", () => {
  it("shows the loading state while resolving", () => {
    mockSession.mockReturnValue({ status: "loading" });
    render(<AdminApp />);
    expect(screen.getByRole("status")).toBeInTheDocument();
  });

  it("renders the shell for an admin", () => {
    mockSession.mockReturnValue({ status: "admin", email: "a@b.com", profile: {}, signOut: vi.fn() });
    render(<AdminApp />);
    expect(screen.getByText("SHELL")).toBeInTheDocument();
  });

  it("renders the login for anon / forbidden / unconfigured", () => {
    for (const status of ["anon", "forbidden", "unconfigured"]) {
      mockSession.mockReturnValue({ status, email: "u@b.com", signIn: vi.fn(), signOut: vi.fn() });
      const { unmount } = render(<AdminApp />);
      expect(screen.getByText(`LOGIN:${status}`)).toBeInTheDocument();
      unmount();
    }
  });
});
```

- [ ] **Step 2: Run the test, verify it FAILS**

Run (from `ui/`): `npx vitest run src/admin/AdminApp.test.tsx`
Expected: FAIL — cannot resolve `./AdminApp`.

- [ ] **Step 3: Implement** `ui/src/admin/AdminApp.tsx`

```tsx
import { useAdminSession } from "./useAdminSession";
import { AdminLogin } from "./AdminLogin";
import { AdminShell } from "./AdminShell";
import { LoadingState } from "../components/state/LoadingState";

export function AdminApp() {
  const session = useAdminSession();
  if (session.status === "loading") return <LoadingState label="Checking access…" />;
  if (session.status === "admin") return <AdminShell email={session.email} onSignOut={session.signOut} />;
  return <AdminLogin session={session} />;
}

export default AdminApp;
```

- [ ] **Step 4: Run the test, verify it PASSES**

Run (from `ui/`): `npx vitest run src/admin/AdminApp.test.tsx`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add ui/src/admin/AdminApp.tsx ui/src/admin/AdminApp.test.tsx
git commit -m "feat(admin): AdminApp gate (loading/login/shell)"
```

---

### Task 6: Wire the `/admin` route + Vercel rewrites + full verification

**Files:**
- Create: `ui/src/lib/route.ts`
- Test: `ui/src/lib/route.test.ts`
- Modify: `ui/src/main.tsx`
- Modify: `vercel.json`

**Interfaces:**
- Consumes: `AdminApp` (lazy), `App`, `Landing`, `LoadingState`.
- Produces: `type Route = "landing" | "app" | "admin"`; `function resolveRoute(pathname: string): Route`.

- [ ] **Step 1: Write the failing test** `ui/src/lib/route.test.ts`

```ts
import { describe, expect, it } from "vitest";
import { resolveRoute } from "./route";

describe("resolveRoute", () => {
  it("maps /admin and subpaths to admin", () => {
    expect(resolveRoute("/admin")).toBe("admin");
    expect(resolveRoute("/admin/")).toBe("admin");
    expect(resolveRoute("/admin/users")).toBe("admin");
  });
  it("maps /app and subpaths to app", () => {
    expect(resolveRoute("/app")).toBe("app");
    expect(resolveRoute("/app/flows")).toBe("app");
  });
  it("maps everything else to landing", () => {
    expect(resolveRoute("/")).toBe("landing");
    expect(resolveRoute("/pricing")).toBe("landing");
    expect(resolveRoute("/administrator")).toBe("landing");
  });
});
```

- [ ] **Step 2: Run the test, verify it FAILS**

Run (from `ui/`): `npx vitest run src/lib/route.test.ts`
Expected: FAIL — cannot resolve `./route`.

- [ ] **Step 3: Implement `ui/src/lib/route.ts`**

```ts
export type Route = "landing" | "app" | "admin";

/** Minimal pathname routing shared by main.tsx. Trailing slashes are ignored.
 *  Note "/administrator" must NOT match admin — only "/admin" and "/admin/...". */
export function resolveRoute(pathname: string): Route {
  const path = pathname.replace(/\/+$/, "");
  if (path === "/admin" || path.startsWith("/admin/")) return "admin";
  if (path === "/app" || path.startsWith("/app/")) return "app";
  return "landing";
}
```

- [ ] **Step 4: Run the test, verify it PASSES**

Run (from `ui/`): `npx vitest run src/lib/route.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Rewrite `ui/src/main.tsx`** to use the route + lazy admin chunk

```tsx
import React, { Suspense } from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { Landing } from "./landing/Landing";
import { ErrorBoundary } from "./components/state/ErrorBoundary";
import { LoadingState } from "./components/state/LoadingState";
import { resolveRoute } from "./lib/route";
import "./index.css";

// Pathname routing: "/" → marketing landing, "/app" → triage app, "/admin" → the
// (lazy-loaded, role-gated) admin panel. On Vercel, /app and /admin are rewritten
// to /index.html (see vercel.json) so this same bundle loads and branches here.
const AdminApp = React.lazy(() => import("./admin/AdminApp"));
const route = resolveRoute(window.location.pathname);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      {route === "admin" ? (
        <Suspense fallback={<LoadingState label="Loading admin…" />}>
          <AdminApp />
        </Suspense>
      ) : route === "app" ? (
        <App />
      ) : (
        <Landing />
      )}
    </ErrorBoundary>
  </React.StrictMode>,
);
```

- [ ] **Step 6: Add `/admin` rewrites to `vercel.json`**

In the `"rewrites"` array, add these two entries alongside the existing `/app` ones:
```json
{ "source": "/admin", "destination": "/" },
{ "source": "/admin/(.*)", "destination": "/" }
```
The array becomes (full context):
```json
  "rewrites": [
    { "source": "/app", "destination": "/" },
    { "source": "/app/(.*)", "destination": "/" },
    { "source": "/admin", "destination": "/" },
    { "source": "/admin/(.*)", "destination": "/" }
  ],
```

- [ ] **Step 7: Verify the full suite, types, build, and coverage**

Run (from `ui/`):
- `npx vitest run src/admin src/lib/route.test.ts` → all admin + route tests pass.
- `npm run build` → `tsc -b && vite build` succeed; confirm the build output lists a separate admin chunk (a `AdminApp-*.js` asset), proving the lazy split.
- `npm run test:coverage` → full suite green, coverage ≥ 80 statements / 70 branches.

- [ ] **Step 8: Commit**

```bash
git add ui/src/lib/route.ts ui/src/lib/route.test.ts ui/src/main.tsx vercel.json
git commit -m "feat(admin): route /admin to the lazy admin app + Vercel rewrites"
```

---

### Task 7: Create the first admin account + smoke test

**Files:** none (operational; live project `brkztcfhmrjjnbjzycie`).

**Interfaces:** consumes the deployed schema/trigger from Phase 0.

- [ ] **Step 1: Create the admin auth user (controller, via Supabase MCP `execute_sql`)**

Generate a strong temporary password (do not hardcode in the repo). Run, substituting `<TEMP_PW>`:
```sql
insert into auth.users
  (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
   raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
   confirmation_token, email_change, email_change_token_new, recovery_token)
select
  '00000000-0000-0000-0000-000000000000', gen_random_uuid(), 'authenticated', 'authenticated',
  'ravi.dholariya@icloud.com', crypt('<TEMP_PW>', gen_salt('bf')), now(),
  '{"provider":"email","providers":["email"]}'::jsonb, '{"full_name":"Ravi Dholariya"}'::jsonb, now(), now(),
  '', '', '', ''
where not exists (select 1 from auth.users u where u.email = 'ravi.dholariya@icloud.com');

update public.profiles set role = 'admin' where email = 'ravi.dholariya@icloud.com';

select email, role from public.profiles where email = 'ravi.dholariya@icloud.com';
```
Expected: one row, `role = admin`. Share `<TEMP_PW>` with the user privately (not in git/commits).

- [ ] **Step 2: Smoke-test the gate (preview tools)**

Start the dev server and verify in the browser preview:
- `/admin` shows the login (since no browser session yet).
- Sign in with `ravi.dholariya@icloud.com` + `<TEMP_PW>` → the shell renders; the Users nav item shows the Phase-5 placeholder; the hash updates to `#users`.
- Sign out returns to the login.
Capture a screenshot of the shell as proof. (If the local dev server lacks the env vars, confirm `ui/.env.local` has `VITE_SUPABASE_URL`/`VITE_SUPABASE_ANON_KEY` from Phase 0.)

- [ ] **Step 3: No commit** (operational task; nothing to add to git).

---

## Self-Review

**1. Spec coverage:**
- Routing `/admin` lazy + Vercel rewrites → Task 6. ✅
- Auth gate (`useAdminSession`, loading/unconfigured/anon/forbidden/admin) → Task 1. ✅
- Login surface (3 variants) → Task 2. ✅
- Shell: sidebar (7 sections) + top bar (title, profile menu, Theme/Density) + hash-synced content → Tasks 3, 4. ✅
- Placeholder + Dashboard placeholder → Task 3. ✅
- AdminApp gate composition → Task 5. ✅
- First admin establishment → Task 7. ✅
- Reuse-not-rebuild (primitives/toggles/LoadingState/tokens), no `/app`/engine change → enforced in every task's files + Global Constraints. ✅
- RLS-is-the-boundary + lazy isolation → Task 6 (lazy) + Global Constraints; the gate never grants admin on role-query error (Task 1 forbidden fallback). ✅

**2. Placeholder scan:** No "TBD/handle errors/similar to Task N". The only literal `Placeholder` is the named component. The `<TEMP_PW>` token in Task 7 is an intentional runtime secret (generated at execution, shared privately, never committed) — not a code placeholder.

**3. Type consistency:** `AdminSession`/`AdminProfile` shape is identical across Tasks 1, 2, 5. `AdminSectionId`, `ADMIN_SECTIONS`, `sectionById` consistent across Tasks 3, 4. `AdminShell` props `{ email, onSignOut }` match between Tasks 4 and 5. `resolveRoute`/`Route` consistent across Task 6. Default exports exist where imported as default (`AdminApp` for `React.lazy`).

## Execution Handoff

(See message.)
