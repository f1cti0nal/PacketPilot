# End-User Accounts (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add optional email/password accounts to `/app` — a `useSession` hook, an `AuthDialog` (signup/login/confirm-pending), and an `AccountMenu` in the shell — without gating any existing functionality.

**Architecture:** Frontend-only on the Phase-0 backend (Supabase Auth + the `handle_new_user` profiles trigger + RLS; no migration). `useSession` mirrors the admin session pattern for end-users; `App.tsx` owns the session + dialog state and feeds an `AccountMenu` into a new `CommandBar`/`AppShell` `accountMenu` slot.

**Tech Stack:** React 18 + TS, `@supabase/supabase-js` (Phase-0 client `ui/src/lib/supabase`), `lib/useDialogA11y` (Escape + focus-trap, signature `useDialogA11y(onClose) → { ref, onKeyDown }`), Tailwind + `index.css` tokens + `lucide-react`. Vitest + RTL. No new deps.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-06-27-end-user-accounts-design.md`. Branch `feat/end-user-accounts` (created).
- **No migration / no backend change** — reuse Phase-0 auth, the `profiles` trigger, and RLS. **No engine/WASM/Tauri change. `/admin` untouched. No new deps.**
- **Opt-in / additive:** never block anonymous use; the analysis path stays untouched; no capture data touches an account.
- **Tokens only** (`var(--color-*)`, `.t-*`, `--r-*`); no hardcoded hex. Account popover is a plain popover (NOT `role="menu"`), matching the admin AccountMenu fix.
- **Run npm/npx from inside `ui/`.** Per task run BOTH `npx vitest run <file>` AND `npx tsc -b` (vitest does not typecheck). Coverage gate ≥ 80/70; `npm run build` must pass. Mock `../lib/supabase` (or `../../lib/supabase`) in tests.

---

### Task 1: End-user session hook (`useSession`)

**Files:**
- Create: `ui/src/auth/useSession.ts`
- Test: `ui/src/auth/useSession.test.tsx`

**Interfaces:**
- Consumes: `supabase`, `supabaseConfigured` from `../lib/supabase`.
- Produces:
  - `interface UserProfile { email: string; full_name: string | null; plan: string }`
  - `type SessionState = { status: "loading" } | { status: "anon"; signIn: (email: string, password: string) => Promise<{ ok: boolean; error?: string }>; signUp: (email: string, password: string) => Promise<{ ok: boolean; needsConfirm?: boolean; error?: string }> } | { status: "authed"; email: string; profile: UserProfile; signOut: () => Promise<void> }`
  - `function useSession(): SessionState`

- [ ] **Step 1: Write the failing test** `ui/src/auth/useSession.test.tsx`

```tsx
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor, act } from "@testing-library/react";

const h = {
  configured: true,
  getSession: vi.fn(),
  signInWithPassword: vi.fn(),
  signUp: vi.fn(),
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
      signUp: (...a: unknown[]) => h.signUp(...a),
      signOut: (...a: unknown[]) => h.signOut(...a),
      onAuthStateChange: (...a: unknown[]) => h.onAuthStateChange(...a),
    },
    from: () => ({
      select: () => ({ eq: () => ({ single: (...a: unknown[]) => h.single(...a) }) }),
    }),
  },
}));

import { useSession } from "./useSession";

beforeEach(() => {
  h.configured = true;
  h.getSession.mockResolvedValue({ data: { session: null } });
  h.onAuthStateChange.mockReturnValue({ data: { subscription: { unsubscribe: vi.fn() } } });
  h.signInWithPassword.mockResolvedValue({ data: {}, error: null });
  h.signUp.mockResolvedValue({ data: { session: null }, error: null });
  h.signOut.mockResolvedValue({ error: null });
  h.single.mockResolvedValue({ data: { email: "a@b.com", full_name: "A", plan: "pro" }, error: null });
});
afterEach(() => {
  vi.clearAllMocks();
});

const session = (uid = "u1", email = "a@b.com") => ({ user: { id: uid, email } });

describe("useSession", () => {
  it("is anon with no session", async () => {
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
  });

  it("is anon when unconfigured", async () => {
    h.configured = false;
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
  });

  it("is authed with the profile when a session exists", async () => {
    h.getSession.mockResolvedValue({ data: { session: session() } });
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("authed"));
    if (result.current.status !== "authed") throw new Error("not authed");
    expect(result.current.profile.plan).toBe("pro");
    expect(result.current.email).toBe("a@b.com");
  });

  it("signIn delegates to supabase.auth.signInWithPassword", async () => {
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
    await act(async () => {
      if (result.current.status === "anon") await result.current.signIn("x@y.com", "pw");
    });
    expect(h.signInWithPassword).toHaveBeenCalledWith({ email: "x@y.com", password: "pw" });
  });

  it("signUp passes emailRedirectTo and reports needsConfirm when no session is returned", async () => {
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
    let res: { ok: boolean; needsConfirm?: boolean } | undefined;
    await act(async () => {
      if (result.current.status === "anon") res = await result.current.signUp("x@y.com", "pw");
    });
    expect(h.signUp).toHaveBeenCalledWith({
      email: "x@y.com",
      password: "pw",
      options: { emailRedirectTo: expect.stringContaining("/app") },
    });
    expect(res).toEqual({ ok: true, needsConfirm: true });
  });

  it("re-derives on auth state change", async () => {
    let cb: ((e: string, s: unknown) => void) | undefined;
    h.onAuthStateChange.mockImplementation((fn: (e: string, s: unknown) => void) => {
      cb = fn;
      return { data: { subscription: { unsubscribe: vi.fn() } } };
    });
    const { result } = renderHook(() => useSession());
    await waitFor(() => expect(result.current.status).toBe("anon"));
    await act(async () => {
      cb?.("SIGNED_IN", session());
    });
    await waitFor(() => expect(result.current.status).toBe("authed"));
  });
});
```

- [ ] **Step 2: Run it, verify FAIL**

`npx vitest run src/auth/useSession.test.tsx` → FAIL (cannot resolve ./useSession).

- [ ] **Step 3: Implement** `ui/src/auth/useSession.ts`

```ts
import { useCallback, useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../lib/supabase";

export interface UserProfile {
  email: string;
  full_name: string | null;
  plan: string;
}

export type SessionState =
  | { status: "loading" }
  | {
      status: "anon";
      signIn: (email: string, password: string) => Promise<{ ok: boolean; error?: string }>;
      signUp: (email: string, password: string) => Promise<{ ok: boolean; needsConfirm?: boolean; error?: string }>;
    }
  | { status: "authed"; email: string; profile: UserProfile; signOut: () => Promise<void> };

type Internal =
  | { status: "loading" }
  | { status: "anon" }
  | { status: "authed"; email: string; profile: UserProfile };

export function useSession(): SessionState {
  const [state, setState] = useState<Internal>(
    supabaseConfigured ? { status: "loading" } : { status: "anon" },
  );

  const signIn = useCallback(async (email: string, password: string) => {
    if (!supabase) return { ok: false, error: "Accounts are unavailable" };
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    return error ? { ok: false, error: error.message } : { ok: true };
  }, []);

  const signUp = useCallback(async (email: string, password: string) => {
    if (!supabase) return { ok: false, error: "Accounts are unavailable" };
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: { emailRedirectTo: `${window.location.origin}/app` },
    });
    if (error) return { ok: false, error: error.message };
    return { ok: true, needsConfirm: !data.session };
  }, []);

  const signOut = useCallback(async () => {
    if (supabase) await supabase.auth.signOut();
  }, []);

  useEffect(() => {
    if (!supabaseConfigured || !supabase) {
      setState({ status: "anon" });
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
      const { data } = await client
        .from("profiles")
        .select("email,full_name,plan")
        .eq("id", session.user.id)
        .single();
      if (cancelled) return;
      // Best-effort: a failed profile read still leaves the user authed (email from the
      // session, plan defaulting to free) rather than bouncing them out.
      setState({
        status: "authed",
        email: (data?.email as string) ?? email,
        profile: {
          email: (data?.email as string) ?? email,
          full_name: (data?.full_name as string | null) ?? null,
          plan: (data?.plan as string) ?? "free",
        },
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
    case "anon":
      return { status: "anon", signIn, signUp };
    case "authed":
      return { status: "authed", email: state.email, profile: state.profile, signOut };
  }
}
```

- [ ] **Step 4: Run it (PASS) + typecheck**

`npx vitest run src/auth/useSession.test.tsx` → PASS (6). `npx tsc -b` → exit 0.

- [ ] **Step 5: Commit**

```bash
git add ui/src/auth/useSession.ts ui/src/auth/useSession.test.tsx
git commit -m "feat(auth): end-user useSession hook (signin/signup/signout + profile)"
```

---

### Task 2: Auth modal (`AuthDialog`)

**Files:**
- Create: `ui/src/auth/AuthDialog.tsx`
- Test: `ui/src/auth/AuthDialog.test.tsx`

**Interfaces:**
- Consumes: `SessionState` (the `anon` variant) from `./useSession`; `useDialogA11y` from `../lib/useDialogA11y`.
- Produces: `function AuthDialog({ session, onClose }: { session: Extract<SessionState, { status: "anon" }>; onClose: () => void }): JSX.Element`

- [ ] **Step 1: Write the failing test** `ui/src/auth/AuthDialog.test.tsx`

```tsx
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AuthDialog } from "./AuthDialog";

const anon = (over: Partial<{ signIn: unknown; signUp: unknown }> = {}) => ({
  status: "anon" as const,
  signIn: (over.signIn as never) ?? vi.fn().mockResolvedValue({ ok: true }),
  signUp: (over.signUp as never) ?? vi.fn().mockResolvedValue({ ok: true, needsConfirm: true }),
});

describe("AuthDialog", () => {
  it("signs in with entered credentials and closes on success", async () => {
    const signIn = vi.fn().mockResolvedValue({ ok: true });
    const onClose = vi.fn();
    render(<AuthDialog session={anon({ signIn })} onClose={onClose} />);
    await userEvent.type(screen.getByLabelText(/email/i), "a@b.com");
    await userEvent.type(screen.getByLabelText(/password/i), "secret");
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    expect(signIn).toHaveBeenCalledWith("a@b.com", "secret");
    expect(onClose).toHaveBeenCalled();
  });

  it("shows the sign-in error", async () => {
    const signIn = vi.fn().mockResolvedValue({ ok: false, error: "Invalid login credentials" });
    render(<AuthDialog session={anon({ signIn })} onClose={vi.fn()} />);
    await userEvent.type(screen.getByLabelText(/email/i), "a@b.com");
    await userEvent.type(screen.getByLabelText(/password/i), "bad");
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    expect(await screen.findByText(/invalid login credentials/i)).toBeInTheDocument();
  });

  it("toggles to sign-up and shows the confirm panel on needsConfirm", async () => {
    const signUp = vi.fn().mockResolvedValue({ ok: true, needsConfirm: true });
    render(<AuthDialog session={anon({ signUp })} onClose={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: /create one/i }));
    await userEvent.type(screen.getByLabelText(/email/i), "new@b.com");
    await userEvent.type(screen.getByLabelText(/password/i), "secret");
    await userEvent.click(screen.getByRole("button", { name: /create account/i }));
    expect(signUp).toHaveBeenCalledWith("new@b.com", "secret");
    expect(await screen.findByText(/check your email/i)).toBeInTheDocument();
    expect(screen.getByText(/new@b.com/)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run it, verify FAIL**

`npx vitest run src/auth/AuthDialog.test.tsx` → FAIL (cannot resolve ./AuthDialog).

- [ ] **Step 3: Implement** `ui/src/auth/AuthDialog.tsx`

```tsx
import { useState, type FormEvent } from "react";
import { X } from "lucide-react";
import { useDialogA11y } from "../lib/useDialogA11y";
import type { SessionState } from "./useSession";

type AnonSession = Extract<SessionState, { status: "anon" }>;

export function AuthDialog({ session, onClose }: { session: AnonSession; onClose: () => void }) {
  const { ref, onKeyDown } = useDialogA11y<HTMLDivElement>(onClose);
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmFor, setConfirmFor] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    if (mode === "signin") {
      const r = await session.signIn(email, password);
      if (!r.ok) setError(r.error ?? "Sign-in failed");
      else onClose();
    } else {
      const r = await session.signUp(email, password);
      if (!r.ok) setError(r.error ?? "Sign-up failed");
      else if (r.needsConfirm) setConfirmFor(email);
      else onClose();
    }
    setBusy(false);
  };

  const title = confirmFor ? "Check your email" : mode === "signin" ? "Sign in" : "Create account";
  const inputCls =
    "rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-[var(--color-text)] outline-none focus:border-[var(--color-accent)]";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4" onClick={onClose}>
      <div
        ref={ref}
        onKeyDown={onKeyDown}
        role="dialog"
        aria-modal="true"
        aria-label="Account"
        onClick={(e) => e.stopPropagation()}
        className="card w-full max-w-sm p-6 shadow-[var(--sh-float)]"
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 className="t-title text-[var(--color-text)]">{title}</h2>
          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className="rounded-[var(--r-tile)] p-1 text-[var(--color-text-faint)] hover:text-[var(--color-text)]"
          >
            <X size={16} aria-hidden />
          </button>
        </div>

        {confirmFor ? (
          <p className="text-sm text-[var(--color-text-dim)]">
            We sent a confirmation link to <span className="text-[var(--color-text)]">{confirmFor}</span>. Click it to
            finish, then sign in.
          </p>
        ) : (
          <form onSubmit={submit} className="flex flex-col gap-3">
            <label className="flex flex-col gap-1 text-sm">
              <span className="t-label text-[var(--color-text-dim)]">Email</span>
              <input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} className={inputCls} />
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="t-label text-[var(--color-text-dim)]">Password</span>
              <input
                type="password"
                autoComplete={mode === "signin" ? "current-password" : "new-password"}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className={inputCls}
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
              {busy ? "Working…" : mode === "signin" ? "Sign in" : "Create account"}
            </button>
            <button
              type="button"
              onClick={() => {
                setMode(mode === "signin" ? "signup" : "signin");
                setError(null);
              }}
              className="text-xs text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
            >
              {mode === "signin" ? "No account? Create one" : "Have an account? Sign in"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

export default AuthDialog;
```

- [ ] **Step 4: Run it (PASS) + typecheck**

`npx vitest run src/auth/AuthDialog.test.tsx` → PASS (3). `npx tsc -b` → exit 0.

- [ ] **Step 5: Commit**

```bash
git add ui/src/auth/AuthDialog.tsx ui/src/auth/AuthDialog.test.tsx
git commit -m "feat(auth): AuthDialog (signin/signup/confirm-pending)"
```

---

### Task 3: Account control (`AccountMenu`)

**Files:**
- Create: `ui/src/auth/AccountMenu.tsx`
- Test: `ui/src/auth/AccountMenu.test.tsx`

**Interfaces:**
- Consumes: `SessionState` from `./useSession`.
- Produces: `function AccountMenu({ session, onOpenAuth }: { session: SessionState; onOpenAuth: () => void }): JSX.Element | null`

- [ ] **Step 1: Write the failing test** `ui/src/auth/AccountMenu.test.tsx`

```tsx
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AccountMenu } from "./AccountMenu";

describe("AccountMenu", () => {
  it("anon shows Sign in and calls onOpenAuth", async () => {
    const onOpenAuth = vi.fn();
    render(<AccountMenu session={{ status: "anon", signIn: vi.fn(), signUp: vi.fn() }} onOpenAuth={onOpenAuth} />);
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(onOpenAuth).toHaveBeenCalled();
  });

  it("authed shows the email, plan, and signs out", async () => {
    const signOut = vi.fn().mockResolvedValue(undefined);
    render(
      <AccountMenu
        session={{ status: "authed", email: "a@b.com", profile: { email: "a@b.com", full_name: "A", plan: "pro" }, signOut }}
        onOpenAuth={vi.fn()}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: /account menu/i }));
    expect(screen.getByText("pro")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /sign out/i }));
    expect(signOut).toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run it, verify FAIL**

`npx vitest run src/auth/AccountMenu.test.tsx` → FAIL (cannot resolve ./AccountMenu).

- [ ] **Step 3: Implement** `ui/src/auth/AccountMenu.tsx`

```tsx
import { useEffect, useRef, useState } from "react";
import { ChevronDown, User } from "lucide-react";
import type { SessionState } from "./useSession";

export function AccountMenu({ session, onOpenAuth }: { session: SessionState; onOpenAuth: () => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  if (session.status === "loading") return null;

  if (session.status === "anon") {
    return (
      <button
        type="button"
        onClick={onOpenAuth}
        className="inline-flex items-center gap-1.5 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-transparent px-2.5 py-1.5 text-xs font-medium text-[var(--color-text-dim)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]"
      >
        <User size={14} aria-hidden />
        <span className="hidden sm:inline">Sign in</span>
      </button>
    );
  }

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        aria-label="Account menu"
        aria-haspopup="true"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="inline-flex items-center gap-1.5 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1.5 text-xs text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
      >
        <User size={14} aria-hidden />
        <span className="hidden max-w-[10rem] truncate sm:inline">{session.email}</span>
        <ChevronDown size={13} aria-hidden />
      </button>
      {open && (
        <div className="absolute right-0 z-40 mt-1 w-52 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-2 shadow-[var(--sh-float)]">
          <div className="truncate px-1 pb-1 text-xs text-[var(--color-text-dim)]">{session.email}</div>
          <div className="px-1 pb-2">
            <span className="inline-flex items-center rounded-[var(--r-chip)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-1.5 py-0.5 t-tag uppercase text-[var(--color-text-dim)]">
              {session.profile.plan}
            </span>
          </div>
          <button
            type="button"
            onClick={() => void session.signOut()}
            className="w-full rounded-[var(--r-micro)] px-2 py-1.5 text-left text-sm text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]"
          >
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}

export default AccountMenu;
```

- [ ] **Step 4: Run it (PASS) + typecheck**

`npx vitest run src/auth/AccountMenu.test.tsx` → PASS (2). `npx tsc -b` → exit 0.

- [ ] **Step 5: Commit**

```bash
git add ui/src/auth/AccountMenu.tsx ui/src/auth/AccountMenu.test.tsx
git commit -m "feat(auth): AccountMenu (sign-in button / authed popover)"
```

---

### Task 4: Wire into the shell + App + full verification

**Files:**
- Modify: `ui/src/cockpit/CommandBar.tsx` (add `accountMenu` slot)
- Modify: `ui/src/components/layout/AppShell.tsx` (thread `accountMenu`)
- Modify: `ui/src/App.tsx` (session + AuthDialog + render AccountMenu)
- Modify: `ui/src/cockpit/CommandBar.test.tsx` (if present — assert the slot renders) — otherwise add coverage via AppShell

**Interfaces:**
- Consumes: `useSession`, `AuthDialog`, `AccountMenu`.
- Produces: a visible account control in the `/app` shell + an openable auth modal.

- [ ] **Step 1: Add the `accountMenu` slot to `ui/src/cockpit/CommandBar.tsx`**

In the props type, add (next to `rulesMenu?: ReactNode;`):
```tsx
  /** Slot for the end-user account control (Sign in / account popover). */
  accountMenu?: ReactNode;
```
Add `accountMenu` to the destructured params. Render it in the right action cluster as an **always-visible** item (not behind `md:`) — place it immediately before `<ThemeToggle />`:
```tsx
        {accountMenu}
        <span className="hidden md:contents"><DensityToggle /></span>
        <ThemeToggle />
```

- [ ] **Step 2: Thread it through `ui/src/components/layout/AppShell.tsx`**

Add to `AppShellProps`:
```tsx
  /** End-user account control rendered in the command bar. */
  accountMenu?: ReactNode;
```
Destructure `accountMenu` in the component params, and pass it to `<CommandBar ... accountMenu={accountMenu} />`.

- [ ] **Step 3: Wire `ui/src/App.tsx`**

Add imports:
```tsx
import { useSession } from "./auth/useSession";
import { AuthDialog } from "./auth/AuthDialog";
import { AccountMenu } from "./auth/AccountMenu";
```
Inside `App()`, near the other hooks/state:
```tsx
  const session = useSession();
  const [authOpen, setAuthOpen] = useState(false);
```
Pass the slot to `<AppShell ...>` (add the prop alongside the existing ones, e.g. near `rulesMenu={...}`):
```tsx
      accountMenu={<AccountMenu session={session} onOpenAuth={() => setAuthOpen(true)} />}
```
Render the dialog alongside the other modals (e.g. after `{settingsOpen && <SettingsDialog … />}`):
```tsx
    {authOpen && session.status === "anon" && (
      <AuthDialog session={session} onClose={() => setAuthOpen(false)} />
    )}
```

- [ ] **Step 4: Verify the suite, types, build, coverage**

From `ui/`:
- `npx tsc -b` → exit 0.
- `npx vitest run src/auth` → all auth tests pass.
- `npx vitest run src/App.test.tsx src/components/layout` → the App + shell tests still pass. If `App.test.tsx` fails because `useSession` instantiates the real Supabase client under the test env, add a module mock at the top of `App.test.tsx`: `vi.mock("./auth/useSession", () => ({ useSession: () => ({ status: "anon", signIn: vi.fn(), signUp: vi.fn() }) }));` (the AccountMenu then renders the Sign-in button with no network). Re-run.
- `npm run build` → tsc + vite succeed.
- `npm run test:coverage` → full suite green; coverage ≥ 80/70. Report the "All files" line.

- [ ] **Step 5: Commit**

```bash
git add ui/src/cockpit/CommandBar.tsx ui/src/components/layout/AppShell.tsx ui/src/App.tsx ui/src/cockpit/CommandBar.test.tsx ui/src/App.test.tsx
git commit -m "feat(auth): surface the account menu + auth modal in the /app shell"
```
(Stage only the test files you actually changed.)

---

### Task 5: Browser smoke test (controller)

**Files:** none (operational).

- [ ] **Step 1: Verify the authed path in a real browser**

With the dev server running, navigate to `/app`. The CommandBar shows a "Sign in" control. Open it, sign in with the existing confirmed demo account `demo+alice@packetpilot.test` / `DemoPass!23`. Confirm: the dialog closes, the account control now shows the email + a **pro** plan chip; reload preserves the authed state (session persisted); "Sign out" returns to the anonymous "Sign in" control; and core analysis (load the sample capture) still works while both signed-out and signed-in. Check `preview_console_logs` (errors) + `preview_network` (failed) are clean. Capture a snapshot as proof.

- [ ] **Step 2: No commit** (operational).

---

## Self-Review

**1. Spec coverage:**
- `useSession` (loading/anon/authed, signIn/signUp/signOut, emailRedirectTo, needsConfirm, re-derive, best-effort profile, unconfigured→anon) → Task 1. ✅
- `AuthDialog` (signin/signup/confirm-pending, errors, a11y via useDialogA11y) → Task 2. ✅
- `AccountMenu` (anon Sign in / authed email+plan+Sign out, plain popover, always-visible) → Task 3. ✅
- Wiring (CommandBar slot, AppShell thread, App session+dialog+menu) → Task 4. ✅
- Privacy/additive (no gating; analysis untouched; anonymous works) → enforced by design (no gating code) + Task 5 verifies anonymous + authed both analyze. ✅
- No migration / `/admin` untouched / no new deps → Global Constraints + file scope. ✅
- Email-confirm redirect (`emailRedirectTo` /app; supabase-js detectSessionInUrl default) → Task 1 signUp option; client unchanged (Phase 0). Supabase dashboard allowlist is the flagged ops note (not a code task). ✅
- Browser smoke via confirmed demo account → Task 5. ✅

**2. Placeholder scan:** No "TBD/handle errors/similar to Task N". The App.test mock is a concrete, conditional contingency with exact code. All code steps are complete.

**3. Type consistency:** `SessionState`/`UserProfile` defined in Task 1 and consumed unchanged in Tasks 2–4. `AuthDialog({session: anon variant, onClose})` and `AccountMenu({session, onOpenAuth})` signatures match their App call sites (Task 4). `accountMenu?: ReactNode` consistent across CommandBar + AppShell. `signUp` return `{ ok, needsConfirm?, error? }` consistent between hook (Task 1), dialog use (Task 2), and test.

## Execution Handoff

(See message.)
