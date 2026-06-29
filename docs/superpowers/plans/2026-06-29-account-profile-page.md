# Account / Profile Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a standalone `/account` page where a signed-in user manages identity (avatar, name, email, role, member-since), security (password, email, sign-out-everywhere, delete account), plan & billing (real subscription detail + Stripe actions), and preferences (theme, density).

**Architecture:** A lazy-loaded `/account` route mirroring `/admin` (`resolveRoute` → `main.tsx` branch → `vercel.json` rewrite). `AccountApp` is a gated shell; `AccountPage` composes four `.card` sections fed by a `useAccount()` hook (reads the caller's own `profiles` + `subscriptions` rows; email from `auth.getUser()`) and an `api.ts` mutation module. Backend adds migration `0016` (avatars Storage bucket + RLS + email-sync trigger) and a `delete-account` Edge Function. The privileged-column guard already exists — no guard work.

**Tech Stack:** React + design tokens + `lucide-react`; `@supabase/supabase-js` (auth, PostgREST, Storage, `functions.invoke`); existing `ThemeToggle`/`DensityToggle`/`useDialogA11y`/`billing.ts`/state primitives; Deno Edge Function; Vitest + RTL.

## Global Constraints

- **Privacy invariant:** the page touches only account + subscription data — never capture data. `/app` stays fully functional anonymously/offline. (verbatim spec)
- **Secrets never in the SPA:** deletion + Stripe-cancel run server-side in the Edge Function (service-role + `STRIPE_SECRET_KEY`); the browser never sees a secret.
- **Privilege guard intact:** self-service writes touch only `full_name`/`avatar_url`; never `plan`/`role`/`status`.
- **No engine/WASM/Tauri change. No admin change. No new SPA deps.**
- **Styling:** design tokens only (`var(--color-…)`, `.card`, `t-*` type classes) — no raw hex, no `text-white`; white-on-accent uses `--color-on-accent`.
- **Gate before merge:** Vitest suite green, coverage ≥ 80/70, `npx tsc -b` + `npm run build` clean, Playwright e2e + axe AA green. Run vitest/tsc **from inside `ui/`**.
- All `api.ts` functions return `{ ok: boolean; error?: string }` and short-circuit `if (!supabase) return { ok:false, error:"Accounts are unavailable" }`.

---

### Task 1: `/account` route resolution

**Files:**
- Modify: `ui/src/lib/route.ts`
- Test: `ui/src/lib/route.test.ts`

**Interfaces:**
- Produces: `Route` union gains `"account"`; `resolveRoute("/account") === "account"`.

- [ ] **Step 1: Add failing tests** in `ui/src/lib/route.test.ts` (create if absent; if present, append):

```ts
import { describe, it, expect } from "vitest";
import { resolveRoute } from "./route";

describe("resolveRoute", () => {
  it("maps /account and subpaths to account", () => {
    expect(resolveRoute("/account")).toBe("account");
    expect(resolveRoute("/account/")).toBe("account");
    expect(resolveRoute("/account/billing")).toBe("account");
  });
  it("does not confuse /accounts or /app/account-ish paths", () => {
    expect(resolveRoute("/accounts")).toBe("landing");
    expect(resolveRoute("/app")).toBe("app");
    expect(resolveRoute("/admin")).toBe("admin");
    expect(resolveRoute("/")).toBe("landing");
  });
});
```

- [ ] **Step 2: Run, expect FAIL** — `cd ui; npx vitest run src/lib/route.test.ts` → fails (`account` not returned / type error).
- [ ] **Step 3: Implement** in `ui/src/lib/route.ts`:

```ts
export type Route = "landing" | "app" | "admin" | "account";

/** Minimal pathname routing shared by main.tsx. Trailing slashes are ignored. */
export function resolveRoute(pathname: string): Route {
  const path = pathname.replace(/\/+$/, "");
  if (path === "/admin" || path.startsWith("/admin/")) return "admin";
  if (path === "/account" || path.startsWith("/account/")) return "account";
  if (path === "/app" || path.startsWith("/app/")) return "app";
  return "landing";
}
```

- [ ] **Step 4: Run, expect PASS** — `npx vitest run src/lib/route.test.ts`.
- [ ] **Step 5: Commit** — `git add ui/src/lib/route.ts ui/src/lib/route.test.ts && git commit -m "feat(account): resolve /account route"`

---

### Task 2: Account mutation API (`api.ts`)

**Files:**
- Create: `ui/src/account/api.ts`
- Test: `ui/src/account/api.test.ts`

**Interfaces:**
- Produces: `updateName(uid, fullName)`, `uploadAvatar(uid, file)` → `{ok,error?,url?}`, `removeAvatar(uid)`, `changePassword(email, current, next)`, `changeEmail(next)`, `signOutEverywhere()`, `deleteAccount()` — all `Promise<{ ok: boolean; error?: string }>` (uploadAvatar also `url?`).
- Consumes: `supabase` from `../lib/supabase`.

- [ ] **Step 1: Write failing tests** `ui/src/account/api.test.ts` — mock `../lib/supabase`. Cover: `updateName` calls `profiles.update({full_name}).eq("id",uid)` and maps error; `uploadAvatar` rejects bad type and >2MB before any upload, else uploads + sets `avatar_url` + returns url; `changePassword` re-auths then `updateUser`, and returns "Current password is incorrect" when re-auth fails; `changeEmail` calls `updateUser({email})`; `signOutEverywhere` calls `signOut({scope:"global"})`; `deleteAccount` invokes `delete-account` and surfaces the function's JSON body via `error.context.json()`.

```ts
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const sb = {
  from: vi.fn(),
  auth: { signInWithPassword: vi.fn(), updateUser: vi.fn(), signOut: vi.fn() },
  storage: { from: vi.fn() },
  functions: { invoke: vi.fn() },
};
vi.mock("../lib/supabase", () => ({ supabase: sb }));
import * as api from "./api";

const upd = vi.fn();
beforeEach(() => {
  upd.mockResolvedValue({ error: null });
  sb.from.mockReturnValue({ update: (v: unknown) => ({ eq: (_c: string, _id: string) => upd(v) }) });
  sb.auth.signInWithPassword.mockResolvedValue({ error: null });
  sb.auth.updateUser.mockResolvedValue({ error: null });
  sb.auth.signOut.mockResolvedValue({ error: null });
  sb.functions.invoke.mockResolvedValue({ data: { ok: true }, error: null });
  sb.storage.from.mockReturnValue({
    upload: vi.fn().mockResolvedValue({ error: null }),
    getPublicUrl: vi.fn().mockReturnValue({ data: { publicUrl: "https://cdn/x.png" } }),
  });
});
afterEach(() => vi.clearAllMocks());

describe("account api", () => {
  it("updateName updates full_name", async () => {
    expect(await api.updateName("u1", "  Ada  ")).toEqual({ ok: true });
    expect(upd).toHaveBeenCalledWith({ full_name: "Ada" });
  });
  it("uploadAvatar rejects wrong type before uploading", async () => {
    const f = new File(["x"], "a.gif", { type: "image/gif" });
    const r = await api.uploadAvatar("u1", f);
    expect(r.ok).toBe(false);
    expect(sb.storage.from).not.toHaveBeenCalled();
  });
  it("uploadAvatar stores + sets avatar_url", async () => {
    const f = new File(["x"], "a.png", { type: "image/png" });
    const r = await api.uploadAvatar("u1", f);
    expect(r).toMatchObject({ ok: true, url: "https://cdn/x.png" });
    expect(upd).toHaveBeenCalledWith({ avatar_url: "https://cdn/x.png" });
  });
  it("changePassword fails fast on bad current password", async () => {
    sb.auth.signInWithPassword.mockResolvedValue({ error: { message: "bad" } });
    const r = await api.changePassword("a@b.c", "wrong", "longenough1");
    expect(r).toEqual({ ok: false, error: "Current password is incorrect" });
    expect(sb.auth.updateUser).not.toHaveBeenCalled();
  });
  it("signOutEverywhere uses global scope", async () => {
    await api.signOutEverywhere();
    expect(sb.auth.signOut).toHaveBeenCalledWith({ scope: "global" });
  });
  it("deleteAccount surfaces the function error body", async () => {
    sb.functions.invoke.mockResolvedValue({
      data: null,
      error: { message: "non-2xx", context: { json: async () => ({ error: "Active subscription" }) } },
    });
    expect(await api.deleteAccount()).toEqual({ ok: false, error: "Active subscription" });
  });
});
```

- [ ] **Step 2: Run, expect FAIL** — `npx vitest run src/account/api.test.ts`.
- [ ] **Step 3: Implement** `ui/src/account/api.ts`:

```ts
import { supabase } from "../lib/supabase";

type Result = { ok: boolean; error?: string };
const NO_BACKEND: Result = { ok: false, error: "Accounts are unavailable" };

const AVATAR_TYPES = ["image/png", "image/jpeg", "image/webp"];
const AVATAR_MAX_BYTES = 2 * 1024 * 1024;

/** Read a failed invoke's real `{error}` body (mirrors auth/billing.ts). */
async function invokeErr(error: { message?: string; context?: unknown } | null): Promise<string> {
  const fallback = error?.message ?? "Something went wrong";
  const ctx = error?.context as { json?: () => Promise<unknown> } | undefined;
  if (!ctx || typeof ctx.json !== "function") return fallback;
  try {
    const body = (await ctx.json()) as { error?: string } | null;
    return body?.error?.trim() || fallback;
  } catch {
    return fallback;
  }
}

export async function updateName(uid: string, fullName: string): Promise<Result> {
  if (!supabase) return NO_BACKEND;
  const name = fullName.trim();
  const { error } = await supabase.from("profiles").update({ full_name: name || null }).eq("id", uid);
  return error ? { ok: false, error: error.message } : { ok: true };
}

export async function uploadAvatar(uid: string, file: File): Promise<Result & { url?: string }> {
  if (!supabase) return NO_BACKEND;
  if (!AVATAR_TYPES.includes(file.type)) return { ok: false, error: "Use a PNG, JPEG, or WebP image" };
  if (file.size > AVATAR_MAX_BYTES) return { ok: false, error: "Image must be 2 MB or smaller" };
  const ext = file.type === "image/png" ? "png" : file.type === "image/webp" ? "webp" : "jpg";
  const path = `${uid}/avatar-${Date.now()}.${ext}`;
  const up = await supabase.storage.from("avatars").upload(path, file, { upsert: true, contentType: file.type });
  if (up.error) return { ok: false, error: up.error.message };
  const url = supabase.storage.from("avatars").getPublicUrl(path).data.publicUrl;
  const { error } = await supabase.from("profiles").update({ avatar_url: url }).eq("id", uid);
  return error ? { ok: false, error: error.message } : { ok: true, url };
}

export async function removeAvatar(uid: string): Promise<Result> {
  if (!supabase) return NO_BACKEND;
  const { error } = await supabase.from("profiles").update({ avatar_url: null }).eq("id", uid);
  return error ? { ok: false, error: error.message } : { ok: true };
}

export async function changePassword(email: string, current: string, next: string): Promise<Result> {
  if (!supabase) return NO_BACKEND;
  if (next.length < 8) return { ok: false, error: "Password must be at least 8 characters" };
  const reauth = await supabase.auth.signInWithPassword({ email, password: current });
  if (reauth.error) return { ok: false, error: "Current password is incorrect" };
  const { error } = await supabase.auth.updateUser({ password: next });
  return error ? { ok: false, error: error.message } : { ok: true };
}

export async function changeEmail(next: string): Promise<Result> {
  if (!supabase) return NO_BACKEND;
  const { error } = await supabase.auth.updateUser({ email: next.trim() });
  return error ? { ok: false, error: error.message } : { ok: true };
}

export async function signOutEverywhere(): Promise<Result> {
  if (!supabase) return NO_BACKEND;
  const { error } = await supabase.auth.signOut({ scope: "global" });
  return error ? { ok: false, error: error.message } : { ok: true };
}

export async function deleteAccount(): Promise<Result> {
  if (!supabase) return NO_BACKEND;
  const { error } = await supabase.functions.invoke("delete-account");
  if (error) return { ok: false, error: await invokeErr(error) };
  return { ok: true };
}
```

- [ ] **Step 4: Run, expect PASS**.
- [ ] **Step 5: Commit** — `git add ui/src/account/api.ts ui/src/account/api.test.ts && git commit -m "feat(account): mutation api (name/avatar/password/email/signout/delete)"`

---

### Task 3: `useAccount` data hook

**Files:**
- Create: `ui/src/account/useAccount.ts`
- Test: `ui/src/account/useAccount.test.tsx`

**Interfaces:**
- Produces: `AccountProfile { id,email,full_name,avatar_url,role,created_at }`, `AccountSubscription { status,price_id,amount_cents,currency,current_period_end,cancel_at_period_end,stripe_customer_id }`, `AccountState` (loading|error|ready), `useAccount(): { state, reload }`. Email is taken from `auth.getUser()`.

- [ ] **Step 1: Write failing test** `useAccount.test.tsx` — mock `../lib/supabase` with `auth.getUser` → `{user:{id:"u1",email:"new@x.com"}}`, a chained `from(...).select(...).eq(...).single()` returning a profile, and the subscriptions chain `.order().limit().maybeSingle()`. Assert: ends `ready`, `profile.email === "new@x.com"` (auth email wins), `subscription` populated; profile error → `error`.

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

const sb: any = { auth: { getUser: vi.fn() }, from: vi.fn() };
vi.mock("../lib/supabase", () => ({ supabase: sb }));
import { useAccount } from "./useAccount";

beforeEach(() => {
  sb.auth.getUser.mockResolvedValue({ data: { user: { id: "u1", email: "new@x.com" } } });
  sb.from.mockImplementation((t: string) => {
    if (t === "profiles") return { select: () => ({ eq: () => ({ single: () =>
      Promise.resolve({ data: { id: "u1", email: "old@x.com", full_name: "Ada", avatar_url: null, role: "user", created_at: "2026-01-01" }, error: null }) }) }) };
    return { select: () => ({ eq: () => ({ order: () => ({ limit: () => ({ maybeSingle: () =>
      Promise.resolve({ data: { status: "active", price_id: "p", amount_cents: 1900, currency: "usd", current_period_end: "2026-07-01", cancel_at_period_end: false, stripe_customer_id: "cus_1" }, error: null }) }) }) }) }) };
  });
});

describe("useAccount", () => {
  it("loads profile (auth email) + subscription", async () => {
    const { result } = renderHook(() => useAccount());
    await waitFor(() => expect(result.current.state.status).toBe("ready"));
    const s = result.current.state as Extract<typeof result.current.state, { status: "ready" }>;
    expect(s.profile.email).toBe("new@x.com");
    expect(s.subscription?.status).toBe("active");
  });
});
```

- [ ] **Step 2: Run, expect FAIL**.
- [ ] **Step 3: Implement** `ui/src/account/useAccount.ts`:

```ts
import { useCallback, useEffect, useState } from "react";
import { supabase } from "../lib/supabase";

export interface AccountProfile {
  id: string; email: string; full_name: string | null;
  avatar_url: string | null; role: string; created_at: string;
}
export interface AccountSubscription {
  status: string; price_id: string | null; amount_cents: number | null;
  currency: string; current_period_end: string | null;
  cancel_at_period_end: boolean; stripe_customer_id: string | null;
}
export type AccountState =
  | { status: "loading" }
  | { status: "error"; error: string }
  | { status: "ready"; profile: AccountProfile; subscription: AccountSubscription | null };

export function useAccount(): { state: AccountState; reload: () => void } {
  const [state, setState] = useState<AccountState>({ status: "loading" });
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    if (!supabase) { setState({ status: "error", error: "Accounts are unavailable" }); return; }
    const client = supabase;
    let cancelled = false;
    setState({ status: "loading" });
    void (async () => {
      const { data: u } = await client.auth.getUser();
      const user = u.user;
      if (cancelled) return;
      if (!user) { setState({ status: "error", error: "You're not signed in" }); return; }
      const prof = await client.from("profiles")
        .select("id,email,full_name,avatar_url,role,created_at").eq("id", user.id).single();
      if (cancelled) return;
      if (prof.error || !prof.data) {
        setState({ status: "error", error: prof.error?.message ?? "Couldn't load your profile" }); return;
      }
      const sub = await client.from("subscriptions")
        .select("status,price_id,amount_cents,currency,current_period_end,cancel_at_period_end,stripe_customer_id")
        .eq("user_id", user.id).order("created_at", { ascending: false }).limit(1).maybeSingle();
      if (cancelled) return;
      const profile = { ...(prof.data as AccountProfile), email: user.email ?? (prof.data as AccountProfile).email };
      setState({ status: "ready", profile, subscription: (sub.data as AccountSubscription | null) ?? null });
    })();
    return () => { cancelled = true; };
  }, [tick]);

  return { state, reload };
}
```

- [ ] **Step 4: Run, expect PASS**.
- [ ] **Step 5: Commit** — `git commit -am "feat(account): useAccount hook (own profile + subscription)"`

---

### Task 4: `PreferencesSection`

**Files:**
- Create: `ui/src/account/sections/PreferencesSection.tsx`
- Test: `ui/src/account/sections/PreferencesSection.test.tsx`

**Interfaces:** Produces `<PreferencesSection />` (no props) rendering labeled Theme + Density rows.

- [ ] **Step 1: Failing test** — renders a "Preferences" heading, a Theme row containing the existing theme toggle (`aria-label` matching `/theme/i`), and a Density row.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement:**

```tsx
import { ThemeToggle } from "../../cockpit/ThemeToggle";
import { DensityToggle } from "../../cockpit/DensityToggle";
import { Card, Row } from "./ui";

export function PreferencesSection() {
  return (
    <Card title="Preferences" desc="How PacketPilot looks on this device. Saved in your browser.">
      <Row label="Theme" hint="Light or dark appearance."><ThemeToggle /></Row>
      <Row label="Density" hint="Comfortable or compact spacing."><DensityToggle /></Row>
    </Card>
  );
}
export default PreferencesSection;
```

- [ ] **Step 3b: Create the shared section primitives** `ui/src/account/sections/ui.tsx` (used by every section — DRY):

```tsx
import type { ReactNode } from "react";

export function Card({ title, desc, children }: { title: string; desc?: string; children: ReactNode }) {
  return (
    <section className="card p-5">
      <header className="mb-4">
        <h2 className="t-title text-[var(--color-text)]">{title}</h2>
        {desc && <p className="mt-0.5 text-sm text-[var(--color-text-dim)]">{desc}</p>}
      </header>
      <div className="flex flex-col gap-4">{children}</div>
    </section>
  );
}

export function Row({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <div className="min-w-0">
        <div className="text-sm font-medium text-[var(--color-text)]">{label}</div>
        {hint && <div className="t-tag text-[var(--color-text-dim)]">{hint}</div>}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

export const fieldCls =
  "rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-accent)]";
export const btnCls =
  "inline-flex items-center justify-center rounded-[var(--r-tile)] bg-[var(--color-accent-deep)] px-3 py-1.5 text-sm font-medium text-[var(--color-on-accent)] disabled:opacity-60";
export const btnGhost =
  "inline-flex items-center justify-center rounded-[var(--r-tile)] border border-[var(--color-border)] bg-transparent px-3 py-1.5 text-sm text-[var(--color-text-dim)] hover:text-[var(--color-text)] disabled:opacity-60";
```

- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** — `git add ui/src/account/sections/PreferencesSection.tsx ui/src/account/sections/PreferencesSection.test.tsx ui/src/account/sections/ui.tsx && git commit -m "feat(account): Preferences section + shared section primitives"`

---

### Task 5: `BillingSection`

**Files:**
- Create: `ui/src/account/sections/BillingSection.tsx`
- Test: `ui/src/account/sections/BillingSection.test.tsx`

**Interfaces:** Consumes `AccountSubscription` (Task 3) + `startCheckout`/`openPortal` (`../../auth/billing`). Props: `{ plan: string; subscription: AccountSubscription | null }`.

- [ ] **Step 1: Failing test** — mock `../../auth/billing`. (a) `plan="pro"` + active subscription → shows status "active", formatted price "$19.00", a renewal date, and a "Manage billing" button that calls `openPortal`. (b) `plan="free"`, `subscription=null` → "Upgrade to Pro" calls `startCheckout`. (c) invoke returns `{ok:false,error:"No billing account yet"}` → message rendered in an alert.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement:**

```tsx
import { useState } from "react";
import { startCheckout, openPortal } from "../../auth/billing";
import type { AccountSubscription } from "../useAccount";
import { Card, btnCls, btnGhost } from "./ui";

const money = (cents: number | null, currency: string) =>
  cents == null ? "—" : new Intl.NumberFormat(undefined, { style: "currency", currency: currency.toUpperCase() }).format(cents / 100);
const day = (iso: string | null) => (iso ? new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : null);

export function BillingSection({ plan, subscription }: { plan: string; subscription: AccountSubscription | null }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isPro = plan === "pro";

  const run = async (fn: () => Promise<{ ok: boolean; error?: string }>) => {
    if (busy) return;
    setBusy(true); setError(null);
    const r = await fn();
    if (!r?.ok) { setError(r?.error ?? "Something went wrong"); setBusy(false); }
  };

  return (
    <Card title="Plan & billing" desc="Your subscription and payment details.">
      <div className="flex items-center gap-2">
        <span className="inline-flex items-center rounded-[var(--r-chip)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-0.5 t-tag uppercase text-[var(--color-text)]">
          {plan}
        </span>
        {subscription && (
          <span className="t-tag text-[var(--color-text-dim)]">· {subscription.status}</span>
        )}
      </div>

      {subscription ? (
        <dl className="grid grid-cols-2 gap-y-2 text-sm">
          <dt className="text-[var(--color-text-dim)]">Price</dt>
          <dd className="text-[var(--color-text)]">{money(subscription.amount_cents, subscription.currency)}/mo</dd>
          {subscription.current_period_end && (
            <>
              <dt className="text-[var(--color-text-dim)]">{subscription.cancel_at_period_end ? "Cancels on" : "Renews on"}</dt>
              <dd className="text-[var(--color-text)]">{day(subscription.current_period_end)}</dd>
            </>
          )}
        </dl>
      ) : (
        <p className="text-sm text-[var(--color-text-dim)]">
          {isPro ? "Pro access is active on your account." : "You're on the Free plan."}
        </p>
      )}

      <div className="flex items-center gap-2">
        {isPro ? (
          <button type="button" disabled={busy} onClick={() => void run(openPortal)} className={btnGhost}>
            {busy ? "Opening…" : "Manage billing"}
          </button>
        ) : (
          <button type="button" disabled={busy} onClick={() => void run(startCheckout)} className={btnCls}>
            {busy ? "Starting…" : "Upgrade to Pro"}
          </button>
        )}
      </div>
      {error && <p role="alert" className="t-tag text-[var(--color-sev-critical)]">{error}</p>}
    </Card>
  );
}
export default BillingSection;
```

- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** — `git commit -am "feat(account): Plan & billing section"`

---

### Task 6: `AccountSection` (avatar + name + identity)

**Files:**
- Create: `ui/src/account/sections/AccountSection.tsx`
- Test: `ui/src/account/sections/AccountSection.test.tsx`

**Interfaces:** Consumes `AccountProfile` (Task 3) + `updateName`/`uploadAvatar`/`removeAvatar` (Task 2). Props: `{ profile: AccountProfile; onChanged: () => void }`.

- [ ] **Step 1: Failing test** — mock `../api`. Renders email (read-only), role badge, "Member since" with the year, and the display name. Clicking "Edit" reveals an input; Save calls `updateName(profile.id, value)` then `onChanged`. Selecting a file in the avatar input calls `uploadAvatar` then `onChanged`.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement:**

```tsx
import { useRef, useState } from "react";
import { User as UserIcon, Pencil } from "lucide-react";
import type { AccountProfile } from "../useAccount";
import { updateName, uploadAvatar, removeAvatar } from "../api";
import { Card, Row, fieldCls, btnCls, btnGhost } from "./ui";

const memberSince = (iso: string) => new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "long" });

export function AccountSection({ profile, onChanged }: { profile: AccountProfile; onChanged: () => void }) {
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(profile.full_name ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const saveName = async () => {
    setBusy(true); setError(null);
    const r = await updateName(profile.id, name);
    setBusy(false);
    if (!r.ok) { setError(r.error ?? "Couldn't save"); return; }
    setEditing(false); onChanged();
  };

  const onPickAvatar = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setBusy(true); setError(null);
    const r = await uploadAvatar(profile.id, file);
    setBusy(false);
    if (!r.ok) { setError(r.error ?? "Upload failed"); return; }
    onChanged();
  };

  const onRemoveAvatar = async () => {
    setBusy(true); setError(null);
    const r = await removeAvatar(profile.id);
    setBusy(false);
    if (!r.ok) { setError(r.error ?? "Couldn't remove"); return; }
    onChanged();
  };

  return (
    <Card title="Account" desc="Your identity across PacketPilot.">
      <div className="flex items-center gap-4">
        <div className="flex h-16 w-16 items-center justify-center overflow-hidden rounded-full border border-[var(--color-border)] bg-[var(--color-surface-2)]">
          {profile.avatar_url ? (
            <img src={profile.avatar_url} alt="Your avatar" className="h-full w-full object-cover" />
          ) : (
            <UserIcon size={28} className="text-[var(--color-text-faint)]" aria-hidden />
          )}
        </div>
        <div className="flex flex-col gap-1.5">
          <input ref={fileRef} type="file" accept="image/png,image/jpeg,image/webp" onChange={onPickAvatar} className="hidden" aria-label="Upload avatar" />
          <div className="flex gap-2">
            <button type="button" disabled={busy} onClick={() => fileRef.current?.click()} className={btnGhost}>Change</button>
            {profile.avatar_url && <button type="button" disabled={busy} onClick={() => void onRemoveAvatar()} className={btnGhost}>Remove</button>}
          </div>
          <span className="t-tag text-[var(--color-text-dim)]">PNG, JPEG or WebP, up to 2 MB.</span>
        </div>
      </div>

      <Row label="Display name" hint="Shown in the app and to admins.">
        {editing ? (
          <span className="flex items-center gap-2">
            <input value={name} onChange={(e) => setName(e.target.value)} className={fieldCls} aria-label="Display name" />
            <button type="button" disabled={busy} onClick={() => void saveName()} className={btnCls}>{busy ? "Saving…" : "Save"}</button>
            <button type="button" onClick={() => { setEditing(false); setName(profile.full_name ?? ""); }} className={btnGhost}>Cancel</button>
          </span>
        ) : (
          <span className="flex items-center gap-2">
            <span className="text-sm text-[var(--color-text)]">{profile.full_name || "—"}</span>
            <button type="button" aria-label="Edit display name" onClick={() => setEditing(true)} className="rounded-[var(--r-tile)] p-1 text-[var(--color-text-faint)] hover:text-[var(--color-text)]">
              <Pencil size={14} aria-hidden />
            </button>
          </span>
        )}
      </Row>

      <Row label="Email" hint="Change it in Security below."><span className="text-sm text-[var(--color-text)]">{profile.email}</span></Row>
      <Row label="Role"><span className="inline-flex items-center rounded-[var(--r-chip)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-0.5 t-tag uppercase text-[var(--color-text-dim)]">{profile.role}</span></Row>
      <Row label="Member since"><span className="text-sm text-[var(--color-text-dim)]">{memberSince(profile.created_at)}</span></Row>
      {error && <p role="alert" className="t-tag text-[var(--color-sev-critical)]">{error}</p>}
    </Card>
  );
}
export default AccountSection;
```

- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** — `git commit -am "feat(account): Account section (avatar + name + identity)"`

---

### Task 7: `SecuritySection`

**Files:**
- Create: `ui/src/account/sections/SecuritySection.tsx`
- Test: `ui/src/account/sections/SecuritySection.test.tsx`

**Interfaces:** Consumes `changePassword`/`changeEmail`/`signOutEverywhere`/`deleteAccount` (Task 2). Props: `{ email: string }`. Uses `window.location.assign` for post-delete/sign-out redirects.

- [ ] **Step 1: Failing test** — mock `../api` + stub `window.location.assign`. Password form: submitting calls `changePassword(email, current, next)`; a success note appears. Email form: calls `changeEmail`, shows "check your email". "Sign out of all devices" calls `signOutEverywhere` then redirects to `/app`. Delete: the confirm button is disabled until the typed value equals `email`; once matched and clicked, `deleteAccount` runs and on success redirects to `/`.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** (three collapsible mini-forms + a danger zone). Full code:

```tsx
import { useState, type FormEvent } from "react";
import { changePassword, changeEmail, signOutEverywhere, deleteAccount } from "../api";
import { Card, fieldCls, btnCls, btnGhost } from "./ui";

export function SecuritySection({ email }: { email: string }) {
  return (
    <Card title="Security" desc="Manage how you sign in — and leave.">
      <PasswordForm email={email} />
      <EmailForm />
      <SignOutAll />
      <DangerZone email={email} />
    </Card>
  );
}

function note(msg: string) {
  return <p className="t-tag text-[var(--color-accent)]">{msg}</p>;
}
function err(msg: string) {
  return <p role="alert" className="t-tag text-[var(--color-sev-critical)]">{msg}</p>;
}

function PasswordForm({ email }: { email: string }) {
  const [cur, setCur] = useState(""); const [next, setNext] = useState(""); const [conf, setConf] = useState("");
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null); const [done, setDone] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); if (busy) return;
    if (next !== conf) { setError("New passwords don't match"); return; }
    setBusy(true); setError(null); setDone(false);
    const r = await changePassword(email, cur, next); setBusy(false);
    if (!r.ok) { setError(r.error ?? "Couldn't change password"); return; }
    setDone(true); setCur(""); setNext(""); setConf("");
  };
  return (
    <form onSubmit={submit} className="flex flex-col gap-2">
      <div className="text-sm font-medium text-[var(--color-text)]">Change password</div>
      <input type="password" autoComplete="current-password" placeholder="Current password" value={cur} onChange={(e) => setCur(e.target.value)} className={fieldCls} aria-label="Current password" required />
      <input type="password" autoComplete="new-password" placeholder="New password" value={next} onChange={(e) => setNext(e.target.value)} className={fieldCls} aria-label="New password" required />
      <input type="password" autoComplete="new-password" placeholder="Confirm new password" value={conf} onChange={(e) => setConf(e.target.value)} className={fieldCls} aria-label="Confirm new password" required />
      <div><button type="submit" disabled={busy} className={btnCls}>{busy ? "Saving…" : "Update password"}</button></div>
      {error && err(error)}
      {done && note("Password updated.")}
    </form>
  );
}

function EmailForm() {
  const [email, setEmail] = useState(""); const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null); const [sent, setSent] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); if (busy) return;
    setBusy(true); setError(null); setSent(false);
    const r = await changeEmail(email); setBusy(false);
    if (!r.ok) { setError(r.error ?? "Couldn't change email"); return; }
    setSent(true); setEmail("");
  };
  return (
    <form onSubmit={submit} className="flex flex-col gap-2 border-t border-[var(--color-border)] pt-4">
      <div className="text-sm font-medium text-[var(--color-text)]">Change email</div>
      <input type="email" autoComplete="email" placeholder="New email address" value={email} onChange={(e) => setEmail(e.target.value)} className={fieldCls} aria-label="New email address" required />
      <div><button type="submit" disabled={busy} className={btnCls}>{busy ? "Sending…" : "Send confirmation"}</button></div>
      {error && err(error)}
      {sent && note("Check your new email for a confirmation link.")}
    </form>
  );
}

function SignOutAll() {
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const run = async () => {
    setBusy(true); setError(null);
    const r = await signOutEverywhere();
    if (!r.ok) { setError(r.error ?? "Couldn't sign out"); setBusy(false); return; }
    window.location.assign("/app");
  };
  return (
    <div className="flex flex-col gap-2 border-t border-[var(--color-border)] pt-4">
      <div className="text-sm font-medium text-[var(--color-text)]">Sign out of all devices</div>
      <div><button type="button" disabled={busy} onClick={() => void run()} className={btnGhost}>{busy ? "Signing out…" : "Sign out everywhere"}</button></div>
      {error && err(error)}
    </div>
  );
}

function DangerZone({ email }: { email: string }) {
  const [confirm, setConfirm] = useState(""); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const armed = confirm.trim().toLowerCase() === email.toLowerCase();
  const run = async () => {
    if (!armed || busy) return;
    setBusy(true); setError(null);
    const r = await deleteAccount();
    if (!r.ok) { setError(r.error ?? "Couldn't delete account"); setBusy(false); return; }
    window.location.assign("/");
  };
  return (
    <div className="flex flex-col gap-2 rounded-[var(--r-tile)] border border-[color:color-mix(in_srgb,var(--color-sev-critical)_40%,transparent)] p-4">
      <div className="text-sm font-medium text-[var(--color-sev-critical)]">Delete account</div>
      <p className="t-tag text-[var(--color-text-dim)]">Permanently deletes your account, profile, and subscription. This can't be undone. Type <span className="text-[var(--color-text)]">{email}</span> to confirm.</p>
      <input value={confirm} onChange={(e) => setConfirm(e.target.value)} className={fieldCls} aria-label="Type your email to confirm deletion" placeholder={email} />
      <div>
        <button type="button" disabled={!armed || busy} onClick={() => void run()}
          className="inline-flex items-center justify-center rounded-[var(--r-tile)] bg-[var(--color-sev-critical)] px-3 py-1.5 text-sm font-medium text-[var(--color-on-accent)] disabled:opacity-50">
          {busy ? "Deleting…" : "Delete my account"}
        </button>
      </div>
      {error && err(error)}
    </div>
  );
}

export default SecuritySection;
```

- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** — `git commit -am "feat(account): Security section (password/email/sign-out-all/delete)"`

---

### Task 8: `AccountPage` + `AccountApp` shell + route wiring

**Files:**
- Create: `ui/src/account/AccountPage.tsx`, `ui/src/account/AccountApp.tsx`
- Modify: `ui/src/main.tsx`, `vercel.json`
- Test: `ui/src/account/AccountApp.test.tsx`, `ui/src/account/AccountPage.test.tsx`

**Interfaces:** Consumes `useSession` (`../auth/useSession`), `useAccount` (Task 3), all four sections. `AccountPage` props: `{ session: Extract<SessionState,{status:"authed"}> }`.

- [ ] **Step 1: Failing tests.** `AccountApp.test.tsx`: mock `../auth/useSession` — `loading` → "Loading account…"; `anon` → calls `window.location.assign("/app")`; `authed` → renders `AccountPage` (stub `./AccountPage`). `AccountPage.test.tsx`: mock `./useAccount` ready + the four sections; assert all four section headings render; error state → `ErrorState`.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** `AccountPage.tsx`:

```tsx
import type { SessionState } from "../auth/useSession";
import { LoadingState } from "../components/state/LoadingState";
import { ErrorState } from "../components/state/ErrorState";
import { useAccount } from "./useAccount";
import { AccountSection } from "./sections/AccountSection";
import { SecuritySection } from "./sections/SecuritySection";
import { BillingSection } from "./sections/BillingSection";
import { PreferencesSection } from "./sections/PreferencesSection";

type Authed = Extract<SessionState, { status: "authed" }>;

export function AccountPage({ session }: { session: Authed }) {
  const { state, reload } = useAccount();
  if (state.status === "loading") return <LoadingState label="Loading your account…" />;
  if (state.status === "error") return <ErrorState title="Couldn't load your account" message={state.error} />;
  return (
    <div className="flex flex-col gap-6">
      <AccountSection profile={state.profile} onChanged={reload} />
      <SecuritySection email={state.profile.email} />
      <BillingSection plan={session.profile.plan} subscription={state.subscription} />
      <PreferencesSection />
    </div>
  );
}
export default AccountPage;
```

`AccountApp.tsx`:

```tsx
import { useEffect } from "react";
import { Radar, ArrowLeft } from "lucide-react";
import { useSession } from "../auth/useSession";
import { LoadingState } from "../components/state/LoadingState";
import { ThemeToggle } from "../cockpit/ThemeToggle";
import { AccountPage } from "./AccountPage";

export function AccountApp() {
  const session = useSession();
  useEffect(() => {
    if (session.status === "anon") window.location.assign("/app");
  }, [session.status]);

  return (
    <div className="min-h-screen bg-[var(--color-bg)] text-[var(--color-text)]">
      <header className="flex h-14 items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-4">
        <a href="/app" aria-label="Back to app" className="flex items-center gap-2 text-[var(--color-text-dim)] hover:text-[var(--color-text)]">
          <ArrowLeft size={16} aria-hidden />
          <span className="flex h-7 w-7 items-center justify-center rounded-[var(--r-tile)]" style={{ background: "color-mix(in srgb, var(--color-accent) 16%, transparent)" }}>
            <Radar size={16} style={{ color: "var(--color-accent)" }} aria-hidden />
          </span>
          <span className="font-display text-[15px] font-medium tracking-tight">PacketPilot</span>
        </a>
        <span className="ml-1 t-label text-[var(--color-text-dim)]">Account</span>
        <div className="ml-auto"><ThemeToggle /></div>
      </header>
      <main className="mx-auto w-full max-w-3xl px-4 py-8">
        {session.status === "loading" && <LoadingState label="Loading account…" />}
        {session.status === "anon" && <LoadingState label="Redirecting…" />}
        {session.status === "authed" && <AccountPage session={session} />}
      </main>
    </div>
  );
}
export default AccountApp;
```

- [ ] **Step 3b: Wire `main.tsx`** — add lazy import + branch:

```tsx
const AccountApp = React.lazy(() => import("./account/AccountApp"));
// …in the tree, before the `route === "app"` branch:
route === "account" ? (
  <Suspense fallback={<LoadingState label="Loading account…" />}>
    <AccountApp />
  </Suspense>
) : route === "app" ? ( /* …unchanged… */ )
```

- [ ] **Step 3c: Wire `vercel.json`** — add to `rewrites`:

```json
{ "source": "/account", "destination": "/" },
{ "source": "/account/(.*)", "destination": "/" }
```

- [ ] **Step 4: Run** `npx vitest run src/account` → PASS. Then `npx tsc -b` clean.
- [ ] **Step 5: Commit** — `git add ui/src/account ui/src/main.tsx vercel.json && git commit -m "feat(account): /account page shell + route wiring"`

---

### Task 9: "Profile & account" entry in `AccountMenu`

**Files:**
- Modify: `ui/src/auth/AccountMenu.tsx`
- Test: `ui/src/auth/AccountMenu.test.tsx`

**Interfaces:** Adds an anchor `<a href="/account">Profile & account</a>` shown only when `session.status === "authed"`, above the plan/billing items.

- [ ] **Step 1: Failing test** (append to existing) — authed render shows a link named `/profile & account/i` with `href="/account"`; anon render does not.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** — inside the authed popover (`AccountMenu.tsx`), as the first item under the email/plan block:

```tsx
<a
  href="/account"
  className="block w-full rounded-[var(--r-micro)] px-2 py-1.5 text-left text-sm text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]"
>
  Profile &amp; account
</a>
```

- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** — `git commit -am "feat(account): link Profile & account from the account menu"`

---

### Task 10: Migration `0016` — avatars bucket + email sync

**Files:**
- Create: `supabase/migrations/0016_account_avatars.sql`

**Interfaces:** Produces the public `avatars` bucket, owner-scoped write policies on `storage.objects`, and an `auth.users` email→`profiles.email` sync trigger.

- [ ] **Step 1: Write the migration:**

```sql
-- Avatars bucket: public read so profiles.avatar_url renders without signed URLs.
insert into storage.buckets (id, name, public)
values ('avatars', 'avatars', true)
on conflict (id) do nothing;

-- Owner-scoped writes: a user may only write within their own "<uid>/" folder.
create policy "avatars public read" on storage.objects
  for select using (bucket_id = 'avatars');
create policy "avatars owner insert" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "avatars owner update" on storage.objects
  for update to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text)
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "avatars owner delete" on storage.objects
  for delete to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);

-- Keep profiles.email consistent after a confirmed auth email change.
create or replace function public.sync_profile_email()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if new.email is distinct from old.email then
    update public.profiles set email = new.email where id = new.id;
  end if;
  return new;
end;
$$;
revoke execute on function public.sync_profile_email() from anon, authenticated;
drop trigger if exists on_auth_user_email_changed on auth.users;
create trigger on_auth_user_email_changed
  after update of email on auth.users
  for each row execute function public.sync_profile_email();
```

- [ ] **Step 2: Apply** via Supabase MCP `apply_migration` (name `0016_account_avatars`) against project `brkztcfhmrjjnbjzycie`.
- [ ] **Step 3: Verify** via MCP `execute_sql`:
  - `select id, public from storage.buckets where id='avatars';` → one public row.
  - `select policyname from pg_policies where schemaname='storage' and tablename='objects' and policyname like 'avatars%';` → 4 rows.
  - `select tgname from pg_trigger where tgrelid='auth.users'::regclass and tgname='on_auth_user_email_changed';` → present.
- [ ] **Step 4: Commit** — `git add supabase/migrations/0016_account_avatars.sql && git commit -m "feat(account): 0016 avatars bucket + email-sync trigger"`

---

### Task 11: `delete-account` Edge Function

**Files:**
- Create: `supabase/functions/delete-account/index.ts`

**Interfaces:** Authed POST; deletes the caller's own auth user (rows cascade), best-effort cancelling their Stripe subscription first. Returns `{ ok: true }` or `{ error }`.

- [ ] **Step 1: Write** `supabase/functions/delete-account/index.ts`:

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

    // Best-effort: cancel the live Stripe subscription so a deleted account stops billing.
    const { data: sub } = await admin
      .from("subscriptions").select("stripe_subscription_id")
      .eq("user_id", user.id).not("stripe_subscription_id", "is", null)
      .limit(1).maybeSingle();
    const subId = sub?.stripe_subscription_id as string | undefined;
    const stripeKey = Deno.env.get("STRIPE_SECRET_KEY");
    if (subId && stripeKey) {
      try { await new Stripe(stripeKey).subscriptions.cancel(subId); } catch (_) { /* never block deletion */ }
    }

    const del = await admin.auth.admin.deleteUser(user.id);
    if (del.error) return json({ error: del.error.message }, 400);
    return json({ ok: true });
  } catch (e) {
    return json({ error: String((e as Error)?.message ?? e) }, 400);
  }
});
```

- [ ] **Step 2: Deploy** via Supabase MCP `deploy_edge_function` (name `delete-account`, `verify_jwt: true`) to project `brkztcfhmrjjnbjzycie`.
- [ ] **Step 3: Smoke-test** — create a throwaway auth user (MCP `execute_sql` or dashboard), call the function with that user's JWT (or verify via a brief in-app run), confirm the `profiles`/`subscriptions` rows are gone (cascade) via `execute_sql`. Document the result.
- [ ] **Step 4: Commit** — `git add supabase/functions/delete-account/index.ts && git commit -m "feat(account): delete-account Edge Function (cascade + Stripe cancel)"`

---

### Task 12: E2E + a11y + full gate + merge

**Files:**
- Modify: `ui/e2e/app.spec.ts` (or add `ui/e2e/account.spec.ts`)

- [ ] **Step 1: Add an e2e** that signs in is not assumed — instead assert the unauthenticated guard: `goto('/account')` redirects to `/app` (anon path), and (if a test session helper exists) the authed page shows the four section headings. Run axe over `/account` for AA (dark + light). Use the existing e2e helpers/patterns; remember junctioned `src/wasm` (copy real files for vite).
- [ ] **Step 2: Full gate (from `ui/`):**
  - `npm run test:coverage` → green, ≥ 80/70.
  - `npx tsc -b` → clean.
  - `npm run build` → clean.
  - `npm run e2e` → green.
- [ ] **Step 3: Browser-verify** with the preview tools: load `/account` while signed in, confirm sections render, avatar upload round-trips, billing detail shows, theme/density toggle; screenshot.
- [ ] **Step 4: Merge + ship** — `git checkout main && git merge --no-ff feat/account-profile-page`, push, confirm Vercel deploy READY, and (one-time) confirm the Supabase migration + function are live in production. Verify `/account` on `https://packet-pilot.vercel.app`.

---

## Self-Review

**Spec coverage:** route (T1) · api incl. all security actions (T2) · data hook w/ auth email (T3) · Preferences (T4) · Billing detail+actions (T5) · Account avatar+name+identity (T6) · Security password/email/signout-all/delete (T7) · page+shell+route wiring+anon guard (T8) · account-menu entry (T9) · avatars bucket+RLS+email-sync (T10) · delete-account function w/ Stripe cancel + cascade (T11) · e2e/axe/gate/merge/deploy (T12). All spec sections map to a task. ✔

**Placeholder scan:** no TBD/TODO; every code step shows real code; SQL/Deno are complete. ✔

**Type consistency:** `AccountProfile`/`AccountSubscription`/`AccountState` defined in T3 and consumed unchanged in T5/T6/T8; `api.ts` signatures in T2 match call sites in T6/T7; `{ok,error?}` result shape uniform; `resolveRoute`→`"account"` (T1) consumed in `main.tsx` (T8). ✔
