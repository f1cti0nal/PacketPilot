# App Features / Feature Flags (Phase 8) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An admin feature-flags manager over `feature_flags` (audited + attributed) plus a `useFeatureFlags` read hook that gates the AI assist on `ai_assist` — with the app staying fully functional offline via hardcoded defaults.

**Architecture:** A pure `evaluateGate()` + a `useFeatureFlags` hook that fetches flags only when authed+configured and otherwise returns a hardcoded `DEFAULTS` map (fail-open). The app gates the AI Summary card + chat button on the evaluated gate (on/off/upsell). Admin CRUD mirrors the Phase-5 hook→view→route pattern; migration `0012` adds SECURITY-DEFINER triggers that stamp `updated_by` and audit changes.

**Tech Stack:** React 18 + TS, Phase-0 Supabase client, Phase-2 `startCheckout`, Tailwind tokens, Vitest + RTL. Supabase MCP for `0012`.

## Global Constraints

- **HARD: offline = full function.** Core features are NEVER flag-checked. Only `ai_assist` is gated this phase. `useFeatureFlags` short-circuits to `DEFAULTS` when `!supabaseConfigured || !authed`, fails open on error, and never blocks render.
- **No RLS change, no Edge Function, no new SPA deps.** Admin writes use the existing `feature_flags_*_admin` policies; reads use the existing authed SELECT.
- **`updated_by` is server-stamped** (a BEFORE trigger sets `auth.uid()`); the client never sets it. `key` is immutable in the UI (create/delete only).
- **Pro-gate UX:** `enabled && plan_gate==='pro' && plan!=='pro'` → `"upsell"` (disabled card + "Upgrade to Pro" → `startCheckout`). `enabled && (plan_gate===null || plan_gate===plan)` → `"on"`. `!enabled` → `"off"`.
- **SQL:** the two triggers are SECURITY DEFINER + `search_path=''` + EXECUTE revoked (mirrors `0009`). Migration number is **`0012`**.
- **Per-task gate:** `npx tsc -b` (Vitest skips typecheck). Final task runs `npm run test:coverage` (≥80/70) + `npm run build`. All UI commands from `D:\Project\PacketPilot\ui`.

---

### Task 1: Migration `0012` — feature-flags stamp + audit triggers (controller-run via MCP)

Controller-run: write the file, apply, live-verify (update a flag → audit row + updated_by), advisors, commit.

**Files:** Create `supabase/migrations/0012_feature_flags_audit.sql`

- [ ] **Step 1: Write the migration**
```sql
-- BEFORE INSERT/UPDATE: stamp updated_by from the JWT (a client-set value is untrusted).
create or replace function public.feature_flags_stamp()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  new.updated_by := auth.uid();
  return new;
end;
$$;
revoke execute on function public.feature_flags_stamp() from public, anon, authenticated;
drop trigger if exists feature_flags_stamp on public.feature_flags;
create trigger feature_flags_stamp
before insert or update on public.feature_flags
for each row execute function public.feature_flags_stamp();

-- AFTER INSERT/UPDATE/DELETE: audit changes to audit_log (mirrors 0009).
create or replace function public.feature_flags_audit()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  changes jsonb := '{}'::jsonb;
begin
  if tg_op = 'DELETE' then
    insert into public.audit_log (actor_id, action, target, meta)
    values (auth.uid(), 'feature_flag.delete', old.key,
      jsonb_build_object('enabled', old.enabled, 'plan_gate', old.plan_gate::text));
    return old;
  elsif tg_op = 'INSERT' then
    insert into public.audit_log (actor_id, action, target, meta)
    values (auth.uid(), 'feature_flag.create', new.key,
      jsonb_build_object('enabled', new.enabled, 'plan_gate', new.plan_gate::text, 'description', new.description));
    return new;
  else
    if new.enabled is distinct from old.enabled then
      changes := changes || jsonb_build_object('enabled', jsonb_build_object('old', old.enabled, 'new', new.enabled));
    end if;
    if new.plan_gate is distinct from old.plan_gate then
      changes := changes || jsonb_build_object('plan_gate', jsonb_build_object('old', old.plan_gate::text, 'new', new.plan_gate::text));
    end if;
    if new.description is distinct from old.description then
      changes := changes || jsonb_build_object('description', jsonb_build_object('old', old.description, 'new', new.description));
    end if;
    if changes <> '{}'::jsonb then
      insert into public.audit_log (actor_id, action, target, meta)
      values (auth.uid(), 'feature_flag.update', new.key, changes);
    end if;
    return new;
  end if;
end;
$$;
revoke execute on function public.feature_flags_audit() from public, anon, authenticated;
drop trigger if exists feature_flags_audit on public.feature_flags;
create trigger feature_flags_audit
after insert or update or delete on public.feature_flags
for each row execute function public.feature_flags_audit();
```

- [ ] **Step 2: Apply (MCP `apply_migration`, name `feature_flags_audit`).** Expected: success.

- [ ] **Step 3: Live-verify (MCP `execute_sql`):**
```sql
update public.feature_flags set enabled = not enabled where key = 'reputation';
select action, target, meta, actor_id, (select updated_by from public.feature_flags where key='reputation') as stamped
from public.audit_log order by created_at desc limit 1;
```
Expected: one row, `action='feature_flag.update'`, `target='reputation'`, `meta` has `enabled.old/new`. (`actor_id`/`stamped` are NULL under the service-role MCP context — that's correct; both come from `auth.uid()`.) Then revert: `update public.feature_flags set enabled = not enabled where key='reputation';`.

- [ ] **Step 4: Advisors (MCP `get_advisors` type=security).** Expected: no new ERROR; the two trigger functions are NOT flagged as publicly-executable (the revoke clears it).

- [ ] **Step 5: Commit**
```bash
cd "D:/Project/PacketPilot" && git add supabase/migrations/0012_feature_flags_audit.sql && git commit -m "feat(db): feature_flags audit + updated_by stamp triggers (0012)"
```

---

### Task 2: `flags.ts` + `useFeatureFlags` read hook

**Files:**
- Create: `ui/src/lib/features/flags.ts`, `ui/src/lib/features/useFeatureFlags.ts`
- Test: `ui/src/lib/features/flags.test.ts`, `ui/src/lib/features/useFeatureFlags.test.ts`

**Interfaces:**
- Produces: `type FlagKey = "ai_assist"`; `type FeatureGate = "on" | "off" | "upsell"`; `interface FlagState { enabled: boolean; plan_gate: "free" | "pro" | null }`; `const DEFAULTS: Record<FlagKey, FlagState>`; `evaluateGate(flag: FlagState, plan: string): FeatureGate`; `useFeatureFlags(authed: boolean, plan: string): { gate: (key: FlagKey) => FeatureGate }`.

- [ ] **Step 1: Write `flags.test.ts` (failing)**
```ts
import { describe, expect, it } from "vitest";
import { evaluateGate } from "./flags";

describe("evaluateGate", () => {
  it("off when disabled regardless of plan", () => {
    expect(evaluateGate({ enabled: false, plan_gate: null }, "pro")).toBe("off");
  });
  it("on when enabled and no plan gate", () => {
    expect(evaluateGate({ enabled: true, plan_gate: null }, "free")).toBe("on");
  });
  it("upsell when pro-gated and user is free", () => {
    expect(evaluateGate({ enabled: true, plan_gate: "pro" }, "free")).toBe("upsell");
  });
  it("on when pro-gated and user is pro", () => {
    expect(evaluateGate({ enabled: true, plan_gate: "pro" }, "pro")).toBe("on");
  });
  it("on when free-gated and user is free", () => {
    expect(evaluateGate({ enabled: true, plan_gate: "free" }, "free")).toBe("on");
  });
});
```

- [ ] **Step 2: Run → FAIL** (`cd "D:/Project/PacketPilot/ui" && npx vitest run src/lib/features/flags.test.ts`).

- [ ] **Step 3: Write `flags.ts`**
```ts
export type FlagKey = "ai_assist";
export type FeatureGate = "on" | "off" | "upsell";
export interface FlagState {
  enabled: boolean;
  plan_gate: "free" | "pro" | null;
}

// The single source of OFFLINE truth. Core features are NOT in this map (they render
// unconditionally and are never flag-checked); only enhancement flags appear here, defaulting
// to the safe value that preserves full local function.
export const DEFAULTS: Record<FlagKey, FlagState> = {
  ai_assist: { enabled: true, plan_gate: null },
};

export function evaluateGate(flag: FlagState, plan: string): FeatureGate {
  if (!flag.enabled) return "off";
  if (flag.plan_gate === "pro" && plan !== "pro") return "upsell";
  return "on";
}
```

- [ ] **Step 4: Write `useFeatureFlags.test.ts` (failing)**
```ts
import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

let result: { data: unknown; error: unknown } = { data: [], error: null };
const selectSpy = vi.fn();
vi.mock("../supabase", () => ({
  supabase: { from: () => ({ select: (...a: unknown[]) => { selectSpy(...a); return Promise.resolve(result); } }) },
  supabaseConfigured: true,
}));

import { useFeatureFlags } from "./useFeatureFlags";

beforeEach(() => {
  result = { data: [], error: null };
  selectSpy.mockClear();
});

describe("useFeatureFlags", () => {
  it("returns DEFAULTS without fetching when not authed", () => {
    const { result: h } = renderHook(() => useFeatureFlags(false, "free"));
    expect(h.current.gate("ai_assist")).toBe("on");
    expect(selectSpy).not.toHaveBeenCalled();
  });

  it("reflects DB flags when authed (disabled → off)", async () => {
    result = { data: [{ key: "ai_assist", enabled: false, plan_gate: null }], error: null };
    const { result: h } = renderHook(() => useFeatureFlags(true, "free"));
    await waitFor(() => expect(h.current.gate("ai_assist")).toBe("off"));
    expect(selectSpy).toHaveBeenCalledWith("key,enabled,plan_gate");
  });

  it("evaluates a pro gate as upsell for free users", async () => {
    result = { data: [{ key: "ai_assist", enabled: true, plan_gate: "pro" }], error: null };
    const { result: h } = renderHook(() => useFeatureFlags(true, "free"));
    await waitFor(() => expect(h.current.gate("ai_assist")).toBe("upsell"));
  });

  it("fails open to DEFAULTS on query error", async () => {
    result = { data: null, error: { message: "boom" } };
    const { result: h } = renderHook(() => useFeatureFlags(true, "free"));
    await waitFor(() => expect(selectSpy).toHaveBeenCalled());
    expect(h.current.gate("ai_assist")).toBe("on");
  });
});
```

- [ ] **Step 5: Write `useFeatureFlags.ts`**
```ts
import { useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../supabase";
import { DEFAULTS, evaluateGate, type FeatureGate, type FlagKey, type FlagState } from "./flags";

export function useFeatureFlags(authed: boolean, plan: string): { gate: (key: FlagKey) => FeatureGate } {
  const [flags, setFlags] = useState<Record<string, FlagState>>({});

  useEffect(() => {
    if (!supabaseConfigured || !supabase || !authed) return;
    const client = supabase;
    let cancelled = false;
    void (async () => {
      try {
        const { data, error } = await client.from("feature_flags").select("key,enabled,plan_gate");
        if (error || !data || cancelled) return; // fail-open: keep DEFAULTS
        const next: Record<string, FlagState> = {};
        for (const r of data as { key: string; enabled: boolean; plan_gate: "free" | "pro" | null }[]) {
          next[r.key] = { enabled: !!r.enabled, plan_gate: r.plan_gate ?? null };
        }
        if (!cancelled) setFlags(next);
      } catch {
        /* fail-open: keep DEFAULTS */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [authed]);

  return { gate: (key: FlagKey) => evaluateGate(flags[key] ?? DEFAULTS[key], plan) };
}
```

- [ ] **Step 6: Run both tests + tsc** — `cd "D:/Project/PacketPilot/ui" && npx vitest run src/lib/features && npx tsc -b` → flags 5/5, useFeatureFlags 4/4 PASS; tsc 0.

- [ ] **Step 7: Commit**
```bash
cd "D:/Project/PacketPilot" && git add ui/src/lib/features/ && git commit -m "feat(flags): offline-safe useFeatureFlags read hook + evaluateGate"
```

---

### Task 3: Gate the AI assist (AiUpsellCard + Dashboard + App)

**Files:**
- Create: `ui/src/cockpit/AiUpsellCard.tsx` (+ Test `ui/src/cockpit/AiUpsellCard.test.tsx`), `ui/src/components/Dashboard.aiGate.test.tsx`
- Modify: `ui/src/components/Dashboard.tsx`, `ui/src/App.tsx`

**Interfaces:** Consumes `startCheckout` from `../auth/billing`; `type FeatureGate` from `../lib/features/flags`; `useFeatureFlags` from `./lib/features/useFeatureFlags`.

- [ ] **Step 1: AiUpsellCard test (failing)**

`ui/src/cockpit/AiUpsellCard.test.tsx`:
```tsx
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const startCheckout = vi.fn().mockResolvedValue({ ok: true });
vi.mock("../auth/billing", () => ({ startCheckout: () => startCheckout() }));

import { AiUpsellCard } from "./AiUpsellCard";

describe("AiUpsellCard", () => {
  it("renders the upsell and starts checkout on click", async () => {
    render(<AiUpsellCard />);
    expect(screen.getByText(/pro feature/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /upgrade to pro/i }));
    expect(startCheckout).toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Write `AiUpsellCard.tsx`**
```tsx
import { Sparkles } from "lucide-react";
import { startCheckout } from "../auth/billing";

export function AiUpsellCard() {
  return (
    <div className="rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] p-4">
      <div className="flex items-center gap-2 text-sm text-[var(--color-text)]">
        <Sparkles size={16} className="text-[var(--color-accent-strong)]" aria-hidden />
        AI Analyst is a Pro feature
      </div>
      <p className="mt-1 t-tag text-[var(--color-text-dim)]">
        Upgrade to Pro to generate an executive summary and chat over this capture.
      </p>
      <button
        type="button"
        onClick={() => void startCheckout()}
        className="mt-2 rounded-[var(--r-micro)] bg-[var(--color-accent)] px-3 py-1.5 text-xs font-medium text-[var(--color-on-accent)] hover:opacity-90"
      >
        Upgrade to Pro
      </button>
    </div>
  );
}

export default AiUpsellCard;
```
Run `cd "D:/Project/PacketPilot/ui" && npx vitest run src/cockpit/AiUpsellCard.test.tsx` → PASS.

- [ ] **Step 3: Add the `aiGate` prop to Dashboard.** In `ui/src/components/Dashboard.tsx`:
  - Add imports near the other cockpit imports: `import { AiUpsellCard } from "../cockpit/AiUpsellCard";` and `import type { FeatureGate } from "../lib/features/flags";`
  - In `interface DashboardProps`, add: `/** Gate for the AI assist surfaces (default on). */ aiGate?: FeatureGate;`
  - In the destructuring `export function Dashboard({ ... activeSource, })`, add `aiGate = "on",` before the closing `}: DashboardProps`.
  - Replace the single line `<AiSummaryCard output={output} captureId={captureKey(output)} />` (currently Dashboard.tsx:132) with:
```tsx
        {aiGate === "on" ? (
          <AiSummaryCard output={output} captureId={captureKey(output)} />
        ) : aiGate === "upsell" ? (
          <AiUpsellCard />
        ) : null}
```

- [ ] **Step 4: Dashboard aiGate test**

`ui/src/components/Dashboard.aiGate.test.tsx`:
```tsx
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "../test/render";
import { Dashboard } from "./Dashboard";
import { makeOutput } from "../test/fixtures";

vi.mock("../cockpit/AiSummaryCard", () => ({ AiSummaryCard: () => <div>AI_SUMMARY_STUB</div> }));
vi.mock("../cockpit/AiUpsellCard", () => ({ AiUpsellCard: () => <div>AI_UPSELL_STUB</div> }));

const base = { output: makeOutput(), selectedIncident: null, onSelectIncident: vi.fn() };

describe("Dashboard AI gate", () => {
  it("renders the AI summary when on (default)", () => {
    render(<Dashboard {...base} />);
    expect(screen.getByText("AI_SUMMARY_STUB")).toBeInTheDocument();
    expect(screen.queryByText("AI_UPSELL_STUB")).not.toBeInTheDocument();
  });
  it("renders the upsell when upsell", () => {
    render(<Dashboard {...base} aiGate="upsell" />);
    expect(screen.getByText("AI_UPSELL_STUB")).toBeInTheDocument();
    expect(screen.queryByText("AI_SUMMARY_STUB")).not.toBeInTheDocument();
  });
  it("renders neither when off", () => {
    render(<Dashboard {...base} aiGate="off" />);
    expect(screen.queryByText("AI_SUMMARY_STUB")).not.toBeInTheDocument();
    expect(screen.queryByText("AI_UPSELL_STUB")).not.toBeInTheDocument();
  });
});
```
Run `cd "D:/Project/PacketPilot/ui" && npx vitest run src/components/Dashboard.aiGate.test.tsx` → 3/3 PASS.

- [ ] **Step 5: Wire App.tsx.** In `ui/src/App.tsx`:
  - Add the import after the other lib imports: `import { useFeatureFlags } from "./lib/features/useFeatureFlags";`
  - Immediately after `const session = useSession();` (App.tsx:121), add:
```tsx
  const aiGate = useFeatureFlags(
    session.status === "authed",
    session.status === "authed" ? session.profile.plan : "free",
  ).gate("ai_assist");
```
  - Change the chat-button line (App.tsx:680) from `onOpenAiChat={summary.status === "ready" && summary.data ? () => setAiChatOpen(true) : undefined}` to:
```tsx
      onOpenAiChat={aiGate === "on" && summary.status === "ready" && summary.data ? () => setAiChatOpen(true) : undefined}
```
  - Add `aiGate={aiGate}` to the `<Dashboard … />` props (App.tsx:730-736 block, e.g. after `activeSource={activeSource}`).

- [ ] **Step 6: Verify App + Dashboard suites + tsc.** Run:
`cd "D:/Project/PacketPilot/ui" && npx vitest run src/App.test.tsx src/components/Dashboard.test.tsx src/cockpit/AiUpsellCard.test.tsx src/components/Dashboard.aiGate.test.tsx && npx tsc -b`
Expected: all PASS (App.test unaffected — `ai_assist` defaults `"on"` under unconfigured supabase, so the chat button + summary render as before); tsc 0.

- [ ] **Step 7: Commit**
```bash
cd "D:/Project/PacketPilot" && git add ui/src/cockpit/AiUpsellCard.tsx ui/src/cockpit/AiUpsellCard.test.tsx ui/src/components/Dashboard.tsx ui/src/components/Dashboard.aiGate.test.tsx ui/src/App.tsx && git commit -m "feat(flags): gate the AI assist on ai_assist (on/off/upsell)"
```

---

### Task 4: `useAdminFeatureFlags` hook

**Files:** Create `ui/src/admin/features/useAdminFeatureFlags.ts`; Test `ui/src/admin/features/useAdminFeatureFlags.test.ts`

**Interfaces:**
- Consumes: `supabase`, `supabaseConfigured` from `../../lib/supabase`.
- Produces:
  - `interface AdminFlag { key: string; description: string | null; enabled: boolean; plan_gate: "free" | "pro" | null; updated_at: string }`
  - `type AdminFlagsState = {status:"loading"} | {status:"error";error:string} | {status:"ready";flags:AdminFlag[]}`
  - `useAdminFeatureFlags(): { state: AdminFlagsState; reload: () => void }`
  - `setEnabled(key, boolean)`, `setPlanGate(key, "free"|"pro"|null)`, `setDescription(key, string)`, `createFlag(key, description)`, `deleteFlag(key)` → `Promise<{ ok: boolean; error?: string }>`

- [ ] **Step 1: Write the failing test**

`ui/src/admin/features/useAdminFeatureFlags.test.ts`:
```ts
import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

let listResult: { data: unknown; error: unknown } = { data: [], error: null };
let eqResult: { error: unknown } = { error: null };
const updateSpy = vi.fn();
const insertSpy = vi.fn();
const deleteSpy = vi.fn();
const eqSpy = vi.fn();

vi.mock("../../lib/supabase", () => {
  const q: Record<string, unknown> = {};
  q.select = () => q;
  q.order = () => Promise.resolve(listResult);
  q.update = (...a: unknown[]) => { updateSpy(...a); return { eq: (...b: unknown[]) => { eqSpy(...b); return Promise.resolve(eqResult); } }; };
  q.insert = (...a: unknown[]) => { insertSpy(...a); return Promise.resolve(eqResult); };
  q.delete = () => ({ eq: (...b: unknown[]) => { deleteSpy(...b); return Promise.resolve(eqResult); } });
  return { supabase: { from: () => q }, supabaseConfigured: true };
});

import { useAdminFeatureFlags, setEnabled, setPlanGate, setDescription, createFlag, deleteFlag } from "./useAdminFeatureFlags";

const SAMPLE = [
  { key: "ai_assist", description: "AI assist", enabled: true, plan_gate: null, updated_at: "2026-06-20T00:00:00Z" },
  { key: "pcap_export", description: "PCAP export", enabled: false, plan_gate: "pro", updated_at: "2026-06-21T00:00:00Z" },
];

beforeEach(() => {
  listResult = { data: SAMPLE, error: null };
  eqResult = { error: null };
  updateSpy.mockClear(); insertSpy.mockClear(); deleteSpy.mockClear(); eqSpy.mockClear();
});

describe("useAdminFeatureFlags", () => {
  it("loads flags into the ready state", async () => {
    const { result } = renderHook(() => useAdminFeatureFlags());
    await waitFor(() => expect(result.current.state.status).toBe("ready"));
    if (result.current.state.status === "ready") expect(result.current.state.flags).toHaveLength(2);
  });

  it("surfaces a query error", async () => {
    listResult = { data: null, error: { message: "boom" } };
    const { result } = renderHook(() => useAdminFeatureFlags());
    await waitFor(() => expect(result.current.state.status).toBe("error"));
    if (result.current.state.status === "error") expect(result.current.state.error).toBe("boom");
  });

  it("setEnabled/setPlanGate/setDescription update by key and return ok", async () => {
    expect(await setEnabled("ai_assist", false)).toEqual({ ok: true });
    expect(updateSpy).toHaveBeenCalledWith({ enabled: false });
    expect(eqSpy).toHaveBeenCalledWith("key", "ai_assist");
    await setPlanGate("ai_assist", "pro");
    expect(updateSpy).toHaveBeenCalledWith({ plan_gate: "pro" });
    await setDescription("ai_assist", "x");
    expect(updateSpy).toHaveBeenCalledWith({ description: "x" });
  });

  it("createFlag inserts and deleteFlag deletes by key", async () => {
    expect(await createFlag("new_flag", "desc")).toEqual({ ok: true });
    expect(insertSpy).toHaveBeenCalledWith({ key: "new_flag", description: "desc" });
    expect(await deleteFlag("new_flag")).toEqual({ ok: true });
    expect(deleteSpy).toHaveBeenCalledWith("key", "new_flag");
  });

  it("returns the error message on a failed mutation", async () => {
    eqResult = { error: { message: "denied" } };
    expect(await setEnabled("ai_assist", true)).toEqual({ ok: false, error: "denied" });
  });
});
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Write `useAdminFeatureFlags.ts`**
```ts
import { useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../../lib/supabase";

export interface AdminFlag {
  key: string;
  description: string | null;
  enabled: boolean;
  plan_gate: "free" | "pro" | null;
  updated_at: string;
}
export type AdminFlagsState =
  | { status: "loading" }
  | { status: "error"; error: string }
  | { status: "ready"; flags: AdminFlag[] };

const COLS = "key,description,enabled,plan_gate,updated_at";

export function useAdminFeatureFlags(): { state: AdminFlagsState; reload: () => void } {
  const [state, setState] = useState<AdminFlagsState>({ status: "loading" });
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
        const { data, error } = await client.from("feature_flags").select(COLS).order("key");
        if (error) throw new Error((error as { message?: string }).message ?? "Query failed");
        if (cancelled) return;
        setState({ status: "ready", flags: (data ?? []) as unknown as AdminFlag[] });
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

async function update(key: string, fields: Record<string, unknown>): Promise<{ ok: boolean; error?: string }> {
  if (!supabase) return { ok: false, error: "Backend not configured" };
  const { error } = await supabase.from("feature_flags").update(fields as never).eq("key", key);
  return error ? { ok: false, error: (error as { message?: string }).message ?? "Update failed" } : { ok: true };
}

export const setEnabled = (key: string, enabled: boolean) => update(key, { enabled });
export const setPlanGate = (key: string, plan_gate: "free" | "pro" | null) => update(key, { plan_gate });
export const setDescription = (key: string, description: string) => update(key, { description });

export async function createFlag(key: string, description: string): Promise<{ ok: boolean; error?: string }> {
  if (!supabase) return { ok: false, error: "Backend not configured" };
  const { error } = await supabase.from("feature_flags").insert({ key, description } as never);
  return error ? { ok: false, error: (error as { message?: string }).message ?? "Create failed" } : { ok: true };
}

export async function deleteFlag(key: string): Promise<{ ok: boolean; error?: string }> {
  if (!supabase) return { ok: false, error: "Backend not configured" };
  const { error } = await supabase.from("feature_flags").delete().eq("key", key);
  return error ? { ok: false, error: (error as { message?: string }).message ?? "Delete failed" } : { ok: true };
}
```

- [ ] **Step 4: Run test + tsc** — `cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/features/useAdminFeatureFlags.test.ts && npx tsc -b` → 5/5 PASS; tsc 0.

- [ ] **Step 5: Commit**
```bash
cd "D:/Project/PacketPilot" && git add ui/src/admin/features/useAdminFeatureFlags.ts ui/src/admin/features/useAdminFeatureFlags.test.ts && git commit -m "feat(admin): useAdminFeatureFlags hook + flag mutators"
```

---

### Task 5: `FeatureFlagsView` + wire `AdminShell` + full gate

**Files:**
- Create: `ui/src/admin/features/FeatureFlagsView.tsx`; Test `ui/src/admin/features/FeatureFlagsView.test.tsx`
- Modify: `ui/src/admin/AdminShell.tsx`, `ui/src/admin/AdminShell.test.tsx`

**Interfaces:** Consumes `useAdminFeatureFlags`, `setEnabled`, `setPlanGate`, `setDescription`, `createFlag`, `deleteFlag`, `type AdminFlag` from `./useAdminFeatureFlags`; `LoadingState`/`ErrorState`; `joinedDate` from `../dashboard/format`.

- [ ] **Step 1: Write the failing view test**

`ui/src/admin/features/FeatureFlagsView.test.tsx`:
```tsx
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const hookState = vi.fn();
const reload = vi.fn();
const setEnabled = vi.fn().mockResolvedValue({ ok: true });
const setPlanGate = vi.fn().mockResolvedValue({ ok: true });
const setDescription = vi.fn().mockResolvedValue({ ok: true });
const createFlag = vi.fn().mockResolvedValue({ ok: true });
const deleteFlag = vi.fn().mockResolvedValue({ ok: true });
vi.mock("./useAdminFeatureFlags", () => ({
  useAdminFeatureFlags: () => ({ state: hookState(), reload }),
  setEnabled: (...a: unknown[]) => setEnabled(...a),
  setPlanGate: (...a: unknown[]) => setPlanGate(...a),
  setDescription: (...a: unknown[]) => setDescription(...a),
  createFlag: (...a: unknown[]) => createFlag(...a),
  deleteFlag: (...a: unknown[]) => deleteFlag(...a),
}));

import { FeatureFlagsView } from "./FeatureFlagsView";

const FLAGS = [
  { key: "ai_assist", description: "AI assist", enabled: true, plan_gate: null, updated_at: "2026-06-20T00:00:00Z" },
  { key: "pcap_export", description: "PCAP export", enabled: false, plan_gate: "pro", updated_at: "2026-06-21T00:00:00Z" },
];

beforeEach(() => {
  hookState.mockReturnValue({ status: "ready", flags: FLAGS });
  reload.mockClear();
  setEnabled.mockClear().mockResolvedValue({ ok: true });
  createFlag.mockClear().mockResolvedValue({ ok: true });
  deleteFlag.mockClear().mockResolvedValue({ ok: true });
});

describe("FeatureFlagsView", () => {
  it("renders a row per flag", () => {
    render(<FeatureFlagsView />);
    const table = screen.getByRole("table");
    expect(within(table).getByText("ai_assist")).toBeInTheDocument();
    expect(within(table).getByText("pcap_export")).toBeInTheDocument();
  });

  it("toggling enabled calls setEnabled then reloads", async () => {
    render(<FeatureFlagsView />);
    await userEvent.click(screen.getByRole("checkbox", { name: /enable ai_assist/i }));
    expect(setEnabled).toHaveBeenCalledWith("ai_assist", false);
    await waitFor(() => expect(reload).toHaveBeenCalled());
  });

  it("changing plan gate calls setPlanGate", async () => {
    render(<FeatureFlagsView />);
    await userEvent.selectOptions(screen.getByRole("combobox", { name: /plan gate for ai_assist/i }), "pro");
    expect(setPlanGate).toHaveBeenCalledWith("ai_assist", "pro");
  });

  it("adds a flag", async () => {
    render(<FeatureFlagsView />);
    await userEvent.type(screen.getByRole("textbox", { name: /new flag key/i }), "new_flag");
    await userEvent.click(screen.getByRole("button", { name: /add flag/i }));
    expect(createFlag).toHaveBeenCalledWith("new_flag", "");
  });

  it("deletes a flag", async () => {
    render(<FeatureFlagsView />);
    await userEvent.click(screen.getByRole("button", { name: /delete pcap_export/i }));
    expect(deleteFlag).toHaveBeenCalledWith("pcap_export");
  });

  it("shows an alert when a mutation fails", async () => {
    setEnabled.mockResolvedValue({ ok: false, error: "denied" });
    render(<FeatureFlagsView />);
    await userEvent.click(screen.getByRole("checkbox", { name: /enable ai_assist/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent("denied");
  });

  it("renders empty and error states", () => {
    hookState.mockReturnValue({ status: "ready", flags: [] });
    const { rerender } = render(<FeatureFlagsView />);
    expect(screen.getByText(/no feature flags/i)).toBeInTheDocument();
    hookState.mockReturnValue({ status: "error", error: "backend down" });
    rerender(<FeatureFlagsView />);
    expect(screen.getByText(/backend down/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Write `FeatureFlagsView.tsx`**
```tsx
import { useState } from "react";
import { LoadingState } from "../../components/state/LoadingState";
import { ErrorState } from "../../components/state/ErrorState";
import { joinedDate } from "../dashboard/format";
import {
  useAdminFeatureFlags,
  setEnabled,
  setPlanGate,
  setDescription,
  createFlag,
  deleteFlag,
  type AdminFlag,
} from "./useAdminFeatureFlags";

type Mutator = () => Promise<{ ok: boolean; error?: string }>;
const GATES = ["all", "free", "pro"] as const;

export function FeatureFlagsView() {
  const { state, reload } = useAdminFeatureFlags();
  const [error, setError] = useState<string | null>(null);
  const [newKey, setNewKey] = useState("");

  const run = async (fn: Mutator) => {
    setError(null);
    const r = await fn();
    if (r.ok) reload();
    else setError(r.error ?? "Update failed");
  };

  const add = async () => {
    const key = newKey.trim();
    if (!key) return;
    await run(() => createFlag(key, ""));
    setNewKey("");
  };

  return (
    <div className="flex flex-col gap-[var(--density-gap)]">
      {error && (
        <p role="alert" className="t-tag text-[var(--color-sev-critical)]">
          {error}
        </p>
      )}
      {state.status === "loading" ? (
        <LoadingState label="Loading feature flags…" />
      ) : state.status === "error" ? (
        <ErrorState title="Couldn't load feature flags" message={state.error} />
      ) : state.flags.length === 0 ? (
        <p className="text-sm text-[var(--color-text-dim)]">No feature flags yet.</p>
      ) : (
        <table className="pp-table">
          <thead>
            <tr>
              <th>Key</th>
              <th>Description</th>
              <th>Enabled</th>
              <th>Plan gate</th>
              <th>Updated</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {state.flags.map((f) => (
              <FlagRow key={f.key} f={f} run={run} />
            ))}
          </tbody>
        </table>
      )}
      <div className="flex items-center gap-2">
        <input
          type="text"
          value={newKey}
          onChange={(e) => setNewKey(e.target.value)}
          placeholder="new_flag_key"
          aria-label="New flag key"
          className="rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-sm text-[var(--color-text)] placeholder:text-[var(--color-text-dim)]"
        />
        <button
          type="button"
          onClick={() => void add()}
          className="rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-xs text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
        >
          Add flag
        </button>
      </div>
    </div>
  );
}

function FlagRow({ f, run }: { f: AdminFlag; run: (fn: Mutator) => void }) {
  const [desc, setDesc] = useState(f.description ?? "");
  return (
    <tr>
      <td className="font-mono-num">{f.key}</td>
      <td>
        <input
          type="text"
          value={desc}
          onChange={(e) => setDesc(e.target.value)}
          onBlur={() => desc !== (f.description ?? "") && run(() => setDescription(f.key, desc))}
          aria-label={`Description for ${f.key}`}
          className="w-full rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1 text-sm text-[var(--color-text)]"
        />
      </td>
      <td>
        <input
          type="checkbox"
          checked={f.enabled}
          onChange={(e) => run(() => setEnabled(f.key, e.target.checked))}
          aria-label={`Enable ${f.key}`}
        />
      </td>
      <td>
        <select
          aria-label={`Plan gate for ${f.key}`}
          value={f.plan_gate ?? "all"}
          onChange={(e) => run(() => setPlanGate(f.key, e.target.value === "all" ? null : (e.target.value as "free" | "pro")))}
          className="rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-1.5 py-0.5 t-tag uppercase text-[var(--color-text-dim)]"
        >
          {GATES.map((g) => (
            <option key={g} value={g}>
              {g}
            </option>
          ))}
        </select>
      </td>
      <td className="font-mono-num text-[var(--color-text-dim)]">{joinedDate(f.updated_at)}</td>
      <td>
        <button
          type="button"
          onClick={() => run(() => deleteFlag(f.key))}
          aria-label={`Delete ${f.key}`}
          className="rounded-[var(--r-micro)] px-2 py-1 t-tag uppercase text-[var(--color-sev-critical)] hover:bg-[var(--color-surface-2)]"
        >
          Delete
        </button>
      </td>
    </tr>
  );
}

export default FeatureFlagsView;
```
Run `cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/features/FeatureFlagsView.test.tsx && npx tsc -b` → 7/7 PASS; tsc 0.

- [ ] **Step 4: Wire AdminShell + its test.** In `ui/src/admin/AdminShell.test.tsx`, add after the traffic mock: `vi.mock("./features/FeatureFlagsView", () => ({ FeatureFlagsView: () => <div>FEATURES_STUB</div> }));` and a test:
```tsx
  it("routes the App Features section to the feature flags view", async () => {
    render(<AdminShell email="a@b.com" onSignOut={vi.fn()} />);
    await userEvent.click(within(screen.getByRole("navigation")).getByRole("button", { name: "App Features" }));
    expect(screen.getByText("FEATURES_STUB")).toBeInTheDocument();
    expect(window.location.hash).toBe("#features");
  });
```
In `ui/src/admin/AdminShell.tsx`, add `import { FeatureFlagsView } from "./features/FeatureFlagsView";` and the branch:
```tsx
          ) : active === "traffic" ? (
            <TrafficView />
          ) : active === "features" ? (
            <FeatureFlagsView />
          ) : (
```

- [ ] **Step 5: Full gate.** Run, in order:
1. `cd "D:/Project/PacketPilot/ui" && npx tsc -b` → exit 0.
2. `cd "D:/Project/PacketPilot/ui" && npm run test:coverage` → all pass, EXIT 0 (no unhandled errors), coverage ≥ 80/70. Report Test Files/Tests totals + "All files" line + exit code.
3. `cd "D:/Project/PacketPilot/ui" && npm run build` → "✓ built".

- [ ] **Step 6: Commit**
```bash
cd "D:/Project/PacketPilot" && git add ui/src/admin/features/FeatureFlagsView.tsx ui/src/admin/features/FeatureFlagsView.test.tsx ui/src/admin/AdminShell.tsx ui/src/admin/AdminShell.test.tsx && git commit -m "feat(admin): App Features feature-flags manager + route"
```

---

## After all tasks

- **Final whole-branch review** (most capable model): diff from `git merge-base main HEAD` to `HEAD`. Focus: the OFFLINE invariant (does the app stay fully functional with `supabaseConfigured=false`? is any CORE feature flag-gated? — must be NO); fail-open on flag-read error; `evaluateGate` correctness + the upsell path; the `0012` triggers (SECURITY DEFINER/revoke, `updated_by` server-stamped, audit meta); admin mutators RLS-gated; `key` immutability in the UI; test hygiene; consistency with Phase-5/6/7 patterns.
- **Browser smoke** (controller, best-effort): /admin → App Features → toggle `ai_assist` off → AI summary card + chat button vanish in /app; set `plan_gate=pro` → a Free account sees the upsell; revert. Confirm `audit_log` rows + `updated_by`.
- **finishing-a-development-branch**: verify the suite, then present merge options.

## Self-review notes

- **Spec coverage:** audit+stamp triggers (Task 1); read hook + evaluator + DEFAULTS (Task 2); AI-assist gate incl. upsell (Task 3); admin hook+mutators (Task 4); admin view + AdminShell wiring + gate (Task 5). Offline-default invariant covered by the `useFeatureFlags` "not authed → DEFAULTS, no fetch" test + App.test staying green unconfigured. All spec sections map to a task.
- **Type consistency:** `FlagKey`/`FeatureGate`/`FlagState`/`DEFAULTS`/`evaluateGate` (Task 2) consumed by `useFeatureFlags` (Task 2) + `Dashboard`/`App` (Task 3); `AdminFlag`/`AdminFlagsState`/`useAdminFeatureFlags`/mutators (Task 4) consumed by `FeatureFlagsView` (Task 5); `FeatureFlagsView` consumed by `AdminShell` (Task 5). `plan_gate` is `"free"|"pro"|null` throughout.
- **No placeholders:** every code/test step is complete; migration SQL given in full.
