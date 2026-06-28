# Settings + Environment (Phase 9, FINAL) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An admin `app_settings` manager (audited) + a read-only secret-safe Environment view + an announcement-banner read loop, with the app fully functional offline and no secret ever read/written from the browser.

**Architecture:** Migration `0013` adds stamp+audit triggers and a whitelist `get_public_settings()` RPC. `useAppSettings` reads the banner via that RPC (fail-open to defaults); `AnnouncementBanner` renders it at the app root. Admin Settings/Environment views mirror the Phase-8 hook→view→route pattern; Environment is read-only and never touches a server secret.

**Tech Stack:** React 18 + TS, Phase-0 Supabase client, Tailwind tokens, Vitest + RTL. Supabase MCP for `0013`.

## Global Constraints

- **HARD: no secret in/through the browser.** Environment shows only public `VITE_*` (masked) + a STATIC server-secret names/locations checklist ("Server-managed", no values, no fetch). No new `VITE_*`. No env write path.
- **HARD: offline = full function.** `useAppSettings` fails open to `SETTINGS_DEFAULTS` (no banner) when `!supabaseConfigured`/error; the banner is additive, never blocks render.
- **Narrow public read:** `get_public_settings()` returns ONLY whitelisted non-secret keys (it's intentionally anon-executable — a benign advisor WARN, same class as `is_admin`).
- **Admin writes RLS-gated + audited; `updated_by` server-stamped; `key` immutable in the UI.** No RLS change.
- **SQL:** triggers SECURITY DEFINER + `search_path=''` + EXECUTE revoked (mirror `0012`); the RPC is SECURITY DEFINER + `search_path=''` + EXECUTE granted to anon/authenticated. Migration number is **`0013`**.
- **Per-task gate:** `npx tsc -b`. Final task runs `npm run test:coverage` (≥80/70) + `npm run build`. All UI commands from `D:\Project\PacketPilot\ui`.

---

### Task 1: Migration `0013` — app_settings audit + public-read RPC (controller-run via MCP)

**Files:** Create `supabase/migrations/0013_app_settings.sql`; Modify `ui/src/lib/supabase/types.ts` (regenerated for the RPC)

- [ ] **Step 1: Write the migration**
```sql
-- BEFORE INSERT/UPDATE: stamp updated_by from the JWT (client value untrusted).
create or replace function public.app_settings_stamp()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  new.updated_by := auth.uid();
  return new;
end;
$$;
revoke execute on function public.app_settings_stamp() from public, anon, authenticated;
drop trigger if exists app_settings_stamp on public.app_settings;
create trigger app_settings_stamp before insert or update on public.app_settings
for each row execute function public.app_settings_stamp();

-- AFTER INSERT/UPDATE/DELETE: audit to audit_log (mirrors 0012).
create or replace function public.app_settings_audit()
returns trigger language plpgsql security definer set search_path = '' as $$
declare changes jsonb := '{}'::jsonb;
begin
  if tg_op = 'DELETE' then
    insert into public.audit_log (actor_id, action, target, meta)
    values (auth.uid(), 'app_setting.delete', old.key, jsonb_build_object('value', old.value));
    return old;
  elsif tg_op = 'INSERT' then
    insert into public.audit_log (actor_id, action, target, meta)
    values (auth.uid(), 'app_setting.create', new.key, jsonb_build_object('value', new.value, 'description', new.description));
    return new;
  else
    if new.value is distinct from old.value then
      changes := changes || jsonb_build_object('value', jsonb_build_object('old', old.value, 'new', new.value));
    end if;
    if new.description is distinct from old.description then
      changes := changes || jsonb_build_object('description', jsonb_build_object('old', old.description, 'new', new.description));
    end if;
    if changes <> '{}'::jsonb then
      insert into public.audit_log (actor_id, action, target, meta)
      values (auth.uid(), 'app_setting.update', new.key, changes);
    end if;
    return new;
  end if;
end;
$$;
revoke execute on function public.app_settings_audit() from public, anon, authenticated;
drop trigger if exists app_settings_audit on public.app_settings;
create trigger app_settings_audit after insert or update or delete on public.app_settings
for each row execute function public.app_settings_audit();

-- Narrow PUBLIC read: only whitelisted, non-secret keys (never the whole admin table).
create or replace function public.get_public_settings()
returns jsonb language sql stable security definer set search_path = '' as $$
  select coalesce(jsonb_object_agg(key, value), '{}'::jsonb)
  from public.app_settings
  where key in ('announcement_banner', 'support_contact_email', 'pro_plan_price_display');
$$;
grant execute on function public.get_public_settings() to anon, authenticated;

-- Seed the banner key (off by default; empty text → nothing shown).
insert into public.app_settings (key, value, description) values
  ('announcement_banner', '{"text":"","severity":"info","dismissible":true}'::jsonb, 'Site-wide announcement banner')
on conflict (key) do nothing;
```

- [ ] **Step 2: Apply (MCP `apply_migration`, name `app_settings`).** Expected: success.

- [ ] **Step 3: Live-verify (MCP `execute_sql`):**
  - `select public.get_public_settings();` → a jsonb object containing `announcement_banner` (empty text).
  - `update public.app_settings set value = '{"text":"Scheduled maintenance Sat 02:00 UTC","severity":"warning","dismissible":true}'::jsonb where key='announcement_banner'; select action, target, meta from public.audit_log where action like 'app_setting%' order by created_at desc limit 1;` → an `app_setting.update` row with `meta.value.old/new`. Then revert the text to empty: `update public.app_settings set value='{"text":"","severity":"info","dismissible":true}'::jsonb where key='announcement_banner';`
  - Confirm anon can call the RPC: `begin; set local role anon; select public.get_public_settings(); rollback;` → returns the whitelisted object (no error).

- [ ] **Step 4: Advisors (MCP `get_advisors` type=security).** Expected: no new ERROR. The two trigger functions are NOT flagged (revoked). `get_public_settings` WILL appear as an anon/authenticated SECURITY-DEFINER-executable WARN — this is INTENTIONAL (the public read path) and benign (returns only whitelisted non-secret keys), same class as the pre-existing `is_admin` WARN.

- [ ] **Step 5: Regenerate types (MCP `generate_typescript_types`)** → overwrite `ui/src/lib/supabase/types.ts`. Confirm it adds `get_public_settings` under Functions (Args `never`/`Record<string,never>`, Returns `Json`). Run `cd "D:/Project/PacketPilot/ui" && npx tsc -b` → exit 0. (If the whole regenerated file is unwieldy, instead hand-add to `types.ts` Functions: `get_public_settings: { Args: Record<PropertyKey, never>; Returns: Json }` — match the style of the existing functions.)

- [ ] **Step 6: Commit**
```bash
cd "D:/Project/PacketPilot" && git add supabase/migrations/0013_app_settings.sql ui/src/lib/supabase/types.ts && git commit -m "feat(db): app_settings audit/stamp triggers + get_public_settings RPC + banner seed (0013)"
```

---

### Task 2: App read loop — publicSettings + useAppSettings + AnnouncementBanner + App wiring

**Files:**
- Create: `ui/src/lib/settings/publicSettings.ts`, `ui/src/lib/settings/useAppSettings.ts`, `ui/src/cockpit/AnnouncementBanner.tsx`
- Test: `ui/src/lib/settings/publicSettings.test.ts`, `ui/src/lib/settings/useAppSettings.test.ts`, `ui/src/cockpit/AnnouncementBanner.test.tsx`
- Modify: `ui/src/App.tsx`

**Interfaces:**
- Produces: `interface AnnouncementBanner { text; severity: "info"|"warning"|"critical"; dismissible }`; `interface PublicSettings { announcement_banner: AnnouncementBanner | null }`; `const SETTINGS_DEFAULTS`; `parsePublicSettings(raw): PublicSettings`; `useAppSettings(): PublicSettings`.

- [ ] **Step 1: Write `publicSettings.test.ts` (failing)**
```ts
import { describe, expect, it } from "vitest";
import { parsePublicSettings, SETTINGS_DEFAULTS } from "./publicSettings";

describe("parsePublicSettings", () => {
  it("parses a valid banner", () => {
    const s = parsePublicSettings({ announcement_banner: { text: "Hi", severity: "warning", dismissible: false } });
    expect(s.announcement_banner).toEqual({ text: "Hi", severity: "warning", dismissible: false });
  });
  it("treats empty/blank text as no banner", () => {
    expect(parsePublicSettings({ announcement_banner: { text: "  ", severity: "info", dismissible: true } }).announcement_banner).toBeNull();
  });
  it("defaults a bad severity to info and dismissible to true", () => {
    const s = parsePublicSettings({ announcement_banner: { text: "x", severity: "boom" } });
    expect(s.announcement_banner).toEqual({ text: "x", severity: "info", dismissible: true });
  });
  it("returns defaults for junk/missing input without throwing", () => {
    expect(parsePublicSettings(null)).toEqual(SETTINGS_DEFAULTS);
    expect(parsePublicSettings({})).toEqual(SETTINGS_DEFAULTS);
    expect(parsePublicSettings("nope")).toEqual(SETTINGS_DEFAULTS);
  });
});
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Write `publicSettings.ts`**
```ts
export interface AnnouncementBanner {
  text: string;
  severity: "info" | "warning" | "critical";
  dismissible: boolean;
}
export interface PublicSettings {
  announcement_banner: AnnouncementBanner | null;
}
export const SETTINGS_DEFAULTS: PublicSettings = { announcement_banner: null };

const SEVERITIES: AnnouncementBanner["severity"][] = ["info", "warning", "critical"];

export function parsePublicSettings(raw: unknown): PublicSettings {
  const obj = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const b = obj.announcement_banner;
  let banner: AnnouncementBanner | null = null;
  if (b && typeof b === "object") {
    const bb = b as Record<string, unknown>;
    const text = typeof bb.text === "string" ? bb.text : "";
    if (text.trim()) {
      const severity = SEVERITIES.includes(bb.severity as AnnouncementBanner["severity"])
        ? (bb.severity as AnnouncementBanner["severity"])
        : "info";
      banner = { text, severity, dismissible: bb.dismissible !== false };
    }
  }
  return { announcement_banner: banner };
}
```

- [ ] **Step 4: Write `useAppSettings.test.ts` (failing)**
```ts
import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

let rpcResult: { data: unknown; error: unknown } = { data: {}, error: null };
const rpcSpy = vi.fn();
vi.mock("../supabase", () => ({
  supabase: { rpc: (...a: unknown[]) => { rpcSpy(...a); return Promise.resolve(rpcResult); } },
  supabaseConfigured: true,
}));

import { useAppSettings } from "./useAppSettings";

beforeEach(() => {
  rpcResult = { data: {}, error: null };
  rpcSpy.mockClear();
});

describe("useAppSettings", () => {
  it("loads a banner from the public RPC", async () => {
    rpcResult = { data: { announcement_banner: { text: "Hi", severity: "info", dismissible: true } }, error: null };
    const { result } = renderHook(() => useAppSettings());
    await waitFor(() => expect(result.current.announcement_banner?.text).toBe("Hi"));
    expect(rpcSpy).toHaveBeenCalledWith("get_public_settings");
  });
  it("fails open to defaults on rpc error", async () => {
    rpcResult = { data: null, error: { message: "boom" } };
    const { result } = renderHook(() => useAppSettings());
    await waitFor(() => expect(rpcSpy).toHaveBeenCalled());
    expect(result.current.announcement_banner).toBeNull();
  });
});
```

- [ ] **Step 5: Write `useAppSettings.ts`**
```ts
import { useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../supabase";
import { parsePublicSettings, SETTINGS_DEFAULTS, type PublicSettings } from "./publicSettings";

export function useAppSettings(): PublicSettings {
  const [settings, setSettings] = useState<PublicSettings>(SETTINGS_DEFAULTS);

  useEffect(() => {
    if (!supabaseConfigured || !supabase) return; // offline → DEFAULTS, no network
    const client = supabase;
    let cancelled = false;
    void (async () => {
      try {
        const { data, error } = await client.rpc("get_public_settings");
        if (error || cancelled) return; // fail-open: keep DEFAULTS
        if (!cancelled) setSettings(parsePublicSettings(data));
      } catch {
        /* fail-open: keep DEFAULTS */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return settings;
}
```

- [ ] **Step 6: Write `AnnouncementBanner.test.tsx` (failing)**
```tsx
import { afterEach, describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AnnouncementBanner } from "./AnnouncementBanner";

afterEach(() => sessionStorage.clear());

describe("AnnouncementBanner", () => {
  it("renders nothing when banner is null or text empty", () => {
    const { container, rerender } = render(<AnnouncementBanner banner={null} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<AnnouncementBanner banner={{ text: "  ", severity: "info", dismissible: true }} />);
    expect(container).toBeEmptyDOMElement();
  });
  it("renders the text and can be dismissed", async () => {
    render(<AnnouncementBanner banner={{ text: "Maintenance soon", severity: "warning", dismissible: true }} />);
    expect(screen.getByText("Maintenance soon")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /dismiss/i }));
    expect(screen.queryByText("Maintenance soon")).not.toBeInTheDocument();
  });
  it("hides the dismiss control when not dismissible", () => {
    render(<AnnouncementBanner banner={{ text: "Notice", severity: "info", dismissible: false }} />);
    expect(screen.queryByRole("button", { name: /dismiss/i })).not.toBeInTheDocument();
  });
});
```

- [ ] **Step 7: Write `AnnouncementBanner.tsx`**
```tsx
import { useState } from "react";
import { X } from "lucide-react";
import type { AnnouncementBanner as Banner } from "../lib/settings/publicSettings";

const SEV_COLOR: Record<string, string> = {
  info: "var(--color-accent)",
  warning: "var(--color-sev-medium)",
  critical: "var(--color-sev-critical)",
};

function dismissKey(text: string): string {
  let h = 0;
  for (let i = 0; i < text.length; i++) h = (h * 31 + text.charCodeAt(i)) | 0;
  return `pp_banner_dismiss_${h}`;
}

export function AnnouncementBanner({ banner }: { banner: Banner | null }) {
  const [dismissed, setDismissed] = useState(false);
  if (!banner || !banner.text.trim() || dismissed) return null;
  let already = false;
  try {
    already = sessionStorage.getItem(dismissKey(banner.text)) === "1";
  } catch {
    already = false;
  }
  if (already) return null;
  const color = SEV_COLOR[banner.severity] ?? "var(--color-accent)";
  return (
    <div role="status" className="flex items-center gap-3 px-4 py-2 text-sm" style={{ background: color, color: "var(--color-on-accent)" }}>
      <span className="flex-1">{banner.text}</span>
      {banner.dismissible && (
        <button
          type="button"
          aria-label="Dismiss announcement"
          onClick={() => {
            try {
              sessionStorage.setItem(dismissKey(banner.text), "1");
            } catch {
              /* ignore */
            }
            setDismissed(true);
          }}
          className="opacity-80 hover:opacity-100"
        >
          <X size={16} aria-hidden />
        </button>
      )}
    </div>
  );
}

export default AnnouncementBanner;
```

- [ ] **Step 8: Wire App.tsx.** Add imports: `import { useAppSettings } from "./lib/settings/useAppSettings";` and `import { AnnouncementBanner } from "./cockpit/AnnouncementBanner";`. After `const session = useSession();` (App.tsx:121) add `const { announcement_banner } = useAppSettings();`. In the return, immediately after the opening `<>` (App.tsx:640) add `<AnnouncementBanner banner={announcement_banner} />` as the first child.

- [ ] **Step 9: Verify** — `cd "D:/Project/PacketPilot/ui" && npx vitest run src/lib/settings src/cockpit/AnnouncementBanner.test.tsx src/App.test.tsx && npx tsc -b` → publicSettings 4/4, useAppSettings 2/2, AnnouncementBanner 3/3, App.test still green; tsc 0. (App.test runs unconfigured → `useAppSettings` short-circuits → no banner → App unchanged.)

- [ ] **Step 10: Commit**
```bash
cd "D:/Project/PacketPilot" && git add ui/src/lib/settings/ ui/src/cockpit/AnnouncementBanner.tsx ui/src/cockpit/AnnouncementBanner.test.tsx ui/src/App.tsx && git commit -m "feat(settings): announcement-banner read loop (useAppSettings + AnnouncementBanner)"
```

---

### Task 3: Admin Settings — useAdminAppSettings + settingMeta + SettingsView (+ route)

**Files:**
- Create: `ui/src/admin/settings/useAdminAppSettings.ts`, `ui/src/admin/settings/settingMeta.ts`, `ui/src/admin/settings/SettingsView.tsx`
- Test: `ui/src/admin/settings/useAdminAppSettings.test.ts`, `ui/src/admin/settings/SettingsView.test.tsx`
- Modify: `ui/src/admin/AdminShell.tsx`, `ui/src/admin/AdminShell.test.tsx`

**Interfaces:**
- Produces: `interface AdminSetting { key: string; value: Json; description: string | null; updated_at: string }`; `type AdminSettingsState`; `useAdminAppSettings()`; `updateValue(key, value: Json)`, `updateDescription(key, string)`, `createSetting(key, description)`, `deleteSetting(key)`; `settingKind(key): "banner" | "json"`.

- [ ] **Step 1: Write `useAdminAppSettings.test.ts` (failing)** — mirror the Phase-8 `useAdminFeatureFlags.test.ts` structure exactly, but for `app_settings`:
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

import { useAdminAppSettings, updateValue, updateDescription, createSetting, deleteSetting } from "./useAdminAppSettings";

const SAMPLE = [
  { key: "branding", value: { product_name: "PacketPilot" }, description: "Branding", updated_at: "2026-06-20T00:00:00Z" },
  { key: "announcement_banner", value: { text: "", severity: "info", dismissible: true }, description: "Banner", updated_at: "2026-06-21T00:00:00Z" },
];

beforeEach(() => {
  listResult = { data: SAMPLE, error: null };
  eqResult = { error: null };
  updateSpy.mockClear(); insertSpy.mockClear(); deleteSpy.mockClear(); eqSpy.mockClear();
});

describe("useAdminAppSettings", () => {
  it("loads settings", async () => {
    const { result } = renderHook(() => useAdminAppSettings());
    await waitFor(() => expect(result.current.state.status).toBe("ready"));
    if (result.current.state.status === "ready") expect(result.current.state.settings).toHaveLength(2);
  });
  it("errors on query failure", async () => {
    listResult = { data: null, error: { message: "boom" } };
    const { result } = renderHook(() => useAdminAppSettings());
    await waitFor(() => expect(result.current.state.status).toBe("error"));
    if (result.current.state.status === "error") expect(result.current.state.error).toBe("boom");
  });
  it("updateValue/updateDescription update by key", async () => {
    expect(await updateValue("branding", { product_name: "X" })).toEqual({ ok: true });
    expect(updateSpy).toHaveBeenCalledWith({ value: { product_name: "X" } });
    expect(eqSpy).toHaveBeenCalledWith("key", "branding");
    await updateDescription("branding", "d");
    expect(updateSpy).toHaveBeenCalledWith({ description: "d" });
  });
  it("createSetting inserts, deleteSetting deletes by key", async () => {
    expect(await createSetting("new_key", "desc")).toEqual({ ok: true });
    expect(insertSpy).toHaveBeenCalledWith({ key: "new_key", description: "desc", value: {} });
    expect(await deleteSetting("new_key")).toEqual({ ok: true });
    expect(deleteSpy).toHaveBeenCalledWith("key", "new_key");
  });
  it("returns the error message on a failed mutation", async () => {
    eqResult = { error: { message: "denied" } };
    expect(await updateValue("branding", {})).toEqual({ ok: false, error: "denied" });
  });
});
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Write `settingMeta.ts`**
```ts
export type SettingKind = "banner" | "json";

/** Known keys get a typed editor; everything else uses the validated raw-JSON editor. */
export function settingKind(key: string): SettingKind {
  return key === "announcement_banner" ? "banner" : "json";
}
```

- [ ] **Step 4: Write `useAdminAppSettings.ts`** (mirror `useAdminFeatureFlags.ts`)
```ts
import { useEffect, useState } from "react";
import { supabase, supabaseConfigured } from "../../lib/supabase";
import type { Json } from "../../lib/supabase/types";

export interface AdminSetting {
  key: string;
  value: Json;
  description: string | null;
  updated_at: string;
}
export type AdminSettingsState =
  | { status: "loading" }
  | { status: "error"; error: string }
  | { status: "ready"; settings: AdminSetting[] };

const COLS = "key,value,description,updated_at";

export function useAdminAppSettings(): { state: AdminSettingsState; reload: () => void } {
  const [state, setState] = useState<AdminSettingsState>({ status: "loading" });
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
        const { data, error } = await client.from("app_settings").select(COLS).order("key");
        if (error) throw new Error((error as { message?: string }).message ?? "Query failed");
        if (cancelled) return;
        setState({ status: "ready", settings: (data ?? []) as unknown as AdminSetting[] });
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

async function patch(key: string, fields: Record<string, unknown>): Promise<{ ok: boolean; error?: string }> {
  if (!supabase) return { ok: false, error: "Backend not configured" };
  const { error } = await supabase.from("app_settings").update(fields as never).eq("key", key);
  return error ? { ok: false, error: (error as { message?: string }).message ?? "Update failed" } : { ok: true };
}

export const updateValue = (key: string, value: Json) => patch(key, { value });
export const updateDescription = (key: string, description: string) => patch(key, { description });

export async function createSetting(key: string, description: string): Promise<{ ok: boolean; error?: string }> {
  if (!supabase) return { ok: false, error: "Backend not configured" };
  const { error } = await supabase.from("app_settings").insert({ key, description, value: {} } as never);
  return error ? { ok: false, error: (error as { message?: string }).message ?? "Create failed" } : { ok: true };
}

export async function deleteSetting(key: string): Promise<{ ok: boolean; error?: string }> {
  if (!supabase) return { ok: false, error: "Backend not configured" };
  const { error } = await supabase.from("app_settings").delete().eq("key", key);
  return error ? { ok: false, error: (error as { message?: string }).message ?? "Delete failed" } : { ok: true };
}
```

- [ ] **Step 5: Run hook test + tsc** → 5/5 PASS, tsc 0.

- [ ] **Step 6: Write `SettingsView.test.tsx` (failing)**
```tsx
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const hookState = vi.fn();
const reload = vi.fn();
const updateValue = vi.fn().mockResolvedValue({ ok: true });
const updateDescription = vi.fn().mockResolvedValue({ ok: true });
const createSetting = vi.fn().mockResolvedValue({ ok: true });
const deleteSetting = vi.fn().mockResolvedValue({ ok: true });
vi.mock("./useAdminAppSettings", () => ({
  useAdminAppSettings: () => ({ state: hookState(), reload }),
  updateValue: (...a: unknown[]) => updateValue(...a),
  updateDescription: (...a: unknown[]) => updateDescription(...a),
  createSetting: (...a: unknown[]) => createSetting(...a),
  deleteSetting: (...a: unknown[]) => deleteSetting(...a),
}));

import { SettingsView } from "./SettingsView";

const SETTINGS = [
  { key: "branding", value: { product_name: "PacketPilot" }, description: "Branding", updated_at: "2026-06-20T00:00:00Z" },
  { key: "announcement_banner", value: { text: "", severity: "info", dismissible: true }, description: "Banner", updated_at: "2026-06-21T00:00:00Z" },
];

beforeEach(() => {
  hookState.mockReturnValue({ status: "ready", settings: SETTINGS });
  reload.mockClear();
  updateValue.mockClear().mockResolvedValue({ ok: true });
  createSetting.mockClear().mockResolvedValue({ ok: true });
  deleteSetting.mockClear().mockResolvedValue({ ok: true });
});

describe("SettingsView", () => {
  it("renders a row per setting", () => {
    render(<SettingsView />);
    const table = screen.getByRole("table");
    expect(within(table).getByText("branding")).toBeInTheDocument();
    expect(within(table).getByText("announcement_banner")).toBeInTheDocument();
  });
  it("edits the banner via the typed editor", async () => {
    render(<SettingsView />);
    const text = screen.getByRole("textbox", { name: /announcement text/i });
    await userEvent.type(text, "Hello");
    await userEvent.tab();
    await waitFor(() => expect(updateValue).toHaveBeenCalled());
    const lastArg = updateValue.mock.calls.at(-1)![1] as { text: string };
    expect(lastArg.text).toContain("Hello");
  });
  it("rejects invalid JSON in a json-kind setting (no write)", async () => {
    render(<SettingsView />);
    const ta = screen.getByRole("textbox", { name: /value json for branding/i });
    await userEvent.clear(ta);
    await userEvent.type(ta, "{not json");
    await userEvent.tab();
    expect(updateValue).not.toHaveBeenCalledWith("branding", expect.anything());
    expect(await screen.findByText(/invalid json/i)).toBeInTheDocument();
  });
  it("adds and deletes a setting", async () => {
    render(<SettingsView />);
    await userEvent.type(screen.getByRole("textbox", { name: /new setting key/i }), "new_key");
    await userEvent.click(screen.getByRole("button", { name: /add setting/i }));
    expect(createSetting).toHaveBeenCalledWith("new_key", "");
    await userEvent.click(screen.getByRole("button", { name: /delete branding/i }));
    expect(deleteSetting).toHaveBeenCalledWith("branding");
  });
  it("renders empty and error states", () => {
    hookState.mockReturnValue({ status: "ready", settings: [] });
    const { rerender } = render(<SettingsView />);
    expect(screen.getByText(/no settings/i)).toBeInTheDocument();
    hookState.mockReturnValue({ status: "error", error: "backend down" });
    rerender(<SettingsView />);
    expect(screen.getByText(/backend down/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 7: Write `SettingsView.tsx`**
```tsx
import { useState } from "react";
import { LoadingState } from "../../components/state/LoadingState";
import { ErrorState } from "../../components/state/ErrorState";
import { joinedDate } from "../dashboard/format";
import {
  useAdminAppSettings,
  updateValue,
  updateDescription,
  createSetting,
  deleteSetting,
  type AdminSetting,
} from "./useAdminAppSettings";
import { settingKind } from "./settingMeta";
import type { Json } from "../../lib/supabase/types";
import type { AnnouncementBanner } from "../../lib/settings/publicSettings";

type Mutator = () => Promise<{ ok: boolean; error?: string }>;
const SEVERITIES: AnnouncementBanner["severity"][] = ["info", "warning", "critical"];

export function SettingsView() {
  const { state, reload } = useAdminAppSettings();
  const [error, setError] = useState<string | null>(null);
  const [newKey, setNewKey] = useState("");

  const run = async (fn: Mutator) => {
    setError(null);
    const r = await fn();
    if (!r) return;
    if (r.ok) reload();
    else setError(r.error ?? "Update failed");
  };

  const add = async () => {
    const key = newKey.trim();
    if (!key) return;
    await run(() => createSetting(key, ""));
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
        <LoadingState label="Loading settings…" />
      ) : state.status === "error" ? (
        <ErrorState title="Couldn't load settings" message={state.error} />
      ) : state.settings.length === 0 ? (
        <p className="text-sm text-[var(--color-text-dim)]">No settings yet.</p>
      ) : (
        <table className="pp-table">
          <thead>
            <tr>
              <th>Key</th>
              <th>Value</th>
              <th>Description</th>
              <th>Updated</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {state.settings.map((s) => (
              <SettingRow key={s.key} s={s} run={run} />
            ))}
          </tbody>
        </table>
      )}
      <div className="flex items-center gap-2">
        <input
          type="text"
          value={newKey}
          onChange={(e) => setNewKey(e.target.value)}
          placeholder="new_setting_key"
          aria-label="New setting key"
          className="rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-sm text-[var(--color-text)] placeholder:text-[var(--color-text-dim)]"
        />
        <button
          type="button"
          onClick={() => void add()}
          className="rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1.5 text-xs text-[var(--color-text-dim)] hover:text-[var(--color-text)]"
        >
          Add setting
        </button>
      </div>
    </div>
  );
}

function SettingRow({ s, run }: { s: AdminSetting; run: (fn: Mutator) => void }) {
  const [desc, setDesc] = useState(s.description ?? "");
  return (
    <tr>
      <td className="font-mono-num align-top">{s.key}</td>
      <td>{settingKind(s.key) === "banner" ? <BannerEditor s={s} run={run} /> : <JsonEditor s={s} run={run} />}</td>
      <td className="align-top">
        <input
          type="text"
          value={desc}
          onChange={(e) => setDesc(e.target.value)}
          onBlur={() => desc !== (s.description ?? "") && run(() => updateDescription(s.key, desc))}
          aria-label={`Description for ${s.key}`}
          className="w-full rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1 text-sm text-[var(--color-text)]"
        />
      </td>
      <td className="font-mono-num align-top text-[var(--color-text-dim)]">{joinedDate(s.updated_at)}</td>
      <td className="align-top">
        <button
          type="button"
          onClick={() => run(() => deleteSetting(s.key))}
          aria-label={`Delete ${s.key}`}
          className="rounded-[var(--r-micro)] px-2 py-1 t-tag uppercase text-[var(--color-sev-critical)] hover:bg-[var(--color-surface-2)]"
        >
          Delete
        </button>
      </td>
    </tr>
  );
}

function BannerEditor({ s, run }: { s: AdminSetting; run: (fn: Mutator) => void }) {
  const v = (s.value && typeof s.value === "object" ? s.value : {}) as Record<string, unknown>;
  const [text, setText] = useState(typeof v.text === "string" ? v.text : "");
  const severity = (SEVERITIES.includes(v.severity as AnnouncementBanner["severity"]) ? v.severity : "info") as AnnouncementBanner["severity"];
  const dismissible = v.dismissible !== false;
  const save = (next: { text?: string; severity?: string; dismissible?: boolean }) =>
    run(() =>
      updateValue(s.key, {
        text: next.text ?? text,
        severity: next.severity ?? severity,
        dismissible: next.dismissible ?? dismissible,
      } as Json),
    );
  return (
    <div className="flex flex-wrap items-center gap-2">
      <input
        type="text"
        value={text}
        onChange={(e) => setText(e.target.value)}
        onBlur={() => text !== (typeof v.text === "string" ? v.text : "") && save({ text })}
        placeholder="Announcement text (empty = hidden)"
        aria-label="Announcement text"
        className="min-w-[14rem] flex-1 rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1 text-sm text-[var(--color-text)]"
      />
      <select
        aria-label="Announcement severity"
        value={severity}
        onChange={(e) => save({ severity: e.target.value })}
        className="rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-1.5 py-0.5 t-tag uppercase text-[var(--color-text-dim)]"
      >
        {SEVERITIES.map((sv) => (
          <option key={sv} value={sv}>
            {sv}
          </option>
        ))}
      </select>
      <label className="flex items-center gap-1 t-tag text-[var(--color-text-dim)]">
        <input type="checkbox" checked={dismissible} aria-label="Announcement dismissible" onChange={(e) => save({ dismissible: e.target.checked })} />
        dismissible
      </label>
    </div>
  );
}

function JsonEditor({ s, run }: { s: AdminSetting; run: (fn: Mutator) => void }) {
  const [raw, setRaw] = useState(JSON.stringify(s.value, null, 2));
  const [bad, setBad] = useState(false);
  return (
    <div className="flex flex-col gap-1">
      <textarea
        value={raw}
        onChange={(e) => {
          setRaw(e.target.value);
          setBad(false);
        }}
        onBlur={() => {
          if (raw === JSON.stringify(s.value, null, 2)) return;
          try {
            const parsed = JSON.parse(raw) as Json;
            run(() => updateValue(s.key, parsed));
          } catch {
            setBad(true);
          }
        }}
        aria-label={`Value JSON for ${s.key}`}
        rows={2}
        className="w-full rounded-[var(--r-micro)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1 font-mono-num text-xs text-[var(--color-text)]"
      />
      {bad && <span className="t-tag text-[var(--color-sev-critical)]">Invalid JSON — not saved.</span>}
    </div>
  );
}

export default SettingsView;
```

- [ ] **Step 8: Wire AdminShell + its test.** In `ui/src/admin/AdminShell.test.tsx` add after the features mock: `vi.mock("./settings/SettingsView", () => ({ SettingsView: () => <div>SETTINGS_STUB</div> }));` and a test clicking the "Settings" nav → `SETTINGS_STUB` + `#settings`. In `ui/src/admin/AdminShell.tsx` add `import { SettingsView } from "./settings/SettingsView";` and the branch `) : active === "settings" ? ( <SettingsView /> ) : (` after the `features` branch.

- [ ] **Step 9: Run** `cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/settings/SettingsView.test.tsx src/admin/AdminShell.test.tsx && npx tsc -b` → SettingsView 5/5, AdminShell PASS, tsc 0.

- [ ] **Step 10: Commit**
```bash
cd "D:/Project/PacketPilot" && git add ui/src/admin/settings/ ui/src/admin/AdminShell.tsx ui/src/admin/AdminShell.test.tsx && git commit -m "feat(admin): Settings manager (app_settings, hybrid value editor) + route"
```

---

### Task 4: Environment view — envMask + EnvironmentView (+ route)

**Files:**
- Create: `ui/src/admin/environment/envMask.ts`, `ui/src/admin/environment/EnvironmentView.tsx`
- Test: `ui/src/admin/environment/envMask.test.ts`, `ui/src/admin/environment/EnvironmentView.test.tsx`
- Modify: `ui/src/admin/AdminShell.tsx`, `ui/src/admin/AdminShell.test.tsx`

- [ ] **Step 1: `envMask.test.ts` (failing)**
```ts
import { describe, expect, it } from "vitest";
import { maskUrl, maskKey } from "./envMask";

describe("env masking", () => {
  it("masks a url to scheme + prefix, never the whole value", () => {
    const m = maskUrl("https://brkztcfhmrjjnbjzycie.supabase.co");
    expect(m).toMatch(/^https:\/\//);
    expect(m).toContain("…");
    expect(m).not.toContain("supabase.co");
  });
  it("masks a key to prefix + suffix only", () => {
    const m = maskKey("sb_publishable_SZeNFP9bBk5mqzjX4cGpKQ_f-ygy641");
    expect(m.startsWith("sb_pub")).toBe(true);
    expect(m.endsWith("y641")).toBe(true);
    expect(m).toContain("…");
    expect(m).not.toContain("SZeNFP9");
  });
  it("returns Missing for empty", () => {
    expect(maskUrl(undefined)).toBe("— Missing");
    expect(maskKey("")).toBe("— Missing");
  });
});
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: `envMask.ts`**
```ts
/** Mask a public URL to scheme + a short prefix; never the full host. */
export function maskUrl(v: string | undefined): string {
  if (!v) return "— Missing";
  const m = /^([a-z]+:\/\/)(.*)$/.exec(v);
  if (!m) return v.slice(0, 8) + "…";
  return m[1] + m[2].slice(0, 8) + "…";
}

/** Mask a public key to a short prefix + suffix only. */
export function maskKey(v: string | undefined): string {
  if (!v) return "— Missing";
  if (v.length <= 12) return v.slice(0, 4) + "…";
  return v.slice(0, 6) + "…" + v.slice(-4);
}
```

- [ ] **Step 4: `EnvironmentView.test.tsx` (failing)**
```tsx
import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";

vi.mock("../settings/useAdminAppSettings", () => ({
  useAdminAppSettings: () => ({
    state: { status: "ready", settings: [{ key: "branding", value: { product_name: "PacketPilot" }, description: "Branding", updated_at: "2026-06-20T00:00:00Z" }] },
    reload: vi.fn(),
  }),
}));

import { EnvironmentView } from "./EnvironmentView";

describe("EnvironmentView", () => {
  it("shows public vars masked and a server-secret checklist with no values", () => {
    render(<EnvironmentView />);
    expect(screen.getByText("VITE_SUPABASE_URL")).toBeInTheDocument();
    // Server secrets listed by name with a 'Server-managed' label and NO value
    const secrets = screen.getByRole("table", { name: /server secrets/i });
    expect(within(secrets).getByText("STRIPE_SECRET_KEY")).toBeInTheDocument();
    expect(within(secrets).getAllByText(/server-managed/i).length).toBeGreaterThan(0);
    // No raw secret value is ever rendered
    expect(screen.queryByText(/sk_live|sk_test|whsec_|service_role/i)).not.toBeInTheDocument();
  });
  it("shows the read-only app settings mirror", () => {
    render(<EnvironmentView />);
    expect(screen.getByText("branding")).toBeInTheDocument();
  });
});
```

- [ ] **Step 5: `EnvironmentView.tsx`**
```tsx
import { supabaseConfigured } from "../../lib/supabase";
import { useAdminAppSettings } from "../settings/useAdminAppSettings";
import { joinedDate } from "../dashboard/format";
import { maskKey, maskUrl } from "./envMask";

const PUBLIC_VARS: { name: string; value: string | undefined; mask: (v: string | undefined) => string }[] = [
  { name: "VITE_SUPABASE_URL", value: import.meta.env.VITE_SUPABASE_URL, mask: maskUrl },
  { name: "VITE_SUPABASE_ANON_KEY", value: import.meta.env.VITE_SUPABASE_ANON_KEY, mask: maskKey },
];

// Static inventory — the browser CANNOT and MUST NOT query these. Names + locations only.
const SERVER_SECRETS: { name: string; location: string; usedBy: string }[] = [
  { name: "STRIPE_SECRET_KEY", location: "Supabase → Edge Function secrets", usedBy: "create-checkout-session, create-portal-session, stripe-webhook" },
  { name: "STRIPE_WEBHOOK_SECRET", location: "Supabase → Edge Function secrets", usedBy: "stripe-webhook" },
  { name: "STRIPE_PRICE_PRO", location: "Supabase → Edge Function secrets", usedBy: "create-checkout-session" },
  { name: "SUPABASE_SERVICE_ROLE_KEY", location: "Supabase → Edge Function secrets", usedBy: "stripe-webhook" },
];

function Chip({ ok }: { ok: boolean }) {
  return (
    <span className="t-tag uppercase" style={{ color: ok ? "var(--color-sev-low)" : "var(--color-sev-medium)" }}>
      {ok ? "Configured" : "Missing"}
    </span>
  );
}

export function EnvironmentView() {
  const { state } = useAdminAppSettings();
  return (
    <div className="flex flex-col gap-[var(--density-gap)]">
      <section>
        <h3 className="mb-1 t-tag uppercase text-[var(--color-text-dim)]">Public app config (browser)</h3>
        <table className="pp-table" aria-label="Public app config">
          <thead>
            <tr><th>Variable</th><th>Status</th><th>Value (masked)</th></tr>
          </thead>
          <tbody>
            {PUBLIC_VARS.map((v) => (
              <tr key={v.name}>
                <td className="font-mono-num">{v.name}</td>
                <td><Chip ok={Boolean(v.value)} /></td>
                <td className="font-mono-num text-[var(--color-text-dim)]">{v.mask(v.value)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mt-1 t-tag text-[var(--color-text-dim)]">
          {supabaseConfigured ? "Backend configured." : "Backend not configured (set these in the Vercel project)."}
        </p>
      </section>

      <section>
        <h3 className="mb-1 t-tag uppercase text-[var(--color-text-dim)]">Server secrets (managed server-side — not visible here)</h3>
        <table className="pp-table" aria-label="Server secrets">
          <thead>
            <tr><th>Secret</th><th>Status</th><th>Where it's set</th><th>Used by</th></tr>
          </thead>
          <tbody>
            {SERVER_SECRETS.map((s) => (
              <tr key={s.name}>
                <td className="font-mono-num">{s.name}</td>
                <td className="t-tag uppercase text-[var(--color-text-dim)]">Server-managed</td>
                <td className="text-[var(--color-text-dim)]">{s.location}</td>
                <td className="t-tag text-[var(--color-text-dim)]">{s.usedBy}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section>
        <h3 className="mb-1 t-tag uppercase text-[var(--color-text-dim)]">App settings (read-only)</h3>
        {state.status === "ready" ? (
          <table className="pp-table" aria-label="App settings mirror">
            <thead>
              <tr><th>Key</th><th>Value</th><th>Updated</th></tr>
            </thead>
            <tbody>
              {state.settings.map((s) => (
                <tr key={s.key}>
                  <td className="font-mono-num">{s.key}</td>
                  <td className="font-mono-num text-[var(--color-text-dim)]">{JSON.stringify(s.value).slice(0, 80)}</td>
                  <td className="font-mono-num text-[var(--color-text-dim)]">{joinedDate(s.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="text-sm text-[var(--color-text-dim)]">Settings unavailable.</p>
        )}
      </section>
    </div>
  );
}

export default EnvironmentView;
```

- [ ] **Step 6: Run** `cd "D:/Project/PacketPilot/ui" && npx vitest run src/admin/environment && npx tsc -b` → envMask 3/3, EnvironmentView 2/2, tsc 0.

- [ ] **Step 7: Wire AdminShell + its test.** In `AdminShell.test.tsx` add `vi.mock("./environment/EnvironmentView", () => ({ EnvironmentView: () => <div>ENV_STUB</div> }));` + a test clicking "Environment" → `ENV_STUB` + `#env`. In `AdminShell.tsx` add `import { EnvironmentView } from "./environment/EnvironmentView";` + the branch `) : active === "env" ? ( <EnvironmentView /> ) : (` after the `settings` branch.

- [ ] **Step 8: Commit**
```bash
cd "D:/Project/PacketPilot" && git add ui/src/admin/environment/ ui/src/admin/AdminShell.tsx ui/src/admin/AdminShell.test.tsx && git commit -m "feat(admin): read-only Environment view (masked public vars + server-secret checklist)"
```

---

### Task 5: Full gate

- [ ] **Step 1:** `cd "D:/Project/PacketPilot/ui" && npx tsc -b` → exit 0.
- [ ] **Step 2:** `cd "D:/Project/PacketPilot/ui" && npm run test:coverage` → all pass, EXIT 0 (no unhandled errors), coverage ≥ 80/70. Report Test Files/Tests totals + "All files" line + exit code.
- [ ] **Step 3:** `cd "D:/Project/PacketPilot/ui" && npm run build` → "✓ built".
- [ ] **Step 4:** if anything fails, fix minimally and re-run. No commit needed if Tasks 1-4 already committed and the gate is green on the existing tree; otherwise commit any fixups.

---

## After all tasks

- **Final whole-branch review** (most capable model): diff from `git merge-base main HEAD` to `HEAD`. Focus: the SECRET-SAFETY invariant (no server secret read/rendered anywhere; Environment server-secret section is static names-only; no new VITE_* secret); the OFFLINE invariant (`useAppSettings` fails open, app fully functional unconfigured); the public-read RPC returns only whitelisted keys (SECURITY DEFINER, intentional anon-exec); the `0013` triggers (stamp/audit, revoke); admin writes RLS-gated; the JSON editor rejects invalid JSON without writing; test hygiene; consistency with Phase-5..8.
- **Browser smoke** (controller, best-effort): /admin → Settings → set the announcement banner text + severity → it appears atop /app (incl. signed-out); /admin → Environment shows masked public vars + the static server-secret checklist (no values) + the settings mirror; confirm `audit_log` rows. Revert the banner text to empty.
- **finishing-a-development-branch**: verify the suite, then present merge options.

## Self-review notes

- **Spec coverage:** audit/stamp triggers + public RPC + seed (Task 1); the banner read loop incl. offline-safe hook + render (Task 2); admin `app_settings` CRUD with the hybrid editor (Task 3); read-only secret-safe Environment (Task 4); gate (Task 5). The secret-safety invariant is enforced by the static names-only server-secret list + masking + no fetch; the offline invariant by `useAppSettings`'s short-circuit + fail-open + the `App.test` staying green unconfigured.
- **Type consistency:** `AnnouncementBanner`/`PublicSettings`/`parsePublicSettings`/`useAppSettings` (Task 2) consumed by `AnnouncementBanner`/`App` (Task 2) and the `BannerEditor` (Task 3); `AdminSetting`/`useAdminAppSettings`/mutators (Task 3) consumed by `SettingsView` (Task 3) + `EnvironmentView` (Task 4); `settingKind` (Task 3); `maskUrl`/`maskKey` (Task 4). `Json` from `lib/supabase/types`.
- **No placeholders:** every code/test step is complete; migration SQL given in full.
