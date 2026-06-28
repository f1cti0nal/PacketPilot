# PacketPilot SaaS — App Features / Feature Flags (Phase 8) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-28
**Branch:** `feat/feature-flags`
**Sub-project:** 8 of the PacketPilot SaaS platform (depends on Phase 0 + Phase 3)

## Context

Phase 8 of the SaaS pivot. Phases 0–7 are merged + deployed. The `/admin` **App Features** section (`sections.ts` id `features`, ToggleRight icon) currently falls through to the placeholder. This phase adds an admin feature-flags manager **and** wires the app to read flags to gate one real feature — proving the whole read+write+audit loop.

Decisions locked with the user:
- **Read path: authed-only + offline DEFAULTS.** Keep the existing authed-only SELECT policy; the app reads flags only when signed in + backend-configured, and falls back to a hardcoded `DEFAULTS` map otherwise. (No RLS change.)
- **Scope: full loop, wire `ai_assist`.** Admin CRUD + a `useFeatureFlags` read hook + gate the AI Analyst assist (Summary card + chat) on the seeded `ai_assist` flag.
- **Pro-gated UX: disabled "Upgrade to Pro" upsell** (reusing the existing checkout) when a flag is `plan_gate='pro'` and the user is Free.

**Grounded in code (Phase-8 understand workflow):**
- `feature_flags`: `key (PK), description, enabled (default false), plan_gate (user_plan enum free|pro, NULL=all), updated_at, updated_by (FK→profiles)`; a `set_updated_at` BEFORE-UPDATE trigger (0002). RLS: `feature_flags_select_authenticated` (any authed reads all rows), `feature_flags_insert/update/delete_admin` (gated by `is_admin()`). **Seeded** with `ai_assist`(null), `reputation`(null), `pcap_export`(pro), `multi_capture_diff`(pro).
- **SELECT is authed-only → anon/offline gets zero rows.** This is why offline safety MUST rest on hardcoded DEFAULTS, not the network.
- The app reads no flags today; plan only gates billing UI; all core analysis works offline/anon.
- `AiSummaryCard` renders at `Dashboard.tsx:132`; the chat button is driven by `onOpenAiChat` (App.tsx:680 → AppShell → CommandBar). `Dashboard` is rendered at App.tsx:730.
- Audit precedent: the Phase-5 `0009` SECURITY DEFINER trigger → `audit_log`. Next migration is **`0012`** (0010/0011 are Phase 7).

## Goal

Let an admin manage feature flags (toggle/plan-gate/describe/create/delete, audited + attributed), and have the app read flags to gate the AI assist — while the app stays **fully functional offline/anon** via hardcoded defaults and core features are never flag-gated.

## Invariants preserved

- **HARD: offline = full function.** Core features are never flag-checked (render unconditionally). Only enhancements get a flag. The read hook short-circuits to `DEFAULTS` before any network call (`!supabaseConfigured || !authed → DEFAULTS`), fails open on error, and never blocks render. Pulling the env vars yields the exact app that ships today.
- **Capture-data isolation unchanged:** the hook reads only `key/enabled/plan_gate` config rows; no capture/flow/finding data leaves the client.
- **Admin-only writes are server-enforced** (existing RLS); the client never sets a trusted `updated_by` — a SECURITY DEFINER trigger stamps it.
- **`key` is effectively immutable in the UI** (create/delete, no rename) so the app's hardcoded `FlagKey` references can't be orphaned.
- **No new SPA deps; no Edge Function; no RLS change.**

## Architecture

```
supabase/migrations/0012_feature_flags_audit.sql   # BEFORE stamp(updated_by) + AFTER audit triggers (SECURITY DEFINER)
ui/src/lib/features/
  flags.ts            # FlagKey, DEFAULTS, FeatureGate, pure evaluateGate()
  useFeatureFlags.ts  # authed+configured → fetch feature_flags; else DEFAULTS; fail-open; gate(key)
ui/src/cockpit/AiUpsellCard.tsx   # "AI Analyst is a Pro feature" → startCheckout()
ui/src/App.tsx                    # compute aiGate; gate chat button + pass aiGate to Dashboard
ui/src/components/Dashboard.tsx   # aiGate prop: on→AiSummaryCard / upsell→AiUpsellCard / off→nothing
ui/src/admin/features/
  useAdminFeatureFlags.ts   # list + setEnabled/setPlanGate/setDescription/createFlag/deleteFlag
  FeatureFlagsView.tsx      # table (key/desc/enabled/plan_gate) + inline edit + add + delete
ui/src/admin/AdminShell.tsx       # route active==="features" → <FeatureFlagsView />
```

**Tech stack:** React 18 + TS, Phase-0 Supabase client, the Phase-2 `startCheckout` (billing), Tailwind tokens, Vitest + RTL. Supabase MCP for `0012`.

## App read side — `flags.ts` + `useFeatureFlags.ts`

```ts
export type FlagKey = "ai_assist";              // only keys the APP reads/gates this phase
export type FeatureGate = "on" | "off" | "upsell";
export interface FlagState { enabled: boolean; plan_gate: "free" | "pro" | null }

// The single source of OFFLINE truth. Core features are NOT in this map (never flag-checked).
export const DEFAULTS: Record<FlagKey, FlagState> = {
  ai_assist: { enabled: true, plan_gate: null },
};

export function evaluateGate(flag: FlagState, plan: string): FeatureGate {
  if (!flag.enabled) return "off";
  if (flag.plan_gate === "pro" && plan !== "pro") return "upsell";
  return "on";
}
```
`useFeatureFlags(authed: boolean, plan: string): { gate: (key: FlagKey) => FeatureGate }` — keeps a `Record<string, FlagState>` (empty initially). In a `useEffect` guarded by `if (!supabaseConfigured || !supabase || !authed) return;`, it fetches `feature_flags.select("key,enabled,plan_gate")` and merges into state; **any error/empty leaves state empty (fail-open)**. `gate(key)` evaluates `evaluateGate(state[key] ?? DEFAULTS[key], plan)`. Offline/anon never fetches → always DEFAULTS. Never awaited; never blocks render.

## App wiring (gate `ai_assist`)

`App.tsx`: `const plan = session.status === "authed" ? session.profile.plan : "free"; const { gate } = useFeatureFlags(session.status === "authed", plan); const aiGate = gate("ai_assist");`
- Chat button (App.tsx:680): `onOpenAiChat={aiGate === "on" && summary.status === "ready" && summary.data ? () => setAiChatOpen(true) : undefined}`.
- `Dashboard` (App.tsx:730): add `aiGate={aiGate}`.

`Dashboard.tsx` (line 132): add an optional `aiGate?: FeatureGate` prop (default `"on"` — existing callers/tests unaffected). Render: `aiGate === "on"` → `<AiSummaryCard … />`; `=== "upsell"` → `<AiUpsellCard />`; `=== "off"` → nothing.

`AiUpsellCard.tsx`: a small card — "AI Analyst is a Pro feature" + an "Upgrade to Pro" button calling `startCheckout()` (Phase-2 billing). Failure-silent (billing surfaces its own errors).

**Net behavior:** default (`ai_assist` enabled, plan_gate null) → AI assist shows for everyone (incl. offline) exactly as today. Admin disables it → hidden for signed-in users (offline still on via DEFAULTS — acceptable, it's an enhancement). Admin sets `plan_gate=pro` → Free signed-in users get the upsell, Pro users get it.

## Admin side — `useAdminFeatureFlags` + `FeatureFlagsView`

`useAdminFeatureFlags(): { state, reload }` (loading|error|ready{flags}) — `feature_flags.select("key,description,enabled,plan_gate,updated_at").order("key")`. Mutators (RLS admin-gated): `setEnabled(key, boolean)`, `setPlanGate(key, "free"|"pro"|null)`, `setDescription(key, string)`, `createFlag(key, description)` (INSERT; PK collision → error surfaced), `deleteFlag(key)` → `{ ok, error? }`.

`FeatureFlagsView`: a `.pp-table` — **Key** (mono, immutable), **Description** (inline-editable text), **Enabled** (checkbox/toggle), **Plan gate** (`<select>`: All / Free / Pro), **Updated**. An "Add flag" row (key + description) and a per-row Delete (with confirm). A row-level error line. Reuses the Phase-5 mutator-run pattern (`run(fn)` → reload / inline error). Wire `AdminShell`: `active === "features"` → `<FeatureFlagsView />` (+ a `vi.mock` stub + route test in `AdminShell.test.tsx`).

## Audit + attribution — `0012`

```sql
-- BEFORE INSERT/UPDATE: stamp updated_by from the JWT (client value not trusted).
create function public.feature_flags_stamp() ... security definer set search_path = '' :
  new.updated_by := auth.uid(); return new;
create trigger feature_flags_stamp before insert or update on public.feature_flags ...

-- AFTER INSERT/UPDATE/DELETE: audit to audit_log (action feature_flag.create/update/delete,
-- target = key, meta = changed/relevant columns). Mirrors 0009.
create function public.feature_flags_audit() ... security definer set search_path = '' ...
create trigger feature_flags_audit after insert or update or delete on public.feature_flags ...
```
Both functions: `EXECUTE revoked` from public/anon/authenticated (trigger-only; clears the SECURITY DEFINER advisory, like 0009). No RLS change.

## Data flow & error handling

Admin opens App Features → RLS-gated read of `feature_flags` (admin via `/admin` route + authed read) → table. A toggle/select/create/delete → `feature_flags` write → RLS enforces admin → the stamp trigger sets `updated_by`, the audit trigger logs it → reload. In the app, a signed-in user's `useFeatureFlags` fetches once and refines `aiGate`; offline/anon/error → DEFAULTS. No flag read can break navigation or local analysis.

## Testing

- **`flags.ts`**: `evaluateGate` — disabled→off; enabled+null→on; enabled+pro+free→upsell; enabled+pro+pro→on; enabled+free+free→on. (Pure → exhaustive.)
- **`useFeatureFlags`** (mock supabase): offline/`!authed` → no fetch, `gate` returns DEFAULTS; authed+configured → fetches, merges, `gate` reflects DB; fetch error → stays DEFAULTS (fail-open).
- **`AiUpsellCard`**: renders the upsell, the button calls `startCheckout` (mock billing).
- **`Dashboard`**: `aiGate` default `"on"` renders `AiSummaryCard` (existing tests stay green); `"upsell"` renders the upsell; `"off"` renders neither.
- **`useAdminFeatureFlags`**: ready maps rows; `setEnabled`/`setPlanGate`/`setDescription` call `update(...).eq("key", …)`; `createFlag` `insert`; `deleteFlag` `delete().eq`; ok/error.
- **`FeatureFlagsView`**: renders a row per flag; toggling enabled calls setEnabled+reload; plan-gate select; add-flag; delete; empty/error; failed mutation alert.
- **`AdminShell.test`**: mock `./features/FeatureFlagsView` + a route test (`#features`).
- **Offline invariant test:** assert the app's `ai_assist` gate resolves `"on"` from DEFAULTS when `supabaseConfigured` is false (no network).
- **Live (MCP):** apply `0012`; update a flag → `audit_log` row appears with `updated_by`+action+meta; `get_advisors` security → no new ERROR (the two triggers' executable WARN cleared by the revoke).
- Gate: full suite green, coverage ≥ 80/70, `tsc -b` clean, `npm run build` ✓, coverage exits 0.
- **Browser smoke** (controller, best-effort): in /admin App Features, toggle `ai_assist` off → the AI Summary card + chat button disappear in /app; set `plan_gate=pro` → a Free account sees the upsell; revert. Confirm `audit_log` rows.

## Out of scope (later)

Gating additional features (`pcap_export`, `multi_capture_diff`, export formats, dashboard cards — the seam exists, wire them in a later phase); public/anon flag reads (Option B); a per-flag rollout %/targeting; an in-app audit-log *viewer* (rows are captured); flag key rename; the Phase-9 Settings/Environment admin.

## File manifest

**Create:** `supabase/migrations/0012_feature_flags_audit.sql`, `ui/src/lib/features/flags.ts` (+ test), `ui/src/lib/features/useFeatureFlags.ts` (+ test), `ui/src/cockpit/AiUpsellCard.tsx` (+ test), `ui/src/admin/features/useAdminFeatureFlags.ts` (+ test), `ui/src/admin/features/FeatureFlagsView.tsx` (+ test).
**Modify:** `ui/src/App.tsx` (compute `aiGate`, gate chat button, pass to Dashboard), `ui/src/components/Dashboard.tsx` (+ test — `aiGate` prop), `ui/src/admin/AdminShell.tsx` (+ `AdminShell.test.tsx`) — route `features`.
**No RLS change. No Edge Function. No engine/WASM/Tauri change. No new SPA deps.**
