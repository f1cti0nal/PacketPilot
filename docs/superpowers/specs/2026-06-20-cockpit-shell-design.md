# Cockpit shell in production — design

- **Date:** 2026-06-20
- **Status:** Approved (design); pending implementation plan
- **Branch:** `feat/cockpit-shell`

## 1. Context & motivation

The "PacketPilot — Cockpit" design is already the production **home** (`Dashboard`), but the app still
wears the old `AppShell` chrome: a top bar only (wordmark, Dashboard/Flows/Recent tabs, capture label,
Load/Export). The cockpit's signature shell — a **persistent threat-rail sidebar** ("who do I chase",
always visible) and a **⌘K command palette** — exists only in the standalone demo (`ui/src/cockpit/`),
and the demo's ⌘K is a non-functional button.

This feature promotes the full cockpit shell into the live app: a persistent, collapsible threat rail, a
restyled command bar, and a **working** ⌘K command palette — without disturbing the load/export/recent/flows
flows that already ship.

## 2. Scope

**In scope**
- Persistent, collapsible **threat-rail sidebar** wired to the active capture's `summary.ip_threats`.
- **Command bar**: the restyled top chrome (tabs + Recent badge, capture label/status, Load, Export, a ⌘K
  trigger, a sidebar collapse toggle).
- **⌘K command palette**: core actions + fuzzy host/threat search.
- Rail/palette host click → **open that host's incident flyout** (fallback: filter Flows).

**Out of scope (non-goals)**
- Changing the engine, data model, or any detector.
- Re-skinning Flows/Recent internals beyond what the global theme already does.
- Wiring the standalone demo's (`CockpitApp`) ⌘K button to the new palette — the demo keeps its decorative
  ⌘K; only production gets the working palette. (Shared components stay demo-compatible.)
- Persisting sidebar-collapsed or palette state across sessions.

## 3. Architecture & layout

`AppShell` becomes a thin **layout orchestrator** that composes shared cockpit components around the
existing `<main>`:

```
┌── CommandBar (top, full-width .glass-band) ────────────────────────────────┐
│ ◉ PacketPilot · ⟨collapse⟩   [Dashboard | Flows | Recent·N]                 │
│                       capture.pcap · ●ANALYZED      ⌘K   Load   Export       │
├───────────────┬─────────────────────────────────────────────────────────────┤
│ ThreatRail    │  <main> children (Dashboard / Flows / Recent)               │
│ (collapsible) │                                                              │
└───────────────┴─────────────────────────────────────────────────────────────┘
   + CommandPalette (⌘K overlay)          + LoadCaptureDialog (own file)
```

Reading order and the one-glow discipline of the existing design system are unchanged.

## 4. Component contracts

### 4.1 `cockpit/CommandBar.tsx` (extend the shared component)
Today (demo) props: `{ captureName, sha256, activeTab, onTab, collapsed, onToggleCollapse }`.
**Add optional props** so production can drive it and the demo still compiles unchanged:
- `tabs?: { id: TabId; label: string; badge?: number }[]` — defaults to the demo's Dashboard/Flows; prod
  passes Dashboard/Flows/Recent with the Recent badge.
- `captureStatus?: "loading" | "ready" | "error" | "idle"` and `captureError?: string` — drives the
  label/pill (Loading… / filename + ●ANALYZED / "No capture").
- `onRequestLoad?: () => void`, `onExport?: () => void`, `exporting?: boolean`, `exportHint?: string` —
  wire the Load/Export buttons (currently decorative `ActionButton`s) when provided.
- `onOpenPalette?: () => void` — the ⌘K button (and the keyboard shortcut, handled in `AppShell`).
When a handler is absent the corresponding control renders disabled/decorative (demo behavior preserved).

### 4.2 `cockpit/ThreatRail.tsx` (extend the shared component)
Make the **nav block optional**: `activeTab?`/`onTab?` become optional; the Triage/Flows nav renders only
when both are provided. Production passes **no nav** (the command bar owns tabs) → the rail is a pure threat
watchlist. Props used in prod: `{ threats, collapsed, activeIp, onSelect }`. Behavior (severity spine, IP,
score bar, IOC dot, tags, 280→64px collapse, worst-first sort, aria-labels) is unchanged.

### 4.3 `cockpit/CommandPalette.tsx` (new)
```ts
interface PaletteAction { id: string; label: string; hint?: string; icon?: LucideIcon; run: () => void }
interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  actions: PaletteAction[];          // Go to Dashboard/Flows/Recent, Load, Export, Toggle sidebar
  threats: IpThreat[];               // active capture's ip_threats (may be empty)
  onSelectHost: (ip: string) => void;
}
```
- Opens on `open=true`; closes on Esc / select / scrim click. Focus moves to the input on open and is
  trapped; focus restores to the opener on close (mirrors `DetailFlyout`'s pattern).
- A single query filters two groups: **Actions** (fuzzy over label) and **Hosts** (fuzzy over
  `ip + tags + attack`), each host row showing severity chip + score.
- `↑/↓` move the highlighted item across both groups; `Enter` activates it (`action.run()` or
  `onSelectHost(ip)`); both then close the palette.
- Rendered as a centered `.glass-panel` modal (`role="dialog" aria-modal`), consistent with `DetailFlyout`.

### 4.4 `cockpit/match.ts` (new, tiny)
Dependency-free fuzzy matcher: `fuzzyScore(query, target): number | null` (subsequence match with a small
bonus for prefix/word-boundary hits); `null` = no match. Used to filter + rank palette results. No new deps.

### 4.5 `components/layout/LoadCaptureDialog.tsx` (extracted)
Move the existing `LoadCaptureDialog` (and its `LoadStatus` type + `loadedSummaryLabel` helper) out of
`AppShell.tsx` verbatim into its own file; `AppShell` imports it. Pure refactor, no behavior change — keeps
`AppShell` a focused orchestrator (it is ~490 lines today).

### 4.6 `components/layout/AppShell.tsx` (refactored)
New responsibility: layout only. Renders `CommandBar` (top), then a flex row of `ThreatRail` +
`<main>{children}</main>`, plus `LoadCaptureDialog` and `CommandPalette`. New props on top of today's:
`threats`, `activeIp`, `onSelectThreat`, `collapsed`, `onToggleCollapse`, `onOpenPalette`, `paletteOpen`,
`onPaletteOpenChange`. Owns the **global ⌘K / Ctrl+K key listener** that calls `onPaletteOpenChange(true)`
and prevents the browser default; it is a no-op when the palette or the load dialog is already open. (⌘K/Ctrl+K
does not collide with text-entry shortcuts, so it stays active even while typing in a filter.) Builds the
palette `actions` array from its props (tab switches, load, export, toggle sidebar).

### 4.7 `components/Dashboard.tsx` (controlled flyout)
Remove the internal `selected` state. New props: `selectedIncident: Incident | null` and
`onSelectIncident: (i: Incident | null) => void`. The threat-watchlist card and incident-hero `onOpen`
call `onSelectIncident`; the `DetailFlyout` renders from `selectedIncident`. `DetailFlyout` stays inside
`Dashboard` (so it shows on the dashboard tab; the rail switches to Dashboard before opening it).

### 4.8 `App.tsx` (lifted state + handlers)
New state: `selectedIncident: Incident | null`, `collapsed: boolean` (auto-collapse < 1100px via
`matchMedia`), `paletteOpen: boolean`, and `activeIp: string | null`. New handler used by both the rail and
the palette:
```ts
const openThreat = (ip: string) => {
  setActiveIp(ip);
  const incidents = summary.data?.summary.incidents ?? [];   // guard: no capture / no incidents
  const inc = incidents.find(i => i.host === ip);
  if (inc) { setSelectedIncident(inc); setTab("dashboard"); }
  else { jumpToFlows({ ip }); }
};
```
`App` passes `threats = summary.data?.summary.ip_threats ?? []`, `activeIp`, `onSelectThreat=openThreat`,
`collapsed`/`onToggleCollapse`, and palette open-state to `AppShell`; and `selectedIncident` +
`onSelectIncident` to `Dashboard`.

## 5. Data flow

```
ip_threats ─► AppShell.ThreatRail ─(row click)─► App.openThreat(ip)
ip_threats ─► AppShell.CommandPalette (host group) ─(select)─► App.openThreat(ip)
                                                                 │
                       incident found ──► setSelectedIncident + tab=dashboard ──► Dashboard.DetailFlyout
                       no incident   ──► jumpToFlows({ ip }) ──► Flows filtered
CommandPalette actions ─► tab switch / onRequestLoad / onExport / toggle sidebar (App/AppShell handlers)
```

Single source of truth for the flyout is `App.selectedIncident`; both the dashboard (hero/watchlist) and the
shell (rail/palette) drive it through the same path.

## 6. Edge cases & error handling

- **Host with no correlated incident** (e.g. a scored talker that isn't an incident host) → `jumpToFlows({ ip })`. No dead clicks.
- **No capture loaded** → rail shows a muted "No capture" state; palette shows only always-available actions (Load capture); host group hidden.
- **No scored threats** → rail "No scored threats" empty state; palette host group empty.
- **Active capture replaced** (load/recent/reanalyze) → `selectedIncident` and `activeIp` reset to null so a stale flyout/highlight can't persist.
- **Reduced motion / transparency** → already handled by the global theme; the palette adds no new infinite animation.

## 7. Responsive

- Rail: 280px expanded, 64px collapsed. Auto-collapse below 1100px (`matchMedia`), with the command-bar
  toggle overriding until the next breakpoint cross. Below ~900px the rail stays collapsed.
- Command bar already degrades (hides the capture label cluster on narrow widths); the ⌘K control may hide
  under `sm` while the keyboard shortcut still works.

## 8. Verification plan

No UI test framework exists in the repo; verification is **typecheck + live-app reproduction** (consistent
with how the cockpit home and the Flows-sort fix were verified):
- `tsc --noEmit -p tsconfig.json` green (prod + the still-working demo).
- Live (`node dev.mjs`, `:5180`):
  - Rail renders the real `ip_threats`; clicking `10.13.37.7` opens its incident flyout (switching to Dashboard from any tab); clicking a no-incident host filters Flows.
  - ⌘K opens the palette; typing an IP filters the host group; Enter jumps; actions switch tabs / open load / export / toggle sidebar.
  - Sidebar collapse toggles and auto-collapses < 1100px.
  - **Regression pass:** Load capture, Export, Recent (open/reanalyze/remove), and Flows all still work; no console errors.
- `/cockpit.html` demo still renders (shared `CommandBar`/`ThreatRail` remain demo-compatible).

## 9. File summary

| File | Change |
|---|---|
| `ui/src/cockpit/CommandBar.tsx` | extend with optional prod props (tabs+badge, capture status, load/export, ⌘K) |
| `ui/src/cockpit/ThreatRail.tsx` | make nav optional (watchlist-only in prod) |
| `ui/src/cockpit/CommandPalette.tsx` | **new** — ⌘K palette (actions + host search) |
| `ui/src/cockpit/match.ts` | **new** — dependency-free fuzzy matcher |
| `ui/src/components/layout/LoadCaptureDialog.tsx` | **new** — extracted from AppShell (verbatim) |
| `ui/src/components/layout/AppShell.tsx` | refactor to layout orchestrator (CommandBar + ThreatRail + main + dialog + palette); ⌘K listener |
| `ui/src/components/Dashboard.tsx` | controlled flyout (`selectedIncident` + `onSelectIncident`) |
| `ui/src/App.tsx` | lift `selectedIncident`; add collapsed/palette/activeIp state + `openThreat` |

## 10. Risks

- **Shared-component coupling:** extending `CommandBar`/`ThreatRail` for prod must not break the demo — mitigated by making every new prop optional and a demo regression check.
- **AppShell churn:** it owns the working load/export/recent wiring; the refactor is layout-only and keeps that wiring intact (extracting the dialog reduces, not increases, risk).
- **⌘K global listener:** must not fire while the load dialog/flyout owns focus or hijack browser shortcuts unexpectedly — listener guards on already-open modals.
