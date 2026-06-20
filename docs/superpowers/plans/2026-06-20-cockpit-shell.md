# Cockpit Shell Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Promote the full cockpit shell — a persistent collapsible threat-rail sidebar, a restyled command bar, and a working ⌘K command palette — into the live PacketPilot app.

**Architecture:** Approach A from the spec — refactor `AppShell` into a thin layout orchestrator that composes the shared `cockpit/CommandBar` + `cockpit/ThreatRail` + a new `cockpit/CommandPalette` around `<main>`, lifting the incident-flyout state from `Dashboard` up to `App`. Shared cockpit components gain **optional** props so the standalone demo (`CockpitApp`, `/cockpit.html`) keeps working.

**Tech Stack:** React 18 + TypeScript (strict) + Vite + Tailwind 3, `lucide-react`, `@tanstack/react-*`. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-06-20-cockpit-shell-design.md`

## Global Constraints

- **No new dependencies.** Fuzzy matching is hand-rolled in `cockpit/match.ts`.
- **TypeScript strict**, incl. `noUnusedLocals` / `noUnusedParameters`. Use `import type` for type-only imports.
- **Typecheck command:** from `ui/`, `npx tsc --noEmit -p tsconfig.json` must exit 0. (The repo's `npm run typecheck` uses `tsc -b` which hits a pre-existing TS6310 on the referenced node project — do **not** use it; use the `-p` form.) Node may not be on PATH; prepend it if needed (`C:\Program Files\nodejs`).
- **No UI test framework exists.** Verification per task = typecheck + targeted live-app check via the dev server (`node dev.mjs` → http://localhost:5180, production app at `/`, demo at `/cockpit.html`). This mirrors how the cockpit home and the Flows-sort fix were verified.
- **Design discipline (unchanged):** cyan = alive/active/focus only; severity color = threat; only the top critical incident "breathes". All numbers use `font-mono-num`. Tokens live in `ui/src/index.css`.
- **Shared-component rule:** every new prop added to `cockpit/CommandBar` and `cockpit/ThreatRail` MUST be optional so `cockpit/CockpitApp.tsx` (the demo) compiles unchanged. Each task touching them re-verifies `/cockpit.html`.
- **Branch:** `feat/cockpit-shell`. Commit after every task.

---

## File Structure

| File | Responsibility |
|---|---|
| `ui/src/components/layout/LoadCaptureDialog.tsx` | **New** — the load/drop dialog, extracted verbatim from `AppShell`. |
| `ui/src/cockpit/match.ts` | **New** — pure `fuzzyScore(query, target)` subsequence matcher. |
| `ui/src/cockpit/CommandPalette.tsx` | **New** — ⌘K overlay: fuzzy actions + host search. |
| `ui/src/cockpit/ThreatRail.tsx` | Modify — make the nav block optional (watchlist-only in prod). |
| `ui/src/cockpit/CommandBar.tsx` | Modify — optional prod props (configurable tabs+badge, capture status, load/export handlers, `onOpenPalette`). |
| `ui/src/components/Dashboard.tsx` | Modify — controlled flyout (`selectedIncident` + `onSelectIncident` props). |
| `ui/src/components/layout/AppShell.tsx` | Modify — layout orchestrator: CommandBar + ThreatRail + main + LoadCaptureDialog + CommandPalette; ⌘K listener. |
| `ui/src/App.tsx` | Modify — lift `selectedIncident`; add `collapsed`/`paletteOpen`/`activeIp` + `openThreat`. |

---

## Task 1: Extract `LoadCaptureDialog` from `AppShell`

Pure refactor — move the dialog (and its helpers) into its own file so `AppShell` can become a thin orchestrator. No behavior change.

**Files:**
- Create: `ui/src/components/layout/LoadCaptureDialog.tsx`
- Modify: `ui/src/components/layout/AppShell.tsx`

**Interfaces:**
- Produces: `LoadCaptureDialog` (default + named export) with props `{ onReplaceData, onAnalyzePcap, onClose }`. The dialog owns its own `LoadStatus` state internally.

- [ ] **Step 1: Create the new file** with the dialog moved out of `AppShell`. Copy the current `LoadCaptureDialog` function, the `LoadStatus` type, and the `loadedSummaryLabel` helper from `AppShell.tsx` verbatim. Make the dialog **self-contained**: move the `const [load, setLoad] = useState<LoadStatus>({ phase: "idle" })` state *into* `LoadCaptureDialog` (it currently lives in `AppShell` and is threaded in as `status`/`onStatusChange`). New signature:

```tsx
// ui/src/components/layout/LoadCaptureDialog.tsx
import { useCallback, useId, useRef, useState, type DragEvent } from "react";
import { AlertTriangle, CheckCircle2, Loader2, Upload, X } from "lucide-react";
import type { AnalysisOutput, FlowRow } from "../../types";
import { loadFlows } from "../../lib/data";
import { isCaptureFile } from "../../lib/wasmEngine";
import { compactNumber, humanBytes } from "../../lib/format";
import { cn } from "../../lib/cn";

type LoadStatus =
  | { phase: "idle" }
  | { phase: "loading"; note: string }
  | { phase: "ready"; summary?: AnalysisOutput; flows?: FlowRow[]; fileNames: string[] }
  | { phase: "error"; message: string };

export function LoadCaptureDialog({
  onReplaceData,
  onAnalyzePcap,
  onClose,
}: {
  onReplaceData: (next: { summary?: AnalysisOutput; flows?: FlowRow[] }) => void;
  onAnalyzePcap: (file: File) => Promise<void>;
  onClose: () => void;
}) {
  const [status, setStatus] = useState<LoadStatus>({ phase: "idle" });
  // ... move the existing handleFiles / onDrop / JSX body here verbatim,
  // replacing `onStatusChange(...)` calls with `setStatus(...)` and `status` reads as-is.
}

function loadedSummaryLabel(s: Extract<LoadStatus, { phase: "ready" }>): string {
  // ... verbatim from AppShell
}

export default LoadCaptureDialog;
```

- [ ] **Step 2: Update `AppShell`** — delete the moved code (the `LoadCaptureDialog` function, `LoadStatus` type, `loadedSummaryLabel`, and the `const [load, setLoad]` state) and import the new component. The render site changes from passing `status`/`onStatusChange` to the new props:

```tsx
import { LoadCaptureDialog } from "./LoadCaptureDialog";
// ...
{loadDialogOpen && (
  <LoadCaptureDialog
    onReplaceData={onReplaceData}
    onAnalyzePcap={onAnalyzePcap}
    onClose={() => onLoadDialogOpenChange(false)}
  />
)}
```
Remove now-unused imports from `AppShell` (`useRef`, `useId`, `DragEvent`, `loadFlows`, `isCaptureFile`, `compactNumber`, the dialog-only icons `Upload`/`X` if not used elsewhere in `AppShell` — keep `Upload` only if still referenced by the header Load button; it is, so keep it).

- [ ] **Step 3: Typecheck.** Run from `ui/`: `npx tsc --noEmit -p tsconfig.json`. Expected: exit 0 (no unused-import or missing-symbol errors).

- [ ] **Step 4: Live check.** Start `node dev.mjs`; at `/`, click **Load capture** → the dialog opens, drag-drop/browse area renders, Esc/close works. No console errors.

- [ ] **Step 5: Commit.**
```bash
git add ui/src/components/layout/LoadCaptureDialog.tsx ui/src/components/layout/AppShell.tsx
git commit -m "refactor(shell): extract LoadCaptureDialog from AppShell"
```

---

## Task 2: `cockpit/match.ts` — fuzzy matcher

**Files:**
- Create: `ui/src/cockpit/match.ts`

**Interfaces:**
- Produces: `fuzzyScore(query: string, target: string): number | null` — higher is better; `null` = no subsequence match. Empty query returns `0` (neutral; matches everything).

- [ ] **Step 1: Write the matcher.**

```ts
// ui/src/cockpit/match.ts
// Dependency-free subsequence fuzzy matcher for the command palette.
// Returns a score (higher = better) or null when `query` is not a subsequence
// of `target`. Case-insensitive. Empty query => 0 (matches everything).
export function fuzzyScore(query: string, target: string): number | null {
  const q = query.trim().toLowerCase();
  if (q === "") return 0;
  const t = target.toLowerCase();
  let score = 0;
  let ti = 0;
  let prev = -2;
  for (let qi = 0; qi < q.length; qi++) {
    const found = t.indexOf(q[qi], ti);
    if (found === -1) return null;
    if (found === prev + 1) score += 3; // contiguous run
    if (found === 0) score += 5; // prefix
    else if (/[.\s:_/-]/.test(t[found - 1])) score += 2; // word boundary
    score += 1;
    prev = found;
    ti = found + 1;
  }
  return score - target.length * 0.05; // prefer tighter targets
}
```

- [ ] **Step 2: Typecheck.** `npx tsc --noEmit -p tsconfig.json` → exit 0.

- [ ] **Step 3: Sanity-verify the pure function** (no test runner; one-off eval). Run from `ui/`:
```bash
npx tsx -e "import {fuzzyScore} from './src/cockpit/match.ts'; console.log(fuzzyScore('103','10.13.37.7')!==null, fuzzyScore('xyz','10.0.0.1')===null, fuzzyScore('flows','Go to Flows')!==null, fuzzyScore('','anything')===0)"
```
Expected output: `true true true true`. (If `tsx` is unavailable, instead verify in Task 8 via the palette filtering live.)

- [ ] **Step 4: Commit.**
```bash
git add ui/src/cockpit/match.ts
git commit -m "feat(palette): dependency-free fuzzy matcher"
```

---

## Task 3: Extend `ThreatRail` — optional nav (watchlist-only in prod)

**Files:**
- Modify: `ui/src/cockpit/ThreatRail.tsx`

**Interfaces:**
- Produces: `ThreatRail` props become `{ threats, collapsed, onSelect, activeIp?, activeTab?, onTab? }`. The Triage/Flows nav + its divider render **only when both `activeTab` and `onTab` are provided**. `onSelect`, `threats`, `collapsed` stay required.

- [ ] **Step 1: Loosen the props type.** In the `ThreatRail({ ... }: {...})` signature, change `activeIp: string | null` → `activeIp?: string | null`, `activeTab: TabId` → `activeTab?: TabId`, `onTab: (t: TabId) => void` → `onTab?: (t: TabId) => void`. Default `activeIp` to `null` in the destructure: `activeIp = null`.

- [ ] **Step 2: Make the nav conditional.** Wrap the `<nav>...</nav>` block AND the `<div className="mx-2 border-t ...">` divider that follows it in `{activeTab && onTab && ( ... )}`. The `NavItem` calls inside already reference `activeTab`/`onTab`; guarded by the conditional they are safe, but TypeScript needs them non-null — bind locals inside the block: `const at = activeTab; const ot = onTab;` and use `at`/`ot`, or keep the `onTab("dashboard")` calls (TS narrows via the `&&` guard at the JSX boundary; if it doesn't, use the local-bind form).

- [ ] **Step 3: Typecheck.** `npx tsc --noEmit -p tsconfig.json` → exit 0 (the demo `CockpitApp` still passes `activeTab`/`onTab`, so its nav still renders).

- [ ] **Step 4: Live check — demo unaffected.** At `/cockpit.html`, the left rail still shows the Triage/Flows nav + the watchlist. No console errors.

- [ ] **Step 5: Commit.**
```bash
git add ui/src/cockpit/ThreatRail.tsx
git commit -m "feat(shell): make ThreatRail nav optional (watchlist-only mode)"
```

---

## Task 4: Extend `CommandBar` — optional production props

Wire the demo's decorative buttons to real handlers and make the tab set configurable, all via optional props so the demo keeps working.

**Files:**
- Modify: `ui/src/cockpit/CommandBar.tsx`

**Interfaces:**
- Consumes: nothing new.
- Produces: `CommandBar` props add (all optional):
  `tabs?: { id: TabId; label: string; badge?: number }[]`,
  `captureStatus?: "idle" | "loading" | "ready" | "error"`, `captureError?: string`,
  `onRequestLoad?: () => void`, `onExport?: () => void`, `exporting?: boolean`, `exportHint?: string`,
  `onOpenPalette?: () => void`.
  Defaults preserve current demo behavior (Dashboard/Flows tabs, decorative buttons, "Analyzed" pill).

- [ ] **Step 1: Add the props + defaults.** Extend the props type and destructure with defaults:
```tsx
const DEFAULT_TABS: ReadonlyArray<{ id: TabId; label: string; badge?: number }> = [
  { id: "dashboard", label: "Dashboard" },
  { id: "flows", label: "Flows" },
];
// in the component params:
tabs = DEFAULT_TABS,
captureStatus = "ready",
captureError,
onRequestLoad,
onExport,
exporting = false,
exportHint,
onOpenPalette,
```

- [ ] **Step 2: Render configurable tabs + badge.** Replace the hard-coded `TABS.map(...)` switcher with `tabs.map(...)`; inside each button, after the label, render the badge when present:
```tsx
{tab.badge ? (
  <span className="ml-1.5 inline-flex min-w-[1.1rem] items-center justify-center rounded-full bg-[color:color-mix(in_srgb,var(--color-accent)_18%,transparent)] px-1 text-[10px] font-semibold text-[var(--color-accent)]">
    {tab.badge}
  </span>
) : null}
```
(Keep `aria-pressed={active}` — it's a single-select button group, per the existing pattern.)

- [ ] **Step 3: Wire the capture label / pill** to `captureStatus`: show `Loading…` (spinner) when `loading`; the filename + cyan `●ANALYZED` pill when `ready` and a name exists; a muted `No capture` (or `captureError`) when `error`/`idle`. Keep the existing markup; gate it on `captureStatus`.

- [ ] **Step 4: Wire the action buttons.** The Load `ActionButton` gets `onClick={onRequestLoad}` and `disabled={!onRequestLoad}`. The Export `ActionButton` gets `onClick={onExport}`, `disabled={!onExport || exporting}`, and shows a `Loader2` spinner when `exporting`; render `exportHint` (with a `CheckCircle2`) beside it when present. The ⌘K button gets `onClick={onOpenPalette}` and `disabled={!onOpenPalette}`. (Extend `ActionButton` to accept `onClick`/`disabled`/`title` props.)

- [ ] **Step 5: Typecheck.** `npx tsc --noEmit -p tsconfig.json` → exit 0 (demo `CockpitApp` passes none of the new props → unchanged behavior).

- [ ] **Step 6: Live check — demo unaffected.** At `/cockpit.html`, the command bar renders as before (Dashboard/Flows, decorative Load/Export, ⌘K). No console errors.

- [ ] **Step 7: Commit.**
```bash
git add ui/src/cockpit/CommandBar.tsx
git commit -m "feat(shell): CommandBar accepts production wiring (tabs, capture status, actions, palette)"
```

---

## Task 5: `cockpit/CommandPalette.tsx` — the ⌘K overlay

**Files:**
- Create: `ui/src/cockpit/CommandPalette.tsx`

**Interfaces:**
- Consumes: `fuzzyScore` (Task 2); `IpThreat`, `Severity` (`../types`); `sevColor` (`./viz`).
- Produces: `CommandPalette` (default + named) and `export interface PaletteAction { id: string; label: string; hint?: string; run: () => void }`. Props:
  `{ open: boolean; onClose: () => void; actions: PaletteAction[]; threats: IpThreat[]; onSelectHost: (ip: string) => void }`.

- [ ] **Step 1: Write the component.**
```tsx
// ui/src/cockpit/CommandPalette.tsx
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { CornerDownLeft, Search } from "lucide-react";
import type { IpThreat } from "../types";
import { humanNumber } from "../lib/format";
import { SEVERITY_META } from "../lib/severity";
import { sevColor } from "./viz";
import { fuzzyScore } from "./match";

export interface PaletteAction {
  id: string;
  label: string;
  hint?: string;
  run: () => void;
}

type Item =
  | { kind: "action"; action: PaletteAction; score: number }
  | { kind: "host"; threat: IpThreat; score: number };

export function CommandPalette({
  open,
  onClose,
  actions,
  threats,
  onSelectHost,
}: {
  open: boolean;
  onClose: () => void;
  actions: PaletteAction[];
  threats: IpThreat[];
  onSelectHost: (ip: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const labelId = useId();

  // Reset + focus on open.
  useEffect(() => {
    if (!open) return;
    setQuery("");
    setActive(0);
    const id = window.setTimeout(() => inputRef.current?.focus(), 0);
    return () => window.clearTimeout(id);
  }, [open]);

  const items = useMemo<Item[]>(() => {
    const acts: Item[] = [];
    for (const a of actions) {
      const score = fuzzyScore(query, a.label);
      if (score !== null) acts.push({ kind: "action", action: a, score });
    }
    acts.sort((a, b) => b.score - a.score);
    const hosts: Item[] = [];
    for (const t of threats) {
      const score = fuzzyScore(query, `${t.ip} ${t.tags.join(" ")} ${t.attack.join(" ")}`);
      if (score !== null) hosts.push({ kind: "host", threat: t, score });
    }
    hosts.sort((a, b) => b.score - a.score);
    return [...acts, ...hosts.slice(0, 8)];
  }, [query, actions, threats]);

  // Keep the highlighted index in range as the list shrinks.
  useEffect(() => {
    setActive((a) => Math.min(a, Math.max(0, items.length - 1)));
  }, [items.length]);

  if (!open) return null;

  const run = (it: Item) => {
    if (it.kind === "action") it.action.run();
    else onSelectHost(it.threat.ip);
    onClose();
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") onClose();
    else if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, items.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const it = items[active];
      if (it) run(it);
    }
  };

  return (
    <div className="fixed inset-0 z-[60] flex items-start justify-center px-4 pt-[12vh]" role="dialog" aria-modal="true" aria-labelledby={labelId}>
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <div
        className="glass-panel relative w-full max-w-lg rounded-[var(--r-card)] border border-[var(--color-border)]"
        style={{ boxShadow: "var(--sh-float)" }}
        onKeyDown={onKeyDown}
      >
        <span id={labelId} className="sr-only">Command palette</span>
        <div className="flex items-center gap-2 border-b border-[var(--color-border)] px-3">
          <Search size={16} className="shrink-0 text-[var(--color-text-faint)]" aria-hidden />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => { setQuery(e.target.value); setActive(0); }}
            placeholder="Jump to a host, or run a command…"
            aria-label="Command palette query"
            className="font-mono-num w-full bg-transparent py-3 text-sm text-[var(--color-text)] outline-none placeholder:font-sans placeholder:text-[var(--color-text-faint)]"
          />
          <kbd className="t-tag shrink-0 rounded border border-[var(--color-border)] px-1.5 py-0.5 text-[var(--color-text-faint)]">ESC</kbd>
        </div>
        <ul className="max-h-[50vh] overflow-y-auto p-1.5">
          {items.length === 0 && (
            <li className="px-3 py-6 text-center text-sm text-[var(--color-text-faint)]">No matches</li>
          )}
          {items.map((it, i) => (
            <PaletteRow
              key={it.kind === "action" ? `a:${it.action.id}` : `h:${it.threat.ip}`}
              item={it}
              active={i === active}
              onMouseEnter={() => setActive(i)}
              onClick={() => run(it)}
            />
          ))}
          {threats.length === 0 && query.trim() !== "" && (
            <li className="px-3 py-2 t-label">load a capture to search hosts</li>
          )}
        </ul>
      </div>
    </div>
  );
}

function PaletteRow({ item, active, onMouseEnter, onClick }: { item: Item; active: boolean; onMouseEnter: () => void; onClick: () => void }) {
  return (
    <li>
      <button
        type="button"
        onMouseEnter={onMouseEnter}
        onClick={onClick}
        className={
          "flex w-full items-center gap-2.5 rounded-[var(--r-tile)] px-2.5 py-2 text-left " +
          (active ? "bg-[var(--color-surface-2)]" : "")
        }
      >
        {item.kind === "action" ? (
          <>
            <span className="min-w-0 flex-1 truncate text-sm text-[var(--color-text)]">{item.action.label}</span>
            {item.action.hint && <span className="t-tag text-[var(--color-text-faint)]">{item.action.hint}</span>}
          </>
        ) : (
          <>
            <span aria-hidden className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: sevColor(item.threat.severity) }} />
            <span className="font-mono-num min-w-0 flex-1 truncate text-sm text-[var(--color-text)]">{item.threat.ip}</span>
            <span className="t-tag uppercase text-[var(--color-text-faint)]">{SEVERITY_META[item.threat.severity].label}</span>
            <span className="font-mono-num text-xs font-semibold" style={{ color: sevColor(item.threat.severity) }}>{item.threat.score}</span>
            <span className="font-mono-num t-tag text-[var(--color-text-faint)]">{humanNumber(item.threat.flows)} fl</span>
          </>
        )}
        {active && <CornerDownLeft size={13} className="shrink-0 text-[var(--color-text-faint)]" aria-hidden />}
      </button>
    </li>
  );
}

export default CommandPalette;
```

- [ ] **Step 2: Typecheck.** `npx tsc --noEmit -p tsconfig.json` → exit 0. (Not mounted yet; behavior is exercised in Task 8.)

- [ ] **Step 3: Commit.**
```bash
git add ui/src/cockpit/CommandPalette.tsx
git commit -m "feat(palette): CommandPalette overlay (actions + host search)"
```

---

## Task 6: Lift the incident-flyout state from `Dashboard` to `App`

Make `Dashboard` a controlled component so the shell (rail/palette, added next) and the dashboard share one flyout state.

**Files:**
- Modify: `ui/src/components/Dashboard.tsx`
- Modify: `ui/src/App.tsx`

**Interfaces:**
- Produces: `DashboardProps` gains `selectedIncident: Incident | null` and `onSelectIncident: (i: Incident | null) => void`; the internal `useState<Incident | null>` is removed.
- Consumes (App): nothing new yet; App owns the state and passes it down.

- [ ] **Step 1: Dashboard — accept controlled props.** In `DashboardProps`, add `selectedIncident: Incident | null;` and `onSelectIncident: (incident: Incident | null) => void;`. Remove `const [selected, setSelected] = useState<Incident | null>(null);` and the `useState` import if now unused (keep `useMemo`). Replace every `setSelected(x)` with `onSelectIncident(x)` and `setSelected(null)` with `onSelectIncident(null)`; replace the `<DetailFlyout incident={selected} ...>` with `incident={selectedIncident}`. In `openHost`, `setSelected(inc)` → `onSelectIncident(inc)`.

- [ ] **Step 2: App — own the state.** Add `const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);` (import `Incident` type). Pass to the dashboard render:
```tsx
<Dashboard
  output={summary.data!}
  onJumpToFlows={jumpToFlows}
  selectedIncident={selectedIncident}
  onSelectIncident={setSelectedIncident}
/>
```

- [ ] **Step 3: Reset on capture change.** In `applyCapture` (the single funnel) and `handleSelectRecent`, add `setSelectedIncident(null);` so a stale flyout can't survive a capture swap.

- [ ] **Step 4: Typecheck.** `npx tsc --noEmit -p tsconfig.json` → exit 0.

- [ ] **Step 5: Live check — home unchanged.** At `/`, the dashboard hero "open details" and a threat-watchlist card click still open the incident flyout; Esc/close still dismiss. No console errors.

- [ ] **Step 6: Commit.**
```bash
git add ui/src/components/Dashboard.tsx ui/src/App.tsx
git commit -m "refactor(dashboard): lift incident-flyout state to App"
```

---

## Task 7: `AppShell` orchestrator + threat rail + collapse wiring

Refactor `AppShell` into `CommandBar` + `ThreatRail` + `<main>` + `LoadCaptureDialog`, and wire `App` to provide threats, the `openThreat` handler, and collapse state (with auto-collapse). The palette is added in Task 8.

**Files:**
- Modify: `ui/src/components/layout/AppShell.tsx`
- Modify: `ui/src/App.tsx`

**Interfaces:**
- Consumes: `CommandBar` (Task 4), `ThreatRail` (Task 3), `LoadCaptureDialog` (Task 1).
- Produces: `AppShellProps` gains `threats: IpThreat[]`, `activeIp: string | null`, `onSelectThreat: (ip: string) => void`, `collapsed: boolean`, `onToggleCollapse: () => void`, `onOpenPalette: () => void`. `App` exposes `openThreat(ip)` and `collapsed` state.

- [ ] **Step 1a: Add an `ip` filter to the Flows deep-link.** Today `App.jumpToFlows` drops `ip` and `FlowsView` has no IP filter, so the `openThreat` fallback below can't filter Flows. Fix three spots:
  - `App.tsx` `FlowsInitialFilter` interface: add `ip?: string;`.
  - `App.tsx` `jumpToFlows`: include `ip` →
    ```tsx
    const jumpToFlows = useCallback(
      (filter: { severity?: Severity; category?: string; ip?: string }) => {
        setFlowsFilter({ severity: filter.severity, category: filter.category, ip: filter.ip });
        setTab("flows");
      }, []);
    ```
  - `FlowsView.tsx`: add `ip?: string;` to `FlowsViewProps['initialFilter']`, and in the `useEffect` that applies `initialFilter`, replace `setQuery("")` with `setQuery(initialFilter.ip ?? "")` (the free-text filter already matches IPs, so an IP query pre-filters the table to that host).

- [ ] **Step 1b: App — shell state + `openThreat`.** Add:
```tsx
const [collapsed, setCollapsed] = useState(false);
const [activeIp, setActiveIp] = useState<string | null>(null);

useEffect(() => {
  const mq = window.matchMedia("(max-width: 1100px)");
  const apply = () => setCollapsed(mq.matches);
  apply();
  mq.addEventListener("change", apply);
  return () => mq.removeEventListener("change", apply);
}, []);

const openThreat = useCallback((ip: string) => {
  setActiveIp(ip);
  const inc = (summary.data?.summary.incidents ?? []).find((i) => i.host === ip);
  if (inc) { setSelectedIncident(inc); setTab("dashboard"); }
  else { jumpToFlows({ ip }); }
}, [summary, jumpToFlows]);
```

- [ ] **Step 2: App — reset `activeIp` on capture change.** In `applyCapture`/`handleSelectRecent`, add `setActiveIp(null);` next to the `setSelectedIncident(null);` from Task 6.

- [ ] **Step 3: AppShell — new props.** Add to `AppShellProps`: `threats: IpThreat[]; activeIp: string | null; onSelectThreat: (ip: string) => void; collapsed: boolean; onToggleCollapse: () => void; onOpenPalette: () => void;` (import `IpThreat`).

- [ ] **Step 4: AppShell — new layout.** Replace the current `<header>…</header>` + `<main>…</main>` body with the orchestrated layout. Build the `tabs` array (with the Recent badge) and the capture status, and compose:
```tsx
const tabs = [
  { id: "dashboard" as const, label: "Dashboard" },
  { id: "flows" as const, label: "Flows" },
  { id: "recent" as const, label: "Recent", badge: recentCount || undefined },
];
const captureStatus =
  summary.status === "ready" ? "ready" :
  summary.status === "loading" ? "loading" :
  summary.status === "error" ? "error" : "idle";

return (
  <div data-component="AppShell" className="flex h-full min-h-0 flex-col bg-bg text-[var(--color-text)]">
    <CommandBar
      captureName={captureName ?? ""}
      sha256={summary.status === "ready" ? summary.data?.source_sha256 ?? undefined : undefined}
      activeTab={activeTab}
      onTab={onTabChange}
      tabs={tabs}
      captureStatus={captureStatus}
      captureError={summary.status === "error" ? summary.error : undefined}
      onRequestLoad={onRequestLoad}
      onExport={() => void handleExportClick()}
      exporting={exporting}
      exportHint={exportHint ?? undefined}
      onOpenPalette={onOpenPalette}
      collapsed={collapsed}
      onToggleCollapse={onToggleCollapse}
    />
    <div className="flex min-h-0 flex-1">
      <ThreatRail
        threats={threats}
        collapsed={collapsed}
        activeIp={activeIp}
        onSelect={onSelectThreat}
      />
      <main className="min-h-0 flex-1 overflow-auto">{children}</main>
    </div>
    {loadDialogOpen && (
      <LoadCaptureDialog onReplaceData={onReplaceData} onAnalyzePcap={onAnalyzePcap} onClose={() => onLoadDialogOpenChange(false)} />
    )}
  </div>
);
```
Keep the existing `handleExportClick`, `exporting`, `exportHint`, `captureName` logic in `AppShell` (they already exist); remove the old inline `<header>` markup and the `TabSwitcher`/`CaptureLabel` helpers if now fully replaced by `CommandBar` (delete them and their now-unused imports). `CommandBar` lives in `ui/src/cockpit/CommandBar.tsx`; import it.

- [ ] **Step 5: App — pass the new props to `AppShell`:**
```tsx
<AppShell
  /* …existing props… */
  threats={summary.status === "ready" ? summary.data?.summary.ip_threats ?? [] : []}
  activeIp={activeIp}
  onSelectThreat={openThreat}
  collapsed={collapsed}
  onToggleCollapse={() => setCollapsed((c) => !c)}
  onOpenPalette={() => setPaletteOpen(true)}   /* paletteOpen added in Task 8; for now use a temporary no-op `() => {}` and replace in Task 8 */
>
```
For this task, pass `onOpenPalette={() => {}}` (no-op) so it typechecks; Task 8 replaces it.

- [ ] **Step 6: Typecheck.** `npx tsc --noEmit -p tsconfig.json` → exit 0.

- [ ] **Step 7: Live check.** At `/`:
  - The left **threat rail** renders the real `ip_threats` (sorted worst-first); the command bar shows Dashboard/Flows/Recent with the Recent badge.
  - Click `10.13.37.7` in the rail → switches to Dashboard and opens its incident flyout. Click a non-incident host → goes to Flows filtered to that IP.
  - The collapse toggle shrinks the rail to 64px; resizing the window below 1100px auto-collapses it.
  - **Regression:** Load capture, Export (hint appears), Recent tab + open/reanalyze, and Flows all still work. No console errors.

- [ ] **Step 8: Commit.**
```bash
git add ui/src/components/layout/AppShell.tsx ui/src/App.tsx ui/src/views/FlowsView.tsx
git commit -m "feat(shell): AppShell orchestrator with persistent threat rail + collapse"
```

---

## Task 8: Wire the ⌘K command palette

Mount `CommandPalette` in `AppShell`, add the global ⌘K listener, and have `App` own the open-state and build the action list.

**Files:**
- Modify: `ui/src/components/layout/AppShell.tsx`
- Modify: `ui/src/App.tsx`

**Interfaces:**
- Consumes: `CommandPalette`, `PaletteAction` (Task 5).
- Produces: `AppShellProps` gains `paletteOpen: boolean; onPaletteOpenChange: (open: boolean) => void;`. `App` owns `paletteOpen`.

- [ ] **Step 1: App — palette state.** Add `const [paletteOpen, setPaletteOpen] = useState(false);`. Replace the Task-7 temporary `onOpenPalette={() => {}}` with `onOpenPalette={() => setPaletteOpen(true)}`, and add `paletteOpen={paletteOpen}` + `onPaletteOpenChange={setPaletteOpen}` to the `AppShell` render.

- [ ] **Step 2: AppShell — props + ⌘K listener.** Add `paletteOpen: boolean; onPaletteOpenChange: (open: boolean) => void;` to `AppShellProps`. Add the global shortcut:
```tsx
useEffect(() => {
  const onKey = (e: KeyboardEvent) => {
    if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) {
      e.preventDefault();
      if (!paletteOpen && !loadDialogOpen) onPaletteOpenChange(true);
    }
  };
  window.addEventListener("keydown", onKey);
  return () => window.removeEventListener("keydown", onKey);
}, [paletteOpen, loadDialogOpen, onPaletteOpenChange]);
```

- [ ] **Step 3: AppShell — build actions + mount the palette.** Just before the `return`, build the action list; mount `CommandPalette` after `LoadCaptureDialog`:
```tsx
const paletteActions: PaletteAction[] = [
  { id: "go-dashboard", label: "Go to Dashboard", hint: "view", run: () => onTabChange("dashboard") },
  { id: "go-flows", label: "Go to Flows", hint: "view", run: () => onTabChange("flows") },
  { id: "go-recent", label: "Go to Recent", hint: "view", run: () => onTabChange("recent") },
  { id: "load", label: "Load capture", hint: "action", run: onRequestLoad },
  { id: "toggle-rail", label: collapsed ? "Expand sidebar" : "Collapse sidebar", hint: "action", run: onToggleCollapse },
  ...(canExport ? [{ id: "export", label: "Export report", hint: "action", run: () => void handleExportClick() }] : []),
];
```
```tsx
<CommandPalette
  open={paletteOpen}
  onClose={() => onPaletteOpenChange(false)}
  actions={paletteActions}
  threats={threats}
  onSelectHost={onSelectThreat}
/>
```
Import `CommandPalette` and the `PaletteAction` type from `../../cockpit/CommandPalette`.

- [ ] **Step 4: Typecheck.** `npx tsc --noEmit -p tsconfig.json` → exit 0.

- [ ] **Step 5: Live check.** At `/`:
  - Press **⌘K / Ctrl+K** → palette opens, input focused. Type `flows` → "Go to Flows" highlighted; Enter → switches to Flows.
  - Type `10.13` → host rows for matching threats; ↓ to one, Enter → opens that host's incident flyout (or filters Flows if no incident).
  - Type `export` → runs the export. Esc / scrim closes the palette.
  - With no capture (desktop/idle), ⌘K still offers Load capture; host group shows the "load a capture" hint.
  - **Regression:** rail, tabs, load/export/recent, flows still work; no console errors.

- [ ] **Step 6: Verify the demo is still intact.** At `/cockpit.html`, the demo command bar + rail render unchanged (its ⌘K remains decorative — out of scope).

- [ ] **Step 7: Commit.**
```bash
git add ui/src/components/layout/AppShell.tsx ui/src/App.tsx
git commit -m "feat(palette): wire ⌘K command palette into the production shell"
```

---

## Final verification (after Task 8)

- [ ] `npx tsc --noEmit -p tsconfig.json` exit 0.
- [ ] Full live pass at `/` per the spec §8 checklist (rail, flyout, ⌘K + host jump, collapse + auto-collapse, regression of load/export/recent/flows).
- [ ] `/cockpit.html` demo unaffected.
- [ ] Screenshot the new shell for the PR.

---

## Self-review notes (author)

- **Spec coverage:** §3 layout → Task 7; §4.1 CommandBar → Task 4; §4.2 ThreatRail → Task 3; §4.3 CommandPalette → Task 5/8; §4.4 match → Task 2; §4.5 LoadCaptureDialog extract → Task 1; §4.6 AppShell → Task 7/8; §4.7 Dashboard controlled → Task 6; §4.8 App state/openThreat → Task 7/8; §6 edge cases → Tasks 6 (reset), 7 (no-incident fallback), 5/8 (empty palette); §7 responsive → Task 7 (auto-collapse). All covered.
- **Type consistency:** `selectedIncident: Incident | null` + `onSelectIncident` (Tasks 6/7/8); `openThreat(ip: string)` used by both rail (`onSelectThreat`) and palette (`onSelectHost`); `PaletteAction` shape consistent between Task 5 (definition) and Task 8 (construction). `FlowsInitialFilter.ip?: string` added in Task 7 Step 1a and consumed by `openThreat`'s fallback + `FlowsView`'s init effect.
- **No placeholders / open decisions remaining:** the Flows `ip`-filter gap is resolved concretely in Task 7 Step 1a (three exact edits).
