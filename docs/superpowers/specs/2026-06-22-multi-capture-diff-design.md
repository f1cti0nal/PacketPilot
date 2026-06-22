# Multi-Capture Diff — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-22
**Branch:** `feat/multi-capture-diff`

## Goal

Compare two analyzed captures and show what changed — new/removed threat IPs, new/removed incidents, and severity-count deltas — answering "what changed since last time?" over the captures already cached in the Recent tab.

## Architecture

Pure UI. A feasibility survey verified the Recent cache persists the **full `AnalysisOutput`** per capture (`ui/src/lib/recent.ts:91`, read via `listRecent()` at `recent.ts:30`), so both captures' diffable entities (`ip_threats[]`, `incidents[]`, `severity_counts`) are already in `localStorage` — no engine re-run, no IndexedDB read, no storage/schema change. Four pieces:

1. **Diff core** — a pure, unit-tested `ui/src/lib/diff.ts` (`diffSummaries`).
2. **Selection** — a multi-select mode in the Recent tab (`RecentView`/`RecentCard`).
3. **Compare view** — a new `compare` tab + `ui/src/views/CompareView.tsx` that reads the two cached summaries directly.
4. **Wiring** — `TabId += "compare"`, an `AppShell` tab + an `App.tsx` render branch, and a command-palette action.

**Tech stack:** React 18 + TypeScript + Tailwind (cockpit conventions: CSS vars, `t-tag`), Vitest + RTL + jsdom. No Rust changes, no new dependencies.

## Global Constraints

- **Pure UI. No engine/WASM/Tauri/storage/schema change.** The ONLY `ui/src/types.ts` change is adding `"compare"` to the `TabId` union (`types.ts:341`). The diff/compare types (`FieldDelta`, `DiffResult`, `SummaryDiff`, …) are defined and exported from `ui/src/lib/diff.ts`, co-located with the logic.
- **No new runtime dependencies.**
- **The `npm run test:coverage` gate stays green** (lines/functions/statements ≥ 80, branches ≥ 70). The diff core is pure and carries the bulk of the coverage. Verify under the locked toolchain (`npm ci` → `npm run build` → `npm run test:coverage`; CI uses vitest 1.6.1) before completion.
- **The diff is deterministic and order-stable** (same inputs → same output ordering) for testability.
- **Match cockpit styling** (CSS vars, `t-tag`, the existing severity palette `severityColor` from `ui/src/lib/palette.ts`) and reuse the transparency primitives where useful.
- **Stage specific files** on commit (never `git add -A`).

## Design Decisions (resolved)

1. **Selection model:** arbitrary two — select any 2 of the cached recent captures; no storage change. (Pin-a-baseline deferred.)
2. **Scope:** `IpThreat` (key `ip`) + `Incident` (key `host`) + `severity_counts` deltas. Findings, traffic rollups, and the time histogram are out of v1 (weak keys / per-capture rebucketing).
3. **Granularity:** entity-level add/remove, **plus field deltas for the `changed` group** (what got worse on an entity present in both).
4. **File mismatch:** allow the diff, with a dismissible "these may be unrelated captures" banner — driven by a **content** signal (zero shared IPs/hosts), not a fragile filename guess.
5. **Order:** the older capture (`analyzedAt`) is the baseline ("before"); a swap toggle flips before/after.

## Reference: existing types (`ui/src/types.ts`)

```ts
interface RecentEntry { id: string; name: string; path?: string; sizeBytes: number;
  sha256?: string; analyzedAt: number; engineVersion: string; origin: RecentOrigin;
  summary: AnalysisOutput; flowCount: number; flowsCached: boolean; }
// the Summary to diff is entry.summary.summary:
interface Summary { /* … */ ip_threats: IpThreat[]; incidents: Incident[]; severity_counts: SeverityCounts; /* … */ }
interface IpThreat { ip; ip_class; severity: Severity; score: number; flows; bytes; ioc: boolean;
  tags: string[]; attack: string[]; evidence: string[]; reputation?: ReputationVerdict[]; }
interface Incident { host; severity: Severity; score: number; title; narrative;
  stages: string[]; attack: string[]; findings: Finding[]; }
interface SeverityCounts { critical; high; medium; low; info: number; }
type TabId = "dashboard" | "flows" | "recent";   // → add "compare"
```

## Diff core — `ui/src/lib/diff.ts` (pure)

```ts
export interface FieldDelta { field: string; before: string | number; after: string | number; }
export interface Changed<T> { key: string; before: T; after: T; deltas: FieldDelta[]; }
export interface DiffResult<T> { added: T[]; removed: T[]; changed: Changed<T>[]; }
export interface SeverityDelta { band: keyof SeverityCounts; before: number; after: number; delta: number; }
export interface SummaryDiff {
  threats: DiffResult<IpThreat>;
  incidents: DiffResult<Incident>;
  severity: SeverityDelta[];   // always 5 bands, signed delta
  shared: number;              // count of entities (threats+incidents) present in BOTH (for the mismatch heuristic)
}
```

- **`diffByKey<T>(before, after, keyOf, deltasOf)`** — index both arrays by `keyOf`; `added` = key only in after, `removed` = key only in before, `changed` = key in both with a non-empty `deltasOf(before, after)`. Output ordering: `added`/`removed` keep their source order; `changed` ordered by key. Pure, generic.
- **`diffSummaries(before: Summary, after: Summary): SummaryDiff`** — applies `diffByKey` to `ip_threats` (key `ip`; `deltasOf` = score, severity, ioc, `tags`/`attack` set-diff, reputation worst-status change) and `incidents` (key `host`; `deltasOf` = score, severity, `stages` set-diff, `findings.length`); builds the 5 `SeverityDelta`s component-wise; sets `shared` = count of threat-ip + incident-host keys present in both.

## Selection — `RecentView` / `RecentCard`

Add `selectedIds: Set<string>` state to `RecentView`; render a selectable affordance (checkbox) on each `RecentCard`; a **"Compare"** button enables only when exactly **2 distinct** ids are selected and, on click, hands the pair (ordered older-first by `analyzedAt`) to the App and switches to the `compare` tab. Single-click "open" behavior is preserved when not in/again-after selection.

## `CompareView` — `ui/src/views/CompareView.tsx`

Props: the two capture ids (or the two `RecentEntry`s). It reads both from `listRecent()`; if either is missing (aged out of the ≤12 cache) → a graceful "capture no longer cached — re-open it from Recent" message. Otherwise computes `diffSummaries(before.summary.summary, after.summary.summary)` and renders:
- **Header:** both capture `name` + `analyzedAt`, "before → after" direction, and a **swap** toggle.
- **Mismatch banner (dismissible):** shown when `diff.shared === 0` and both captures are non-empty — "These captures share no threat IPs or hosts; they may be unrelated."
- **Severity-delta strip:** the 5 bands with signed deltas (e.g. `critical +2`, `low −5`), colored by band.
- **Threat IPs** and **Incidents** sections, each collapsible with **Added / Removed / Changed** groups. Added/removed rows reuse the existing threat/incident card visuals; `changed` rows show the `FieldDelta`s (e.g. `score 40→85`, `medium→critical`, `+IOC`). Empty diff (no added/removed/changed anywhere, severity all-zero) → a "No differences" state.
- `ThreatRail` is not rendered in compare mode.

## Wiring

- `ui/src/types.ts`: `TabId` gains `"compare"`.
- `ui/src/components/layout/AppShell.tsx`: add the `compare` tab to the tab list (`:132-136`) and a **"Compare captures"** `PaletteAction` (`:142-149`) that switches to the Recent tab in selection mode.
- `ui/src/App.tsx`: in the tab switch (`:448-478`), render `<CompareView .../>` when `tab === "compare"`; hold the `compareIds: [string, string] | null` state (set by the Recent "Compare" action) and the swap state.

## Data flow & error handling

`diffSummaries` is a pure function of two `Summary` objects already in the browser — no fetching, no async. Missing cached capture → graceful message (no crash). Same id selected twice is prevented by the selection UI (needs 2 distinct). Identical captures → "No differences". Empty `ip_threats`/`incidents` → empty groups render nothing.

## Testing

- **`diff.ts` unit tests (the bulk):** `diffByKey` added/removed/changed + ordering; `diffSummaries` over fixtures — a new threat IP (added), a gone one (removed), one that escalated (changed with `score`/`severity`/`ioc` deltas), an incident that gained a kill-chain stage, severity-band deltas, `shared` count; identical-input → empty diff; empty-input → empty.
- **`CompareView` render test:** added/removed/changed rows + the severity strip render; the mismatch banner shows when `shared===0`; "No differences" on identical; the swap toggle flips direction; a missing capture shows the graceful message.
- **`RecentView` selection test:** selecting 2 enables Compare; <2 or >2 disables it.
- Coverage stays ≥ 80/70.

## Out of scope (fast-follows)

- **Findings diff** (weak identity key on null-`dst_ip` fan-out sweeps).
- **Traffic rollups** (top talkers / protocols / ports) and the **time histogram** (adaptive per-capture buckets need rebucketing to be comparable).
- **Pin-a-baseline** (a pinned capture exempt from the 12-entry cache trim — a small `recent.ts` change).
- N-way / trend comparison across more than two captures.

## File manifest

**Create:** `ui/src/lib/diff.ts` + `diff.test.ts`; `ui/src/views/CompareView.tsx` + `CompareView.test.tsx`.
**Modify:** `ui/src/types.ts` (`TabId` union — add `"compare"`), `ui/src/components/recent/RecentView.tsx` (+ `RecentCard`) + a selection test, `ui/src/components/layout/AppShell.tsx` (tab + palette action), `ui/src/App.tsx` (compare tab render + state).
**No engine, WASM, Tauri, or storage change.**
