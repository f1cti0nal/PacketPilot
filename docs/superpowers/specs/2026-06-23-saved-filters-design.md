# Saved filter profiles — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-23
**Branch:** `feat/saved-filters`

## Goal

Persist + name flow filter sets so recurring hunts ("external C2 only, exclude CDNs") are one click, and shareable as JSON. No filter persistence exists today (only the recent-captures list).

## Architecture

A small `lib/filterProfiles.ts` (localStorage CRUD, mirroring `lib/recent.ts`) plus a compact `FilterProfiles` control in the FlowsView filter bar. A profile captures the four existing filter facets — `{ query, category, severity, proto }` — and applying one drives the existing FlowsView setters. **Pure UI: no engine, no WASM, no Tauri.** Fully verifiable with local vitest + tsc + build (no `build:wasm` content change) — well-suited while CI is billing-blocked.

**Tech stack:** React 18 + TS; Vitest. No new deps.

## Global Constraints

- **Pure UI** — no engine/WASM/Tauri change. The existing FlowsView filter state (`query: string`, `category: string`, `severity?: Severity`, `proto?: number`) and its setters/`clearFilters`/`hasActiveFilters` are the integration point; the FlowsTable + analysis pipeline are untouched.
- **Persistence mirrors `recent.ts`** — `localStorage` under a versioned key (`packetpilot.filterProfiles.v1`), all access try/catch-wrapped (parse/quota errors swallowed, never throw), JSON serialize/deserialize. No IndexedDB (profiles are tiny).
- **No new dependencies.** Reuse the existing `downloadText` helper (platform.ts) for JSON export + a hidden `<input type=file>` for import.
- **Resilient import** — a malformed/oversized import file is rejected with a non-throwing notice; nothing is persisted on failure. Imported profiles merge by `name` (a same-name import overwrites that profile).
- **Coverage gate** stays green (80/70) under the locked toolchain (vitest 1.6.1). Stage specific files.

## Reference: the seams (verified)

```ts
// ui/src/views/FlowsView.tsx:47-50  const [query,setQuery]=useState(""); [category,setCategory]=useState(ALL_CATEGORIES);
//   [severity,setSeverity]=useState<Severity|undefined>(undefined); [proto,setProto]=useState<number|undefined>(undefined);
//   :184 hasActiveFilters = (query!=="" || category!==ALL_CATEGORIES || severity!==undefined || proto!==undefined)
//   :190 clearFilters = () => { setQuery(""); setCategory(ALL_CATEGORIES); setSeverity(undefined); setProto(undefined); }
//   the filter bar JSX renders the query input + category/severity/proto selects + the clear control (attach Profiles next to it)
// ui/src/lib/recent.ts:17 RECENT_KEY="packetpilot.recent.v1" ; :30 listRecent(){ localStorage.getItem; JSON.parse (try/catch) } ; :46 persist(){ localStorage.setItem(JSON.stringify) (try/catch w/ quota trim) } ; :115 clearRecent(){ removeItem }
// ui/src/lib/platform.ts downloadText(content, filename, mime)  (blob + anchor)
// ui/src/types.ts Severity  ; ui/src/views/FlowsView.tsx ALL_CATEGORIES sentinel + the category token set
```

## Components

### 1. `ui/src/lib/filterProfiles.ts` (new)
```ts
export interface FlowFilter { query: string; category: string; severity?: Severity; proto?: number }
export interface FilterProfile { id: string; name: string; filter: FlowFilter }

export function listProfiles(): FilterProfile[];            // localStorage get + JSON.parse, try/catch → []
export function saveProfile(name: string, filter: FlowFilter): FilterProfile[]; // upsert by trimmed name; id = a stable slug/counter; persist; returns the new list
export function removeProfile(id: string): FilterProfile[];
export function clearProfiles(): FilterProfile[];
export function serializeProfiles(): string;                // JSON.stringify(listProfiles()) for export
export function importProfiles(json: string): { ok: boolean; profiles: FilterProfile[]; message: string }; // parse + validate each entry (name:string, filter shape); merge-by-name into the stored list; never throws
```
Key `packetpilot.filterProfiles.v1`; persist try/catch like `recent.ts::persist`. Validation drops entries whose shape is wrong rather than failing the whole import (report how many imported).

### 2. `ui/src/components/flows/FilterProfiles.tsx` (new)
A "Profiles ▾" dropdown button for the filter bar. Props: `{ current: FlowFilter; hasActiveFilters: boolean; onApply: (f: FlowFilter) => void; onNotice?: (msg: string) => void }`. Renders:
- the saved profiles list (click a row → `onApply(profile.filter)`), with a per-row delete (×).
- "Save current filters…" — prompts for a name (a small inline input or `window.prompt`), calls `saveProfile(name, current)`; disabled when `!hasActiveFilters`.
- "Export JSON" → `downloadText(serializeProfiles(), "packetpilot-filters.json", "application/json")`; "Import JSON" → a hidden file input → read text → `importProfiles(text)` → refresh the list + `onNotice` the result.
- empty-state text when no profiles saved.
Local component state holds the list (re-read from `listProfiles()` after each mutation). Matches cockpit styling (`t-tag`/border tokens).

### 3. FlowsView wiring
Render `<FilterProfiles current={{ query, category, severity, proto }} hasActiveFilters={hasActiveFilters} onApply={applyProfile} onNotice={setNotice} />` in the filter bar next to the clear-filters control. `applyProfile(f)` = `setQuery(f.query); setCategory(f.category); setSeverity(f.severity); setProto(f.proto)`. Surface `onNotice` via a small transient line (reuse an existing notice mechanism, or a local state shown in the bar).

## Data flow & error handling

Save → localStorage (per-browser; survives reload). Apply → the four FlowsView setters → the existing filter pipeline re-runs. Export → JSON blob download. Import → file read → `importProfiles` validates each entry, merges by name, persists; a malformed/non-JSON file → `{ ok:false, message }` surfaced via `onNotice`, nothing persisted. Quota/parse errors swallowed like `recent.ts`. No profiles → the dropdown shows an empty state; "Save current" is the only enabled action (when filters are active).

## Testing

- **`filterProfiles.ts`:** save → list round-trip; upsert-by-name (saving the same name twice keeps one, updated); remove; clear; `serializeProfiles` → `importProfiles` round-trip restores the set; a malformed import (`"{"`, or `[{bad}]`) → `{ ok:false }` and the store unchanged; partial import (one valid + one invalid entry) imports the valid one + reports; the v1 key is used. (Use jsdom localStorage; clear between tests.)
- **`FilterProfiles.tsx`:** applying a profile calls `onApply` with its filter; "Save current" (with active filters) persists + the row appears; "Save current" disabled when `!hasActiveFilters`; delete removes a row; empty-state when none; export triggers a download (spy the anchor click).
- Coverage ≥ 80/70 under the locked toolchain.

## Out of scope

- Cross-device sync / IndexedDB; capturing sort or row-selection in a profile; per-profile share URLs; saved filters for other views (Dashboard/Recent); a settings page for managing them (the dropdown is the surface).

## File manifest

**UI — create:** `ui/src/lib/filterProfiles.ts`, `ui/src/components/flows/FilterProfiles.tsx` (+ co-located tests).
**UI — modify:** `ui/src/views/FlowsView.tsx` (render the control + `applyProfile` + a notice line).
**No engine/WASM/Tauri change, no new deps.**
