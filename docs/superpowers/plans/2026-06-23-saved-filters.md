# Saved filter profiles — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist + name flow filter sets so recurring hunts are one click, and shareable as JSON.

**Architecture:** A `lib/filterProfiles.ts` (localStorage CRUD, mirroring `recent.ts`) + a `FilterProfiles` dropdown in the FlowsView filter bar. A profile captures `{ query, category, severity, proto }` and applying it drives the existing FlowsView setters. Pure UI — no engine/WASM/Tauri.

**Tech Stack:** React 18 + TS; Vitest. No new deps.

## Global Constraints

- **Pure UI** — no engine/WASM/Tauri change; the FlowsView filter state + setters are the only integration point.
- **localStorage, versioned key `packetpilot.filterProfiles.v1`**, all access try/catch-wrapped (never throws), JSON serialize/deserialize — mirror `recent.ts`. No IndexedDB.
- **No new deps.** JSON export reuses `downloadText` (platform.ts); import via a hidden file input.
- **Resilient import** — malformed file → a non-throwing notice, nothing persisted; valid entries merge by `name`.
- Coverage gate ≥ 80/70 under the locked toolchain (vitest 1.6.1). Stage specific files. node at `/c/Program Files/nodejs`; do NOT `npm install`.

## Reference: the seams (verbatim, verified)

```ts
// ui/src/views/FlowsView.tsx:47 const [query,setQuery]=useState(""); :48 [category,setCategory]=useState(ALL_CATEGORIES);
//   :49 [severity,setSeverity]=useState<Severity|undefined>(undefined); :50 [proto,setProto]=useState<number|undefined>(undefined);
//   :184 hasActiveFilters (query!=="" || category!==ALL_CATEGORIES || severity!==undefined || proto!==undefined)
//   :190 clearFilters = () => { setQuery(""); setCategory(ALL_CATEGORIES); setSeverity(undefined); setProto(undefined); }
//   ALL_CATEGORIES is a module sentinel string ; the filter bar JSX renders the query input + selects + a clear control
// ui/src/lib/recent.ts:17 const RECENT_KEY="packetpilot.recent.v1"
//   :30 listRecent(){ try{ const raw=localStorage.getItem(RECENT_KEY); if(!raw) return []; const parsed=JSON.parse(raw); … } catch { return []; } }
//   :46 persist(list){ try{ localStorage.setItem(RECENT_KEY, JSON.stringify(list)); } catch { /* quota: trim + retry */ } }
//   :115 clearRecent(){ try{ localStorage.removeItem(RECENT_KEY); } catch {} ; return []; }
// ui/src/lib/platform.ts downloadText(content, filename, mime)
// ui/src/types.ts  Severity
```

---

### Task 1: `lib/filterProfiles.ts`

**Files:**
- Create: `ui/src/lib/filterProfiles.ts`, `ui/src/lib/filterProfiles.test.ts`

**Interfaces:**
- Produces: `FlowFilter`, `FilterProfile`, `listProfiles`, `saveProfile`, `removeProfile`, `clearProfiles`, `serializeProfiles`, `importProfiles`.

- [ ] **Step 1: Write the failing test** — `ui/src/lib/filterProfiles.test.ts`:

```ts
import { describe, it, expect, beforeEach } from "vitest";
import {
  listProfiles, saveProfile, removeProfile, clearProfiles, serializeProfiles, importProfiles,
  type FlowFilter,
} from "./filterProfiles";

const f = (over: Partial<FlowFilter> = {}): FlowFilter => ({ query: "10.0.0.5", category: "c2", severity: undefined, proto: undefined, ...over });

describe("filterProfiles", () => {
  beforeEach(() => localStorage.clear());

  it("saves and lists, persisting under the v1 key", () => {
    saveProfile("C2 hunt", f());
    expect(listProfiles().map((p) => p.name)).toEqual(["C2 hunt"]);
    expect(localStorage.getItem("packetpilot.filterProfiles.v1")).toContain("C2 hunt");
  });

  it("upserts by name (same name keeps one, updated filter)", () => {
    saveProfile("hunt", f({ query: "a" }));
    saveProfile("hunt", f({ query: "b" }));
    const list = listProfiles();
    expect(list).toHaveLength(1);
    expect(list[0].filter.query).toBe("b");
  });

  it("removes and clears", () => {
    const list = saveProfile("x", f());
    expect(removeProfile(list[0].id)).toHaveLength(0);
    saveProfile("y", f());
    expect(clearProfiles()).toHaveLength(0);
    expect(listProfiles()).toHaveLength(0);
  });

  it("round-trips via serialize/import", () => {
    saveProfile("p1", f({ query: "one" }));
    saveProfile("p2", f({ query: "two", severity: "high" as any }));
    const json = serializeProfiles();
    localStorage.clear();
    const res = importProfiles(json);
    expect(res.ok).toBe(true);
    expect(listProfiles().map((p) => p.name).sort()).toEqual(["p1", "p2"]);
  });

  it("rejects malformed import without throwing or persisting", () => {
    saveProfile("keep", f());
    const res = importProfiles("{ not json");
    expect(res.ok).toBe(false);
    expect(listProfiles().map((p) => p.name)).toEqual(["keep"]); // unchanged
  });

  it("imports valid entries and skips invalid ones", () => {
    const res = importProfiles(JSON.stringify([
      { id: "a", name: "good", filter: { query: "q", category: "web" } },
      { id: "b", name: "", filter: { query: "x", category: "web" } }, // invalid: empty name
      { nope: true },                                                  // invalid: wrong shape
    ]));
    expect(res.ok).toBe(true);
    expect(listProfiles().map((p) => p.name)).toEqual(["good"]);
  });
});
```

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/lib/filterProfiles.test.ts` → FAIL (module not found).

- [ ] **Step 3: Implement** — `ui/src/lib/filterProfiles.ts`:

```ts
import type { Severity } from "../types";

/** The persisted subset of FlowsView filter state. */
export interface FlowFilter {
  query: string;
  category: string;
  severity?: Severity;
  proto?: number;
}

/** A named, saved filter set. */
export interface FilterProfile {
  id: string;
  name: string;
  filter: FlowFilter;
}

const KEY = "packetpilot.filterProfiles.v1";

/** Read the saved profiles; any parse error yields an empty list (never throws). */
export function listProfiles(): FilterProfile[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isProfile);
  } catch {
    return [];
  }
}

function persist(list: FilterProfile[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(list));
  } catch {
    /* quota or serialization error: drop silently, like recent.ts */
  }
}

/** Validate an unknown value as a FilterProfile (name non-empty, filter shape sound). */
function isProfile(v: unknown): v is FilterProfile {
  if (typeof v !== "object" || v === null) return false;
  const p = v as Record<string, unknown>;
  if (typeof p.name !== "string" || p.name.trim() === "") return false;
  const fl = p.filter as Record<string, unknown> | undefined;
  if (typeof fl !== "object" || fl === null) return false;
  if (typeof fl.query !== "string" || typeof fl.category !== "string") return false;
  return true;
}

/** Upsert a profile by trimmed name; returns the new list. */
export function saveProfile(name: string, filter: FlowFilter): FilterProfile[] {
  const trimmed = name.trim();
  if (trimmed === "") return listProfiles();
  const list = listProfiles().filter((p) => p.name !== trimmed);
  list.push({ id: `fp_${trimmed.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`, name: trimmed, filter });
  persist(list);
  return list;
}

export function removeProfile(id: string): FilterProfile[] {
  const list = listProfiles().filter((p) => p.id !== id);
  persist(list);
  return list;
}

export function clearProfiles(): FilterProfile[] {
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
  return [];
}

/** JSON for export (the full profile array). */
export function serializeProfiles(): string {
  return JSON.stringify(listProfiles(), null, 2);
}

/** Import profiles from JSON: validate each entry, merge by name into the store. Never throws. */
export function importProfiles(json: string): { ok: boolean; profiles: FilterProfile[]; message: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return { ok: false, profiles: listProfiles(), message: "Not valid JSON" };
  }
  if (!Array.isArray(parsed)) {
    return { ok: false, profiles: listProfiles(), message: "Expected a JSON array of profiles" };
  }
  const incoming = parsed.filter(isProfile);
  if (incoming.length === 0) {
    return { ok: false, profiles: listProfiles(), message: "No valid profiles in file" };
  }
  const byName = new Map(listProfiles().map((p) => [p.name, p]));
  for (const p of incoming) byName.set(p.name, p);
  const merged = [...byName.values()];
  persist(merged);
  return { ok: true, profiles: merged, message: `Imported ${incoming.length} profile${incoming.length === 1 ? "" : "s"}` };
}
```

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/lib/filterProfiles.test.ts` → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 5: Commit**

```bash
git add ui/src/lib/filterProfiles.ts ui/src/lib/filterProfiles.test.ts
git commit -m "feat(ui): filterProfiles localStorage CRUD + JSON import/export"
```

---

### Task 2: `FilterProfiles` component + FlowsView wiring

**Files:**
- Create: `ui/src/components/flows/FilterProfiles.tsx`, `ui/src/components/flows/FilterProfiles.test.tsx`
- Modify: `ui/src/views/FlowsView.tsx` (render the control + `applyProfile` + a notice line)

**Interfaces:**
- Consumes: `filterProfiles` (T1); the FlowsView filter state + setters.
- Produces: `FilterProfiles({ current, hasActiveFilters, onApply, onNotice })`.

- [ ] **Step 1: Write the failing test** — `ui/src/components/flows/FilterProfiles.test.tsx`:

```tsx
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { FilterProfiles } from "./FilterProfiles";
import { saveProfile, type FlowFilter } from "../../lib/filterProfiles";

const cur: FlowFilter = { query: "1.2.3.4", category: "c2", severity: undefined, proto: undefined };

describe("FilterProfiles", () => {
  beforeEach(() => localStorage.clear());

  it("applies a saved profile via onApply", () => {
    saveProfile("C2", { query: "9.9.9.9", category: "c2" });
    const onApply = vi.fn();
    render(<FilterProfiles current={cur} hasActiveFilters onApply={onApply} />);
    fireEvent.click(screen.getByText("Profiles")); // open the menu
    fireEvent.click(screen.getByText("C2"));
    expect(onApply).toHaveBeenCalledWith(expect.objectContaining({ query: "9.9.9.9", category: "c2" }));
  });

  it("save-current persists the active filter", () => {
    render(<FilterProfiles current={cur} hasActiveFilters onApply={vi.fn()} />);
    fireEvent.click(screen.getByText("Profiles"));
    // the implementation may use a prompt or an inline input; drive whichever it uses to save "hunt"
    // then assert the row appears + localStorage has it:
    // (adapt the interaction to the real Save UI)
  });

  it("save-current is disabled with no active filters", () => {
    render(<FilterProfiles current={cur} hasActiveFilters={false} onApply={vi.fn()} />);
    fireEvent.click(screen.getByText("Profiles"));
    expect(screen.getByText(/save current/i).closest("button")).toBeDisabled();
  });
});
```

> NOTE: pick a concrete Save UI (an inline `<input>` + a Save button is more testable than `window.prompt`). Make the test drive that exact interaction. Match the existing test style for the menu open/close (the cockpit dropdowns — e.g. CommandPalette/ExportMenu tests — for the open pattern).

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/components/flows/FilterProfiles.test.tsx` → FAIL.

- [ ] **Step 3: Implement** — `ui/src/components/flows/FilterProfiles.tsx`: a "Profiles ▾" button toggling a dropdown (mirror the `ExportMenu` open/outside-click pattern — read it). Local state `const [profiles, setProfiles] = useState(listProfiles())`; a `refresh = () => setProfiles(listProfiles())`. Contents:
- a list of `profiles`: each row a button `onClick={() => onApply(p.filter)}` + a small `×` `onClick={() => { setProfiles(removeProfile(p.id)); }}`. Empty-state text when none.
- a "Save current filters…" row: an inline `<input>` (name) + a Save button `disabled={!hasActiveFilters || name.trim()===""}` → `setProfiles(saveProfile(name, current)); setName("")`.
- "Export JSON" → `downloadText(serializeProfiles(), "packetpilot-filters.json", "application/json")` (import `downloadText`; if it's not exported from platform.ts, export it or inline a tiny blob-download). "Import JSON" → a hidden `<input type="file" accept=".json">`; on change read the file text → `const res = importProfiles(text); refresh(); onNotice?.(res.message)`.

Props: `{ current: FlowFilter; hasActiveFilters: boolean; onApply: (f: FlowFilter) => void; onNotice?: (msg: string) => void }`. Cockpit styling (`t-tag`, border/`--color-*` tokens).

Then `FlowsView.tsx`: add a `const [notice, setNotice] = useState<string | null>(null)`; render `<FilterProfiles current={{ query, category, severity, proto }} hasActiveFilters={hasActiveFilters} onApply={applyProfile} onNotice={setNotice} />` in the filter bar next to the clear control; `const applyProfile = useCallback((f: FlowFilter) => { setQuery(f.query); setCategory(f.category); setSeverity(f.severity); setProto(f.proto); }, [])`; show `notice` as a small transient line in the bar (and clear it on the next filter change, or after a timeout — keep it simple, e.g. render it when non-null).

> NOTE: confirm `downloadText` is exported from `platform.ts` (it's currently a module-private helper — export it, or add a tiny local blob-download in the component). Reuse the real `ExportMenu`/dropdown open+outside-click pattern. `FlowFilter`'s `category` uses the same token space as FlowsView's `category` state (the `ALL_CATEGORIES` sentinel is a valid saved value).

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/components/flows/FilterProfiles.test.tsx src/views` (the FlowsView tests too) → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 5: Commit**

```bash
git add ui/src/components/flows/FilterProfiles.tsx ui/src/components/flows/FilterProfiles.test.tsx ui/src/views/FlowsView.tsx ui/src/lib/platform.ts
git commit -m "feat(ui): FilterProfiles dropdown in the flows filter bar"
```

---

### Task 3: Full gate

- [ ] **Step 1: UI gate** — `cd ui && export PATH="/c/Program Files/nodejs:/c/Users/ravid/.cargo/bin:$PATH"`:
```bash
git diff --stat package.json package-lock.json
git checkout -- package.json package-lock.json 2>/dev/null || true
npm ci
node -p "require('./node_modules/vitest/package.json').version"   # 1.6.1
npm run build:wasm      # (unchanged content; needed so `npm run build` resolves the wasm bundle)
npm run build; echo "build EXIT: $?"          # EXIT 0
npm run test:coverage; echo "cov EXIT: $?"    # EXIT 0; All files >= 80/70 — paste it
```
Do NOT `npm install`.

- [ ] **Step 2: Engine gate (sanity — should be untouched)** — confirm no engine files changed: `git diff --name-only main..HEAD -- engine/ | head` → empty. (No engine build needed for a pure-UI feature.)

- [ ] **Step 3: Fill any gap** — if a metric dips from the new component/lib, add a focused test (e.g. the import/export round-trip in the component; the empty-state) and re-run step 1.

- [ ] **Step 4: Commit** (if tests added)

```bash
git add ui/src/<new/updated tests>
git commit -m "test(ui): hold the coverage gate for saved filter profiles"
```

---

## Self-Review

**1. Spec coverage:** the `filterProfiles` lib (T1) → spec §1; the `FilterProfiles` component + FlowsView wiring (T2) → §2-3; gate (T3) → constraints/testing. localStorage v1 key, resilient import, no new deps, pure-UI, JSON export/import — all covered. Cross-device/IndexedDB out of scope. ✓

**2. Placeholder scan:** complete code for the lib; the component is specified concretely (the brief gives the exact props, the dropdown contents, the save/apply/delete/export/import behaviors). The NOTEs (pick a testable Save UI, reuse ExportMenu's open pattern, export `downloadText`) are concrete in-repo verifications. ✓

**3. Type consistency:** `FlowFilter { query, category, severity?, proto? }` (T1) ⇄ FlowsView's `{ query, category, severity, proto }` state ⇄ `FilterProfiles` `current`/`onApply` (T2) ⇄ `applyProfile` calls the four setters. `FilterProfile { id, name, filter }` persisted/serialized/imported consistently. `localStorage` key `packetpilot.filterProfiles.v1` everywhere. ✓
