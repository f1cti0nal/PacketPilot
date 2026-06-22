# Multi-Capture Diff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compare two analyzed captures over the already-cached Recent data — new/removed threat IPs, new/removed incidents, severity-count deltas, with field deltas for changed entities.

**Architecture:** Pure UI. A pure `ui/src/lib/diff.ts` (`diffSummaries`) computes the diff from two `Summary` objects already in the Recent localStorage cache; a multi-select mode in the Recent tab hands a capture pair to a new `compare` tab + `ui/src/views/CompareView.tsx`. No engine/WASM/Tauri/storage change; the only `types.ts` touch is adding `"compare"` to `TabId`.

**Tech Stack:** React 18 + TypeScript + Tailwind (cockpit: CSS vars, `t-tag`, `severityColor` from `ui/src/lib/palette.ts`), Vitest + React Testing Library + jsdom.

## Global Constraints

- **Pure UI. No engine/WASM/Tauri/storage/schema change.** Only `ui/src/types.ts` change: add `"compare"` to the `TabId` union. Diff/compare types live in `ui/src/lib/diff.ts`.
- **No new runtime dependencies.**
- **`npm run test:coverage` gate stays green** (lines/functions/statements ≥ 80, branches ≥ 70). The diff core is pure and carries the bulk of coverage. Verify under the locked toolchain (`npm ci` → `npm run build` → `npm run test:coverage`; CI uses vitest 1.6.1) before completion.
- **The diff is deterministic + order-stable**: `added`/`removed` keep source order; `changed` is sorted by key.
- **Match cockpit styling** (CSS vars, `t-tag`, `font-mono-num`, `severityColor`).
- **TOOLCHAIN:** node/npx at `/c/Program Files/nodejs/`. Tests: `cd ui && npx vitest run <path>`. Do NOT run `npm install` (re-drifts the lock; node_modules is pre-provisioned).
- **Stage specific files** on commit (never `git add -A`).

## Reference: existing types (`ui/src/types.ts`, no change except TabId)

```ts
interface IpThreat { ip: string; ip_class; severity: Severity; score: number; flows; bytes;
  ioc: boolean; tags: string[]; attack: string[]; evidence: string[]; reputation?: ReputationVerdict[]; }
interface Incident { host: string; severity: Severity; score: number; title; narrative;
  stages: string[]; attack: string[]; findings: Finding[]; }
interface SeverityCounts { critical: number; high: number; medium: number; low: number; info: number; }
interface Summary { /* … */ ip_threats: IpThreat[]; incidents: Incident[]; severity_counts: SeverityCounts; /* … */ }
interface AnalysisOutput { /* … */ summary: Summary; }
interface RecentEntry { id: string; name: string; sha256?: string; analyzedAt: number;
  summary: AnalysisOutput; /* … */ }     // the Summary to diff is entry.summary.summary
type TabId = "dashboard" | "flows" | "recent";   // → add "compare"
```

---

### Task 1: Diff core — `ui/src/lib/diff.ts`

**Files:**
- Create: `ui/src/lib/diff.ts`
- Test: `ui/src/lib/diff.test.ts`

**Interfaces:**
- Produces: `diffByKey<T>(before, after, keyOf, deltasOf): DiffResult<T>`; `diffSummaries(before: Summary, after: Summary): SummaryDiff`; types `FieldDelta`, `Changed<T>`, `DiffResult<T>`, `SeverityDelta`, `SummaryDiff`.

- [ ] **Step 1: Write the failing test** — `ui/src/lib/diff.test.ts`

```ts
import { describe, it, expect } from "vitest";
import { diffByKey, diffSummaries } from "./diff";
import type { IpThreat, Incident, Summary, SeverityCounts } from "../types";

const sev = (o: Partial<SeverityCounts> = {}): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0, ...o });
const summary = (over: Partial<Summary>): Summary =>
  ({ ip_threats: [], incidents: [], severity_counts: sev(), ...over } as Summary);
const threat = (o: Partial<IpThreat>): IpThreat =>
  ({ ip: "1.1.1.1", ip_class: "public", severity: "low", score: 10, flows: 1, bytes: 1,
     ioc: false, tags: [], attack: [], evidence: [], ...o } as IpThreat);
const incident = (o: Partial<Incident>): Incident =>
  ({ host: "10.0.0.1", severity: "low", score: 10, title: "t", narrative: "n",
     stages: [], attack: [], findings: [], ...o } as Incident);

describe("diffByKey", () => {
  it("splits into added / removed / changed and sorts changed by key", () => {
    const r = diffByKey(
      [{ k: "a", v: 1 }, { k: "b", v: 2 }],
      [{ k: "b", v: 9 }, { k: "c", v: 3 }],
      (x) => x.k,
      (a, b) => (a.v !== b.v ? [{ field: "v", before: a.v, after: b.v }] : []),
    );
    expect(r.added.map((x) => x.k)).toEqual(["c"]);
    expect(r.removed.map((x) => x.k)).toEqual(["a"]);
    expect(r.changed).toHaveLength(1);
    expect(r.changed[0]).toMatchObject({ key: "b", deltas: [{ field: "v", before: 2, after: 9 }] });
  });
});

describe("diffSummaries", () => {
  it("diffs threats by ip with field deltas, incidents by host, and severity bands", () => {
    const before = summary({
      ip_threats: [threat({ ip: "1.1.1.1", score: 40, severity: "medium" }), threat({ ip: "2.2.2.2" })],
      incidents: [incident({ host: "h1", stages: ["Discovery"] })],
      severity_counts: sev({ critical: 1, low: 5 }),
    });
    const after = summary({
      ip_threats: [threat({ ip: "1.1.1.1", score: 85, severity: "critical", ioc: true }), threat({ ip: "9.9.9.9" })],
      incidents: [incident({ host: "h1", stages: ["Discovery", "Command & Control"] })],
      severity_counts: sev({ critical: 3, low: 0 }),
    });
    const d = diffSummaries(before, after);
    expect(d.threats.added.map((t) => t.ip)).toEqual(["9.9.9.9"]);
    expect(d.threats.removed.map((t) => t.ip)).toEqual(["2.2.2.2"]);
    expect(d.threats.changed[0].key).toBe("1.1.1.1");
    expect(d.threats.changed[0].deltas).toEqual(expect.arrayContaining([
      { field: "score", before: 40, after: 85 },
      { field: "severity", before: "medium", after: "critical" },
      { field: "ioc", before: "no", after: "yes" },
    ]));
    expect(d.incidents.changed[0].deltas).toEqual(expect.arrayContaining([
      { field: "stages", before: "Discovery", after: "Command & Control,Discovery" },
    ]));
    expect(d.severity.find((s) => s.band === "critical")).toMatchObject({ before: 1, after: 3, delta: 2 });
    expect(d.shared).toBe(2); // ip 1.1.1.1 + host h1 present in both
  });

  it("returns an empty diff for identical inputs", () => {
    const s = summary({ ip_threats: [threat({ ip: "1.1.1.1" })], incidents: [incident({ host: "h1" })] });
    const d = diffSummaries(s, s);
    expect(d.threats.added).toHaveLength(0);
    expect(d.threats.removed).toHaveLength(0);
    expect(d.threats.changed).toHaveLength(0);
    expect(d.severity.every((b) => b.delta === 0)).toBe(true);
  });
});
```

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/lib/diff.test.ts` → FAIL (module not found).

- [ ] **Step 3: Implement** — `ui/src/lib/diff.ts`

```ts
import type { IpThreat, Incident, Summary, SeverityCounts, RepStatus } from "../types";

export interface FieldDelta { field: string; before: string | number; after: string | number; }
export interface Changed<T> { key: string; before: T; after: T; deltas: FieldDelta[]; }
export interface DiffResult<T> { added: T[]; removed: T[]; changed: Changed<T>[]; }
export interface SeverityDelta { band: keyof SeverityCounts; before: number; after: number; delta: number; }
export interface SummaryDiff {
  threats: DiffResult<IpThreat>;
  incidents: DiffResult<Incident>;
  severity: SeverityDelta[];
  /** Count of entities (threat IPs + incident hosts) present in BOTH captures. */
  shared: number;
}

/** Generic keyed diff: added = key only in `after`, removed = key only in `before`, changed = key in both with deltas. */
export function diffByKey<T>(
  before: T[],
  after: T[],
  keyOf: (t: T) => string,
  deltasOf: (before: T, after: T) => FieldDelta[],
): DiffResult<T> {
  const beforeMap = new Map(before.map((t) => [keyOf(t), t]));
  const afterMap = new Map(after.map((t) => [keyOf(t), t]));
  const added = after.filter((t) => !beforeMap.has(keyOf(t)));
  const removed = before.filter((t) => !afterMap.has(keyOf(t)));
  const changed: Changed<T>[] = [];
  for (const [key, b] of beforeMap) {
    const a = afterMap.get(key);
    if (!a) continue;
    const deltas = deltasOf(b, a);
    if (deltas.length > 0) changed.push({ key, before: b, after: a, deltas });
  }
  changed.sort((x, y) => (x.key < y.key ? -1 : x.key > y.key ? 1 : 0));
  return { added, removed, changed };
}

/** A field delta for a sorted set comparison, or null when the sets are equal. */
function setDelta(field: string, before: string[], after: string[]): FieldDelta | null {
  const b = [...before].sort().join(",");
  const a = [...after].sort().join(",");
  if (b === a) return null;
  return { field, before: b || "(none)", after: a || "(none)" };
}

const REP_RANK: Record<RepStatus, number> = { malicious: 5, benign: 4, unknown: 3, clean: 2, notfound: 1, unavailable: 0 };
function worstRep(t: IpThreat): string {
  if (!t.reputation || t.reputation.length === 0) return "";
  return [...t.reputation].sort((x, y) => REP_RANK[y.status] - REP_RANK[x.status])[0].status;
}

function threatDeltas(before: IpThreat, after: IpThreat): FieldDelta[] {
  const d: FieldDelta[] = [];
  if (before.score !== after.score) d.push({ field: "score", before: before.score, after: after.score });
  if (before.severity !== after.severity) d.push({ field: "severity", before: before.severity, after: after.severity });
  if (before.ioc !== after.ioc) d.push({ field: "ioc", before: before.ioc ? "yes" : "no", after: after.ioc ? "yes" : "no" });
  const tags = setDelta("tags", before.tags, after.tags); if (tags) d.push(tags);
  const attack = setDelta("attack", before.attack, after.attack); if (attack) d.push(attack);
  const rb = worstRep(before), ra = worstRep(after);
  if (rb !== ra) d.push({ field: "reputation", before: rb || "(none)", after: ra || "(none)" });
  return d;
}

function incidentDeltas(before: Incident, after: Incident): FieldDelta[] {
  const d: FieldDelta[] = [];
  if (before.score !== after.score) d.push({ field: "score", before: before.score, after: after.score });
  if (before.severity !== after.severity) d.push({ field: "severity", before: before.severity, after: after.severity });
  const stages = setDelta("stages", before.stages, after.stages); if (stages) d.push(stages);
  if (before.findings.length !== after.findings.length)
    d.push({ field: "findings", before: before.findings.length, after: after.findings.length });
  return d;
}

const SEV_BANDS: (keyof SeverityCounts)[] = ["critical", "high", "medium", "low", "info"];

export function diffSummaries(before: Summary, after: Summary): SummaryDiff {
  const threats = diffByKey(before.ip_threats, after.ip_threats, (t) => t.ip, threatDeltas);
  const incidents = diffByKey(before.incidents, after.incidents, (i) => i.host, incidentDeltas);
  const severity: SeverityDelta[] = SEV_BANDS.map((band) => {
    const b = before.severity_counts[band] ?? 0;
    const a = after.severity_counts[band] ?? 0;
    return { band, before: b, after: a, delta: a - b };
  });
  const beforeKeys = new Set<string>([
    ...before.ip_threats.map((t) => `ip:${t.ip}`),
    ...before.incidents.map((i) => `host:${i.host}`),
  ]);
  let shared = 0;
  for (const t of after.ip_threats) if (beforeKeys.has(`ip:${t.ip}`)) shared++;
  for (const i of after.incidents) if (beforeKeys.has(`host:${i.host}`)) shared++;
  return { threats, incidents, severity, shared };
}
```

> NOTE: confirm `RepStatus` is exported from `ui/src/types.ts` (it is — used by `ReputationVerdict`). If the `Summary` interface uses a different field name than `ip_threats`/`incidents`/`severity_counts`, adjust to the real names (check `types.ts`).

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/lib/diff.test.ts` → PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add ui/src/lib/diff.ts ui/src/lib/diff.test.ts
git commit -m "feat(diff): pure diffSummaries core for multi-capture compare"
```

---

### Task 2: Recent multi-select → Compare

**Files:**
- Modify: `ui/src/components/recent/RecentView.tsx` (`RecentViewProps`, `RecentCard`, `RecentView`)
- Test: `ui/src/components/recent/RecentView.test.tsx` (create)

**Interfaces:**
- Produces: `RecentViewProps` gains `onCompare?: (beforeId: string, afterId: string) => void` — called with the two selected ids ordered older-first by `analyzedAt`.

- [ ] **Step 1: Write the failing test** — `ui/src/components/recent/RecentView.test.tsx`

```tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { RecentView } from "./RecentView";
import type { RecentEntry } from "../../types";

const entry = (id: string, analyzedAt: number): RecentEntry =>
  ({ id, name: id, sizeBytes: 1, analyzedAt, engineVersion: "x", origin: "browser",
     flowCount: 1, flowsCached: false,
     summary: { summary: { ip_threats: [], incidents: [], severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } } } } as unknown as RecentEntry);

const noop = () => {};

describe("RecentView compare selection", () => {
  it("enables Compare only at exactly 2 selections and calls onCompare older-first", async () => {
    const user = userEvent.setup();
    const onCompare = vi.fn();
    render(
      <RecentView
        entries={[entry("new", 200), entry("old", 100)]}
        onOpen={noop} onReanalyze={noop} onRemove={noop} onClear={noop} onLoadNew={noop}
        onCompare={onCompare}
      />,
    );
    const compareBtn = screen.getByRole("button", { name: /compare/i });
    expect(compareBtn).toBeDisabled();
    const checkboxes = screen.getAllByRole("checkbox");
    await user.click(checkboxes[0]);
    expect(screen.getByRole("button", { name: /compare/i })).toBeDisabled(); // 1 selected
    await user.click(checkboxes[1]);
    const enabled = screen.getByRole("button", { name: /compare/i });
    expect(enabled).toBeEnabled(); // 2 selected
    await user.click(enabled);
    expect(onCompare).toHaveBeenCalledWith("old", "new"); // older (100) first
  });
});
```

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/components/recent/RecentView.test.tsx` → FAIL (no checkbox / no Compare button).

- [ ] **Step 3: Implement** — edit `ui/src/components/recent/RecentView.tsx`:

(a) Add `useState` to the React import if absent: `import { useState } from "react";` (check the existing import line).

(b) Add `onCompare` to `RecentViewProps`:

```tsx
  onLoadNew: () => void;
  /** Compare two selected captures (ids ordered older-first by analyzedAt). */
  onCompare?: (beforeId: string, afterId: string) => void;
```

(c) Extend `RecentCard`'s signature + add a selection checkbox. Change its param list to add `selected`/`onToggleSelect`/`selectable`, and insert a checkbox in the header `<div className="flex items-start justify-between gap-2">` block — before the title button:

```tsx
function RecentCard({
  entry,
  active,
  busy,
  selectable,
  selected,
  onToggleSelect,
  onOpen,
  onReanalyze,
  onRemove,
}: {
  entry: RecentEntry;
  active: boolean;
  busy: boolean;
  selectable: boolean;
  selected: boolean;
  onToggleSelect: (id: string) => void;
  onOpen: (e: RecentEntry) => void;
  onReanalyze: (e: RecentEntry) => void;
  onRemove: (e: RecentEntry) => void;
}) {
```

In the header row, before the title `<button>`:

```tsx
      <div className="flex items-start justify-between gap-2">
        {selectable && (
          <input
            type="checkbox"
            checked={selected}
            onChange={() => onToggleSelect(entry.id)}
            aria-label={`Select ${entry.name} to compare`}
            className="mt-1 h-3.5 w-3.5 shrink-0 accent-[var(--color-accent)]"
          />
        )}
        <button
          type="button"
          onClick={() => onOpen(entry)}
```

(Leave the rest of `RecentCard` unchanged.)

(d) In `RecentView`, add selection state + the Compare button + pass props to each card. Add `onCompare` to the destructured props, then:

```tsx
export function RecentView({
  entries,
  activeId = null,
  busyId = null,
  onOpen,
  onReanalyze,
  onRemove,
  onClear,
  onLoadNew,
  onCompare,
}: RecentViewProps) {
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const toggleSelect = (id: string) =>
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const selectable = !!onCompare && entries.length >= 2;
  const startCompare = () => {
    if (!onCompare || selectedIds.size !== 2) return;
    const [a, b] = entries.filter((e) => selectedIds.has(e.id)).sort((x, y) => x.analyzedAt - y.analyzedAt);
    onCompare(a.id, b.id);
    setSelectedIds(new Set());
  };
```

In the header action row (next to "Load capture"/"Clear all"), add the Compare button when `selectable`:

```tsx
        <div className="flex items-center gap-2">
          {selectable && (
            <button
              type="button"
              onClick={startCompare}
              disabled={selectedIds.size !== 2}
              className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-2 px-3 py-1.5 text-xs font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)] disabled:opacity-50"
            >
              <GitCompare className="h-3.5 w-3.5" aria-hidden />
              Compare ({selectedIds.size}/2)
            </button>
          )}
          <button
            type="button"
            onClick={onLoadNew}
```

In the card grid, pass the new props:

```tsx
            <RecentCard
              key={entry.id}
              entry={entry}
              active={entry.id === activeId}
              busy={entry.id === busyId}
              selectable={selectable}
              selected={selectedIds.has(entry.id)}
              onToggleSelect={toggleSelect}
              onOpen={onOpen}
              onReanalyze={onReanalyze}
              onRemove={onRemove}
            />
```

(e) Add `GitCompare` to the existing `lucide-react` import in this file (it already imports icons like `Upload`, `Trash2`, `FileStack` — add `GitCompare` to that list).

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/components/recent/RecentView.test.tsx` → PASS.

- [ ] **Step 5: Commit**

```bash
git add ui/src/components/recent/RecentView.tsx ui/src/components/recent/RecentView.test.tsx
git commit -m "feat(recent): multi-select + Compare button (older-first pair)"
```

---

### Task 3: `CompareView`

**Files:**
- Create: `ui/src/views/CompareView.tsx`
- Test: `ui/src/views/CompareView.test.tsx`

**Interfaces:**
- Consumes: `diffSummaries`, `SummaryDiff`, `FieldDelta`, `Changed`, `DiffResult` from `../lib/diff` (Task 1); `severityColor` from `../lib/palette`.
- Produces: `export function CompareView({ before, after, onSwap }: { before?: RecentEntry; after?: RecentEntry; onSwap: () => void }): JSX.Element`

- [ ] **Step 1: Write the failing test** — `ui/src/views/CompareView.test.tsx`

```tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CompareView } from "./CompareView";
import type { RecentEntry, Summary, IpThreat, Incident, SeverityCounts } from "../types";

const sev = (o: Partial<SeverityCounts> = {}): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0, ...o });
const threat = (o: Partial<IpThreat>): IpThreat =>
  ({ ip: "1.1.1.1", ip_class: "public", severity: "low", score: 10, flows: 1, bytes: 1,
     ioc: false, tags: [], attack: [], evidence: [], ...o } as IpThreat);
const incident = (o: Partial<Incident>): Incident =>
  ({ host: "h1", severity: "low", score: 10, title: "t", narrative: "n", stages: [], attack: [], findings: [], ...o } as Incident);
const ent = (id: string, s: Partial<Summary>): RecentEntry =>
  ({ id, name: id, analyzedAt: id === "a" ? 100 : 200, sizeBytes: 1, engineVersion: "x", origin: "browser",
     flowCount: 1, flowsCached: false,
     summary: { summary: { ip_threats: [], incidents: [], severity_counts: sev(), ...s } } } as unknown as RecentEntry);

describe("CompareView", () => {
  it("shows a graceful message when a capture is missing", () => {
    render(<CompareView before={undefined} after={ent("b", {})} onSwap={() => {}} />);
    expect(screen.getByText(/no longer cached/i)).toBeInTheDocument();
  });

  it("renders added / removed / changed threats with field deltas", () => {
    const before = ent("a", { ip_threats: [threat({ ip: "1.1.1.1", score: 40 }), threat({ ip: "2.2.2.2" })] });
    const after = ent("b", { ip_threats: [threat({ ip: "1.1.1.1", score: 85, severity: "critical" }), threat({ ip: "9.9.9.9" })] });
    render(<CompareView before={before} after={after} onSwap={() => {}} />);
    expect(screen.getByText("9.9.9.9")).toBeInTheDocument(); // added
    expect(screen.getByText("2.2.2.2")).toBeInTheDocument(); // removed
    expect(screen.getByText("1.1.1.1")).toBeInTheDocument(); // changed
    expect(screen.getByText(/40\s*→\s*85/)).toBeInTheDocument(); // score delta
  });

  it("shows the unrelated-captures banner when nothing is shared", () => {
    const before = ent("a", { ip_threats: [threat({ ip: "1.1.1.1" })] });
    const after = ent("b", { ip_threats: [threat({ ip: "9.9.9.9" })] });
    render(<CompareView before={before} after={after} onSwap={() => {}} />);
    expect(screen.getByText(/may be unrelated/i)).toBeInTheDocument();
  });

  it("shows No differences for identical captures and supports swap", async () => {
    const user = userEvent.setup();
    const onSwap = vi.fn();
    const before = ent("a", { incidents: [incident({ host: "h1" })] });
    const after = ent("b", { incidents: [incident({ host: "h1" })] });
    render(<CompareView before={before} after={after} onSwap={onSwap} />);
    expect(screen.getByText(/no differences/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /swap/i }));
    expect(onSwap).toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/views/CompareView.test.tsx` → FAIL (module not found).

- [ ] **Step 3: Implement** — `ui/src/views/CompareView.tsx`

```tsx
import { ArrowLeftRight } from "lucide-react";
import type { RecentEntry, IpThreat, Incident } from "../types";
import { diffSummaries } from "../lib/diff";
import type { Changed, DiffResult, FieldDelta } from "../lib/diff";
import { severityColor } from "../lib/palette";

/** A signed delta number, colored: increases (worse) red, decreases green. */
function Signed({ n }: { n: number }) {
  if (n === 0) return <span className="text-[var(--color-text-faint)]">0</span>;
  const color = n > 0 ? "var(--color-sev-high)" : "var(--color-sev-low)";
  return <span style={{ color }}>{n > 0 ? "+" : ""}{n}</span>;
}

function DeltaRow({ deltas }: { deltas: FieldDelta[] }) {
  return (
    <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-[var(--color-text-faint)]">
      {deltas.map((d, i) => (
        <span key={i} className="font-mono-num">
          {d.field} <span className="text-[var(--color-text-dim)]">{d.before} → {d.after}</span>
        </span>
      ))}
    </div>
  );
}

function EntityRow({ ipOrHost, severity, kind }: { ipOrHost: string; severity: string; kind: "+" | "−" | "~" }) {
  return (
    <div className="flex items-center gap-2 text-xs">
      <span aria-hidden className="w-3 select-none text-center font-mono-num text-[var(--color-text-faint)]">{kind}</span>
      <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: severityColor(severity as never) }} aria-hidden />
      <span className="font-mono-num truncate text-[var(--color-text)]">{ipOrHost}</span>
    </div>
  );
}

function DiffSection<T extends IpThreat | Incident>({
  title, result, label,
}: { title: string; result: DiffResult<T>; label: (t: T) => string }) {
  const total = result.added.length + result.removed.length + result.changed.length;
  if (total === 0) return null;
  return (
    <section className="flex flex-col gap-2">
      <h2 className="text-sm font-semibold text-[var(--color-text)]">{title} <span className="text-[var(--color-text-faint)]">({total})</span></h2>
      {result.added.length > 0 && (
        <div className="flex flex-col gap-1">
          <div className="text-[10px] uppercase tracking-wider text-[var(--color-sev-high)]">Added · {result.added.length}</div>
          {result.added.map((t, i) => <EntityRow key={i} ipOrHost={label(t)} severity={t.severity} kind="+" />)}
        </div>
      )}
      {result.removed.length > 0 && (
        <div className="flex flex-col gap-1">
          <div className="text-[10px] uppercase tracking-wider text-[var(--color-sev-low)]">Removed · {result.removed.length}</div>
          {result.removed.map((t, i) => <EntityRow key={i} ipOrHost={label(t)} severity={t.severity} kind="−" />)}
        </div>
      )}
      {result.changed.length > 0 && (
        <div className="flex flex-col gap-1.5">
          <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-dim)]">Changed · {result.changed.length}</div>
          {result.changed.map((c: Changed<T>, i) => (
            <div key={i} className="flex flex-col gap-0.5">
              <EntityRow ipOrHost={c.key} severity={c.after.severity} kind="~" />
              <div className="pl-5"><DeltaRow deltas={c.deltas} /></div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

export function CompareView({ before, after, onSwap }: { before?: RecentEntry; after?: RecentEntry; onSwap: () => void }) {
  if (!before || !after) {
    return (
      <div data-component="CompareView" className="flex h-full items-center justify-center p-10 text-center">
        <p className="max-w-sm text-sm text-[var(--color-text-dim)]">
          One of the captures is no longer cached. Re-open it from the Recent tab and try comparing again.
        </p>
      </div>
    );
  }
  const diff = diffSummaries(before.summary.summary, after.summary.summary);
  const threatTotal = diff.threats.added.length + diff.threats.removed.length + diff.threats.changed.length;
  const incidentTotal = diff.incidents.added.length + diff.incidents.removed.length + diff.incidents.changed.length;
  const severityChanged = diff.severity.some((b) => b.delta !== 0);
  const noDiff = threatTotal === 0 && incidentTotal === 0 && !severityChanged;
  const bothNonEmpty =
    (before.summary.summary.ip_threats.length + before.summary.summary.incidents.length) > 0 &&
    (after.summary.summary.ip_threats.length + after.summary.summary.incidents.length) > 0;
  const unrelated = diff.shared === 0 && bothNonEmpty;

  return (
    <div data-component="CompareView" className="flex h-full min-h-0 flex-col gap-4 overflow-auto">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="text-base font-semibold text-[var(--color-text)]">Compare captures</h1>
        <div className="flex items-center gap-2 text-xs text-[var(--color-text-dim)]">
          <span className="font-mono-num truncate">{before.name}</span>
          <span aria-hidden>→</span>
          <span className="font-mono-num truncate">{after.name}</span>
        </div>
        <button
          type="button"
          onClick={onSwap}
          className="ml-auto inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-2 px-2.5 py-1.5 text-xs font-medium text-[var(--color-text-dim)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]"
        >
          <ArrowLeftRight className="h-3.5 w-3.5" aria-hidden /> Swap
        </button>
      </div>

      {unrelated && (
        <div className="rounded-md border border-[var(--color-sev-medium)] bg-[color-mix(in_srgb,var(--color-sev-medium)_12%,transparent)] px-3 py-2 text-xs text-[var(--color-text-dim)]">
          These captures share no threat IPs or hosts; they may be unrelated.
        </div>
      )}

      <div className="flex flex-wrap gap-3">
        {diff.severity.map((b) => (
          <div key={b.band} className="rounded-md border border-border bg-surface-2 px-3 py-1.5 text-xs">
            <span className="capitalize text-[var(--color-text-dim)]">{b.band}</span>{" "}
            <span className="font-mono-num"><Signed n={b.delta} /></span>
          </div>
        ))}
      </div>

      {noDiff ? (
        <div className="flex flex-1 items-center justify-center rounded-xl border border-dashed border-border p-10 text-sm text-[var(--color-text-dim)]">
          No differences between these captures.
        </div>
      ) : (
        <div className="flex flex-col gap-5">
          <DiffSection title="Threat IPs" result={diff.threats} label={(t: IpThreat) => t.ip} />
          <DiffSection title="Incidents" result={diff.incidents} label={(i: Incident) => i.host} />
        </div>
      )}
    </div>
  );
}
```

> NOTE: `severityColor` expects a `Severity`; the `as never` cast keeps the row generic over threats/incidents (both carry `severity: Severity`). If tsc rejects `as never`, cast to `Severity` (`import type { Severity }`).

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/views/CompareView.test.tsx` → PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add ui/src/views/CompareView.tsx ui/src/views/CompareView.test.tsx
git commit -m "feat(compare): CompareView — added/removed/changed + severity strip"
```

---

### Task 4: Wiring — `compare` tab + App state + palette

**Files:**
- Modify: `ui/src/types.ts` (`TabId`), `ui/src/components/layout/AppShell.tsx` (tab + palette action), `ui/src/App.tsx` (state + render + RecentView `onCompare`)

**Interfaces:**
- Consumes: `CompareView` (Task 3); `RecentView.onCompare` (Task 2).

- [ ] **Step 1: Extend `TabId`** — `ui/src/types.ts:341`

```ts
export type TabId = "dashboard" | "flows" | "recent" | "compare";
```

- [ ] **Step 2: AppShell — conditional compare tab + palette action.** Add an optional `compareActive?: boolean` to `AppShellProps` (near `activeTab`/`onTabChange`):

```ts
  activeTab: TabId;
  onTabChange: (t: TabId) => void;
  /** Whether a capture comparison is active (shows the Compare tab). */
  compareActive?: boolean;
```

Destructure `compareActive = false` in the component params, then change the `tabs` array (`:132-136`) to append the compare tab conditionally:

```tsx
  const tabs = [
    { id: "dashboard" as const, label: "Dashboard" },
    { id: "flows" as const, label: "Flows" },
    { id: "recent" as const, label: "Recent", badge: recentCount || undefined },
    ...(compareActive ? [{ id: "compare" as const, label: "Compare" }] : []),
  ];
```

Add a palette action to `paletteActions` (`:142-149`), after `go-recent`:

```tsx
    { id: "go-compare", label: "Compare captures", hint: "view", run: () => onTabChange("recent") },
```

(The action sends the user to Recent, where they select two captures and click Compare.)

- [ ] **Step 3: App — compare state + render + RecentView wiring.** In `ui/src/App.tsx`:

Add the import (near the `RecentView` import, line ~30):

```tsx
import { CompareView } from "./views/CompareView";
```

Add state (near `const [tab, setTab] = useState<TabId>("dashboard");`, line ~84):

```tsx
  const [compareIds, setCompareIds] = useState<[string, string] | null>(null);
  const [compareSwapped, setCompareSwapped] = useState(false);
  const startCompare = (beforeId: string, afterId: string) => {
    setCompareIds([beforeId, afterId]);
    setCompareSwapped(false);
    setTab("compare");
  };
```

Pass `compareActive` to `<AppShell>` (next to `activeTab={tab} onTabChange={setTab}`, line ~426):

```tsx
        compareActive={compareIds !== null}
```

Pass `onCompare` to `<RecentView>` (in the tab switch, the `recent` branch):

```tsx
          onLoadNew={handleRequestLoad}
          onCompare={startCompare}
```

Add the `compare` branch at the TOP of the tab-switch conditional (before `tab === "flows"`), so it renders the CompareView resolving the pair from `recent`:

```tsx
{tab === "compare" ? (
  (() => {
    const [olderId, newerId] = compareIds ?? ["", ""];
    const older = recent.find((e) => e.id === olderId);
    const newer = recent.find((e) => e.id === newerId);
    const before = compareSwapped ? newer : older;
    const after = compareSwapped ? older : newer;
    return <CompareView before={before} after={after} onSwap={() => setCompareSwapped((s) => !s)} />;
  })()
) : tab === "flows" ? (
  <FlowsView state={flows} initialFilter={flowsFilter} activeSource={activeSource} />
) : tab === "recent" ? (
```

- [ ] **Step 4: Verify** — `cd ui && npx vitest run src/App.test.tsx` (if present) — existing App tests stay green (compare inactive by default). `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors. Manually confirm: the `tabs` literal types still satisfy `TabId` (the `as const` ids must all be members of the extended union).

- [ ] **Step 5: Commit**

```bash
git add ui/src/types.ts ui/src/components/layout/AppShell.tsx ui/src/App.tsx
git commit -m "feat(compare): compare tab + App state + Recent onCompare wiring"
```

---

### Task 5: Coverage gate + CI-toolchain verification

**Files:**
- Add focused tests wherever `npm run test:coverage` shows a new file below the bar.

- [ ] **Step 1: Realign to the CI toolchain** —

```bash
cd ui && git diff --stat package.json package-lock.json
git checkout -- package.json package-lock.json 2>/dev/null || true
npm ci
node -p "require('./node_modules/vitest/package.json').version"   # MUST print 1.6.1
```

Do NOT run `npm install`.

- [ ] **Step 2: Build gate** — `cd ui && npm run build; echo "build EXIT: $?"` → EXIT 0, zero `error TS` (`tsc -b && vite build`; type-checks all test files under vitest 1.6.1 — the new `userEvent`/`vi.fn` mocks must type-check there; if a `vi.fn` spread/tuple error appears, type the mock `vi.fn<[Args], Ret>()`).

- [ ] **Step 3: Coverage gate** — `cd ui && npm run test:coverage; echo "EXIT: $?"` → EXIT 0; `All files` lines/functions/statements ≥ 80, branches ≥ 70. Paste that line into the report.

- [ ] **Step 4: Fill gaps** — `diff.ts` should be ~100% (pure). If `CompareView`/`RecentView` branches dip the bar, add a real behavior test (e.g. a removed incident, an empty-both "No differences", an unrelated-captures banner not shown when shared > 0). Re-run step 3.

- [ ] **Step 5: Commit** (only if tests were added)

```bash
git add ui/src/lib/diff.test.ts ui/src/views/CompareView.test.tsx ui/src/components/recent/RecentView.test.tsx
git commit -m "test(compare): hold the coverage gate for multi-capture diff"
```

---

## Self-Review

**1. Spec coverage:** diff core (T1) → spec §"Diff core" (threats by ip, incidents by host, severity deltas, `shared`); Recent multi-select (T2) → §"Selection"; CompareView (T3) → §"CompareView" (severity strip, added/removed/changed, field deltas, mismatch banner via `shared===0`, swap, missing-capture, No-differences); wiring (T4) → §"Wiring" (TabId, AppShell tab+palette, App state); coverage (T5) → §"Testing". Arbitrary-two selection, older-baseline order, content-based mismatch — all covered. Findings/traffic/pin-baseline correctly absent (out of scope). ✓

**2. Placeholder scan:** every code step has complete code. The two notes (RepStatus export confirmation in T1; `as never`/`Severity` cast in T3) are concrete in-repo verifications, not placeholders. ✓

**3. Type consistency:** `diffSummaries(before, after)`, `DiffResult<T>{added,removed,changed}`, `Changed<T>{key,before,after,deltas}`, `FieldDelta{field,before,after}`, `SummaryDiff{threats,incidents,severity,shared}`, `CompareView({before?,after?,onSwap})`, `RecentView.onCompare(beforeId,afterId)`, `AppShell.compareActive`, `TabId += "compare"` — all consistent across T1–T4. ✓
