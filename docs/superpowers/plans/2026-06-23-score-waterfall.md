# Score waterfall (explainability) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A visual score breakdown — each `+N`/`−N` term that built a host's score, plus the engine's clamp/floor adjustments — in the incident `DetailFlyout`.

**Architecture:** Pure UI. A `lib/scoreTerms.ts` parses `IpThreat.evidence` strings into additive terms + non-additive notes; a `ScoreWaterfall` component renders them; the `DetailFlyout` shows it (Dashboard looks up the host's `IpThreat` and passes its evidence/score). No engine/WASM/Tauri change.

**Tech Stack:** React 18 + TS; Vitest. No new deps.

## Global Constraints

- **Pure UI** — no engine/WASM/Tauri change. Inputs: `IpThreat.evidence: string[]` + `IpThreat.score: number`.
- **The final bar is the authoritative `score`**, never the sum of parsed terms — clamp/floor are annotations, so the visual never lies.
- **Never throws** — a non-`(±N)` entry becomes a note; empty input → empty result.
- The parse regex `/\(([+-]?\d+)\)\s*$/` matches only a bare signed integer in trailing parens — `(>= 60)`/`(>= 90)` floor lines must NOT parse as terms.
- No new deps. Coverage gate ≥ 80/70 (vitest 1.6.1). Stage specific files. node at `/c/Program Files/nodejs`; do NOT `npm install`.

## Reference: the seams (verbatim, verified)

```ts
// ui/src/types.ts:128 IpThreat { ip; ip_class; severity: Severity; score: number; ...; attack: string[]; evidence: string[] }
//   :142 Incident { host: string; severity: Severity; score: number; attack[]; stages; narrative; findings: Finding[] }
// ui/src/cockpit/DetailFlyout.tsx:14 export function DetailFlyout({ incident, onClose, onJumpToFlows }: { incident: Incident|null; onClose: ()=>void; onJumpToFlows:(ip:string)=>void })
//   :101 <SectionLabel className="mb-2 mt-5">Findings · {incident.findings.length}</SectionLabel>  (render the waterfall ABOVE this)
//   imports: SectionLabel, SeverityChip from cockpit/primitives ; sevColor from cockpit/viz ; EvidenceList from ../components/transparency/EvidenceList
// ui/src/components/Dashboard.tsx ~line 164 <DetailFlyout incident={selectedIncident} onClose={() => onSelectIncident(null)} onJumpToFlows={toFlowsIp} />
//   Dashboard has s.ip_threats (IpThreat[]) in scope as `s.ip_threats`
// ui/src/components/transparency/EvidenceList.tsx — sibling transparency component (grouping pattern); ScoreWaterfall lives next to it
// engine contract (score/mod.rs): "category X (+N)", "ioc: … (+35)", "external public peer (+15)", "all-internal peers (-10)", "behavior: … (+10)"; non-additive "clamp: raw A -> S", "floor: … (>= 60)", "floor: … (>= 90)"
// ui/src/cockpit/viz.ts sevColor(severity) ; ui/src/cockpit/primitives SectionLabel
```

---

### Task 1: `lib/scoreTerms.ts` (the parser)

**Files:**
- Create: `ui/src/lib/scoreTerms.ts`, `ui/src/lib/scoreTerms.test.ts`

**Interfaces:**
- Produces: `ScoreTerm`, `ParsedScore`, `parseScoreTerms`.

- [ ] **Step 1: Write the failing test** — `ui/src/lib/scoreTerms.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { parseScoreTerms } from "./scoreTerms";

describe("parseScoreTerms", () => {
  it("parses a positive additive term", () => {
    expect(parseScoreTerms(["category c2 (+45)"])).toEqual({
      terms: [{ label: "category c2", points: 45 }],
      notes: [],
    });
  });

  it("parses a negative term", () => {
    const r = parseScoreTerms(["all-internal peers (-10)"]);
    expect(r.terms).toEqual([{ label: "all-internal peers", points: -10 }]);
  });

  it("routes clamp + floor lines to notes, not terms", () => {
    const r = parseScoreTerms([
      "category c2 (+45)",
      "ioc: endpoint ip on threat feed (+35)",
      "clamp: raw 105 -> 100",
      "floor: ioc + c2/anomalous forces Critical (>= 90)",
    ]);
    expect(r.terms.map((t) => t.points)).toEqual([45, 35]);
    expect(r.terms.map((t) => t.label)).toEqual([
      "category c2",
      "ioc: endpoint ip on threat feed",
    ]);
    expect(r.notes).toEqual([
      "clamp: raw 105 -> 100",
      "floor: ioc + c2/anomalous forces Critical (>= 90)",
    ]);
  });

  it("does not treat (>= 60) as a term", () => {
    const r = parseScoreTerms(["floor: ioc match forces High (>= 60)"]);
    expect(r.terms).toEqual([]);
    expect(r.notes).toEqual(["floor: ioc match forces High (>= 60)"]);
  });

  it("handles +0 and empty input", () => {
    expect(parseScoreTerms(["category unknown (+0)"]).terms).toEqual([
      { label: "category unknown", points: 0 },
    ]);
    expect(parseScoreTerms([])).toEqual({ terms: [], notes: [] });
  });

  it("a non-matching string becomes a note (never throws)", () => {
    const r = parseScoreTerms(["just a freeform note"]);
    expect(r.terms).toEqual([]);
    expect(r.notes).toEqual(["just a freeform note"]);
  });
});
```

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/lib/scoreTerms.test.ts` → FAIL (module not found).

- [ ] **Step 3: Implement** — `ui/src/lib/scoreTerms.ts`:

```ts
/** One additive scoring contribution parsed from an evidence string. */
export interface ScoreTerm {
  label: string;
  points: number;
}

/** Additive terms + non-additive annotations (clamp/floor) parsed from IpThreat.evidence. */
export interface ParsedScore {
  terms: ScoreTerm[];
  notes: string[];
}

/** Trailing "(+45)" / "(-10)" / "(+0)" — a bare signed integer in parens at end of string. */
const TERM_RE = /\(([+-]?\d+)\)\s*$/;

/**
 * Parse the engine's score evidence strings into additive {label, points} terms and
 * non-additive notes (the `clamp:`/`floor:` lines, which carry no bare `(±N)`). Never throws;
 * any string without a trailing signed-integer paren becomes a note.
 */
export function parseScoreTerms(evidence: string[] | undefined): ParsedScore {
  const terms: ScoreTerm[] = [];
  const notes: string[] = [];
  for (const raw of evidence ?? []) {
    const entry = typeof raw === "string" ? raw : String(raw);
    const m = entry.match(TERM_RE);
    if (m) {
      terms.push({ label: entry.slice(0, m.index).trim(), points: parseInt(m[1], 10) });
    } else {
      notes.push(entry);
    }
  }
  return { terms, notes };
}
```

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/lib/scoreTerms.test.ts` → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 5: Commit**

```bash
git add ui/src/lib/scoreTerms.ts ui/src/lib/scoreTerms.test.ts
git commit -m "feat(ui): parseScoreTerms — split score evidence into additive terms + clamp/floor notes"
```

---

### Task 2: `ScoreWaterfall.tsx` (the component)

**Files:**
- Create: `ui/src/components/transparency/ScoreWaterfall.tsx`, `ui/src/components/transparency/ScoreWaterfall.test.tsx`

**Interfaces:**
- Consumes: `parseScoreTerms` (T1); `sevColor` (cockpit/viz); `SectionLabel` (cockpit/primitives); `Severity` (types).
- Produces: `ScoreWaterfall({ evidence, score, severity })`.

- [ ] **Step 1: Write the failing test** — `ui/src/components/transparency/ScoreWaterfall.test.tsx`:

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "../../test/render";
import { ScoreWaterfall } from "./ScoreWaterfall";

const evidence = [
  "category c2 (+45)",
  "ioc: endpoint ip on threat feed (+35)",
  "all-internal peers (-10)",
  "clamp: raw 105 -> 100",
];

describe("ScoreWaterfall", () => {
  it("renders a row per additive term, the final score, and the clamp note", () => {
    render(<ScoreWaterfall evidence={evidence} score={100} severity="critical" />);
    expect(screen.getByText("category c2")).toBeInTheDocument();
    expect(screen.getByText("ioc: endpoint ip on threat feed")).toBeInTheDocument();
    expect(screen.getByText(/\+45/)).toBeInTheDocument();
    expect(screen.getByText(/-10|−10/)).toBeInTheDocument(); // ascii or unicode minus
    expect(screen.getByText(/Score/i)).toBeInTheDocument();
    expect(screen.getByText(/100/)).toBeInTheDocument();
    expect(screen.getByText(/clamp: raw 105/)).toBeInTheDocument();
  });

  it("renders nothing when there are no terms and no notes", () => {
    const { container } = render(<ScoreWaterfall evidence={[]} score={0} severity="info" />);
    expect(container).toBeEmptyDOMElement();
  });
});
```

> NOTE: confirm `Severity` includes the values used (`"critical"`, `"info"`) — read `ui/src/types.ts`. Use the project's `render` from `../../test/render` (NOT @testing-library directly). If the final-score row renders the number and the word "Score" in separate elements, the two `getByText` calls above still hold; if combined into one node like "Score 100/100", change to `getByText(/Score\s*100/i)`.

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/components/transparency/ScoreWaterfall.test.tsx` → FAIL.

- [ ] **Step 3: Implement** — `ui/src/components/transparency/ScoreWaterfall.tsx`. Use `parseScoreTerms(evidence)`; render nothing if `terms.length === 0 && notes.length === 0`. Otherwise a small section:
- `<SectionLabel>Score breakdown</SectionLabel>`.
- one row per term: the `label` (truncate), a proportional bar (`width: ${(Math.abs(points) / maxAbs) * 100}%`, `maxAbs = Math.max(1, ...terms.map(t => Math.abs(t.points)))`), colored positive vs negative, and a signed number (`${points >= 0 ? "+" : ""}${points}`). Positive = an accent/ok color, negative = a danger color — use inline colors from the existing palette: positive `var(--color-accent)` (or a green token already in the cockpit), negative `var(--color-danger)`/the critical severity color via `sevColor("critical")`. If a named token is uncertain, derive from `sevColor`: positive `sevColor("low")`-ish is wrong — instead hardcode two clear hex/token values consistent with the cockpit (e.g. positive `#27c498`/`var(--color-ok)`, negative `#f0556a`/`var(--color-danger)`); pick whichever tokens the cockpit already defines (grep `--color-ok`/`--color-danger`/`--color-accent` in `ui/src` and the CSS).
- a final emphasized row: the literal text `Score` and `${score}/100`, colored with `sevColor(severity)`.
- the `notes` as small dim mono lines (`font-mono-num text-[var(--color-text-faint)]`), each rendered verbatim.
Cockpit styling (`t-tag`, `SectionLabel`, tokens). Keep it a focused presentational component.

> NOTE: grep the actual color tokens before hardcoding — `grep -rE "\-\-color-(ok|danger|accent|positive|negative)" ui/src ui/*.css ui/src/**/*.css` (and `sevColor`'s implementation in `cockpit/viz.ts`) so the bar colors use real tokens. Reuse the `ScoreBar` primitive's approach if it already encodes a score color.

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/components/transparency/ScoreWaterfall.test.tsx` → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 5: Commit**

```bash
git add ui/src/components/transparency/ScoreWaterfall.tsx ui/src/components/transparency/ScoreWaterfall.test.tsx
git commit -m "feat(ui): ScoreWaterfall — visual +N/-N score breakdown with clamp/floor notes"
```

---

### Task 3: DetailFlyout + Dashboard wiring (+ gate)

**Files:**
- Modify: `ui/src/cockpit/DetailFlyout.tsx` (2 optional props + render the waterfall), `ui/src/components/Dashboard.tsx` (look up the host's IpThreat + pass it)
- Test: `ui/src/cockpit/DetailFlyout.test.tsx` (extend; create if absent)

**Interfaces:**
- Consumes: `ScoreWaterfall` (T2); `IpThreat` (types).

- [ ] **Step 1: Write the failing test** — extend the DetailFlyout test:

```tsx
// in ui/src/cockpit/DetailFlyout.test.tsx (reuse the existing incident fixture / makeOutput().summary.incidents![0])
it("renders the score waterfall when scoreEvidence is provided", () => {
  const incident = makeOutput().summary.incidents![0];
  render(
    <DetailFlyout
      incident={incident}
      onClose={() => {}}
      onJumpToFlows={() => {}}
      scoreEvidence={["category c2 (+45)", "ioc: endpoint ip on threat feed (+35)"]}
      hostScore={90}
    />,
  );
  expect(screen.getByText(/Score breakdown/i)).toBeInTheDocument();
  expect(screen.getByText("category c2")).toBeInTheDocument();
});

it("omits the score waterfall when scoreEvidence is absent", () => {
  const incident = makeOutput().summary.incidents![0];
  render(<DetailFlyout incident={incident} onClose={() => {}} onJumpToFlows={() => {}} />);
  expect(screen.queryByText(/Score breakdown/i)).toBeNull();
});
```

> NOTE: match the existing DetailFlyout test's imports (`render`/`screen` from `../test/render`, `makeOutput` from `../test/fixtures`). If no DetailFlyout test file exists, create one with these two cases + the imports the Dashboard test uses. Confirm `makeOutput().summary.incidents` is non-empty (the Dashboard test already relies on `incidents![0]`).

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/cockpit/DetailFlyout.test.tsx` → FAIL (no `scoreEvidence` prop / no waterfall).

- [ ] **Step 3: Implement** —
(a) `DetailFlyout.tsx`: add to the props type `scoreEvidence?: string[]; hostScore?: number;` and the destructure. Import `ScoreWaterfall` from `../components/transparency/ScoreWaterfall`. Directly ABOVE the `<SectionLabel …>Findings · …` block, render:
```tsx
            {scoreEvidence && scoreEvidence.length > 0 && (
              <ScoreWaterfall
                evidence={scoreEvidence}
                score={hostScore ?? incident.score}
                severity={incident.severity}
              />
            )}
```
(b) `Dashboard.tsx`: add `const threatByHost = useMemo(() => new Map((s.ip_threats ?? []).map((t) => [t.ip, t])), [s.ip_threats]);` (near the other useMemo maps). At the `<DetailFlyout …>` call, add:
```tsx
          scoreEvidence={selectedIncident ? threatByHost.get(selectedIncident.host)?.evidence : undefined}
          hostScore={selectedIncident ? threatByHost.get(selectedIncident.host)?.score : undefined}
```
(`selectedIncident` is the Dashboard's controlled flyout incident — confirm the prop name in the existing `<DetailFlyout>` render; it is `incident={selectedIncident}`.)

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/cockpit/DetailFlyout.test.tsx src/components/Dashboard.test.tsx` → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 5: Commit**

```bash
git add ui/src/cockpit/DetailFlyout.tsx ui/src/components/Dashboard.tsx ui/src/cockpit/DetailFlyout.test.tsx
git commit -m "feat(ui): surface the ScoreWaterfall in the incident DetailFlyout"
```

- [ ] **Step 6: Full gate** — `cd ui && export PATH="/c/Program Files/nodejs:/c/Users/ravid/.cargo/bin:$PATH"`:
```bash
git diff --stat package.json package-lock.json
git checkout -- package.json package-lock.json 2>/dev/null || true
npm ci
node -p "require('./node_modules/vitest/package.json').version"   # 1.6.1
npm run build:wasm
npm run build; echo "build EXIT: $?"          # EXIT 0
npm run test:coverage; echo "cov EXIT: $?"    # EXIT 0; All files >= 80/70 — paste it
git diff --name-only main..HEAD -- engine/ | head   # empty (pure UI)
```
Do NOT `npm install`. If a metric dips, add a focused test (e.g. the negative-term color path, or a notes-only render) and re-run.

- [ ] **Step 7: Commit** (if gate top-up tests added)

```bash
git add ui/src/<new/updated tests>
git commit -m "test(ui): hold the gate for the score waterfall"
```

---

## Self-Review

**1. Spec coverage:** the parser (T1) → spec §1; the component (T2) → §2; the flyout + Dashboard wiring (T3) → §3 + gate. Pure-UI, final-bar-is-authoritative, clamp/floor-as-notes, `(>= 60)`-not-a-term, never-throws, scope-A (incident hosts via the flyout) — all covered. ✓

**2. Placeholder scan:** complete code for the parser + its tests; the component is specified concretely (parse → rows → final score → notes) with a NOTE to grep the real color tokens before hardcoding; the wiring gives the exact props + lookup. The NOTEs (confirm Severity values; reuse the existing test imports/fixtures; grep color tokens; confirm the DetailFlyout render prop names) are concrete in-repo verifications. ✓

**3. Type consistency:** `ScoreTerm{label,points}`/`ParsedScore{terms,notes}` (T1) ⇄ `ScoreWaterfall({evidence,score,severity})` consumes `parseScoreTerms` (T2) ⇄ `DetailFlyout` adds `scoreEvidence?:string[]`/`hostScore?:number` and renders `<ScoreWaterfall>` (T3) ⇄ Dashboard passes `threatByHost.get(host)?.evidence`/`?.score` (both from `IpThreat`). `severity: Severity` threads from `incident.severity`. ✓
