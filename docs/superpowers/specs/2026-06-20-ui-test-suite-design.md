# UI test suite — design

- **Date:** 2026-06-20
- **Status:** Approved (design); pending implementation plan
- **Branch:** `feat/ui-test-suite` (off `chore/remove-cockpit-demo`)

## 1. Context & motivation

The `ui/` app has **zero tests** today (`package.json` scripts: `dev`/`build`/`preview`/`typecheck`). The
substantial cockpit UI (home dashboard + shell + ⌘K palette) has been verified only by `tsc` + manual live
checks. Real test gates would catch the classes of bug we actually hit this session — an algorithmic data bug
(`protoSegments` double-counting), a config mismatch (the `bytesTotal`/`bytes` column id), and a render-time
crash (`source_sha256: null`) — and make future subagent-driven work safe.

This adds a **comprehensive** UI test suite: pure-logic units, component render/interaction tests for every
major widget, and a coverage gate enforced in CI.

## 2. Scope

**In scope**
- Test runner + React component testing infra (Vitest + React Testing Library + jsdom).
- Pure-logic unit tests for `cockpit/match`, `lib/severity`, `lib/format`, `cockpit/viz`, `lib/data`.
- Component render + interaction tests for the cockpit widgets, the shell, and smoke tests for the Flows/Recent views.
- A shared typed `AnalysisOutput` test fixture.
- A coverage gate (thresholds) run in the existing CI `ui` job, failing the build under threshold.

**Out of scope (non-goals)**
- Engine (Rust) tests — already covered by the `engine` CI job.
- End-to-end / real-browser tests (Playwright) — jsdom + RTL is sufficient for this layer.
- Testing the orphaned legacy triage components (`components/triage/*`, `TimelineChart`, `CategoryChart`) that the cockpit Dashboard replaced — excluded from coverage, not tested.
- Visual-regression / screenshot testing.

## 3. Stack & configuration

**Dev dependencies (added):** `vitest`, `jsdom`, `@testing-library/react`, `@testing-library/jest-dom`,
`@testing-library/user-event`, `@vitest/coverage-v8`. No runtime deps. Pin to versions compatible with
Vite 5 / React 18 (Vitest 1.x).

**`ui/vitest.config.ts`** (separate from `vite.config.ts` to keep the build config clean; it reuses the
React plugin):
```ts
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    coverage: {
      provider: "v8",
      reporter: ["text", "html"],
      include: ["src/**/*.{ts,tsx}"],
      exclude: [
        "src/main.tsx", "src/**/*.d.ts", "src/types.ts", "src/vite-env.d.ts",
        "src/lib/platform.ts", "src/lib/wasmEngine.ts", "src/lib/recent.ts", "src/wasm/**",
        "src/components/triage/**", "src/components/TopTalkers.tsx",
        "src/components/layout/{DashboardGrid,Panel,StatTile,TabBar}.tsx",
        "src/components/primitives/Chip.tsx",
        "src/test/**", "**/*.test.{ts,tsx}",
      ],
      thresholds: { lines: 80, functions: 80, statements: 80, branches: 70 },
    },
  },
});
```
(The excludes are entry/type-only files, the Tauri/WASM integration shims, the orphaned legacy components,
and the dead layout stubs.)

**`package.json` scripts (added):**
```json
"test": "vitest run",
"test:watch": "vitest",
"test:coverage": "vitest run --coverage"
```

**`ui/src/test/setup.ts`** — jest-dom matchers + the jsdom polyfills these components need:
- `@testing-library/jest-dom` import.
- `window.matchMedia` mock (App auto-collapse `matchMedia("(max-width:1100px)")`).
- `ResizeObserver` + `IntersectionObserver` stubs (TanStack Virtual / any observer use).
- `Element.prototype.scrollTo` no-op.
- A `getBoundingClientRect` returning a non-zero size for the virtualizer's scroll element (so `FlowsTable`
  renders rows under jsdom) — applied narrowly in the FlowsTable test, or globally if harmless.
- `afterEach(cleanup)` (RTL auto-cleanup is on with globals, but assert it).

## 4. Test fixture

`ui/src/test/fixtures.ts` — exports `makeOutput(overrides?): AnalysisOutput` and a few `FlowRow[]` helpers.
A focused, typed rebuild of the engine output shape (NOT a demo page): one CRITICAL multi-stage incident
(`10.13.37.7`), 2–3 `ip_threats` (incident + non-incident host), a small `time_histogram` (incl. one
`data_exfil` finding so the heatmap exfil-marker path is covered), `category_breakdown` spanning a critical +
benign category, `proto` counts that satisfy the engine invariant (`tls+http+other_tcp == tcp`,
`dns+other_udp == udp`, `+ non_ipv4 == total_packets`), and `severity_counts` with **0 critical flows** (to
cover the data-trap path). `source_sha256: null` variant for the CaptureIntegrity guard test.

## 5. Pure-logic unit tests (exhaustive)

| Module | Behaviors asserted |
|---|---|
| `cockpit/match` | `fuzzyScore`: subsequence match returns number; non-subsequence → `null`; empty query → `0`; prefix + word-boundary bonuses rank higher; case-insensitive. |
| `lib/severity` | `normCategory` (kebab/space → snake); `severityForCategory` mapping incl. unknown→none; `SEVERITY_ORDER`; `rollupSeverity` sums flows/pkts/bytes per band + total. |
| `lib/format` | `humanBytes` (base-1024 + digit rules + ≤0), `humanNumber`/`compactNumber`, `durationHumanNs`/`durationHumanMs` boundaries, `percent` (incl. 0 total), `nsToDateTime`/`nsToTime`, `shortHash`, `basename`. |
| `cockpit/viz` | `clamp01`; `polarToCartesian`/`describeArc` known points; `circumference`; `sparkline` path shape + single-point + empty; **`protoSegments` filters value>0, is the LEAF partition, and Σ values == total_packets** (regression for the double-count bug). |
| `lib/data` | `normalizeFlow`: bigint→number, Date→ms, `bytesTotal = c2s+s2c`, `durationMs`, proto label, severity fallback. |

## 6. Component / interaction tests

Each renders with `makeOutput()` (or focused props). RTL + user-event.

| Component | Behaviors |
|---|---|
| `CommandPalette` | opens (`open` prop); query filters actions (fuzzy) + hosts; `↑/↓` move highlight, `Enter` runs action / `onSelectHost`; Esc + scrim close; focus moves to input on open and is **trapped** (Tab cycles); no-capture shows only actions + the host hint (mutually exclusive with "No matches"). |
| `ThreatRail` | renders threats sorted worst-first (severity then score); row click → `onSelect(ip)`; collapsed mode (`collapsed`) renders dots only; `activeIp` marks the active row; **no nav** (watchlist-only). |
| `CommandBar` | renders the passed `tabs` + Recent badge; `aria-pressed` reflects `activeTab`; Load/Export buttons disabled without handlers, call handlers when provided; ⌘K button → `onOpenPalette`; capture status pill states. |
| `KpiCluster` | verdict cell color/icon follow the **worst incident severity** (critical→red; all-high→high, not red); incident count; per-flow ring renders; sparkline present. |
| `IncidentHero` | renders host/score/MITRE/kill-chain stages + evidence; beacon radar present when a `beacon` finding exists; `.glow-critical` (breathing) only when `primary` + severity critical; `onPivot`/`onOpen` fire. |
| `CategoryMatrix` | severity-first sort (scan/c2 above high-volume web/dns); `onJump(token)` on row click; empty state. |
| `ProtocolMix` | segment widths/percent from `protoSegments`; **percentages sum to ~100**; TLS-heavy caption when TLS dominates; empty state. |
| `TopTalkersCard` | rows from `top_talkers`; flagged hosts marked; `onSelect(ip)`; bytes/pkts/flows render. |
| `CaptureIntegrity` | renders **without crashing when `source_sha256` is null** (regression); decode-error/coverage tiles; clean vs warn states. |
| `ActivityHeatmap` | renders one cell per bucket; the peak marker is **red "exfil burst" only when a `data_exfil` finding exists**, else neutral "peak volume"; hover tooltip; empty state. |
| instruments (`ScoreRing`/`SeverityRing`/`BeaconRadar`) | render at given props without error; ring reflects score fraction. |
| `Dashboard` | render smoke with `makeOutput()`: hero + threat-watchlist card + heatmap + the 4-card grid present; controlled `selectedIncident` opens the flyout. |
| `AppShell` | renders CommandBar + ThreatRail + children; ⌘K / Ctrl+K keydown calls `onPaletteOpenChange(true)` (and is a no-op when a dialog is open); palette mounts when `paletteOpen`. |
| `App` (integration) | `openThreat(ip)` routes: incident host → `selectedIncident` set + tab "dashboard"; non-incident host → Flows tab with the IP filter; capture swap resets `selectedIncident`/`activeIp`. |
| `FlowsView` / `FlowsTable` / `FlowDetail` / `RecentView` | smoke render: FlowsTable with mocked scroll-element size so rows appear + default sort `bytes` desc applies (regression for the id fix); FlowsView filter bar narrows rows; FlowDetail renders a selected flow's fields; RecentView lists entries + fires open/remove. |

## 7. Coverage gate & CI

- `vitest run --coverage` enforces the §3 thresholds (lines/functions/statements ≥ 80%, branches ≥ 70%) over
  `src/**` minus the exclusions. Under threshold → non-zero exit → **CI fails**.
- Extend `.github/workflows/ci.yml` `ui` job with a test step:
  ```yaml
  - run: npm run test:coverage
  ```
  placed after `npm ci` (before or after `npm run build`; independent). The job already does `npm ci` on
  Node 20, so no other CI change is needed.

## 8. Risks & mitigations

- **jsdom gaps** (matchMedia/observers/layout) → covered by `src/test/setup.ts` polyfills; documented per §3.
- **TanStack Virtual under jsdom** renders 0 rows without a measured scroll element → mock `getBoundingClientRect`/`scrollHeight` for the FlowsTable test; keep it a smoke test, not a deep virtualization test.
- **Coverage threshold realism** — 80/70 is the agreed starting bar; if the comprehensive component tests fall short on integration-heavy files (`App`, `AppShell`), either add focused tests or tune the threshold/excludes at implementation time (do not silently lower below the agreed bar without flagging).
- **No flaky timers** — components use `setTimeout(…,0)` for focus; use `user-event` + `findBy*`/`waitFor`, not fixed delays.

## 9. File summary

| File | Change |
|---|---|
| `ui/package.json` | add devDeps + `test`/`test:watch`/`test:coverage` scripts |
| `ui/vitest.config.ts` | **new** — jsdom + coverage thresholds + excludes |
| `ui/src/test/setup.ts` | **new** — jest-dom + jsdom polyfills |
| `ui/src/test/fixtures.ts` | **new** — typed `AnalysisOutput`/`FlowRow` fixtures |
| `ui/src/**/*.test.ts(x)` | **new** — the unit + component tests (colocated) |
| `.github/workflows/ci.yml` | add `npm run test:coverage` to the `ui` job |
