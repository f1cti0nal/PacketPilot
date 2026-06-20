# UI Test Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a comprehensive UI test suite (Vitest + React Testing Library + jsdom) — pure-logic units, component render/interaction tests for every major widget, and an 80/70 coverage gate in CI.

**Architecture:** One Vitest runner over jsdom. Pure functions tested directly; components tested with RTL + `user-event` against a shared typed `AnalysisOutput` fixture; jsdom gaps polyfilled in a setup file. Coverage (v8) thresholds enforced in the existing CI `ui` job.

**Tech Stack:** Vitest 1.x, jsdom, @testing-library/{react,jest-dom,user-event}, @vitest/coverage-v8. React 18 + TypeScript strict + Vite 5.

**Spec:** `docs/superpowers/specs/2026-06-20-ui-test-suite-design.md`

## Global Constraints

- **No new runtime dependencies** — all additions are `devDependencies`.
- **These tests target EXISTING code** (not TDD-first). The cycle is: write test → run → expect **PASS**. A failing test means either a real bug (fix it + note it in the commit) or a wrong test (fix the test) — never leave a failing test or weaken an assertion to make it pass.
- **Run tests** from `ui/`. node may not be on PATH; prepend `C:\Program Files\nodejs` (Bash: `export PATH="/c/Program Files/nodejs:$PATH"`). Commands: `npm test` (= `vitest run`), `npm run test:coverage`. A single file: `npx vitest run src/path/to/file.test.ts`.
- **Typecheck** still gates: `npx tsc --noEmit -p tsconfig.json` (exit 0). Tests are `.ts`/`.tsx`, type-checked by `tsc`.
- **TS strict** (noUnusedLocals/Params); use `import type` for types.
- **Coverage gate:** lines/functions/statements ≥ 80%, branches ≥ 70% over `src/**` minus the spec's exclude list. Do not lower the bar without flagging.
- **Branch:** `feat/ui-test-suite`. Commit after every task.
- **Fixture, not demo:** test data lives in `src/test/fixtures.ts` — never reintroduce a rendered demo page.

---

## File Structure

| File | Responsibility |
|---|---|
| `ui/package.json` | + devDeps, + `test`/`test:watch`/`test:coverage` scripts |
| `ui/vitest.config.ts` | **new** — jsdom env, setup, v8 coverage + thresholds + excludes |
| `ui/src/test/setup.ts` | **new** — jest-dom matchers + jsdom polyfills (matchMedia, observers, scrollTo) |
| `ui/src/test/fixtures.ts` | **new** — `makeOutput()` + flow-row helpers (typed `AnalysisOutput`) |
| `ui/src/test/render.tsx` | **new** — tiny RTL re-export + a `getBoundingClientRect` sizing helper for virtualized tests |
| `ui/src/**/*.test.ts(x)` | **new** — colocated unit + component tests |
| `.github/workflows/ci.yml` | + `npm run test:coverage` step in the `ui` job |

---

## Task 1: Test harness

**Files:**
- Modify: `ui/package.json`
- Create: `ui/vitest.config.ts`, `ui/src/test/setup.ts`, `ui/src/test/sanity.test.ts`

**Interfaces:**
- Produces: a working `npm test`; the `vitest.config.ts` coverage block (thresholds + excludes) consumed by Task 8.

- [ ] **Step 1: Install dev dependencies.** From `ui/`:
```bash
npm i -D vitest@^1.6.0 jsdom@^24 @testing-library/react@^16 @testing-library/jest-dom@^6 @testing-library/user-event@^14 @vitest/coverage-v8@^1.6.0
```
(Versions: Vitest 1.x pairs with `@vitest/coverage-v8` 1.x and Vite 5. RTL 16 supports React 18.)

- [ ] **Step 2: Create `ui/vitest.config.ts`.**
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
    restoreMocks: true,
    coverage: {
      provider: "v8",
      reporter: ["text", "html"],
      include: ["src/**/*.{ts,tsx}"],
      exclude: [
        "src/main.tsx", "src/**/*.d.ts", "src/types.ts", "src/vite-env.d.ts",
        "src/lib/platform.ts", "src/lib/wasmEngine.ts", "src/lib/recent.ts", "src/wasm/**",
        "src/components/triage/**", "src/components/TopTalkers.tsx",
        "src/components/layout/DashboardGrid.tsx", "src/components/layout/Panel.tsx",
        "src/components/layout/StatTile.tsx", "src/components/layout/TabBar.tsx",
        "src/components/primitives/Chip.tsx",
        "src/test/**", "**/*.test.{ts,tsx}",
      ],
      thresholds: { lines: 80, functions: 80, statements: 80, branches: 70 },
    },
  },
});
```

- [ ] **Step 3: Create `ui/src/test/setup.ts`** (jest-dom + jsdom polyfills the components need).
```ts
import "@testing-library/jest-dom/vitest";
import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

afterEach(() => cleanup());

// App auto-collapse reads matchMedia.
if (!window.matchMedia) {
  window.matchMedia = (query: string) =>
    ({ matches: false, media: query, onchange: null,
       addEventListener: () => {}, removeEventListener: () => {},
       addListener: () => {}, removeListener: () => {}, dispatchEvent: () => false }) as MediaQueryList;
}

// Observers used by virtualization / charts.
class NoopObserver { observe() {} unobserve() {} disconnect() {} }
vi.stubGlobal("ResizeObserver", NoopObserver);
vi.stubGlobal("IntersectionObserver", NoopObserver);

// jsdom lacks these.
if (!Element.prototype.scrollTo) Element.prototype.scrollTo = () => {};
```

- [ ] **Step 4: Add scripts to `ui/package.json`** (in `"scripts"`):
```json
"test": "vitest run",
"test:watch": "vitest",
"test:coverage": "vitest run --coverage"
```

- [ ] **Step 5: Create a sanity test** `ui/src/test/sanity.test.ts`:
```ts
import { describe, it, expect } from "vitest";
describe("harness", () => {
  it("runs and has jsdom", () => {
    expect(typeof document).toBe("object");
    expect(1 + 1).toBe(2);
  });
});
```

- [ ] **Step 6: Run.** `npm test` → PASS (1 file, 1 test). Then `npx tsc --noEmit -p tsconfig.json` → exit 0.

- [ ] **Step 7: Commit.**
```bash
git add ui/package.json ui/package-lock.json ui/vitest.config.ts ui/src/test/setup.ts ui/src/test/sanity.test.ts
git commit -m "test: vitest + RTL + jsdom harness with coverage config"
```

---

## Task 2: Shared fixture + render helper

**Files:**
- Create: `ui/src/test/fixtures.ts`, `ui/src/test/render.tsx`, `ui/src/test/fixtures.test.ts`

**Interfaces:**
- Produces:
  - `makeOutput(overrides?: Partial<AnalysisOutput>): AnalysisOutput` — valid engine output: one CRITICAL multi-stage incident on `10.13.37.7` (host_sweep + beacon + data_exfil findings), `ip_threats` for `10.13.37.7` (incident host) and `45.77.13.37` (non-incident), a `time_histogram` whose max-bytes bucket is the exfil, `category_breakdown` with `c2` (critical) + `web` (info), `proto` satisfying `tls+http+other_tcp==tcp`, `dns+other_udp==udp`, `tcp+udp+non_ipv4==total_packets`, and `severity_counts` with **critical:0**.
  - `makeFlows(n?: number): FlowRow[]` — normalized rows with varied bytes (one large) for sort tests.
  - `render` (re-export of RTL render), `screen`, `userEvent`, and `sizeScrollElement(el)` (sets a non-zero `getBoundingClientRect` for virtualized lists).

- [ ] **Step 1: Create `ui/src/test/fixtures.ts`.**
```ts
import type { AnalysisOutput, Finding, FlowRow, IpThreat } from "../types";

const f = (p: Partial<Finding> & Pick<Finding, "kind" | "severity" | "score" | "title" | "src_ip">): Finding => ({
  dst_ip: null, dst_port: null, attack: [], evidence: [],
  interval_ns: null, jitter_cv: null, contacts: null, ...p,
});

const incident1Findings: Finding[] = [
  f({ kind: "host_sweep", severity: "high", score: 65, src_ip: "10.13.37.7", dst_port: 445,
      title: "Host sweep: 10.13.37.7 probed 24 hosts on port 445", attack: ["T1046"], contacts: 24 }),
  f({ kind: "beacon", severity: "high", score: 70, src_ip: "10.13.37.7", dst_ip: "45.77.13.37", dst_port: 443,
      title: "Periodic beacon: 10.13.37.7 -> 45.77.13.37:443", attack: ["T1071"],
      interval_ns: 30_000_000_000, jitter_cv: 0.013, contacts: 2999 }),
  f({ kind: "data_exfil", severity: "high", score: 72, src_ip: "10.13.37.7", dst_ip: "185.220.101.5", dst_port: 443,
      title: "Data exfiltration: 10.13.37.7 -> 185.220.101.5:443 (1.2 MB out)", attack: ["T1048"] }),
];

const ip_threats: IpThreat[] = [
  { ip: "10.13.37.7", ip_class: "private", severity: "critical", score: 89, flows: 3100, bytes: 1_738_997,
    ioc: false, tags: ["internal"], attack: ["T1046", "T1071", "T1048"], evidence: ["multi-stage kill chain"] },
  { ip: "45.77.13.37", ip_class: "public", severity: "high", score: 72, flows: 2999, bytes: 404_865,
    ioc: true, tags: ["public", "c2"], attack: ["T1071"], evidence: ["periodic beaconing to 45.77.13.37:443"] },
];

// time_histogram: flat baseline + one exfil peak (max bytes) at index 5.
const time_histogram = Array.from({ length: 12 }, (_, i) => ({
  epoch_sec: 1_700_000_000 + i * 120,
  pkts: i === 5 ? 1850 : 120,
  bytes: i === 5 ? 1_180_000 : 16_000,
}));

export function makeOutput(overrides: Partial<AnalysisOutput> = {}): AnalysisOutput {
  return {
    schema_version: 1, engine_version: "0.1.0",
    source_path: "captures/test.pcap", source_sha256: "deadbeef".repeat(8),
    source_bytes: 6_000_000, link_type: "EN10MB", elapsed_ms: 100,
    summary: {
      total_packets: 40_000, total_bytes: 5_700_000, captured_bytes: 5_700_000,
      total_flows: 39_000, decode_errors: 0, non_ip_frames: 0,
      proto: { tcp: 27_838, udp: 12_162, dns: 12_162, http: 11_922, tls: 15_836, other_tcp: 80, other_udp: 0, truncated: 0, non_ipv4: 0 },
      first_ts_ns: 1_700_000_000_000_000_000, last_ts_ns: 1_700_000_120_000_000_000, duration_ns: 120_000_000_000,
      unique_hosts: 96,
      top_talkers: [
        { ip: "10.13.37.7", pkts: 4017, bytes: 1_738_997, flows: 3100 },
        { ip: "45.77.13.37", pkts: 2999, bytes: 404_865, flows: 2999 },
        { ip: "10.0.0.9", pkts: 1181, bytes: 132_848, flows: 1181 },
      ],
      protocol_hierarchy: [], port_histogram: [], time_histogram, time_bucket_secs: 120,
      category_breakdown: [
        { category: "web", flows: 26_859, pkts: 27_758, bytes: 4_788_108 },
        { category: "c2", flows: 8, pkts: 2999, bytes: 404_865 },
      ],
      severity_counts: { critical: 0, high: 12, medium: 280, low: 3000, info: 35_708 },
      ip_threats,
      findings: incident1Findings,
      incidents: [
        { host: "10.13.37.7", severity: "critical", score: 89,
          title: "Multi-stage incident on 10.13.37.7",
          narrative: "10.13.37.7 swept the network, then beaconed to a C2, then exfiltrated data.",
          stages: ["Discovery", "Command & Control", "Exfiltration"],
          attack: ["T1046", "T1071", "T1048"], findings: incident1Findings },
      ],
    },
    ...overrides,
  };
}

export function makeFlows(n = 5): FlowRow[] {
  return Array.from({ length: n }, (_, i): FlowRow => ({
    flowId: i, flowIdBig: BigInt(i), captureId: 0,
    srcIp: "10.0.0.1", dstIp: i === 0 ? "185.220.101.5" : "10.0.0.2",
    srcPort: 40000 + i, dstPort: 443, proto: 6, protoLabel: "TCP",
    appProto: "TLS", appProtoSrc: "payload", sni: null,
    bytesC2s: i === 0 ? 1_200_000 : 1000, bytesS2c: 500,
    bytesTotal: (i === 0 ? 1_200_000 : 1000) + 500,
    pkts: 10, startMs: 1_700_000_000_000 + i * 1000, endMs: 1_700_000_001_000 + i * 1000, durationMs: 1000,
    tcpFlagsC2s: 0, tcpFlagsS2c: 0, ttlMinC2s: 64, category: "web", severity: "info", threatScore: 0, ioc: false,
  }));
}
```

- [ ] **Step 2: Create `ui/src/test/render.tsx`** (test utilities).
```tsx
export { render, screen, within, waitFor, fireEvent, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
export { userEvent };

/** jsdom returns 0-size rects; TanStack Virtual needs a measured scroll element. */
export function sizeScrollElement(el: HTMLElement, height = 600, scrollHeight = 6000) {
  Object.defineProperty(el, "getBoundingClientRect", {
    configurable: true,
    value: () => ({ width: 1000, height, top: 0, left: 0, right: 1000, bottom: height, x: 0, y: 0, toJSON() {} }),
  });
  Object.defineProperty(el, "clientHeight", { configurable: true, value: height });
  Object.defineProperty(el, "scrollHeight", { configurable: true, value: scrollHeight });
}
```

- [ ] **Step 3: Create `ui/src/test/fixtures.test.ts`** — assert the fixture's invariants (these guard the fixture itself):
```ts
import { describe, it, expect } from "vitest";
import { makeOutput } from "./fixtures";

describe("makeOutput fixture", () => {
  const o = makeOutput();
  const p = o.summary.proto;
  it("proto leaf invariants hold", () => {
    expect(p.tls + p.http + p.other_tcp).toBe(p.tcp);
    expect(p.dns + p.other_udp).toBe(p.udp);
    expect(p.tcp + p.udp + p.non_ipv4).toBe(o.summary.total_packets);
  });
  it("has zero critical flows but a critical incident (data trap)", () => {
    expect(o.summary.severity_counts!.critical).toBe(0);
    expect(o.summary.incidents!.some((i) => i.severity === "critical")).toBe(true);
  });
  it("has a data_exfil finding and an exfil-peak bucket", () => {
    expect(o.summary.findings!.some((f) => f.kind === "data_exfil")).toBe(true);
    const max = Math.max(...o.summary.time_histogram.map((b) => b.bytes));
    expect(o.summary.time_histogram[5].bytes).toBe(max);
  });
});
```

- [ ] **Step 4: Run + typecheck.** `npx vitest run src/test/fixtures.test.ts` → PASS. `npx tsc --noEmit -p tsconfig.json` → exit 0.

- [ ] **Step 5: Commit.**
```bash
git add ui/src/test/fixtures.ts ui/src/test/render.tsx ui/src/test/fixtures.test.ts
git commit -m "test: shared AnalysisOutput fixture + render helpers"
```

---

## Task 3: Pure-logic tests — `cockpit/match` + `cockpit/viz`

**Files:** Create `ui/src/cockpit/match.test.ts`, `ui/src/cockpit/viz.test.ts`

- [ ] **Step 1: `match.test.ts`** — full code:
```ts
import { describe, it, expect } from "vitest";
import { fuzzyScore } from "./match";

describe("fuzzyScore", () => {
  it("returns null when not a subsequence", () => {
    expect(fuzzyScore("xyz", "10.0.0.1")).toBeNull();
  });
  it("returns 0 for empty query", () => {
    expect(fuzzyScore("", "anything")).toBe(0);
  });
  it("matches a subsequence", () => {
    expect(fuzzyScore("103", "10.13.37.7")).not.toBeNull();
  });
  it("is case-insensitive", () => {
    expect(fuzzyScore("FLOWS", "Go to Flows")).not.toBeNull();
  });
  it("ranks a prefix/contiguous match above a scattered one", () => {
    const prefix = fuzzyScore("flo", "Flows")!;
    const scattered = fuzzyScore("flo", "Foo lorem o")!;
    expect(prefix).toBeGreaterThan(scattered);
  });
});
```

- [ ] **Step 2: `viz.test.ts`** — full code (includes the protoSegments regression):
```ts
import { describe, it, expect } from "vitest";
import { clamp01, circumference, polarToCartesian, sparkline, protoSegments } from "./viz";
import { makeOutput } from "../test/fixtures";

describe("viz geometry", () => {
  it("clamp01 clamps", () => {
    expect(clamp01(-1)).toBe(0); expect(clamp01(2)).toBe(1); expect(clamp01(0.5)).toBe(0.5);
  });
  it("circumference = 2*pi*r", () => {
    expect(circumference(10)).toBeCloseTo(2 * Math.PI * 10);
  });
  it("polarToCartesian: 0deg is straight up", () => {
    const p = polarToCartesian(0, 0, 10, 0);
    expect(p.x).toBeCloseTo(0); expect(p.y).toBeCloseTo(-10);
  });
  it("sparkline returns empty for no values and a path for values", () => {
    expect(sparkline([], 80, 20).line).toBe("");
    expect(sparkline([1, 2, 3], 80, 20).line.startsWith("M")).toBe(true);
  });
});

describe("protoSegments", () => {
  it("is the leaf partition that sums to total_packets (no double-count)", () => {
    const o = makeOutput().summary;
    const segs = protoSegments(o.proto);
    // never includes the L4 parents tcp/udp
    expect(segs.find((s) => s.key === "tcp")).toBeUndefined();
    expect(segs.find((s) => s.key === "udp")).toBeUndefined();
    const sum = segs.reduce((a, s) => a + s.value, 0);
    expect(sum).toBe(o.total_packets);
  });
  it("filters zero-value segments", () => {
    const segs = protoSegments(makeOutput().summary.proto);
    expect(segs.every((s) => s.value > 0)).toBe(true);
  });
});
```

- [ ] **Step 3: Run.** `npx vitest run src/cockpit/match.test.ts src/cockpit/viz.test.ts` → all PASS. (If `protoSegments` sum fails, it's a real regression — STOP and report.)

- [ ] **Step 4: Commit.**
```bash
git add ui/src/cockpit/match.test.ts ui/src/cockpit/viz.test.ts
git commit -m "test: fuzzyScore + viz geometry + protoSegments leaf-partition"
```

---

## Task 4: Pure-logic tests — `lib/severity` + `lib/format` + `lib/data`

**Files:** Create `ui/src/lib/severity.test.ts`, `ui/src/lib/format.test.ts`, `ui/src/lib/data.test.ts`

- [ ] **Step 1: `severity.test.ts`** — assert: `normCategory("file-transfer")==="file_transfer"` and trims/lowercases; `severityForCategory("c2")==="critical"`, `"scan"==="high"`, `"web"==="info"`, unknown token →`"none"`; `SEVERITY_ORDER` is `["critical","high","medium","low","info"]`; `rollupSeverity([{category:"c2",flows:8,pkts:2999,bytes:404865},{category:"web",flows:100,pkts:100,bytes:100}])` puts c2's flows under `critical` and web's under `info`, and `total.flows===108`. Write one `it` per clause with explicit `expect`s.

- [ ] **Step 2: `format.test.ts`** — assert exact strings:
```ts
import { describe, it, expect } from "vitest";
import { humanBytes, humanNumber, compactNumber, percent, durationHumanNs, shortHash, basename } from "./format";
describe("format", () => {
  it("humanBytes", () => {
    expect(humanBytes(0)).toBe("0 B");
    expect(humanBytes(5_700_000)).toBe("5.44 MB");
    expect(humanBytes(1024)).toBe("1.00 KB");
  });
  it("humanNumber / compactNumber", () => {
    expect(humanNumber(40000)).toBe("40,000");
    expect(compactNumber(40000)).toBe("40K");
  });
  it("percent (incl. zero total)", () => {
    expect(percent(1, 4)).toBe("25.0%");
    expect(percent(1, 0)).toBe("0%");
  });
  it("durationHumanNs", () => {
    expect(durationHumanNs(120_000_000_000)).toBe("2m 0.0s");
  });
  it("shortHash / basename", () => {
    expect(shortHash("abcdef0123456789", 4, 4)).toBe("abcd…6789");
    expect(basename("a/b/c.pcap")).toBe("c.pcap");
    expect(basename("a\\b\\c.pcap")).toBe("c.pcap");
  });
});
```
(If any expected string differs from the implementation, the IMPLEMENTATION is the source of truth — read `lib/format.ts` and assert what it actually returns; do not change `format.ts`.)

- [ ] **Step 3: `data.test.ts`** — `normalizeFlow` on a `RawFlowRow` (bigints + `Date`s): assert `flowId`/`captureId` are numbers, `bytesTotal === bytesC2s + bytesS2c`, `durationMs === endMs - startMs`, `protoLabel === "TCP"` for proto 6, `severity` falls back via category when the column is null. Construct the `RawFlowRow` inline with `new Date(...)` and `BigInt(...)`.

- [ ] **Step 4: Run** the three files → PASS. **Step 5: Commit** `test: lib severity/format/data units`.

---

## Task 5: Component tests — shell widgets (CommandPalette, ThreatRail, CommandBar, instruments)

**Files:** Create `ui/src/cockpit/{CommandPalette,ThreatRail,CommandBar,instruments}.test.tsx`

Pattern for every component test: `import { render, screen, userEvent } from "../test/render";` then render with props/fixture and assert. Use `await userEvent.setup()` for interactions; prefer `findBy*`/`waitFor` over delays.

- [ ] **Step 1: `CommandPalette.test.tsx`** — full code for the hard behaviors:
```tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen, userEvent } from "../test/render";
import { CommandPalette, type PaletteAction } from "./CommandPalette";
import { makeOutput } from "../test/fixtures";

const threats = makeOutput().summary.ip_threats!;
const actions = (run = vi.fn()): PaletteAction[] => [
  { id: "go-flows", label: "Go to Flows", run },
  { id: "load", label: "Load capture", run },
];

describe("CommandPalette", () => {
  it("does not render when closed", () => {
    render(<CommandPalette open={false} onClose={() => {}} actions={actions()} threats={threats} onSelectHost={() => {}} />);
    expect(screen.queryByLabelText("Command palette query")).toBeNull();
  });
  it("filters actions by fuzzy query", async () => {
    const u = userEvent.setup();
    render(<CommandPalette open onClose={() => {}} actions={actions()} threats={[]} onSelectHost={() => {}} />);
    await u.type(screen.getByLabelText("Command palette query"), "flows");
    expect(screen.getByText("Go to Flows")).toBeInTheDocument();
    expect(screen.queryByText("Load capture")).toBeNull();
  });
  it("Enter runs the highlighted action and closes", async () => {
    const u = userEvent.setup(); const run = vi.fn(); const onClose = vi.fn();
    render(<CommandPalette open onClose={onClose} actions={actions(run)} threats={[]} onSelectHost={() => {}} />);
    await u.type(screen.getByLabelText("Command palette query"), "flows");
    await u.keyboard("{Enter}");
    expect(run).toHaveBeenCalled(); expect(onClose).toHaveBeenCalled();
  });
  it("host query → onSelectHost", async () => {
    const u = userEvent.setup(); const onSelectHost = vi.fn();
    render(<CommandPalette open onClose={() => {}} actions={actions()} threats={threats} onSelectHost={onSelectHost} />);
    await u.type(screen.getByLabelText("Command palette query"), "45.77");
    await u.keyboard("{Enter}");
    expect(onSelectHost).toHaveBeenCalledWith("45.77.13.37");
  });
  it("Escape closes", async () => {
    const u = userEvent.setup(); const onClose = vi.fn();
    render(<CommandPalette open onClose={onClose} actions={actions()} threats={[]} onSelectHost={() => {}} />);
    await u.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: `ThreatRail.test.tsx`** — render with `makeOutput().summary.ip_threats`, `collapsed={false}`, `onSelect`. Assert: the CRITICAL host (`10.13.37.7`) row appears before the `high` host (worst-first); clicking a row calls `onSelect("10.13.37.7")` (use the `aria-label^="10.13.37.7"` button); with `collapsed`, the IP text is absent but the row buttons (50→here 2) still exist (dots). One full example:
```tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen, userEvent } from "../test/render";
import { ThreatRail } from "./ThreatRail";
import { makeOutput } from "../test/fixtures";
it("worst-first order + row click", async () => {
  const u = userEvent.setup(); const onSelect = vi.fn();
  render(<ThreatRail threats={makeOutput().summary.ip_threats!} collapsed={false} activeIp={null} onSelect={onSelect} />);
  const labels = screen.getAllByRole("button").map((b) => b.getAttribute("aria-label") || "");
  expect(labels[0]).toContain("10.13.37.7"); // critical first
  await u.click(screen.getByRole("button", { name: /^10\.13\.37\.7/ }));
  expect(onSelect).toHaveBeenCalledWith("10.13.37.7");
});
```
Add the remaining `it`s (collapsed mode hides IP text; `activeIp` sets `aria-current`).

- [ ] **Step 3: `CommandBar.test.tsx`** — render with `tabs=[{id:"dashboard",label:"Dashboard"},{id:"recent",label:"Recent",badge:3}]`, `activeTab="dashboard"`, handlers via `vi.fn()`. Assert: Recent badge "3" shows; the active tab has `aria-pressed="true"`; clicking a tab calls `onTab`; the Load button calls `onRequestLoad`; the ⌘K button calls `onOpenPalette`; Export disabled when `onExport` omitted. (`captureStatus="ready"` with a `captureName` shows the name.)

- [ ] **Step 4: `instruments.test.tsx`** — smoke render `ScoreRing` (score 89, severity critical), `SeverityRing` (counts), `BeaconRadar` — each renders an `<svg>` without throwing; `ScoreRing` shows "89". Keep these minimal.

- [ ] **Step 5: Run** all four files → PASS. **Step 6: Commit** `test: shell widget components (palette/rail/commandbar/instruments)`.

---

## Task 6: Component tests — canvas widgets

**Files:** Create `ui/src/cockpit/{KpiCluster,IncidentHero,CategoryMatrix,ProtocolMix,TopTalkersCard,CaptureIntegrity,ActivityHeatmap}.test.tsx`. Each renders with `makeOutput()` (or its sub-objects) via `../test/render`.

- [ ] **Step 1: `CaptureIntegrity.test.tsx`** — full code (the null-sha regression):
```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { CaptureIntegrity } from "./CaptureIntegrity";
import { makeOutput } from "../test/fixtures";
describe("CaptureIntegrity", () => {
  it("renders the integrity card", () => {
    render(<CaptureIntegrity output={makeOutput()} />);
    expect(screen.getByText(/Capture integrity/i)).toBeInTheDocument();
  });
  it("does not crash when source_sha256 is null", () => {
    const o = makeOutput({ source_sha256: null as unknown as string });
    expect(() => render(<CaptureIntegrity output={o} />)).not.toThrow();
  });
});
```

- [ ] **Step 2: `ProtocolMix.test.tsx`** — render `<ProtocolMix proto={makeOutput().summary.proto} />`; assert each legend percent text exists and the percents are derived from the leaf total (e.g. TLS shows `39.6%`, computed as `15836/40000`); assert the TLS-heavy caption renders. (Read `ProtocolMix.tsx` for the exact legend text format.)

- [ ] **Step 3: `CategoryMatrix.test.tsx`** — render `<CategoryMatrix breakdown={makeOutput().summary.category_breakdown} onJump={fn} />`; assert the `c2` (critical) row label appears above the `web` (info) row (severity-first), and clicking a row calls `onJump` with the category token.

- [ ] **Step 4: `KpiCluster.test.tsx`** — render `<KpiCluster output={makeOutput()} />`; assert the incident count "1" + "CRITICAL" verdict shows; then render with an all-`high` incident (`makeOutput({ summary: { ...makeOutput().summary, incidents: [{...crit, severity:"high"}] } })` — simplest: build via overrides) and assert the verdict is NOT colored critical-red (check the count is not styled `--color-sev-critical`; assert the AlertOctagon/critical marker is absent). Keep it to the verdict-color behavior + a render smoke.

- [ ] **Step 5: `IncidentHero.test.tsx`** — render `<IncidentHero incident={makeOutput().summary.incidents![0]} primary onPivot={fn} onOpen={fn} />`; assert host, score "89", a kill-chain stage label, the beacon radar ("Beacon lock") present (a beacon finding exists), and a MITRE tag; clicking the evidence/pivot fires the callbacks.

- [ ] **Step 6: `TopTalkersCard.test.tsx`** — render with `makeOutput().summary.top_talkers`; assert rows for the IPs, the flagged host marker on `45.77.13.37`, and `onSelect` on row click.

- [ ] **Step 7: `ActivityHeatmap.test.tsx`** — render `<ActivityHeatmap histogram={hist} bucketSecs={120} findings={findings} />`. With a `data_exfil` finding present → the marker caption reads "exfil burst"; render again with `findings={[]}` → caption reads "peak volume" (neutral). Assert the cell count equals the histogram length.

- [ ] **Step 8: Run** all seven → PASS. **Step 9: Commit** `test: canvas widget components`.

---

## Task 7: Integration + smoke (App, AppShell, Dashboard, Flows/Recent)

**Files:** Create `ui/src/App.test.tsx`, `ui/src/components/layout/AppShell.test.tsx`, `ui/src/components/Dashboard.test.tsx`, `ui/src/views/FlowsView.test.tsx`, `ui/src/components/recent/RecentView.test.tsx`

- [ ] **Step 1: `App.test.tsx`** — the openThreat routing. App fetches the sample on mount, so mock the data layer:
```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, userEvent, waitFor } from "./test/render";
import { makeOutput, makeFlows } from "./test/fixtures";

vi.mock("./lib/data", () => ({
  loadSummary: vi.fn(async () => makeOutput()),
  loadFlows: vi.fn(async () => makeFlows()),
}));
vi.mock("./lib/platform", () => ({
  isTauri: () => false,
  openCaptureDialog: vi.fn(), analyzeViaTauri: vi.fn(), exportReport: vi.fn(),
}));

import App from "./App";

describe("App routing", () => {
  beforeEach(() => localStorage.clear());
  it("rail click on the incident host opens its flyout on the dashboard", async () => {
    const u = userEvent.setup();
    render(<App />);
    await screen.findByRole("button", { name: /^10\.13\.37\.7/ }); // rail populated
    await u.click(screen.getByRole("button", { name: /^10\.13\.37\.7/ }));
    await waitFor(() => expect(screen.getByRole("dialog", { name: /Incident detail for 10\.13\.37\.7/i })).toBeInTheDocument());
  });
  it("rail click on a non-incident host routes to filtered Flows", async () => {
    const u = userEvent.setup();
    render(<App />);
    await u.click(await screen.findByRole("button", { name: /^45\.77\.13\.37/ }));
    const filter = await screen.findByLabelText("Filter flows");
    expect((filter as HTMLInputElement).value).toBe("45.77.13.37");
  });
});
```
(If `App` reads other modules on mount that break under jsdom — e.g. `lib/recent` — add a `vi.mock("./lib/recent", () => ({ listRecent: () => [], recordRecent: () => [], getFlows: vi.fn(), putFlows: vi.fn(), entryId: () => "x", removeRecent: () => [], clearRecent: () => [] }))`. Read `App.tsx` imports first and mock exactly what mount touches.)

- [ ] **Step 2: `AppShell.test.tsx`** — render `<AppShell {...minimalProps}>child</AppShell>` with `vi.fn()` handlers and `makeOutput().summary.ip_threats` as `threats`. Assert: the child renders, the rail renders the threats, and dispatching `new KeyboardEvent("keydown",{key:"k",ctrlKey:true})` on window calls `onPaletteOpenChange(true)`. Build `minimalProps` from `AppShellProps` (read the interface) — `summary={{status:"ready",data:makeOutput()}}`, `paletteOpen={false}`, etc.

- [ ] **Step 3: `Dashboard.test.tsx`** — render `<Dashboard output={makeOutput()} selectedIncident={null} onSelectIncident={fn} />`; assert the hero (host 10.13.37.7), the "Threat watchlist" card, the "Activity" heatmap, and "Category threat matrix" are present (render smoke). Then render with `selectedIncident={makeOutput().summary.incidents![0]}` and assert the flyout dialog is open.

- [ ] **Step 4: `FlowsView.test.tsx`** — render `<FlowsView state={{status:"ready", rows: makeFlows(20)}} />`. Before asserting rows, size the scroll element: after render, `sizeScrollElement(container.querySelector('[role=grid]')!)` then re-query. Assert: rows render, the default-sorted first row shows the largest bytes (`1.25 MB` style — the big flow), and typing in "Filter flows" narrows the rows. (FlowsTable virtualization needs the sized scroll element from `render.tsx`.)

- [ ] **Step 5: `RecentView.test.tsx`** — render `<RecentView entries={[entry]} ... />` with a hand-built `RecentEntry` (read the type) and `vi.fn()` callbacks; assert the entry name renders and clicking it fires `onOpen`, the remove control fires `onRemove`.

- [ ] **Step 6: Run** all five → PASS. **Step 7: Commit** `test: App routing + AppShell/Dashboard/Flows/Recent integration & smoke`.

---

## Task 8: Coverage gate + CI

**Files:** Modify `.github/workflows/ci.yml`

- [ ] **Step 1: Run coverage.** `npm run test:coverage`. Read the text report. If it passes the 80/80/80/70 thresholds → proceed. If it falls short on a covered file, ADD focused tests for the uncovered branches (do not lower the threshold; do not add files to `exclude` to game it). Re-run until the gate passes. If a genuinely-untestable integration file is dragging it down, STOP and flag to the controller (the bar was agreed at 80/70).

- [ ] **Step 2: Add the CI step.** In `.github/workflows/ci.yml`, in the `ui` job's `steps:`, add after `- run: npm ci`:
```yaml
      - run: npm run test:coverage
```
(Keep `- run: npm run build` as well.)

- [ ] **Step 3: Verify the workflow YAML is valid** (indentation matches the existing steps; 6-space indent under `steps:`).

- [ ] **Step 4: Final run.** `npm run test:coverage` → all tests PASS and thresholds met. `npx tsc --noEmit -p tsconfig.json` → exit 0.

- [ ] **Step 5: Commit.**
```bash
git add .github/workflows/ci.yml
git commit -m "ci: run vitest coverage gate in the ui job"
```

---

## Self-review notes (author)

- **Spec coverage:** §3 stack/config → Task 1; §4 fixture → Task 2; §5 pure logic → Tasks 3–4; §6 components → Tasks 5–6 (widgets) + Task 7 (Dashboard/AppShell/App/Flows/Recent); §7 coverage gate + CI → Task 8; §8 risks (jsdom polyfills, FlowsTable sizing, no fixed delays) → setup.ts (Task 1) + `sizeScrollElement` (Task 2) + the `findBy/waitFor` pattern (Tasks 5–7). All covered.
- **Type consistency:** `makeOutput`/`makeFlows`/`sizeScrollElement` signatures defined in Task 2 are used verbatim in Tasks 3–7; `PaletteAction` imported from `./CommandPalette` matches Task 5 of the cockpit-shell plan; component prop names (`output`, `incident`, `selectedIncident`/`onSelectIncident`, `threats`/`collapsed`/`activeIp`/`onSelect`, `paletteOpen`/`onPaletteOpenChange`) match the merged source.
- **Tests target existing code** (not TDD) — each "Run" step expects PASS; a failure is a real bug to report, not a step to skip. Stated in Global Constraints.
- **No coverage-gaming:** Task 8 forbids lowering thresholds or padding `exclude` to pass; shortfalls are filled with real tests or escalated.
