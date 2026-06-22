# Detection→UI Transparency Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface the reasoning the engine already computes — per-provider reputation verdicts, per-finding evidence and scores, and grouped severity rationale — that the UI currently drops at render time.

**Architecture:** Pure UI-rendering feature. A survey verified every field rendered already crosses the WASM/Tauri boundary and is declared in `ui/src/types.ts`. Build four small, pure, unit-tested primitive components in `ui/src/components/transparency/`, then compose them into five existing surfaces. No engine, WASM, Tauri, or `types.ts` change. Directional packet counts are deferred (need a Parquet schema column).

**Tech Stack:** React 18 + TypeScript + Tailwind (cockpit conventions: CSS vars, `t-tag`), Vitest + React Testing Library + jsdom.

## Global Constraints

- **No new runtime dependencies. No engine/WASM/Tauri/`types.ts` change.** Every field used is already declared in `ui/src/types.ts`.
- **The `npm run test:coverage` gate stays green:** lines/functions/statements ≥ 80, branches ≥ 70. Verify under the locked toolchain (`npm ci` → `npm run build` → `npm run test:coverage`) before completion — local `node_modules` may have drifted; CI uses vitest 1.6.1.
- **No coupling to engine string formats:** the evidence "explainer" renders `evidence[]` strings as-is (grouped by the prefix before the first `:`); it does NOT parse signed point-terms (`+45`, `-10`).
- **Match cockpit styling:** CSS vars (`var(--color-*)`), `t-tag`, `font-mono-num`, and the existing severity palette (`severityColor` from `ui/src/lib/palette.ts`).
- **Components render nothing on empty/absent data** (no "no data" placeholders, no crashes).
- **TOOLCHAIN:** node/npx at `/c/Program Files/nodejs/`. Tests: `cd ui && npx vitest run <path>`. Do NOT run `npm install`/`npm i` (it re-drifts the lock); node_modules is pre-provisioned.
- **Stage specific files** on commit (never `git add -A` — untracked `ui/coverage/`, `ui/.claude/` must not be swept).

## Reference: existing types (in `ui/src/types.ts`, already declared)

```ts
type RepStatus = "malicious" | "benign" | "clean" | "unknown" | "notfound" | "unavailable";
interface ReputationVerdict {
  source: string; status: RepStatus; malicious: boolean;
  score: number | null;            // 0..=100; null when unknown/notfound/unavailable
  tags: string[]; link: string | null; fetched_at: number; // unix seconds
}
interface IpThreat {
  ip; ip_class; severity: Severity; score: number; flows; bytes; ioc;
  tags: string[]; attack: string[]; evidence: string[]; reputation?: ReputationVerdict[];
}
interface Finding {
  kind; severity: Severity; score: number; title; src_ip; dst_ip; dst_port;
  attack: string[]; evidence: string[];
  interval_ns: number | null; jitter_cv: number | null; contacts: number | null;
}
type Severity = "critical" | "high" | "medium" | "low" | "info" | "none";
```

## Reference: existing severity helper (reuse, do not duplicate)

```ts
// ui/src/lib/palette.ts
export function severityColor(sev: Severity): string;   // → literal color via cssVar(SEVERITY_META[sev].cssVar)
```

---

### Task A1: `ScoreBadge` primitive

**Files:**
- Create: `ui/src/components/transparency/ScoreBadge.tsx`
- Test: `ui/src/components/transparency/ScoreBadge.test.tsx`

**Interfaces:**
- Produces: `export function ScoreBadge({ score, severity }: { score: number; severity?: Severity }): JSX.Element`

- [ ] **Step 1: Write the failing test** — `ui/src/components/transparency/ScoreBadge.test.tsx`

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ScoreBadge } from "./ScoreBadge";

describe("ScoreBadge", () => {
  it("renders the rounded score out of 100", () => {
    render(<ScoreBadge score={73} severity="high" />);
    expect(screen.getByText("73")).toBeInTheDocument();
    expect(screen.getByText("/100")).toBeInTheDocument();
  });

  it("clamps out-of-range scores to 0..100", () => {
    render(<ScoreBadge score={150} />);
    expect(screen.getByText("100")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/components/transparency/ScoreBadge.test.tsx` → FAIL (module not found).

- [ ] **Step 3: Implement** — `ui/src/components/transparency/ScoreBadge.tsx`

```tsx
import type { Severity } from "../../types";
import { severityColor } from "../../lib/palette";

/** A 0–100 score chip colored by severity band. */
export function ScoreBadge({ score, severity }: { score: number; severity?: Severity }) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const color = severity ? severityColor(severity) : "var(--color-text-dim)";
  return (
    <span
      className="font-mono-num inline-flex items-center rounded px-1.5 py-0.5 text-[0.7rem] font-semibold tabular-nums"
      style={{ color, backgroundColor: `color-mix(in srgb, ${color} 14%, transparent)` }}
      title={`Score ${clamped}/100`}
    >
      {clamped}
      <span className="text-[var(--color-text-faint)]">/100</span>
    </span>
  );
}
```

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/components/transparency/ScoreBadge.test.tsx` → PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add ui/src/components/transparency/ScoreBadge.tsx ui/src/components/transparency/ScoreBadge.test.tsx
git commit -m "feat(ui): ScoreBadge transparency primitive"
```

---

### Task A2: `EvidenceList` primitive

**Files:**
- Create: `ui/src/components/transparency/EvidenceList.tsx`
- Test: `ui/src/components/transparency/EvidenceList.test.tsx`

**Interfaces:**
- Produces: `export function EvidenceList({ evidence }: { evidence: string[] }): JSX.Element | null`

- [ ] **Step 1: Write the failing test** — `ui/src/components/transparency/EvidenceList.test.tsx`

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { EvidenceList } from "./EvidenceList";

describe("EvidenceList", () => {
  it("renders nothing when empty", () => {
    const { container } = render(<EvidenceList evidence={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("groups items by the prefix before the first colon", () => {
    render(
      <EvidenceList
        evidence={["reputation: abuseipdb malicious 78% (+25)", "c2: periodic beacon 60s"]}
      />,
    );
    expect(screen.getByText("reputation")).toBeInTheDocument();
    expect(screen.getByText("abuseipdb malicious 78% (+25)")).toBeInTheDocument();
    expect(screen.getByText("c2")).toBeInTheDocument();
    expect(screen.getByText("periodic beacon 60s")).toBeInTheDocument();
  });

  it("renders prefix-less strings without a group label", () => {
    render(<EvidenceList evidence={["high fan-out to 40 hosts"]} />);
    expect(screen.getByText("high fan-out to 40 hosts")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/components/transparency/EvidenceList.test.tsx` → FAIL (module not found).

- [ ] **Step 3: Implement** — `ui/src/components/transparency/EvidenceList.tsx`

```tsx
/** Group evidence strings by the signal prefix before the first ":". Prefix-less strings group under `null`. */
function groupEvidence(evidence: string[]): { label: string | null; items: string[] }[] {
  const order: (string | null)[] = [];
  const groups = new Map<string | null, string[]>();
  for (const e of evidence) {
    const idx = e.indexOf(":");
    const label = idx > 0 ? e.slice(0, idx).trim() : null;
    const item = idx > 0 ? e.slice(idx + 1).trim() : e;
    if (!groups.has(label)) {
      groups.set(label, []);
      order.push(label);
    }
    groups.get(label)!.push(item);
  }
  return order.map((label) => ({ label, items: groups.get(label)! }));
}

/** Renders the full evidence[] list, grouped by signal prefix. Renders nothing when empty. */
export function EvidenceList({ evidence }: { evidence: string[] }) {
  if (!evidence || evidence.length === 0) return null;
  const groups = groupEvidence(evidence);
  return (
    <ul className="flex flex-col gap-1.5">
      {groups.map((g, gi) => (
        <li key={gi} className="flex flex-col gap-0.5">
          {g.label && (
            <span className="font-mono-num text-[0.65rem] uppercase tracking-wide text-[var(--color-text-faint)]">
              {g.label}
            </span>
          )}
          <ul className="flex flex-col gap-0.5">
            {g.items.map((item, ii) => (
              <li
                key={ii}
                className="flex gap-1.5 text-xs leading-snug text-[var(--color-text-faint)]"
              >
                <span aria-hidden className="select-none">·</span>
                <span className="min-w-0 break-words">{item}</span>
              </li>
            ))}
          </ul>
        </li>
      ))}
    </ul>
  );
}
```

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/components/transparency/EvidenceList.test.tsx` → PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add ui/src/components/transparency/EvidenceList.tsx ui/src/components/transparency/EvidenceList.test.tsx
git commit -m "feat(ui): EvidenceList transparency primitive (prefix grouping)"
```

---

### Task A3: `ProviderVerdictList` primitive

**Files:**
- Create: `ui/src/components/transparency/ProviderVerdictList.tsx`
- Test: `ui/src/components/transparency/ProviderVerdictList.test.tsx`

**Interfaces:**
- Consumes: `ReputationVerdict`, `RepStatus` from `ui/src/types.ts`.
- Produces: `export function ProviderVerdictList({ verdicts, now }: { verdicts: ReputationVerdict[]; now?: number }): JSX.Element | null` — `now` is unix-seconds, defaults to the current time; inject it in tests for deterministic freshness.

- [ ] **Step 1: Write the failing test** — `ui/src/components/transparency/ProviderVerdictList.test.tsx`

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ProviderVerdictList } from "./ProviderVerdictList";
import type { ReputationVerdict } from "../../types";

const v = (over: Partial<ReputationVerdict>): ReputationVerdict => ({
  source: "abuseipdb", status: "unknown", malicious: false, score: null,
  tags: [], link: null, fetched_at: 1000, ...over,
});

describe("ProviderVerdictList", () => {
  it("renders nothing when there are no verdicts", () => {
    const { container } = render(<ProviderVerdictList verdicts={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("lists every provider, worst status first", () => {
    render(
      <ProviderVerdictList
        now={1000}
        verdicts={[
          v({ source: "greynoise", status: "benign", score: 0 }),
          v({ source: "abuseipdb", status: "malicious", score: 90 }),
        ]}
      />,
    );
    const sources = screen.getAllByText(/greynoise|abuseipdb/).map((n) => n.textContent);
    expect(sources[0]).toBe("abuseipdb"); // malicious sorts first
    expect(screen.getByText("90%")).toBeInTheDocument();
  });

  it("shows an em dash when the score is null and a report link when present", () => {
    render(
      <ProviderVerdictList
        now={1000}
        verdicts={[v({ status: "unknown", score: null, link: "https://example.com/r" })]}
      />,
    );
    expect(screen.getByText("—")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: /report/i });
    expect(link).toHaveAttribute("href", "https://example.com/r");
  });

  it("renders a coarse freshness from fetched_at vs now", () => {
    render(<ProviderVerdictList now={1000 + 3600 * 2} verdicts={[v({ fetched_at: 1000 })]} />);
    expect(screen.getByText("2h ago")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/components/transparency/ProviderVerdictList.test.tsx` → FAIL (module not found).

- [ ] **Step 3: Implement** — `ui/src/components/transparency/ProviderVerdictList.tsx`

```tsx
import type { ReputationVerdict, RepStatus } from "../../types";

/** Worst-first ordering: malicious is worst; benign/clean are best. */
const STATUS_RANK: Record<RepStatus, number> = {
  malicious: 5, unknown: 3, notfound: 2, unavailable: 1, benign: 0, clean: 0,
};
const STATUS_COLOR: Record<RepStatus, string> = {
  malicious: "var(--color-sev-critical, #ef4444)",
  benign: "var(--color-sev-low, #22c55e)",
  clean: "var(--color-sev-low, #22c55e)",
  unknown: "var(--color-text-faint)",
  notfound: "var(--color-text-faint)",
  unavailable: "var(--color-text-faint)",
};

/** Coarse "as of" age from a unix-seconds timestamp. */
function freshness(fetchedAt: number, now: number): string {
  const secs = Math.max(0, now - fetchedAt);
  if (secs < 90) return "just now";
  const mins = Math.round(secs / 60);
  if (mins < 90) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 36) return `${hrs}h ago`;
  return `${Math.round(hrs / 24)}d ago`;
}

/** Full per-provider reputation breakdown. Renders nothing when there are no verdicts. */
export function ProviderVerdictList({
  verdicts,
  now = Math.floor(Date.now() / 1000),
}: {
  verdicts: ReputationVerdict[];
  now?: number;
}) {
  if (!verdicts || verdicts.length === 0) return null;
  const sorted = [...verdicts].sort((a, b) => STATUS_RANK[b.status] - STATUS_RANK[a.status]);
  return (
    <ul className="flex flex-col gap-1">
      {sorted.map((vd, i) => (
        <li key={`${vd.source}-${i}`} className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs">
          <span className="font-medium text-[var(--color-text)]">{vd.source}</span>
          <span style={{ color: STATUS_COLOR[vd.status] }}>{vd.status}</span>
          <span className="font-mono-num tabular-nums text-[var(--color-text-dim)]">
            {vd.score != null ? `${vd.score}%` : "—"}
          </span>
          {vd.tags.length > 0 && (
            <span className="font-mono-num text-[0.65rem] text-[var(--color-text-faint)]">
              {vd.tags.join(", ")}
            </span>
          )}
          {vd.link && (
            <a
              href={vd.link}
              target="_blank"
              rel="noopener noreferrer"
              className="text-[var(--color-accent)] underline"
            >
              report ↗
            </a>
          )}
          <span className="ml-auto text-[0.65rem] text-[var(--color-text-faint)]">
            {freshness(vd.fetched_at, now)}
          </span>
        </li>
      ))}
    </ul>
  );
}
```

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/components/transparency/ProviderVerdictList.test.tsx` → PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add ui/src/components/transparency/ProviderVerdictList.tsx ui/src/components/transparency/ProviderVerdictList.test.tsx
git commit -m "feat(ui): ProviderVerdictList per-provider reputation breakdown"
```

---

### Task A4: `FindingMetrics` primitive

**Files:**
- Create: `ui/src/components/transparency/FindingMetrics.tsx`
- Test: `ui/src/components/transparency/FindingMetrics.test.tsx`

**Interfaces:**
- Consumes: `Finding` from `ui/src/types.ts`; `ScoreBadge` from `./ScoreBadge` (Task A1).
- Produces: `export function FindingMetrics({ finding }: { finding: Finding }): JSX.Element`

- [ ] **Step 1: Write the failing test** — `ui/src/components/transparency/FindingMetrics.test.tsx`

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { FindingMetrics } from "./FindingMetrics";
import type { Finding } from "../../types";

const f = (over: Partial<Finding>): Finding => ({
  kind: "beacon", severity: "high", score: 70, title: "t", src_ip: "1.1.1.1",
  dst_ip: "2.2.2.2", dst_port: 443, attack: [], evidence: [],
  interval_ns: null, jitter_cv: null, contacts: null, ...over,
});

describe("FindingMetrics", () => {
  it("always renders the score badge", () => {
    render(<FindingMetrics finding={f({ score: 82 })} />);
    expect(screen.getByText("82")).toBeInTheDocument();
  });

  it("renders only the metrics that are present", () => {
    render(<FindingMetrics finding={f({ interval_ns: 60_000_000_000, jitter_cv: 0.12, contacts: null })} />);
    expect(screen.getByText("period")).toBeInTheDocument();
    expect(screen.getByText("jitter")).toBeInTheDocument();
    expect(screen.queryByText("contacts")).not.toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/components/transparency/FindingMetrics.test.tsx` → FAIL (module not found).

- [ ] **Step 3: Implement** — `ui/src/components/transparency/FindingMetrics.tsx`

```tsx
import type { Finding } from "../../types";
import { ScoreBadge } from "./ScoreBadge";

/** Humanize a nanosecond interval to a compact period string. */
function humanizeInterval(ns: number): string {
  const s = ns / 1e9;
  if (s < 1) return `${Math.round(ns / 1e6)}ms`;
  if (s < 90) return `${s < 10 ? s.toFixed(1) : Math.round(s)}s`;
  const m = s / 60;
  if (m < 90) return `${m < 10 ? m.toFixed(1) : Math.round(m)}m`;
  return `${(m / 60).toFixed(1)}h`;
}

/** Compact "why this severity" metrics row for a finding: score + any present beacon/contact metrics. */
export function FindingMetrics({ finding }: { finding: Finding }) {
  const parts: { label: string; value: string }[] = [];
  if (finding.interval_ns != null) parts.push({ label: "period", value: humanizeInterval(finding.interval_ns) });
  if (finding.jitter_cv != null) parts.push({ label: "jitter", value: finding.jitter_cv.toFixed(2) });
  if (finding.contacts != null) parts.push({ label: "contacts", value: String(finding.contacts) });
  return (
    <div className="flex flex-wrap items-center gap-2">
      <ScoreBadge score={finding.score} severity={finding.severity} />
      {parts.map((p) => (
        <span key={p.label} className="font-mono-num text-[0.7rem] text-[var(--color-text-faint)]">
          {p.label} <span className="text-[var(--color-text-dim)]">{p.value}</span>
        </span>
      ))}
    </div>
  );
}
```

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/components/transparency/FindingMetrics.test.tsx` → PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add ui/src/components/transparency/FindingMetrics.tsx ui/src/components/transparency/FindingMetrics.test.tsx
git commit -m "feat(ui): FindingMetrics transparency primitive"
```

---

### Task B1: `ReputationChip` → expandable popover (also lights up `ThreatRail`)

**Files:**
- Modify: `ui/src/cockpit/ReputationChip.tsx` (full rewrite below)
- Test: `ui/src/cockpit/ReputationChip.test.tsx` (create if absent; if it exists, keep its assertions and ADD the popover test)

**Interfaces:**
- Consumes: `ProviderVerdictList` from `../components/transparency/ProviderVerdictList` (Task A3).
- Produces: `ReputationChip` keeps the same prop `{ reputation: ReputationVerdict[] }` — `ThreatRail.tsx:94` already renders it, so the rail gets the popover with no further change.

- [ ] **Step 1: Check for an existing test** — `ls ui/src/cockpit/ReputationChip.test.tsx`. If it exists, read it; the trigger still renders the worst `source` + `status [score]` text and the full `title`, so existing summary assertions stay valid. You will ADD the popover-expansion test in Step 3's test below; merge, don't replace.

- [ ] **Step 2: Write the failing test** — `ui/src/cockpit/ReputationChip.test.tsx` (add this test; keep any existing ones)

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ReputationChip } from "./ReputationChip";
import type { ReputationVerdict } from "../types";

const v = (over: Partial<ReputationVerdict>): ReputationVerdict => ({
  source: "abuseipdb", status: "unknown", malicious: false, score: null,
  tags: [], link: null, fetched_at: 1000, ...over,
});

describe("ReputationChip", () => {
  it("renders nothing without verdicts", () => {
    const { container } = render(<ReputationChip reputation={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("summarizes the worst verdict and expands to every provider on click", async () => {
    const user = userEvent.setup();
    render(
      <ReputationChip
        reputation={[
          v({ source: "greynoise", status: "benign", score: 0 }),
          v({ source: "abuseipdb", status: "malicious", score: 90 }),
        ]}
      />,
    );
    // Collapsed: worst (malicious) summarized in the trigger.
    const trigger = screen.getByRole("button");
    expect(trigger).toHaveTextContent("abuseipdb");
    // Expand.
    await user.click(trigger);
    expect(screen.getByText("greynoise")).toBeInTheDocument();
    expect(screen.getByText("90%")).toBeInTheDocument();
  });
});
```

- [ ] **Step 3: Run it to verify it fails** — `cd ui && npx vitest run src/cockpit/ReputationChip.test.tsx` → FAIL (no button / providers not listed).

- [ ] **Step 4: Implement** — replace `ui/src/cockpit/ReputationChip.tsx` entirely with:

```tsx
import { useState } from "react";
import type { ReputationVerdict, RepStatus } from "../types";
import { ProviderVerdictList } from "../components/transparency/ProviderVerdictList";

const RANK: Record<RepStatus, number> = { malicious: 5, benign: 4, unknown: 3, clean: 2, notfound: 1, unavailable: 0 };
const COLOR: Record<RepStatus, string> = {
  malicious: "var(--color-critical, #ef4444)", benign: "var(--color-low, #22c55e)",
  unknown: "var(--color-text-faint)", clean: "var(--color-text-faint)",
  notfound: "var(--color-text-faint)", unavailable: "var(--color-text-faint)",
};

/** Compact reputation summary (worst status) that expands to the full per-provider breakdown on click. */
export function ReputationChip({ reputation }: { reputation: ReputationVerdict[] }) {
  const [open, setOpen] = useState(false);
  if (!reputation || reputation.length === 0) return null;
  const worst = [...reputation].sort((a, b) => RANK[b.status] - RANK[a.status])[0];
  const label = worst.score != null ? `${worst.status} ${worst.score}` : worst.status;
  return (
    <span className="relative inline-flex">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="t-tag inline-flex items-center gap-1"
        title={reputation.map((vd) => `${vd.source}: ${vd.status}`).join(" · ")}
      >
        <span aria-hidden style={{ width: 6, height: 6, borderRadius: 9999, background: COLOR[worst.status] }} />
        <span style={{ color: COLOR[worst.status] }}>{worst.source} {label}</span>
      </button>
      {open && (
        <div className="absolute left-0 top-full z-20 mt-1 min-w-[16rem] rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] p-2 shadow-lg">
          <ProviderVerdictList verdicts={reputation} />
        </div>
      )}
    </span>
  );
}
```

- [ ] **Step 5: Run it to verify it passes** — `cd ui && npx vitest run src/cockpit/ReputationChip.test.tsx src/cockpit/ThreatRail.test.tsx` → PASS (existing ThreatRail tests still green; the rail now embeds the interactive chip).

- [ ] **Step 6: Commit**

```bash
git add ui/src/cockpit/ReputationChip.tsx ui/src/cockpit/ReputationChip.test.tsx
git commit -m "feat(ui): expandable per-provider reputation popover in ReputationChip"
```

---

### Task B2: Threat card — reputation breakdown + tags + shared evidence

**Files:**
- Modify: `ui/src/components/triage/ThreatsPanel.tsx` (the `ThreatCard` component, lines ~37-137)
- Test: `ui/src/components/triage/ThreatsPanel.test.tsx` (keep existing; add the new assertions)

**Interfaces:**
- Consumes: `ProviderVerdictList` (A3), `EvidenceList` (A2).

- [ ] **Step 1: Write the failing test** — add to `ui/src/components/triage/ThreatsPanel.test.tsx` (create the file if absent, importing the panel's default export and rendering with a fixture threat). Minimal new test:

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import ThreatsPanel from "./ThreatsPanel"; // adjust to the actual export (default or named)
import type { IpThreat } from "../../types";

const threat: IpThreat = {
  ip: "9.9.9.9", ip_class: "public", severity: "high", score: 80, flows: 3, bytes: 1000,
  ioc: false, tags: ["reputation", "public"], attack: [],
  evidence: ["reputation: abuseipdb malicious 78% (+25)"],
  reputation: [
    { source: "abuseipdb", status: "malicious", malicious: true, score: 78, tags: ["c2"], link: null, fetched_at: 1000 },
  ],
};

describe("ThreatsPanel reputation transparency", () => {
  it("shows the per-provider reputation breakdown and tags on the card", () => {
    render(<ThreatsPanel threats={[threat]} />); // adjust prop name to the real one
    expect(screen.getByText("abuseipdb")).toBeInTheDocument();
    expect(screen.getByText("78%")).toBeInTheDocument();
  });
});
```

> NOTE to implementer: open `ThreatsPanel.tsx` first to confirm the panel's export name and its props (how it receives `threats`). Adjust the import/props above to match before running. Do not weaken the assertion.

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/components/triage/ThreatsPanel.test.tsx` → FAIL (no `abuseipdb` text).

- [ ] **Step 3: Implement** — in `ThreatCard`, add imports at the top of `ThreatsPanel.tsx`:

```tsx
import { ProviderVerdictList } from "../transparency/ProviderVerdictList";
import { EvidenceList } from "../transparency/EvidenceList";
```

Replace the existing `{/* Evidence */}` block:

```tsx
      {/* Evidence */}
      {threat.evidence.length > 0 && (
        <ul className="flex flex-col gap-0.5">
          {threat.evidence.map((e, i) => (
            <li
              key={i}
              className="flex gap-1.5 text-xs leading-snug text-[var(--color-text-faint)]"
            >
              <span aria-hidden className="select-none">
                ·
              </span>
              <span className="min-w-0 break-words">{e}</span>
            </li>
          ))}
        </ul>
      )}
```

with:

```tsx
      {/* Tags */}
      {threat.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {threat.tags.map((t) => (
            <span key={t} className="t-tag text-[var(--color-text-dim)]">{t}</span>
          ))}
        </div>
      )}

      {/* Per-provider reputation breakdown */}
      {threat.reputation && threat.reputation.length > 0 && (
        <ProviderVerdictList verdicts={threat.reputation} />
      )}

      {/* Evidence */}
      <EvidenceList evidence={threat.evidence} />
```

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/components/triage/ThreatsPanel.test.tsx` → PASS.

- [ ] **Step 5: Commit**

```bash
git add ui/src/components/triage/ThreatsPanel.tsx ui/src/components/triage/ThreatsPanel.test.tsx
git commit -m "feat(ui): reputation breakdown + tags + grouped evidence on threat cards"
```

---

### Task B3: Incident finding row — evidence + score (parity with the flyout)

**Files:**
- Modify: `ui/src/components/triage/IncidentsPanel.tsx` (the `FindingRow` component, lines ~71-100)
- Test: `ui/src/components/triage/IncidentsPanel.test.tsx` (keep existing; add the new assertion)

**Interfaces:**
- Consumes: `EvidenceList` (A2), `FindingMetrics` (A4).

- [ ] **Step 1: Write the failing test** — add to `ui/src/components/triage/IncidentsPanel.test.tsx` (create if absent). Render an incident whose finding carries evidence + score; assert both surface in the row.

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import IncidentsPanel from "./IncidentsPanel"; // adjust to the actual export
import type { Incident } from "../../types";

const incident: Incident = {
  host: "10.0.0.5", severity: "high", score: 75, title: "t", narrative: "n",
  stages: ["Command & Control"], attack: [],
  findings: [{
    kind: "beacon", severity: "high", score: 88, title: "beacon to 2.2.2.2",
    src_ip: "10.0.0.5", dst_ip: "2.2.2.2", dst_port: 443, attack: [],
    evidence: ["c2: periodic beacon 60s"], interval_ns: 60_000_000_000, jitter_cv: 0.1, contacts: 20,
  }],
};

describe("IncidentsPanel finding transparency", () => {
  it("shows the finding's evidence and score in the row", () => {
    render(<IncidentsPanel incidents={[incident]} />); // adjust prop name to the real one
    expect(screen.getByText("periodic beacon 60s")).toBeInTheDocument();
    expect(screen.getByText("88")).toBeInTheDocument();
  });
});
```

> NOTE to implementer: confirm `IncidentsPanel`'s export name + props before running; adjust import/props to match. Do not weaken the assertion.

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/components/triage/IncidentsPanel.test.tsx` → FAIL.

- [ ] **Step 3: Implement** — add imports at the top of `IncidentsPanel.tsx`:

```tsx
import { EvidenceList } from "../transparency/EvidenceList";
import { FindingMetrics } from "../transparency/FindingMetrics";
```

In `FindingRow`, the current `<li>` renders only the header `<div>` (icon + title + metrics string). Replace the metrics-string span and extend the `<li>` body so the row becomes:

```tsx
    <li className="flex flex-col gap-1 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-2">
      <div className="flex flex-wrap items-center gap-2">
        <span
          className="inline-flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 text-[0.7rem] font-semibold"
          style={{
            color,
            backgroundColor: `color-mix(in srgb, ${color} 16%, transparent)`,
          }}
        >
          <Icon size={12} aria-hidden />
          {meta.label}
        </span>
        <span className="font-mono-num min-w-0 flex-1 truncate text-xs text-[var(--color-text-dim)]">
          {finding.title}
        </span>
      </div>
      <FindingMetrics finding={finding} />
      <EvidenceList evidence={finding.evidence} />
    </li>
```

(The old `const metrics = findingMetrics(finding);` line and the `{metrics.length > 0 && (...)}` span are replaced by `<FindingMetrics />`. If `findingMetrics` is now unused, remove it to satisfy `noUnusedLocals`.)

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/components/triage/IncidentsPanel.test.tsx` → PASS.

- [ ] **Step 5: Commit**

```bash
git add ui/src/components/triage/IncidentsPanel.tsx ui/src/components/triage/IncidentsPanel.test.tsx
git commit -m "feat(ui): finding evidence + score on incident finding rows"
```

---

### Task B4: Detail flyout — finding metrics + shared evidence

**Files:**
- Modify: `ui/src/cockpit/DetailFlyout.tsx` (the findings list, lines ~108-133)
- Test: `ui/src/cockpit/DetailFlyout.test.tsx` (keep existing; add the new assertion)

**Interfaces:**
- Consumes: `EvidenceList` (A2), `FindingMetrics` (A4).

- [ ] **Step 1: Write the failing test** — add to `ui/src/cockpit/DetailFlyout.test.tsx` (create if absent). Render the flyout for an incident whose finding has a score + evidence; assert the score badge shows (the flyout already shows evidence text, so the NEW signal is the score).

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { DetailFlyout } from "./DetailFlyout"; // adjust to the actual export
import type { Incident } from "../types";

const incident: Incident = {
  host: "10.0.0.5", severity: "high", score: 75, title: "t", narrative: "n",
  stages: ["Command & Control"], attack: [],
  findings: [{
    kind: "beacon", severity: "high", score: 88, title: "beacon",
    src_ip: "10.0.0.5", dst_ip: "2.2.2.2", dst_port: 443, attack: [],
    evidence: ["c2: periodic beacon 60s"], interval_ns: 60_000_000_000, jitter_cv: 0.1, contacts: 20,
  }],
};

describe("DetailFlyout finding score", () => {
  it("renders the finding score badge", () => {
    render(<DetailFlyout incident={incident} onClose={() => {}} />); // adjust props to the real signature
    expect(screen.getByText("88")).toBeInTheDocument();
  });
});
```

> NOTE to implementer: open `DetailFlyout.tsx` to confirm its export name + the exact props it needs to render (it may require an `open`/`incident`/`onClose` shape). Adjust the render call to match; do not weaken the assertion.

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/cockpit/DetailFlyout.test.tsx` → FAIL (no `88`).

- [ ] **Step 3: Implement** — add imports at the top of `DetailFlyout.tsx`:

```tsx
import { EvidenceList } from "../components/transparency/EvidenceList";
import { FindingMetrics } from "../components/transparency/FindingMetrics";
```

In the findings `.map(...)`, replace the inner finding `<li>` body. The current body renders a header `<div>` (SeverityDot + kind + metric string `m`), the title `<div>`, and the inline evidence `<ul>`. Replace the inline evidence `<ul>...</ul>` block and the metric-string span so the body becomes:

```tsx
                <li key={`${f.kind}-${i}`} className="rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-1)] p-3">
                  <div className="flex items-center gap-2">
                    <SeverityDot severity={f.severity} />
                    <span className="text-[13px] font-medium text-[var(--color-text)]">{humanizeKind(f.kind)}</span>
                  </div>
                  <div className="font-mono-num mt-1 text-xs text-[var(--color-text-dim)]">{f.title}</div>
                  <div className="mt-2">
                    <FindingMetrics finding={f} />
                  </div>
                  <div className="mt-2 border-l border-[var(--color-border)] pl-2.5">
                    <EvidenceList evidence={f.evidence} />
                  </div>
                </li>
```

(The `const m = findingMetric(f);` line and the `{m && <span ...>{m}</span>}` are replaced by `<FindingMetrics />`. If `findingMetric` is now unused, remove it to satisfy `noUnusedLocals`.)

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/cockpit/DetailFlyout.test.tsx` → PASS.

- [ ] **Step 5: Commit**

```bash
git add ui/src/cockpit/DetailFlyout.tsx ui/src/cockpit/DetailFlyout.test.tsx
git commit -m "feat(ui): finding metrics + grouped evidence in the detail flyout"
```

---

### Task C1: Coverage gate + CI-toolchain verification

**Files:**
- Add focused tests wherever `npm run test:coverage` shows a new `components/transparency/*` or modified surface below the bar.

- [ ] **Step 1: Realign to the CI toolchain** — drift check, then realign:

```bash
cd ui && git diff --stat package.json package-lock.json
# If vitest/vite were bumped, discard and reinstall the locked set:
git checkout -- package.json package-lock.json 2>/dev/null || true
npm ci
node -p "require('./node_modules/vitest/package.json').version"   # expect 1.6.1
```

- [ ] **Step 2: Run the actual gate** — `cd ui && npm run test:coverage` → read the `All files` line. Functions/lines/statements ≥ 80, branches ≥ 70, EXIT 0.

- [ ] **Step 3: Fill gaps** — for any new/modified file below the bar, add a real behavior test (assert observable output, not a smoke render). Likely already covered by A1–A4 + B1–B4; if a surface integration dropped branch coverage, add the missing-branch case (e.g. a threat with empty `reputation`, a finding with all-null metrics).

- [ ] **Step 4: Verify the build gate** — `cd ui && npm run build` → EXIT 0, zero `error TS` (this is `tsc -b && vite build`, a CI gate). Then re-run `npm run test:coverage` → EXIT 0.

- [ ] **Step 5: Commit**

```bash
git add ui/src/components/transparency ui/src/cockpit ui/src/components/triage
git commit -m "test(ui): hold the coverage gate for the transparency layer"
```

---

## Self-Review

**1. Spec coverage:** ProviderVerdictList (A3) + chip popover (B1) + card breakdown (B2) → spec §"per-provider reputation, both placements". EvidenceList (A2) + grouping → §"grouped strings, full list". ScoreBadge (A1) + FindingMetrics (A4) + B3/B4 → §"finding score + evidence parity". ThreatRail → covered by B1 (rail already embeds the chip). Coverage gate → C1. Directional packets → out of scope (deferred). All spec sections map to a task. ✓

**2. Placeholder scan:** every code step has complete code; the three surface tests carry an explicit "confirm the export/props" note because those panels' exact prop signatures must be read in-repo (the implementer adjusts the render call but may not weaken the assertion). No "TBD"/"add error handling"/"similar to". ✓

**3. Type consistency:** `ProviderVerdictList({ verdicts, now })`, `EvidenceList({ evidence })`, `ScoreBadge({ score, severity })`, `FindingMetrics({ finding })` are used identically in A-tasks and B-tasks. `ReputationChip({ reputation })` prop unchanged. ✓
