# Signature matches panel — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A read-only "Signature matches" Dashboard panel listing the `rule_match` findings (msg, sid, src→dst:port, MITRE), giving imported-rule hits a consolidated home.

**Architecture:** Pure UI — filter `summary.findings` for `kind === "rule_match"` and render, mirroring `DomainThreatsPanel`. No engine/WASM/Tauri change.

**Tech Stack:** React 18 + TS; Vitest. No new deps.

## Global Constraints

- **Pure UI** — no engine/WASM/Tauri change. The `rule_match` finding shape (engine `rule_finding`, phase A) is the contract: `title`=msg, `src_ip`/`dst_ip`/`dst_port`, `attack`=MITRE, `evidence[0]="rule sid:N"`, `severity`.
- **Hide when empty** — `return null` when no `rule_match` findings (mirrors `DomainThreatsPanel`).
- **Defensive sid parse** — regex over `evidence`; missing sid → omit the tag, never throw.
- No new deps. Coverage ≥ 80/70 (vitest 1.6.1). Stage specific files. node at `/c/Program Files/nodejs`; do NOT `npm install`.

## Reference: the seams (verified)

```ts
// ui/src/types.ts:151 FindingKind union — does NOT include "rule_match"; ADD it.
//   Finding { kind: FindingKind; severity: Severity; score: number; title: string; src_ip: string; dst_ip: string|null; dst_port: number|null; attack: string[]; evidence: string[]; … }
// ui/src/cockpit/primitives.tsx:49 SeverityChip({severity}) ; :77 MitreTag({id})
// ui/src/components/triage/DomainThreatsPanel.tsx — the panel pattern to MIRROR (section + header(icon+title+count) + <ul> of cards ; `if (empty) return null`).
// ui/src/components/Dashboard.tsx:165 <DomainThreatsPanel domains={s.domain_threats ?? []} /> ; s.findings in scope.
// engine rule_finding evidence: evidence[0]="rule sid:{sid}", evidence[1]="matched content ({n} bytes)".
```

---

### Task 1: `"rule_match"` in the union + `SignatureMatchesPanel`

**Files:**
- Modify: `ui/src/types.ts` (add `"rule_match"` to `FindingKind`)
- Create: `ui/src/components/triage/SignatureMatchesPanel.tsx`, `ui/src/components/triage/SignatureMatchesPanel.test.tsx`

**Interfaces:**
- Produces: `SignatureMatchesPanel({ findings: Finding[] })`.

- [ ] **Step 1: Add `"rule_match"` to the union** — `ui/src/types.ts`, the `FindingKind` type:
```ts
export type FindingKind =
  | "beacon"
  | "host_sweep"
  | "brute_force"
  | "cleartext_creds"
  | "pii_exposure"
  | "lateral_movement"
  | "data_exfil"
  | "dns_tunnel"
  | "rule_match";
```

- [ ] **Step 2: Write the failing test** — `ui/src/components/triage/SignatureMatchesPanel.test.tsx`:
```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "../../test/render";
import { SignatureMatchesPanel } from "./SignatureMatchesPanel";
import type { Finding } from "../../types";

const ruleMatch = (over: Partial<Finding> = {}): Finding => ({
  kind: "rule_match",
  severity: "high",
  score: 70,
  title: "C2 beacon pattern",
  src_ip: "10.0.0.5",
  dst_ip: "203.0.113.9",
  dst_port: 443,
  attack: ["T1071"],
  evidence: ["rule sid:1001", "matched content (3 bytes)"],
  interval_ns: null,
  jitter_cv: null,
  contacts: null,
  ...over,
});

const beacon = (): Finding => ({ ...ruleMatch(), kind: "beacon", title: "beaconing", evidence: [] });

describe("SignatureMatchesPanel", () => {
  it("renders a row per rule_match with msg, sid, src→dst:port, and MITRE", () => {
    render(<SignatureMatchesPanel findings={[ruleMatch(), beacon()]} />);
    expect(screen.getByText("C2 beacon pattern")).toBeInTheDocument();
    expect(screen.getByText(/1001/)).toBeInTheDocument();          // the sid
    expect(screen.getByText(/10\.0\.0\.5/)).toBeInTheDocument();   // src
    expect(screen.getByText(/203\.0\.113\.9/)).toBeInTheDocument();// dst
    expect(screen.getByText("T1071")).toBeInTheDocument();         // MITRE chip
    // a non-rule finding is NOT listed
    expect(screen.queryByText("beaconing")).toBeNull();
  });

  it("renders nothing when there are no rule_match findings", () => {
    const { container } = render(<SignatureMatchesPanel findings={[beacon()]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders a rule_match without a sid (evidence lacks one) and does not throw", () => {
    render(<SignatureMatchesPanel findings={[ruleMatch({ evidence: ["matched content (3 bytes)"] })]} />);
    expect(screen.getByText("C2 beacon pattern")).toBeInTheDocument();
  });
});
```
> NOTE: use the project's `render` from `../../test/render`. `MitreTag` renders the id text (`"T1071"`) — confirm by reading it; if it prefixes/links, adjust the query. Severity `"high"` is a valid `Severity`.

- [ ] **Step 3: Run to verify it fails** — `cd ui && npx vitest run src/components/triage/SignatureMatchesPanel.test.tsx` → FAIL.

- [ ] **Step 4: Implement** — `ui/src/components/triage/SignatureMatchesPanel.tsx`. Mirror `DomainThreatsPanel`:
```tsx
import { ShieldAlert } from "lucide-react";
import type { Finding } from "../../types";
import { humanNumber } from "../../lib/format";
import { SeverityChip, MitreTag } from "../../cockpit/primitives";

/** Extract the rule sid from a finding's evidence (defensive; null if absent). */
function sidOf(f: Finding): string | null {
  for (const e of f.evidence) {
    const m = e.match(/sid:(\d+)/);
    if (m) return m[1];
  }
  return null;
}

function MatchCard({ f }: { f: Finding }) {
  const sid = sidOf(f);
  const dst = f.dst_ip ? `${f.dst_ip}${f.dst_port != null ? `:${f.dst_port}` : ""}` : "—";
  return (
    <li className="flex flex-col gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="min-w-0 flex-1 truncate text-sm font-semibold text-[var(--color-text)]" title={f.title}>
          {f.title}
        </span>
        {sid && <span className="t-tag font-mono-num text-[var(--color-text-faint)]">sid {sid}</span>}
        <SeverityChip severity={f.severity} />
      </div>
      <div className="font-mono-num flex items-center gap-1.5 text-xs text-[var(--color-text-dim)]">
        <span className="truncate">{f.src_ip}</span>
        <span className="text-[var(--color-text-faint)]">→</span>
        <span className="truncate">{dst}</span>
      </div>
      {f.attack.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          {f.attack.map((a) => (
            <MitreTag key={a} id={a} />
          ))}
        </div>
      )}
    </li>
  );
}

/** Consolidated read-only list of imported-rule (`rule_match`) findings. Hidden when none. */
export function SignatureMatchesPanel({ findings }: { findings: Finding[] }) {
  const matches = (findings ?? []).filter((f) => f.kind === "rule_match");
  if (matches.length === 0) return null;
  return (
    <section
      data-component="SignatureMatchesPanel"
      aria-label="Signature matches"
      className="rounded-lg border border-border bg-surface p-4 shadow-sm"
    >
      <div className="mb-3 flex items-baseline justify-between gap-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-[var(--color-text-dim)]">
          <ShieldAlert size={15} className="text-[var(--color-accent)]" /> Signature matches
        </h2>
        <span className="font-mono-num text-xs text-[var(--color-text-faint)]">{humanNumber(matches.length)} matched</span>
      </div>
      <ul className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
        {matches.slice(0, 50).map((f, i) => (
          <MatchCard key={`${sidOf(f) ?? "nosid"}-${f.src_ip}-${f.dst_ip}-${i}`} f={f} />
        ))}
      </ul>
    </section>
  );
}
```
> NOTE: confirm `humanNumber` is exported from `lib/format` (DomainThreatsPanel imports it); confirm the `border-border`/`bg-surface` utility classes the section uses match DomainThreatsPanel's (copy them verbatim from that file's `<section>`).

- [ ] **Step 5: Run to verify it passes** — `cd ui && npx vitest run src/components/triage/SignatureMatchesPanel.test.tsx` → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 6: Commit**
```bash
git add ui/src/types.ts ui/src/components/triage/SignatureMatchesPanel.tsx ui/src/components/triage/SignatureMatchesPanel.test.tsx
git commit -m "feat(ui): SignatureMatchesPanel — list rule_match findings"
```

---

### Task 2: Dashboard wiring + full gate

**Files:**
- Modify: `ui/src/components/Dashboard.tsx`

**Interfaces:**
- Consumes: `SignatureMatchesPanel` (T1).

- [ ] **Step 1: Render the panel** — `Dashboard.tsx`: `import { SignatureMatchesPanel } from "./triage/SignatureMatchesPanel";` and render it adjacent to `<DomainThreatsPanel …>` (~:165):
```tsx
        <SignatureMatchesPanel findings={s.findings ?? []} />
        <DomainThreatsPanel domains={s.domain_threats ?? []} />
```

- [ ] **Step 2: (Optional) Dashboard smoke test** — if the existing `Dashboard.test.tsx` builds a `makeOutput()` with findings, add an assertion that a `rule_match` finding (push one into the fixture's `summary.findings` in a local copy) surfaces the "Signature matches" header; else skip (the panel's own test covers it). Do NOT break the existing Dashboard tests.

- [ ] **Step 3: Run** — `cd ui && npx vitest run src/components/Dashboard.test.tsx` → PASS (existing tests unaffected; the panel hides when the fixture has no rule_match findings). `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 4: Commit**
```bash
git add ui/src/components/Dashboard.tsx ui/src/components/Dashboard.test.tsx
git commit -m "feat(ui): surface SignatureMatchesPanel on the Dashboard"
```

- [ ] **Step 5: Full gate** — `cd ui && export PATH="/c/Program Files/nodejs:/c/Users/ravid/.cargo/bin:$PATH"`:
```bash
git checkout -- package.json package-lock.json 2>/dev/null || true
npm ci
node -p "require('./node_modules/vitest/package.json').version"   # 1.6.1
npm run build:wasm
npm run build; echo "build EXIT: $?"          # 0
npm run test:coverage; echo "cov EXIT: $?"    # 0; All files >= 80/70 — paste it
git diff --name-only main..HEAD -- engine/ | head   # empty (pure UI)
```
Do NOT `npm install`. If a metric dips, add a focused test (e.g. the sid-absent path, or the multi-MITRE render) and re-run.

- [ ] **Step 6: Commit** (if gate top-up tests added).

---

## Self-Review

**1. Spec coverage:** the `"rule_match"` union add + the panel (T1) → spec §1-2; the Dashboard wiring + gate (T2) → §3. Hide-when-empty, defensive sid parse, msg/src→dst/MITRE/severity render, mirror DomainThreatsPanel — all covered. Clickable pivot + grouping + incident-correlation out of scope. ✓

**2. Placeholder scan:** complete code for the union, the panel (incl. `sidOf` + `MatchCard`), the tests, the Dashboard render. The NOTEs (confirm `MitreTag` renders the id text; `humanNumber` export; copy DomainThreatsPanel's section classes verbatim) are concrete in-repo verifications. ✓

**3. Type consistency:** `FindingKind` gains `"rule_match"` ⇄ `SignatureMatchesPanel({ findings: Finding[] })` filters `f.kind === "rule_match"` ⇄ consumes `f.title`/`f.evidence`/`f.src_ip`/`f.dst_ip`/`f.dst_port`/`f.attack`/`f.severity` (all `Finding` fields) ⇄ `Dashboard` passes `s.findings`. `sidOf(f) -> string|null`. ✓
