# Clickable signature-match rows — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Signature matches panel rows clickable — a click pivots to the matched host's flows.

**Architecture:** Pure UI — an optional `onJump` makes each card a button that calls `onJumpToFlows({ ip })`; the Dashboard wires `toFlowsIp`. Backward-compatible (static when `onJump` absent).

**Tech Stack:** React 18 + TS; Vitest. No new deps.

## Global Constraints

- **Pure UI** — no engine/WASM/Tauri change. Reuse `onJumpToFlows({ ip })`.
- **Backward-compatible** — `onJump` absent → renders exactly as today; the existing panel tests pass unchanged.
- **No nested interactives** — `MitreTag` is a non-interactive span; a card-level `<button>` is valid.
- No new deps. Coverage ≥ 80/70 (vitest 1.6.1). node at `/c/Program Files/nodejs`; do NOT `npm install`.

## Reference: the seams (verified)

```ts
// ui/src/components/Dashboard.tsx:81 toFlowsIp = (ip)=>onJumpToFlows?.({ip}) — the pivot the threat cards/top-talkers use
// ui/src/views/FlowsView.tsx:128 setQuery(initialFilter.ip ?? "") — {ip} drilldown filters flows to that IP
// ui/src/components/triage/SignatureMatchesPanel.tsx — MatchCard (<li>); f.src_ip:string, f.dst_ip:string|null ; SeverityChip/MitreTag from cockpit/primitives
// the threat-watchlist card (Dashboard.tsx ThreatWatchlist) — a full-width text-left <button> inside <li> with hover:border-[var(--color-border-strong)] — the clickable-card pattern to mirror
```

---

### Task 1: `onJump` prop + clickable card + Dashboard wire (+ gate)

**Files:**
- Modify: `ui/src/components/triage/SignatureMatchesPanel.tsx`, `ui/src/components/triage/SignatureMatchesPanel.test.tsx`, `ui/src/components/Dashboard.tsx`

**Interfaces:**
- Produces: `SignatureMatchesPanel({ findings, onJump? })`.

- [ ] **Step 1: Write the failing tests** — add to `SignatureMatchesPanel.test.tsx`:
```tsx
import { vi } from "vitest";
import { fireEvent } from "../../test/render"; // ensure fireEvent is imported

it("a row click pivots to the matched destination via onJump", () => {
  const onJump = vi.fn();
  render(<SignatureMatchesPanel findings={[ruleMatch()]} onJump={onJump} />);
  fireEvent.click(screen.getByRole("button", { name: /View flows for 203\.0\.113\.9/i }));
  expect(onJump).toHaveBeenCalledWith("203.0.113.9"); // dst_ip
});

it("falls back to src_ip when dst_ip is null", () => {
  const onJump = vi.fn();
  render(<SignatureMatchesPanel findings={[ruleMatch({ dst_ip: null, dst_port: null })]} onJump={onJump} />);
  fireEvent.click(screen.getByRole("button", { name: /View flows for 10\.0\.0\.5/i }));
  expect(onJump).toHaveBeenCalledWith("10.0.0.5"); // src_ip
});

it("renders static (non-button) rows when onJump is absent", () => {
  render(<SignatureMatchesPanel findings={[ruleMatch()]} />);
  expect(screen.getByText("C2 beacon pattern")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /View flows for/i })).toBeNull();
});
```
(Reuse the existing `ruleMatch()`/`beacon()` fixtures + the existing `render`/`screen` imports in the file; add `vi` + `fireEvent` if not already imported. Keep the existing 3 tests unchanged.)

- [ ] **Step 2: Run to verify they fail** — `cd ui && npx vitest run src/components/triage/SignatureMatchesPanel.test.tsx` → FAIL (no button / onJump).

- [ ] **Step 3: Implement** — `SignatureMatchesPanel.tsx`:
- Thread `onJump?: (ip: string) => void` into the panel signature → pass to each `MatchCard`.
- `MatchCard({ f, onJump }: { f: Finding; onJump?: (ip: string) => void })`: compute `const pivot = f.dst_ip ?? f.src_ip;`. Refactor so the card's inner content is a reusable block, then:
  - When `onJump`: render the `<li>` containing a full-width `<button type="button" onClick={() => onJump(pivot)} aria-label={\`View flows for ${pivot}\`} className="flex w-full flex-col gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3 text-left transition-colors hover:border-[var(--color-border-strong)]">{content}</button>`.
  - When absent: render the existing static `<li className="… border … p-3">{content}</li>` (current markup) unchanged.
  - Keep `MitreTag`/`SeverityChip`/`sidOf`/the src→dst line inside `content`. (MitreTag is a non-interactive span — safe inside the button.)
- `SignatureMatchesPanel`: `export function SignatureMatchesPanel({ findings, onJump }: { findings: Finding[]; onJump?: (ip: string) => void })` → `<MatchCard key={…} f={f} onJump={onJump} />`.

- [ ] **Step 4: Run to verify they pass** — `cd ui && npx vitest run src/components/triage/SignatureMatchesPanel.test.tsx` → PASS (3 existing + 3 new). `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 5: Wire the Dashboard** — `Dashboard.tsx`: `<SignatureMatchesPanel findings={s.findings ?? []} onJump={toFlowsIp} />`. Run `cd ui && npx vitest run src/components/Dashboard.test.tsx` → PASS (existing tests unaffected).

- [ ] **Step 6: Commit**
```bash
git add ui/src/components/triage/SignatureMatchesPanel.tsx ui/src/components/triage/SignatureMatchesPanel.test.tsx ui/src/components/Dashboard.tsx
git commit -m "feat(ui): clickable signature-match rows pivot to the host's flows"
```

- [ ] **Step 7: Full gate** — `cd ui && export PATH="/c/Program Files/nodejs:/c/Users/ravid/.cargo/bin:$PATH"`:
```bash
git checkout -- package.json package-lock.json 2>/dev/null || true
npm ci
node -p "require('./node_modules/vitest/package.json').version"   # 1.6.1
npm run build:wasm
npm run build; echo "build EXIT: $?"          # 0
npm run test:coverage; echo "cov EXIT: $?"    # 0; All files >= 80/70 — paste it
git diff --name-only main..HEAD -- engine/ | head   # empty (pure UI)
```
Do NOT `npm install`.

- [ ] **Step 8: Commit** (if a gate top-up test was needed).

---

## Self-Review

**1. Spec coverage:** `onJump` prop + clickable card (pivot `dst_ip ?? src_ip`) + the static fallback + Dashboard wire + tests + gate — all in T1. Backward-compat, no-nested-interactive, IP text-query pivot — covered. Precise flow filter + separate src/dst clicks out of scope. ✓

**2. Placeholder scan:** complete code for the tests + the `onJump`/`pivot`/button-vs-static split + the Dashboard wire. The only "reuse" is the existing test fixtures + the threat-card button classes (concrete in-repo refs). ✓

**3. Type consistency:** `onJump?: (ip: string) => void` (panel + MatchCard) ⇄ `pivot = f.dst_ip ?? f.src_ip` (string, since `src_ip` is non-null) ⇄ Dashboard `toFlowsIp: (ip:string)=>void` ⇄ `onJumpToFlows({ ip })`. ✓
