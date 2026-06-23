# Host-carve UI button — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A "Carve host pcap" action on the IP threat cards, completing the PCAP-carve feature (the engine/WASM/Tauri/platform already support `CarveTarget::Host`).

**Architecture:** Pure UI — thread `activeSource` from App → Dashboard → ThreatWatchlist → each host card; the card's carve action calls the existing `carveSubPcap({ host: ip, … }, activeSource, name)`. No engine/WASM/Tauri change.

**Tech Stack:** React 18 + TS; Vitest. No new deps.

## Global Constraints

- **Pure UI** — no engine/WASM/Tauri change; reuse `carveSubPcap` + `packetsAvailable`.
- **Same gating as the flow carve** — disabled (with a tooltip) when `!packetsAvailable(activeSource)`.
- **Whole-capture host window** — `{ host: ip, start_ns: 0, end_ns: HOST_CARVE_END_NS }`, `HOST_CARVE_END_NS = 9e18` (> any real ns ~1.8e18, < i64::MAX 9.22e18).
- **No-throw** — `carveSubPcap` returns `ExportResult`; surface via a transient notice.
- No new deps. Coverage gate ≥ 80/70 (vitest 1.6.1). Stage specific files. node at `/c/Program Files/nodejs`; do NOT `npm install`.

## Reference: the seams (verbatim, verified)

```ts
// ui/src/lib/packets.ts  carveSubPcap(query: CarveQuery, source: ActiveSource, name: string): Promise<ExportResult> ; packetsAvailable(source): boolean
// ui/src/types.ts  CarveQuery { host?:string; src_ip?:string; dst_ip?:string; src_port?:number; dst_port?:number; proto?:number; start_ns:number; end_ns:number } ; ActiveSource = {kind:"path";path}|{kind:"bytes";bytes}|null
// ui/src/components/Dashboard.tsx:32 DashboardProps { output, onJumpToFlows?, selectedIncident, onSelectIncident }
//   :54 export function Dashboard({ output, onJumpToFlows, selectedIncident, onSelectIncident }: DashboardProps)
//   :102 <ThreatWatchlist threats={s.ip_threats ?? []} onSelect={openHost} />
//   ThreatWatchlist is a local fn-component (search `function ThreatWatchlist({`) rendering compact host cards; each card has threat.ip + an onSelect click (the openHost pivot)
// ui/src/App.tsx:117 const [activeSource,setActiveSource]=useState<ActiveSource>(null) ; :614 <Dashboard output={summary.data!} onJumpToFlows={jumpToFlows} selectedIncident={…} onSelectIncident={setSelectedIncident} />
// ui/src/views/FlowsView.tsx carveFlow: const res = await carveSubPcap(query, activeSource, name); if(res.ok) setPktError(null); else if(res.message) setPktError(res.message);
// ui/src/components/FlowDetail.tsx the flow carve button uses <Scissors size={14}/> + canInspect gating + a disabled tooltip
```

---

### Task 1: Thread `activeSource` + the host-carve button

**Files:**
- Modify: `ui/src/App.tsx` (pass `activeSource`), `ui/src/components/Dashboard.tsx` (`DashboardProps.activeSource` + `carveHost` + `ThreatWatchlist` carve button + notice)
- Test: the Dashboard test (`grep -rl "Dashboard" ui/src --include=*.test.tsx`; else create `ui/src/components/Dashboard.test.tsx`)

**Interfaces:**
- Consumes: `carveSubPcap`/`packetsAvailable` (lib/packets.ts), `ActiveSource`/`CarveQuery` (types.ts).

- [ ] **Step 1: Write the failing test** — add a Dashboard test asserting the host-carve button:

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { Dashboard } from "./Dashboard";

vi.mock("../lib/packets", async (orig) => ({
  ...(await orig<typeof import("../lib/packets")>()),
  carveSubPcap: vi.fn(async () => ({ ok: true, message: "Carved 3 packets" })),
}));
import { carveSubPcap } from "../lib/packets";

const output = makeOutputWithThreat("10.0.0.9"); // an AnalysisOutput with one ip_threat ip=10.0.0.9 (reuse the real fixture)

describe("Dashboard host carve", () => {
  beforeEach(() => vi.mocked(carveSubPcap).mockClear());

  it("carve button is disabled when no source is retained", () => {
    render(<Dashboard output={output} activeSource={null} selectedIncident={null} onSelectIncident={vi.fn()} />);
    const btn = screen.getByRole("button", { name: /carve .*host|carve this host/i });
    expect(btn).toBeDisabled();
  });

  it("clicking the carve button calls carveSubPcap with the host ip", () => {
    render(<Dashboard output={output} activeSource={{ kind: "bytes", bytes: new ArrayBuffer(8) }} selectedIncident={null} onSelectIncident={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: /carve .*host|carve this host/i }));
    expect(carveSubPcap).toHaveBeenCalledWith(
      expect.objectContaining({ host: "10.0.0.9" }),
      expect.objectContaining({ kind: "bytes" }),
      expect.stringContaining("10.0.0.9"),
    );
  });
});
```

> NOTE: reuse the REAL AnalysisOutput fixture the existing Dashboard/threat tests use (`makeOutputWithThreat` is a placeholder — find/extend the fixture so `summary.ip_threats` has one entry with `ip: "10.0.0.9"`). The carve button needs an accessible name (an `aria-label`/`title` containing "carve" + "host") so `getByRole("button", { name: /carve/i })` finds it. If multiple threat cards render, scope to the first or give the fixture one threat.

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/components/Dashboard.test.tsx` → FAIL (no carve button / `activeSource` prop).

- [ ] **Step 3: Implement** —
(a) `App.tsx:614`: add `activeSource={activeSource}` to the `<Dashboard …>` props.
(b) `Dashboard.tsx`:
- imports: add `useCallback`, `useState` (if not present); `import { carveSubPcap, packetsAvailable } from "../lib/packets";`; `import type { ActiveSource } from "../types";`; add `Scissors` to the lucide-react import.
- `const HOST_CARVE_END_NS = 9e18;` (module const, near the top).
- `DashboardProps`: add `/** Active capture source — enables per-host pcap carve when retained. */ activeSource: ActiveSource;`.
- `Dashboard({ output, onJumpToFlows, selectedIncident, onSelectIncident, activeSource })`:
```tsx
  const canCarve = packetsAvailable(activeSource);
  const [carveNotice, setCarveNotice] = useState<string | null>(null);
  const carveHost = useCallback(
    async (ip: string) => {
      const res = await carveSubPcap(
        { host: ip, start_ns: 0, end_ns: HOST_CARVE_END_NS },
        activeSource,
        `${ip}-carve.pcap`,
      );
      if (res.ok) setCarveNotice(res.message);
      else if (res.message) setCarveNotice(res.message);
    },
    [activeSource],
  );
```
- pass to the watchlist: `<ThreatWatchlist threats={s.ip_threats ?? []} onSelect={openHost} onCarveHost={carveHost} canCarve={canCarve} />`.
- render the notice (near the watchlist), e.g. `{carveNotice && <p role="status" className="px-1 text-xs text-[var(--color-text-faint)]">{carveNotice}</p>}`.
(c) `ThreatWatchlist` (the local fn-component): add `onCarveHost`/`canCarve` to its props; in each host card, add a small carve icon button next to the existing controls:
```tsx
              {onCarveHost && (
                <button
                  type="button"
                  aria-label={`Carve ${threat.ip} host packets`}
                  title={canCarve ? "Carve this host's packets (.pcap)" : "Packets are only available for captures analyzed from a pcap"}
                  disabled={!canCarve}
                  onClick={(e) => { e.stopPropagation(); onCarveHost(threat.ip); }}
                  className={cn(
                    "shrink-0 rounded p-1 transition-colors",
                    canCarve
                      ? "text-[var(--color-text-faint)] hover:text-[var(--color-accent)]"
                      : "cursor-not-allowed text-[var(--color-text-faint)] opacity-50",
                  )}
                >
                  <Scissors size={12} />
                </button>
              )}
```

> NOTE: place the button where it won't break the card's existing click-to-pivot (`stopPropagation` prevents the carve click from also firing `onSelect`). Use the card's real field for the host (`threat.ip`). If `cn` isn't imported in Dashboard.tsx, use the local className helper the file already uses (or plain template strings). Match the card's existing control styling.

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/components/Dashboard.test.tsx` → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors (the new required `activeSource` prop means every `<Dashboard>` usage — App + any test — must pass it; fix the compiler-flagged call sites).

- [ ] **Step 5: Commit**

```bash
git add ui/src/App.tsx ui/src/components/Dashboard.tsx ui/src/components/Dashboard.test.tsx
git commit -m "feat(ui): Carve host pcap button on the threat watchlist"
```

---

### Task 2: Full gate

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

- [ ] **Step 2: Engine untouched (sanity)** — `git diff --name-only main..HEAD -- engine/ | head` → empty.

- [ ] **Step 3: Fill any gap** — if a metric dips, add a focused test (e.g. the carveNotice surfaced after a successful carve; the stopPropagation behavior) and re-run step 1.

- [ ] **Step 4: Commit** (if tests added)

```bash
git add ui/src/<new/updated tests>
git commit -m "test(ui): hold the gate for the host-carve button"
```

---

## Self-Review

**1. Spec coverage:** `activeSource` threading + `carveHost` + the `ThreatWatchlist` button (T1) → spec §1-3; gate (T2) → constraints/testing. Pure-UI, same gating, whole-capture window, no-throw notice, stopPropagation — all covered. Incident-flyout entry + window picker out of scope. ✓

**2. Placeholder scan:** complete code for the App prop, the Dashboard `carveHost`/notice, the watchlist button. The NOTEs (reuse the real AnalysisOutput threat fixture; match the card's control styling + `cn`/host-field; fix the now-required `activeSource` prop at every `<Dashboard>` call site) are concrete in-repo verifications. ✓

**3. Type consistency:** `DashboardProps.activeSource: ActiveSource` (added) ⇄ App passes `activeSource` ⇄ `carveHost` calls `carveSubPcap({ host, start_ns, end_ns }, activeSource, name)` with the `CarveQuery` shape ⇄ `ThreatWatchlist` `onCarveHost: (ip) => void` + `canCarve: boolean`. `HOST_CARVE_END_NS` numeric, within i64. ✓
