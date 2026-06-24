# Saved rule sets — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist imported rulesets in localStorage + a dropdown to re-apply/delete them; a loaded `.rules` file auto-saves by name.

**Architecture:** Pure UI — a `ruleSets.ts` lib (mirrors `filterProfiles.ts`) + a `RuleSetsMenu` dropdown (mirrors `FilterProfiles`); `App.loadRules` is split into `applyRuleText` so a file and a saved set share the apply path. No engine change.

**Tech Stack:** React 18 + TS; Vitest. No new deps.

## Global Constraints

- **Pure UI** — no engine/WASM/Tauri. Reuse `applyRules` + `pickRuleBase` (no stacking).
- **localStorage `packetpilot.ruleSets.v1`**, try/catch, never-throws (mirror `filterProfiles.ts`). `MAX_RULESET_BYTES = 256*1024`; oversized → `{ok:false}` (not saved, no throw).
- No new deps. Coverage ≥ 80/70 (vitest 1.6.1). node `/c/Program Files/nodejs`; do NOT `npm install`.

## Reference: the seams (verified)

```ts
// ui/src/lib/filterProfiles.ts — CLONE the structure (KEY, listProfiles/saveProfile upsert-by-trimmed-name/removeProfile/clearProfiles, isProfile, persist try/catch)
// ui/src/components/flows/FilterProfiles.tsx — the dropdown (open + outside-click mousedown listener; list rows + per-row ×; an action row)
// ui/src/App.tsx:563-577 loadRules(file) (the body to split) ; :152 rulesInputRef ; :623 onLoadRules ; pickRuleBase/ruleBaseRef/captureKey/applyRules/packetsAvailable already imported
// ui/src/cockpit/CommandBar.tsx:62 onLoadRules?:()=>void ; :188-200 the ShieldAlert button → REPLACE with `rulesMenu?: ReactNode`
// ui/src/cockpit/AppShell.tsx — threads onLoadRules to CommandBar + paletteActions
```

---

### Task 1: `ui/src/lib/ruleSets.ts`

**Files:** Create `ui/src/lib/ruleSets.ts`, `ui/src/lib/ruleSets.test.ts`

- [ ] **Step 1: Write the failing test** — `ruleSets.test.ts`:
```ts
import { describe, it, expect, beforeEach } from "vitest";
import { listRuleSets, saveRuleSet, removeRuleSet, clearRuleSets } from "./ruleSets";

describe("ruleSets", () => {
  beforeEach(() => localStorage.clear());

  it("saves and lists under the v1 key", () => {
    const r = saveRuleSet("c2.rules", "alert tcp any any -> any 443 (content:\"x\"; sid:1;)");
    expect(r.ok).toBe(true);
    expect(listRuleSets().map((s) => s.name)).toEqual(["c2.rules"]);
    expect(localStorage.getItem("packetpilot.ruleSets.v1")).toContain("c2.rules");
  });
  it("upserts by trimmed name (keeps one, updated text)", () => {
    saveRuleSet("set", "a"); saveRuleSet("set", "b");
    const list = listRuleSets();
    expect(list).toHaveLength(1);
    expect(list[0].text).toBe("b");
  });
  it("removes and clears", () => {
    const list = saveRuleSet("x", "a").sets;
    expect(removeRuleSet(list[0].id)).toHaveLength(0);
    saveRuleSet("y", "a"); expect(clearRuleSets()).toHaveLength(0);
  });
  it("rejects oversized text without saving or throwing", () => {
    const big = "x".repeat(256 * 1024 + 1);
    const r = saveRuleSet("big", big);
    expect(r.ok).toBe(false);
    expect(listRuleSets()).toHaveLength(0);
  });
  it("survives malformed storage without throwing", () => {
    localStorage.setItem("packetpilot.ruleSets.v1", "{ not json");
    expect(listRuleSets()).toEqual([]);
  });
});
```

- [ ] **Step 2: Run to verify it fails** — `cd ui && npx vitest run src/lib/ruleSets.test.ts` → FAIL.

- [ ] **Step 3: Implement** — `ruleSets.ts` (clone `filterProfiles.ts`):
```ts
export interface RuleSet { id: string; name: string; text: string }

const KEY = "packetpilot.ruleSets.v1";
const MAX_RULESET_BYTES = 256 * 1024;

function isRuleSet(v: unknown): v is RuleSet {
  if (typeof v !== "object" || v === null) return false;
  const r = v as Record<string, unknown>;
  return typeof r.id === "string" && typeof r.name === "string" && r.name.trim() !== "" && typeof r.text === "string";
}

export function listRuleSets(): RuleSet[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? parsed.filter(isRuleSet) : [];
  } catch {
    return [];
  }
}

function persist(list: RuleSet[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(list));
  } catch {
    /* quota: drop silently (mirrors filterProfiles) */
  }
}

export function saveRuleSet(name: string, text: string): { ok: boolean; sets: RuleSet[]; message?: string } {
  const trimmed = name.trim();
  if (trimmed === "") return { ok: false, sets: listRuleSets(), message: "Empty name" };
  if (text.length > MAX_RULESET_BYTES) return { ok: false, sets: listRuleSets(), message: "Ruleset too large to save" };
  const list = listRuleSets().filter((s) => s.name !== trimmed);
  list.push({ id: `rs_${trimmed.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`, name: trimmed, text });
  persist(list);
  return { ok: true, sets: list };
}

export function removeRuleSet(id: string): RuleSet[] {
  const list = listRuleSets().filter((s) => s.id !== id);
  persist(list);
  return list;
}

export function clearRuleSets(): RuleSet[] {
  try { localStorage.removeItem(KEY); } catch { /* ignore */ }
  return [];
}
```

- [ ] **Step 4: Run to verify it passes** — `cd ui && npx vitest run src/lib/ruleSets.test.ts` → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → clean.

- [ ] **Step 5: Commit**
```bash
git add ui/src/lib/ruleSets.ts ui/src/lib/ruleSets.test.ts
git commit -m "feat(ui): ruleSets localStorage CRUD (persist imported rulesets)"
```

---

### Task 2: `RuleSetsMenu` component

**Files:** Create `ui/src/components/flows/RuleSetsMenu.tsx` (alongside `FilterProfiles.tsx`), `ui/src/components/flows/RuleSetsMenu.test.tsx`

**Interfaces:** `RuleSetsMenu({ onLoadFile, onApply, disabled, onNotice? })`.

- [ ] **Step 1: Write the failing test** — `RuleSetsMenu.test.tsx`:
```tsx
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent } from "../../test/render";
import { RuleSetsMenu } from "./RuleSetsMenu";
import { saveRuleSet } from "../../lib/ruleSets";

describe("RuleSetsMenu", () => {
  beforeEach(() => localStorage.clear());

  it("applies a saved set via onApply", () => {
    saveRuleSet("c2.rules", "alert tcp any any -> any 443 (content:\"x\"; sid:1;)");
    const onApply = vi.fn();
    render(<RuleSetsMenu onLoadFile={vi.fn()} onApply={onApply} disabled={false} />);
    fireEvent.click(screen.getByText(/Rules/i)); // open
    fireEvent.click(screen.getByText("c2.rules"));
    expect(onApply).toHaveBeenCalledWith(expect.objectContaining({ name: "c2.rules" }));
  });
  it("calls onLoadFile from the load row", () => {
    const onLoadFile = vi.fn();
    render(<RuleSetsMenu onLoadFile={onLoadFile} onApply={vi.fn()} disabled={false} />);
    fireEvent.click(screen.getByText(/Rules/i));
    fireEvent.click(screen.getByText(/Load .rules file/i));
    expect(onLoadFile).toHaveBeenCalled();
  });
  it("disables actions + shows empty-state appropriately", () => {
    render(<RuleSetsMenu onLoadFile={vi.fn()} onApply={vi.fn()} disabled={true} />);
    fireEvent.click(screen.getByText(/Rules/i));
    expect(screen.getByText(/Load .rules file/i).closest("button")).toBeDisabled();
  });
});
```
> NOTE: mirror `FilterProfiles.tsx`'s open/outside-click + the cockpit `t-tag`/token styling. The trigger button text contains "Rules". The load row label contains "Load .rules file". A delete `×` per saved row → `setSets(removeRuleSet(rs.id))`.

- [ ] **Step 2: Run to verify it fails** — FAIL.

- [ ] **Step 3: Implement** — `RuleSetsMenu.tsx` mirroring `FilterProfiles.tsx`: `const [open,setOpen]=useState(false)`; `const ref=useRef<HTMLDivElement>(null)` + a `mousedown` document listener (gated on `open`) that closes on outside click; `const [sets,setSets]=useState(listRuleSets)`. A "Rules ▾" button (`disabled` styling per the `disabled` prop affects the action rows, not the menu open). Dropdown contents: a "Load .rules file…" row `<button disabled={disabled} onClick={() => { setOpen(false); onLoadFile(); }}>`; the saved sets `sets.map(rs => a row with a button onClick={() => { setOpen(false); onApply(rs); }} disabled={disabled} + a × button onClick={() => setSets(removeRuleSet(rs.id))}>`; an empty-state when `sets.length===0`. Tooltip on the disabled rows: "Available for captures analyzed from a pcap".

- [ ] **Step 4: Run to verify it passes** — PASS; tsc clean.

- [ ] **Step 5: Commit**
```bash
git add ui/src/components/flows/RuleSetsMenu.tsx ui/src/components/flows/RuleSetsMenu.test.tsx
git commit -m "feat(ui): RuleSetsMenu dropdown (apply/delete/load saved rulesets)"
```

---

### Task 3: App split + CommandBar/AppShell wiring (+ gate)

**Files:** Modify `ui/src/App.tsx`, `ui/src/cockpit/CommandBar.tsx`, `ui/src/cockpit/AppShell.tsx`, `ui/src/App.test.tsx`

- [ ] **Step 1: Split `loadRules` + auto-save (App.tsx).** Extract `applyRuleText`:
```tsx
const applyRuleText = useCallback(async (text: string) => {
  if (summary.status !== "ready" || !summary.data || !packetsAvailable(activeSource)) return;
  const currentData = summary.data;
  const key = captureKey(currentData);
  const base = pickRuleBase(ruleBaseRef, key, currentData);
  try {
    const res = await applyRules(text, base, activeSource);
    setSummary({ status: "ready", data: res.output });
    setRuleNotice(`Rules: ${res.loaded} loaded, ${res.skipped} skipped, ${res.matches} match${res.matches === 1 ? "" : "es"}`);
  } catch (e) {
    setRuleNotice(e instanceof Error ? e.message : "Failed to apply rules");
  }
}, [summary, activeSource]);

const loadRules = useCallback(async (file: File) => {
  const text = await file.text();
  saveRuleSet(file.name, text);  // persist (non-fatal if it fails)
  await applyRuleText(text);
}, [applyRuleText]);

const applyRuleSet = useCallback((rs: RuleSet) => { void applyRuleText(rs.text); }, [applyRuleText]);
```
(Import `saveRuleSet`, `type RuleSet` from `./lib/ruleSets`; `pickRuleBase`/`ruleBaseRef`/`captureKey`/`applyRules`/`packetsAvailable` are already in scope.)

- [ ] **Step 2: CommandBar slot.** `CommandBar.tsx`: replace the `onLoadRules?: () => void` prop + the ShieldAlert button (`:188-200`) with `rulesMenu?: ReactNode` (import `ReactNode` from react), rendered in the same spot (`{rulesMenu}`).

- [ ] **Step 3: AppShell thread.** `AppShell.tsx`: add a `rulesMenu?: ReactNode` prop; pass it to `<CommandBar rulesMenu={rulesMenu} … />` (instead of `onLoadRules`); KEEP `onLoadRules` for the ⌘K palette action (the file-load shortcut).

- [ ] **Step 4: App render.** App: pass to `<AppShell>` `rulesMenu={<RuleSetsMenu onLoadFile={() => rulesInputRef.current?.click()} onApply={applyRuleSet} disabled={!packetsAvailable(activeSource)} />}` (keep `onLoadRules={packetsAvailable(activeSource) ? () => rulesInputRef.current?.click() : undefined}` for the palette).

- [ ] **Step 5: Write/extend the App test.** Add to `App.test.tsx`: with a ready summary + a bytes `activeSource`, loading a `.rules` File (drive `loadRules` via the rendered RuleSetsMenu's load row → the file input, OR the most testable path) → `saveRuleSet` persisted the set (assert `listRuleSets()` has the filename) AND `applyRules` was called; applying a saved set (via the menu) → `applyRules` called with the set's text. Mock `platform.applyRules`. If driving the full upload→bytes flow is awkward, at minimum assert `loadRules` persists via `ruleSets` + the menu wiring (a focused test).
> NOTE: the existing App rule tests run in browser-sample mode (activeSource null) — keep them passing; add the bytes-path coverage where feasible, else cover `applyRuleSet`→`applyRuleText` at the unit boundary.

- [ ] **Step 6: Run** — `cd ui && npx vitest run src/App.test.tsx` → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → clean.

- [ ] **Step 7: Commit**
```bash
git add ui/src/App.tsx ui/src/cockpit/CommandBar.tsx ui/src/cockpit/AppShell.tsx ui/src/App.test.tsx
git commit -m "feat(ui): wire RuleSetsMenu — auto-save loaded rulesets + apply saved"
```

- [ ] **Step 8: Full gate** — `cd ui && export PATH="/c/Program Files/nodejs:/c/Users/ravid/.cargo/bin:$PATH"`:
```bash
git checkout -- package.json package-lock.json 2>/dev/null || true
npm ci
node -p "require('./node_modules/vitest/package.json').version"   # 1.6.1
npm run build:wasm
npm run build; echo "build EXIT: $?"          # 0
npm run test:coverage; echo "cov EXIT: $?"    # 0; All files >= 80/70 — paste it
git diff --name-only main..HEAD -- engine/ | head   # empty
```
Do NOT `npm install`.

- [ ] **Step 9: Commit** any gate top-up tests.

---

## Self-Review

**1. Spec coverage:** `ruleSets` CRUD (T1) → spec §1; `RuleSetsMenu` (T2) → §3; the App split + auto-save + `applyRuleSet` + CommandBar/AppShell slot (T3) → §2,§4 + gate. localStorage v1 key, size cap, no-throw, no-stacking (reuses pickRuleBase), pure-UI — all covered. Export/import + name-prompt out of scope. ✓

**2. Placeholder scan:** complete code for `ruleSets.ts` + the App split; `RuleSetsMenu` concretely specified (mirror FilterProfiles). The NOTEs (mirror FilterProfiles open pattern; the most-testable App path) are concrete in-repo refs. ✓

**3. Type consistency:** `RuleSet{id,name,text}` (T1) ⇄ `RuleSetsMenu onApply:(rs:RuleSet)=>void` (T2) ⇄ App `applyRuleSet(rs)=applyRuleText(rs.text)` + `loadRules` `saveRuleSet(file.name,text)` ⇄ CommandBar/AppShell `rulesMenu?:ReactNode`. ✓
