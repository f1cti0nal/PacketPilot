# Saved rule sets — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-23
**Branch:** `feat/saved-rule-sets`

## Goal

Persist imported rulesets so they survive reload and re-apply to new captures. Today the "Load detection rules" button re-picks a `.rules` file every time; this saves loaded sets in localStorage and offers a dropdown to re-apply or delete them. Mirrors the saved-filters feature.

## Architecture

Pure UI, localStorage — **no engine/WASM/Tauri change** (`applyRules` is reused as-is). A `ruleSets.ts` lib (CRUD, a near-clone of `filterProfiles.ts`) + a `RuleSetsMenu` dropdown (mirroring `FilterProfiles`) that replaces the single CommandBar load-rules button. The App's `loadRules` is split so a file *and* a saved set's text run the same apply path (over the per-capture base snapshot — no stacking).

**Tech stack:** React 18 + TS; Vitest. No new deps.

## Global Constraints

- **Pure UI** — no engine/WASM/Tauri. Reuse `applyRules` + the `pickRuleBase` base snapshot (no stacking on re-apply).
- **localStorage, versioned key `packetpilot.ruleSets.v1`**, all access try/catch (never throws), JSON serialize/deserialize — mirror `filterProfiles.ts`. A per-set text cap (`MAX_RULESET_BYTES = 256 * 1024`) — oversized text is rejected on save (never throws; reported via the return).
- **No-throw** at the UI boundary; the apply path keeps its existing `ExportResult`/notice behavior.
- No new deps. Coverage gate ≥ 80/70 (vitest 1.6.1).

## Reference: the seams (verified)

```ts
// ui/src/lib/filterProfiles.ts — the localStorage CRUD pattern to MIRROR (KEY, try/catch listProfiles/saveProfile(upsert by trimmed name)/removeProfile/clearProfiles, isProfile validator)
// ui/src/components/flows/FilterProfiles.tsx — the dropdown pattern (open/outside-click, list rows + per-row delete, an action row)
// ui/src/App.tsx:563 loadRules(file): if not ready/no-source return; text=await file.text(); key=captureKey(currentData); base=pickRuleBase(ruleBaseRef,key,currentData); try { res=await applyRules(text,base,activeSource); setSummary({…res.output}); setRuleNotice(`Rules: …`) } catch { setRuleNotice(…) }
//   :152 rulesInputRef ; :623 onLoadRules={packetsAvailable(activeSource) ? () => rulesInputRef.current?.click() : undefined} (passed to AppShell → CommandBar + the ⌘K palette)
// ui/src/cockpit/CommandBar.tsx:62 onLoadRules?: ()=>void ; :188-200 the ShieldAlert button (onClick={onLoadRules}, disabled={!onLoadRules}) — REPLACE the button with a `rulesMenu?: ReactNode` slot
// ui/src/cockpit/AppShell.tsx — threads onLoadRules to CommandBar + paletteActions (keep the palette's onLoadRules; swap the CommandBar pass to rulesMenu)
// ui/src/lib/packets.ts packetsAvailable(activeSource)
```

## Components

### 1. `ui/src/lib/ruleSets.ts` (new)
```ts
export interface RuleSet { id: string; name: string; text: string }
export function listRuleSets(): RuleSet[];                                   // localStorage get + JSON.parse, try/catch → []
export function saveRuleSet(name: string, text: string): { ok: boolean; sets: RuleSet[]; message?: string }; // upsert by trimmed name; reject if text > MAX; persist; never throws
export function removeRuleSet(id: string): RuleSet[];
export function clearRuleSets(): RuleSet[];
```
Key `packetpilot.ruleSets.v1`; `isRuleSet` validator (id/name/text strings, name non-empty); persist try/catch (quota swallowed) — all mirroring `filterProfiles.ts`. `saveRuleSet` returns `{ok:false, …, message}` when the text exceeds `MAX_RULESET_BYTES` (so the caller can notice) rather than throwing.

### 2. `ui/src/App.tsx` — split the apply path + auto-save
- Extract `applyRuleText(text: string)` = the body of the current `loadRules` from `currentData` through the `try/catch` (everything except `await file.text()`). `useCallback([summary, activeSource])`.
- `loadRules(file) = { const text = await file.text(); saveRuleSet(file.name, text); await applyRuleText(text); }` (auto-persist on load; a save failure is non-fatal — the apply still runs).
- `applyRuleSet(rs: RuleSet) = applyRuleText(rs.text)`.
- Render `<RuleSetsMenu … />` and pass it to the CommandBar via the new `rulesMenu` slot (keep `onLoadRules` for the ⌘K palette + the hidden file input).

### 3. `ui/src/components/.../RuleSetsMenu.tsx` (new)
A "Rules ▾" dropdown (mirror `FilterProfiles`'s open/outside-click). Props: `{ onLoadFile: () => void; onApply: (rs: RuleSet) => void; disabled: boolean; onNotice?: (m: string) => void }`. Contents:
- a "Load .rules file…" row → `onLoadFile()` (triggers the hidden input), disabled per `disabled`.
- the saved sets (`listRuleSets()`): each row a button `onClick={() => onApply(rs)}` (disabled when `disabled`) + a small `×` → `setSets(removeRuleSet(rs.id))`.
- empty-state text when none saved.
Local state holds the list (re-read after a mutation). Disabled (with a tooltip "Available for captures analyzed from a pcap") when `disabled` (i.e. `!packetsAvailable(activeSource)`). Cockpit styling.

### 4. `CommandBar.tsx` + `AppShell.tsx`
`CommandBar`: replace `onLoadRules?: () => void` + the ShieldAlert button with `rulesMenu?: ReactNode`, rendered in the same spot. `AppShell`: pass `rulesMenu` to the CommandBar (instead of `onLoadRules`); keep `onLoadRules` for the ⌘K palette action.

## Data flow & error handling

Load file → `saveRuleSet(name, text)` (persist; oversized → a notice, not saved) + `applyRuleText` (the existing apply over the base snapshot, no-throw notice). Apply saved set → `applyRuleText(rs.text)`. Delete → `removeRuleSet`. localStorage quota/parse errors swallowed (like `filterProfiles`). The per-capture base snapshot (`pickRuleBase`) still prevents stacking on re-apply.

## Testing

- **`ruleSets.ts`:** save/list round-trip + upsert-by-name; remove/clear; an oversized text → `{ok:false}` (not saved, no throw); malformed/quota → no throw; the `v1` key.
- **`RuleSetsMenu`:** lists saved sets; clicking a set calls `onApply(rs)`; delete removes a row; "Load .rules file…" calls `onLoadFile`; disabled when `disabled`; empty-state.
- **App:** loading a file auto-saves the set (`saveRuleSet` called with the filename) + runs `applyRuleText`; applying a saved set runs `applyRuleText` over the base snapshot. (Mock `platform.applyRules` + `ruleSets`.)
- Coverage ≥ 80/70.

## Out of scope

Export/import rule sets as JSON (a later add); editing rule text in-app; engine/Tauri persistence; cross-device sync; a name prompt on save (auto-use the filename).

## File manifest

**UI — create:** `ui/src/lib/ruleSets.ts`, `ui/src/components/.../RuleSetsMenu.tsx` (+ co-located tests).
**UI — modify:** `ui/src/App.tsx` (`applyRuleText` split + auto-save + `applyRuleSet` + render the menu), `ui/src/cockpit/CommandBar.tsx` (the `rulesMenu` slot), `ui/src/cockpit/AppShell.tsx` (thread the slot) + the co-located tests.
**No engine/WASM/Tauri change, no new deps.**
