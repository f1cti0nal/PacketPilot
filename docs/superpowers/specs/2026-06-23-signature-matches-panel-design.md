# Signature matches panel — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-23
**Branch:** `feat/signature-matches-panel`

## Goal

Give imported-rule matches a consolidated home on the Dashboard. Rule import (phase A engine + phase B in-app) folds `RuleMatch` findings into `summary.findings`, but the UI only surfaces them indirectly (a threat-card uplift + a transient count notice) — there's no view of *what* matched (which signatures, where). This adds a read-only "Signature matches" panel listing those findings.

## Architecture

Pure UI. The `RuleMatch` findings already exist in `summary.findings` with `kind: "rule_match"`. A new `SignatureMatchesPanel` filters them and renders a list, mirroring the existing `DomainThreatsPanel` (the other Dashboard triage panel). No engine/WASM/Tauri change.

**Tech stack:** React 18 + TS; Vitest. No new deps.

## Global Constraints

- **Pure UI** — no engine/WASM/Tauri change. The `RuleMatch` finding shape (set by the engine `rule_finding` in phase A) is the contract: `kind: "rule_match"`, `title` = the rule `msg`, `src_ip`/`dst_ip`/`dst_port`, `attack` = MITRE ids, `evidence` includes `"rule sid:N"` + `"matched content (… bytes)"`, `severity`.
- **Invisible until relevant** — the panel returns `null` when there are no `rule_match` findings (so it doesn't clutter the Dashboard for captures with no rules applied), exactly like `DomainThreatsPanel` hides when empty.
- **Defensive parse** — the sid is parsed from the `evidence` `"rule sid:N"` line; a missing/garbled sid falls back to omitting it (never throws).
- No new deps. Coverage gate ≥ 80/70 (vitest 1.6.1). Stage specific files.

## Reference: the seams (verified)

```ts
// ui/src/types.ts:151 export type FindingKind = … (snake-case wire tokens) — "rule_match" is NOT yet in the union (phase A was engine+CLI); ADD it.
//   Finding { kind: FindingKind; severity: Severity; score: number; title: string; src_ip: string; dst_ip: string|null; dst_port: number|null; attack: string[]; evidence: string[]; … }
// ui/src/components/triage/DomainThreatsPanel.tsx — the Dashboard triage-panel pattern to MIRROR: a <section data-component aria-label> + a header (icon + title + count) + a <ul> of cards; `if (empty) return null`.
// ui/src/cockpit/primitives  MitreTag (the ATT&CK chip) ; SectionLabel ; (SeverityChip is in cockpit/* — grep for it)
// ui/src/components/Dashboard.tsx:165 <DomainThreatsPanel domains={s.domain_threats ?? []} /> ; s.findings is in scope (passed to ActivityHeatmap at :147)
// engine rule_finding evidence (the contract): evidence[0] = "rule sid:{sid}", evidence[1] = "matched content ({n} bytes)"
```

## Components

### 1. `ui/src/types.ts`
Add `"rule_match"` to the `FindingKind` union (the engine already emits it; the TS union is stale). Confirm it's absent first; if already present, no change.

### 2. `ui/src/components/triage/SignatureMatchesPanel.tsx` (new)
```tsx
export function SignatureMatchesPanel({ findings }: { findings: Finding[] }) { … }
```
- `const matches = (findings ?? []).filter((f) => f.kind === "rule_match");`
- `if (matches.length === 0) return null;`
- A `<section data-component="SignatureMatchesPanel" aria-label="Signature matches">` with a header: an icon (`ShieldAlert` / `FileSearch` from lucide — match the rule-import button's icon for consistency), the title **"Signature matches"**, and a count (`matches.length`).
- A `<ul>` of cards (cap the rendered rows, e.g. `matches.slice(0, 50)`), each card:
  - the rule **msg** (`f.title`) — bold, truncate.
  - the **sid** — parse from `f.evidence` via `/sid:(\d+)/` over the evidence entries; render as a small `sid 1001` tag when found.
  - **`src_ip → dst_ip:dst_port`** (mono), with `dst_port`/`dst_ip` omitted gracefully when null.
  - the **MITRE chips** — `f.attack.map((a) => <MitreTag id={a} />)`.
  - a `SeverityChip severity={f.severity}` (or the severity-colored accent used elsewhere).
  - cockpit styling (`--color-*` tokens, `t-tag`, `font-mono-num`), mirroring `DomainThreatsPanel`'s card.
- A small `sidOf(f: Finding): string | null` helper (the defensive regex parse).

### 3. `ui/src/components/Dashboard.tsx`
Render `<SignatureMatchesPanel findings={s.findings ?? []} />` adjacent to `<DomainThreatsPanel …>` (~:165).

## Data flow & error handling

`summary.findings` → filter `kind === "rule_match"` → render. No rule matches → the panel doesn't render. The sid parse is a defensive regex (no throw; omits the sid tag if absent). No new data fetched — the findings are already present from the rule apply (CLI phase A / in-app phase B). The panel is read-only.

## Testing

- **`SignatureMatchesPanel`:** with a `rule_match` finding (title "C2 beacon", evidence `["rule sid:1001", …]`, attack `["T1071"]`, src/dst/port set) → renders the msg, the `sid 1001` tag, `src→dst:port`, and the `T1071` MITRE chip. With no `rule_match` findings (empty, or only other kinds) → renders nothing (`container` empty / `queryBy` null). A `rule_match` finding whose evidence lacks a sid → renders the row without a sid tag (no throw).
- **`Dashboard`:** includes the panel when `summary.findings` has a `rule_match` (smoke); the existing Dashboard tests still pass.
- Coverage ≥ 80/70.

## Out of scope

Clicking a match to pivot to the host's flows (the threat-card uplift already links the host; a `onJumpToFlows` pivot is a possible later add); grouping/dedup by sid; per-match drill-down; incident-correlating rule matches (engine, deferred to rule-import phase C). Just the consolidated read-only list.

## File manifest

**UI — create:** `ui/src/components/triage/SignatureMatchesPanel.tsx` (+ a co-located test).
**UI — modify:** `ui/src/types.ts` (`"rule_match"` in `FindingKind`), `ui/src/components/Dashboard.tsx` (render the panel) + the Dashboard test if it asserts panel presence.
**No engine/WASM/Tauri change, no new deps.**
