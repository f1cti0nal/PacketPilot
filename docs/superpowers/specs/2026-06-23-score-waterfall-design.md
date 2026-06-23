# Score waterfall (explainability) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-23
**Branch:** `feat/score-waterfall`

## Goal

Make the threat score *provable*. Today a host shows a score (e.g. 90/100) but the reasoning lives in a raw `evidence[]` string list that isn't even on the Dashboard. This adds a visual **score waterfall** — each `+N`/`−N` term that built the score, plus the engine's clamp/floor adjustments — in the host drill-down (the incident `DetailFlyout`).

## Approach — pure-UI parse (no engine change)

The engine scorer already emits the terms as human-readable evidence strings on `IpThreat.evidence` (e.g. `"category c2 (+45)"`, `"ioc: endpoint ip on threat feed (+35)"`, `"external public peer (+15)"`, `"all-internal peers (-10)"`, `"behavior: beacon-shaped (+10)"`). A reusable component parses them — **no engine/WASM/Tauri change** (well-suited while CI is billing-blocked). Structured engine score-terms (the transparency-layer memo's preferred long-term shape) are explicitly out of scope here; parsing the stable, tested strings is sufficient.

**Honesty about the engine's two non-additive steps** (verified in `engine/crates/ppcap-core/src/score/mod.rs`):
- Lines ending in `(±N)` are **additive terms**. Their running cumulative sum = the engine's *raw* accumulator `acc`.
- `clamp: raw {acc} -> {score}` and `floor: ioc match forces High (>= 60)` / `floor: ioc + c2/anomalous forces Critical (>= 90)` are **non-additive annotations**. The clamp bounds `acc` into 0..=100; a floor raises the score to a minimum. They are NOT bars — they explain why the final score differs from the sum of terms.
- The parse regex `\(([+-]?\d+)\)` matches only a bare signed integer in parens, so `(>= 60)` / `(>= 90)` in the floor lines are correctly NOT treated as additive terms.

**Tech stack:** React 18 + TS; Vitest. No new deps.

## Global Constraints

- **Pure UI** — no engine/WASM/Tauri change. `IpThreat.evidence: string[]` + `IpThreat.score: number` are the inputs; the score evidence format in `score/mod.rs` is the (stable, tested) contract.
- **The final bar is the authoritative `IpThreat.score`**, not the sum of parsed terms — so a clamp/floor never makes the visual lie. The annotations explain any gap.
- **Graceful on unknown shapes** — evidence with no `(±N)` term renders no bars (just notes, or nothing); the parser never throws.
- **No new dependencies.** Reuse the cockpit primitives + the `components/transparency/` pattern. Coverage gate ≥ 80/70 (vitest 1.6.1). Stage specific files.

## Reference: the seams (verified)

```ts
// ui/src/types.ts:128 IpThreat { ip; ip_class; severity: Severity; score: number; flows; bytes; ioc; attack: string[]; evidence: string[]; ... }
//   :142 Incident { host: string; severity; score; attack[]; stages; narrative; findings: Finding[] }  (NO score evidence[])
// ui/src/cockpit/DetailFlyout.tsx:14 DetailFlyout({ incident, onClose, onJumpToFlows }: { incident: Incident|null; ... })
//   :72 renders {incident.score} ; :101 "Findings · N" then each finding's <EvidenceList evidence={f.evidence} />
// ui/src/components/Dashboard.tsx:~164 <DetailFlyout incident={selectedIncident} onClose=… onJumpToFlows={toFlowsIp} />
//   Dashboard has s.ip_threats (IpThreat[]) and s.incidents; openHost opens the flyout only when incidentByHost.get(host) exists
// ui/src/components/transparency/EvidenceList.tsx  the existing raw evidence renderer (grouped by prefix) — the waterfall is the score-specific sibling
// engine score evidence (the contract): score/mod.rs pushes "category X (+N)", "ioc: … (+35)", "external public peer (+15)", "all-internal peers (-10)", "behavior: … (+10)", and non-additive "clamp: raw A -> S", "floor: … (>= 60|90)"
```

## Components

### 1. `ui/src/lib/scoreTerms.ts` (new, pure)
```ts
export interface ScoreTerm { label: string; points: number }
export interface ParsedScore { terms: ScoreTerm[]; notes: string[] }
/** Parse IpThreat.evidence into additive {label,points} terms + non-additive notes (clamp/floor). Never throws. */
export function parseScoreTerms(evidence: string[]): ParsedScore;
```
- For each entry: if it matches `/\(([+-]?\d+)\)\s*$/`, it's an additive term — `points = parseInt(group)`, `label = entry with the (±N) suffix stripped, trimmed`. Otherwise it's a note (pushed to `notes`) — this captures `clamp:`/`floor:` lines (and any future non-`(±N)` evidence).
- Empty/`undefined` input → `{ terms: [], notes: [] }`.

### 2. `ui/src/components/transparency/ScoreWaterfall.tsx` (new)
Props: `{ evidence: string[]; score: number; severity: Severity }`. Renders nothing when `parseScoreTerms(evidence).terms.length === 0 && notes.length === 0`. Otherwise:
- A `SectionLabel` "Score breakdown".
- One row per additive term: the `label`, a signed `+N`/`−N` (green for `≥0`, red for `<0`), and a proportional bar segment (width ∝ `|points|` relative to the max `|points|`). A running cumulative is acceptable but optional; the per-term magnitude is the primary signal.
- A final emphasized row: **`Score {score}/100`** with the severity color (`sevColor`).
- The `notes` (clamp/floor) rendered below as small dim mono lines (e.g. "raw 105 → clamped 100", shown verbatim from the evidence string).
- Cockpit styling: `t-tag`/`SectionLabel`/`--color-*` tokens; green = `--color-ok`/positive token already used, red = `--color-danger`/severity-critical token (use existing tokens; fall back to `sevColor`/inline if a named token is absent).

### 3. `DetailFlyout` + Dashboard wiring
- `DetailFlyout` props gain `scoreEvidence?: string[]` + `hostScore?: number`. When `scoreEvidence?.length`, render `<ScoreWaterfall evidence={scoreEvidence} score={hostScore ?? incident.score} severity={incident.severity} />` directly above the "Findings" section.
- `Dashboard`: build `const threatByHost = useMemo(() => new Map((s.ip_threats ?? []).map((t) => [t.ip, t])), [s.ip_threats])`; pass `scoreEvidence={selectedIncident ? threatByHost.get(selectedIncident.host)?.evidence : undefined}` + `hostScore={selectedIncident ? threatByHost.get(selectedIncident.host)?.score : undefined}` to `<DetailFlyout>`.

## Data flow & error handling

Click a watchlist host with an incident → `DetailFlyout` opens → it receives the matching `IpThreat.evidence`/`score` → `ScoreWaterfall` parses + renders the breakdown above Findings. A host whose `IpThreat` lacks `(±N)` evidence (older summaries, or a clean host) → the waterfall renders nothing (the flyout is unchanged). `parseScoreTerms` never throws on malformed strings (a non-matching entry just becomes a note). The final bar is always the authoritative `score`.

## Coverage (scope A)

The waterfall appears in the flyout, which opens only for hosts that have a correlated **incident** (the highest-severity subset). Hosts without an incident don't open the flyout and so don't show a waterfall — an accepted limitation for this scope. (Scope B — making every scored host open a minimal flyout with the breakdown — is a deliberate future extension, not built here.)

## Testing

- **`scoreTerms.ts`:** parses `"category c2 (+45)"` → `{label:"category c2", points:45}`; negative `"all-internal peers (-10)"` → `points:-10`; `"clamp: raw 105 -> 100"` and `"floor: ioc match forces High (>= 60)"` → `notes` (NOT terms); `"external public peer (+15)"` + `"ioc: … (+35)"` mix; `[]` → empty; a garbage string with no parens → a note. (The `(>= 60)` must NOT parse as a term.)
- **`ScoreWaterfall.tsx`:** with a realistic evidence set, renders a row per additive term (assert a couple of labels + signed points), the final `Score N/100`, and a clamp/floor note; empty evidence → renders nothing (`container` empty / `queryBy` null).
- **`DetailFlyout`:** given `scoreEvidence`, the "Score breakdown" appears; without it, it does not (existing flyout tests still pass).
- Coverage ≥ 80/70 under the locked toolchain.

## Out of scope

- Structured engine score-terms (`Vec<ScoreTerm>`) — a future hardening; this parses the existing strings.
- Per-flow (ScoredFlow) waterfall; surfacing it for non-incident hosts (scope B); adding the waterfall to AI context or STIX/CSV/MISP export; animating the bars.

## File manifest

**UI — create:** `ui/src/lib/scoreTerms.ts`, `ui/src/components/transparency/ScoreWaterfall.tsx` (+ co-located tests).
**UI — modify:** `ui/src/cockpit/DetailFlyout.tsx` (render the waterfall + 2 optional props), `ui/src/components/Dashboard.tsx` (look up the host's IpThreat + pass evidence/score) + the DetailFlyout/Dashboard tests.
**No engine/WASM/Tauri change, no new deps.**
