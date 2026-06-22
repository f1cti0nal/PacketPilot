# Detection→UI Transparency Layer — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-22
**Branch:** `feat/detection-ui-transparency`

## Goal

Surface the reasoning the engine already computes — per-provider reputation
verdicts, per-finding evidence and scores, severity rationale, and directional
packet counts — which the UI currently drops at render time. Make the
just-shipped reputation and AI investments **legible and trustworthy** ("why is
this 45/Low? which providers flagged it? what's the evidence?").

## Architecture

A **pure UI-rendering** feature: a parallel survey verified that 16 of 17
reasoning data points already cross the WASM/Tauri JSON boundary and are declared
in `ui/src/types.ts` — they are simply not rendered. The work is a small set of
shared, unit-tested primitive components composed into existing surfaces (the
reputation chip, threat card, threat rail, incident finding rows, detail flyout).
**No engine change, no WASM rebuild, no `types.ts` change.**

Directional packet counts — the one reasoning field NOT already across the
boundary — are **deferred** (see Out of Scope): reaching the desktop/CLI/recent
surfaces requires a new Parquet `flows` column mirrored across the columnar
schema + writer + WASM DTO + TS row types + mappers, which is disproportionate to
its (low) reasoning value for this feature.

**Tech stack:** React 18 + TypeScript + Tailwind (cockpit conventions: CSS vars,
`t-tag`). No Rust changes. No new dependencies.

## Global Constraints

- **No new runtime dependencies.**
- **W1 requires no engine change and no WASM rebuild** — it renders data already
  present in the browser's `AnalysisOutput`. No change to `ui/src/types.ts` (every
  field used is already declared).
- **The `npm run test:coverage` gate stays green** (lines/functions/statements ≥
  80, branches ≥ 70). New primitives are pure and individually tested.
- **No fragile coupling to engine string formats**: the score "explainer" renders
  the engine's `evidence[]` strings as-is (grouped for readability); it does NOT
  parse the signed point-terms (`+45`, `-10`) out of them.
- Match existing cockpit styling (CSS vars, `t-tag`, the existing severity
  palette helpers).

## Design Decisions (resolved)

1. **Score explainer:** render `evidence[]` strings grouped/styled by signal
   prefix — no term parsing (decoupled from engine wording). A parsed "waterfall"
   is an explicit fast-follow, to be done later via *structured* engine
   score-terms, not string parsing.
2. **Per-provider reputation placement:** both — an expandable `ReputationChip`
   popover for a quick glance AND a full breakdown section in the threat card /
   detail flyout.
3. **Directional packets:** DEFERRED. Reaching the desktop/CLI/recent surfaces
   needs a new Parquet `flows` column (`columnar/schema.rs` carries directional
   bytes but aggregate `pkts` only) mirrored across the columnar schema + writer +
   WASM DTO + `RawFlowRow`/`WasmFlow`/`FlowRow` + both mappers — disproportionate
   to its low reasoning value. Tracked as a fast-follow.
4. **Evidence density:** show the full `evidence[]` list (no truncation).
5. **Component architecture:** shared transparency primitives (Approach A) — the
   same data renders across several surfaces, so shared, consistent, testable
   units beat per-surface inline rendering.

## Relevant existing types (already in `ui/src/types.ts`, no edits needed for W1)

```ts
interface ReputationVerdict {                 // types.ts:111
  source: string; status: RepStatus; malicious: boolean;
  score: number | null;                       // 0..=100; null when unknown/notfound/unavailable
  tags: string[]; link: string | null; fetched_at: number; // unix seconds
}
interface IpThreat {                          // types.ts:121
  ip; ip_class; severity; score; flows; bytes; ioc;
  tags: string[]; attack: string[]; evidence: string[];
  reputation?: ReputationVerdict[];
}
interface Finding {                           // types.ts:151
  kind; severity; score: number; title; src_ip; dst_ip; dst_port;
  attack: string[]; evidence: string[];
  interval_ns: number | null; jitter_cv: number | null; contacts: number | null;
}
```

## W1 — Shared primitive components

New directory `ui/src/components/transparency/`. Each is a pure function of its
props, renders nothing on empty/absent data, and has a focused RTL test.

### `ProviderVerdictList`
- **Props:** `{ verdicts: ReputationVerdict[] }`
- Renders one row per provider, sorted worst-status first via a small
  status-rank helper over the real `RepStatus` values — `malicious` (worst), then
  the neutral `unknown`/`notfound`/`unavailable`, then `benign`/`clean` (best):
  `source` · status badge · `score%` (or "—" when `score` is null) · `tags` ·
  `↗ link` (external, only when `link` non-null) · "as of {relative fetched_at}"
  freshness.
- Empty array → renders `null`.

### `EvidenceList`
- **Props:** `{ evidence: string[] }`
- Renders the full list, grouped by the signal prefix before the first `:` in
  each string (e.g. `reputation:`, `c2:`, `ioc:`) for readability; strings with no
  `:` prefix fall into a default ungrouped section. No term parsing. Empty →
  `null`.

### `ScoreBadge`
- **Props:** `{ score: number; severity?: Severity }`
- A 0–100 score chip colored by severity band (reuses the existing severity
  palette helper).

### `FindingMetrics`
- **Props:** `{ finding: Finding }`
- Compact "why this severity" row: renders `score` (via `ScoreBadge`),
  `contacts`, `interval_ns` (humanized to a period), `jitter_cv` — only the
  fields that are non-null.

## W1 — Surface integrations

| Surface | File:line | Change |
|---|---|---|
| **ReputationChip** | `ui/src/cockpit/ReputationChip.tsx:11-20` | The glyph becomes the trigger for an expandable, controlled popover wrapping `ProviderVerdictList`. Keep the summary glyph (worst status) as the collapsed state. |
| **Threat card** | `ui/src/components/triage/ThreatsPanel.tsx:37-137` (evidence ~`:120-134`) | Add a `ProviderVerdictList` breakdown + `tags[]`; route the existing evidence through `EvidenceList`. |
| **Threat rail** | `ui/src/cockpit/ThreatRail.tsx:79-97` (chip `:94`) | Expose the new `ReputationChip` popover on each `RailRow`. |
| **Incident finding row** | `ui/src/components/triage/IncidentsPanel.tsx:71-100` | Add `EvidenceList` + `FindingMetrics` (restores the "why" layer the flyout already shows but the incident card drops). |
| **Detail flyout** | `ui/src/cockpit/DetailFlyout.tsx:108-133` | Add a `FindingMetrics` row; route evidence through the shared `EvidenceList`. |

## Data flow & error handling

Components are pure functions of `AnalysisOutput` data already in the browser —
no new fetching, no async. Optional fields (`link`, `fetched_at`, individual
finding metrics) are omitted gracefully when absent; empty `reputation`/`evidence`
arrays render nothing (no "no data" placeholders, no crashes).

## Testing

- **Primitive unit tests (RTL):** `ProviderVerdictList` (rows render + worst-first
  sort, empty → null, `link` present/absent, null `score` → "—", freshness
  formatting); `EvidenceList` (full list, prefix grouping, empty → null);
  `ScoreBadge` (band color); `FindingMetrics` (renders only present fields).
- **Integration:** `ReputationChip` popover expands and lists every provider;
  `IncidentsPanel` finding row shows evidence + score.
- Coverage stays ≥ 80/70; verify under the locked toolchain (`npm ci` →
  `npm run build` + `npm run test:coverage`) before completion.

## Out of scope (fast-follows)

- **Directional packet counts** (`pkts_c2s`/`pkts_s2c` in `FlowDetail`) —
  deferred; needs a new Parquet `flows` column mirrored across the columnar
  schema + writer + WASM DTO + TS row types + mappers (low reasoning value, real
  schema/cached-parquet blast radius).
- Parsed score "waterfall" widget — do it later via *structured* engine
  score-term data, not by parsing `evidence[]` strings.
- Structured export to UI (STIX/CSV), multi-capture diff, SNI-domain reputation —
  separate initiatives from the "what's next" survey.

## File manifest

**Create:** `ui/src/components/transparency/{ProviderVerdictList,EvidenceList,ScoreBadge,FindingMetrics}.tsx` + co-located `.test.tsx`.
**Modify:** `ui/src/cockpit/ReputationChip.tsx`, `ui/src/cockpit/ThreatRail.tsx`, `ui/src/cockpit/DetailFlyout.tsx`, `ui/src/components/triage/ThreatsPanel.tsx`, `ui/src/components/triage/IncidentsPanel.tsx` (+ their tests).
**No engine, WASM, Tauri, or `types.ts` changes.**
