# Structured score-terms — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-23
**Branch:** `feat/structured-score-terms`

## Goal

Replace the UI's brittle `(±N)` string-parsing in the score waterfall with engine-emitted **typed** score terms, single-sourcing the points. The transparency-layer memo's preferred shape: the engine already knows each term's `(label, points)`; emit them typed instead of re-deriving them from formatted strings in the browser.

## Architecture

The scorer emits a typed `Vec<ScoreTerm>` alongside the existing evidence strings, via a DRY helper that keeps them in sync. The terms thread through the per-host aggregation onto `IpThreat.score_terms`; the UI `ScoreWaterfall` reads the typed field, **falling back to `parseScoreTerms` for older summaries**. The evidence strings stay **byte-identical** (the helper formats `"{label} ({:+})"`, which reproduces today's `"category c2 (+45)"` / `"all-internal peers (-10)"`), so the HTML report, the AI context, and the clamp/floor notes are untouched.

`ScoreTerm` lives in the **model** (`model`), so both `score::ScoredFlow` and `model::IpThreat` use it without a layering violation (`score` already depends on `model`; `model` must not depend on `score`).

**Tech stack:** Rust (ppcap-core) + React/TS. No new deps.

## Global Constraints

- **No new deps.** C-free + wasm-safe preserved (pure compute). `serde(default)` on the new `IpThreat.score_terms` so old summary JSON still deserializes.
- **Byte-identical evidence** — the existing `score` tests assert exact evidence strings; they MUST pass unchanged. `format!("{label} ({:+})", points)` reproduces every current additive string.
- **`parseScoreTerms` is kept** (the UI fallback for summaries without `score_terms`), not deleted.
- Run cargo from `engine/`; `cargo fmt`. UI: vitest 1.6.1, 80/70, `build:wasm`, tsc.

## Reference: the seams (verified)

```
// score/mod.rs:55 pub struct ScoredFlow { severity, score: u16, evidence: Vec<String>, attack } ; :68 pub fn score_flow(rec, fm) -> ScoredFlow { acc:i32; evidence }
//   :75-148 the additive sites: `acc += PTS_*; evidence.push("… (+N)")` (category/ioc/external/behavior) ; the non-additive clamp/floor pushes (~:148/:157/:163) stay raw
//   PTS_* are i32 point consts. (category generic case uses format!("category {} (+10)", rec.category.as_str()).)
// stats/mod.rs:335-349 the per-IP reseed: on a new worst flow, e.evidence.clear() then copy sc.evidence (bounded max_evidence_per_ip=6, deduped) — ALSO reseed terms there
// model/summary.rs  IpThreat { …, evidence: Vec<String>, #[serde(default)] reputation, #[serde(default)] fingerprints } ← add #[serde(default)] score_terms: Vec<ScoreTerm> ; ScoreTerm defined here (or a model module)
// ui/src/lib/scoreTerms.ts:2 interface ScoreTerm { label: string; points: number } (already exists) ; parseScoreTerms(evidence) -> { terms, notes }
// ui/src/components/transparency/ScoreWaterfall.tsx:16 const { terms, notes } = parseScoreTerms(evidence) ← prefer scoreTerms when present
// ui/src/types.ts IpThreat (add score_terms?: ScoreTerm[]) ; ui/src/cockpit/DetailFlyout.tsx scoreEvidence prop (the waterfall input from the host IpThreat) — also pass scoreTerms
```

## Components

### 1. `model` — `ScoreTerm`
```rust
/// One additive scoring contribution (label + signed points). Mirrors the `(±N)` evidence string.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScoreTerm { pub label: String, pub points: i32 }
```
(In `model/summary.rs` next to `IpThreat`, or a small `model` location — keep it model-level.)

### 2. `score/mod.rs`
- `ScoredFlow` gains `pub terms: Vec<ScoreTerm>`.
- A helper (free fn or closure) `add_term(acc: &mut i32, evidence: &mut Vec<String>, terms: &mut Vec<ScoreTerm>, label: impl Into<String>, points: i32)`:
  ```rust
  let label = label.into();
  *acc += points;
  terms.push(ScoreTerm { label: label.clone(), points });
  evidence.push(format!("{label} ({points:+})"));
  ```
- Replace each additive site (`acc += PTS_C2; evidence.push("category c2 (+45)")`, etc.) with `add_term(&mut acc, &mut evidence, &mut terms, "category c2", PTS_C2)`. (Confirm `format!("{} ({:+})", "category c2", 45)` == `"category c2 (+45)"` — it does; `{:+}` on `0` → `"+0"`, on `-10` → `"-10"`.) The generic-category case: `add_term(&mut …, format!("category {}", rec.category.as_str()), PTS_*)`.
- The **clamp/floor** pushes (`evidence.push(format!("clamp: raw {acc} -> {score}"))`, the two `floor:` lines) stay as raw `evidence.push` — they are NOT additive terms. `terms` excludes them.
- Build the returned `ScoredFlow { …, evidence, terms, … }`.

### 3. `stats/mod.rs`
- The accumulator's per-IP row gains a `terms: Vec<ScoreTerm>` (bounded like evidence isn't necessary — terms are few; cap is optional). In the worst-flow reseed (the `e.evidence.clear()` + copy block ~:335), also `e.terms = sc.terms.clone();`.
- `IpThreat` (model/summary.rs): `#[serde(default)] pub score_terms: Vec<ScoreTerm>`. In `stats::finish()` where `IpThreat` is built from the per-IP row, set `score_terms: row.terms`.

### 4. `ui/src/types.ts`
`ScoreTerm { label: string; points: number }` (define or import from the lib's shape); add `score_terms?: ScoreTerm[]` to `IpThreat`.

### 5. `ui/src/components/transparency/ScoreWaterfall.tsx`
Add a `scoreTerms?: ScoreTerm[]` prop:
```tsx
const { terms, notes } = scoreTerms && scoreTerms.length
  ? { terms: scoreTerms, notes: parseScoreTerms(evidence).notes }
  : parseScoreTerms(evidence);
```
`DetailFlyout`/Dashboard pass the host's `IpThreat.score_terms` as `scoreTerms` (alongside the existing `scoreEvidence`/`hostScore`).

## Data flow & error handling

`score_flow` → `add_term` → `ScoredFlow.terms` (additive only) → worst-flow reseed → `IpThreat.score_terms` → summary JSON → `ScoreWaterfall` renders typed bars + the notes (still parsed from evidence). Old summaries (no `score_terms`) → `parseScoreTerms(evidence)` fallback. Evidence byte-identical → report/AI/notes unaffected. No new failure modes.

## Testing

- **`score`:** a unit test that `add_term` pushes the right `ScoreTerm` AND the byte-identical evidence string; `ScoredFlow.terms` for a C2+ioc+external flow == the additive terms (labels/points); the **existing** per-category/ioc/external/behavior/clamp/floor evidence-string assertions pass UNCHANGED (the byte-identical invariant).
- **`stats`/`model`:** a host's `IpThreat.score_terms` mirrors its worst flow's additive terms; an old-JSON `IpThreat` (no `score_terms`) deserializes to empty (serde default).
- **UI `ScoreWaterfall`:** with `scoreTerms` provided → renders those bars (the labels/signed points) without touching the evidence strings for terms; without `scoreTerms` → falls back to parsing evidence (the existing waterfall tests still pass); notes still render.
- **Gate:** engine `cargo test -p ppcap-core` + clippy `-D warnings` + C-free + ppcap-wasm build; UI vitest 1.6.1 80/70 + `build:wasm` + tsc + build.

## Out of scope

Per-flow score-terms in the flows table/columnar (Parquet); restructuring clamp/floor as typed (they stay notes); deleting `parseScoreTerms`; changing the scoring math or the evidence-string format.

## File manifest

**Engine — modify:** `engine/crates/ppcap-core/src/model/summary.rs` (`ScoreTerm` + `IpThreat.score_terms`), `engine/crates/ppcap-core/src/score/mod.rs` (`ScoredFlow.terms` + `add_term` + the additive-site refactor), `engine/crates/ppcap-core/src/stats/mod.rs` (carry terms → IpThreat).
**UI — modify:** `ui/src/types.ts` (`IpThreat.score_terms`), `ui/src/components/transparency/ScoreWaterfall.tsx` (prefer typed), `ui/src/cockpit/DetailFlyout.tsx` + `ui/src/components/Dashboard.tsx` (pass `scoreTerms`) + the co-located tests.
**No new deps.**
