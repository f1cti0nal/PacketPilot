# Structured score-terms — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The engine emits typed `Vec<ScoreTerm>` alongside the evidence strings; `IpThreat.score_terms` carries them; the UI `ScoreWaterfall` reads the typed field (fallback to `parseScoreTerms`).

**Architecture:** A DRY `add_term` helper in the scorer single-sources points (typed term + byte-identical evidence string). Threads through stats → `IpThreat.score_terms`. UI prefers typed; keeps the parse as fallback.

**Tech Stack:** Rust (ppcap-core) + React/TS. No new deps.

## Global Constraints

- **No new deps.** C-free + wasm-safe. `#[serde(default)]` on `IpThreat.score_terms` (old JSON → empty).
- **Byte-identical evidence** — the existing `score` tests assert exact evidence strings; they MUST pass unchanged. `format!("{label} ({points:+})")` reproduces every current additive string (`{:+}` → `+45`/`-10`/`+0`).
- **`parseScoreTerms` kept** as the UI fallback (not deleted).
- `ScoreTerm` lives in the **model** (`score` and `model::IpThreat` both use it; `model` must not depend on `score`).
- Run cargo from `engine/`; `cargo fmt`. UI: vitest 1.6.1, 80/70, `build:wasm`, tsc.

## Reference: the seams (verbatim, verified)

```
// score/mod.rs:55 ScoredFlow { severity, score:u16, evidence:Vec<String>, attack } ; the additive sites :75-148 `acc += PTS_*; evidence.push("… (+N)")` ; clamp :147 + floors :157/:163 stay raw ; the ScoredFlow{…} literal ~:169
// stats/mod.rs:121 per-IP row field `evidence: Vec<String>` (add `terms`) ; :336 worst-flow reseed `e.evidence.clear(); copy sc.evidence` (add `e.terms = sc.terms.clone();` HERE only) ; :346-349 the evidence top-up (do NOT touch terms there) ; :549-561 IpThreat{ …, evidence: s.evidence.clone(), … } (add `score_terms: s.terms.clone()`)
// model/summary.rs IpThreat { …, evidence, #[serde(default)] reputation, #[serde(default)] fingerprints } ← add `#[serde(default)] score_terms: Vec<ScoreTerm>` + define `ScoreTerm`
// ui/src/lib/scoreTerms.ts:2 interface ScoreTerm{label,points} ; parseScoreTerms(evidence)->{terms,notes}
// ui/src/components/transparency/ScoreWaterfall.tsx:16 const {terms,notes}=parseScoreTerms(evidence) ; ui/src/types.ts IpThreat ; ui/src/cockpit/DetailFlyout.tsx scoreEvidence prop ; ui/src/components/Dashboard.tsx the <DetailFlyout scoreEvidence=… hostScore=…> render (add scoreTerms)
```

---

### Task 1: `model::ScoreTerm` + `score::ScoredFlow.terms` + `add_term` refactor

**Files:**
- Modify: `engine/crates/ppcap-core/src/model/summary.rs` (`ScoreTerm`), `engine/crates/ppcap-core/src/score/mod.rs`

**Interfaces:**
- Produces: `ScoreTerm { label, points }`; `ScoredFlow.terms: Vec<ScoreTerm>`.

- [ ] **Step 1: Define `ScoreTerm`** — in `model/summary.rs` (next to `IpThreat`):
```rust
/// One additive scoring contribution (label + signed points). Mirrors the `(±N)` evidence string.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScoreTerm {
    pub label: String,
    pub points: i32,
}
```

- [ ] **Step 2: Write the failing test** — in `score/mod.rs` `#[cfg(test)]`:
```rust
#[test]
fn score_flow_emits_typed_terms_matching_evidence() {
    // build a FlowRecord + FeedMatch that hits category + external (mirror an existing score test fixture)
    let sc = score_flow(&rec, &fm);
    // additive terms are typed:
    assert!(sc.terms.iter().any(|t| t.label == "category c2" && t.points == 45));
    // and every term has a byte-identical evidence string:
    for t in &sc.terms {
        let expected = format!("{} ({:+})", t.label, t.points);
        assert!(sc.evidence.contains(&expected), "missing evidence for term {t:?}");
    }
    // clamp/floor are NOT terms (they stay evidence-only):
    assert!(!sc.terms.iter().any(|t| t.label.starts_with("clamp") || t.label.starts_with("floor")));
}
```
> NOTE: reuse the exact `FlowRecord`/`FeedMatch` construction from an existing `score_flow` test (grep the `#[cfg(test)]` block); pick a flow that triggers a known additive term (e.g. C2 category).

- [ ] **Step 3: Run to verify it fails** — `cd engine && cargo test -p ppcap-core score_flow_emits_typed_terms` → FAIL.

- [ ] **Step 4: Implement** — `score/mod.rs`:
  - `use crate::model::summary::ScoreTerm;`. `ScoredFlow` gains `pub terms: Vec<ScoreTerm>`.
  - In `score_flow`, add `let mut terms: Vec<ScoreTerm> = Vec::new();` next to `evidence`. Add a helper:
```rust
fn add_term(acc: &mut i32, evidence: &mut Vec<String>, terms: &mut Vec<ScoreTerm>, label: impl Into<String>, points: i32) {
    let label = label.into();
    *acc += points;
    terms.push(ScoreTerm { label: label.clone(), points });
    evidence.push(format!("{label} ({points:+})"));
}
```
  - Replace EACH additive site. E.g. `acc += PTS_C2; evidence.push("category c2 (+45)".to_string());` → `add_term(&mut acc, &mut evidence, &mut terms, "category c2", PTS_C2);` (confirm `PTS_C2 == 45` so the string is identical). The generic category: `add_term(&mut acc, &mut evidence, &mut terms, format!("category {}", rec.category.as_str()), PTS_OTHER);`. Do this for category (all arms incl. `(+0)`), ioc (+35 ×3), external (+15) / all-internal (-10), behavior (+10 ×2) — every `acc += …; evidence.push("… (+N)")` pair.
  - **Leave the clamp (:147) and the two floor pushes (:157/:163) as raw `evidence.push`** (no `add_term`).
  - Add `terms,` to the returned `ScoredFlow { … }` literal.

- [ ] **Step 5: Run to verify it passes** — `cd engine && cargo test -p ppcap-core score` → PASS — **the NEW test AND every existing `score` test (the evidence-string assertions are byte-identical)**. `cargo fmt`; `cargo clippy -p ppcap-core --all-targets -- -D warnings` → clean.

- [ ] **Step 6: Commit**
```bash
git add engine/crates/ppcap-core/src/model/summary.rs engine/crates/ppcap-core/src/score/mod.rs
git commit -m "feat(score): typed ScoreTerm emitted alongside byte-identical evidence"
```

---

### Task 2: `IpThreat.score_terms` + stats threading

**Files:**
- Modify: `engine/crates/ppcap-core/src/model/summary.rs` (`IpThreat.score_terms`), `engine/crates/ppcap-core/src/stats/mod.rs`

**Interfaces:**
- Consumes: `ScoreTerm` (T1), `ScoredFlow.terms` (T1).

- [ ] **Step 1: Add the field** — `model/summary.rs` `IpThreat`: after `fingerprints`, `#[serde(default)] pub score_terms: Vec<ScoreTerm>,`.

- [ ] **Step 2: Write the failing tests** — in `stats/mod.rs` `#[cfg(test)]` (mirror an existing accumulator test that builds a worst flow + finishes):
```rust
#[test]
fn ip_threat_carries_worst_flow_score_terms() {
    // observe a flow whose ScoredFlow has additive terms (e.g. a C2 flow) for some IP, finish:
    let sum = /* accumulate + finish, mirroring an existing stats test */;
    let card = sum.ip_threats.iter().find(|c| c.ip == "<the ip>").unwrap();
    assert!(card.score_terms.iter().any(|t| t.label == "category c2" && t.points == 45));
}
```
And a model serde-default test (in model/summary.rs or stats):
```rust
#[test]
fn ip_threat_score_terms_defaults_empty_on_old_json() {
    let json = r#"{"ip":"203.0.113.7","ip_class":"public","severity":"low","score":20,"flows":3,"bytes":1000,"ioc":false,"tags":["public"],"attack":[],"evidence":[]}"#;
    let row: IpThreat = serde_json::from_str(json).unwrap();
    assert!(row.score_terms.is_empty());
}
```

- [ ] **Step 3: Run to verify they fail** — `cd engine && cargo test -p ppcap-core score_terms` → FAIL.

- [ ] **Step 4: Implement** — `stats/mod.rs`:
  - The per-IP row struct (~:121, with `evidence`): add `terms: Vec<ScoreTerm>,` (import `ScoreTerm`). Default empty in the row's constructor/`Default`.
  - In the **worst-flow reseed branch** (~:336, the `if f.severity > e.max_sev …` block, right after `e.evidence.clear()`): add `e.terms = sc.terms.clone();`. **Do NOT** touch `terms` in the top-up loop (:346-349) — the terms reflect ONLY the worst flow (so they reconcile with the reported score).
  - In the `IpThreat { … }` build in `finish` (~:549-561): add `score_terms: s.terms.clone(),`.

- [ ] **Step 5: Run to verify they pass** — `cd engine && cargo test -p ppcap-core` → PASS (the new tests + all existing). `cargo fmt`; clippy clean.

- [ ] **Step 6: Commit**
```bash
git add engine/crates/ppcap-core/src/model/summary.rs engine/crates/ppcap-core/src/stats/mod.rs
git commit -m "feat(stats): carry the worst-flow score_terms onto IpThreat"
```

---

### Task 3: UI — `score_terms` type + `ScoreWaterfall` prefers typed (+ full gate)

**Files:**
- Modify: `ui/src/types.ts`, `ui/src/components/transparency/ScoreWaterfall.tsx`, `ui/src/cockpit/DetailFlyout.tsx`, `ui/src/components/Dashboard.tsx`
- Test: `ui/src/components/transparency/ScoreWaterfall.test.tsx`

**Interfaces:**
- Consumes: `IpThreat.score_terms` (T2).

- [ ] **Step 1: Add the type** — `ui/src/types.ts`: `IpThreat` gains `score_terms?: ScoreTerm[]` (import/define `ScoreTerm { label: string; points: number }` — reuse the shape from `lib/scoreTerms.ts` or re-declare in types.ts and have scoreTerms.ts import it; pick one source).

- [ ] **Step 2: Write the failing test** — extend `ScoreWaterfall.test.tsx`:
```tsx
it("prefers typed scoreTerms over parsing the evidence strings", () => {
  // scoreTerms present → those bars render; the evidence has DIFFERENT (±N) so we can tell which was used
  render(<ScoreWaterfall evidence={["category c2 (+99)", "clamp: raw 105 -> 100"]} scoreTerms={[{ label: "category c2", points: 45 }]} score={100} severity="critical" />);
  expect(screen.getByText("category c2")).toBeInTheDocument();
  expect(screen.getByText(/\+45/)).toBeInTheDocument();      // from the typed term
  expect(screen.queryByText(/\+99/)).toBeNull();             // NOT parsed from evidence
  expect(screen.getByText(/clamp: raw 105/)).toBeInTheDocument(); // notes still from evidence
});
it("falls back to parsing evidence when scoreTerms is absent/empty", () => {
  render(<ScoreWaterfall evidence={["category c2 (+45)"]} score={45} severity="high" />);
  expect(screen.getByText(/\+45/)).toBeInTheDocument();      // parsed
});
```
(Keep the existing ScoreWaterfall tests unchanged — they pass no `scoreTerms` → the fallback path, still green.)

- [ ] **Step 3: Run to verify it fails** — `cd ui && npx vitest run src/components/transparency/ScoreWaterfall.test.tsx` → FAIL.

- [ ] **Step 4: Implement** —
  - `ScoreWaterfall.tsx`: add `scoreTerms?: ScoreTerm[]` to the props; 
    ```tsx
    const { terms, notes } = scoreTerms && scoreTerms.length
      ? { terms: scoreTerms, notes: parseScoreTerms(evidence).notes }
      : parseScoreTerms(evidence);
    ```
  - `DetailFlyout.tsx`: add a `scoreTerms?: ScoreTerm[]` prop; pass it to `<ScoreWaterfall … scoreTerms={scoreTerms} />`.
  - `Dashboard.tsx`: at the `<DetailFlyout … scoreEvidence={…} hostScore={…}>` render, add `scoreTerms={selectedIncident ? threatByHost.get(selectedIncident.host)?.score_terms : undefined}` (mirroring the existing `scoreEvidence` lookup).

- [ ] **Step 5: Run to verify it passes** — `cd ui && npx vitest run src/components/transparency/ScoreWaterfall.test.tsx src/components/Dashboard.test.tsx src/cockpit/DetailFlyout.test.tsx` → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 6: Commit**
```bash
git add ui/src/types.ts ui/src/components/transparency/ScoreWaterfall.tsx ui/src/cockpit/DetailFlyout.tsx ui/src/components/Dashboard.tsx ui/src/components/transparency/ScoreWaterfall.test.tsx
git commit -m "feat(ui): ScoreWaterfall prefers typed score_terms (falls back to parse)"
```

- [ ] **Step 7: Full gate** — engine: `cd engine && export PATH="/c/Users/ravid/.cargo/bin:$PATH"; cargo fmt --all -- --check; cargo clippy -p ppcap-core --all-targets -- -D warnings; cargo test -p ppcap-core 2>&1 | tail -6; cargo tree -p ppcap-core -e no-dev | grep -Ei "zstd-sys|lz4-sys|cc |cmake|bzip2-sys|openssl-sys|zlib-sys" || echo "C-FREE OK"; cd crates/ppcap-wasm && cargo build --target x86_64-pc-windows-gnu 2>&1 | tail -2`. UI: `cd ui && export PATH="/c/Program Files/nodejs:/c/Users/ravid/.cargo/bin:$PATH"; git checkout -- package.json package-lock.json 2>/dev/null; npm ci; npm run build:wasm; npm run build; echo "build EXIT: $?"; npm run test:coverage; echo "cov EXIT: $?"` (≥80/70). Do NOT `npm install`.

- [ ] **Step 8: Commit** any gate fixups.

---

## Self-Review

**1. Spec coverage:** `ScoreTerm` + `add_term` refactor (T1) → spec §1-2; `IpThreat.score_terms` + stats (T2) → §3; UI type + `ScoreWaterfall` prefer-typed + flyout/Dashboard (T3) → §4-5 + gate. Byte-identical evidence, serde-default, parse-fallback, worst-flow-only terms — all covered. Columnar terms + clamp/floor-as-typed out of scope. ✓

**2. Placeholder scan:** complete code for `ScoreTerm`, `add_term`, the stats threading, the UI prefer-typed; the NOTEs (reuse existing score/stats fixtures; confirm `PTS_C2==45`; one ScoreTerm source) are concrete in-repo verifications. ✓

**3. Type consistency:** `ScoreTerm{label:String,points:i32}` (model) ⇄ `ScoredFlow.terms` (T1) ⇄ stats row `terms` + `IpThreat.score_terms` (T2) ⇄ TS `ScoreTerm{label,points}` + `IpThreat.score_terms?` (T3) ⇄ `ScoreWaterfall scoreTerms?` ⇄ `parseScoreTerms` fallback returns the same `{label,points}` shape. ✓
