# PacketPilot — Case-Level Alert Queue

**Implementation Plan**

| | |
|---|---|
| **Status** | Proposed — ready to implement |
| **Feature branch** | `claude/smart-alerting-context-t78kzq` (stacked after Smart Alerting + Evidence Custody; PR #149) |
| **Date** | 2026-07-23 |
| **Scope** | Engine (Rust: `case/` fold + `CaseAlert` rows in `case.json`) · Report (`case.html` queue section) · CLI (batch stderr one-liner) · Docs (batch-triage.md) · **No UI / no WASM changes** (batch is CLI-first) |

> **How this plan was produced.** Single-pass design continuing this session's pipeline: the
> Smart Alerting plan (§16) names "case-level queue" as its follow-up, and the repo's market
> research (docs/market-research/2026-07-11 §1.1) ranks cross-capture work as the top validated
> workflow gap. Grounded in firsthand reads of `case/mod.rs` (`run_case` loop :298-390, ranking
> :394-426, `SharedIndicator` build :404-426), `report::case_html` (:1293), and the batch CLI
> tail (`dispatch_batch`).

---

## 1. Summary & Goals

**What ships.** **Case-Level Alert Queue (CAQ)**: `analyze --batch <dir>` already derives a
Smart Alerting queue *per capture* (the analyze seam runs inside `run_case`'s per-capture
`run()`); this feature fuses them into **one ranked, case-wide queue** in `case.json` and
`case.html`. The merge key is the alert id itself — SAC ids are **stable by construction**
(`host:<ip>`, `chain:<host-set-hash>`, `rollup:<kind>` hash identically in every capture) — so
the same story recurring across captures collapses into one `CaseAlert` row carrying its
capture list, a summed finding count, and a **bounded recurrence uplift** (cross-capture
persistence is corroboration, the same doctrine as `shared_indicators`' ≥2-captures gate).
A folder of 30 sandbox pcaps stops being 30 queues: it becomes one list answering *"what do I
look at first across the whole case."*

| Today | With CAQ |
|---|---|
| Batch ranks *captures* and lists shared *indicators*; alert queues stay siloed per capture | One case-wide queue: the same story merged across captures, worst-first |
| A beacon host recurring in 6 captures looks like 6 separate per-capture rows | One row: "seen in 6 captures", recurrence-uplifted, top of the case queue |
| Recurrence carries no rank weight | `+5`/extra capture, capped `+15` — visible as a `ScoreTerm`, mirroring the corroboration-cap doctrine |

**Non-goals.** No re-derivation or cross-capture re-correlation (pure fold over per-capture
queues — bounded memory stays one-capture); no case-level coverage invariant (the per-capture
queues in `captures/<id>.json` remain the receipts; `total_case_alerts` makes truncation
visible); no UI (the case dashboard remains the known batch follow-up); no change to
`shared_indicators` (complementary: indicators correlate *values*, the queue correlates
*stories*).

## 2. Data Model (`case/mod.rs`)

```rust
/// One row of the case-wide alert queue: the same story (stable Alert id) merged across
/// every capture it appeared in. Representative fields come from the worst member.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CaseAlert {
    pub id: String,                 // the shared per-capture Alert.id
    pub source: AlertSource,
    pub band: PriorityBand,         // of the fused priority
    /// clamp(max member priority + min(5·(captures−1), 15), 0, 100)
    pub priority: u16,
    pub severity: Severity,         // max across members
    pub confidence: u8,             // max across members
    pub title: String,              // worst member's
    pub action: String,             // worst member's
    pub actor: String,              // worst member's
    /// Sorted capture_ids this story appeared in (>= 1).
    pub captures: Vec<String>,
    pub capture_count: u32,
    pub finding_count: u64,         // summed member finding_count
    /// "base: worst per-capture alert priority" + "recurring: seen in N captures" (+cap/clamp
    /// terms when binding) — Σ terms == priority, the SAC ledger discipline.
    pub priority_terms: Vec<ScoreTerm>,
    pub first_seen_ns: Option<i64>, // min across members (ns since epoch — comparable)
    pub last_seen_ns: Option<i64>,  // max across members
}
```

`CaseSummary` gains `#[serde(default)] pub case_alerts: Vec<CaseAlert>` (ranked, capped
`MAX_CASE_ALERTS = 64`) and `#[serde(default)] pub total_case_alerts: u64` (pre-truncation
count — truncation is never silent). `schema_version` stays 1 (additive-default, the house
evolution). Constants: `PTS_CASE_RECURRENCE = 5`, `CASE_RECURRENCE_CAP = 15`,
`MAX_CASE_ALERTS = 64`.

## 3. Semantics & Wiring

- **Fold** (inside the `run_case` per-capture loop, beside the indicator fold at :341): for
  each `out.summary.alerts` entry, merge into `BTreeMap<id, Draft>` — representative fields
  replaced when the member's priority is strictly higher (ties: first capture in
  discovery order wins — deterministic), severity/confidence maxed, finding_count summed,
  first/last min/maxed, capture id recorded. One capture in memory at a time; drafts are
  bounded (≤ soft-capped queue per capture × captures, compact rows).
- **Finish** (beside the shared-indicator build): recurrence uplift with a materialized term
  when ≥2 captures; final clamp term when binding (Σ terms == priority, test-enforced). Sort
  `(priority desc, severity desc, capture_count desc, id asc)` — strict total order; truncate
  to `MAX_CASE_ALERTS`, `total_case_alerts` records the pre-truncation count.
- **Report**: `case_html` gains a "Case alert queue" card between the header tiles and the
  captures table — band chip (severity palette), priority/conf, title, "seen in N captures",
  action line, ledger; omitted when empty. Header tiles gain an "Alerts" tile. All strings
  through `esc()`.
- **CLI**: batch stderr one-liner after the case write:
  `case alerts: 7 across 30 captures — 1 act-now, 2 investigate; top: "…"` (quiet-gated).
- Errored captures contribute nothing (their entries already carry the error).

## 4. Testing (named)

In `tests/case_triage.rs` (existing harness — `build_case_dir` generates beacon/webonly/
portscan captures): `case_alerts_merge_recurring_story_across_captures` (two same-seed beacon
captures ⇒ one CaseAlert with `capture_count == 2`, the recurrence term, and priority >
either member's), `case_alert_ledger_reconciles` (Σ terms == priority on every row),
`case_alerts_rank_worst_first_and_are_deterministic` (two runs byte-identical),
`old_case_json_without_case_alerts_still_parses` (serde default). In `report` tests:
`case_html_renders_alert_queue_section` / omits-when-empty.

## 5. Invariants & Checklist

Bounded (compact rows, hard cap, visible truncation) · deterministic (BTree fold, strict sort,
no clock) · pure fold (no re-analysis, no network) · additive serde (`case.json` back-compat)
· `shared_indicators`/capture ranking untouched.

| File | Change |
|---|---|
| `engine/crates/ppcap-core/src/case/mod.rs` | `CaseAlert` + fold + finish + constants |
| `engine/crates/ppcap-core/src/report/mod.rs` | `case_alerts_html` card in `case_html` |
| `engine/crates/ppcap-core/src/lib.rs` | re-export `CaseAlert` |
| `engine/crates/ppcap-cli/src/cli.rs` | batch one-liner |
| `engine/crates/ppcap-core/tests/case_triage.rs` | the named tests |
| `docs/batch-triage.md` | "Case alert queue" section |
| **NOT touched** | per-capture pipeline, `summary.alerts`, UI, wasm, Parquet/SQL schemas |

**Follow-ups:** case-level evidence bundle (ECC §10), desktop case dashboard surfacing this
queue, cross-capture flow stitching (batch-triage's own follow-up list).
