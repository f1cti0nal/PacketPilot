# Incident-correlate rule matches — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-23
**Branch:** `feat/correlate-rule-matches`

## Goal

Make imported-rule (`RuleMatch`) matches appear in the **incident** view — the kill-chain incident hero/flyout in the UI and the incidents section of the HTML report — not just as standalone findings. Today the rule findings are folded into `summary.findings` *after* `correlate_incidents` already ran (during `analyze`), so they never reach `summary.incidents`.

## Architecture

A shared engine helper, `detect::fold_rule_findings`, folds the rule findings **and re-correlates incidents** (`correlate_incidents` is a pure, re-runnable `pub` function). It replaces the inline two-line fold the three rule-apply surfaces (WASM / Tauri / CLI) currently do. Re-correlation rebuilds `summary.incidents` from the full `summary.findings` (now including the rule matches), so each rule match joins its actor host's incident. The UI incident surfaces and the report's incidents section consume `summary.incidents`/`summary.findings` and update **automatically** — no UI/report change.

**Tech stack:** Rust (ppcap-core, ppcap-wasm, src-tauri, ppcap-cli). No new deps.

## Global Constraints

- **No new deps.** C-free + wasm-safe preserved (`fold_rule_findings`/`correlate_incidents` are pure compute in ppcap-core; ppcap-wasm includes it).
- **One source of truth** — the three surfaces call the same `fold_rule_findings`; the fold semantics (card uplift + findings append + re-correlate) live in one place.
- **No stacking** — the UI re-load already applies over the per-capture base snapshot (`pickRuleBase`), and re-correlation is deterministic over the fold result, so re-loading a different ruleset reproduces a clean incident set. `correlate_incidents` is pure (no I/O / no order dependence beyond its internal sort).
- **`analyze` is unchanged** — `summary.findings` is exactly the input `correlate_incidents` used at `analyze/mod.rs:328-329`, so re-correlating reproduces the original incidents **plus** the rule matches (no regression to the non-rules path).

## Reference: the seams (verified)

```
// engine/crates/ppcap-core/src/detect/mod.rs:1478 pub fn correlate_incidents(findings: &[Finding]) -> Vec<Incident>  (pure; groups by src_ip → incidents) ; :674 use model::finding::{Finding, FindingKind}
// engine/crates/ppcap-core/src/model/summary.rs Summary { findings: Vec<Finding>, incidents: Vec<Incident>, ip_threats, … } + pub fn apply_findings(&mut self, &[Finding]) (raise-only card uplift)
// engine/crates/ppcap-core/src/analyze/mod.rs:328 summary.incidents = correlate_incidents(&findings); :329 summary.findings = findings;  ← summary.findings == the correlate input (UNCHANGED)
// the 3 inline folds to REPLACE (each: apply_findings(&rf); findings.extend(rf.iter().cloned());):
//   engine/crates/ppcap-wasm/src/lib.rs:422-423 (apply_rules)
//   ui/src-tauri/src/lib.rs:164-165 (apply_rules_to)
//   engine/crates/ppcap-cli/src/cli.rs:258-259 (--rules)
// ppcap-core/lib.rs re-exports apply_rules/parse_rules/etc — add fold_rule_findings
```

## Components

### 1. `engine/crates/ppcap-core/src/detect/mod.rs` — `fold_rule_findings`
```rust
/// Fold post-hoc rule-match findings into a built `Summary`: uplift the implicated IP threat
/// cards, append the findings, and **re-correlate incidents** so the matches join their host's
/// incident (the kill-chain view). Re-running `correlate_incidents` over `summary.findings`
/// reproduces the original incidents plus the rule matches.
pub fn fold_rule_findings(summary: &mut Summary, rule_findings: &[Finding]) {
    summary.apply_findings(rule_findings);
    summary.findings.extend_from_slice(rule_findings);
    summary.incidents = correlate_incidents(&summary.findings);
}
```
(Add `use crate::model::summary::Summary;` if not already imported. `Finding` is `Clone` → `extend_from_slice` is fine.)
Re-export from `ppcap-core/lib.rs` alongside the other rule exports: `pub use detect::fold_rule_findings;`.

### 2. The three rule-apply surfaces
Replace the inline `out.summary.apply_findings(&rf); out.summary.findings.extend(rf.iter().cloned());` with `ppcap_core::fold_rule_findings(&mut out.summary, &rf);` in:
- `engine/crates/ppcap-wasm/src/lib.rs` (`apply_rules`)
- `ui/src-tauri/src/lib.rs` (`apply_rules_to`)
- `engine/crates/ppcap-cli/src/cli.rs` (`--rules` block)

## Data flow & error handling

`apply_rules` (any surface) → `fold_rule_findings(&mut summary, &rule_findings)` → card uplift + findings append + `summary.incidents = correlate_incidents(&summary.findings)` → the updated `AnalysisOutput` flows through the existing JSON / UI (`setSummary` re-renders the incident hero/flyout) / report (`incidents_html`). No new failure modes (`correlate_incidents` is infallible). No new data fetched.

## Testing

- **`fold_rule_findings` (ppcap-core):**
  - a `Summary` with one detector finding (e.g. a beacon on host `10.0.0.5`) already correlated into one incident → fold a `RuleMatch` on the **same** src host → `summary.incidents` for `10.0.0.5` now contains a `RuleMatch` in its findings (assert the incident's findings include `FindingKind::RuleMatch`).
  - fold a `RuleMatch` on a **new** src host (no detector findings) → a new incident for that host appears in `summary.incidents`.
  - the IP threat card for the host is uplifted (apply_findings still runs) — reuse the existing apply_findings test pattern.
  - idempotence-ish: folding the same rule set twice over the same base would double the findings (callers don't do this — the UI uses the base snapshot), but assert a single fold yields the expected incident set.
- **Cross-surface (CLI):** `ppcap analyze --rules <file>` over a pcap whose payload matches a rule → the JSON `summary.incidents` includes the rule match (or extend the existing CLI rules test).
- **Gate:** `cargo test -p ppcap-core -p ppcap-cli` green; clippy `-D warnings`; C-free gate empty; `cd ui/src-tauri && cargo check` (the Tauri call-site compiles); `cd engine/crates/ppcap-wasm && cargo build --target x86_64-pc-windows-gnu`.

## Out of scope

Changing `correlate_incidents`'s grouping/narrative logic or the `Incident` model; per-flow matched-bytes; the full Suricata DSL; any UI/report code (they consume `incidents`/`findings` and update automatically — confirm via the existing UI/report tests still passing, no new UI work). The `Summary::apply_findings` evidence-cap semantics are unchanged.

## File manifest

**Engine — modify:** `engine/crates/ppcap-core/src/detect/mod.rs` (`fold_rule_findings` + test), `engine/crates/ppcap-core/src/lib.rs` (re-export), `engine/crates/ppcap-wasm/src/lib.rs` + `engine/crates/ppcap-cli/src/cli.rs` (call-site swaps), `ui/src-tauri/src/lib.rs` (call-site swap).
**No new deps; no UI/report code change.**
