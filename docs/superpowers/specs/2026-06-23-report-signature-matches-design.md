# Rule matches in the HTML report — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-23
**Branch:** `feat/report-signature-matches`

## Goal

Surface imported-rule matches in the engine's HTML triage report. Rule import (engine/CLI + in-app) folds `RuleMatch` findings into `summary.findings`, but the HTML report only renders findings via the **incidents** section — and `RuleMatch` findings are not incident-correlated (they append after `correlate_incidents`), so a `ppcap analyze --rules …` run produces matches that appear in the JSON and the UI panel but **never in the HTML report**. This adds a "Signature matches" report section, parallel to the UI panel.

## Architecture

Engine-only (`report/mod.rs`). A new `signature_matches_html(&sum.findings)` helper renders the `RuleMatch` findings as a `<section class="card">` and `render_html` inserts it right after the active-incidents section. The section is **omitted when there are no rule matches** (like every other conditional section). Reuses the existing `esc` (HTML-escape), `kind_label`, and the card/table styling. No new deps; pure compute (stays C-free + wasm-safe — `report` lives in ppcap-core).

**Tech stack:** Rust (ppcap-core). No new deps.

## Global Constraints

- **No new deps.** C-free gate stays empty; `report` is pure compute (wasm-safe — ppcap-wasm includes ppcap-core).
- **Omitted when empty** — `signature_matches_html` returns `""` when there are no `RuleMatch` findings, so the report is unchanged for captures with no rules applied (every existing report test must still pass).
- **HTML-escape all dynamic text** via the existing `esc` (msg, IPs, MITRE ids, sid) — no injection from rule msg/content.
- **Defensive sid parse** — scan `evidence` for `sid:N`; omit the sid cell if absent (never panic).
- Run cargo from `engine/`; `cargo fmt` before commit.

## Reference: the seams (verified)

```
// engine/crates/ppcap-core/src/report/mod.rs:42 pub fn render_html(…) -> String — builds <section class="card"> blocks
//   :156 s.push_str(&incidents_html(&sum.incidents));  ← INSERT the new section right after this
//   :164-206 the "Top threats" <table> (the table markup pattern to mirror: <h2>/<table><thead>…<tbody>…)
//   esc(...) HTML-escape helper (used throughout) ; kind_label(FindingKind) (:412, RuleMatch→"Signature Match")
// engine/crates/ppcap-core/src/model/finding.rs Finding { kind: FindingKind, severity, title, src_ip, dst_ip: Option<String>, dst_port: Option<u16>, attack: Vec<String>, evidence: Vec<String> }
//   FindingKind::RuleMatch ; rule_finding evidence[0] = "rule sid:{sid}"
// sum.findings : Vec<Finding> is in scope in render_html (sum is the Summary)
```

## Components

### 1. `signature_matches_html(findings: &[Finding]) -> String` (new, in `report/mod.rs`)
```rust
fn signature_matches_html(findings: &[Finding]) -> String {
    let matches: Vec<&Finding> = findings.iter().filter(|f| f.kind == FindingKind::RuleMatch).collect();
    if matches.is_empty() {
        return String::new();
    }
    // <section class="card"><h2>Signature matches</h2><table><thead>…</thead><tbody>… (one <tr> per match, top 50) </tbody></table></section>
    // Columns: Rule (msg / title), SID, Source → Destination (src_ip → dst_ip:dst_port), ATT&CK (attack joined), Severity.
    // Every cell HTML-escaped via esc(). SID via sid_of(f) (omit the cell content if None). dst omitted gracefully when None.
}
fn sid_of(f: &Finding) -> Option<&str> {
    // scan f.evidence for an entry containing "sid:" → return the trailing digits substring (defensive; None if absent).
}
```
- Cap the rendered rows at the first 50 (mirroring the other tables' `take(25)`-style caps — pick 50; note any truncation is acceptable for a report).
- Severity rendered as its label (reuse whatever the Top-threats / incidents tables use for a severity cell — a class or `Severity::as_str()`).

### 2. `render_html` (insert)
After `s.push_str(&incidents_html(&sum.incidents));` (:156): `s.push_str(&signature_matches_html(&sum.findings));`.

## Data flow & error handling

`render_html` → `signature_matches_html(&sum.findings)` → filter `RuleMatch` → (empty → `""`, section omitted) → else a card table. `sid_of` is a defensive scan (no panic; omits the cell if absent). `dst_ip`/`dst_port` are `Option` → rendered as `src → —` / `src → dst` / `src → dst:port` gracefully. All dynamic text escaped. No new data fetched.

## Testing

- **`report` test:** `render_html` over a summary whose `findings` includes a `RuleMatch` (title "C2 beacon", evidence `["rule sid:1001"]`, attack `["T1071"]`, src `10.0.0.5`, dst `203.0.113.9:443`) → the returned HTML `contains` `"Signature matches"`, the escaped msg, `1001`, `10.0.0.5`, `203.0.113.9`, and `T1071`. A summary with NO `RuleMatch` findings → the HTML does NOT contain `"Signature matches"` (section omitted). A `RuleMatch` whose evidence lacks a sid → renders without a panic (no sid cell content).
- **Existing report tests** unchanged/passing (the section is omitted for their fixtures).
- **Gate:** `cargo test -p ppcap-core` green; clippy `-D warnings` clean; C-free gate empty; `cd engine/crates/ppcap-wasm && cargo build --target x86_64-pc-windows-gnu` builds.

## Out of scope

Incident-correlating rule matches (the deeper engine change — deferred to rule-import phase C); rule matches in CSV/STIX/MISP/CEF exporters (those already iterate `summary.findings`, so matches ride along — no change); the AI exec summary; any UI/WASM/Tauri/CLI change (the CLI already writes the HTML via `--html`).

## File manifest

**Engine — modify:** `engine/crates/ppcap-core/src/report/mod.rs` (the `signature_matches_html` + `sid_of` helpers + the `render_html` insertion + a test).
**No new deps; no UI/WASM-export/Tauri/CLI change.**
