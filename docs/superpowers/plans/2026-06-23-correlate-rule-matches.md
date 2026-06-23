# Incident-correlate rule matches — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `RuleMatch` findings join their host's incident — a shared `fold_rule_findings` re-correlates incidents after folding rule findings, used by the WASM/Tauri/CLI rule-apply surfaces.

**Architecture:** `detect::fold_rule_findings(summary, rule_findings)` does the card uplift + findings append + `correlate_incidents` re-run; the three surfaces call it instead of inlining the fold. Engine-only; UI/report update automatically.

**Tech Stack:** Rust (ppcap-core, ppcap-wasm, src-tauri, ppcap-cli). No new deps.

## Global Constraints

- **No new deps.** C-free + wasm-safe preserved (pure compute). `analyze` path unchanged.
- **One source of truth** — the three surfaces call the same `fold_rule_findings`.
- Run cargo from `engine/` (PATH `/c/Users/ravid/.cargo/bin`); Tauri `cargo check` needs MinGW on PATH; `cargo fmt` before commit.

## Reference: the seams (verbatim, verified)

```
// detect/mod.rs:1478 pub fn correlate_incidents(findings:&[Finding])->Vec<Incident> (pure) ; :674 use crate::model::finding::{Finding,FindingKind}
// model/summary.rs Summary { findings: Vec<Finding>, incidents: Vec<Incident>, ip_threats, … } ; pub fn apply_findings(&mut self, &[Finding])
// analyze/mod.rs:328 summary.incidents = correlate_incidents(&findings); :329 summary.findings = findings;  (UNCHANGED — summary.findings == correlate input)
// the 3 inline folds to REPLACE (each two lines: apply_findings(&rf); findings.extend(rf.iter().cloned());):
//   ppcap-wasm/src/lib.rs:422-423 (apply_rules) ; ui/src-tauri/src/lib.rs:164-165 (apply_rules_to) ; ppcap-cli/src/cli.rs:258-259 (--rules)
// ppcap-core/lib.rs — re-export fold_rule_findings (alongside apply_rules/parse_rules)
// detect/mod.rs has the existing #[cfg(test)] correlate_incidents tests (mirror their Finding fixtures) + the apply_findings_uplifts tests in stats/summary
```

---

### Task 1: `detect::fold_rule_findings` + re-export + tests

**Files:**
- Modify: `engine/crates/ppcap-core/src/detect/mod.rs`, `engine/crates/ppcap-core/src/lib.rs`

**Interfaces:**
- Produces: `fold_rule_findings(&mut Summary, &[Finding])`.

- [ ] **Step 1: Write the failing tests** — in `detect/mod.rs` `#[cfg(test)]` (mirror the existing `correlate_incidents` tests' `Finding` construction; build a `Summary` via `AnalysisOutput::default().summary` + push a detector finding + correlate it, OR construct the `Summary` directly):
```rust
fn rule_match_on(src: &str, dst: &str) -> Finding {
    Finding {
        kind: FindingKind::RuleMatch, severity: Severity::High, score: 70,
        title: "sig hit".into(), src_ip: src.into(), dst_ip: Some(dst.into()), dst_port: Some(443),
        attack: vec!["T1071".into()], evidence: vec!["rule sid:1001".into()],
        interval_ns: None, jitter_cv: None, contacts: None,
    }
}

#[test]
fn fold_rule_findings_joins_same_host_incident() {
    // a beacon finding on 10.0.0.5, correlated into one incident
    let beacon = /* a Beacon finding on src 10.0.0.5 (mirror an existing correlate test fixture) */;
    let mut sum = crate::model::output::AnalysisOutput::default().summary;
    sum.findings = vec![beacon.clone()];
    sum.incidents = correlate_incidents(&sum.findings);
    // also seed an ip_threats card for 10.0.0.5 so the uplift has a target (mirror the apply_findings test)
    // …push an IpThreat { ip: "10.0.0.5", severity: Low, score: 20, … } into sum.ip_threats…

    fold_rule_findings(&mut sum, &[rule_match_on("10.0.0.5", "203.0.113.9")]);

    let inc = sum.incidents.iter().find(|i| i.host == "10.0.0.5").expect("incident for host");
    assert!(inc.findings.iter().any(|f| f.kind == FindingKind::RuleMatch));   // rule match joined the incident
    // card uplifted by apply_findings:
    assert_eq!(sum.ip_threats.iter().find(|c| c.ip == "10.0.0.5").unwrap().severity, Severity::High);
}

#[test]
fn fold_rule_findings_creates_incident_for_new_host() {
    let mut sum = crate::model::output::AnalysisOutput::default().summary; // no findings/incidents
    fold_rule_findings(&mut sum, &[rule_match_on("10.9.9.9", "8.8.8.8")]);
    assert!(sum.incidents.iter().any(|i| i.host == "10.9.9.9"));            // new incident for the rule-only host
    assert!(sum.findings.iter().any(|f| f.kind == FindingKind::RuleMatch)); // appended to findings
}
```
> NOTE: copy the exact `Finding` field set + a real `Beacon` fixture from the existing `correlate_incidents` tests (~detect/mod.rs:2284+); confirm `Incident` has a `host` + `findings` field (read the model). For the uplift assertion, seed an `IpThreat` card the way the `apply_findings` test does.

- [ ] **Step 2: Run to verify they fail** — `cd engine && cargo test -p ppcap-core fold_rule_findings` → FAIL (undefined).

- [ ] **Step 3: Implement** — in `detect/mod.rs` (add `use crate::model::summary::Summary;` if absent):
```rust
/// Fold post-hoc rule-match findings into a built `Summary`: uplift the implicated IP threat
/// cards, append the findings, and re-correlate incidents so the matches join their host's
/// incident. Re-running `correlate_incidents` over `summary.findings` reproduces the original
/// incidents plus the rule matches (`analyze` sets `summary.findings` to the same input).
pub fn fold_rule_findings(summary: &mut Summary, rule_findings: &[Finding]) {
    summary.apply_findings(rule_findings);
    summary.findings.extend_from_slice(rule_findings);
    summary.incidents = correlate_incidents(&summary.findings);
}
```
  And `ppcap-core/lib.rs`: add `fold_rule_findings` to the existing `pub use detect::{…}` (or a new `pub use detect::fold_rule_findings;`).

- [ ] **Step 4: Run to verify they pass** — `cd engine && cargo test -p ppcap-core fold_rule_findings` → PASS. `cargo fmt`; `cargo clippy -p ppcap-core --all-targets -- -D warnings` → clean.

- [ ] **Step 5: Commit**
```bash
git add engine/crates/ppcap-core/src/detect/mod.rs engine/crates/ppcap-core/src/lib.rs
git commit -m "feat(detect): fold_rule_findings — re-correlate incidents after a rule apply"
```

---

### Task 2: The three call-site swaps (+ full gate)

**Files:**
- Modify: `engine/crates/ppcap-wasm/src/lib.rs`, `ui/src-tauri/src/lib.rs`, `engine/crates/ppcap-cli/src/cli.rs`

**Interfaces:**
- Consumes: `ppcap_core::fold_rule_findings` (T1).

- [ ] **Step 1: Swap the three folds.** Replace, in each, the two lines
  `out.summary.apply_findings(&rf);` + `out.summary.findings.extend(rf.iter().cloned());`
  with `ppcap_core::fold_rule_findings(&mut out.summary, &rf);`:
  - `engine/crates/ppcap-wasm/src/lib.rs` (the `apply_rules` fn, ~:422-423).
  - `ui/src-tauri/src/lib.rs` (the `apply_rules_to` command, ~:164-165).
  - `engine/crates/ppcap-cli/src/cli.rs` (the `--rules` block, ~:258-259).

- [ ] **Step 2: CLI assertion (if a CLI rules test exists).** If `cli.rs` has a `--rules` integration/parse test, extend it (or add a focused one) asserting the analyzed `summary.incidents` includes a `RuleMatch` for a matching pcap; if the existing CLI test is parse-only, skip (T1 covers the fold; the WASM `apply_rules` test already exercises the fold via the export — confirm it still passes after the swap).

- [ ] **Step 3: Full gate** — `cd engine && export PATH="/c/Users/ravid/opt/mingw64/bin:/c/Users/ravid/.cargo/bin:$PATH"`:
```bash
cargo fmt --all -- --check; echo "fmt: $?"
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -6; echo "clippy EXIT: ${PIPESTATUS[0]}"
cargo test -p ppcap-core -p ppcap-cli 2>&1 | tail -10; echo "test EXIT: ${PIPESTATUS[0]}"
cargo tree -p ppcap-core -e no-dev | grep -Ei "zstd-sys|lz4-sys|cc |cmake|bzip2-sys|openssl-sys|zlib-sys" || echo "C-FREE OK"
```
Then the wasm + tauri compiles:
```bash
cd engine/crates/ppcap-wasm && cargo test --target x86_64-pc-windows-gnu 2>&1 | tail -4; echo "wasm test EXIT: ${PIPESTATUS[0]}"
cd ../../../ui/src-tauri && cargo check 2>&1 | tail -4; echo "tauri check EXIT: ${PIPESTATUS[0]}"
```
All green. `git diff --stat engine/Cargo.lock engine/crates/ppcap-wasm/Cargo.lock` → expect empty (no new deps); commit both if changed.

- [ ] **Step 4: Commit**
```bash
git add engine/crates/ppcap-wasm/src/lib.rs ui/src-tauri/src/lib.rs engine/crates/ppcap-cli/src/cli.rs
git commit -m "feat(rules): re-correlate incidents on apply via fold_rule_findings (wasm/tauri/cli)"
```

---

## Self-Review

**1. Spec coverage:** the helper + re-export + tests (T1) → spec §1; the three call-site swaps + gate (T2) → §2. One-source-of-truth, re-correlate-after-fold, analyze-unchanged, no-deps, UI/report-auto-update — all covered. correlate logic + model + per-flow bytes out of scope. ✓

**2. Placeholder scan:** complete code for `fold_rule_findings` + the swap. The NOTEs (mirror an existing `correlate_incidents` Finding/Beacon fixture; confirm `Incident.host`/`.findings`; the CLI test shape) are concrete in-repo reads. ✓

**3. Type consistency:** `fold_rule_findings(&mut Summary, &[Finding])` (T1) ⇄ `summary.apply_findings(&[Finding])` + `correlate_incidents(&[Finding]) -> Vec<Incident>` ⇄ the three surfaces call `ppcap_core::fold_rule_findings(&mut out.summary, &rf)` where `rf: Vec<Finding>` from `apply_rules`. `Finding: Clone` → `extend_from_slice`. ✓
