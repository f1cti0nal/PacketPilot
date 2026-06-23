# Rule matches in the HTML report — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A "Signature matches" section in the HTML report listing `RuleMatch` findings, so `--rules` matches appear in the headless triage output.

**Architecture:** Engine-only (`report/mod.rs`). A new `signature_matches_html(&sum.findings)` card section, inserted into `render_html` after the incidents section; omitted when there are no rule matches.

**Tech Stack:** Rust (ppcap-core). No new deps.

## Global Constraints

- **No new deps.** C-free gate stays empty; `report` is pure compute (wasm-safe).
- **Omitted when empty** — `signature_matches_html` returns `""` with no `RuleMatch` findings; every existing report test must still pass.
- **HTML-escape all dynamic text** via the existing `esc` (msg, IPs, MITRE, sid).
- **Defensive sid parse** — scan `evidence` for `sid:N`; omit gracefully, never panic.
- Run cargo from `engine/` (PATH `/c/Users/ravid/.cargo/bin`); `cargo fmt` before commit.

## Reference: the seams (verified)

```
// report/mod.rs:42 pub fn render_html(...) -> String ; :156 s.push_str(&incidents_html(&sum.incidents)); ← INSERT after this
//   :164-206 the "Top threats" <h2>/<table><thead>…<tbody> + per-row <td> pattern to MIRROR (incl. how a severity cell is rendered — read it)
//   esc(...) HTML-escape ; kind_label(FindingKind) (:412, RuleMatch→"Signature Match")
//   incidents_html (read it) shows how findings' fields (title/src/dst/attack/severity) are already rendered — reuse the same cell idioms
// model/finding.rs Finding { kind: FindingKind, severity: Severity, title: String, src_ip: String, dst_ip: Option<String>, dst_port: Option<u16>, attack: Vec<String>, evidence: Vec<String> }
//   FindingKind::RuleMatch ; rule_finding evidence[0] = "rule sid:{sid}"
// the existing #[cfg(test)] in report/mod.rs — how a Summary/Finding fixture is built for a render_html test (mirror it)
```

---

### Task 1: `signature_matches_html` + `sid_of` + insertion + test

**Files:**
- Modify: `engine/crates/ppcap-core/src/report/mod.rs`

**Interfaces:**
- Produces: `signature_matches_html(&[Finding]) -> String` (private); the `render_html` insertion.

- [ ] **Step 1: Read the patterns to mirror.** In `report/mod.rs`: the "Top threats" table (:164-206) for the `<table>`/`<tr>`/`<td>` + **severity-cell** idiom; `incidents_html` for how a finding's title/src/dst/attack/severity are already rendered (reuse those idioms verbatim — e.g. how `attack` is joined, how severity becomes a class/label); the existing `#[cfg(test)]` `render_html` test for how a `Summary`/`Finding` fixture is constructed.

- [ ] **Step 2: Write the failing test** — add to `report/mod.rs` `#[cfg(test)]` (build the `Summary` the way the existing report test does, but push a `RuleMatch` finding into `summary.findings`):
```rust
#[test]
fn report_renders_signature_matches_section() {
    let mut sum = /* the minimal Summary the existing render_html test builds */;
    sum.findings.push(Finding {
        kind: FindingKind::RuleMatch,
        severity: Severity::High,
        score: 70,
        title: "C2 beacon".to_string(),
        src_ip: "10.0.0.5".to_string(),
        dst_ip: Some("203.0.113.9".to_string()),
        dst_port: Some(443),
        attack: vec!["T1071".to_string()],
        evidence: vec!["rule sid:1001".to_string(), "matched content (3 bytes)".to_string()],
        interval_ns: None,
        jitter_cv: None,
        contacts: None,
    });
    let html = render_html(/* the same args the existing test uses */);
    assert!(html.contains("Signature matches"));
    assert!(html.contains("C2 beacon"));
    assert!(html.contains("1001"));        // sid
    assert!(html.contains("10.0.0.5"));    // src
    assert!(html.contains("203.0.113.9")); // dst
    assert!(html.contains("T1071"));       // MITRE
}

#[test]
fn report_omits_signature_matches_when_none() {
    let sum = /* the minimal Summary with NO rule_match findings (the existing fixture) */;
    let html = render_html(/* same args */);
    assert!(!html.contains("Signature matches"));
}
```
> NOTE: copy the exact `Summary` construction + the exact `render_html(...)` argument list from the existing report test (don't invent a fixture). Confirm the `Finding` field set against `model/finding.rs` (it may differ slightly — match it).

- [ ] **Step 3: Run to verify it fails** — `cd engine && cargo test -p ppcap-core report::` (or the test names) → FAIL.

- [ ] **Step 4: Implement** — in `report/mod.rs`:
```rust
/// Extract the rule sid from a finding's evidence (defensive; None if absent).
fn sid_of(f: &Finding) -> Option<&str> {
    for e in &f.evidence {
        if let Some(idx) = e.find("sid:") {
            let rest = &e[idx + 4..];
            let digits: &str = rest.trim_start();
            let end = digits.find(|c: char| !c.is_ascii_digit()).unwrap_or(digits.len());
            if end > 0 {
                return Some(&digits[..end]);
            }
        }
    }
    None
}

/// "Signature matches" card section — the imported-rule (`RuleMatch`) findings. "" when none.
fn signature_matches_html(findings: &[Finding]) -> String {
    let matches: Vec<&Finding> = findings.iter().filter(|f| f.kind == FindingKind::RuleMatch).collect();
    if matches.is_empty() {
        return String::new();
    }
    let mut s = String::new();
    s.push_str("<section class=\"card\"><h2>Signature matches</h2><table><thead><tr>\
        <th>Rule</th><th>SID</th><th>Source → Destination</th><th>ATT&amp;CK</th><th>Severity</th>\
        </tr></thead><tbody>");
    for f in matches.iter().take(50) {
        let dst = match (&f.dst_ip, f.dst_port) {
            (Some(ip), Some(p)) => format!("{}:{}", esc(ip), p),
            (Some(ip), None) => esc(ip),
            (None, _) => "—".to_string(),
        };
        let attack = f.attack.iter().map(|a| esc(a)).collect::<Vec<_>>().join(", ");
        let sid = sid_of(f).map(esc).unwrap_or_default();
        s.push_str(&format!(
            "<tr><td>{title}</td><td>{sid}</td><td>{src} → {dst}</td><td>{attack}</td><td>{sev}</td></tr>",
            title = esc(&f.title),
            sid = sid,
            src = esc(&f.src_ip),
            dst = dst,
            attack = attack,
            sev = /* the severity cell idiom the Top-threats / incidents table uses — mirror it (label or class) */,
        ));
    }
    s.push_str("</tbody></table></section>\n");
    s
}
```
  Then in `render_html`, after `s.push_str(&incidents_html(&sum.incidents));`: `s.push_str(&signature_matches_html(&sum.findings));`.
  (Match the real `esc` signature — `esc(&str) -> String` vs `Cow`; adjust `.map(esc)` accordingly. Use the file's actual severity-cell rendering for the `sev` column.)

- [ ] **Step 5: Run to verify it passes** — `cd engine && cargo test -p ppcap-core report::` → PASS (both new tests + the existing report tests). `cargo fmt`.

- [ ] **Step 6: Commit**
```bash
git add engine/crates/ppcap-core/src/report/mod.rs
git commit -m "feat(report): Signature matches section for RuleMatch findings"
```

---

### Task 2: Full gate

- [ ] **Step 1: Full engine gate** — `cd engine && export PATH="/c/Users/ravid/.cargo/bin:$PATH"`:
```bash
cargo fmt --all -- --check; echo "fmt: $?"
cargo clippy -p ppcap-core --all-targets -- -D warnings 2>&1 | tail -5; echo "clippy EXIT: ${PIPESTATUS[0]}"
cargo test -p ppcap-core 2>&1 | tail -10; echo "test EXIT: ${PIPESTATUS[0]}"
cargo tree -p ppcap-core -e no-dev | grep -Ei "zstd-sys|lz4-sys|cc |cmake|bzip2-sys|openssl-sys|zlib-sys" || echo "C-FREE OK"
```
- [ ] **Step 2: ppcap-wasm build** (report is in core): `cd engine/crates/ppcap-wasm && cargo build --target x86_64-pc-windows-gnu 2>&1 | tail -3; echo "wasm build EXIT: ${PIPESTATUS[0]}"`. No new deps → lockfiles unchanged; `git diff --stat engine/Cargo.lock engine/crates/ppcap-wasm/Cargo.lock` (commit both if changed).

- [ ] **Step 3: Commit** any fmt/lockfile fixups (only if changed).

---

## Self-Review

**1. Spec coverage:** `signature_matches_html` + `sid_of` + the insertion + tests (T1) → spec §1-2; the gate (T2) → constraints/testing. Omitted-when-empty, esc-escaped, defensive sid, after-incidents placement, top-50 cap — all covered. Incident-correlation + exporters out of scope. ✓

**2. Placeholder scan:** complete code for `sid_of` + `signature_matches_html` + the insertion + the tests. The deferred specifics (the exact `Summary`/`render_html` test-fixture construction; the severity-cell idiom; the `esc` signature) are concrete in-repo reads, not vague TODOs. ✓

**3. Type consistency:** `signature_matches_html(&[Finding]) -> String` filters `f.kind == FindingKind::RuleMatch`; consumes `f.title`/`f.src_ip`/`f.dst_ip:Option`/`f.dst_port:Option`/`f.attack`/`f.severity`/`f.evidence`; `sid_of(&Finding) -> Option<&str>`; inserted in `render_html` over `sum.findings`. ✓
