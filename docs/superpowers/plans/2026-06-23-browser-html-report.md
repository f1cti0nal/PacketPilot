# Browser HTML report export — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The browser's "Export report" downloads the real HTML triage report (desktop parity), not a summary-JSON fallback.

**Architecture:** Expose `render_html` via WASM (`render_report`, mirroring `export_stix`); swap the browser branch of `platform.exportReport` to render + download the HTML. Desktop path untouched.

**Tech Stack:** Rust (ppcap-wasm) + React/TS. No new deps.

## Global Constraints

- **No new deps.** WASM path C-free + wasm-safe (`render_html` is pure compute; `ppcap_core::render_html` already re-exported at ppcap-core/lib.rs:83). Engine-core unchanged.
- **Desktop path untouched** — the Tauri `save_report` branch of `exportReport` keeps working.
- **No-throw** — `exportReport` returns `ExportResult`; a render failure → `{ ok: false, message }`.
- ⚠️ **`i64` ts → `BigInt()`** at the JS↔wasm boundary (same as STIX).
- Run ppcap-wasm tests from its own dir; UI: node `/c/Program Files/nodejs`, vitest 1.6.1, `build:wasm` regenerates the binding; do NOT `npm install`.

## Reference: the seams (verbatim, verified)

```
// engine/crates/ppcap-core/src/report/mod.rs:42 pub fn render_html(out:&AnalysisOutput, generated_unix_secs:i64, ai_summary:Option<&str>)->String ; re-exported ppcap-core/lib.rs:83
// engine/crates/ppcap-wasm/src/lib.rs:447 pub fn export_stix(output_json:&str, generated_unix_secs:i64)->Result<String,JsValue> { let out:AnalysisOutput=from_str?; Ok(core::...) }  ← MIRROR
// ui/src/lib/wasmEngine.ts:16-17 `export_stix as wasmExportStix` ; exportStixWasm(outputJson, generatedUnixSecs:number){ await ensureWasm(); return wasmExportStix(outputJson, BigInt(generatedUnixSecs)); }  ← MIRROR
// ui/src/lib/platform.ts:62 exportReport(summary, aiSummary?)->Promise<ExportResult>: Tauri branch = save_report (KEEP); browser branch currently downloads JSON (REPLACE). :118 downloadText(content,filename,mime) ; captureBase(summary) for the filename
```

---

### Task 1: WASM `render_report` export

**Files:**
- Modify: `engine/crates/ppcap-wasm/src/lib.rs`

**Interfaces:**
- Produces: `#[wasm_bindgen] render_report(output_json, generated_unix_secs: i64, ai_summary: Option<String>) -> Result<String, JsValue>`.

- [ ] **Step 1: Write the failing test** — in ppcap-wasm tests (reuse the existing `analyze`/`apply_rules` pcap fixture to get an `AnalysisOutput` JSON, OR build a minimal `AnalysisOutput` and `serde_json::to_string` it):
```rust
#[test]
fn render_report_emits_html() {
    // get an AnalysisOutput JSON: analyze a tiny pcap → AnalyzeResult, take ["summary"] (the AnalysisOutput)
    let pcap = /* the existing test pcap fixture */;
    let analyze_json = crate::analyze(&pcap, "t.pcap".into()).unwrap();
    let out_json = serde_json::from_str::<serde_json::Value>(&analyze_json).unwrap()["summary"].to_string();
    let html = crate::render_report(&out_json, 1_700_000_000, None).unwrap();
    assert!(html.contains("<!doctype html>"));
    assert!(html.contains("Executive summary"));
    // with an ai summary, the card text appears:
    let html2 = crate::render_report(&out_json, 1_700_000_000, Some("AI says: suspicious beacon".to_string())).unwrap();
    assert!(html2.contains("AI says: suspicious beacon"));
}
```
> NOTE: reuse the same pcap-fixture + `analyze(...)["summary"]` extraction the `apply_rules` wasm test (T1 of the rule-import-ui feature) used — that's the proven way to get an `AnalysisOutput` JSON in a wasm test. Confirm `render_html` includes the `ai_summary` text in a card (it does — the AI-assist feature added that param).

- [ ] **Step 2: Run to verify it fails** — `cd engine/crates/ppcap-wasm && cargo test --target x86_64-pc-windows-gnu render_report` → FAIL.

- [ ] **Step 3: Implement** — in `ppcap-wasm/src/lib.rs` (next to `export_stix`):
```rust
/// Render the full HTML triage report for `output_json` (browser parity with the desktop `save_report`).
#[wasm_bindgen]
pub fn render_report(output_json: &str, generated_unix_secs: i64, ai_summary: Option<String>) -> Result<String, JsValue> {
    let out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(ppcap_core::render_html(&out, generated_unix_secs, ai_summary.as_deref()))
}
```

- [ ] **Step 4: Run to verify it passes** — `cd engine/crates/ppcap-wasm && cargo test --target x86_64-pc-windows-gnu render_report` → PASS. `cargo fmt`.

- [ ] **Step 5: Commit**
```bash
git add engine/crates/ppcap-wasm/src/lib.rs engine/crates/ppcap-wasm/Cargo.lock
git commit -m "feat(wasm): render_report export (HTML triage report)"
```
(Cargo.lock only if changed — likely unchanged.)

---

### Task 2: `renderReportWasm` + `exportReport` browser branch (+ gate)

**Files:**
- Modify: `ui/src/lib/wasmEngine.ts`, `ui/src/lib/platform.ts`, the platform test (`ui/src/lib/platform.test.ts`)

**Interfaces:**
- Consumes: the wasm `render_report` (T1).
- Produces: `renderReportWasm`; the upgraded `exportReport` browser path.

- [ ] **Step 1: Regenerate the binding** — `export PATH="/c/Program Files/nodejs:/c/Users/ravid/.cargo/bin:$PATH"; cd ui && npm run build:wasm` (so the generated `render_report` binding exists for the `import`).

- [ ] **Step 2: Write the failing test** — in `platform.test.ts` (mirror the existing export tests' mocking of `wasmEngine` + the anchor/downloadText spy):
```ts
// mock renderReportWasm in the wasmEngine mock; force the browser path (isTauri → false).
it("exportReport (browser) downloads the rendered HTML report", async () => {
  renderReportWasm.mockResolvedValue("<!doctype html><html>…report…</html>");
  const res = await exportReport(summary /*, aiSummary? */);
  expect(renderReportWasm).toHaveBeenCalled();
  // assert an .html / text/html download happened (spy downloadText or the anchor), and:
  expect(res).toEqual({ ok: true, message: "Downloaded" });
});
it("exportReport (browser) returns ok:false when the render rejects", async () => {
  renderReportWasm.mockRejectedValue(new Error("boom"));
  const res = await exportReport(summary);
  expect(res.ok).toBe(false);
});
```
(Match how the file mocks `isTauri`/`wasmEngine`/`downloadText` for the other export tests; add `renderReportWasm` to the `wasmEngine` mock. Keep the existing export tests unchanged.)

- [ ] **Step 3: Run to verify it fails** — `cd ui && npx vitest run src/lib/platform.test.ts` → FAIL.

- [ ] **Step 4: Implement** —
  - `wasmEngine.ts`: add `import { render_report as wasmRenderReport }` to the wasm import block; 
```ts
export async function renderReportWasm(outputJson: string, generatedUnixSecs: number, aiSummary?: string): Promise<string> {
  await ensureWasm();
  return wasmRenderReport(outputJson, BigInt(generatedUnixSecs), aiSummary ?? undefined) as string;
}
```
  - `platform.ts`: `import { renderReportWasm } from "./wasmEngine";` (add to the existing wasmEngine import). Replace the `exportReport` browser-fallback block (the `// Browser fallback: download the summary as pretty JSON` section through its `return`) with:
```ts
  // Browser: render the full HTML report via WASM (parity with the desktop save_report).
  try {
    const html = await renderReportWasm(JSON.stringify(summary), Math.floor(Date.now() / 1000), aiSummary);
    downloadText(html, `${captureBase(summary)}-report.html`, "text/html");
    return { ok: true, message: "Downloaded" };
  } catch (e) {
    return { ok: false, message: e instanceof Error ? e.message : "Report export failed" };
  }
```
  Leave the Tauri branch (`save_report`) untouched.

- [ ] **Step 5: Run to verify it passes** — `cd ui && npx vitest run src/lib/platform.test.ts` → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 6: Commit**
```bash
git add ui/src/lib/wasmEngine.ts ui/src/lib/platform.ts ui/src/lib/platform.test.ts
git commit -m "feat(ui): browser exportReport renders the HTML report via WASM"
```

- [ ] **Step 7: Full gate** — `cd ui && export PATH="/c/Program Files/nodejs:/c/Users/ravid/.cargo/bin:$PATH"`:
```bash
git checkout -- package.json package-lock.json 2>/dev/null || true
npm ci
node -p "require('./node_modules/vitest/package.json').version"   # 1.6.1
npm run build:wasm
npm run build; echo "build EXIT: $?"          # 0
npm run test:coverage; echo "cov EXIT: $?"    # 0; All files >= 80/70 — paste it
```
Engine: `cd engine/crates/ppcap-wasm && cargo test --target x86_64-pc-windows-gnu 2>&1 | tail -4`. Do NOT `npm install`. Lockfiles: commit `engine/crates/ppcap-wasm/Cargo.lock` if changed.

- [ ] **Step 8: Commit** any gate fixups.

---

## Self-Review

**1. Spec coverage:** WASM `render_report` + test (T1) → spec §1; `renderReportWasm` + the `exportReport` browser branch + tests + gate (T2) → §2-3. Desktop-untouched, no-throw, i64→BigInt, parity HTML — all covered. Desktop path/preview/PDF out of scope. ✓

**2. Placeholder scan:** complete code for the WASM export, the wasm wrapper, the `exportReport` branch. The NOTEs (reuse the analyze-fixture for the wasm test; match the platform test's mock style) are concrete in-repo refs. ✓

**3. Type consistency:** `render_report(&str, i64, Option<String>) -> Result<String,_>` (T1) ⇄ `renderReportWasm(outputJson, number, aiSummary?) -> Promise<string>` (BigInt at the boundary) ⇄ `exportReport` calls it with `JSON.stringify(summary)`, `Math.floor(Date.now()/1000)`, `aiSummary` → `downloadText(html, …, "text/html")` ⇄ `ExportResult` no-throw. ✓
