# Browser HTML report export — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-23
**Branch:** `feat/browser-html-report`

## Goal

Make the browser's "Export report" produce the real HTML triage report, matching the desktop. Today `platform.exportReport` renders the rich HTML report only on desktop (the Tauri `save_report` command); the **browser branch falls back to downloading raw summary JSON** (`packetpilot-summary.json`). `render_html` isn't exposed to WASM. This exposes it and brings the browser export to desktop parity.

## Architecture

Expose the engine `render_html` via WASM (`render_report`), and swap the browser branch of `platform.exportReport` to render + download the HTML. Mirrors the structured-export pattern (CSV/STIX already round-trip a string via WASM). The desktop path is unchanged. No new UI action — `exportReport` is already wired (App.tsx:505); this only upgrades what the browser produces.

**Tech stack:** Rust (ppcap-wasm) + React/TS. No new deps.

## Global Constraints

- **No new deps.** WASM path stays C-free + wasm-safe (`render_html` is pure compute in ppcap-core). Engine-core unchanged.
- **Desktop path untouched** — the Tauri `save_report` branch of `exportReport` keeps working exactly as today.
- **No-throw** — `exportReport` returns `ExportResult` (the export contract); a WASM/render failure yields `{ ok: false, message }`, never an exception.
- ⚠️ **`i64` timestamp → `BigInt()`** at the JS↔wasm boundary (the same gotcha STIX/MISP/CEF exports handle).
- Gates: ppcap-wasm builds + a render test; UI 80/70 (vitest 1.6.1) + `build:wasm` (regenerates the `render_report` binding) + tsc.

## Reference: the seams (verified)

```
// engine/crates/ppcap-core/src/report/mod.rs:42 pub fn render_html(out: &AnalysisOutput, generated_unix_secs: i64, ai_summary: Option<&str>) -> String
// engine/crates/ppcap-wasm/src/lib.rs:311 #[wasm_bindgen] export_stix(output_json, generated_unix_secs: i64) -> Result<String,JsValue> — MIRROR (parse AnalysisOutput, call core, return String; same i64 ts param)
// ui/src/lib/wasmEngine.ts:117 exportStixWasm(outputJson, generatedUnixSecs) — the wasm wrapper to mirror (incl. the i64→BigInt handling); import { export_stix } shows the binding-name convention
// ui/src/lib/platform.ts:62 exportReport(summary, aiSummary?) -> Promise<ExportResult> — desktop branch (save_report) KEEP; the BROWSER branch (currently downloads summary JSON) is what changes
//   :118 downloadText(content, filename, mime) ; ExportResult is the no-throw export contract
// ui/src/App.tsx:36 imports exportReport ; :505 return exportReport(summary.data, ai?.text) — the call site (UNCHANGED)
```

## Components

### 1. WASM — `engine/crates/ppcap-wasm/src/lib.rs`
```rust
/// Render the full HTML triage report for `output_json` (mirrors the desktop `save_report`).
#[wasm_bindgen]
pub fn render_report(output_json: &str, generated_unix_secs: i64, ai_summary: Option<String>) -> Result<String, JsValue> {
    let out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(ppcap_core::render_html(&out, generated_unix_secs, ai_summary.as_deref()))
}
```
- Confirm `render_html` is re-exported from `ppcap_core` (`pub use report::render_html` in lib.rs) — if not, add the re-export (it's `pub fn` in `report/mod.rs`; ensure `ppcap_core::render_html` resolves). `Option<String>` maps to a JS optional string param.

### 2. `ui/src/lib/wasmEngine.ts`
```ts
export async function renderReportWasm(outputJson: string, generatedUnixSecs: number, aiSummary?: string): Promise<string> {
  await ensureWasm();
  return wasmRenderReport(outputJson, BigInt(generatedUnixSecs), aiSummary ?? undefined) as string;
}
```
(`import { render_report as wasmRenderReport }`; mirror `exportStixWasm`'s `ensureWasm` + `BigInt(generatedUnixSecs)` — confirm STIX uses `BigInt`; match it exactly. `aiSummary ?? undefined` → the wasm `Option<String>`.)

### 3. `ui/src/lib/platform.ts` — `exportReport` browser branch
Replace the JSON-fallback block (the `// Browser fallback: download the summary as pretty JSON` section) with:
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
(Reuse the existing `captureBase(summary)` for the filename; import `renderReportWasm`. The Tauri branch above is unchanged.)

## Data flow & error handling

Browser `exportReport` → `renderReportWasm(summaryJson, now, aiSummary)` → `render_html` → HTML string → `downloadText(.html)` → `{ ok: true, "Downloaded" }`. A render/parse failure → `{ ok: false, message }` (no throw). Desktop → `save_report` (unchanged). The report includes everything render_html emits (incidents, severity SVG, top threats, signature matches, …). `Date.now()` is the report's generated timestamp; `aiSummary` is the same optional value `exportReport` already receives.

## Testing

- **WASM `render_report` test** (ppcap-wasm): render a small `AnalysisOutput` (reuse the existing test fixture) → the returned HTML `contains` `"<!doctype html>"` + `"Executive summary"` + a known value (e.g. a top-talker IP from the fixture); with an `ai_summary` arg, the HTML contains the AI card text.
- **`platform.exportReport` (browser)**: mock `renderReportWasm` (returns `"<html>…</html>"`) + spy `downloadText`/the anchor → assert `downloadText` called with the HTML + a `.html` filename + `text/html`, and the result is `{ ok: true }`; a `renderReportWasm` rejection → `{ ok: false }`. The Tauri-branch test (if present) unchanged.
- Gate: `cd engine/crates/ppcap-wasm && cargo test --target x86_64-pc-windows-gnu` builds + the render test passes; UI vitest 1.6.1 80/70 + `build:wasm` + tsc + build.

## Out of scope

The desktop `save_report` path (works); an in-app report preview/print; PDF; the CLI `--html` (exists); changing `exportReport`'s signature or its call site.

## File manifest

**Engine — modify:** `engine/crates/ppcap-wasm/src/lib.rs` (`render_report` export; + `ppcap_core::render_html` re-export in ppcap-core/lib.rs if absent).
**UI — modify:** `ui/src/lib/wasmEngine.ts` (`renderReportWasm`), `ui/src/lib/platform.ts` (the `exportReport` browser branch) + the co-located tests. `npm run build:wasm` regenerates the binding.
**No new deps; no desktop/CLI/Dashboard change.**
