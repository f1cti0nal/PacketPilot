# Structured Export (STIX 2.1 / CSV) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-22
**Branch:** `feat/structured-export`

## Goal

Expose the engine's already-written STIX 2.1 bundle + findings CSV to the UI on both surfaces (desktop save + browser download/copy), turning PacketPilot's findings into portable SOAR/SIEM artifacts.

## Architecture

Engine-seam plumbing + UI — **no new `ppcap-core` analytics**. A feasibility survey verified two pure, WASM-safe, already-unit-tested functions in `engine/crates/ppcap-core/src/export/mod.rs`:
- `findings_csv(out: &AnalysisOutput) -> String` (`mod.rs:17`) — RFC 4180 CSV, header `kind,severity,score,src_ip,dst_ip,dst_port,attack,title,evidence`, one row per finding.
- `stix_bundle(out: &AnalysisOutput, generated_unix_secs: i64) -> String` (`mod.rs:47`) — deterministic STIX 2.1 bundle (attack-pattern + indicator + relationship SDOs); the only time source is the `i64` arg (same contract as `render_html`).

Because both are pure and unconditionally built, a single WASM export each gives the **browser the exact same artifact as the desktop** — no divergent path. Two Tauri commands give the desktop native file-write + a string for clipboard. A `platform.ts` layer mirrors the existing `exportReport`, and an Export dropdown menu surfaces the formats. **A WASM rebuild is required** so the new exports ship to the browser bundle.

**Tech stack:** Rust (`ppcap-wasm`, `src-tauri`) for the seam; React 18 + TS + Tailwind for the UI; Vitest + RTL. No new dependencies.

## Global Constraints

- **No change to `ppcap-core` export logic** — v1 exposes the existing `findings_csv`/`stix_bundle` exactly as they emit today.
- **A WASM rebuild is required** (`npm run build:wasm`) so `export_csv`/`export_stix` reach the browser. CI's `ui` job already runs `build:wasm` before tsc/vite — confirm it picks up the new exports.
- **Both surfaces produce the identical artifact** (pure engine fns); the browser must NOT fall back to a different format (unlike today's HTML-report→JSON browser fallback).
- **STIX `generated_unix_secs`** is supplied by the caller: `Math.floor(Date.now()/1000)` (browser) / `now_unix_secs` (desktop, as `save_report` does). CSV needs no time.
- **No new runtime dependencies.** Match cockpit styling. Export actions gated on `canExport = summary.status === "ready" && !!summary.data` (`AppShell.tsx:94`).
- **The `npm run test:coverage` gate stays green** (80/70); verify under the locked toolchain (`npm ci` → `npm run build:wasm` → `npm run build` → `npm run test:coverage`; CI uses vitest 1.6.1) before completion.
- **Stage specific files** on commit (never `git add -A`).

## Design Decisions (resolved)

1. **Formats:** CSV + STIX 2.1 (expose the existing fns). MISP/CEF deferred (new engine fns).
2. **Copy + file:** both — a file download AND a copy-to-clipboard action per format.
3. **Surface:** an Export **dropdown menu** (HTML report / CSV / STIX, each with download + copy), with the same actions also in the ⌘K palette.
4. **Enrichment:** none — v1 emits exactly what the fns produce today (behavioral findings + ATT&CK + indicators). Reputation-in-STIX and AI-narrative ride-along are deferred.

## Engine seam

### WASM — `engine/crates/ppcap-wasm/src/lib.rs`
Two `#[wasm_bindgen]` exports mirroring `apply_reputation(output_json: &str, …) -> Result<String, JsValue>` (`lib.rs:164`):
```rust
#[wasm_bindgen]
pub fn export_csv(output_json: &str) -> Result<String, JsValue>;      // parse AnalysisOutput → findings_csv → String
#[wasm_bindgen]
pub fn export_stix(output_json: &str, generated_unix_secs: i64) -> Result<String, JsValue>; // → stix_bundle
```
(Each: `serde_json::from_str::<AnalysisOutput>` → call the core fn → `Ok(string)`; map parse errors to `JsValue` like `apply_reputation`.)

### Tauri — `ui/src-tauri/src/lib.rs`
Mirror `save_report` (`lib.rs:209`). File-write commands for download + string-return commands for copy (the desktop webview does not initialize WASM):
```rust
#[tauri::command] fn save_csv(summary: AnalysisOutput, path: String) -> Result<(), String>;   // findings_csv → fs::write
#[tauri::command] fn save_stix(summary: AnalysisOutput, path: String) -> Result<(), String>;  // stix_bundle(now) → fs::write
#[tauri::command] fn export_csv(summary: AnalysisOutput) -> Result<String, String>;            // returns the string (for copy)
#[tauri::command] fn export_stix(summary: AnalysisOutput) -> Result<String, String>;           // returns the string (for copy)
```
`save_stix`/`export_stix` compute `now_unix_secs` internally (as `save_report` does). Register all four in `generate_handler!` (`lib.rs:225`). (The plan may collapse `save_*` to call the same internal helper as `export_*`.)

## Platform layer — `ui/src/lib/platform.ts`

Mirror `exportReport` (`platform.ts:60`, desktop `save()`-dialog + `invoke`, browser blob+anchor). Add:
- `exportCsv(summary)` / `exportStix(summary)` → **file**: desktop = `save({ defaultPath })` → `invoke("save_csv"|"save_stix", { summary, path })`; browser = call the WASM export (via the existing WASM-init path used for `analyze`/`apply_reputation`) → `Blob` → anchor download + `revokeObjectURL`.
- `copyCsv(summary)` / `copyStix(summary)` → **clipboard**: generate the string (browser = WASM export; desktop = `invoke("export_csv"|"export_stix", { summary })`) → `navigator.clipboard.writeText(str)`.
- All return the existing `ExportResult { ok, message }`; failures return `{ ok: false, message }` (no throw).

## UI — Export dropdown menu

Convert the single `Export` `ActionButton` (`ui/src/cockpit/CommandBar.tsx:149`) into a small dropdown menu (a focused new component, e.g. `cockpit/ExportMenu.tsx`): **HTML report**, **CSV**, **STIX bundle** — each with a **Download** and a **Copy** item (HTML report keeps download-only). The same actions are added to `paletteActions` (`AppShell.tsx:146`) as flat entries (`export-csv`, `export-stix`, `export-csv-copy`, `export-stix-copy`), conditionally spread on `canExport` exactly like the existing `export` action. App-level handlers (next to `handleExport`, `App.tsx:411`) call the new `platform.ts` fns with `summary.data`.

## Filenames

`<capture>-findings.csv` and `<capture>-stix.json`, where `<capture>` is the basename of the source (fallback `packetpilot`). STIX 2.1 bundles are valid JSON (`.json`).

## Data flow & error handling

`summary.data` (the `AnalysisOutput`) flows to the export fns already. Actions are enabled only when `canExport`. A cancelled save dialog → `{ ok: false, message: "" }` (silent). Clipboard/file/WASM failures → `{ ok: false, message }` surfaced via the existing export toast/result handling; never crash. Empty findings → a valid header-only CSV / minimal STIX bundle (the core fns already handle this).

## Testing

- **WASM round-trip** (`ui/src/lib/wasm` or a parity-style test): init the WASM, call `export_csv`/`export_stix` on a fixture `AnalysisOutput`, assert the CSV header line + a finding row, and `"type":"bundle"` / `"spec_version":"2.1"` in the STIX output.
- **`platform.ts` test:** assert the desktop branch (`isTauri` true → `save()` + `invoke("save_csv"…)`) vs the browser branch (WASM string → blob/anchor), and the copy path (`navigator.clipboard.writeText` called with the string). Mock the WASM + Tauri seams.
- **ExportMenu render test:** the menu's items render and are disabled when `!canExport`; clicking an item calls the right handler.
- The core fns are already unit-tested (`export/mod.rs:229-294`). Coverage ≥ 80/70; WASM rebuilt before the gate.

## Out of scope (fast-follows)

- **MISP-event JSON / CEF** formats (new engine fns).
- **Reputation verdicts** as STIX indicators / CSV rows (feed-confirmed malicious IPs with no behavioral finding; needs an engine change to read the threat-card/reputation side).
- **AI-narrative ride-along** (e.g. a STIX `note` SDO).
- **src-IP-as-observable** for fan-out findings (`dst_ip: None`); richer STIX (`kill_chain_phases`, Identity/provenance SDO, `source_sha256` chain-of-custody stamping).

## File manifest

**Modify (engine seam):** `engine/crates/ppcap-wasm/src/lib.rs` (2 exports), `ui/src-tauri/src/lib.rs` (4 commands + handler registration).
**Create:** `ui/src/cockpit/ExportMenu.tsx` + test.
**Modify (UI):** `ui/src/lib/platform.ts` (exportCsv/exportStix/copyCsv/copyStix) + test, `ui/src/cockpit/CommandBar.tsx` (use ExportMenu), `ui/src/components/layout/AppShell.tsx` (palette actions), `ui/src/App.tsx` (handlers). **No `ppcap-core` change.**
