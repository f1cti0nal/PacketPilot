# Sigma rule export — implementation plan

Spec: [2026-06-24-sigma-export-design.md](../specs/2026-06-24-sigma-export-design.md)

Mirrors the CEF/MISP export-surface chain exactly. One vertical PR.

## Engine

1. `export/mod.rs`: `sigma_rules(out) -> String` (multi-doc YAML, one rule per finding; reuses
   `det_uuid` for ids) + helpers `yaml_str` (escaped double-quoted scalar), `attack_url`,
   `sigma_level` (severity → Sigma level), `sigma_category` (kind → logsource category). Test:
   one doc per finding, required keys present, dst_ip vs src_ip selection, level + `attack.` tag,
   determinism, empty-input → "".
2. `lib.rs`: re-export `sigma_rules`. Refresh the module doc comment (now CSV/STIX/MISP/CEF/Sigma).

## WASM / Tauri

3. `ppcap-wasm/src/lib.rs`: `export_sigma(json) -> Result<String, JsValue>` (mirrors `export_cef`).
4. `ui/src-tauri/src/lib.rs`: `save_sigma(summary, path)` + `export_sigma(summary)` commands +
   register both in the handler list.

## UI

5. `wasmEngine.ts`: import `export_sigma as wasmExportSigma` + `exportSigmaWasm()`.
6. `platform.ts`: `exportSigma()` (save/download, `-sigma.yml`) + `copySigma()` (clipboard),
   branching on `isTauri()`.
7. `App.tsx`: import + `handleExportSigma` / `handleCopySigma` + pass `onExportSigma` / `onCopySigma`
   to AppShell.
8. `AppShell.tsx`: props + add to the ExportMenu dropdown actions and the ⌘K palette actions.
9. Tests: `platform.test.ts` (exportSigma desktop/browser + copySigma) and an `AppShell.test.tsx`
   case clicking the Sigma dropdown actions (also keeps the function-coverage gate ≥ 80%).

## Gates

Engine: `fmt` · `clippy -D warnings` · `test` · C-free gate · `wasm32`. Desktop: `cargo check` the
src-tauri crate (new commands). UI: `build:wasm` · `test:coverage` (80/70) · `build`. Then PR, watch
CI, merge on local gates.
