# Rule import — in-app surface (phase B) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-23
**Branch:** `feat/rule-import-ui`

## Goal

Make the imported-rules detection usable in the app. Phase A shipped the engine `apply_rules` + a CLI `--rules` flag; this exposes it to the browser (WASM) and desktop (Tauri) and adds a "Load detection rules" UI action that folds the matches into the displayed summary (re-rendering the threat-card uplift), with a result notice. **No consent gate** — rule matching is local/offline (no network, no external service).

## Architecture

Mirror the carve cross-surface seam. The engine `apply_rules(reader, len, &[Rule])` + `parse_rules` already exist. Expose a single "parse + apply + fold" entry per runtime that re-reads the retained capture, matches, and returns the updated `AnalysisOutput` JSON + the `{loaded, skipped, matches}` counts. The UI applies it over a **per-capture base snapshot** so re-loading a different ruleset replaces rather than stacks, and reputation enrichment is preserved.

**Tech stack:** Rust (ppcap-wasm, src-tauri) + React/TS. No new deps.

## Global Constraints

- **No new deps.** The WASM path stays C-free + wasm-safe (`apply_rules`/`parse_rules` are already pure compute). Engine unchanged (phase A is reused as-is).
- **No clobber / no stacking** — applying rules must not drop a prior reputation enrichment, and re-loading rules must not duplicate findings. Achieved by applying over a captured pre-rules base (the SNI-domain clobber lesson), not over the already-rules-augmented summary.
- **No-throw at the boundary** — a malformed rules file yields a `skipped` count, never an exception; source-not-retained disables the action.
- Coverage/parity gates: engine WASM/Tauri parity with the native `apply_rules`; UI 80/70 (vitest 1.6.1, `build:wasm`); ppcap-wasm builds.

## Reference: the seams (verified)

```
// engine/crates/ppcap-wasm/src/lib.rs:277 #[wasm_bindgen] pub fn apply_reputation(output_json, verdicts_json) -> Result<String,JsValue> { let mut out: AnalysisOutput = parse; …apply…; to_json } ← MIRROR
//   :86 carve_pcap(bytes, query_json) (the bytes-in pattern) ; :339 analyze(bytes, name)
// ppcap-core exports: parse_rules(text)->RuleParse{rules,skipped}, apply_rules<R:Read+'static>(reader,len,&[Rule])->Vec<Finding>, Summary::apply_findings(&[Finding])
// ui/src/lib/wasmEngine.ts:78 applyReputationWasm (the wasm wrapper pattern) ; ui/src/lib/platform.ts (IS_TAURI branch; carveSubPcap bytes→wasm / path→tauri)
// ui/src/App.tsx:113 const [summary,setSummary]=useState<SummaryState>; enrichAndCommit (serialize-enrichment over the freshest same-capture summary) ; :281 runReputation ; captureKey(output) identity
// ui/src-tauri/ the carve_pcap_to command + generate_handler! registration (the path-reread command pattern to mirror)
// ui/src/cockpit/AppShell.tsx paletteActions / exportActions (⌘K) — add a "Load detection rules…" action
// ui/src/lib/packets.ts packetsAvailable(activeSource) ; ActiveSource = {kind:"path"|"bytes"}|null
```

## Components

### 1. WASM — `engine/crates/ppcap-wasm/src/lib.rs`
```rust
#[wasm_bindgen]
pub fn apply_rules(bytes: &[u8], rules_text: &str, output_json: &str) -> Result<String, JsValue>;
```
- `parse_rules(rules_text)` → `apply_rules(Cursor::new(bytes.to_vec()), Some(len), &parsed.rules)` (owned reader, `'static`) → `out.summary.apply_findings(&rf)` + `out.summary.findings.extend(rf)` → return `serde_json::to_string(&{ output: out, loaded: parsed.rules.len(), skipped: parsed.skipped.len(), matches: rf.len() })`. A small `#[derive(Serialize)]` wrapper `RuleApplyResult { output: AnalysisOutput, loaded, skipped, matches }`. (Named `apply_rules` in the wasm module to avoid colliding with the core re-export — it's a separate symbol.)

### 2. Tauri — `ui/src-tauri/`
```rust
#[tauri::command]
fn apply_rules_to(path: String, rules_text: String, output_json: String) -> Result<String, String>;
```
- Same flow but `apply_rules(File::open(path), metadata.len(), &rules)`; returns the same `RuleApplyResult` JSON. Register in `generate_handler!` (mirror `carve_pcap_to`).

### 3. `ui/src/lib/wasmEngine.ts` + `platform.ts`
- `wasmEngine.ts`: `applyRulesWasm(bytes: ArrayBuffer, rulesText: string, output: AnalysisOutput) -> RuleApplyResult` (call the wasm `apply_rules`, JSON in/out).
- `platform.ts`: `applyRules(rulesText: string, output: AnalysisOutput, source: ActiveSource) -> Promise<RuleApplyResult>`: `{kind:"bytes"}` → `applyRulesWasm`; `{kind:"path"}` → the Tauri `apply_rules_to`; `null`/not-retained → throw a typed "source unavailable" the UI guards against. `interface RuleApplyResult { output: AnalysisOutput; loaded: number; skipped: number; matches: number }`.

### 4. UI — `App.tsx` + a load action
- A `ruleBaseRef = useRef<{ key: string; data: AnalysisOutput } | null>(null)`. `loadRules(file)`:
  1. `const text = await file.text()`.
  2. Determine the base: if `ruleBaseRef.current?.key === captureKey(summary.data)` use `ruleBaseRef.current.data`; else snapshot `ruleBaseRef.current = { key: captureKey(summary.data), data: summary.data }` (captures the post-reputation state). Apply over the base.
  3. `const res = await applyRules(text, base, activeSource)`.
  4. `setSummary({ status: "ready", data: res.output })`; set a transient notice `rules: ${res.loaded} loaded, ${res.skipped} skipped, ${res.matches} matches`.
- Entry points: a "Load detection rules…" action in the **⌘K palette** + a small button on the Dashboard (or the shell), each opening a hidden `<input type="file" accept=".rules,.txt">`. Gated/disabled on `!packetsAvailable(activeSource)` (tooltip "available for captures analyzed from a pcap"). The RuleMatch findings then surface through the existing threat-card uplift + heatmap automatically.

## Data flow & error handling

Load rules → read text → apply over the per-capture base snapshot (preserving reputation, preventing stacking) → updated `AnalysisOutput` → `setSummary` re-renders. Re-loading a different ruleset re-derives from the same base. Source not retained → action disabled. Malformed rules → `skipped` count in the notice; never throws. No network.

## Testing

- **Engine parity:** a WASM/Tauri `apply_rules` parity test — the same pcap+rules through the wasm/command path yields the same findings count as the native `apply_rules` (mirror the reputation cross-surface parity test).
- **`platform.applyRules`:** bytes→WASM and path→Tauri branches (mock both); the `RuleApplyResult` shape; source-unavailable throws/guards.
- **UI:** `loadRules` reads the file → calls `applyRules` → `setSummary` with the returned output + the notice shows the counts; re-loading uses the same base (no stacking — assert the base snapshot is reused for the same captureKey); the action is disabled when `activeSource` is null.
- Gates: engine `cargo test` + ppcap-wasm build; UI vitest 1.6.1 80/70 + `build:wasm` + tsc + build.

## Out of scope (phase C)

A dedicated "Signature matches" panel/list; incident-correlating RuleMatch findings (engine — they append after `correlate_incidents`); persisting/managing rule sources across sessions; in-app rule editing; STIX/MISP/CEF export of rule matches (they already ride along in `summary.findings` for the existing exporters).

## File manifest

**Engine — modify:** `engine/crates/ppcap-wasm/src/lib.rs` (the `apply_rules` wasm export + `RuleApplyResult`), `ui/src-tauri/src/…` (the `apply_rules_to` command + handler registration).
**UI — modify:** `ui/src/lib/wasmEngine.ts` (`applyRulesWasm`), `ui/src/lib/platform.ts` (`applyRules` + `RuleApplyResult`), `ui/src/App.tsx` (`loadRules` + `ruleBaseRef` + the notice), the ⌘K palette + a Dashboard/shell button (+ co-located tests). `npm run build:wasm` regenerates the wasm bindings.
**No new deps; no engine-core change (phase A reused).**
