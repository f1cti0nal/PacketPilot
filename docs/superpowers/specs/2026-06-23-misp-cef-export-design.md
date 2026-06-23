# MISP + CEF export — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-23
**Branch:** `feat/misp-cef-export`

## Goal

Emit findings as **MISP-event JSON** (threat-intel sharing / offline MISP) and **CEF** (ArcSight / SIEM / syslog) so PacketPilot output flows into a SOC — extending the proven STIX/CSV structured-export seam (roadmap: SIEM/SOAR export + offline MISP).

## Architecture

Two new pure engine functions next to `findings_csv`/`stix_bundle` in `export/mod.rs`, reading the same `Summary` (findings + `ip_threats` + `domain_threats` + fingerprints/reputation), then mirrored across every surface exactly as CSV/STIX already are: a WASM export → Tauri save+copy commands → `platform.ts` export+copy functions → `ExportMenu` actions. The functions are pure + deterministic (reuse the existing `det_uuid` for stable UUIDs); the `ExportResult` no-throw contract and the wasm-bindgen `i64`→`BigInt` handling (for the MISP timestamp, like STIX) are preserved.

**Tech stack:** Rust (`ppcap-core` `export/mod.rs`; `ppcap-wasm`; `src-tauri`); React 18 + TS; Vitest. No new deps (MISP is `serde_json`; CEF is a string builder).

## Global Constraints

- **Mirror the STIX/CSV seam exactly** — same function/command/wrapper/action shape, no new pattern. `findings_csv`/`stix_bundle` and their callers are untouched.
- **Pure, deterministic, no-throw.** Both fns take `&AnalysisOutput`, return `String`, never panic; identical input → identical output. Reuse `det_uuid` (MISP UUIDs) + the existing `csv_field`/`iso` style helpers; add a `cef_escape`.
- **No new dependencies.** MISP via `serde_json::json!`; CEF via `String`.
- **`ExportResult` contract:** every UI export path returns `{ ok, message }` and never throws (try/catch → `{ ok:false, message }`); a cancelled save → `{ ok:false, message:"" }`.
- **`build:wasm` required** (two new WASM exports). The MISP timestamp is `i64` on the wasm boundary → wrap with `BigInt()` in the TS wrapper (the STIX gotcha); CEF takes no timestamp (parameterless → no BigInt).
- Engine gates: fmt, clippy `-D warnings`, `test --workspace`, `--features online`, C-free. UI gate under the locked toolchain (vitest 1.6.1; 80/70) incl. `build:wasm`. Stage specific files.

## Reference: the seam to mirror (verbatim, verified)

```rust
// export/mod.rs: pub fn findings_csv(out)->String ; pub fn stix_bundle(out, generated_unix_secs:i64)->String
//   helpers: fn iso(secs:i64)->String (RFC3339) ; fn csv_field(s)->String ; fn det_uuid(seed:&str)->String (UUIDv5, FNV dual-pass)
//   struct IndicatorAcc { name, description, attack:BTreeSet<String> }
//   reads: out.summary.findings (Finding{kind,severity,score,src_ip,dst_ip:Option,dst_port:Option,attack:Vec,title,evidence:Vec}),
//          out.summary.ip_threats[].fingerprints (FingerprintHit{ja3:Option,ja4:Option,label}), out.summary.domain_threats, out.engine_version
// lib.rs: pub use export::{findings_csv, stix_bundle, …}
// ppcap-wasm/src/lib.rs:301 export_csv(output_json)->Result<String,JsValue> ; :308 export_stix(output_json, generated_unix_secs:i64)->Result<String,JsValue>
// src-tauri/src/lib.rs:303 save_csv(summary,path) ; save_stix(summary,path){stix_bundle(&summary, now_unix_secs())} ; export_csv(summary)->String ; export_stix(summary)->String ; generate_handler![…]
// ui/src/lib/wasmEngine.ts:104 exportCsvWasm(json) ; exportStixWasm(json, secs){ wasmExportStix(json, BigInt(secs)) }
// ui/src/lib/platform.ts: ExportResult{ok,message} ; captureBase(summary) ; downloadText(content,name,mime) ; copyText ;
//   exportCsv/exportStix (isTauri? save()+invoke save_* : wasm+downloadText) ; copyCsv/copyStix (isTauri? invoke export_* : wasm ; copyText)
// ui/src/components/layout/AppShell.tsx:139 exportActions = [report, csv, csv-copy, stix, stix-copy] ; :123 runExport(fn) surfaces res.message
//   (the onExport*/onCopy* callbacks are props to AppShell, wired in App.tsx)
```

## Components

### 1. Engine — `export/mod.rs`

**`pub fn misp_event(out: &AnalysisOutput, generated_unix_secs: i64) -> String`** — a MISP core-format Event:
```json
{ "Event": {
  "uuid": det_uuid("misp:event:{source_path}:{secs}"),
  "info": "PacketPilot analysis of {source_basename} — {N} findings",
  "date": "YYYY-MM-DD", "threat_level_id": "{1 high|2 medium|3 low|4 undefined from max severity}",
  "analysis": "2", "published": false, "timestamp": "{secs}",
  "Attribute": [ … ], "Tag": [ … ]
}}
```
Attributes (each with a stable `uuid: det_uuid(...)`, `to_ids`, `comment`):
- external dst IPs from findings → `{ type:"ip-dst", category:"Network activity", value, to_ids:true, comment: finding.title }` (deduped, deterministic order).
- `domain_threats` → `{ type:"domain", category:"Network activity", value: host, to_ids: <has a malicious reputation verdict>, comment }`.
- `ip_threats[].fingerprints` → `{ type:"ja3-fingerprint-md5", value: ja3, comment: label }` and, for ja4, `{ type:"ja4", value: ja4, comment: label }` (deduped across IPs).

Event `Tag`s: the union of ATT&CK ids → `{ "name": "misp-galaxy:mitre-attack-pattern=\"{T-id}\"" }` (or `{ "name":"mitre-attack:{T-id}" }` — pick one, document it).

`threat_level_id` from the highest `severity_counts` band present (critical/high→1, medium→2, low→3, else 4). `date` from `iso`-style YYYY-MM-DD of `generated_unix_secs`.

**`pub fn cef_records(out: &AnalysisOutput) -> String`** — one CEF line per `Finding`:
```
CEF:0|PacketPilot|PacketPilot|{out.engine_version}|{f.kind.as_str()}|{f.title}|{sev 0-10}|{ext}
```
`sev`: critical=10, high=8, medium=5, low=3, info=1 (from `f.severity`). `ext` = space-joined `key=value` with `cef_escape` (escape `\`→`\\`, `|`→`\|`, `=`→`\=`, newline→`\n` in values): `src={f.src_ip} dst={f.dst_ip?} dpt={f.dst_port?} cs1Label=ATT&CK cs1={f.attack.join(",")} cn1Label=score cn1={f.score} msg={f.evidence.join("; ")}`. Lines joined by `\n`. Empty findings → empty string.

Add `fn cef_escape(s: &str) -> String`. Re-export both fns from `lib.rs`.

### 2. WASM — `ppcap-wasm/src/lib.rs`
```rust
#[wasm_bindgen] pub fn export_misp(output_json: &str, generated_unix_secs: i64) -> Result<String, JsValue>  // parse → misp_event
#[wasm_bindgen] pub fn export_cef(output_json: &str) -> Result<String, JsValue>                            // parse → cef_records
```

### 3. Tauri — `src-tauri/src/lib.rs`
`save_misp(summary,path){ write misp_event(&summary, now_unix_secs()) }`, `save_cef(summary,path){ write cef_records(&summary) }`, `export_misp(summary)->String`, `export_cef(summary)->String` (copy variants). Register all 4 in `generate_handler!`.

### 4. TS wrappers + platform — `wasmEngine.ts` + `platform.ts`
- `exportMispWasm(json, secs) { wasmExportMisp(json, BigInt(secs)) }`, `exportCefWasm(json)`.
- `exportMisp`/`copyMisp` (filename `{base}-misp.json`, mime `application/json`, MISP needs `Math.floor(Date.now()/1000)`), `exportCef`/`copyCef` (filename `{base}-cef.txt`, mime `text/plain`). All mirror `exportStix`/`copyStix` exactly (isTauri save-dialog+invoke vs wasm+downloadText / copy).

### 5. UI — `AppShell.tsx` + `App.tsx`
Add 4 `exportActions`: `misp` (download), `misp-copy`, `cef` (download), `cef-copy`. Thread the 4 callbacks (`onExportMisp`/`onCopyMisp`/`onExportCef`/`onCopyCef`) as AppShell props, wired in App.tsx to `exportMisp`/`copyMisp`/`exportCef`/`copyCef` (mirroring the existing STIX callback wiring). The flat menu grows 5→9 (acceptable; matches the pattern).

## Data flow & error handling

`AnalysisOutput.summary` → `misp_event`/`cef_records` → string → (desktop) Tauri save/copy command / (browser) WASM export → blob download / clipboard. Empty findings/threats → a valid empty MISP event (no Attributes) / empty CEF string. A failed save/copy → `{ ok:false, message }` (no throw). Old captures (no fingerprints/domain_threats via `#[serde(default)]`) → those attribute sections are simply empty.

## Testing

- **Engine:** `misp_event` → parses as JSON, has `Event.Attribute` entries for a fixture with an external IP + a domain + a fingerprint, ATT&CK tags present, `threat_level_id` matches the max severity, deterministic (same input → identical bytes); `cef_records` → one `CEF:0|PacketPilot|…` line per finding, the severity maps correctly, `cef_escape` escapes `|`/`=`/`\`/newline, empty findings → `""`. Reuse the existing export-test fixtures.
- **Cross-surface:** the WASM `export_misp`/`export_cef` round-trip a fixture; the BigInt path for MISP mirrors STIX.
- **UI:** the 4 new `platform.ts` fns route desktop vs browser correctly (mock like the existing exportStix/copyStix tests); the 4 new `ExportMenu` actions invoke them. Coverage ≥ 80/70 under the locked toolchain incl. `build:wasm`.

## Out of scope

- Sigma-rule generation (RuleForge); TAXII push; per-flow CEF; a grouped/submenu export dropdown; MISP object templates (flat Attributes only).

## File manifest

**Engine — modify:** `engine/crates/ppcap-core/src/export/mod.rs` (`misp_event` + `cef_records` + `cef_escape`), `engine/crates/ppcap-core/src/lib.rs` (re-export), `engine/crates/ppcap-wasm/src/lib.rs` (`export_misp`/`export_cef`), `ui/src-tauri/src/lib.rs` (`save_misp`/`save_cef`/`export_misp`/`export_cef` + register).
**UI — modify:** `ui/src/lib/wasmEngine.ts` (`exportMispWasm`/`exportCefWasm`), `ui/src/lib/platform.ts` (`exportMisp`/`copyMisp`/`exportCef`/`copyCef`), `ui/src/components/layout/AppShell.tsx` (4 actions + props), `ui/src/App.tsx` (wire the 4 callbacks) + co-located tests.
**No new deps; STIX/CSV exporters untouched.**
