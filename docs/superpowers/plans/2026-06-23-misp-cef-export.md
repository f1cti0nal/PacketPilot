# MISP + CEF export — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit findings as MISP-event JSON and CEF (syslog/ArcSight) — extend the STIX/CSV export seam with two SOC-friendly formats.

**Architecture:** Two new pure engine fns (`misp_event`, `cef_records`) next to `findings_csv`/`stix_bundle`, mirrored across WASM → Tauri (save+copy) → `platform.ts` (export+copy) → `ExportMenu` actions exactly as STIX/CSV are. Deterministic (reuse `det_uuid`); `ExportResult` no-throw; MISP `i64`→`BigInt`.

**Tech Stack:** Rust (`ppcap-core`/`ppcap-wasm`/`src-tauri`); React 18 + TS; Vitest. No new deps.

## Global Constraints

- **Mirror the STIX/CSV seam exactly** — `findings_csv`/`stix_bundle` + callers untouched. Pure/deterministic/no-panic; reuse `det_uuid`.
- **No new deps** (MISP via `serde_json::json!`; CEF via `String` + a `cef_escape`).
- **`ExportResult` no-throw** in the UI; cancelled save → `{ ok:false, message:"" }`.
- **`build:wasm` required.** MISP timestamp `i64` on the wasm boundary → `BigInt()` in the TS wrapper (the STIX gotcha); CEF parameterless (no BigInt).
- Engine gates: fmt, clippy `-D warnings`, `test --workspace`, `--features online`, C-free. UI gate (vitest 1.6.1; 80/70) incl. `build:wasm`. Stage specific files.
- **TOOLCHAIN:** cargo `/c/Users/ravid/.cargo/bin` (from `engine/`), MinGW `/c/Users/ravid/opt/mingw64/bin` (src-tauri/online), node `/c/Program Files/nodejs`. `cargo fmt` before each engine commit; do NOT `npm install`.

## Reference: the seam to mirror (verbatim, verified)

```rust
// export/mod.rs: findings_csv(out)->String ; stix_bundle(out, generated_unix_secs:i64)->String
//   fn iso(secs:i64)->String (RFC3339) ; fn csv_field(s)->String ; fn det_uuid(seed:&str)->String (UUIDv5)
//   reads out.summary.{findings, ip_threats[].fingerprints, domain_threats, severity_counts}, out.engine_version
//   Finding { kind, severity, score, src_ip:String, dst_ip:Option<String>, dst_port:Option<u16>, attack:Vec<String>, title, evidence:Vec<String> }
//   FingerprintHit { ja3:Option<String>, ja4:Option<String>, label:String } ; DomainThreat { host, …, reputation:Vec<ReputationVerdict> }
// lib.rs: pub use export::{findings_csv, stix_bundle, …}
// ppcap-wasm/src/lib.rs:301 export_csv(json)->Result<String,JsValue> ; :308 export_stix(json, i64)->Result<String,JsValue>
// src-tauri/src/lib.rs: save_csv(summary,path) ; save_stix(summary,path){stix_bundle(&summary, now_unix_secs())} ;
//   export_csv(summary)->String ; export_stix(summary)->String ; generate_handler![ analyze_capture, save_report, save_csv, save_stix, export_csv, export_stix, … ]
// wasmEngine.ts:104 exportCsvWasm(json) ; exportStixWasm(json, secs){ wasmExportStix(json, BigInt(secs)) } (wasm imports: export_csv as wasmExportCsv, export_stix as wasmExportStix)
// platform.ts: ExportResult{ok,message} ; captureBase(summary) ; downloadText(content,name,mime) ; copyText(s) ;
//   exportStix(summary){ name=`${captureBase}-stix.json`; isTauri? save()+invoke("save_stix",{summary,path}) : exportStixWasm(JSON.stringify(summary), Math.floor(Date.now()/1000))+downloadText } ;
//   copyStix(summary){ isTauri? invoke("export_stix",{summary}) : exportStixWasm(...) ; copyText }
// AppShell.tsx:139 exportActions=[{report},{csv},{csv-copy},{stix},{stix-copy}] (props: onExport, onExportCsv, onCopyCsv, onExportStix, onCopyStix) ; :123 runExport(fn) surfaces res.message
//   App.tsx wires onExportStix={() => exportStix(summary)} etc. to AppShell (find it).
```

---

### Task 1: Engine — `misp_event` + `cef_records`

**Files:**
- Modify: `engine/crates/ppcap-core/src/export/mod.rs` (`misp_event` + `cef_records` + `cef_escape`), `engine/crates/ppcap-core/src/lib.rs` (re-export)
- Test: in `export/mod.rs` (or the existing export test file)

**Interfaces:**
- Produces: `misp_event(out: &AnalysisOutput, generated_unix_secs: i64) -> String`; `cef_records(out: &AnalysisOutput) -> String`.

- [ ] **Step 1: Write the failing test** — add to the export tests (reuse the existing fixture that builds an `AnalysisOutput` with findings + an ip_threat + a domain_threat — search the export tests for it):

```rust
#[test]
fn misp_event_has_attributes_and_is_deterministic() {
    let out = sample_output_with_findings(); // reuse the existing export-test fixture
    let s = misp_event(&out, 1_700_000_000);
    let v: serde_json::Value = serde_json::from_str(&s).expect("valid JSON");
    assert_eq!(v["Event"]["analysis"], "2");
    let attrs = v["Event"]["Attribute"].as_array().unwrap();
    assert!(attrs.iter().any(|a| a["type"] == "ip-dst"));   // an external dst IP from a finding
    // deterministic:
    assert_eq!(s, misp_event(&out, 1_700_000_000));
}

#[test]
fn cef_records_one_escaped_line_per_finding() {
    let out = sample_output_with_findings();
    let s = cef_records(&out);
    let lines: Vec<&str> = s.lines().collect();
    assert_eq!(lines.len(), out.summary.findings.len());
    assert!(lines.iter().all(|l| l.starts_with("CEF:0|PacketPilot|PacketPilot|")));
    // severity is a 0-10 int in the 7th pipe field
    let f0 = &out.summary.findings[0];
    assert!(lines[0].contains(&format!("|{}|", cef_severity(f0.severity))));
}

#[test]
fn cef_escape_escapes_specials() {
    assert_eq!(cef_escape("a|b=c\\d"), "a\\|b\\=c\\\\d");
}

#[test]
fn empty_summary_exports_are_valid() {
    let out = empty_output(); // reuse an existing empty-AnalysisOutput helper
    assert!(serde_json::from_str::<serde_json::Value>(&misp_event(&out, 0)).is_ok());
    assert_eq!(cef_records(&out), "");
}
```

> NOTE: reuse the REAL export-test fixtures (`sample_output_with_findings`/`empty_output` are placeholders — find the fixture the `findings_csv`/`stix_bundle` tests use). `cef_severity`/`cef_escape` are helpers you add. `Severity` + the structs are already in scope in `export/mod.rs`.

- [ ] **Step 2: Run it to verify it fails** — `cd engine && cargo test -p ppcap-core misp_event cef_records` → FAIL.

- [ ] **Step 3: Implement** — in `export/mod.rs` add:

```rust
/// Escape a CEF extension value (CEF spec: backslash, pipe, equals, newline).
fn cef_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|").replace('=', "\\=").replace('\n', "\\n").replace('\r', "")
}

/// CEF severity 0..=10 from the engine severity band.
fn cef_severity(sev: Severity) -> u8 {
    match sev {
        Severity::Critical => 10,
        Severity::High => 8,
        Severity::Medium => 5,
        Severity::Low => 3,
        Severity::Info => 1,
    }
}

/// MISP `threat_level_id` (1 High, 2 Medium, 3 Low, 4 Undefined) from the worst band present.
fn misp_threat_level(sc: &crate::model::summary::SeverityCounts) -> &'static str {
    if sc.critical > 0 || sc.high > 0 { "1" } else if sc.medium > 0 { "2" } else if sc.low > 0 { "3" } else { "4" }
}

/// Render the analysis as a MISP core-format Event JSON (flat Attributes). Deterministic;
/// `generated_unix_secs` stamps the event date/timestamp.
pub fn misp_event(out: &AnalysisOutput, generated_unix_secs: i64) -> String {
    use std::collections::{BTreeMap, BTreeSet};
    let date = iso(generated_unix_secs).split('T').next().unwrap_or("1970-01-01").to_string();
    let base = out.source_path.rsplit(['/', '\\']).next().unwrap_or("capture");

    let mut attrs: Vec<serde_json::Value> = Vec::new();
    let mut techniques: BTreeSet<String> = BTreeSet::new();
    let mut seen_ip: BTreeSet<String> = BTreeSet::new();

    let attr = |type_: &str, value: &str, to_ids: bool, comment: &str| {
        serde_json::json!({
            "uuid": det_uuid(&format!("misp:attr:{type_}:{value}")),
            "type": type_, "category": "Network activity",
            "value": value, "to_ids": to_ids, "comment": comment
        })
    };

    for f in &out.summary.findings {
        for a in &f.attack { techniques.insert(a.clone()); }
        if let Some(dst) = &f.dst_ip {
            if seen_ip.insert(dst.clone()) {
                attrs.push(attr("ip-dst", dst, true, &f.title));
            }
        }
    }
    for d in &out.summary.domain_threats {
        let mal = d.reputation.iter().any(|r| r.status == "malicious");
        attrs.push(attr("domain", &d.host, mal, ""));
    }
    let mut fps: BTreeMap<String, &crate::model::summary::FingerprintHit> = BTreeMap::new();
    for t in &out.summary.ip_threats {
        for fp in &t.fingerprints {
            fps.entry(format!("{}|{}|{}", fp.ja3.as_deref().unwrap_or(""), fp.ja4.as_deref().unwrap_or(""), fp.label)).or_insert(fp);
        }
    }
    for fp in fps.values() {
        if let Some(j) = &fp.ja3 { attrs.push(attr("ja3-fingerprint-md5", j, true, &fp.label)); }
        if let Some(j) = &fp.ja4 { attrs.push(attr("ja4", j, true, &fp.label)); }
    }

    let tags: Vec<serde_json::Value> = techniques.iter()
        .map(|t| serde_json::json!({ "name": format!("mitre-attack:{t}") }))
        .collect();

    let event = serde_json::json!({ "Event": {
        "uuid": det_uuid(&format!("misp:event:{}:{generated_unix_secs}", out.source_path)),
        "info": format!("PacketPilot analysis of {base} — {} findings", out.summary.findings.len()),
        "date": date,
        "threat_level_id": misp_threat_level(&out.summary.severity_counts),
        "analysis": "2", "published": false,
        "timestamp": generated_unix_secs.to_string(),
        "Attribute": attrs, "Tag": tags
    }});
    serde_json::to_string_pretty(&event).unwrap_or_else(|_| "{}".to_string())
}

/// Render the findings as CEF (one line per finding; ArcSight/syslog). Empty findings → "".
pub fn cef_records(out: &AnalysisOutput) -> String {
    let mut lines: Vec<String> = Vec::new();
    for f in &out.summary.findings {
        let mut ext = format!("src={}", cef_escape(&f.src_ip));
        if let Some(d) = &f.dst_ip { ext.push_str(&format!(" dst={}", cef_escape(d))); }
        if let Some(p) = f.dst_port { ext.push_str(&format!(" dpt={p}")); }
        if !f.attack.is_empty() { ext.push_str(&format!(" cs1Label=ATT&CK cs1={}", cef_escape(&f.attack.join(",")))); }
        ext.push_str(&format!(" cn1Label=score cn1={}", f.score));
        if !f.evidence.is_empty() { ext.push_str(&format!(" msg={}", cef_escape(&f.evidence.join("; ")))); }
        lines.push(format!(
            "CEF:0|PacketPilot|PacketPilot|{}|{}|{}|{}|{}",
            cef_escape(&out.engine_version),
            cef_escape(f.kind.as_str()),
            cef_escape(&f.title),
            cef_severity(f.severity),
            ext
        ));
    }
    lines.join("\n")
}
```
Re-export from `lib.rs`: extend `pub use export::{…}` with `cef_records, misp_event`.

> NOTE: confirm the exact `Severity` enum path + variants, `SeverityCounts` field names (`critical/high/medium/low/info`), and `ReputationVerdict.status` type (it's a `String` or an enum — match `r.status == "malicious"` to the real type; if `status` is an enum, compare to its variant). The CEF header field 5 (`f.kind.as_str()`) is the signature id; field 6 (`f.title`) the name. Note: the pipe-delimited CEF *header* fields also technically need `\|` escaping — `cef_escape` covers it (it escapes `=` too, which is harmless in the header).

- [ ] **Step 4: Run it to verify it passes** — `cd engine && cargo test -p ppcap-core export` → PASS. `cargo fmt && cargo clippy -p ppcap-core --all-targets -- -D warnings` → clean.

- [ ] **Step 5: Commit**

```bash
cd engine && cargo fmt
git add engine/crates/ppcap-core/src/export/mod.rs engine/crates/ppcap-core/src/lib.rs
git commit -m "feat(engine): MISP-event + CEF exporters"
```

---

### Task 2: WASM exports + Tauri commands

**Files:**
- Modify: `engine/crates/ppcap-wasm/src/lib.rs` (`export_misp`/`export_cef`), `ui/src-tauri/src/lib.rs` (`save_misp`/`save_cef`/`export_misp`/`export_cef` + register)

**Interfaces:**
- Consumes: `ppcap_core::export::{misp_event, cef_records}`.

- [ ] **Step 1: Write the failing test** — add to ppcap-wasm tests (or assert via the src-tauri build): a small test that `export_cef`'s logic produces a `CEF:0|` line for a fixture. (If wasm-bindgen exports are awkward to unit-test, the gate is `cargo build -p ppcap-wasm` + `cd ui/src-tauri && cargo build`; T1 already covers correctness.) Prefer a tiny Rust test on the wasm `export_*` if feasible; else make this task's verification the two builds.

- [ ] **Step 2: Run/verify the baseline** — `cd engine && cargo build -p ppcap-wasm` builds before the change.

- [ ] **Step 3: Implement** —
(a) `ppcap-wasm/src/lib.rs` (mirror `export_csv`/`export_stix` at ~:301):
```rust
#[wasm_bindgen]
pub fn export_misp(output_json: &str, generated_unix_secs: i64) -> Result<String, JsValue> {
    let out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(ppcap_core::export::misp_event(&out, generated_unix_secs))
}

#[wasm_bindgen]
pub fn export_cef(output_json: &str) -> Result<String, JsValue> {
    let out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(ppcap_core::export::cef_records(&out))
}
```
(b) `src-tauri/src/lib.rs` (mirror `save_stix`/`export_stix`):
```rust
#[tauri::command]
fn save_misp(summary: AnalysisOutput, path: String) -> Result<(), String> {
    let s = ppcap_core::export::misp_event(&summary, now_unix_secs());
    std::fs::write(&path, s).map_err(|e| format!("write misp: {e}"))
}
#[tauri::command]
fn save_cef(summary: AnalysisOutput, path: String) -> Result<(), String> {
    let s = ppcap_core::export::cef_records(&summary);
    std::fs::write(&path, s).map_err(|e| format!("write cef: {e}"))
}
#[tauri::command]
fn export_misp(summary: AnalysisOutput) -> Result<String, String> {
    Ok(ppcap_core::export::misp_event(&summary, now_unix_secs()))
}
#[tauri::command]
fn export_cef(summary: AnalysisOutput) -> Result<String, String> {
    Ok(ppcap_core::export::cef_records(&summary))
}
```
Add `save_misp, save_cef, export_misp, export_cef` to `generate_handler!`.

- [ ] **Step 4: Verify** — `cd engine && cargo build -p ppcap-wasm`; `cd ui/src-tauri && export PATH="/c/Users/ravid/opt/mingw64/bin:/c/Users/ravid/.cargo/bin:$PATH" && cargo build` → both clean. `cargo fmt && cargo clippy -p ppcap-core -p ppcap-wasm --all-targets -- -D warnings` (from engine/) → clean.

- [ ] **Step 5: Commit**

```bash
cd engine && cargo fmt
git add engine/crates/ppcap-wasm/src/lib.rs ui/src-tauri/src/lib.rs
git commit -m "feat(engine): MISP/CEF WASM exports + Tauri save/export commands"
```

---

### Task 3: TS wrappers + platform router

**Files:**
- Modify: `ui/src/lib/wasmEngine.ts` (`exportMispWasm`/`exportCefWasm`), `ui/src/lib/platform.ts` (`exportMisp`/`copyMisp`/`exportCef`/`copyCef`)
- Test: `ui/src/lib/platform.test.ts` (mirror the exportStix/copyStix tests)

**Interfaces:**
- Produces: `exportMisp`/`copyMisp`/`exportCef`/`copyCef` returning `ExportResult`.

- [ ] **Step 1: Write the failing test** — mirror the existing `exportStix`/`copyStix` tests (browser → wasm + downloadText; copy → copyText). Add cases for `exportMisp` (browser → `exportMispWasm` + download) and `exportCef`.

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/lib/platform.test.ts` → FAIL.

- [ ] **Step 3: Implement** —
(a) `wasmEngine.ts`: add `export_misp as wasmExportMisp, export_cef as wasmExportCef` to the wasm import + 
```ts
export async function exportMispWasm(outputJson: string, generatedUnixSecs: number): Promise<string> {
  await ensureWasm();
  return wasmExportMisp(outputJson, BigInt(generatedUnixSecs));
}
export async function exportCefWasm(outputJson: string): Promise<string> {
  await ensureWasm();
  return wasmExportCef(outputJson);
}
```
(b) `platform.ts`: add (mirror `exportStix`/`copyStix` exactly):
```ts
export async function exportMisp(summary: AnalysisOutput): Promise<ExportResult> {
  const name = `${captureBase(summary)}-misp.json`;
  if (isTauri()) {
    const path = await save({ defaultPath: name, filters: [{ name: "MISP event", extensions: ["json"] }] });
    if (!path) return { ok: false, message: "" };
    try { await invoke("save_misp", { summary, path }); return { ok: true, message: "MISP event saved" }; }
    catch (e) { return { ok: false, message: `Save failed: ${e}` }; }
  }
  try { downloadText(await exportMispWasm(JSON.stringify(summary), Math.floor(Date.now() / 1000)), name, "application/json"); return { ok: true, message: "Downloaded" }; }
  catch (e) { return { ok: false, message: `Export failed: ${e}` }; }
}
export async function exportCef(summary: AnalysisOutput): Promise<ExportResult> {
  const name = `${captureBase(summary)}-cef.txt`;
  if (isTauri()) {
    const path = await save({ defaultPath: name, filters: [{ name: "CEF", extensions: ["txt", "cef"] }] });
    if (!path) return { ok: false, message: "" };
    try { await invoke("save_cef", { summary, path }); return { ok: true, message: "CEF saved" }; }
    catch (e) { return { ok: false, message: `Save failed: ${e}` }; }
  }
  try { downloadText(await exportCefWasm(JSON.stringify(summary)), name, "text/plain"); return { ok: true, message: "Downloaded" }; }
  catch (e) { return { ok: false, message: `Export failed: ${e}` }; }
}
export async function copyMisp(summary: AnalysisOutput): Promise<ExportResult> {
  try {
    const s = isTauri() ? await invoke<string>("export_misp", { summary }) : await exportMispWasm(JSON.stringify(summary), Math.floor(Date.now() / 1000));
    return copyText(s);
  } catch (e) { return { ok: false, message: `Copy failed: ${e}` }; }
}
export async function copyCef(summary: AnalysisOutput): Promise<ExportResult> {
  try {
    const s = isTauri() ? await invoke<string>("export_cef", { summary }) : await exportCefWasm(JSON.stringify(summary));
    return copyText(s);
  } catch (e) { return { ok: false, message: `Copy failed: ${e}` }; }
}
```

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/lib/platform.test.ts` → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 5: Commit**

```bash
git add ui/src/lib/wasmEngine.ts ui/src/lib/platform.ts ui/src/lib/platform.test.ts
git commit -m "feat(ui): MISP/CEF export+copy platform routers"
```

---

### Task 4: ExportMenu actions + App wiring

**Files:**
- Modify: `ui/src/components/layout/AppShell.tsx` (4 actions + 4 props), `ui/src/App.tsx` (wire the 4 callbacks)
- Test: the AppShell test (if present) — else rely on the gate

**Interfaces:**
- Consumes: `exportMisp`/`copyMisp`/`exportCef`/`copyCef` (T3).

- [ ] **Step 1: Read the existing STIX wiring** — in `App.tsx`, find where `onExportStix`/`onCopyStix` are passed to `<AppShell>` (they call `exportStix`/`copyStix` from platform.ts with the current summary). In `AppShell.tsx`, find the `onExportStix`/`onCopyStix` prop declarations + the `stix`/`stix-copy` `exportActions` entries + the `runExport` deps.

- [ ] **Step 2: Implement** —
(a) `AppShell.tsx`: add 4 props `onExportMisp`, `onCopyMisp`, `onExportCef`, `onCopyCef` (same type as `onExportStix`); add 4 `exportActions` entries after the STIX ones:
```tsx
    { id: "misp", label: "MISP event — download", run: () => void runExport(onExportMisp) },
    { id: "misp-copy", label: "MISP event — copy", run: () => void runExport(onCopyMisp) },
    { id: "cef", label: "CEF — download", run: () => void runExport(onExportCef) },
    { id: "cef-copy", label: "CEF — copy", run: () => void runExport(onCopyCef) },
```
and add the 4 new callbacks to the `useMemo` deps.
(b) `App.tsx`: wire the 4 props on `<AppShell …>` exactly like `onExportStix`/`onCopyStix` (calling `exportMisp(summary)`/`copyMisp(summary)`/`exportCef(summary)`/`copyCef(summary)` — import them from platform.ts).

- [ ] **Step 3: Verify** — `cd ui && npx vitest run` for the AppShell/App tests (`grep -rl "AppShell\|exportActions" ui/src --include=*.test.tsx`) → green. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 4: Commit**

```bash
git add ui/src/components/layout/AppShell.tsx ui/src/App.tsx
# + any AppShell test
git commit -m "feat(ui): MISP/CEF entries in the export menu"
```

---

### Task 5: Full gate

- [ ] **Step 1: Engine gate** — `export PATH="/c/Users/ravid/opt/mingw64/bin:/c/Users/ravid/.cargo/bin:$PATH"`, from `engine/`:
```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p ppcap-core --features online
```
All green.

- [ ] **Step 2: UI gate** — `cd ui && export PATH="/c/Program Files/nodejs:/c/Users/ravid/.cargo/bin:$PATH"`:
```bash
git diff --stat package.json package-lock.json
git checkout -- package.json package-lock.json 2>/dev/null || true
npm ci
node -p "require('./node_modules/vitest/package.json').version"   # 1.6.1
npm run build:wasm
npm run build; echo "build EXIT: $?"          # EXIT 0
npm run test:coverage; echo "cov EXIT: $?"    # EXIT 0; All files >= 80/70 — paste it
```
Do NOT `npm install`.

- [ ] **Step 3: Fill any gap** — if a metric dips from the new platform/AppShell code, add a focused test and re-run.

- [ ] **Step 4: Commit** (if tests added)

```bash
git add ui/src/<new/updated tests>
git commit -m "test: hold the gate for MISP/CEF export"
```

---

## Self-Review

**1. Spec coverage:** engine `misp_event`/`cef_records` (T1) → spec §1; WASM/Tauri (T2) → §2-3; TS wrappers+platform (T3) → §4; ExportMenu+App (T4) → §5; gate (T5). Mirror STIX/CSV, no new deps, ExportResult no-throw, MISP i64→BigInt, CEF parameterless — all covered. Sigma/TAXII out of scope. ✓

**2. Placeholder scan:** complete code for both exporters, the wasm/tauri commands, the TS routers. The NOTEs (reuse the real export-test fixtures; confirm Severity/SeverityCounts/ReputationVerdict.status exact types; find the App.tsx STIX wiring to mirror) are concrete in-repo verifications. ✓

**3. Type/consistency:** `misp_event(out, i64)`/`cef_records(out)` (T1 engine) ⇄ `export_misp(json, i64)`/`export_cef(json)` (T2 wasm) ⇄ `exportMispWasm(json, secs→BigInt)`/`exportCefWasm(json)` (T3) ⇄ `exportMisp`/`copyMisp`/`exportCef`/`copyCef` (T3 platform) ⇄ the 4 ExportMenu actions + App callbacks (T4). The Tauri save/export command names match the platform `invoke(...)` strings. MISP carries the timestamp (BigInt path); CEF doesn't. All consistent. ✓
