# Rule import — in-app surface (phase B) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose engine `apply_rules` to the browser (WASM) + desktop (Tauri) and add a "Load detection rules" UI action that folds matches into the displayed summary.

**Architecture:** Mirror the carve/reputation cross-surface seam. One "parse + apply + fold" entry per runtime returns the updated `AnalysisOutput` + `{loaded, skipped, matches}`. The UI applies over a per-capture base snapshot (no clobber / no stacking). No consent (local/offline).

**Tech Stack:** Rust (ppcap-wasm, src-tauri) + React/TS. No new deps.

## Global Constraints

- **No new deps.** WASM path stays C-free + wasm-safe (`apply_rules`/`parse_rules` already pure compute). Engine-core unchanged (phase A reused).
- **No clobber / no stacking** — apply over a captured pre-rules base (preserves reputation, prevents re-load duplication).
- **No-throw at the boundary** — malformed rules → a `skipped` count; source-not-retained disables the action.
- Run cargo from `engine/` for ppcap-wasm; `cargo check` for src-tauri (PATH must include MinGW `/c/Users/ravid/opt/mingw64/bin` + cargo). UI: node at `/c/Program Files/nodejs`; `npm run build:wasm` regenerates bindings; gate 80/70 (vitest 1.6.1).
- ⚠️ The full Tauri desktop build is the (billing-blocked) CI job — the Tauri task verifies via `cargo check` on src-tauri + WASM parity, NOT a full bundle.

## Reference: the seams (verified)

```
// engine/crates/ppcap-wasm/src/lib.rs:277 #[wasm_bindgen] apply_reputation(output_json, verdicts_json)->Result<String,JsValue> (parse AnalysisOutput→mutate→to_json) ← MIRROR ; :86 carve_pcap(bytes,..) bytes-in ; :339 analyze(bytes,name)
// ppcap-core: parse_rules(text)->RuleParse{rules,skipped}, apply_rules<R:Read+'static>(reader,len,&[Rule])->Vec<Finding>, Summary::apply_findings(&[Finding])
// ui/src-tauri/src/lib.rs:134 carve_pcap_to(path_in, query, path_out)->Result<u64,String> (path-reread command) + the generate_handler! list (find it) ← MIRROR
// ui/src/lib/wasmEngine.ts:78 applyReputationWasm (wasm wrapper) ; ui/src/lib/platform.ts IS_TAURI branch + carveSubPcap (bytes→wasm/path→tauri) ; packetsAvailable(source)
// ui/src/App.tsx:113 [summary,setSummary] ; enrichAndCommit ; captureKey(output:{source_sha256,source_path}) from ui/src/lib/ai/cache.ts:35
// ui/src/cockpit/AppShell.tsx paletteActions/exportActions (⌘K)
```

---

### Task 1: WASM `apply_rules` export + `RuleApplyResult`

**Files:**
- Modify: `engine/crates/ppcap-wasm/src/lib.rs`

**Interfaces:**
- Produces: `#[wasm_bindgen] apply_rules(bytes, rules_text, output_json) -> String` (a `RuleApplyResult` JSON).

- [ ] **Step 1: Write the failing test** — in `ppcap-wasm` tests (mirror an existing wasm test that builds a pcap; reuse the analyze/carve fixture):
```rust
#[test]
fn apply_rules_folds_matches_into_output() {
    let pcap = /* a crafted TCP/443 pcap whose payload contains "abc" — reuse the existing test pcap helper */;
    let out_json = crate::analyze(&pcap, "t.pcap".into()).unwrap();   // base AnalysisOutput JSON
    let rules = r#"alert tcp any any -> any 443 (msg:"hit"; content:"abc"; sid:7; metadata:mitre T1071;)"#;
    let res_json = crate::apply_rules(&pcap, rules, &out_json).unwrap();
    let v: serde_json::Value = serde_json::from_str(&res_json).unwrap();
    assert_eq!(v["loaded"], 1);
    assert_eq!(v["skipped"], 0);
    assert!(v["matches"].as_u64().unwrap() >= 1);
    // the finding is folded into output.summary.findings
    let findings = v["output"]["summary"]["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["title"] == "hit"));
}
```
> NOTE: reuse the ppcap-wasm test's existing pcap fixture (grep the test module for how `analyze`/`carve_pcap` tests build their bytes); craft the payload to contain `abc`.

- [ ] **Step 2: Run to verify it fails** — `cd engine/crates/ppcap-wasm && cargo test --target x86_64-pc-windows-gnu apply_rules` → FAIL.

- [ ] **Step 3: Implement** — in `ppcap-wasm/src/lib.rs`:
```rust
#[derive(serde::Serialize)]
struct RuleApplyResult {
    output: ppcap_core::AnalysisOutput,
    loaded: usize,
    skipped: usize,
    matches: usize,
}

/// Parse a ruleset, apply it over the pcap `bytes`, and fold the matches into `output_json`.
#[wasm_bindgen]
pub fn apply_rules(bytes: &[u8], rules_text: &str, output_json: &str) -> Result<String, JsValue> {
    let mut out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let parsed = ppcap_core::parse_rules(rules_text);
    let owned = bytes.to_vec();
    let len = Some(owned.len() as u64);
    let rf = ppcap_core::apply_rules(std::io::Cursor::new(owned), len, &parsed.rules);
    out.summary.apply_findings(&rf);
    out.summary.findings.extend(rf.iter().cloned());
    let res = RuleApplyResult { matches: rf.len(), loaded: parsed.rules.len(), skipped: parsed.skipped.len(), output: out };
    serde_json::to_string(&res).map_err(|e| JsValue::from_str(&e.to_string()))
}
```
(Confirm `AnalysisOutput` is the correct re-exported type + that `apply_rules`/`parse_rules`/`apply_findings` are reachable from `ppcap_core::` — they were re-exported in phase A.)

- [ ] **Step 4: Run to verify it passes** — `cd engine/crates/ppcap-wasm && cargo test --target x86_64-pc-windows-gnu apply_rules` → PASS. `cargo fmt`.

- [ ] **Step 5: Commit**
```bash
git add engine/crates/ppcap-wasm/src/lib.rs engine/crates/ppcap-wasm/Cargo.lock
git commit -m "feat(wasm): apply_rules export (parse + apply + fold → RuleApplyResult)"
```

---

### Task 2: Tauri `apply_rules_to` command

**Files:**
- Modify: `ui/src-tauri/src/lib.rs`

**Interfaces:**
- Produces: `apply_rules_to(path, rules_text, output_json) -> Result<String, String>` (the same `RuleApplyResult` JSON), registered in `generate_handler!`.

- [ ] **Step 1: Implement** — mirror `carve_pcap_to` (:134):
```rust
#[derive(serde::Serialize)]
struct RuleApplyResult {
    output: ppcap_core::AnalysisOutput,
    loaded: usize,
    skipped: usize,
    matches: usize,
}

#[tauri::command]
fn apply_rules_to(path: String, rules_text: String, output_json: String) -> Result<String, String> {
    let mut out: ppcap_core::AnalysisOutput =
        serde_json::from_str(&output_json).map_err(|e| e.to_string())?;
    let parsed = ppcap_core::parse_rules(&rules_text);
    let file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
    let len = std::fs::metadata(&path).ok().map(|m| m.len());
    let rf = ppcap_core::apply_rules(file, len, &parsed.rules);
    out.summary.apply_findings(&rf);
    out.summary.findings.extend(rf.iter().cloned());
    let res = RuleApplyResult { matches: rf.len(), loaded: parsed.rules.len(), skipped: parsed.skipped.len(), output: out };
    serde_json::to_string(&res).map_err(|e| e.to_string())
}
```
Register `apply_rules_to` in the `tauri::generate_handler![ … ]` list (find it in `lib.rs`/`run()`).

- [ ] **Step 2: Verify it compiles** — `export PATH="/c/Users/ravid/opt/mingw64/bin:/c/Users/ravid/.cargo/bin:$PATH"; cd ui/src-tauri && cargo check 2>&1 | tail -8; echo "check EXIT: ${PIPESTATUS[0]}"` → 0. (The full `tauri build` is the CI desktop job — not run here; `cargo check` type-checks the command. If `cargo check` cannot run locally due to the desktop toolchain, REPORT it — the command is line-for-line parallel to `carve_pcap_to` + the WASM `apply_rules` which IS tested, so parity covers correctness.)

- [ ] **Step 3: Commit**
```bash
git add ui/src-tauri/src/lib.rs ui/src-tauri/Cargo.lock 2>/dev/null
git commit -m "feat(tauri): apply_rules_to command (path re-read → RuleApplyResult)"
```

---

### Task 3: `wasmEngine.applyRulesWasm` + `platform.applyRules`

**Files:**
- Modify: `ui/src/lib/wasmEngine.ts`, `ui/src/lib/platform.ts`
- Test: `ui/src/lib/platform.test.ts` (or co-located)

**Interfaces:**
- Consumes: the wasm `apply_rules` (T1) + the Tauri `apply_rules_to` (T2).
- Produces: `RuleApplyResult`, `applyRulesWasm`, `applyRules`.

- [ ] **Step 1: Write the failing test** — `applyRules` branches:
```ts
// mock wasmEngine.applyRulesWasm + the tauri invoke; assert:
// - {kind:"bytes"} → calls applyRulesWasm with the bytes + rules + output, returns the RuleApplyResult
// - {kind:"path"} (IS_TAURI) → invokes "apply_rules_to" with { path, rulesText, outputJson }
// - null source → throws/rejects a typed "source unavailable"
```
(Mirror the existing `carveSubPcap`/reputation platform tests' mocking style.)

- [ ] **Step 2: Run to verify it fails** — `cd ui && npx vitest run src/lib/platform.test.ts` → FAIL.

- [ ] **Step 3: Implement** —
  - `wasmEngine.ts`: `export interface RuleApplyResult { output: AnalysisOutput; loaded: number; skipped: number; matches: number }` (or define in platform.ts + import); `export async function applyRulesWasm(bytes: ArrayBuffer, rulesText: string, output: AnalysisOutput): Promise<RuleApplyResult> { const wasm = await loadWasm(); const json = wasm.apply_rules(new Uint8Array(bytes), rulesText, JSON.stringify(output)); return JSON.parse(json) as RuleApplyResult; }` (mirror `applyReputationWasm`'s loadWasm + JSON in/out).
  - `platform.ts`: 
```ts
export async function applyRules(rulesText: string, output: AnalysisOutput, source: ActiveSource): Promise<RuleApplyResult> {
  if (!source) throw new Error("Packets are only available for captures analyzed from a pcap");
  if (source.kind === "bytes") return applyRulesWasm(source.bytes, rulesText, output);
  // desktop path:
  const { invoke } = await import("@tauri-apps/api/core");
  const json = await invoke<string>("apply_rules_to", { path: source.path, rulesText, outputJson: JSON.stringify(output) });
  return JSON.parse(json) as RuleApplyResult;
}
```
(Confirm the Tauri arg naming convention — camelCase `rulesText`/`outputJson` ↔ the Rust snake `rules_text`/`output_json`; Tauri auto-converts. Match how `carveSubPcap` passes args.)

- [ ] **Step 4: Run to verify it passes** — `cd ui && npx vitest run src/lib/platform.test.ts` → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 5: Commit**
```bash
git add ui/src/lib/wasmEngine.ts ui/src/lib/platform.ts ui/src/lib/platform.test.ts
git commit -m "feat(ui): applyRules platform seam (bytes→wasm / path→tauri)"
```

---

### Task 4: UI load-rules action + `ruleBaseRef` (+ full gate)

**Files:**
- Modify: `ui/src/App.tsx` (the `loadRules` handler + `ruleBaseRef` + the notice + a hidden file input + the ⌘K palette action + a button)
- Test: `ui/src/App.test.tsx` (extend)

**Interfaces:**
- Consumes: `applyRules` (T3); `captureKey`; `packetsAvailable`.

- [ ] **Step 1: Write the failing test** — extend `App.test.tsx`: with a ready summary + a bytes `activeSource`, triggering the load-rules action with a `.rules` file calls `applyRules` and updates the displayed summary (mock `platform.applyRules` → a `RuleApplyResult` with a new finding + `matches:1`); the result notice shows "1 … 1 match"; re-loading reuses the same base (assert `applyRules` is called the 2nd time with the SAME base output object, not the rules-augmented one). (Mock at the `platform` module boundary.)
> NOTE: match how App.test.tsx drives actions (it may go through the ⌘K palette or a button); pick the most direct testable entry. If wiring a full file-input interaction is awkward in jsdom, expose `loadRules(file: File)` in a testable way and drive it, OR drive the palette action with a stubbed file.

- [ ] **Step 2: Run to verify it fails** — `cd ui && npx vitest run src/App.test.tsx` → FAIL.

- [ ] **Step 3: Implement** — in `App.tsx`:
  - `const ruleBaseRef = useRef<{ key: string; data: AnalysisOutput } | null>(null);`
  - `const [ruleNotice, setRuleNotice] = useState<string | null>(null);`
  - 
```tsx
const loadRules = useCallback(async (file: File) => {
  if (summary.status !== "ready" || !packetsAvailable(activeSource)) return;
  const text = await file.text();
  const key = captureKey(summary.data);
  const base = ruleBaseRef.current?.key === key ? ruleBaseRef.current.data : summary.data;
  if (ruleBaseRef.current?.key !== key) ruleBaseRef.current = { key, data: summary.data };
  try {
    const res = await applyRules(text, base, activeSource);
    setSummary({ status: "ready", data: res.output });
    setRuleNotice(`Rules: ${res.loaded} loaded, ${res.skipped} skipped, ${res.matches} match${res.matches === 1 ? "" : "es"}`);
  } catch (e) {
    setRuleNotice(e instanceof Error ? e.message : "Failed to apply rules");
  }
}, [summary, activeSource]);
```
  - A hidden `<input ref={rulesInputRef} type="file" accept=".rules,.txt" onChange={(e) => { const f = e.target.files?.[0]; if (f) void loadRules(f); e.target.value = ""; }} hidden />`.
  - A "Load detection rules…" entry: add to the ⌘K palette actions (in AppShell's `paletteActions` — pass a callback that triggers `rulesInputRef.current?.click()`) AND a small button (Dashboard or the shell), both gated on `packetsAvailable(activeSource)`.
  - Render `ruleNotice` as a transient line (near the dashboard/shell).

- [ ] **Step 4: Run to verify it passes** — `cd ui && npx vitest run src/App.test.tsx` → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 5: Commit**
```bash
git add ui/src/App.tsx ui/src/cockpit/AppShell.tsx ui/src/App.test.tsx
git commit -m "feat(ui): Load detection rules action (apply over a per-capture base snapshot)"
```

- [ ] **Step 6: Full gate** — UI: `cd ui && export PATH="/c/Program Files/nodejs:/c/Users/ravid/.cargo/bin:$PATH"`:
```bash
git checkout -- package.json package-lock.json 2>/dev/null || true
npm ci
node -p "require('./node_modules/vitest/package.json').version"   # 1.6.1
npm run build:wasm      # regenerate bindings incl. the new apply_rules
npm run build; echo "build EXIT: $?"          # 0
npm run test:coverage; echo "cov EXIT: $?"    # 0; All files >= 80/70 — paste it
```
Engine: `cd engine/crates/ppcap-wasm && cargo test --target x86_64-pc-windows-gnu 2>&1 | tail -6; echo "wasm test EXIT: ${PIPESTATUS[0]}"`. C-free unaffected (no core change). Lockfiles: commit `engine/crates/ppcap-wasm/Cargo.lock` if changed.

- [ ] **Step 7: Commit any gate fixups.**

---

## Self-Review

**1. Spec coverage:** WASM export (T1) → spec §1; Tauri command (T2) → §2; platform/wasm wrappers (T3) → §3; UI load action + ruleBaseRef + notice (T4) → §4 + gate. No-consent, no-clobber/no-stacking (base snapshot), no-throw, RuleApplyResult shape, no-deps — all covered. Dedicated panel + incident-correlation out of scope. ✓

**2. Placeholder scan:** complete code for the WASM export, the Tauri command, the platform/wasm wrappers, the `loadRules` handler; the NOTEs (reuse the ppcap-wasm pcap fixture; find the generate_handler list; the Tauri arg camelCase convention; the most-testable load entry; confirm AnalysisOutput re-export) are concrete in-repo verifications. ✓

**3. Type consistency:** `RuleApplyResult { output: AnalysisOutput, loaded, skipped, matches }` is defined identically in WASM (Serialize), Tauri (Serialize), and TS (interface) and returned by `applyRulesWasm`/`apply_rules_to`/`applyRules` ⇄ `loadRules` consumes `res.output`/`res.loaded`/`res.skipped`/`res.matches`. `captureKey(output)` keys the `ruleBaseRef`. `applyRules(rulesText, output, source)` ⇄ the bytes/path branch. ✓
