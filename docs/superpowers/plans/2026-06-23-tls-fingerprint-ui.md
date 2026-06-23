# TLS fingerprinting (JA3/JA4) — Sub-project B (UI + AI + export) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface A's JA3/JA4 fingerprints: per-flow values in the flows table/detail (pure UI), and a per-IP matched-malware rollup (`IpThreat.fingerprints`) driving a threat-card chip, the AI threat line, and STIX indicators.

**Architecture:** A small engine rollup threads the matched fingerprint (value + family) into `IpThreat.fingerprints` via a transient `FlowRecord.fingerprint_label` (no Parquet bump); the UI consumes A's already-present `FlowDto`/Parquet `ja3`/`ja4` for the flows table and `IpThreat.fingerprints` for the cards/AI/STIX.

**Tech Stack:** Rust (`ppcap-core`: model/analyze/stats/export); React 18 + TS; Vitest.

## Global Constraints

- **Flows-table layer is pure UI** — `ja3`/`ja4` already exist on A's `FlowDto`/Parquet; thread through `FlowRow` + the two mappers + render. Every flow's fingerprint shows here.
- **Cards / AI / STIX show ONLY the matched-malware subset** — surfaced only when a flow's fingerprint matched the feed (`fingerprint_label.is_some()`), carrying the family.
- **`FlowRecord.fingerprint_label` is transient** — set in the analyze pipeline, consumed by stats in the same pass; NOT a Parquet column, NOT in `FlowDto`. No `FLOW_PARQUET_VERSION` change.
- **`IpThreat.fingerprints` is `#[serde(default)]`** (+ TS optional) — old captures still deserialize.
- **No new deps, no consent, no WASM/Tauri command signature change.** `build:wasm` required (Summary JSON gains `ip_threats[].fingerprints`). UI gate under the locked toolchain (vitest 1.6.1; 80/70). Engine gates: fmt, clippy `-D warnings`, `test --workspace`.
- **TOOLCHAIN:** cargo `/c/Users/ravid/.cargo/bin` (run from `engine/`), MinGW `/c/Users/ravid/opt/mingw64/bin` for online; node/npx `/c/Program Files/nodejs`. `cargo fmt` before each engine commit; do NOT `npm install`. Stage specific files.

## Reference: the seams B touches (verbatim, verified)

```rust
// model/summary.rs:105 IpThreat { ip, ip_class, severity, score, flows, bytes, ioc, tags, attack, evidence, #[serde(default)] reputation }
// model/flow.rs FlowRecord { …, ja3:Option<String>, ja4:Option<String>, ioc } (A) ; ::new sets them None
// enrich/mod.rs FlowEnrichment { …, ja3_ioc, ja4_ioc, fingerprint_label:Option<String> } (A/T5)
// analyze/mod.rs:402-412
//   let enr = enricher.enrich(record);
//   let fm = enricher.feed_match(&enr);
//   let scored = score_flow(record, &fm);
//   record.severity = scored.severity; record.threat_score = scored.score; record.ioc = fm.any();
//   stats.observe_flow(record); stats.observe_scored_flow(record, &scored);
// stats/mod.rs:112 struct IpThreatStat { max_sev, max_score, flows, bytes, ioc, attack:BTreeSet<String>, evidence:Vec<String> }
// stats/mod.rs:314 observe_scored_flow(f,sc) — per_ip_threat.entry(ip); evidence reseed/dedup pattern
// stats/mod.rs:520 finish(): builds Vec<IpThreat> from per_ip_threat (tags, attack, evidence, reputation:Vec::new())
// export/mod.rs:98 stix_bundle indicator loop (det_uuid seed "indicator:{ip}", pattern "[ipv4-addr:value='{ip}']") ; :160 det_uuid
```
```ts
// ui/src/types.ts:254 RawFlowRow {…, sni:string|null, …} ; :285 WasmFlow {…, sni:string|null, …} ; :319 FlowRow {…, sni:string|null, …}
// ui/src/types.ts:112 ReputationVerdict ; :122 IpThreat { …, evidence:string[], reputation?:ReputationVerdict[] }
// ui/src/lib/data.ts:85 normalizeFlow (sni: r.sni,) ; :126 flowRowFromWasm (sni: r.sni ?? null,)
// ui/src/components/flows/FlowsTable.tsx:184 "Proto / App / SNI" cell (renders f.sni)
// ui/src/components/FlowDetail.tsx:378 "Application (L7)" Section (TLS SNI Field)
// ui/src/components/triage/ThreatsPanel.tsx:120 tags + ProviderVerdictList + EvidenceList ; :58 IOC chip markup
// ui/src/lib/ai/context.ts:30 threatLine(t) (appends reputation as source:status)
```

---

### Task 1: Engine rollup — `IpThreat.fingerprints` (+ transient `FlowRecord.fingerprint_label`)

**Files:**
- Modify: `engine/crates/ppcap-core/src/model/summary.rs` (`FingerprintHit` + `IpThreat.fingerprints`), `engine/crates/ppcap-core/src/model/flow.rs` (`FlowRecord.fingerprint_label`), `engine/crates/ppcap-core/src/analyze/mod.rs` (set it), `engine/crates/ppcap-core/src/stats/mod.rs` (aggregate)

**Interfaces:**
- Consumes: A's `FlowRecord.ja3/ja4`, `FlowEnrichment.fingerprint_label`.
- Produces: `FingerprintHit { ja3: Option<String>, ja4: Option<String>, label: String }`; `IpThreat.fingerprints: Vec<FingerprintHit>`.

- [ ] **Step 1: Write the failing test** — add to `stats/mod.rs` tests (mirror an existing per-IP test):

```rust
#[test]
fn ip_threat_rolls_up_matched_fingerprint() {
    let mut acc = StatsAccumulator::new(StatsConfig::default()); // use the real ctor/config name
    let mut f = make_flow(/* a TLS flow lo->hi */); // reuse the existing flow test builder
    f.ja3 = Some("aaa".into());
    f.fingerprint_label = Some("CobaltStrike".into());
    let sc = ScoredFlow { severity: Severity::High, score: 80, evidence: vec![], attack: vec![] };
    acc.observe_flow(&f);
    acc.observe_scored_flow(&f, &sc);
    // a second flow to the same IP with the SAME fingerprint must not duplicate the hit:
    acc.observe_flow(&f);
    acc.observe_scored_flow(&f, &sc);
    let summary = acc.finish(/* args */);
    let t = summary.ip_threats.iter().find(|t| t.ip == f.key.lo_ip.to_string()).unwrap();
    assert_eq!(t.fingerprints.len(), 1);
    assert_eq!(t.fingerprints[0].label, "CobaltStrike");
    assert_eq!(t.fingerprints[0].ja3.as_deref(), Some("aaa"));
}

#[test]
fn ip_threat_has_no_fingerprints_when_unmatched() {
    // a flow with ja3 set but fingerprint_label None => no hit
}
```

> NOTE: use the REAL accumulator type/ctor + `finish` signature + flow builder from the existing `stats/mod.rs` tests (e.g. `make_flow`/`StatsAccumulator::new`); the names above are placeholders for those real helpers. `ScoredFlow`'s fields must match `score/mod.rs`.

- [ ] **Step 2: Run it to verify it fails** — `cd engine && cargo test -p ppcap-core ip_threat_rolls_up_matched_fingerprint` → FAIL.

- [ ] **Step 3: Implement** —
(a) `model/summary.rs`: add the type (near `IpThreat`) and the field:
```rust
/// A malware TLS fingerprint matched on this IP's flows (the IOC-matched subset; display-only).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FingerprintHit {
    #[serde(default)]
    pub ja3: Option<String>,
    #[serde(default)]
    pub ja4: Option<String>,
    pub label: String,
}
```
On `IpThreat`, after `reputation`: `#[serde(default)] pub fingerprints: Vec<FingerprintHit>,`.

(b) `model/flow.rs`: add `#[serde(default)] pub fingerprint_label: Option<String>,` to `FlowRecord` (after `ioc`), and `fingerprint_label: None,` to `FlowRecord::new`. (Transient — do NOT touch the Parquet writer / `FlowDto`.)

(c) `analyze/mod.rs` (the :402-412 block): after `record.ioc = fm.any();` add:
```rust
    record.fingerprint_label = enr.fingerprint_label.clone();
```

(d) `stats/mod.rs`: import `FingerprintHit`; add `fingerprints: Vec<FingerprintHit>,` to `IpThreatStat`; in `observe_scored_flow`, inside the `for ip in [..]` loop after the evidence/attack folding, add:
```rust
            if let Some(label) = &f.fingerprint_label {
                let hit = FingerprintHit { ja3: f.ja3.clone(), ja4: f.ja4.clone(), label: label.clone() };
                const MAX_FP_PER_IP: usize = 6;
                if e.fingerprints.len() < MAX_FP_PER_IP && !e.fingerprints.contains(&hit) {
                    e.fingerprints.push(hit);
                }
            }
```
In `finish()`'s `IpThreat { … }` construction, add `fingerprints: s.fingerprints.clone(),`.

- [ ] **Step 4: Run it to verify it passes** — `cd engine && cargo test -p ppcap-core` → all pass (the new tests + existing). `cargo fmt && cargo clippy -p ppcap-core --all-targets -- -D warnings` → clean.

- [ ] **Step 5: Commit**

```bash
cd engine && cargo fmt
git add engine/crates/ppcap-core/src/model/summary.rs engine/crates/ppcap-core/src/model/flow.rs engine/crates/ppcap-core/src/analyze/mod.rs engine/crates/ppcap-core/src/stats/mod.rs
git commit -m "feat(engine): roll matched JA3/JA4 fingerprints into IpThreat.fingerprints"
```

---

### Task 2: STIX export — JA3/JA4 indicators

**Files:**
- Modify: `engine/crates/ppcap-core/src/export/mod.rs` (`stix_bundle`)
- Test: `engine/crates/ppcap-core/tests/` (the existing STIX test, or inline)

**Interfaces:**
- Consumes: `IpThreat.fingerprints` (T1).

- [ ] **Step 1: Write the failing test** — add to the existing STIX test (find it: `grep -rl stix_bundle engine/crates/ppcap-core/tests engine/crates/ppcap-core/src`):

```rust
#[test]
fn stix_emits_ja3_fingerprint_indicator() {
    let mut out = make_output_with_ip_threat(); // an AnalysisOutput with one ip_threat
    out.summary.ip_threats[0].fingerprints = vec![ppcap_core::model::summary::FingerprintHit {
        ja3: Some("e7d705a3286e19ea42f587b344ee6865".into()),
        ja4: None,
        label: "CobaltStrike".into(),
    }];
    let bundle = ppcap_core::export::stix_bundle(&out, 1_700_000_000);
    assert!(bundle.contains("CobaltStrike"));
    assert!(bundle.contains("e7d705a3286e19ea42f587b344ee6865"));
    assert!(bundle.contains("x-tls-fingerprint:ja3"));
    // deterministic: same input => same bundle
    assert_eq!(bundle, ppcap_core::export::stix_bundle(&out, 1_700_000_000));
}
```

> NOTE: reuse the existing STIX test's fixture builder; `FingerprintHit`'s path is `ppcap_core::model::summary::FingerprintHit` (confirm/re-export as needed).

- [ ] **Step 2: Run it to verify it fails** — `cd engine && cargo test -p ppcap-core stix_emits_ja3` → FAIL.

- [ ] **Step 3: Implement** — in `export/mod.rs` `stix_bundle`, after the per-IP indicator loop, add a deduped fingerprint-indicator pass:

```rust
    // JA3/JA4 fingerprint indicators (deduped across IPs; deterministic order).
    let mut fps: std::collections::BTreeMap<String, &crate::model::summary::FingerprintHit> =
        std::collections::BTreeMap::new();
    for t in &out.summary.ip_threats {
        for fp in &t.fingerprints {
            let key = format!(
                "{}|{}|{}",
                fp.ja3.as_deref().unwrap_or(""),
                fp.ja4.as_deref().unwrap_or(""),
                fp.label
            );
            fps.entry(key).or_insert(fp);
        }
    }
    for (key, fp) in &fps {
        let mut parts: Vec<String> = Vec::new();
        if let Some(j) = &fp.ja3 {
            parts.push(format!("x-tls-fingerprint:ja3 = '{j}'"));
        }
        if let Some(j) = &fp.ja4 {
            parts.push(format!("x-tls-fingerprint:ja4 = '{j}'"));
        }
        if parts.is_empty() {
            continue;
        }
        let ind_id = format!("indicator--{}", det_uuid(&format!("indicator:fp:{key}")));
        objects.push(serde_json::json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": ts,
            "modified": ts,
            "name": format!("Malicious TLS fingerprint ({})", fp.label),
            "description": format!("TLS client fingerprint attributed to {}", fp.label),
            "indicator_types": ["malicious-activity"],
            "pattern": format!("[{}]", parts.join(" OR ")),
            "pattern_type": "stix",
            "valid_from": ts
        }));
    }
```

(`ts` + `objects` + `det_uuid` are already in scope in `stix_bundle`.)

- [ ] **Step 4: Run it to verify it passes** — `cd engine && cargo test -p ppcap-core stix` → PASS. `cargo fmt && cargo clippy -p ppcap-core --all-targets -- -D warnings` → clean.

- [ ] **Step 5: Commit**

```bash
cd engine && cargo fmt
git add engine/crates/ppcap-core/src/export/mod.rs engine/crates/ppcap-core/tests/
git commit -m "feat(engine): emit JA3/JA4 fingerprint indicators in the STIX bundle"
```

---

### Task 3: UI flows — per-flow JA3/JA4 (pure UI)

**Files:**
- Modify: `ui/src/types.ts` (`FlowRow`/`RawFlowRow`/`WasmFlow`), `ui/src/lib/data.ts` (both mappers), `ui/src/components/flows/FlowsTable.tsx`, `ui/src/components/FlowDetail.tsx`, `ui/src/views/FlowsView.tsx`
- Test: `ui/src/lib/data.test.ts` (or the existing mapper test)

**Interfaces:**
- Consumes: A's `FlowDto`/Parquet `ja3`/`ja4`.
- Produces: `FlowRow.ja3/ja4: string | null`.

- [ ] **Step 1: Write the failing test** — add to the existing data/mapper test (`grep -rl "flowRowFromWasm\|normalizeFlow" ui/src --include=*.test.ts`):

```ts
it("threads ja3/ja4 from WASM + parquet rows into FlowRow", () => {
  const w = makeWasmFlow({ ja3: "769,47,0,29,0", ja4: "t13d0204h2_aaa_bbb" } as any);
  const r = flowRowFromWasm(w);
  expect(r.ja3).toBe("769,47,0,29,0");
  expect(r.ja4).toBe("t13d0204h2_aaa_bbb");
  const raw = makeRawFlowRow({ ja3: "x", ja4: null } as any);
  const n = normalizeFlow(raw);
  expect(n.ja3).toBe("x");
  expect(n.ja4).toBeNull();
});
```

> NOTE: reuse the test file's existing `makeWasmFlow`/`makeRawFlowRow` fixture builders; just add `ja3`/`ja4`.

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/lib/data.test.ts` → FAIL.

- [ ] **Step 3: Implement** —
(a) `types.ts`: add `ja3: string | null;` + `ja4: string | null;` after `sni` in `RawFlowRow`, `WasmFlow`, and `FlowRow`.
(b) `lib/data.ts`: in `normalizeFlow`, after `sni: r.sni,` add `ja3: r.ja3, ja4: r.ja4,`; in `flowRowFromWasm`, after `sni: r.sni ?? null,` add `ja3: r.ja3 ?? null, ja4: r.ja4 ?? null,`.
(c) `FlowsTable.tsx`: in the "Proto / App / SNI" cell, after the `{f.sni && (…)}` block, add a compact fingerprint line:
```tsx
        {(f.ja3 || f.ja4) && (
          <span
            className="font-mono-num truncate text-xs text-[var(--color-text-faint)]"
            title={[f.ja3 && `JA3: ${f.ja3}`, f.ja4 && `JA4: ${f.ja4}`].filter(Boolean).join("\n")}
          >
            {f.ja4 ? `JA4 ${f.ja4.slice(0, 12)}…` : `JA3 ${f.ja3!.slice(0, 12)}…`}
          </span>
        )}
```
(d) `FlowDetail.tsx`: in the "Application (L7)" Section, after the "TLS SNI" Field, add:
```tsx
  <Field label="TLS JA3" mono title={flow.ja3 ?? undefined}>
    {flow.ja3 ?? <span className="text-[var(--color-text-faint)]">—</span>}
  </Field>
  <Field label="TLS JA4" mono title={flow.ja4 ?? undefined}>
    {flow.ja4 ?? <span className="text-[var(--color-text-faint)]">—</span>}
  </Field>
```
(e) `FlowsView.tsx`: in the search-haystack string, add ` + " " + (r.ja3 ?? "") + " " + (r.ja4 ?? "")`.

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/lib/data.test.ts` → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 5: Commit**

```bash
git add ui/src/types.ts ui/src/lib/data.ts ui/src/components/flows/FlowsTable.tsx ui/src/components/FlowDetail.tsx ui/src/views/FlowsView.tsx ui/src/lib/data.test.ts
git commit -m "feat(ui): show per-flow JA3/JA4 in the flows table, detail, and search"
```

---

### Task 4: UI threat-card fingerprint chip + AI context

**Files:**
- Modify: `ui/src/types.ts` (`IpThreat.fingerprints` + `FingerprintHit`), `ui/src/components/triage/ThreatsPanel.tsx` (chip), `ui/src/lib/ai/context.ts` (`threatLine`)
- Test: `ui/src/components/triage/ThreatsPanel.test.tsx` + `ui/src/lib/ai/context.test.ts` (add cases)

**Interfaces:**
- Consumes: engine `IpThreat.fingerprints` (T1) via the Summary JSON.
- Produces: `IpThreat.fingerprints?: FingerprintHit[]`; a chip + an AI line.

- [ ] **Step 1: Write the failing tests** — add to `ThreatsPanel.test.tsx`:

```tsx
it("shows a fingerprint chip naming the malware family", () => {
  render(<ThreatsPanel threats={[makeThreat({ fingerprints: [{ ja3: "abc", ja4: null, label: "CobaltStrike" }] })]} />);
  expect(screen.getByText(/CobaltStrike/)).toBeInTheDocument();
});
it("shows no fingerprint chip when there are none", () => {
  render(<ThreatsPanel threats={[makeThreat({ fingerprints: [] })]} />);
  expect(screen.queryByText(/CobaltStrike/)).not.toBeInTheDocument();
});
```
and to `context.test.ts`:
```ts
it("names matched fingerprint families in the threat line", () => {
  const out = makeOutput();
  out.summary.ip_threats = [makeThreat({ ip: "1.2.3.4", fingerprints: [{ ja3: "abc", ja4: null, label: "CobaltStrike" }] })];
  expect(buildContext(out)).toContain("fingerprint: CobaltStrike");
});
```

> NOTE: reuse the real `makeThreat`/`makeOutput` fixtures; extend them with the optional `fingerprints` field.

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/components/triage/ThreatsPanel.test.tsx src/lib/ai/context.test.ts` → FAIL.

- [ ] **Step 3: Implement** —
(a) `types.ts`: add
```ts
export interface FingerprintHit {
  ja3: string | null;
  ja4: string | null;
  label: string;
}
```
and on `IpThreat`: `fingerprints?: FingerprintHit[];`.
(b) `ThreatsPanel.tsx` `ThreatCard`: before the `<EvidenceList … />`, add the chip row:
```tsx
        {threat.fingerprints && threat.fingerprints.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {threat.fingerprints.map((fp, i) => (
              <span
                key={i}
                className="inline-flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 text-xs font-semibold"
                style={{
                  color: "var(--color-sev-critical)",
                  backgroundColor: "color-mix(in srgb, var(--color-sev-critical) 16%, transparent)",
                }}
                title={[fp.ja3 && `JA3: ${fp.ja3}`, fp.ja4 && `JA4: ${fp.ja4}`].filter(Boolean).join("\n")}
              >
                <ShieldAlert size={12} />
                {fp.ja4 ? "JA4" : "JA3"} · {fp.label}
              </span>
            ))}
          </div>
        )}
```
(`ShieldAlert` is already imported in this file — confirm.)
(c) `lib/ai/context.ts` `threatLine`: add a `fp` segment and include it in the return:
```ts
  const fp = t.fingerprints?.length
    ? ` — fingerprint: ${t.fingerprints.map((f) => f.label).join(", ")}`
    : "";
  return `- ${t.ip} (${t.ip_class}) — ${t.severity} ${t.score}/100${t.ioc ? " IOC" : ""}${tags}${ev}${rep}${fp}`;
```

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/components/triage/ThreatsPanel.test.tsx src/lib/ai/context.test.ts` → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 5: Commit**

```bash
git add ui/src/types.ts ui/src/components/triage/ThreatsPanel.tsx ui/src/lib/ai/context.tsx ui/src/components/triage/ThreatsPanel.test.tsx ui/src/lib/ai/context.test.ts
# (note: context.ts not .tsx — adjust)
git commit -m "feat(ui): threat-card JA3/JA4 fingerprint chip + name families in the AI context"
```

---

### Task 5: Full gate (engine + UI under the locked toolchain)

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
npm run build; echo "build EXIT: $?"          # EXIT 0, 0 TS errors
npm run test:coverage; echo "cov EXIT: $?"    # EXIT 0; All files >= 80/70 — paste it
```
Do NOT `npm install`.

- [ ] **Step 3: Fill any gap** — if a metric dips because of the new UI code (the chip / mappers / threatLine), add a focused real-behavior test and re-run step 2.

- [ ] **Step 4: Commit** (if any tests added)

```bash
git add ui/src/<new-or-updated tests>
git commit -m "test(ui): hold the coverage gate for the JA3/JA4 surfacing"
```

---

## Self-Review

**1. Spec coverage:** engine rollup `IpThreat.fingerprints` + transient `fingerprint_label` (T1) → spec §1-2; STIX indicators (T2) → §3; flows UI (T3) → §4; threat chip + AI (T4) → §5-6; gate (T5) → Global Constraints + Testing. Pure-UI flows vs matched-only cards/AI/STIX, transient label (no Parquet bump), `#[serde(default)]`, no new deps/consent — all honored. CSV out of scope. ✓

**2. Placeholder scan:** every code step has complete code. The NOTEs (use the real stats/STIX/data/threat test fixtures + ctor/finish signatures; confirm `ShieldAlert` import; `context.ts` not `.tsx`) are concrete in-repo verifications. ✓

**3. Type consistency:** engine `FingerprintHit { ja3:Option<String>, ja4:Option<String>, label:String }` (T1) ⇄ TS `FingerprintHit { ja3:string|null, ja4:string|null, label:string }` (T4) ⇄ STIX reads `fp.ja3/ja4/label` (T2). `IpThreat.fingerprints` (T1 engine, T4 TS). `FlowRow.ja3/ja4` (T3) from `RawFlowRow`/`WasmFlow`. `FlowRecord.fingerprint_label` set in analyze (T1), read in stats (T1). All consistent. ✓
