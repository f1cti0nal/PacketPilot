# TLS fingerprinting (JA3/JA4) — Sub-project B (UI + AI + export) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-23
**Branch:** `feat/tls-fingerprint-ui`
**Parent feature:** "TLS fingerprinting everywhere" — A (engine, SHIPPED PR #19) → **B (surface it, this spec)**. B consumes A's `FlowRecord.ja3/ja4` + the IOC match, and adds the missing per-IP rollup so the matched family reaches the AI + exports.

## Goal

Make A's JA3/JA4 fingerprints visible and actionable everywhere: the raw fingerprint on every flow (copy/pivot), the matched-malware **family** on threat cards and in the AI summary, and JA3/JA4 indicators in STIX.

## Architecture

Two layers, mirroring how reputation/IOC already surface:
- **Per-flow (informational), pure UI:** A's WASM `FlowDto` + Parquet already carry `ja3`/`ja4`. B threads them through the TS `FlowRow` type + the two mappers into the flows table + flow-detail + search. **No engine change** for this layer.
- **Per-IP matched-malware (the security signal):** the AI context (`buildContext` reads `summary` only) and the STIX exporter (`stix_bundle` reads `summary.ip_threats`/`findings` only) never see flows. So B adds a **small engine rollup** — the matched fingerprint (value + family) threaded into `IpThreat.fingerprints` — then surfaces it on the threat-card chip, in the AI `threatLine`, and as STIX indicators.

**Cross-surface:** `IpThreat.fingerprints` rides the existing `Summary` JSON (serde), so the WASM `analyze` + Tauri command + the STIX/CSV WASM exports need **no signature change** — only `build:wasm` to regenerate, and the hand-written TS `IpThreat` type to gain the field.

**Tech stack:** Rust (`ppcap-core` only — model/stats/analyze/export); React 18 + TS (types, flows table, threat card, AI context); Vitest.

## Global Constraints

- **The flows-table layer is pure UI** — `ja3`/`ja4` already exist on A's `FlowDto`/Parquet; B only adds TS types + mappers + render. Every flow's fingerprint shows here (matched or not — informational).
- **The threat-card / AI / STIX layer shows ONLY the matched-malware subset** — a fingerprint surfaces there only when it matched the (embedded ∪ user) feed (`ja3_ioc`/`ja4_ioc`), carrying its family label. This mirrors how IOC/reputation surface; it keeps cards/AI uncluttered by benign fingerprints.
- **`FlowRecord.fingerprint_label` is transient** (in-memory only; NOT a new Parquet column / NOT in `FlowDto`) — it's set in the analyze pipeline from the enrichment and consumed by the stats stage in the same pass. No Parquet schema bump, no `FLOW_PARQUET_VERSION` change.
- **`IpThreat.fingerprints` is `#[serde(default)]`** (+ the TS field optional) so old cached captures still deserialize.
- **No new dependencies.** No new consent/toggle (local detection; nothing leaves the device except the existing opt-in AI/export the user already triggers).
- **`build:wasm` is required** (the `Summary` JSON gains `ip_threats[].fingerprints`); verify the UI under the locked toolchain (vitest 1.6.1; `npm ci` → `build:wasm` → `build` → `test:coverage`, 80/70). Engine gates: fmt, clippy `-D warnings`, `test --workspace`. Stage specific files.

## Reference: the seams B touches (verified)

```rust
// model/summary.rs:107  IpThreat { ip, ip_class, severity, score, flows, bytes, ioc, tags, attack, evidence, reputation }
// model/flow.rs  FlowRecord { …, ja3:Option<String>, ja4:Option<String>, ioc, … }   (A shipped ja3/ja4)
// enrich/mod.rs  FlowEnrichment { …, ja3_ioc, ja4_ioc, fingerprint_label:Option<String> }   (A/T5)
// analyze/mod.rs:404  let enr = enricher.enrich(record); let fm = enricher.feed_match(&enr);
//                :406  let scored = score_flow(record, &fm); …; :409 record.ioc = fm.any();   ← set record.fingerprint_label = enr.fingerprint_label here
// stats/mod.rs:314  observe_scored_flow(f:&FlowRecord, sc:&ScoredFlow) → per_ip_threat: HashMap<IpAddr, IpThreatStat>  (:113); finish() materializes IpThreat
// export/mod.rs  stix_bundle(out, ts) (indicator SDOs + det_uuid) ; findings_csv(out)
// schema.sql:13  indicator_t ENUM (… 'ja3','ja4' …)  — already lists ja3/ja4
```
```ts
// ui/src/types.ts  FlowRow { …, sni:string|null, … } ; RawFlowRow / WasmFlow (the DTO shapes) ; IpThreat { …, evidence:string[], reputation? }
// ui/src/lib/data.ts  normalizeFlow(RawFlowRow)→FlowRow ; flowRowFromWasm(WasmFlow)→FlowRow   (sni passthrough; ja3/ja4 mirror it)
// ui/src/components/flows/FlowsTable.tsx  the "Proto / App / SNI" column cell ; ui/src/components/FlowDetail.tsx "Application (L7)" section
// ui/src/views/FlowsView.tsx  the free-text search haystack
// ui/src/components/triage/ThreatsPanel.tsx ThreatCard  (ProviderVerdictList + EvidenceList) — add a fingerprint chip
// ui/src/lib/ai/context.ts threatLine(t)  — appends reputation; add fingerprint family
```

## Components

### 1. Engine — model
`model/summary.rs`: a new
```rust
pub struct FingerprintHit { pub ja3: Option<String>, pub ja4: Option<String>, pub label: String }
```
and on `IpThreat`: `#[serde(default)] pub fingerprints: Vec<FingerprintHit>`.
`model/flow.rs`: `#[serde(default)] pub fingerprint_label: Option<String>` on `FlowRecord` (transient; `::new` → `None`; NOT written by the Parquet writer / NOT in `FlowDto`).

### 2. Engine — pipeline + stats
`analyze/mod.rs` (the per-flow finalize at ~:404-409): after `record.ioc = fm.any();`, add `record.fingerprint_label = enr.fingerprint_label.clone();` (so the stats stage sees the matched family).
`stats/mod.rs`: in `IpThreatStat`, add a bounded, deduped set of `FingerprintHit` (key = `(ja3, ja4, label)`); in `observe_scored_flow`, when `f.fingerprint_label.is_some()`, insert `FingerprintHit { ja3: f.ja3.clone(), ja4: f.ja4.clone(), label }`; in `finish()`, materialize into `IpThreat.fingerprints` (cap a few per IP, deterministic order).

### 3. Engine — STIX export
`export/mod.rs` `stix_bundle`: for each `IpThreat` with `fingerprints`, emit one `indicator` SDO per hit — name `"Malicious TLS fingerprint (<label>)"`, `pattern` a custom STIX pattern for the present value (e.g. `[x-tls-fingerprint:ja3 = '<ja3>']` / `[x-tls-fingerprint:ja4 = '<ja4>']`), `indicator_types: ["malicious-activity"]`, `det_uuid` seed `indicator:ja3:<ja3>` / `indicator:ja4:<ja4>` (stable). No relationship required (display-only, not ATT&CK-coupled). (CSV is out of scope — `findings_csv` is finding-shaped, not IP-shaped.)

### 4. UI — flows (pure)
`types.ts`: add `ja3: string | null` + `ja4: string | null` to `FlowRow` (after `sni`) and to `RawFlowRow`/`WasmFlow`; add an optional `fingerprints?: FingerprintHit[]` (+ a `FingerprintHit` TS type) to `IpThreat`.
`lib/data.ts`: `normalizeFlow` + `flowRowFromWasm` pass `ja3`/`ja4` through (mirror `sni`).
`FlowsTable.tsx`: in the "Proto / App / SNI" cell, add a compact truncated JA3/JA4 line (mono, faint, `title` = full value). `FlowDetail.tsx`: add "TLS JA3" + "TLS JA4" fields in the "Application (L7)" section after SNI. `FlowsView.tsx`: add `ja3`/`ja4` to the search haystack.

### 5. UI — threat-card fingerprint chip
`ThreatsPanel.tsx` `ThreatCard`: when `threat.fingerprints?.length`, render a chip row (mirroring the reputation chip): a red/critical-tinted `JA3 · <label>` / `JA4 · <label>` badge per hit (the malware family), `title` = the full ja3/ja4 hash. Reuse the transparency styling.

### 6. AI context
`lib/ai/context.ts` `threatLine`: append ` — fingerprint: ${t.fingerprints.map(f => f.label).join(", ")}` when `t.fingerprints?.length`. (Summary-only invariant preserved — the family rides `IpThreat`.)

## Data flow & error handling

Decode → A's per-flow `ja3`/`ja4` + the IOC match → pipeline sets `record.fingerprint_label` → stats rolls matched hits into `IpThreat.fingerprints` → Summary JSON. UI: `FlowDto`→`FlowRow` shows every flow's fingerprint; `IpThreat.fingerprints` drives the threat chip + the AI line + STIX indicators. No fingerprints / no match → empty vectors, omitted everywhere; never throws. Old captures (no `fingerprints`/`ja3`/`ja4`) deserialize via defaults.

## Testing

- **Engine:** a flow with a matched builtin fingerprint → `IpThreat.fingerprints` carries the hit (value + label); dedup across flows for one IP; `stix_bundle` emits a `ja3`/`ja4` indicator SDO with the family name + a stable det_uuid; a no-match capture → empty.
- **UI:** `FlowRow` carries `ja3`/`ja4` from both mappers; the flows table + FlowDetail render them; the search matches a ja3/ja4 substring; the threat card shows a fingerprint chip for an IP with `fingerprints` and nothing when empty; `buildContext` names the family in the threat line.
- Coverage ≥ 80/70 under the locked toolchain incl. `build:wasm`. Engine gates green.

## Out of scope

- CSV fingerprint columns (finding-shaped export); QUIC JA4; JA3S/JA4S; non-matched fingerprints on cards/AI; a settings toggle for the embedded set.

## File manifest

**Engine — modify:** `engine/crates/ppcap-core/src/model/summary.rs` (`FingerprintHit` + `IpThreat.fingerprints`), `engine/crates/ppcap-core/src/model/flow.rs` (`FlowRecord.fingerprint_label`), `engine/crates/ppcap-core/src/analyze/mod.rs` (set `record.fingerprint_label`), `engine/crates/ppcap-core/src/stats/mod.rs` (aggregate), `engine/crates/ppcap-core/src/export/mod.rs` (STIX ja3/ja4 indicators).
**UI — modify:** `ui/src/types.ts` (FlowRow/RawFlowRow/WasmFlow ja3/ja4 + IpThreat.fingerprints + FingerprintHit), `ui/src/lib/data.ts` (2 mappers), `ui/src/components/flows/FlowsTable.tsx`, `ui/src/components/FlowDetail.tsx`, `ui/src/views/FlowsView.tsx` (search), `ui/src/components/triage/ThreatsPanel.tsx` (chip), `ui/src/lib/ai/context.ts` (threatLine) + co-located tests.
**No new deps, no consent, no Parquet schema change, no WASM/Tauri command signature change.**
