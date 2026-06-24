# Suspicious User-Agent detection — implementation plan

Spec: [2026-06-24-suspicious-ua-design.md](../specs/2026-06-24-suspicious-ua-design.md)

Engine-only behavioral detector over the shipped `http_ua` + UI finding-kind wiring. One PR
(direct to main). No new column.

## Engine (`engine/crates/ppcap-core/src/`)

1. `model/finding.rs`: `FindingKind::SuspiciousUa` + `as_str` → `"suspicious_ua"`.
2. `detect/mod.rs`: `TOOL_USER_AGENTS` table + `match_tool_ua`; `BehaviorTracker.tool_ua:
   HashMap<IpAddr, ToolUaStat>` (+ `new()`); `observe_user_agent`; `ToolUaCandidate` +
   `tool_ua_candidates`; `SuspiciousUaParams { enabled }` + `detect_suspicious_ua` (High, T1595);
   incident arms (Discovery).
3. `analyze/mod.rs`: per-packet `observe_user_agent` when `meta.http_ua` is set;
   `PipelineConfig.suspicious_ua` + `detect_suspicious_ua`. `lib.rs`: re-export `SuspiciousUaParams`.
   `report/mod.rs`: `kind_label` → "Suspicious User-Agent".

## UI (`ui/src/`)

4. `types.ts`: `FindingKind` += `"suspicious_ua"`. `cockpit/IncidentHero.tsx` +
   `components/triage/IncidentsPanel.tsx`: `KIND_META` (Bug, label "Attack Tool"), `KIND_STAGE`
   (Discovery), `CONTACT_NOUN` ("requests").

## Tests

5. `detect/mod.rs`: known tools → flagged (most-active first), benign browser ignored;
   `match_tool_ua` case-insensitive + dual-use clients excluded.

## Verify

Engine: full `cargo test -p ppcap-core` · `clippy`. UI: `test:coverage` · `build`. `build:wasm`.
Review focused on the FP table. Then commit direct to `main`.
