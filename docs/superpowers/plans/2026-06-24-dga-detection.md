# DGA detection — implementation plan

Spec: [2026-06-24-dga-detection-design.md](../specs/2026-06-24-dga-detection-design.md)

Engine-only behavioral detector + UI finding-kind wiring. One PR.

## Engine (`engine/crates/ppcap-core/src/`)

1. `model/finding.rs`: `FindingKind::Dga` + `as_str` → `"dga"`.
2. `detect/mod.rs`:
   - `DgaStats { suspect: HashSet<String>, queries, sample }` + `MAX_DGA_SUSPECT = 256`.
   - `BehaviorTracker.dga: HashMap<IpAddr, DgaStats>` (+ `new()`); fold inside `observe_dns_query`
     (score the registered label, track distinct suspect domains per source).
   - `DgaCandidate` + `dga_candidates(min_distinct_domains)`.
   - `DgaParams { enabled, min_distinct_domains: 10 }` + `detect_dga` (Medium, → High at ≥25;
     T1568.002; `dst_port` 53).
   - helpers `registered_domain` (PSL-free registrable label; skip arpa/IP/single-label),
     `is_dga_label` (loose randomness heuristic), `max_consonant_run`.
   - incident-correlation arms: `stage_ordinal`/`stage_label`/`kind_phrase` for `Dga` (C2 stage).
3. `analyze/mod.rs`: `PipelineConfig.dga` + Default + `detect_dga(&tracker, &cfg.dga)`.
4. `lib.rs`: re-export `DgaParams`. `report/mod.rs`: `kind_label` → "DGA Domains".
   `export/mod.rs`: Sigma category → "dns".

## UI (`ui/src/`)

5. `types.ts`: `FindingKind` += `"dga"`.
6. `cockpit/IncidentHero.tsx` + `components/triage/IncidentsPanel.tsx`: `KIND_META` (Shuffle glyph),
   `KIND_STAGE` (C2), `CONTACT_NOUN` ("domains").

## Tests

7. `detect/mod.rs`: many-distinct-random → flagged; below-threshold + normal browsing → none;
   random CDN *subdomains* → none (the FP control); `is_dga_label` word-vs-random; `registered_domain`
   extraction + arpa/IP/single-label skip.
8. Fix the stale positional indices in `tests/threat_e2e.rs` (severity/score/ioc 21/22/23 → 23/24/25;
   latent miss from the per-flow-TLS columns).

## Verify

Engine: `cargo test -p ppcap-core` (full suite) · `clippy`. UI: `test:coverage` · `build`.
`build:wasm` (confirm wasm-compat). Adversarial review focused on FP control. Then PR, merge on local
gates.
