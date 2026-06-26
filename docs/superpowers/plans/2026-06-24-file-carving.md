# File carving — implementation plan

Spec: [2026-06-24-file-carving-design.md](../specs/2026-06-24-file-carving-design.md)

A new streaming carver module + the `FindingKind` seam + a summary IOC list + a dashboard panel.
Direct to main.

## Engine (`engine/crates/ppcap-core/src/`)

1. `carve/mod.rs` (new; `pub(crate) mod carve` in lib.rs): `HttpBodyCarver` (mirrors
   `TlsCertReassembler`) + `CarveState` (per-flow in-order reassembly via TCP seq: gap aborts,
   retransmit/overlap handled) + streaming SHA-256 (no body buffering) + header parsing
   (Content-Length required; Content-Encoding / chunked abort) + the embedded known-bad set (EICAR) +
   `CarveObservation`. Unit tests: single-packet, EICAR known-bad, split body, gap-abort,
   retransmit-tolerate, compressed/chunked-skip, panic-safety.
2. `analyze/mod.rs`: expose `Sha256` (`pub(crate)`, + `new`/`update`/`finalize_bytes`) and a `hex_of`
   helper; create `HttpBodyCarver` + feed it per frame (beside `cert_reasm.observe`); at EOF drain →
   `summary.carved_files` + push a `malware_download_finding` (Critical, T1105, client-attributed)
   for each known-bad.
3. Seam: `model/finding.rs` `FindingKind::MalwareDownload` + `as_str`; `report/mod.rs` `kind_label`;
   `detect/mod.rs` `stage_ordinal` (4, C2) / `stage_label` ("Command & Control") / `kind_phrase`.
4. `model/summary.rs`: `CarvedFile { client, server, sha256, size, known_bad }` + `Summary.carved_files`
   (serde-default) + `Summary::empty()` + `stats::finish` literal + `enrich/reputation.rs` literal.
5. E2E (`tests/l7_enrichment_proof.rs`): a single-packet EICAR HTTP response → assert `carved_files`
   has the hash + `known_bad` + a `MalwareDownload` finding attributed to the client.

## UI (`ui/src/`)

6. `types.ts`: `CarvedFile` + `carved_files?`; `FindingKind` union + `malware_download`.
7. `FindingKind` seam: both `KIND_META` maps (IncidentHero + IncidentsPanel) + `KIND_STAGE` +
   `CONTACT_NOUN` (FileWarning glyph).
8. `cockpit/CarvedFilesCard.tsx`: hash · size · client←server, known-bad badge, hidden when empty;
   Dashboard wire. Test.

## Verify

Engine: full `cargo test -p ppcap-core` (incl. the EICAR e2e) · `clippy`. UI: `test:coverage` ·
`build`. `build:wasm` (wasm embeds the engine). Adversarial review (reassembly-safety /
hash-correctness / attribution-fp). Verify branch = main, then commit direct to `main`.
