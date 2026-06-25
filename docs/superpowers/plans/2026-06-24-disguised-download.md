# Magic-byte + disguised-download detector — implementation plan

Spec: [2026-06-24-disguised-download-design.md](../specs/2026-06-24-disguised-download-design.md)

Content-based file-type detection + a masquerade detector. Direct to main. Reuses the L7-sniff peek
+ the established detector seam.

## Engine (`engine/crates/ppcap-core/src/`)

1. `model/packet.rs`: `PacketMeta.download_disguised: bool` (+ the 7 PacketMeta literal sites incl.
   `tests/flow_symmetry`).
2. `decode/mod.rs`: `http_body_magic` (magic table, body after `\r\n\r\n`) + `looks_binary` (MZ gate)
   + `is_benign_content_type`; `sniff_http_download` → `(Option<DownloadKind>, bool)` (kind =
   magic.or(header); disguised = exec magic + benign type); set `meta.download` + `meta.download_disguised`.
   Tests: magic/masquerade, octet-stream-not-disguised, genuine-jpeg, MZ-text FP, `.json` ≠ `.js`.
3. `model/finding.rs`: `FindingKind::DisguisedDownload` + `as_str`. `report/mod.rs`: `kind_label`.
4. `detect/mod.rs`: `DisguisedDownloadCandidate` + `DisguisedDlStat` tracker field (+ `new()`),
   `observe_disguised_download`, `disguised_download_candidates`, `DisguisedDownloadParams` + Default,
   `detect_disguised_download` (High, T1036+T1105), incident arms (stage 4 / "Command & Control" /
   "downloaded a disguised executable"); import `DownloadKind`. Test: client-attributed finding +
   disabled switch.
5. `analyze/mod.rs`: `PipelineConfig.disguised_download` + Default + feed (client=dst, server=src) +
   `findings.extend`. `lib.rs`: re-export `DisguisedDownloadParams`.

## UI (`ui/src/`)

6. `types.ts` `FindingKind` union; `cockpit/IncidentHero.tsx` (KIND_META + KIND_STAGE + CONTACT_NOUN,
   `VenetianMask`); `components/triage/IncidentsPanel.tsx` KIND_META.

## Verify

Engine: full `cargo test -p ppcap-core` + `clippy`. UI: `test:coverage` + `build`. `build:wasm`.
Adversarial review (parser safety / disguise FP+evasion / attribution+bounds). Commit direct to main.
