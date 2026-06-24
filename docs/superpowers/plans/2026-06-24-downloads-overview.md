# HTTP downloads overview — implementation plan

Spec: [2026-06-24-downloads-overview-design.md](../specs/2026-06-24-downloads-overview-design.md)

Header-based download classifier + a stats rollup + a dashboard panel. Direct to main. Mirrors the
passive-DNS / L2-identity rollup-and-panel pattern; reuses `http_header_value`.

## Engine (`engine/crates/ppcap-core/src/`)

1. `model/packet.rs`: `DownloadKind` enum (Executable/Script/Installer/Archive) + `as_str`;
   `PacketMeta.download: Option<DownloadKind>` (+ the ~7 PacketMeta literal sites incl. `tests/`).
2. `decode/mod.rs`: `sniff_http_download` (response-only via `HTTP/` prefix) + `cdisp_filename_ext`
   (exact last-dot extension) + `classify_download` (MIME + ext tables); set `meta.download` next to
   the other payload-free sniffs. Import `DownloadKind`. Test: classify exe/script/installer/archive,
   None for html/request, `.json` ≠ `.js`.
3. `model/summary.rs`: `DownloadEvent { client, server, kind, count }`; `Summary.downloads`
   (serde-default) + `Summary::empty()`; `enrich/reputation.rs` literal.
4. `stats/mod.rs`: `downloads: HashMap<(IpAddr,IpAddr,DownloadKind),u64>` (+ `new()`); fold in
   `observe_packet` (client=dst_ip, server=src_ip; bounded); rank in `finish` (top-64). Import
   `DownloadKind`. Test: server→client attribution + count.

## UI (`ui/src/`)

5. `types.ts`: `DownloadEvent` + `downloads` on the summary. `cockpit/DownloadsCard.tsx`: panel
   (kind · client ← server · count), risk-colored via `--color-sev-*`, hidden when empty.
   `Dashboard.tsx`: import + render. Test: rows render + hidden-when-empty.

## Verify

Engine: full `cargo test -p ppcap-core` + `clippy`. UI: `test:coverage` + `build`. `build:wasm`
(serde carries the field). Adversarial review (parser safety / classification / attribution+privacy).
Then commit direct to `main`.
