# PCAP slice / carve export — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-23
**Branch:** `feat/pcap-carve`

## Goal

Export a focused sub-pcap for a chosen **flow** or **host** (a malicious IP / incident host) — reproducible evidence an analyst can open in Wireshark or hand to a colleague, without re-filtering the original capture by hand.

## Architecture

A new engine `carve_pcap` re-reads the capture (streaming, bounded), matches packets against a `CarveQuery` (a flow 5-tuple + window, **or** a single host IP + window), and writes a classic pcap into an in-memory buffer using the **already-present, tested pcap writer** in `gen/container.rs`, stamped with the capture's `link_type`. The reader's `RawFrame { data, link_type, ts_ns, cap_len, wire_len }` carries everything a pcap record needs — the gap today is only that `extract_flow_packets` (the drilldown) discards `RawFrame.data` and base64-caps the L4 payload at 512 bytes, so carve is a **new, parallel engine path** (not a change to the drilldown).

Exposed cross-surface like the existing drilldown: a **WASM** export returns the pcap bytes (→ browser blob download) and a **Tauri** command carves from the source path and writes the chosen output path directly (no large byte array over IPC). The UI adds a "Carve sub-pcap" button to **FlowDetail** (this flow) and a "Carve host pcap" action to the **IP threat card / incident flyout** (this host; an incident carves its `host` IP).

**Tech stack:** Rust (`ppcap-core` `packets.rs` + reuse `gen/container.rs`; `ppcap-wasm`; `src-tauri`); React 18 + TS; Vitest.

## Global Constraints

- **Reuse the existing writer.** `crate::gen::container::{dlt_for, write_pcap_header, write_legacy_record}` are `pub` and always compiled (`pub mod gen;`). Do NOT write a new pcap writer. (Optionally re-export them under a `pcapio` alias for readability — not required.)
- **New parallel path, drilldown untouched.** `extract_flow_packets` / the `WirePacket` model stay as-is; carve is a separate fn that emits raw frame bytes.
- **Classic pcap output only** (DLT from the capture's `link_type` via `dlt_for`; magic `0xa1b2c3d4`, snaplen 65535). pcapng output is out of scope.
- **Bounded, panic-free.** Streaming re-read (64 KiB reader buffer); a max-packets and max-bytes cap (mirror `PacketCaps`); on overflow stop and set a `truncated` flag (logged), never OOM. A malformed frame is skipped, never panics.
- **Homogeneous link type.** Use the first matched frame's `link_type` for the global header; skip a matched frame whose `link_type` differs (rare; mixed-link pcapng). Count skipped in the result.
- **Browser needs the retained source bytes** — carve uses the same `activeSource` (≤ 64 MiB retained `Uint8Array`) the packet inspector uses; the UI disables carve when the source isn't retained (exactly like "Inspect packets"). Desktop re-reads the file path.
- **No new dependencies.** No consent (purely local; the carved file is a user-initiated save, same as the HTML/CSV/STIX exports).
- **`build:wasm` required** (new WASM export). Engine gates: fmt, clippy `-D warnings`, `test --workspace`. UI gate under the locked toolchain (vitest 1.6.1; 80/70). Stage specific files.

## Reference: the seams (verified)

```rust
// reader/mod.rs:83  RawFrame { index, ts_ns, iface_id, wire_len, cap_len, link_type: LinkType, data: &[u8] }
//   (data borrowed until next next_frame() — write it out immediately)
// reader  open(path) / open_reader(cursor) -> Box<dyn PacketSource>; source.next_frame() -> Result<Option<RawFrame>>
// gen/container.rs:28 dlt_for(LinkType)->u32 ; :65 write_pcap_header(w,LinkType)->Result<usize> (magic a1b2c3d4, snaplen 65535)
//   :81 write_legacy_record(w, ts_ns, caplen, origlen)->Result<usize> (16-byte hdr) ; caller writes caplen bytes after
//   split_secs_usec(ts_ns)->(u32,u32) (floored, neg-safe)
// packets.rs:28 PacketQuery { src_ip, dst_ip, src_port, dst_port, transport, start_ns, end_ns } ; :40 PacketCaps ; :93 extract_flow_packets
// ppcap-wasm/src/lib.rs:46 extract_packets(bytes, query_json, caps_json)->Result<String,JsValue>  (the export pattern to mirror; carve returns Vec<u8>)
// src-tauri/src/lib.rs:70 extract_flow_packets(path, query)->Result<FlowPackets,String> ; :228 save_csv pattern (std::fs::write) ; handler list :277
// ui/src/lib/platform.ts exportCsv (isTauri ? save-dialog+invoke : wasm+downloadText) ; downloadText helper
// ui/src/lib/wasmEngine.ts extractPacketsViaWasm ; ui/src/lib/platform.ts extractPacketsViaTauri
// ui/src/components/FlowDetail.tsx:337 "Inspect packets" button (onInspectPackets) ; FlowRow {srcIp,dstIp,srcPort,dstPort,proto,startMs,endMs}
// ui/src/cockpit/DetailFlyout.tsx footer (incident) ; ui/src/components/triage/ThreatsPanel.tsx ThreatCard (IpThreat.ip)
```

## Components

### 1. Engine — `carve_pcap` (`packets.rs`)
```rust
pub enum CarveTarget {
    Flow { src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16, transport: Transport },
    Host { ip: IpAddr },
}
pub struct CarveQuery { pub target: CarveTarget, pub start_ns: i64, pub end_ns: i64 }
pub struct CarveResult { pub pcap: Vec<u8>, pub packets: u64, pub truncated: bool, pub skipped_link_mismatch: u64 }

pub fn carve_pcap(source: Box<dyn PacketSource>, q: &CarveQuery, caps: &PacketCaps) -> Result<CarveResult>;
```
Re-read the source; for each frame in `[start_ns, end_ns]` that matches the target (Flow = bidirectional 5-tuple, reusing the same match logic as `extract_flow_packets`; Host = `src_ip == ip || dst_ip == ip` from the decoded `PacketMeta`), write a record via `write_legacy_record(&mut buf, frame.ts_ns, frame.cap_len, frame.wire_len)` then `buf.write_all(frame.data)`. Write `write_pcap_header(&mut buf, link)` once, from the first matched frame's `link_type`; skip later frames whose `link_type` differs (count them). Stop at the packet/byte cap (set `truncated`). An empty match yields a valid header-only pcap (`packets: 0`).

### 2. Cross-surface
- **WASM** (`ppcap-wasm`): `carve_pcap(bytes: &[u8], query_json: &str, caps_json: &str) -> Result<Vec<u8>, JsValue>` (wasm-bindgen returns `Uint8Array`; returns just the pcap bytes — the count/truncation can ride a header or a second small export if needed, but v1 returns bytes).
- **Tauri** (`src-tauri`): `carve_pcap_to(path_in: String, query: CarveQueryArg, path_out: String) -> Result<u64, String>` — opens `path_in`, carves, writes `path_out` directly via `std::fs::write`, returns the packet count. (Avoids serializing a large byte array over IPC.) Register in the handler list.

### 3. UI — platform + buttons
- `ui/src/lib/platform.ts`: `carveSubPcap(target: CarveTarget-ish, source, suggestedName): Promise<ExportResult>` — desktop: `save()` dialog → `invoke("carve_pcap_to", {...})`; browser: `carvePcapViaWasm(bytes, query)` → a new `downloadBinary(bytes, name, "application/vnd.tcpdump.pcap")` helper (mirrors `downloadText`). `ui/src/lib/wasmEngine.ts`: `carvePcapViaWasm(bytes, query) -> Uint8Array`.
- **FlowDetail.tsx**: a "Carve sub-pcap" button beside "Inspect packets" (same `canInspect`/source-retained gating), building a `Flow` query from the `FlowRow` 5-tuple + `[startMs, endMs]→ns`.
- **IP threat card** (`ThreatsPanel`) and/or the **incident flyout** (`DetailFlyout`): a "Carve host pcap" action building a `Host` query from `threat.ip` / `incident.host` (full-capture window).

### 4. Naming
`{srcIp}-{dstIp}-{srcPort}-{dstPort}.pcap` (flow) / `{host}-carve.pcap` (host).

## Data flow & error handling

Source (browser: retained `activeSource` bytes; desktop: file path) → `carve_pcap` matches + writes → bytes (browser blob) / file (desktop). No matched packets → a valid 24-byte-header pcap (Wireshark opens it as empty) + a "0 packets" toast. Source not retained (browser) → carve disabled with a tooltip (same as Inspect). Cap hit → carve what fits + a "truncated to N packets" toast. Never panics; never OOMs.

## Testing

- **Engine:** generate a synthetic capture (the `gen` scenarios), `carve_pcap` a known flow → **re-open the carved bytes with the reader** and assert: the global header DLT == the source link type; the packet count + per-packet `cap_len`/`wire_len`/`ts_ns`/`data` equal exactly the source flow's packets (round-trip). Host carve matches any packet touching the IP. The packet cap sets `truncated` + stops. Empty match → header-only pcap, reader yields 0 frames. A frame with a mismatched link type is skipped + counted.
- **UI:** `carveSubPcap` builds the correct query from a `FlowRow` / IP and routes desktop (invoke) vs browser (wasm + `downloadBinary`); the FlowDetail button is disabled when the source isn't retained; the host action builds a `Host` query. Cross-surface: the WASM carve round-trips a fixture.
- Coverage ≥ 80/70 under the locked toolchain incl. `build:wasm`. Engine gates green.

## Out of scope

- pcapng output; packet editing / anonymization / payload scrubbing; carving a Recent capture without retained source bytes (browser); multi-flow / arbitrary-filter carve beyond flow + single host; per-incident carve as a distinct query (it reuses Host carve on `incident.host`).

## File manifest

**Engine — modify:** `engine/crates/ppcap-core/src/packets.rs` (`CarveQuery`/`CarveTarget`/`CarveResult` + `carve_pcap`), `engine/crates/ppcap-core/src/lib.rs` (re-export the carve API), `engine/crates/ppcap-wasm/src/lib.rs` (`carve_pcap` export), `ui/src-tauri/src/lib.rs` (`carve_pcap_to` + register).
**UI — modify:** `ui/src/types.ts` (carve query/target TS types), `ui/src/lib/wasmEngine.ts` (`carvePcapViaWasm`), `ui/src/lib/platform.ts` (`carveSubPcap` + `downloadBinary`), `ui/src/components/FlowDetail.tsx` (button), `ui/src/components/triage/ThreatsPanel.tsx` and/or `ui/src/cockpit/DetailFlyout.tsx` (host action) + co-located tests.
**Reuse (no change):** `engine/crates/ppcap-core/src/gen/container.rs` (the pcap writer). **No new deps.**
