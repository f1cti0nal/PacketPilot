# Packet drill-down — design

- **Date:** 2026-06-20
- **Status:** Approved (design); pending implementation plan
- **Branch:** `feat/packet-drilldown` (stacked on `feat/ui-test-suite`)

## 1. Context & motivation

PacketPilot's UI only ever sees **flow-level aggregates** — `FlowRow` from `flows.parquet` (or the WASM
`analyze`), and the engine discards packet payloads after app-proto classification. The `FlowDetail` panel
already shows every flow field, but an analyst can't drop to the packets to confirm a finding (see a beacon's
regular small frames, an exfil's big asymmetric upload, or read a cleartext credential on the wire).

This adds **real per-packet drill-down with payloads** — a Wireshark-lite inspector for a selected flow —
**computed on demand** by re-reading the source capture, so nothing is precomputed or stored.

## 2. Scope

**In scope**
- A Rust `extract_flow_packets` that re-reads a capture and returns one flow's packets (metadata + capped payloads).
- Exposure via a **Tauri command** (desktop, from the file path) and a **WASM export** (browser, from retained bytes).
- UI: retain the active capture's source; a `lib/packets` routing layer; a cockpit `PacketInspector` (virtualized packet list + hex/ASCII payload viewer) reached from `FlowDetail`.

**Out of scope (non-goals)**
- Precomputing/storing packets (no `packets.parquet`; no payloads at rest) — see §9.
- Protocol dissection beyond what the engine already derives (no TCP-stream reassembly, no L7 field decode); the viewer shows raw bytes as hex/ASCII.
- Packet export / "save as pcap".
- Packets for **`summary.json + flows.parquet` imports** and the bundled sample (no source capture → "unavailable").
- Engine changes to the analysis pipeline or detectors.

## 3. Data contract

**Caps (constants; tunable):** `MAX_PACKETS_PER_FLOW = 2000`, `PAYLOAD_CAP_BYTES = 512`.

**Wire (engine JSON / Tauri payload — snake_case, matching the engine convention):**
```jsonc
// FlowPackets
{ "total": 5821, "truncated": true, "packets": [ /* PacketRecord, ≤ MAX_PACKETS_PER_FLOW */ ] }
// PacketRecord
{ "index": 0, "ts_ns": 1700000000123456000, "direction": "c2s",
  "wire_len": 1514, "cap_len": 1514, "tcp_flags": 24,
  "seq": 1, "ack": 1, "payload_len": 1448,
  "payload_b64": "…", "payload_truncated": true }
```
- `direction`: `"c2s"` = from the flow's client (`src`) to server (`dst`); `"s2c"` = reverse.
- `tcp_flags` = 0 and `seq`/`ack` = null for non-TCP packets.
- `payload_b64` = base64 of the **first `PAYLOAD_CAP_BYTES`** of L4 payload; `payload_truncated` = `payload_len > cap`.
- `total` = packets matched before the `MAX_PACKETS_PER_FLOW` cap; `truncated` = more than the cap existed.

**FlowKey (UI → engine):** derived from `FlowRow` —
`{ src_ip, dst_ip, src_port, dst_port, proto, start_ns, end_ns }`.
*`FlowRow` timestamps are millisecond-precision (`start_ts` Date → ms), so `start_ns`/`end_ns` are
`startMs*1e6`/`endMs*1e6` with a **±1 ms tolerance** applied by the matcher to avoid edge misses. The 5-tuple
is the primary identity; the window only disambiguates same-tuple flows at different times.*

**UI types (`ui/src/types.ts`, camelCase after normalization):**
```ts
export interface PacketRow {
  index: number; tsNs: number; relMs: number;       // relMs = (tsNs - flow start ns)/1e6
  direction: "c2s" | "s2c"; wireLen: number; capLen: number;
  tcpFlags: number; seq: number | null; ack: number | null;
  payloadLen: number; payload: Uint8Array; payloadTruncated: boolean;   // payload decoded from b64
}
export interface FlowPackets { total: number; truncated: boolean; packets: PacketRow[]; }
```

## 4. Engine (`ppcap-core` + surfaces)

- **`extract_flow_packets(source, key: FlowKey, caps: PacketCaps) -> FlowPackets`** in `ppcap-core` — re-runs
  the existing packet reader over `source`, keeps packets whose 5-tuple matches **either direction** within
  `[start_ns - 1ms, end_ns + 1ms]`, assigns `direction` relative to `key`'s client, copies up to
  `PAYLOAD_CAP_BYTES` of L4 payload, stops collecting at `MAX_PACKETS_PER_FLOW` (still counting `total`).
  Reuses the parser/reader — **no new parsing logic**. `source` is abstract (a byte slice or a file/reader).
- **Tauri command** `extract_packets(path: String, key: FlowKey, caps: PacketCaps) -> Result<FlowPackets, String>`
  (in `ui/src-tauri`) — opens the file at `path` and calls the core fn.
- **WASM export** `extract_packets(bytes: &[u8], key_json: &str, caps_json: &str) -> String`
  (in `ppcap-wasm`) — parses key/caps, calls the core fn, returns `FlowPackets` JSON. **The wasm bundle
  (`ui/src/wasm/`) must be rebuilt** via `ui/scripts/build-wasm.mjs` (needs the Rust `wasm32` target +
  `wasm-pack`/`wasm-bindgen`).

## 5. UI

- **Source retention** — `App` keeps the active capture's source as
  `ActiveSource = { kind: "path"; path: string } | { kind: "bytes"; bytes: ArrayBuffer } | null`:
  - Tauri native/recent loads already carry `path` → `{ kind: "path" }`.
  - The in-browser WASM path (`handleAnalyzePcap`) currently discards the bytes → **retain them** as
    `{ kind: "bytes" }`, guarded by a size ceiling (`MAX_RETAIN_BYTES ≈ 64 MB`; above it, source = null →
    packets unavailable for that capture, to bound memory).
  - `summary+parquet` import and the bundled sample → `null`.
  - `activeSource` lifts to `App` state beside `summary`/`flows`, **reset on every capture swap** (the
    `applyCapture`/recent funnels).
- **`ui/src/lib/packets.ts`** — `extractFlowPackets(source: ActiveSource, flow: FlowRow, caps?): Promise<FlowPackets>`:
  builds the `FlowKey` from `flow`, routes to the Tauri command (`path`) or WASM export (`bytes`), decodes
  `payload_b64 → Uint8Array`, normalizes to camelCase, derives `relMs`. Throws `PacketsUnavailableError` when
  `source` is null. A `packetsAvailable(source): boolean` helper gates the UI affordance.
- **`ui/src/lib/hexdump.ts`** — pure `hexLines(bytes: Uint8Array): { offset: string; hex: string; ascii: string }[]`
  (16 bytes/row, `offset` 8-hex, `hex` space-separated with a mid gap, `ascii` printable-or-`.`). Unit-tested.
- **`ui/src/cockpit/PacketInspector.tsx`** — a cockpit `glass-panel` overlay (`role="dialog"`, focus-trapped
  like `DetailFlyout`): a flow header (endpoints/proto + a "first 2000 of N" notice when `truncated`); a
  **virtualized packet list** (reuse the `FlowsTable` TanStack-virtual pattern) — columns
  `# · rel-time · dir(→/←) · size · TCP flags · payload-len · ASCII preview`; selecting a row opens the
  **hex+ASCII viewer** for that packet (`offset | 16 hex | ascii`, `font-mono-num`). States: loading
  (extracting…), unavailable, empty (no packets matched), capped notice.
- **`FlowDetail` entry** — add an "Inspect packets" button, enabled only when `packetsAvailable(activeSource)`;
  otherwise disabled with a tooltip ("Packets are only available for captures analyzed from a pcap"). Clicking
  calls `extractFlowPackets` and opens `PacketInspector`. `App` threads `activeSource` down through `FlowsView`
  to `FlowDetail`; the inspector's open-state + loaded `FlowPackets` live in **`FlowsView`** (which already owns
  the selected flow + `FlowDetail`).

## 6. Edge cases & error handling

- **No source** (import/sample/over-size WASM) → the "Inspect packets" affordance is disabled; if invoked, a clear "unavailable" state.
- **No packets matched** (e.g. a flow whose source was truncated) → empty state, not an error.
- **Capped** (`truncated`) → "showing first 2000 of N packets" notice.
- **Non-TCP** flows → `tcp_flags`/`seq`/`ack` absent; the list/viewer omit those columns/fields gracefully.
- **Empty payload** packets (ACKs, etc.) → payload viewer shows "no payload".
- **Extraction failure** (unreadable file, bad bytes) → caught, surfaced as an error state with the message; the rest of the app is unaffected.
- **Large capture re-parse** is O(capture size) per request — acceptable for one on-demand flow; show the loading state. (Indexing is a future optimization, out of scope.)

## 7. Testing

- **Engine (`cargo test`, `ppcap-core`):** `extract_flow_packets` over a synthetic pcap built with the existing
  `frames` helpers — assert matched count + `total`, per-packet direction, `wire_len`, `tcp_flags`, the payload
  cap + `payload_truncated`, the `MAX_PACKETS_PER_FLOW` truncation path, and the ±1 ms window tolerance.
- **UI (vitest):** `hexdump.hexLines` (pure: offsets, padding, non-printable→`.`, partial last row);
  `lib/packets` routing (mock the Tauri `invoke` and the WASM export; assert key derivation + base64 decode +
  the unavailable path); `PacketInspector` (render with fixture `FlowPackets` → list rows, select a row → hex
  viewer, capped/empty/loading states); `FlowDetail` button enabled/disabled by `packetsAvailable`. Adds a
  `makePackets()` fixture to `src/test/fixtures.ts`. Keeps the 80/70 coverage gate green (new `lib/packets.ts`
  has a Tauri/WASM branch that is mock-tested; the `src-tauri` Rust + the generated `wasm/` are coverage-excluded).

## 8. Phasing (the plan sequences these; each independently testable)

1. **Engine** — `extract_flow_packets` + `FlowKey`/`PacketCaps`/`FlowPackets` types in `ppcap-core` + cargo tests.
2. **Surfaces** — the Tauri command + the WASM export + **rebuild the wasm bundle** (and a guard if the toolchain is absent).
3. **UI data path** — `ActiveSource` retention in `App` (incl. the WASM-bytes retention + size guard + reset), `lib/packets.ts`, `lib/hexdump.ts`, the `PacketRow`/`FlowPackets` UI types + a `makePackets` fixture.
4. **Inspector** — `PacketInspector` (list + hex viewer + states) + its tests.
5. **Wire-in** — `FlowDetail` "Inspect packets" button + gating, `FlowsView`/`App` threading of `activeSource`, end-to-end states.

## 9. Risks & decisions

- **Privacy** — raw payloads exist only transiently in the open inspector (decoded in memory, never written to disk/IndexedDB/cache). The `summary+parquet` path stays payload-free.
- **Memory** — retaining the active WASM capture's bytes costs one capture's size; bounded by `MAX_RETAIN_BYTES` (~64 MB) above which packets are unavailable rather than risk OOM.
- **WASM toolchain dependency** — phase 2 needs `wasm32` + `wasm-pack`/`wasm-bindgen`; the plan checks and fails clearly if missing (the engine + UI phases don't need it, so work can proceed around it).
- **Perf** — a full re-parse per request; fine for single-flow on-demand use, with a loading state. Indexing is a deliberate non-goal for v1.
- **ms-precision window** — mitigated by the ±1 ms tolerance + 5-tuple-primary matching (§3).

## 10. File summary

| File | Change |
|---|---|
| `engine/crates/ppcap-core/src/packets.rs` | **new** — `extract_flow_packets` + `FlowKey`/`PacketCaps`/`FlowPackets`/`PacketRecord` + tests (wired into `lib.rs`) |
| `engine/crates/ppcap-wasm/src/lib.rs` | + `extract_packets` WASM export |
| `ui/src-tauri/src/` (the module with the existing `analyze` command) | + `extract_packets` Tauri command, registered in the `invoke_handler` |
| `ui/src/wasm/*` | regenerated wasm bundle |
| `ui/src/types.ts` | + `PacketRow` / `FlowPackets` (+ `ActiveSource`) |
| `ui/src/lib/packets.ts` | **new** — routing + normalization + `packetsAvailable` |
| `ui/src/lib/hexdump.ts` | **new** — `hexLines` formatter |
| `ui/src/cockpit/PacketInspector.tsx` | **new** — list + hex/ASCII viewer overlay |
| `ui/src/components/FlowDetail.tsx` | + "Inspect packets" affordance + gating |
| `ui/src/App.tsx`, `ui/src/views/FlowsView.tsx` | retain/thread `activeSource`; open the inspector |
| `ui/src/test/fixtures.ts` | + `makePackets()` |
| `ui/src/**/*.test.ts(x)` | + tests per §7 |
