# PCAP slice / carve export — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Export a focused sub-pcap for a chosen flow or host (a malicious IP / incident host) — reproducible evidence to open in Wireshark or hand to a colleague.

**Architecture:** A new engine `carve_pcap` re-reads the capture (streaming, bounded), matches packets (a flow 5-tuple+window or a single host IP), and writes a classic pcap into a buffer via the existing `gen/container` writer. WASM returns the bytes (→ browser blob download); Tauri carves from the source path and writes the chosen path directly. UI: a "Carve sub-pcap" button in FlowDetail (flow) + a "Carve host pcap" action on the IP threat card (host).

**Tech Stack:** Rust (`ppcap-core` `packets.rs` reusing `gen/container.rs`; `ppcap-wasm`; `src-tauri`); React 18 + TS; Vitest.

## Global Constraints

- **Reuse the existing writer** — `crate::gen::container::{write_pcap_header, write_legacy_record}` (pub, always compiled). Do NOT write a new pcap writer.
- **New parallel path** — `extract_flow_packets` / `WirePacket` untouched; carve emits raw `frame.data`.
- **Classic pcap only** (DLT from the capture `link_type`). Bounded: `caps.max_packets` + a `MAX_CARVE_BYTES` byte cap; on overflow stop + set `truncated`. Malformed frame skipped, never panics.
- **Homogeneous link type** — write the header once from `source.link_type()`; skip a matched frame whose `frame.link_type` differs (count it).
- **No new deps, no consent.** `build:wasm` required (new WASM export). Engine gates: fmt, clippy `-D warnings`, `test --workspace`. UI gate under the locked toolchain (vitest 1.6.1; 80/70). Stage specific files.
- **TOOLCHAIN:** cargo `/c/Users/ravid/.cargo/bin` (from `engine/`), MinGW `/c/Users/ravid/opt/mingw64/bin` (src-tauri/online), node `/c/Program Files/nodejs`. `cargo fmt` before each engine commit; do NOT `npm install`.

## Reference: the seams (verbatim, verified)

```rust
// packets.rs PacketQuery { src_ip, dst_ip, src_port, dst_port, transport, start_ns, end_ns }
//   PacketCaps { max_packets, payload_cap } ; const WINDOW_TOL_NS (±1ms window tolerance)
//   extract_flow_packets loop: while let Some(frame)=source.next_frame()? { ts window; meta=decode_frame(&frame)?;
//     (s,d)=meta.src_ip/dst_ip; fwd/rev 5-tuple match; ... }  ← reuse this match shape
// reader/mod.rs:83 RawFrame<'a> { index, ts_ns, iface_id, wire_len, cap_len, link_type:LinkType, data:&[u8] }
//   :96 trait PacketSource { fn link_type(&self)->LinkType; fn next_frame(&mut self)->Result<Option<RawFrame<'_>>>; }
//   :222 open(path)->Result<Box<dyn PacketSource>> ; :235 open_reader<R:Read+'static>(r, len)->Result<Box<dyn PacketSource>>
// gen/container.rs:65 write_pcap_header(w, LinkType)->Result<usize> (magic a1b2c3d4, snaplen 65535)
//   :81 write_legacy_record(w, ts_ns, caplen, origlen)->Result<usize>  (caller writes caplen bytes after)
// lib.rs:48 pub mod packets; :76 pub use packets::{extract_flow_packets, FlowPackets, PacketCaps, PacketQuery, PacketRecord};
// ppcap-wasm/src/lib.rs:45 extract_packets(bytes, query_json, caps_json)->Result<String,JsValue> (QueryDto/CapsDto; open_reader; ppcap_core::extract_flow_packets)
// src-tauri/src/lib.rs PacketQueryArg{src_ip,dst_ip,src_port,dst_port,proto,start_ns,end_ns}; extract_flow_packets(path,query); save_csv(summary,path){std::fs::write}; generate_handler![ … ]
// ui/src/lib/platform.ts exportCsv (isTauri? save()+invoke : wasm+downloadText) ; downloadText(content,name,mime) ; extractPacketsViaTauri(path,query)
// ui/src/lib/wasmEngine.ts extractPacketsViaWasm(bytes, query) -> WireFlowPackets
// ui/src/components/FlowDetail.tsx props { flow, onClose, activeSource, onInspectPackets } ; canInspect=packetsAvailable(activeSource) ; the "Inspect packets" <button onClick={onInspectPackets} disabled={!canInspect}>
// ui/src/views/FlowsView.tsx openInspector(flow){ extractFlowPackets(activeSource, flow) … } ; <FlowDetail … onInspectPackets={()=>openInspector(selected)} />
// ui/src/lib/data.ts (or platform) extractFlowPackets(activeSource, flow) — builds the PacketQuery from a FlowRow + routes wasm/tauri (the model carveSubPcap mirrors)
```

---

### Task 1: Engine `carve_pcap`

**Files:**
- Modify: `engine/crates/ppcap-core/src/packets.rs` (`CarveTarget`/`CarveQuery`/`CarveResult` + `carve_pcap`), `engine/crates/ppcap-core/src/lib.rs` (re-export)
- Test: in `packets.rs` (a round-trip test using `gen` + the reader)

**Interfaces:**
- Consumes: `PacketSource`, `decode_frame`, `WINDOW_TOL_NS`, `gen::container::{write_pcap_header, write_legacy_record}`.
- Produces: `carve_pcap(source, &CarveQuery, &PacketCaps) -> Result<CarveResult>`.

- [ ] **Step 1: Write the failing test** — add to `packets.rs` tests. Generate a small synthetic capture with the `gen` module, carve a flow, re-open the carved bytes with the reader, assert the packets:

```rust
#[test]
fn carve_pcap_round_trips_a_flow() {
    // Build a synthetic capture in memory (reuse the gen scenario helpers used by other packets.rs tests).
    let bytes: Vec<u8> = synth_capture(); // a helper that returns pcap bytes with a known TCP flow A<->B
    let src = crate::reader::open_reader(std::io::Cursor::new(bytes.clone()), Some(bytes.len() as u64)).unwrap();
    // pick the flow's 5-tuple (from the synth helper's known endpoints):
    let q = CarveQuery {
        target: CarveTarget::Flow {
            src_ip: "10.0.0.1".parse().unwrap(), dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 1234, dst_port: 80, transport: Transport::Tcp,
        },
        start_ns: i64::MIN / 2, end_ns: i64::MAX / 2,
    };
    let res = carve_pcap(src, &q, &PacketCaps::default()).unwrap();
    assert!(res.packets > 0);
    // Re-open the carved pcap and confirm every frame matches the flow:
    let mut rd = crate::reader::open_reader(std::io::Cursor::new(res.pcap.clone()), Some(res.pcap.len() as u64)).unwrap();
    let mut n = 0u64;
    while let Some(f) = rd.next_frame().unwrap() {
        let m = crate::decode::decode_frame(&f).unwrap();
        let s = m.src_ip.unwrap(); let d = m.dst_ip.unwrap();
        assert!((s.to_string() == "10.0.0.1" || s.to_string() == "10.0.0.2"));
        assert!((d.to_string() == "10.0.0.1" || d.to_string() == "10.0.0.2"));
        n += 1;
    }
    assert_eq!(n, res.packets);
}

#[test]
fn carve_host_matches_any_packet_touching_ip() {
    // CarveTarget::Host { ip: "10.0.0.2" } → every carved frame has src or dst == 10.0.0.2
}

#[test]
fn carve_empty_match_is_a_valid_header_only_pcap() {
    // a query matching nothing → res.packets == 0, res.pcap is a 24-byte header, reader yields 0 frames
}
```

> NOTE: reuse the REAL synthetic-capture helper the existing `packets.rs` tests use (search the test module for how they build pcap bytes for `extract_flow_packets` tests — e.g. a `gen`-based helper or a raw fixture). Use its actual endpoints/ports in the query. `decode_frame`/`Transport` are already imported in `packets.rs`.

- [ ] **Step 2: Run it to verify it fails** — `cd engine && cargo test -p ppcap-core carve_pcap_round_trips` → FAIL.

- [ ] **Step 3: Implement** — in `packets.rs` add (near `extract_flow_packets`):

```rust
use std::io::Write as _;

/// 64 MiB carve byte budget (matches the browser's retained-source cap).
pub const MAX_CARVE_BYTES: usize = 64 * 1024 * 1024;

/// What to carve: a directed flow 5-tuple (matched bidirectionally) or a single host IP.
#[derive(Clone, Debug)]
pub enum CarveTarget {
    Flow { src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16, transport: Transport },
    Host { ip: IpAddr },
}

/// The carve request: a target plus an inclusive `[start_ns, end_ns]` window (use a wide range for "all").
#[derive(Clone, Debug)]
pub struct CarveQuery { pub target: CarveTarget, pub start_ns: i64, pub end_ns: i64 }

/// The carved capture bytes + counters.
#[derive(Clone, Debug)]
pub struct CarveResult {
    pub pcap: Vec<u8>,
    pub packets: u64,
    pub truncated: bool,
    pub skipped_link_mismatch: u64,
}

/// Stream `source` once and write a classic pcap of the packets matching `q` (bounded by
/// `caps.max_packets` and `MAX_CARVE_BYTES`). The global header carries the capture's link type;
/// frames with a different link type are skipped (counted). An empty match yields a valid
/// header-only pcap. Re-reads the capture; nothing is stored across the call; never panics.
pub fn carve_pcap(
    mut source: Box<dyn PacketSource>,
    q: &CarveQuery,
    caps: &PacketCaps,
) -> Result<CarveResult> {
    let lo = q.start_ns.saturating_sub(WINDOW_TOL_NS);
    let hi = q.end_ns.saturating_add(WINDOW_TOL_NS);
    let link = source.link_type();
    let mut buf: Vec<u8> = Vec::new();
    crate::gen::container::write_pcap_header(&mut buf, link)?;

    let mut packets: u64 = 0;
    let mut truncated = false;
    let mut skipped_link_mismatch: u64 = 0;

    while let Some(frame) = source.next_frame()? {
        if frame.ts_ns < lo || frame.ts_ns > hi {
            continue;
        }
        let meta = match decode_frame(&frame) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let (s, d) = match (meta.src_ip, meta.dst_ip) {
            (Some(s), Some(d)) => (s, d),
            _ => continue,
        };
        let matched = match &q.target {
            CarveTarget::Flow { src_ip, dst_ip, src_port, dst_port, transport } => {
                meta.transport == *transport
                    && ((s == *src_ip && d == *dst_ip && meta.src_port == *src_port && meta.dst_port == *dst_port)
                        || (s == *dst_ip && d == *src_ip && meta.src_port == *dst_port && meta.dst_port == *src_port))
            }
            CarveTarget::Host { ip } => s == *ip || d == *ip,
        };
        if !matched {
            continue;
        }
        if frame.link_type != link {
            skipped_link_mismatch += 1;
            continue;
        }
        if packets as usize >= caps.max_packets || buf.len() + 16 + frame.data.len() > MAX_CARVE_BYTES {
            truncated = true;
            break;
        }
        crate::gen::container::write_legacy_record(&mut buf, frame.ts_ns, frame.cap_len, frame.wire_len)?;
        buf.write_all(frame.data)
            .map_err(|e| PpError::io("write carved frame", e))?;
        packets += 1;
    }

    Ok(CarveResult { pcap: buf, packets, truncated, skipped_link_mismatch })
}
```

(b) `lib.rs:76`: extend the re-export → `pub use packets::{carve_pcap, CarveQuery, CarveResult, CarveTarget, extract_flow_packets, FlowPackets, PacketCaps, PacketQuery, PacketRecord};`

> NOTE: confirm `PpError::io` + `IpAddr`/`Transport` are already imported in `packets.rs` (they are — used by `extract_flow_packets`). `decode_frame` is the same one `extract_flow_packets` calls.

- [ ] **Step 4: Run it to verify it passes** — `cd engine && cargo test -p ppcap-core carve` → PASS. `cargo fmt && cargo clippy -p ppcap-core --all-targets -- -D warnings` → clean.

- [ ] **Step 5: Commit**

```bash
cd engine && cargo fmt
git add engine/crates/ppcap-core/src/packets.rs engine/crates/ppcap-core/src/lib.rs
git commit -m "feat(engine): carve_pcap — write a classic sub-pcap for a flow or host"
```

---

### Task 2: WASM export + Tauri command

**Files:**
- Modify: `engine/crates/ppcap-wasm/src/lib.rs` (`carve_pcap` export), `ui/src-tauri/src/lib.rs` (`carve_pcap_to` + `CarveQueryArg` + register)

**Interfaces:**
- Consumes: `ppcap_core::{carve_pcap, CarveQuery, CarveTarget, PacketCaps}`.
- Produces: WASM `carve_pcap(bytes, query_json) -> Vec<u8>`; Tauri `carve_pcap_to(path_in, query, path_out) -> u64`.

- [ ] **Step 1: Write the failing test** — add a wasm-side round-trip unit test (or a `ppcap-wasm` integration test) that builds the query JSON, calls the underlying core via the same path, and asserts non-empty pcap bytes. (If wasm-bindgen exports are awkward to unit-test, assert the core `carve_pcap` round-trip in T1 covers correctness and make T2's gate `cargo build -p ppcap-wasm` + the src-tauri `cargo build`.) Add a small Rust test for the `CarveTarget`-from-DTO mapping:

```rust
// in ppcap-wasm tests (or a #[cfg(test)] mod): the QueryDto -> CarveQuery mapping picks Flow vs Host correctly
#[test]
fn carve_query_dto_maps_flow_and_host() {
    let flow = carve_query_from_dto(CarveQueryDto { host: None, src_ip: Some("1.1.1.1".into()), dst_ip: Some("2.2.2.2".into()), src_port: Some(1), dst_port: Some(2), proto: Some(6), start_ns: 0, end_ns: 1 }).unwrap();
    assert!(matches!(flow.target, CarveTarget::Flow { .. }));
    let host = carve_query_from_dto(CarveQueryDto { host: Some("9.9.9.9".into()), src_ip: None, dst_ip: None, src_port: None, dst_port: None, proto: None, start_ns: 0, end_ns: 1 }).unwrap();
    assert!(matches!(host.target, CarveTarget::Host { .. }));
}
```

> NOTE: factor a small `carve_query_from_dto(CarveQueryDto) -> Result<CarveQuery, String>` shared helper (in ppcap-wasm and mirrored in src-tauri) so the Flow-vs-Host selection (host set → Host; else Flow) is testable + identical on both surfaces.

- [ ] **Step 2: Run it to verify it fails** — `cd engine && cargo test -p ppcap-wasm carve_query_dto_maps` → FAIL.

- [ ] **Step 3: Implement** —
(a) `ppcap-wasm/src/lib.rs`: add a `CarveQueryDto` (`host: Option<String>`, `src_ip/dst_ip: Option<String>`, `src_port/dst_port: Option<u16>`, `proto: Option<u8>`, `start_ns: i64`, `end_ns: i64`), the `carve_query_from_dto` helper, and:
```rust
#[wasm_bindgen]
pub fn carve_pcap(bytes: &[u8], query_json: &str) -> Result<Vec<u8>, JsValue> {
    let dto: CarveQueryDto =
        serde_json::from_str(query_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let q = carve_query_from_dto(dto).map_err(|e| JsValue::from_str(&e))?;
    let len = bytes.len() as u64;
    let source = ppcap_core::reader::open_reader(Cursor::new(bytes.to_vec()), Some(len))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let res = ppcap_core::carve_pcap(source, &q, &ppcap_core::PacketCaps::default())
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(res.pcap)
}
```
(b) `src-tauri/src/lib.rs`: add a `CarveQueryArg` (same shape, serde Deserialize), the same `carve_query_from_dto` mapping, and:
```rust
#[tauri::command]
fn carve_pcap_to(path_in: String, query: CarveQueryArg, path_out: String) -> Result<u64, String> {
    let q = carve_query_from_arg(query)?;
    let source = ppcap_core::reader::open(std::path::Path::new(&path_in)).map_err(|e| e.to_string())?;
    let res = ppcap_core::carve_pcap(source, &q, &ppcap_core::PacketCaps::default()).map_err(|e| e.to_string())?;
    std::fs::write(&path_out, &res.pcap).map_err(|e| format!("write pcap: {e}"))?;
    Ok(res.packets)
}
```
Register `carve_pcap_to` in `generate_handler![ … ]`.

- [ ] **Step 4: Verify** — `cd engine && cargo test -p ppcap-wasm && cargo build -p ppcap-wasm`; `cd ui/src-tauri && export PATH="/c/Users/ravid/opt/mingw64/bin:/c/Users/ravid/.cargo/bin:$PATH" && cargo build`. `cargo fmt && cargo clippy --workspace --all-targets -- -D warnings` (from engine/ for the core/wasm) → clean.

- [ ] **Step 5: Commit**

```bash
cd engine && cargo fmt
git add engine/crates/ppcap-wasm/src/lib.rs ui/src-tauri/src/lib.rs
git commit -m "feat(engine): carve_pcap WASM export + carve_pcap_to Tauri command"
```

---

### Task 3: TS platform + wasmEngine wrappers

**Files:**
- Modify: `ui/src/lib/wasmEngine.ts` (`carvePcapViaWasm`), `ui/src/lib/platform.ts` (`carveSubPcap` + `downloadBinary`), `ui/src/types.ts` (carve query TS type)
- Test: `ui/src/lib/platform.test.ts` (or the existing platform/export test)

**Interfaces:**
- Produces: `carvePcapViaWasm(bytes, query) -> Uint8Array`; `carveSubPcap(query, source, name) -> Promise<ExportResult>`.

- [ ] **Step 1: Write the failing test** — add to the platform test (mock `isTauri`/wasm like the existing export tests):

```ts
it("carveSubPcap (browser) carves via wasm and downloads a binary", async () => {
  // mock isTauri() -> false, carvePcapViaWasm -> Uint8Array([0xa1,0xb2,0xc3,0xd4]), spy downloadBinary
  const res = await carveSubPcap({ host: "9.9.9.9", start_ns: 0, end_ns: 9 }, browserSource, "9.9.9.9-carve.pcap");
  expect(res.ok).toBe(true);
  // assert the blob/anchor download was triggered
});
```

> NOTE: match the existing platform-test mocking style (how `exportCsv`/`exportCsvWasm` are mocked). A `CarveQuery` TS type: `{ host?: string; src_ip?: string; dst_ip?: string; src_port?: number; dst_port?: number; proto?: number; start_ns: number; end_ns: number }`.

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/lib/platform.test.ts` → FAIL.

- [ ] **Step 3: Implement** —
(a) `wasmEngine.ts`: add `carve_pcap as wasmCarvePcap` to the wasm import + 
```ts
export async function carvePcapViaWasm(bytes: ArrayBuffer, query: object): Promise<Uint8Array> {
  await ensureWasm();
  return wasmCarvePcap(new Uint8Array(bytes), JSON.stringify(query)) as Uint8Array;
}
```
(b) `platform.ts`: add a binary download helper + the router (mirror `exportCsv`):
```ts
function downloadBinary(bytes: Uint8Array, filename: string, mime: string): void {
  const blob = new Blob([bytes], { type: mime });
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
  } finally { URL.revokeObjectURL(url); }
}

export async function carveSubPcap(query: CarveQuery, source: ActiveSource, name: string): Promise<ExportResult> {
  if (isTauri()) {
    const path = await save({ defaultPath: name, filters: [{ name: "PCAP", extensions: ["pcap"] }] });
    if (!path) return { ok: false, message: "" };
    try {
      const n = await invoke<number>("carve_pcap_to", { pathIn: sourcePath(source), query, pathOut: path });
      return { ok: true, message: `Carved ${n} packets` };
    } catch (e) { return { ok: false, message: `Carve failed: ${e}` }; }
  }
  try {
    const bytes = await carvePcapViaWasm(sourceBytes(source), query);
    downloadBinary(bytes, name, "application/vnd.tcpdump.pcap");
    return { ok: true, message: "Downloaded" };
  } catch (e) { return { ok: false, message: `Carve failed: ${e}` }; }
}
```

> NOTE: use the SAME `ActiveSource` accessors the existing `extractFlowPackets` uses to get the desktop path vs the browser retained bytes (find them — e.g. `sourcePath(source)` / `sourceBytes(source)` or inline like `extractPacketsViaTauri`/`extractPacketsViaWasm` do). The Tauri arg names must match the command (`path_in`→`pathIn`, `path_out`→`pathOut` per Tauri's camelCase convention — verify against how `extract_flow_packets` args are passed).

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/lib/platform.test.ts` → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 5: Commit**

```bash
git add ui/src/lib/wasmEngine.ts ui/src/lib/platform.ts ui/src/types.ts ui/src/lib/platform.test.ts
git commit -m "feat(ui): carveSubPcap platform router + carvePcapViaWasm wrapper"
```

---

### Task 4: UI carve buttons (FlowDetail + IP threat card)

**Files:**
- Modify: `ui/src/components/FlowDetail.tsx` (flow carve button), `ui/src/views/FlowsView.tsx` (wire it), `ui/src/components/triage/ThreatsPanel.tsx` (host carve action)
- Test: the FlowDetail / ThreatsPanel tests

**Interfaces:**
- Consumes: `carveSubPcap` (T3), `packetsAvailable(activeSource)` gating.

- [ ] **Step 1: Write the failing test** — add to `FlowDetail` test: the "Carve sub-pcap" button is present, disabled when the source isn't retained, and calls `onCarvePcap` when clicked. And to `ThreatsPanel` test: a "Carve host pcap" control calls its handler with the IP.

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/components/FlowDetail.test.tsx src/components/triage/ThreatsPanel.test.tsx` → FAIL.

- [ ] **Step 3: Implement** —
(a) `FlowDetail.tsx`: add `onCarvePcap: () => void` to `FlowDetailProps`; render a "Carve sub-pcap" button next to "Inspect packets" (same `canInspect` gating + a `FileDown`/`Scissors` icon):
```tsx
        <button type="button" onClick={onCarvePcap} disabled={!canInspect}
          title={canInspect ? "Export this flow as a .pcap" : "Packets are only available for captures analyzed from a pcap"}
          className={cn("flex w-full items-center justify-center gap-2 rounded-md border px-3 py-1.5 text-sm transition-colors …",
            canInspect ? "border-[var(--color-border)] text-[var(--color-text)] hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]" : "cursor-not-allowed border-[var(--color-border)] text-[var(--color-text-faint)]")}>
          <Scissors size={14} /> Carve sub-pcap
        </button>
```
(b) `FlowsView.tsx`: add an `onCarvePcap={() => carveFlow(selected)}` prop; `carveFlow(flow)` builds the `CarveQuery` from the flow (`{ src_ip: flow.srcIp, dst_ip: flow.dstIp, src_port: flow.srcPort, dst_port: flow.dstPort, proto: flow.proto, start_ns: Math.round(flow.startMs*1e6), end_ns: Math.round(flow.endMs*1e6) }`) and calls `carveSubPcap(query, activeSource, \`${flow.srcIp}-${flow.dstIp}-${flow.srcPort}-${flow.dstPort}.pcap\`)`, surfacing the `ExportResult` via the existing toast/notice mechanism (mirror how `extractFlowPackets` errors are surfaced).
(c) `ThreatsPanel.tsx` `ThreatCard`: add a small "Carve host pcap" action (icon button) that calls a new `onCarveHost?: (ip: string) => void` prop with `threat.ip`; wire it from the Dashboard/AppShell where the active source is available, calling `carveSubPcap({ host: ip, start_ns: <capture start ns or MIN>, end_ns: <MAX> }, activeSource, \`${ip}-carve.pcap\`)`. (If threading the source to the threat card is heavy, scope the host action to where the source is already in scope — e.g. the incident flyout — and note it.)

> NOTE: reuse the existing toast/notice + the `ExportResult` handling the export menu uses (find `runExport`). The host action needs `activeSource`; thread it from the same place FlowsView gets it, or attach the host carve to the surface that already has the source. Keep the flow carve (FlowDetail) as the primary; the host carve is the secondary entry.

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/components/FlowDetail.test.tsx src/components/triage/ThreatsPanel.test.tsx` → PASS. tsc clean.

- [ ] **Step 5: Commit**

```bash
git add ui/src/components/FlowDetail.tsx ui/src/views/FlowsView.tsx ui/src/components/triage/ThreatsPanel.tsx ui/src/components/FlowDetail.test.tsx ui/src/components/triage/ThreatsPanel.test.tsx
git commit -m "feat(ui): Carve sub-pcap button (flow) + Carve host pcap action"
```

---

### Task 5: Full gate

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
npm run build; echo "build EXIT: $?"          # EXIT 0
npm run test:coverage; echo "cov EXIT: $?"    # EXIT 0; All files >= 80/70 — paste it
```
Do NOT `npm install`.

- [ ] **Step 3: Fill any gap** — if a metric dips from the new UI/platform code, add a focused real-behavior test (e.g. `carveSubPcap` desktop path; `downloadBinary`; the FlowDetail button gating) and re-run step 2.

- [ ] **Step 4: Commit** (if tests added)

```bash
git add ui/src/<new/updated tests>
git commit -m "test(ui): hold the coverage gate for PCAP carve"
```

---

## Self-Review

**1. Spec coverage:** engine `carve_pcap` (T1) → spec §1; WASM/Tauri (T2) → §2; TS platform router (T3) → §3; UI buttons (T4) → §3-4; gate (T5) → constraints/testing. Reuse the existing writer, classic-pcap-only, bounded + truncation, first-frame/source link type + skip-mismatch, flow + host targets, browser source-retained gating, WASM-returns-bytes / Tauri-writes-path — all covered. pcapng/editing out of scope. ✓

**2. Placeholder scan:** complete code for `carve_pcap`, the WASM/Tauri commands, the TS router. The NOTEs (reuse the real synth-capture helper + `ActiveSource` accessors + toast mechanism; confirm `PpError::io`/imports; match Tauri camelCase arg names) are concrete in-repo verifications. ✓

**3. Type consistency:** `CarveTarget`/`CarveQuery`/`CarveResult` (T1 engine) ⇄ `CarveQueryDto`/`CarveQueryArg` mapped via `carve_query_from_dto` (T2) ⇄ TS `CarveQuery` (T3) ⇄ the UI query builders (T4). `carve_pcap` returns `Vec<u8>` (WASM bytes) / `res.packets` (Tauri u64). `carveSubPcap` consumes the TS `CarveQuery` + `ActiveSource`. All consistent. ✓
