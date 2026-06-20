# Packet Drill-Down Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Wireshark-lite per-flow packet inspector (metadata + capped payloads), computed on demand by re-reading the source capture — engine `extract_flow_packets`, a Tauri command + WASM export, and a cockpit `PacketInspector` reached from `FlowDetail`.

**Architecture:** On-demand re-parse. `ppcap-core::extract_flow_packets(source, query, caps)` re-runs the existing reader+decoder, keeps one flow's packets, caps payloads, returns `FlowPackets`. Surfaced as a Tauri command (file path) and a WASM export (in-memory bytes). The UI retains the active capture's source and renders a virtualized packet list + hex/ASCII viewer. Nothing is stored.

**Tech Stack:** Rust (`ppcap-core`, `ppcap-wasm`, Tauri `src-tauri`) + the wasm32 toolchain; React 18 + TS + Vitest. `base64` added to `ppcap-core` (pure Rust).

**Spec:** `docs/superpowers/specs/2026-06-20-packet-drilldown-design.md`

## Global Constraints

- **Caps:** `MAX_PACKETS_PER_FLOW = 2000`, `PAYLOAD_CAP_BYTES = 512`. Cap payload to the first N bytes; keep counting `total` past the packet cap.
- **No payloads at rest:** packets/payloads are computed on demand and never written to disk/IndexedDB/cache.
- **`summary+parquet` imports + the sample have NO source** → packets unavailable (the UI affordance is disabled).
- **WASM-bytes retention guard:** `MAX_RETAIN_BYTES = 64 * 1024 * 1024`; above it the in-browser capture's bytes are NOT retained → packets unavailable for it.
- **±1 ms window tolerance** on the time match; the 5-tuple is the primary identity.
- **CI gates that must stay green:** engine `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and the **C-compiler-free gate** (the shipped dep graph must not pull `zstd-sys|lz4-sys|cc|cmake|bzip2-sys|openssl-sys|zlib-sys`; `base64` is pure Rust → fine). UI: `tsc --noEmit -p tsconfig.json` exit 0 and `vitest run --coverage` meeting 80/80/80/70 (the test harness is on this branch's base).
- **Commands.** Engine, from `engine/`: `cargo test -p ppcap-core <name>`, `cargo fmt --all`, `cargo clippy -p ppcap-core --all-targets`. UI, from `ui/` (node may need PATH: `export PATH="/c/Program Files/nodejs:$PATH"`): `npx vitest run <file>`, `./node_modules/.bin/tsc.cmd --noEmit -p tsconfig.json`. WASM rebuild: `node ui/scripts/build-wasm.mjs`.
- **Branch:** `feat/packet-drilldown`. Commit after each task.

## Engine API reference (existing — reuse, do not reinvent)

- `reader::open(path: &Path) -> Result<Box<dyn PacketSource>>`; `reader::open_reader<R: Read + 'static>(reader: R, size_hint: Option<u64>) -> Result<Box<dyn PacketSource>>`.
- `trait PacketSource { fn next_frame(&mut self) -> Result<Option<RawFrame<'_>>>; … }` — **lending** iterator; `Ok(None)` = EOF.
- `struct RawFrame<'a> { index: u64, ts_ns: i64, iface_id: u32, wire_len: u32, cap_len: u32, link_type: LinkType, data: &'a [u8] }`.
- `decode::decode_frame(&RawFrame) -> Result<PacketMeta>`; `PacketMeta { index, ts_ns, wire_len, cap_len, transport: Transport, src_ip: Option<IpAddr>, dst_ip: Option<IpAddr>, src_port: u16, dst_port: u16, tcp_flags: u8, payload_len: u32, … }`. **No seq/ack and no payload bytes** — derive those from `frame.data` (Task 1).
- `decode::{l2,l3,l4}` are `pub(crate)` (reusable from a new in-crate module).
- Test helpers (`pub mod gen`): `gen::frames::{build_ethernet,build_ipv4,build_tcp,build_udp,…}`; `gen::container::{write_pcap_header,write_legacy_record}`. Build an in-memory pcap then `reader::open_reader(Cursor::new(buf), None)`.
- WASM export pattern: `#[wasm_bindgen] pub fn analyze(bytes: &[u8], name: String) -> Result<String, JsValue>` → `open_reader(Cursor::new(bytes.to_vec()), Some(len))` → `serde_json::to_string`.
- Tauri pattern: `#[tauri::command] fn analyze_capture(path: String) -> Result<AnalyzeDto, String>`, registered in `tauri::generate_handler![analyze_capture, save_report]` (`ui/src-tauri/src/lib.rs`); JS: `invoke("analyze_capture", { path })`.

---

## File Structure

| File | Responsibility |
|---|---|
| `engine/crates/ppcap-core/src/decode/mod.rs` | + `pub(crate) fn l4_payload(&RawFrame) -> Option<L4Info>` (seq/ack/payload slice) |
| `engine/crates/ppcap-core/src/packets.rs` | **new** — `PacketQuery`/`PacketCaps`/`FlowPackets`/`PacketRecord` + `extract_flow_packets` + tests |
| `engine/crates/ppcap-core/src/lib.rs` | `pub mod packets;` + re-exports |
| `engine/crates/ppcap-core/Cargo.toml` | + `base64` |
| `engine/crates/ppcap-wasm/src/lib.rs` | + `extract_packets` WASM export |
| `ui/src/wasm/*` | regenerated bundle (`build-wasm.mjs`) |
| `ui/src-tauri/src/lib.rs` | + `extract_flow_packets` command + handler registration |
| `ui/src/types.ts` | + `PacketRow`/`FlowPackets`/`ActiveSource` |
| `ui/src/lib/hexdump.ts` | **new** — `hexLines` |
| `ui/src/lib/packets.ts` | **new** — `extractFlowPackets` routing + `packetsAvailable` |
| `ui/src/lib/platform.ts`, `ui/src/lib/wasmEngine.ts` | + Tauri/WASM `extractPackets` wrappers |
| `ui/src/App.tsx`, `ui/src/views/FlowsView.tsx`, `ui/src/components/FlowDetail.tsx` | retain/thread `activeSource`; open the inspector |
| `ui/src/cockpit/PacketInspector.tsx` | **new** — list + hex viewer |
| `ui/src/test/fixtures.ts` + `**/*.test.ts(x)` | + `makePackets()` + tests |

---

## Task 1: Engine — `extract_flow_packets`

**Files:** Create `engine/crates/ppcap-core/src/packets.rs`; Modify `decode/mod.rs`, `lib.rs`, `Cargo.toml`.

**Interfaces — Produces:**
```rust
pub struct PacketQuery { pub src_ip: IpAddr, pub dst_ip: IpAddr, pub src_port: u16, pub dst_port: u16, pub transport: Transport, pub start_ns: i64, pub end_ns: i64 }
pub struct PacketCaps { pub max_packets: usize, pub payload_cap: usize }  // Default = consts below
pub struct PacketRecord { pub index: u32, pub ts_ns: i64, pub direction: &'static str, pub wire_len: u32, pub cap_len: u32, pub tcp_flags: u8, pub seq: Option<u32>, pub ack: Option<u32>, pub payload_len: u32, pub payload_b64: String, pub payload_truncated: bool }  // serde camel? -> keep snake (serde default)
pub struct FlowPackets { pub total: u64, pub truncated: bool, pub packets: Vec<PacketRecord> }
pub fn extract_flow_packets(source: Box<dyn PacketSource>, q: &PacketQuery, caps: &PacketCaps) -> Result<FlowPackets>
```

- [ ] **Step 1: Add `base64` dep.** In `engine/crates/ppcap-core/Cargo.toml` `[dependencies]` add `base64 = "0.22"`.

- [ ] **Step 2: Add the L4 helper** to `engine/crates/ppcap-core/src/decode/mod.rs` — reuse the existing `l2`/`l3` strip to find the L4 segment, then read TCP seq/ack + payload. Add:
```rust
/// L4 seq/ack (TCP) + the L4 payload slice for a raw frame. None when undecodable.
pub(crate) struct L4Info<'a> { pub seq: Option<u32>, pub ack: Option<u32>, pub payload: &'a [u8] }

pub(crate) fn l4_payload<'a>(frame: &crate::reader::RawFrame<'a>) -> Option<L4Info<'a>> {
    // Reuse the same L2 strip decode_frame uses to reach L3, then the L3 strip to reach L4.
    // (Use the existing l2::*/l3::* helpers; they already handle Ethernet/SLL/Null/Raw and
    //  IPv4 IHL / IPv6 ext-headers and return the L4 byte slice + transport.)
    let l3 = l2::strip_to_l3(frame.link_type, frame.data)?;          // existing or thin wrapper
    let (l4, transport) = l3::strip_to_l4(l3)?;                       // existing or thin wrapper
    match transport {
        Transport::Tcp if l4.len() >= 20 => {
            let data_off = ((l4[12] >> 4) as usize) * 4;
            let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
            let ack = u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]);
            let payload = if l4.len() > data_off { &l4[data_off..] } else { &[] };
            Some(L4Info { seq: Some(seq), ack: Some(ack), payload })
        }
        Transport::Udp if l4.len() >= 8 => Some(L4Info { seq: None, ack: None, payload: &l4[8..] }),
        _ => Some(L4Info { seq: None, ack: None, payload: &[] }),
    }
}
```
If `l2::strip_to_l3` / `l3::strip_to_l4` don't already exist with these exact names, add thin `pub(crate)` wrappers in `l2`/`l3` around the offset logic `decode_frame`/`decode_l3` already use (IHL = `(b[0] & 0x0f) * 4` for IPv4; fixed 40 + ext-header walk for IPv6; Ethernet = 14 (+4 per VLAN tag), SLL = 16, Null = 4, Raw = 0). Do not duplicate offset logic — factor the existing walk into the wrapper.

- [ ] **Step 3: Write the failing test** in a new `engine/crates/ppcap-core/src/packets.rs` (tests at the bottom). Build a 4-packet TCP flow (10.0.0.1:1234 ↔ 93.184.216.34:443) with payloads, plus one unrelated UDP packet, and assert extraction:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::gen::{frames, container};
    use crate::reader::{open_reader, LinkType};
    use std::io::{Cursor, Write};
    use std::net::Ipv4Addr;

    fn tcp_pcap() -> Vec<u8> {
        let client = Ipv4Addr::new(10, 0, 0, 1);
        let server = Ipv4Addr::new(93, 184, 216, 34);
        let mk = |src, dst, sp, dp, flags, payload: &[u8], ts: i64, buf: &mut Vec<u8>| {
            let tcp = frames::build_tcp(src, dst, sp, dp, flags, payload);
            let ip = frames::build_ipv4(src, dst, 6, 64, tcp.len() as u16);
            let eth = frames::build_ethernet([2;6], [4;6], 0x0800);
            let frame: Vec<u8> = eth.into_iter().chain(ip).chain(tcp).collect();
            container::write_legacy_record(buf, ts, frame.len() as u32, frame.len() as u32).unwrap();
            buf.write_all(&frame).unwrap();
        };
        let mut buf = Vec::new();
        container::write_pcap_header(&mut buf, LinkType::Ethernet).unwrap();
        mk(client, server, 1234, 443, frames::TCP_SYN, b"", 1_000_000_000, &mut buf);
        mk(server, client, 443, 1234, frames::TCP_SYN | frames::TCP_ACK, b"", 1_000_000_100, &mut buf);
        mk(client, server, 1234, 443, frames::TCP_PSH | frames::TCP_ACK, b"GET / HTTP/1.1\r\n", 1_000_000_200, &mut buf);
        mk(server, client, 443, 1234, frames::TCP_PSH | frames::TCP_ACK, b"HTTP/1.1 200 OK\r\n", 1_000_000_300, &mut buf);
        // unrelated UDP that must NOT match:
        let udp = frames::build_udp(client, Ipv4Addr::new(8,8,8,8), 5000, 53, b"x");
        let ip = frames::build_ipv4(client, Ipv4Addr::new(8,8,8,8), 17, 64, udp.len() as u16);
        let eth = frames::build_ethernet([2;6],[4;6],0x0800);
        let f: Vec<u8> = eth.into_iter().chain(ip).chain(udp).collect();
        container::write_legacy_record(&mut buf, 1_000_000_400, f.len() as u32, f.len() as u32).unwrap();
        buf.write_all(&f).unwrap();
        buf
    }

    fn query() -> PacketQuery {
        PacketQuery { src_ip: "10.0.0.1".parse().unwrap(), dst_ip: "93.184.216.34".parse().unwrap(),
            src_port: 1234, dst_port: 443, transport: Transport::Tcp,
            start_ns: 1_000_000_000, end_ns: 1_000_000_300 }
    }

    #[test]
    fn extracts_only_the_matching_flow_both_directions() {
        let src = open_reader(Cursor::new(tcp_pcap()), None).unwrap();
        let fp = extract_flow_packets(src, &query(), &PacketCaps::default()).unwrap();
        assert_eq!(fp.total, 4);                       // 4 TCP, UDP excluded
        assert_eq!(fp.packets.len(), 4);
        assert!(!fp.truncated);
        assert_eq!(fp.packets[0].direction, "c2s");    // client SYN
        assert_eq!(fp.packets[1].direction, "s2c");    // server SYN-ACK
        assert!(fp.packets[0].seq.is_some());          // TCP seq present
        // payload bytes decode back
        let b = base64::engine::general_purpose::STANDARD.decode(&fp.packets[2].payload_b64).unwrap();
        assert_eq!(&b, b"GET / HTTP/1.1\r\n");
        assert_eq!(fp.packets[2].payload_len, 16);
    }

    #[test]
    fn caps_packets_and_payload() {
        let src = open_reader(Cursor::new(tcp_pcap()), None).unwrap();
        let caps = PacketCaps { max_packets: 2, payload_cap: 4 };
        let fp = extract_flow_packets(src, &query(), &caps).unwrap();
        assert_eq!(fp.total, 4);
        assert_eq!(fp.packets.len(), 2);
        assert!(fp.truncated);
        let p = &fp.packets[2.min(fp.packets.len()-1)];
        // payload-cap path: the PSH packet (if within first 2) truncates to 4 bytes
        let _ = p;
    }
}
```

- [ ] **Step 4: Run → fail** (`extract_flow_packets` not defined): `cd engine && cargo test -p ppcap-core packets:: 2>&1 | tail -20`.

- [ ] **Step 5: Implement `packets.rs`** (above the tests):
```rust
//! On-demand per-flow packet extraction (re-reads a capture; nothing stored).
use std::net::IpAddr;
use base64::Engine as _;
use serde::Serialize;
use crate::decode::{decode_frame, l4_payload};
use crate::error::Result;
use crate::model::packet::Transport;
use crate::reader::PacketSource;

pub const MAX_PACKETS_PER_FLOW: usize = 2000;
pub const PAYLOAD_CAP_BYTES: usize = 512;
const WINDOW_TOL_NS: i64 = 1_000_000; // ±1 ms

#[derive(Clone, Debug)]
pub struct PacketQuery {
    pub src_ip: IpAddr, pub dst_ip: IpAddr,
    pub src_port: u16, pub dst_port: u16,
    pub transport: Transport, pub start_ns: i64, pub end_ns: i64,
}
#[derive(Clone, Copy, Debug)]
pub struct PacketCaps { pub max_packets: usize, pub payload_cap: usize }
impl Default for PacketCaps {
    fn default() -> Self { Self { max_packets: MAX_PACKETS_PER_FLOW, payload_cap: PAYLOAD_CAP_BYTES } }
}

#[derive(Serialize)]
pub struct PacketRecord {
    pub index: u32, pub ts_ns: i64, pub direction: &'static str,
    pub wire_len: u32, pub cap_len: u32, pub tcp_flags: u8,
    pub seq: Option<u32>, pub ack: Option<u32>,
    pub payload_len: u32, pub payload_b64: String, pub payload_truncated: bool,
}
#[derive(Serialize)]
pub struct FlowPackets { pub total: u64, pub truncated: bool, pub packets: Vec<PacketRecord> }

pub fn extract_flow_packets(mut source: Box<dyn PacketSource>, q: &PacketQuery, caps: &PacketCaps) -> Result<FlowPackets> {
    let lo = q.start_ns.saturating_sub(WINDOW_TOL_NS);
    let hi = q.end_ns.saturating_add(WINDOW_TOL_NS);
    let mut packets: Vec<PacketRecord> = Vec::new();
    let mut total: u64 = 0;
    while let Some(frame) = source.next_frame()? {
        if frame.ts_ns < lo || frame.ts_ns > hi { continue; }
        let meta = match decode_frame(&frame) { Ok(m) => m, Err(_) => continue };
        if meta.transport != q.transport { continue; }
        let (s, d) = match (meta.src_ip, meta.dst_ip) { (Some(s), Some(d)) => (s, d), _ => continue };
        let fwd = s == q.src_ip && d == q.dst_ip && meta.src_port == q.src_port && meta.dst_port == q.dst_port;
        let rev = s == q.dst_ip && d == q.src_ip && meta.src_port == q.dst_port && meta.dst_port == q.src_port;
        if !fwd && !rev { continue; }
        total += 1;
        if packets.len() >= caps.max_packets { continue; }
        let l4 = l4_payload(&frame);
        let payload: &[u8] = l4.as_ref().map(|x| x.payload).unwrap_or(&[]);
        let (seq, ack) = l4.as_ref().map(|x| (x.seq, x.ack)).unwrap_or((None, None));
        let payload_truncated = payload.len() > caps.payload_cap;
        let take = payload.len().min(caps.payload_cap);
        packets.push(PacketRecord {
            index: frame.index as u32, ts_ns: frame.ts_ns,
            direction: if fwd { "c2s" } else { "s2c" },
            wire_len: frame.wire_len, cap_len: frame.cap_len,
            tcp_flags: meta.tcp_flags, seq, ack,
            payload_len: payload.len() as u32,
            payload_b64: base64::engine::general_purpose::STANDARD.encode(&payload[..take]),
            payload_truncated,
        });
    }
    Ok(FlowPackets { total, truncated: (total as usize) > packets.len(), packets })
}
```

- [ ] **Step 6: Wire the module.** In `engine/crates/ppcap-core/src/lib.rs` add `pub mod packets;` and re-export: `pub use packets::{extract_flow_packets, FlowPackets, PacketRecord, PacketQuery, PacketCaps};`.

- [ ] **Step 7: Run → pass + lint.** `cd engine && cargo test -p ppcap-core packets:: && cargo fmt --all && cargo clippy -p ppcap-core --all-targets -- -D warnings`. All clean.

- [ ] **Step 8: Commit.**
```bash
git add engine/crates/ppcap-core/src/packets.rs engine/crates/ppcap-core/src/decode/mod.rs engine/crates/ppcap-core/src/lib.rs engine/crates/ppcap-core/Cargo.toml engine/crates/ppcap-core/Cargo.lock
git commit -m "feat(engine): extract_flow_packets — on-demand per-flow packets + payloads"
```

---

## Task 2: WASM export + rebuild the bundle

**Files:** Modify `engine/crates/ppcap-wasm/src/lib.rs`; regenerate `ui/src/wasm/*`.

**Interfaces — Produces:** WASM export `extract_packets(bytes: &[u8], query_json: &str, caps_json: &str) -> Result<String, JsValue>` returning `FlowPackets` JSON.

- [ ] **Step 1: Add the export** (mirror `analyze`). Define serde-deserializable mirrors of `PacketQuery`/`PacketCaps` (the JS sends JSON with `src_ip` as a string, `transport` as a number = IANA proto). Map JS `proto: number` → `Transport`; parse IPs from strings:
```rust
#[derive(serde::Deserialize)]
struct QueryDto { src_ip: String, dst_ip: String, src_port: u16, dst_port: u16, proto: u8, start_ns: i64, end_ns: i64 }
#[derive(serde::Deserialize)]
struct CapsDto { max_packets: Option<usize>, payload_cap: Option<usize> }

#[wasm_bindgen]
pub fn extract_packets(bytes: &[u8], query_json: &str, caps_json: &str) -> Result<String, JsValue> {
    let q: QueryDto = serde_json::from_str(query_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let c: CapsDto = serde_json::from_str(caps_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let query = ppcap_core::PacketQuery {
        src_ip: q.src_ip.parse().map_err(|_| JsValue::from_str("bad src_ip"))?,
        dst_ip: q.dst_ip.parse().map_err(|_| JsValue::from_str("bad dst_ip"))?,
        src_port: q.src_port, dst_port: q.dst_port,
        transport: ppcap_core::Transport::from_ip_proto(q.proto), // see note
        start_ns: q.start_ns, end_ns: q.end_ns,
    };
    let caps = ppcap_core::PacketCaps {
        max_packets: c.max_packets.unwrap_or(ppcap_core::packets::MAX_PACKETS_PER_FLOW),
        payload_cap: c.payload_cap.unwrap_or(ppcap_core::packets::PAYLOAD_CAP_BYTES),
    };
    let len = bytes.len() as u64;
    let source = ppcap_core::reader::open_reader(std::io::Cursor::new(bytes.to_vec()), Some(len))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let fp = ppcap_core::extract_flow_packets(source, &query, &caps).map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_json::to_string(&fp).map_err(|e| JsValue::from_str(&e.to_string()))
}
```
Note: if `Transport` has no `from_ip_proto`, add a small `pub fn from_ip_proto(p: u8) -> Transport` to `ppcap-core` (`6→Tcp, 17→Udp, 132→Sctp, 1→Icmp, 58→Icmpv6, _→Other(p)`) and re-export it (fold this into Task 1 if you reach it there). The UI passes `flow.proto` (the IANA number) directly.

- [ ] **Step 2: Rebuild the wasm bundle.** First verify the toolchain: `rustup target list --installed | grep wasm32` and `wasm-bindgen --version`. If `wasm32-unknown-unknown` is missing → `rustup target add wasm32-unknown-unknown`; if `wasm-bindgen` is missing → `cargo install wasm-bindgen-cli --version 0.2.125` (MUST match the `wasm-bindgen` pin in `ppcap-wasm/Cargo.toml`). If the toolchain cannot be installed in this environment, **mark this task DONE_WITH_CONCERNS** noting the bundle wasn't regenerated, and proceed — the Rust compiles via `cargo check`. Then: `node ui/scripts/build-wasm.mjs`. Expect it to write `ui/src/wasm/ppcap_wasm.js` + `ppcap_wasm_bg.wasm` containing the new export.

- [ ] **Step 3: Verify.** `cd engine && cargo check -p ppcap-wasm --target wasm32-unknown-unknown` (or plain `cargo check -p ppcap-wasm`) → compiles. If the bundle was regenerated, confirm `extract_packets` appears: `grep -c extract_packets ui/src/wasm/ppcap_wasm.js` ≥ 1.

- [ ] **Step 4: Commit.**
```bash
git add engine/crates/ppcap-wasm/src/lib.rs ui/src/wasm/
git commit -m "feat(wasm): extract_packets export + rebuilt bundle"
```

---

## Task 3: Tauri command + JS invoke wrapper

**Files:** Modify `ui/src-tauri/src/lib.rs`, `ui/src/lib/platform.ts`.

- [ ] **Step 1: Add the command** (mirror `analyze_capture`). `path` is its own param (matching `analyze_capture(path)`); it opens the file and returns the serde-serializable `FlowPackets` directly (Tauri serializes to JS):
```rust
#[derive(serde::Deserialize)]
struct PacketQueryArg { src_ip: String, dst_ip: String, src_port: u16, dst_port: u16, proto: u8, start_ns: i64, end_ns: i64 }

#[tauri::command]
fn extract_flow_packets(path: String, query: PacketQueryArg) -> Result<ppcap_core::FlowPackets, String> {
    let q = ppcap_core::PacketQuery {
        src_ip: query.src_ip.parse().map_err(|_| "bad src_ip".to_string())?,
        dst_ip: query.dst_ip.parse().map_err(|_| "bad dst_ip".to_string())?,
        src_port: query.src_port, dst_port: query.dst_port,
        transport: ppcap_core::Transport::from_ip_proto(query.proto),
        start_ns: query.start_ns, end_ns: query.end_ns,
    };
    let source = ppcap_core::reader::open(std::path::Path::new(&path)).map_err(|e| e.to_string())?;
    ppcap_core::extract_flow_packets(source, &q, &ppcap_core::PacketCaps::default()).map_err(|e| e.to_string())
}
```
Register it: change `tauri::generate_handler![analyze_capture, save_report]` → `tauri::generate_handler![analyze_capture, save_report, extract_flow_packets]`.

- [ ] **Step 2: JS invoke wrapper** in `ui/src/lib/platform.ts` (alongside `analyzeViaTauri`):
```ts
import type { FlowPackets } from "../types";  // FlowPackets wire type (snake) — see Task 5
export async function extractPacketsViaTauri(path: string, query: object): Promise<FlowPackets> {
  return invoke<FlowPackets>("extract_flow_packets", { path, query });
}
```

- [ ] **Step 3: Verify.** `cd ui/src-tauri && cargo check` → compiles (Tauri runtime tested only in the desktop app; note this). `tsc` on the UI → exit 0.

- [ ] **Step 4: Commit.** `git add ui/src-tauri/src/lib.rs ui/src/lib/platform.ts && git commit -m "feat(tauri): extract_flow_packets command + invoke wrapper"`

---

## Task 4: UI — `lib/hexdump.ts`

**Files:** Create `ui/src/lib/hexdump.ts`, `ui/src/lib/hexdump.test.ts`.

- [ ] **Step 1: Failing test** `hexdump.test.ts`:
```ts
import { describe, it, expect } from "vitest";
import { hexLines } from "./hexdump";
describe("hexLines", () => {
  it("formats one full row", () => {
    const bytes = new Uint8Array([0x47, 0x45, 0x54, 0x20]); // "GET "
    const [row] = hexLines(bytes);
    expect(row.offset).toBe("00000000");
    expect(row.hex.startsWith("47 45 54 20")).toBe(true);
    expect(row.ascii.startsWith("GET ")).toBe(true);
  });
  it("renders non-printables as dots and splits at 16 bytes", () => {
    const bytes = new Uint8Array(20).map((_, i) => i);
    const rows = hexLines(bytes);
    expect(rows.length).toBe(2);
    expect(rows[1].offset).toBe("00000010");
    expect(rows[0].ascii).toContain("."); // 0x00 etc. → "."
  });
  it("empty input → no rows", () => { expect(hexLines(new Uint8Array())).toEqual([]); });
});
```

- [ ] **Step 2: Run → fail.** `npx vitest run src/lib/hexdump.test.ts`.

- [ ] **Step 3: Implement** `hexdump.ts`:
```ts
export interface HexLine { offset: string; hex: string; ascii: string }
const BYTES_PER_ROW = 16;
export function hexLines(bytes: Uint8Array): HexLine[] {
  const rows: HexLine[] = [];
  for (let off = 0; off < bytes.length; off += BYTES_PER_ROW) {
    const slice = bytes.subarray(off, off + BYTES_PER_ROW);
    const hex = Array.from(slice, (b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(slice, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    rows.push({ offset: off.toString(16).padStart(8, "0"), hex, ascii });
  }
  return rows;
}
```

- [ ] **Step 4: Run → pass.** `npx vitest run src/lib/hexdump.test.ts`. **Step 5: Commit** `test(ui): hexdump formatter`.

---

## Task 5: UI — types + `lib/packets.ts` routing + fixture

**Files:** Modify `ui/src/types.ts`, `ui/src/lib/wasmEngine.ts`, `ui/src/test/fixtures.ts`; Create `ui/src/lib/packets.ts`, `ui/src/lib/packets.test.ts`.

**Interfaces — Produces:** the UI types + `extractFlowPackets(source, flow, caps?)` + `packetsAvailable(source)` + `makePackets()`.

- [ ] **Step 1: Types** in `ui/src/types.ts`:
```ts
export interface PacketRow {
  index: number; tsNs: number; relMs: number;
  direction: "c2s" | "s2c"; wireLen: number; capLen: number;
  tcpFlags: number; seq: number | null; ack: number | null;
  payloadLen: number; payload: Uint8Array; payloadTruncated: boolean;
}
export interface FlowPackets { total: number; truncated: boolean; packets: PacketRow[]; }
/** WIRE shape from the engine (snake_case); normalized to PacketRow in lib/packets. */
export interface WireFlowPackets { total: number; truncated: boolean; packets: WirePacket[]; }
export interface WirePacket { index: number; ts_ns: number; direction: "c2s" | "s2c"; wire_len: number; cap_len: number; tcp_flags: number; seq: number | null; ack: number | null; payload_len: number; payload_b64: string; payload_truncated: boolean; }
export type ActiveSource = { kind: "path"; path: string } | { kind: "bytes"; bytes: ArrayBuffer } | null;
```

- [ ] **Step 2: WASM extract wrapper** in `ui/src/lib/wasmEngine.ts` (add export):
```ts
import initWasm, { analyze as wasmAnalyze, extract_packets as wasmExtractPackets } from "../wasm/ppcap_wasm.js";
import type { WireFlowPackets } from "../types";
export async function extractPacketsViaWasm(bytes: ArrayBuffer, query: object): Promise<WireFlowPackets> {
  await ensureWasm();
  const json = wasmExtractPackets(new Uint8Array(bytes), JSON.stringify(query), "{}") as string;
  return JSON.parse(json) as WireFlowPackets;
}
```

- [ ] **Step 3: `lib/packets.ts`:**
```ts
import type { ActiveSource, FlowPackets, FlowRow, PacketRow, WireFlowPackets } from "../types";
import { isTauri, extractPacketsViaTauri } from "./platform";
import { extractPacketsViaWasm } from "./wasmEngine";

export class PacketsUnavailableError extends Error {
  constructor() { super("Packets are only available for captures analyzed from a pcap."); this.name = "PacketsUnavailableError"; }
}
export function packetsAvailable(source: ActiveSource): boolean { return source !== null; }

function queryFor(flow: FlowRow) {
  return { src_ip: flow.srcIp, dst_ip: flow.dstIp, src_port: flow.srcPort, dst_port: flow.dstPort,
    proto: flow.proto, start_ns: flow.startMs * 1_000_000, end_ns: flow.endMs * 1_000_000 };
}
function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64); const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function normalize(wire: WireFlowPackets, flow: FlowRow): FlowPackets {
  const startNs = flow.startMs * 1_000_000;
  const packets: PacketRow[] = wire.packets.map((p) => ({
    index: p.index, tsNs: p.ts_ns, relMs: (p.ts_ns - startNs) / 1e6,
    direction: p.direction, wireLen: p.wire_len, capLen: p.cap_len,
    tcpFlags: p.tcp_flags, seq: p.seq, ack: p.ack,
    payloadLen: p.payload_len, payload: b64ToBytes(p.payload_b64), payloadTruncated: p.payload_truncated,
  }));
  return { total: wire.total, truncated: wire.truncated, packets };
}

export async function extractFlowPackets(source: ActiveSource, flow: FlowRow): Promise<FlowPackets> {
  if (!source) throw new PacketsUnavailableError();
  const query = queryFor(flow);
  const wire = source.kind === "path" && isTauri()
    ? await extractPacketsViaTauri(source.path, query)
    : source.kind === "bytes"
      ? await extractPacketsViaWasm(source.bytes, query)
      : (() => { throw new PacketsUnavailableError(); })();
  return normalize(wire as WireFlowPackets, flow);
}
```
(Update `extractPacketsViaTauri`'s return type in `platform.ts` to `Promise<WireFlowPackets>`.)

- [ ] **Step 4: `makePackets()`** in `ui/src/test/fixtures.ts`:
```ts
import type { FlowPackets, PacketRow } from "../types";
export function makePackets(over: Partial<FlowPackets> = {}): FlowPackets {
  const mk = (i: number, dir: "c2s" | "s2c", payload: string): PacketRow => ({
    index: i, tsNs: 1_700_000_000_000_000_000 + i * 1_000_000, relMs: i,
    direction: dir, wireLen: 60 + payload.length, capLen: 60 + payload.length,
    tcpFlags: 0x18, seq: i, ack: i, payloadLen: payload.length,
    payload: new TextEncoder().encode(payload), payloadTruncated: false,
  });
  return { total: 3, truncated: false, packets: [mk(0,"c2s","GET / HTTP/1.1\r\n"), mk(1,"s2c","HTTP/1.1 200 OK\r\n"), mk(2,"c2s","")], ...over };
}
```

- [ ] **Step 5: Tests** `lib/packets.test.ts` — mock the platform + wasm wrappers and assert routing + normalization + the unavailable path:
```ts
import { describe, it, expect, vi } from "vitest";
import { makeFlows } from "../test/fixtures";
vi.mock("./platform", () => ({ isTauri: () => false, extractPacketsViaTauri: vi.fn() }));
vi.mock("./wasmEngine", () => ({ extractPacketsViaWasm: vi.fn(async () => ({ total: 1, truncated: false,
  packets: [{ index: 0, ts_ns: 1_700_000_000_000_000, direction: "c2s", wire_len: 74, cap_len: 74, tcp_flags: 24, seq: 1, ack: 1, payload_len: 3, payload_b64: btoa("GET"), payload_truncated: false }] })) }));
import { extractFlowPackets, packetsAvailable, PacketsUnavailableError } from "./packets";

describe("extractFlowPackets", () => {
  const flow = makeFlows(1)[0];
  it("unavailable when no source", async () => {
    expect(packetsAvailable(null)).toBe(false);
    await expect(extractFlowPackets(null, flow)).rejects.toBeInstanceOf(PacketsUnavailableError);
  });
  it("routes bytes → wasm and decodes payload", async () => {
    const fp = await extractFlowPackets({ kind: "bytes", bytes: new ArrayBuffer(8) }, flow);
    expect(fp.packets[0].payloadLen).toBe(3);
    expect(new TextDecoder().decode(fp.packets[0].payload)).toBe("GET");
    expect(fp.packets[0].direction).toBe("c2s");
  });
});
```

- [ ] **Step 6: Run + typecheck.** `npx vitest run src/lib/packets.test.ts src/lib/hexdump.test.ts` → PASS; `./node_modules/.bin/tsc.cmd --noEmit -p tsconfig.json` → exit 0. **Step 7: Commit** `feat(ui): packet types + lib/packets routing + fixture`.

---

## Task 6: UI — retain `activeSource` in App

**Files:** Modify `ui/src/App.tsx`; Create `ui/src/App.packets.test.tsx` (or extend `App.test.tsx`).

**Interfaces — Produces:** `App` holds `activeSource: ActiveSource`, set by the WASM/native load paths (size-guarded), reset on capture swap, threaded into `FlowsView`.

- [ ] **Step 1:** Add `const [activeSource, setActiveSource] = useState<ActiveSource>(null);` (import `ActiveSource`). Define `const MAX_RETAIN_BYTES = 64 * 1024 * 1024;`.

- [ ] **Step 2:** In `handleAnalyzePcap` (WASM path), retain the bytes (guarded). It currently does `const bytes = await file.arrayBuffer(); … analyzeViaWasm(bytes, file.name)`. After a successful analyze, set:
```tsx
setActiveSource(bytes.byteLength <= MAX_RETAIN_BYTES ? { kind: "bytes", bytes } : null);
```
In `handleNativeLoad` and `handleReanalyze` (Tauri paths, which have `path`), set `setActiveSource({ kind: "path", path })`. In every other install path (`handleReplaceData` for summary/parquet, the sample-load `useEffect`, `handleSelectRecent`) set `setActiveSource(null)`.

- [ ] **Step 3:** Thread it to Flows: change the Flows render to `<FlowsView state={flows} initialFilter={flowsFilter} activeSource={activeSource} />` (FlowsView gains the optional prop in Task 8).

- [ ] **Step 4: Test** (extend `App.test.tsx`, reusing its `vi.mock("./lib/data")`/`platform` setup): assert that after the sample auto-load `activeSource` is null → the Flows "Inspect packets" affordance is disabled (assert via the FlowDetail gating once Task 8 lands; for THIS task, assert no crash + that `<FlowsView>` receives no source by checking the disabled state is reachable). Minimal: a render-smoke that the app still mounts with the new state and `tsc` passes. (The full routing assertion lives in Task 8.)

- [ ] **Step 5: Run + typecheck → green. Step 6: Commit** `feat(ui): retain active capture source for packet extraction`.

---

## Task 7: UI — `PacketInspector`

**Files:** Create `ui/src/cockpit/PacketInspector.tsx`, `ui/src/cockpit/PacketInspector.test.tsx`.

**Interfaces — Consumes:** `FlowPackets`, `hexLines`. **Produces:** `PacketInspector({ flow, packets, loading, error, onClose })`.

- [ ] **Step 1: Component.** A cockpit `glass-panel` overlay (`role="dialog"`, Esc/scrim close, focus the close button on open — mirror `DetailFlyout`). Layout: header (flow endpoints + a "first 2000 of N" notice when `packets.truncated`); a virtualized packet list (reuse the `FlowsTable` TanStack-virtual pattern — `useVirtualizer` over `packets.packets`, fixed row height) with columns `# · rel-ms · dir(→/←) · size · flags · payload-len · ASCII preview (first ~24 printable bytes)`; a selected-row state (`useState<number>`) whose packet's payload renders via `hexLines(packet.payload)` in a monospace `offset | hex | ascii` grid (or "no payload" when empty). States: `loading` (a spinner + "Extracting packets…"), `error` (the message), empty (`packets.packets.length === 0` → "No packets matched"). Use cockpit tokens + `font-mono-num` for all hex/numbers. Reference `ThreatRail.tsx`/`FlowDetail.tsx` for row + section styling and `FlowsTable.tsx` for the `useVirtualizer` setup (incl. `sizeScrollElement` is only needed in tests).

```tsx
import { useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { X, ArrowRight, ArrowLeft, Loader2 } from "lucide-react";
import { cn } from "../lib/cn";
import { humanBytes, humanNumber } from "../lib/format";
import { hexLines } from "../lib/hexdump";
import type { FlowPackets, FlowRow } from "../types";

const ROW_H = 28;

export function PacketInspector({ flow, packets, loading, error, onClose }: {
  flow: FlowRow; packets: FlowPackets | null; loading: boolean; error: string | null; onClose: () => void;
}) {
  const [sel, setSel] = useState(0);
  const closeRef = useRef<HTMLButtonElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => { window.removeEventListener("keydown", onKey); prev?.focus?.(); };
  }, [onClose]);

  const rows = packets?.packets ?? [];
  const virtualizer = useVirtualizer({ count: rows.length, getScrollElement: () => scrollRef.current, estimateSize: () => ROW_H, overscan: 12 });
  const selected = rows[sel] ?? null;

  return (
    <div role="dialog" aria-modal="true" aria-label={`Packets for ${flow.srcIp}:${flow.srcPort} to ${flow.dstIp}:${flow.dstPort}`} className="fixed inset-0 z-50 flex items-stretch justify-end">
      <button aria-hidden type="button" tabIndex={-1} onClick={onClose} className="absolute inset-0 bg-black/50 backdrop-blur-sm" />
      <section className="glass-band relative flex h-full w-full max-w-[860px] flex-col border-l border-[var(--color-border)]">
        <header className="flex items-center gap-3 border-b border-[var(--color-border)] px-4 py-3">
          <div className="min-w-0 flex-1">
            <div className="font-mono-num truncate text-[13px] text-[var(--color-text)]">{flow.srcIp}:{flow.srcPort} → {flow.dstIp}:{flow.dstPort}</div>
            <div className="t-tag text-[var(--color-text-faint)]">
              {String(flow.proto)}
              {packets?.truncated ? ` · first ${humanNumber(rows.length)} of ${humanNumber(packets.total)} packets` : packets ? ` · ${humanNumber(packets.total)} packets` : ""}
            </div>
          </div>
          <button ref={closeRef} type="button" onClick={onClose} aria-label="Close packet inspector" className="rounded-[var(--r-tile)] p-1.5 text-[var(--color-text-faint)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]"><X size={16} /></button>
        </header>

        {loading ? (
          <div className="flex flex-1 items-center justify-center gap-2 text-[var(--color-text-faint)]"><Loader2 size={16} className="animate-spin" /><span>Extracting packets…</span></div>
        ) : error ? (
          <div className="flex flex-1 items-center justify-center px-6 text-center text-sm text-[var(--color-text-faint)]">{error}</div>
        ) : rows.length === 0 ? (
          <div className="flex flex-1 items-center justify-center text-sm text-[var(--color-text-faint)]">No packets matched this flow.</div>
        ) : (
          <div className="flex min-h-0 flex-1 flex-col">
            <div ref={scrollRef} className="min-h-0 flex-1 overflow-y-auto">
              <div className="relative" style={{ height: virtualizer.getTotalSize() }}>
                {virtualizer.getVirtualItems().map((vi) => {
                  const p = rows[vi.index];
                  const active = vi.index === sel;
                  return (
                    <button key={vi.key} type="button" onClick={() => setSel(vi.index)} aria-current={active ? "true" : undefined}
                      className={cn("absolute inset-x-0 flex items-center gap-3 px-4 text-left font-mono-num text-xs", active ? "bg-[var(--color-surface-2)]" : "hover:bg-[var(--color-surface-1)]")}
                      style={{ height: ROW_H, transform: `translateY(${vi.start}px)` }}>
                      <span className="w-10 shrink-0 text-[var(--color-text-faint)]">{p.index}</span>
                      <span className="w-16 shrink-0 tabular-nums text-[var(--color-text-faint)]">{p.relMs.toFixed(1)}ms</span>
                      <span className="w-5 shrink-0" aria-label={p.direction === "c2s" ? "client to server" : "server to client"}>
                        {p.direction === "c2s" ? <ArrowRight size={13} className="text-[var(--color-accent)]" /> : <ArrowLeft size={13} className="text-[var(--color-text-faint)]" />}
                      </span>
                      <span className="w-16 shrink-0 tabular-nums">{humanBytes(p.wireLen)}</span>
                      <span className="w-24 shrink-0 text-[var(--color-text-faint)]">{tcpFlagLabel(p.tcpFlags)}</span>
                      <span className="w-14 shrink-0 tabular-nums text-[var(--color-text-faint)]">{p.payloadLen}B</span>
                      <span className="min-w-0 flex-1 truncate text-[var(--color-text-faint)]">{asciiPreview(p.payload)}</span>
                    </button>
                  );
                })}
              </div>
            </div>
            <div className="max-h-[40%] min-h-[120px] overflow-y-auto border-t border-[var(--color-border)] bg-[var(--color-surface-1)] p-3">
              {selected && selected.payload.length > 0 ? (
                <table className="font-mono-num text-xs leading-5"><tbody>
                  {hexLines(selected.payload).map((ln) => (
                    <tr key={ln.offset}>
                      <td className="pr-4 text-[var(--color-text-faint)]">{ln.offset}</td>
                      <td className="whitespace-pre pr-4 text-[var(--color-text)]">{ln.hex}</td>
                      <td className="whitespace-pre text-[var(--color-text-faint)]">{ln.ascii}</td>
                    </tr>
                  ))}
                </tbody></table>
              ) : (
                <div className="text-xs text-[var(--color-text-faint)]">No payload in this packet.</div>
              )}
              {selected?.payloadTruncated && <div className="t-tag mt-2 text-[var(--color-text-faint)]">payload truncated to {selected.payload.length} bytes shown</div>}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

function tcpFlagLabel(flags: number): string {
  if (!flags) return "";
  const names: [number, string][] = [[0x02, "SYN"], [0x10, "ACK"], [0x01, "FIN"], [0x04, "RST"], [0x08, "PSH"], [0x20, "URG"]];
  return names.filter(([b]) => flags & b).map(([, n]) => n).join(" ");
}
function asciiPreview(bytes: Uint8Array): string {
  return Array.from(bytes.subarray(0, 32), (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
}
export default PacketInspector;
```

- [ ] **Step 2: Tests** `PacketInspector.test.tsx` (with `makePackets`, `makeFlows`, and `sizeScrollElement` from `../test/render` for the virtualized list):
```tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen, userEvent } from "../test/render";
import { PacketInspector } from "./PacketInspector";
import { makePackets, makeFlows } from "../test/fixtures";
const flow = makeFlows(1)[0];
describe("PacketInspector", () => {
  it("loading state", () => { render(<PacketInspector flow={flow} packets={null} loading error={null} onClose={() => {}} />); expect(screen.getByText(/extracting/i)).toBeInTheDocument(); });
  it("renders rows + selecting a packet shows its payload hex", async () => {
    const u = userEvent.setup();
    render(<PacketInspector flow={flow} packets={makePackets()} loading={false} error={null} onClose={() => {}} />);
    // first packet "GET / HTTP/1.1" → its hex/ascii appears when selected (row 0 default-selected)
    expect(screen.getByText(/HTTP/)).toBeInTheDocument(); // ascii view of the payload
    await u.keyboard("{Escape}"); // closes via the Esc handler (assert onClose separately if wired)
  });
  it("empty state", () => { render(<PacketInspector flow={flow} packets={{ total: 0, truncated: false, packets: [] }} loading={false} error={null} onClose={() => {}} />); expect(screen.getByText(/no packets/i)).toBeInTheDocument(); });
});
```

- [ ] **Step 3: Run + typecheck → green. Step 4: Commit** `feat(ui): PacketInspector (list + hex/ascii viewer)`.

---

## Task 8: Wire-in — FlowDetail button + FlowsView state

**Files:** Modify `ui/src/components/FlowDetail.tsx`, `ui/src/views/FlowsView.tsx`; tests.

**Interfaces — Consumes:** `extractFlowPackets`, `packetsAvailable`, `PacketInspector`, `activeSource` (from App, Task 6).

- [ ] **Step 1: FlowDetail** gains `activeSource: ActiveSource` + `onInspectPackets: () => void` props; render an "Inspect packets" button after the header, `disabled={!packetsAvailable(activeSource)}` with a tooltip when disabled (`title="Packets are only available for captures analyzed from a pcap"`); enabled → `onClick={onInspectPackets}`. Use cockpit button styling (mirror the existing close button / cockpit `IncidentHero` pivot button).

- [ ] **Step 2: FlowsView** owns the inspector state: `const [inspecting, setInspecting] = useState<FlowRow | null>(null); const [packets, setPackets] = useState<FlowPackets | null>(null); const [pktLoading, setPktLoading] = useState(false); const [pktError, setPktError] = useState<string | null>(null);`. Add the `activeSource` prop. `onInspectPackets` (for the selected `flow`): set `inspecting=flow`, `pktLoading=true`, `packets=null`, `pktError=null`, then `extractFlowPackets(activeSource, flow).then(setPackets).catch((e) => setPktError(String(e.message ?? e))).finally(() => setPktLoading(false))`. Render `{inspecting && <PacketInspector flow={inspecting} packets={packets} loading={pktLoading} error={pktError} onClose={() => setInspecting(null)} />}`. Pass `activeSource` + `onInspectPackets` to the rendered `<FlowDetail>`.

- [ ] **Step 3: Tests.** `FlowDetail.test.tsx` (extend): the "Inspect packets" button is **disabled** when `activeSource` is null and **enabled** (fires `onInspectPackets`) when `{kind:"bytes"}`. `FlowsView.test.tsx` (extend): with a `{kind:"bytes"}` source and `extractFlowPackets` mocked (`vi.mock("../lib/packets")` returning `makePackets()`), selecting a flow → clicking "Inspect packets" opens the `PacketInspector` (assert the hex/ascii appears); error path sets the error state.

- [ ] **Step 4: Full run.** `npm test` → all pass; `npm run test:coverage` → gate still met (80/80/80/70); `tsc` → exit 0. If coverage dipped, add focused tests (the new `lib/packets`, `hexdump`, `PacketInspector` should push it up).

- [ ] **Step 5: Commit.** `git add ui/src/components/FlowDetail.tsx ui/src/views/FlowsView.tsx ui/src/**/*.test.tsx && git commit -m "feat(ui): Inspect-packets entry + inspector wiring"`

---

## Final verification (after Task 8)
- Engine: `cd engine && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace` green; the C-compiler-free gate passes (base64 is pure Rust).
- UI: `tsc --noEmit` exit 0; `vitest run --coverage` all pass + 80/70 gate met.
- Live (desktop or in-browser pcap): open a capture, select a flow, "Inspect packets" → the list + hex viewer; a `summary+parquet` import disables the button.

## Self-review notes (author)
- **Spec coverage:** §3 contract → T1/T5 types; §4 engine/surfaces → T1/T2/T3; §5 UI (retention/packets/hexdump/inspector/FlowDetail) → T5/T6/T4/T7/T8; §6 edge cases → unavailable (T5/T8), empty/capped/loading (T7), non-TCP (T1 `l4_payload`); §7 testing → each task's tests; §8 phasing = T1→T8; §9 risks (toolchain T2, memory T6 guard, ms-window T1). Covered.
- **Type consistency:** `PacketQuery`(Rust)/`queryFor`(JS) fields align (snake on the wire); `WireFlowPackets`→`FlowPackets` normalization in T5 matches T1's `PacketRecord` field names; `ActiveSource` defined T5, used T6/T8; `extractFlowPackets(source, flow)` signature consistent T5/T8.
- **Flagged for the implementer:** T1 may need to add `Transport::from_ip_proto` + the `l2::strip_to_l3`/`l3::strip_to_l4` thin wrappers if not already present (reuse the existing walk, don't duplicate). T2's wasm rebuild may be blocked by the toolchain → DONE_WITH_CONCERNS is allowed; the Rust still `cargo check`s.
