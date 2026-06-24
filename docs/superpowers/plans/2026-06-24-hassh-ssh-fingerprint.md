# HASSH SSH fingerprinting — implementation plan

Spec: [2026-06-24-hassh-ssh-fingerprint-design.md](../specs/2026-06-24-hassh-ssh-fingerprint-design.md)

Per-flow column (the established ~12-file / 6-layer template) + a new SSH parser. One PR.

## Engine (`engine/crates/ppcap-core/src/`)

1. `ssh/mod.rs` (new): `sniff_client_hassh(src_port, dst_port, payload) -> Option<String>` —
   banner-skip, `parse_kexinit` (bounded), `NameListReader`, `MD5("kex;enc_c2s;mac_c2s;comp_c2s")`
   via `fingerprint::md5_hex`. Client-only via the port heuristic. Unit tests. Register `mod ssh` in
   `lib.rs`.
2. `model/packet.rs`: `PacketMeta.hassh`. `decode/mod.rs`: call the sniff (set `meta.hassh`).
3. `model/flow.rs`: `FlowRecord.hassh` + `new()` + sticky `observe` fold.
4. Columnar: `schema.rs` (column 24 `hassh`, `FLOW_PARQUET_VERSION` 5→6, `flow_columns_in_order`
   27), `mod.rs` (builder + `finish` + `write` + `dict_cols` + test count 27). `sql/schema.sql`
   (`hassh` after `tls_cipher`). `ppcap-wasm` `FlowDto.hassh` + `from_record`.

## UI (`ui/src/`)

5. `types.ts`: `hassh` on `RawFlowRow`/`WasmFlow`/`FlowRow`. `lib/data.ts`: map in both paths.
6. `components/flows/FlowsTable.tsx`: HASSH chip. `components/FlowDetail.tsx`: HASSH field.
   `views/FlowsView.tsx`: add to the search index. `test/fixtures.ts`: `makeFlows` carries a hassh.

## Tests

7. `ssh/mod.rs`: HASSH == MD5 of the c2s lists; banner-prefix skip; server KEXINIT not client-FP;
   non-SSH rejected. `data.test.ts`: hassh passthrough (WASM + parquet). `FlowDetail.test.tsx` +
   `FlowsView.test.tsx`: the field + chip render. Update the positional indices in
   `schema_drift` / `columnar_roundtrip` / `threat_e2e`.

## Verify

Engine: full `cargo test -p ppcap-core` · `clippy`. UI: `test:coverage` · `build`. `build:wasm`.
Adversarial review of the parser (FP, panic-safety, the HASSH formula, the port heuristic, column
drift). Then PR, merge on local gates.
