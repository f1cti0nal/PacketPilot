# HASSHServer — implementation plan

Spec: [2026-06-24-hassh-server-design.md](../specs/2026-06-24-hassh-server-design.md)

Second per-flow column, mirroring `hassh`. One PR. Phase B of the HASSH feature.

## Engine (`engine/crates/ppcap-core/src/`)

1. `ssh/mod.rs`: `parse_kexinit` returns all 7 lists (add `enc_s2c`/`mac_s2c`/`comp_s2c`);
   `sniff_server_hassh` = `MD5("kex;enc_s2c;mac_s2c;comp_s2c")`, TCP-only, server orientation
   (`src_port < dst_port`). Tests: server HASSH == MD5 of the s2c lists (distinct from client);
   client/symmetric/non-TCP → none.
2. `decode/mod.rs`: also set `meta.hassh_server`. `model/packet.rs`: `PacketMeta.hassh_server`
   (+ all literal sites). `model/flow.rs`: `FlowRecord.hassh_server` + `new()` + sticky fold.
3. Columnar: `schema.rs` (column 25 `hassh_server`, `FLOW_PARQUET_VERSION` 6→7, 28 cols), `mod.rs`
   (builder + finish + write + dict_cols + test 28). `sql/schema.sql`. `ppcap-wasm` `FlowDto`.
4. Test positional readers: `schema_drift` (28), `columnar_roundtrip` (28 + severity/score/ioc at
   25/26/27), `threat_e2e` (25/26/27).

## UI (`ui/src/`)

5. `types.ts`: `hassh_server`/`hasshServer` on the three row types. `lib/data.ts`: both paths.
   `FlowsTable.tsx` (HASSHs chip) + `FlowDetail.tsx` (field) + `FlowsView.tsx` (search) +
   `test/fixtures.ts` + `data.test.ts`.

## Verify

Engine: full `cargo test -p ppcap-core` · `clippy`. UI: `test:coverage` · `build`. `build:wasm`.
Focused review of the s2c mapping + server orientation + 28-column lockstep. Then PR, merge on local
gates.
