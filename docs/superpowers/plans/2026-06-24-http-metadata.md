# HTTP request metadata — implementation plan

Spec: [2026-06-24-http-metadata-design.md](../specs/2026-06-24-http-metadata-design.md)

Two per-flow columns reusing the decode L7 sniff + header helpers. One PR (direct to main).

## Engine (`engine/crates/ppcap-core/src/`)

1. `decode/mod.rs`: `http_header_value(buf, name)` (anchored header-line extraction, body never
   scanned, printable-ASCII, `MAX_HTTP_HEADER = 256`). `L7Hint::Http { host, user_agent }` (was
   `{ method }`); `l7_hint` extracts both on an HTTP request; the decode arm sets
   `meta.http_host`/`http_ua`. Tests: `http_header_value` extract/bound/anchor + `l7_hint` carries
   host/UA.
2. `model/packet.rs`: `PacketMeta.http_host`/`http_ua` (+ all literal sites). `model/flow.rs`:
   `FlowRecord.http_host`/`http_ua` + `new()` + sticky folds.
3. Columnar: `schema.rs` (columns 27/28, `FLOW_PARQUET_VERSION` 8→9, 31 cols), `mod.rs` (builders +
   finish + write + dict_cols + test 31). `sql/schema.sql`. `ppcap-wasm` `FlowDto`.
4. Test positional readers: `schema_drift` (31), `columnar_roundtrip` (31 + severity/score/ioc at
   28/29/30), `threat_e2e` (28/29/30).

## UI (`ui/src/`)

5. `types.ts`: `http_host`/`http_ua` (+ `httpHost`/`httpUa` on FlowRow). `lib/data.ts`: both paths.
   `FlowsTable.tsx` (Host chip, UA in tooltip) + `FlowDetail.tsx` (two fields) + `FlowsView.tsx`
   (search) + `test/fixtures.ts` + `data.test.ts`.

## Verify

Engine: full `cargo test -p ppcap-core` · `clippy`. UI: `test:coverage` · `build`. `build:wasm`.
Review of parse safety + privacy + 31-column lockstep. Then commit direct to `main`.
