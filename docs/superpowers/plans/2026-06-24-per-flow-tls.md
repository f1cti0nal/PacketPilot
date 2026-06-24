# Per-flow TLS version + cipher columns — implementation plan

Spec: [2026-06-24-per-flow-tls-design.md](../specs/2026-06-24-per-flow-tls-design.md)

One vertical PR. Mirrors the ja3/ja4 column path through all 6 pipeline layers.

## Engine

1. `tls/mod.rs`: `pub(crate) sniff_server_hello(payload) -> Option<(&'static str, String)>` (version
   label + cipher label) over `parse_server_hello`; `cipher_label` / `cipher_name` + a `COMMON_CIPHERS`
   table (modern + reuse `WEAK_CIPHERS` names). Fix the reassembler `observe` ClientHello
   discriminator → `app_proto == Tls && (ja3 || ja4)`.
2. `model/packet.rs`: `PacketMeta.tls_version` / `tls_cipher` (+ all literal sites: decode ctor, the
   test literals in decode/stats/flow/model-flow + tests/flow_symmetry).
3. `decode/mod.rs`: in the L7 sniff block, `sniff_server_hello(payload)` → set app_proto=Tls +
   tls_version + tls_cipher. Test: ServerHello sets them, ClientHello does not.
4. `model/flow.rs`: `FlowRecord.tls_version` / `tls_cipher` fields + `new()` + sticky `observe`.
   Extend the ja3/ja4 sticky test.
5. `columnar/schema.rs`: bump `FLOW_PARQUET_VERSION` 4→5, add 2 Arrow fields after ja4, add to
   `flow_columns_in_order` ([..;26]), update the "26 columns" doc.
6. `columnar/mod.rs`: 2 `StringBuilder`s (struct + new + finish Vec order) + 2 write() appends +
   the finish test's append_null + num_columns 24→26.
7. `sql/schema.sql`: add `tls_version, tls_cipher` to the flow view SELECT (after ja4).
8. `tests/schema_drift.rs`: count 24→26. `tests/columnar_roundtrip.rs`: count 24→26 + shift the
   severity/threat_score/ioc positional indices +2.
9. `ppcap-wasm/src/lib.rs`: `FlowDto` 2 fields + `from_record` mapping.

## UI

10. `types.ts`: add to `RawFlowRow`, `WasmFlow`, `FlowRow` (`tlsVersion`/`tlsCipher`).
11. `lib/data.ts`: map in `normalizeFlow` + `flowRowFromWasm`.
12. `components/flows/FlowsTable.tsx`: a compact version chip in the Proto/App/SNI column (cipher in
    the tooltip). `components/FlowDetail.tsx`: 2 fields in the L7 section.
13. Tests: extend `data.test.ts` (assert the tls mapping); `makeFlows` fixture carries the fields.

## Gates

Engine: `fmt` · `clippy -D warnings` · `test` (incl. schema_drift + columnar_roundtrip) · C-free ·
`wasm32`. UI: `build:wasm` · `test:coverage` (80/70) · `build`. Then adversarial review, PR, merge on
local gates.
