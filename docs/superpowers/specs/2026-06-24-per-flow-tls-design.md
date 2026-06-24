# Per-flow TLS version + cipher columns — design

Status: design · 2026-06-24 · Feature: surface the negotiated TLS **version** and **cipher suite**
per flow in the flows table, alongside the existing JA3 / JA4 / SNI columns.

## Problem

The flows table shows the client-side TLS fingerprint (SNI / JA3 / JA4) per flow, but not the
*negotiated* TLS posture — the protocol version and cipher suite the server actually chose. That is
the signal an analyst wants to spot **legacy TLS (1.0/1.1) or weak ciphers across all flows**, not
only the ones that trip the weak-TLS *finding* (which is gated on a threshold). The engine already
parses the server ServerHello (for the weak-TLS detector); this exposes that data per-flow.

## Approach

Mirror the JA3/JA4 column path through the entire pipeline (FlowRecord → Arrow/Parquet → DuckDB view
→ WASM/Tauri flow rows → UI FlowRow → flows table + detail), populated from a **decode-time
ServerHello sniff**:
- `decode`: a payload-free best-effort sniff — when an L4 payload begins with a server ServerHello,
  `crate::tls::sniff_server_hello` extracts the negotiated `(version, cipher)` and decode sets
  `PacketMeta.tls_version` (a version label, with the `supported_versions` override so TLS 1.3 reads
  correctly) + `tls_cipher` (the IANA cipher name when known, else `0xNNNN`). The ServerHello almost
  always fits the first server packet, so a decode-time single-packet sniff is sufficient for the
  column (the detector's bounded reassembler handles the rare multi-segment case independently).
- `FlowRecord`: two new sticky fields folded first-non-empty (exactly like sni/ja3/ja4).
- Persisted as two new Arrow/Parquet columns (`tls_version`, `tls_cipher`) between `ja4` and
  `severity`; `FLOW_PARQUET_VERSION` bumped 4 → 5; the DuckDB view SELECT + `flow_columns_in_order`
  + the schema-drift / roundtrip guards updated.
- UI: carried on `RawFlowRow` (parquet, by-name) / `WasmFlow` (FlowDto JSON) and mapped to
  `FlowRow.tlsVersion` / `tlsCipher`; shown as a compact version chip in the flows table (cipher in
  the tooltip) and as two fields in the flow detail's Application (L7) section.

## A subtlety this introduces

Previously only a ClientHello set `app_proto = Tls`. Now a ServerHello does too (it *is* TLS). The
reassembler used `app_proto == Tls` to mean "ClientHello"; that discriminator is changed to
`app_proto == Tls && (ja3 || ja4)` (a ClientHello always fingerprints; a ServerHello never does), so
the cert detector still routes server flights correctly. (Caught by the existing cert end-to-end
test.) The classify/stats ripple is benign-or-better: a server-only TLS flow is now correctly
labeled TLS.

## Scope

In: negotiated version + cipher per flow over TCP-TLS (all versions — ServerHello is cleartext),
table chip + detail fields. Out: full IANA cipher-name table (common + weak suites named, else hex),
QUIC, per-flow JA3S/server fingerprints.

## Invariants

No new dependencies; C-free. Bounded (payload-free sniff; sticky strings like ja3/ja4). The 6-layer
column order stays identical (CI-guarded by `schema_drift` + `columnar_roundtrip`).
