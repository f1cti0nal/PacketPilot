# HASSHServer — server-side SSH fingerprint — design

Status: design · 2026-06-24 · Feature: phase B of HASSH — add the **server**-side SSH fingerprint
(`hasshServer`) as a second per-flow column, completing the SSH-fingerprinting story (JA3S to HASSH's
JA3).

## Problem

The HASSH feature added the SSH *client* fingerprint (`hassh`). The server side — `MD5("kex;enc_s2c;
mac_s2c;comp_s2c")` over the server's KEXINIT — was explicitly deferred. HASSHServer identifies the
SSH *server* build (OpenSSH version family, dropbear, a honeypot's stack, an embedded device), useful
for asset inventory and spotting anomalous/rogue SSH servers. The KEXINIT parser already exists and
already reads every name-list; only the server lists were discarded.

## Approach

Engine-only, no new deps:
- `ssh/mod.rs`: `parse_kexinit` now returns all seven HASSH-relevant lists. `sniff_server_hassh`
  computes `MD5("kex;enc_s2c;mac_s2c;comp_s2c")`, the exact mirror of `sniff_client_hassh` — TCP-only,
  and the server's KEXINIT travels **from** the lower / listening port (`src_port < dst_port`,
  strict). The two port gates are mutually exclusive, so a single KEXINIT packet sets at most one of
  `hassh` / `hassh_server`.
- The fingerprint threads through the per-flow-column pipeline exactly like `hassh`: `PacketMeta.
  hassh_server` → sticky `FlowRecord.hassh_server` → Arrow/Parquet column 25 (`FLOW_PARQUET_VERSION`
  6 → 7, 28 columns) → DuckDB view → `ppcap-wasm` `FlowDto` → UI `RawFlowRow`/`WasmFlow`/`FlowRow` →
  a HASSHs chip in the flows table + a "SSH HASSHServer" field in the drawer + the flows search index.

## Scope

In: the **server** HASSHServer single per-flow column. Out: cross-segment KEXINIT reassembly (shared
with the client path), matching against a fingerprint feed.

## Invariants

Engine-only; no new deps. Bounded + panic-free parsing (unchanged from HASSH). Payload-free. The
`hassh` / `hassh_server` port gates are mutually exclusive. Column shift to 28 with schema-drift /
roundtrip / threat_e2e positional readers updated in lockstep.
