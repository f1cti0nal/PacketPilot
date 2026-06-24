# HASSH — SSH client fingerprinting — design

Status: design · 2026-06-24 · Feature: a per-flow **HASSH** column — the SSH analogue of JA3/JA4 — so
analysts can fingerprint and pivot on SSH client software.

## Problem

PacketPilot fingerprints TLS clients (JA3/JA4) and servers (per-flow TLS version/cipher), but SSH —
a top brute-force / lateral-movement vector — is opaque beyond the flow 5-tuple. HASSH
(`MD5("kex;enc;mac;comp")` over a client's `SSH_MSG_KEXINIT`) identifies the SSH *client stack*:
OpenSSH, PuTTY, libssh, **paramiko**, Go `x/crypto/ssh`, scanners — scripted/automated clients have
distinct, recurring HASSHes. It pairs naturally with the brute-force detector (fingerprint the
attacking client) and is a recognized, deployable IOC.

## Approach

A per-flow `hassh` column over the existing per-flow-column pipeline — engine-only parsing, no new
dependencies (reuses the vendored `fingerprint::md5_hex`):
- `ssh/mod.rs` (`sniff_client_hassh`): skip an optional `SSH-…` identification line, parse the
  KEXINIT (bounded, allocation-light, `None` on any mismatch), and `MD5` the four client→server
  name-lists `kex;enc_c2s;mac_c2s;comp_c2s`. Payload-free — only the derived fingerprint is kept.
- **Client/server role:** HASSH is the *client's*. Without flow state, `decode` orients by port (the
  server listens on the lower port): a client→server KEXINIT travels toward the lower port
  (`dst_port <= src_port`); server KEXINITs are skipped.
- The fingerprint threads through the standard pipeline: `PacketMeta.hassh` → sticky
  `FlowRecord.hassh` (client-only, so direction-independent like `ja3`) → Arrow/Parquet column 24 →
  DuckDB `flow` view → `ppcap-wasm` `FlowDto` → UI `RawFlowRow`/`WasmFlow`/`FlowRow` → a chip in the
  flows table + a field in the flow drawer + the flows search index.

## Scope

In: the **client** HASSH (single per-flow column), parsed from a single-segment **TCP** KEXINIT. Out
(phase B): `hasshServer`, cross-segment KEXINIT reassembly, an SSH `AppProto` label, matching HASSH
against a malware-fingerprint feed.

Review-hardened: the sniff is TCP-gated (SSH is TCP-only, mirroring the cleartext-cred / PII
sniffers), and the client/server port check is strict (`dst_port < src_port`) so a symmetric
`src==dst` flow drops rather than mislabeling. Residual (documented, low-impact): a server on a port
*higher* than the client's source port inverts the port heuristic — the proper fix is the deferred
orientation-aware `hasshServer` column.

## Invariants

Engine-only; no new deps. Bounded + panic-free parsing (every slice bounds-checked). Payload-free
(only the MD5 retained). `FLOW_PARQUET_VERSION` bumped 5 → 6 with the new column; schema-drift /
roundtrip / threat_e2e positional readers updated in lockstep.
