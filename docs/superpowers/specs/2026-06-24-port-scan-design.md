# Vertical port-scan detection — design

Status: design · 2026-06-24 · Feature: detect one source probing many distinct ports on a single host
(ATT&CK T1046, Network Service Discovery — the vertical/port-enumeration variant).

## Problem

PacketPilot detects **horizontal** sweeps (the `fanout` map: one source → many distinct *hosts* on
one *port*, e.g. an SMB sweep). The **orthogonal** axis — one source → many distinct *ports* on one
*host* (the `nmap -p-` signature) — is not covered. Vertical port scanning is the other half of
reconnaissance and a flagship NDR detection; the two are complementary, not redundant.

## Approach

A behavioral detector mirroring the host-sweep, over the existing contact-fold path — engine-only, no
new deps:
- **Tracker:** `port_scan: HashMap<(src, host), HashSet<port>>` folded in `observe_flow_contact`
  alongside `fanout`, with the same two-dimensional bound (`max_fanout_per_src` ports per pair,
  `max_tracked_keys` pairs).
- **Detector:** `detect_port_scan` flags a `(src, host)` pair at ≥ `min_ports` (default **30**)
  distinct ports. High severity, T1046, `dst_ip = Some(host)` / `dst_port = None` (a per-host
  finding, the mirror of the sweep's per-port `dst_ip = None`). Discovery kill-chain stage.

## FP control

Two gates (the second was added in adversarial review):
1. **Probe-only counting (the load-bearing FP control):** only a *probe* flow — one that did **not**
   complete a real bidirectional session — counts toward the port set. A flow with ≥ `SCAN_SESSION_BYTES`
   (512) *wire* bytes in **both** directions is a real session and is excluded. This is what separates
   a scanner from a *busy legit client*: passive-FTP data transfers, health checks, and service-mesh
   calls complete real sessions (bytes both ways), while a SYN/RST scan probe stays tiny each way.
   Without it, the port count alone cannot tell an FTP mirror's dozens of data ports from a scan.
   Mirrors the lateral-movement detector's `min_session_bytes` floor.
2. `min_ports = 30` keeps the count well above ordinary client probing, and a `PortScanParams.ignore_src`
   allowlist exempts a sanctioned vulnerability scanner / monitoring probe (mirrors
   `LateralMovementParams.ignore_src`).

## Scope

In: the `(src, host)` distinct **probed** port count, with a min-ports floor + an ignore-src
allowlist. Out: horizontal+vertical correlation, per-port-range heuristics. Residual (narrow): a
client doing many *tiny* completed sessions (< 512 B each way) to one host across 30+ ports is still
counted — handled by `ignore_src`.

## Invariants

Engine-only; no new deps. Bounded memory (per-pair port set + map both capped, mirroring `fanout`).
Deterministic order. A real scanner that hits *both* many hosts and many ports legitimately raises
*both* a sweep and a port-scan finding — correct, not a double-count.
