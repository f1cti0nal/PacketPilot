# SYN-flood / TCP-DoS detection — design

Status: design · 2026-06-24 · Feature: detect a service flooded with half-open connections (ATT&CK
T1499.001, Endpoint DoS: OS Exhaustion Flood). Fills the **Impact** tactic — the one ATT&CK tactic
the detector suite did not cover.

## Problem

PacketPilot's detectors span Discovery (sweep, port-scan), Credential Access (brute-force, cleartext
creds), Lateral Movement, Collection (PII, ARP-spoof), Command-and-Control (beacon, DNS-tunnel, DGA),
and Exfiltration — but nothing for **Impact / denial-of-service**. A SYN flood (and TCP DoS in
general) is a flood of connection attempts that never complete the handshake, exhausting a target
service. It's a distinct shape: **many half-open connections to one `(target, port)`**.

## Approach

A behavioral detector reusing the session-completion signal built for the port-scan — engine-only, no
new deps:
- **Tracker:** `syn_flood: HashMap<(target, port), {incomplete, sources}>`, folded in
  `observe_flow_contact` behind a **dedicated half-open gate** (review-hardened): a flow counts only
  when its **client→server** wire bytes stay below `SYN_FLOOD_HALF_OPEN_BYTES` (256) — i.e. the client
  sent only handshake control (SYN/ACK/RST), never an application request. This is deliberately
  decoupled from the port-scan's `SCAN_SESSION_BYTES` gate (a different question), so a busy
  small-response service does **not** false-positive: even a health check / HTTP 204 / OCSP client
  *sends a request*, pushing its client→server bytes over the floor. (We key on the client sending
  nothing real — **not** `bytes_in == 0`: a flood to an *open* port still draws a SYN-ACK back, so
  `bytes_in ≈ 60`, not 0.) It increments the per-target incomplete count and records the (bounded)
  distinct sources.
- **Detector:** `detect_syn_flood` flags a `(target, port)` at ≥ `min_incomplete` (default **200**)
  half-open connections. High severity, T1499.001, Impact kill-chain stage. The evidence reports the
  source count, distinguishing a single-source flood from a distributed one. `ignore_dst` exempts a
  known load-tested target.

## Orthogonality (why it doesn't overlap)

This shares the probe-flow fold with the port-scan but keys differently: **port-scan** = one source →
many *ports* on one host (`(src, dst)`); **SYN-flood** = many incomplete connections to one
*`(dst, port)`*. A host sweep puts one incomplete per `(dst, X)` (no single target floods); a vertical
scan puts one per `(dst, port)` (each port a distinct bucket). So sweeps/scans don't false-positive as
a flood, and a flow legitimately contributes to both signals only when both shapes are truly present.

## Scope

In: the per-`(target, port)` half-open count with a min-incomplete floor + an ignore-dst allowlist.
Out: UDP/ICMP volumetric floods, amplification-reflection detection, rate/timing analysis.

## Invariants

Engine-only; no new deps. Bounded memory (per-target source set + map both capped; saturating count).
Deterministic order. Reuses the existing probe-flow gate (no new per-packet work).
