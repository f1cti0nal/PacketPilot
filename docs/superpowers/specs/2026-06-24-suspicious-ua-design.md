# Suspicious User-Agent (attack-tool) detection — design

Status: design · 2026-06-24 · Feature: flag sources whose HTTP `User-Agent` matches a known
attack-tool / scanner signature (ATT&CK T1595, Active Scanning).

## Problem

The HTTP-metadata feature now extracts the request `User-Agent` per flow. Many scanners and
exploitation tools ship a default, self-identifying User-Agent (`sqlmap`, `Nikto`, `Nmap NSE`,
`masscan`, `nuclei`, `WPScan`, Shellshock probes …) and a surprising fraction of real attackers never
change it. Surfacing that as a finding turns a raw column into an actionable indicator, and it pairs
with the port-scan / brute-force detectors (a scanning host *and* a tool UA is a strong combined
signal).

## Approach

A behavioral detector over the (just-shipped) `http_ua`, engine-only, no new deps and **no new
column** (it's a `Finding`):
- `detect/mod.rs`: a `TOOL_USER_AGENTS` table of high-confidence tool substrings → label.
  `observe_user_agent(src, ua)` (called per HTTP request in the analyze loop) records a source only
  when its UA matches a tool (the derived label + hit count + one example UA — never raw payload
  beyond the bounded sample). `detect_suspicious_ua` emits one High-severity `SuspiciousUa` finding
  per source. Discovery kill-chain stage.

## FP control

The table is deliberately limited to **unambiguous, coined** tool tokens (`sqlmap`, `nikto`,
`masscan`, `nuclei`, …) with no realistic benign User-Agent collision. Dual-use clients (`curl`,
`wget`, `python-requests`) — which legitimate scripts also use — are **excluded**. Review-hardened:
`hydra` was *removed* — it is an ordinary word / product name (the Hydra livecoding tool, config
frameworks, CI systems) that collides with benign UAs, and THC-Hydra is a login brute-forcer (already
covered by the brute-force detector) that rarely speaks HTTP, so its benign-collision-to-true-positive
ratio was the worst in the table. A User-Agent is trivially spoofable, so this is a convenience signal
(false negatives expected when an attacker changes the UA), not a guarantee.

## Scope

In: the high-confidence tool-UA table → a per-source finding. Out: dual-use-client heuristics, JA4H
HTTP fingerprinting, full request-fingerprint behavioral analysis.

## Invariants

Engine-only; no new deps; no new column. Bounded (per-source map capped, sample capped). Deterministic
order. Derived metadata only (the tool label + a bounded example UA).
