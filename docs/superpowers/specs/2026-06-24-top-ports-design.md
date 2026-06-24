# Top ports / services panel — design

Status: design · 2026-06-24 · Feature: a dashboard panel ranking the busiest ports in the capture,
with well-known service names.

## Problem

The engine computes `summary.port_histogram` (per-`(port, transport)` pkts + bytes, sorted by pkts),
but **nothing in the UI visualizes it**. The dashboard's `ProtocolMix` shows *app protocols*, which
hides the actual port numbers — so an analyst can't see traffic on **non-standard ports** (4444,
8443, odd high ports), a classic C2 / odd-service tell. (Found the same way as the protocol
sunburst: grepping the stats module for populated-but-unvisualized `Summary` fields.)

## Approach

A **pure-UI** dashboard panel, `TopPortsCard`, over `port_histogram` — no engine change, no deps:
- `lib/services.ts` (`serviceName(port)`): a well-known-port → service-name table (HTTPS / SSH / DNS
  / RDP / SMB / …). Absence of a name is itself a signal — the panel labels such ports
  **"non-standard."**
- `cockpit/TopPortsCard.tsx`: the top 8 ports (by pkts, then bytes), each a row with port number +
  transport + service (or "non-standard") + pkt/byte counts + a proportional bar. Display-only;
  hidden when no ports were seen.

Complements `ProtocolMix` at port-level granularity.

## Scope

In: top-8 ports with service labels + proportional bars. Out: click-to-filter-flows (the flows
filter has no direct port field; deferred), a full IANA port registry, per-host port breakdown.

## Invariants

Pure UI; no engine change; no new deps. Deterministic; hidden when empty.
