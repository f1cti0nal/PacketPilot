# Protocol hierarchy sunburst — design

Status: design · 2026-06-24 · Feature: a dashboard sunburst of the capture's `ip → L4 → L7` byte
composition — the classic Wireshark "protocol hierarchy" view (PROJECT-SPEC §D protocol treemap/
sunburst).

## Problem

The engine already computes `summary.protocol_hierarchy` (leaf paths like `ip.tcp.https` /
`ip.udp.dns` with bytes + pkts), but **nothing in the UI visualizes it**. The dashboard's
`ProtocolMix` shows the *flat* `proto` counts (a bar list), not the protocol *tree*. Analysts
specifically value the nested hierarchy — seeing how much TLS sits inside TCP, DNS inside UDP, etc.

## Approach

A **pure-UI** dashboard panel, `ProtocolSunburst`, over the existing `protocol_hierarchy` — no engine
change, no new dependencies:
- `lib/protocolSunburst.ts` (`buildSunburst`): accumulates each engine leaf path's prefixes into a
  tree (the engine emits exactly one leaf path per packet class — `bump_path` once per packet — so
  prefixes accumulate with **no double-counting**, and a parent's bytes always equal the sum of its
  children's). Lays out a deterministic two-ring sunburst: ring 1 = L4 (tcp/udp/icmp…), ring 2 = L7
  (https/dns/…), each child filling its parent's angular span proportional to bytes. Each arc's SVG
  `d` (annular sector) is pre-computed. The root span is clamped just under a full turn so a single
  100%-share protocol never degenerates to a zero-length arc.
- `cockpit/ProtocolSunburst.tsx`: renders the arcs (colored by L4, the L7 ring at lower opacity),
  labels the larger segments, a centre `IP` + total, per-arc `<title>` tooltips, and an L4 legend.
  Display-only; hidden when the capture has no protocol breakdown.

Deterministic (no layout simulation) → fully unit-testable; the geometry was visually validated
before finalizing.

## Scope

In: the `ip → L4 → L7` two-ring sunburst over `protocol_hierarchy`, tooltips + legend. Out:
click-to-filter-flows (the L7 token → appProto mapping is fuzzy; deferred), >2 rings, animation, a
treemap alternative.

## Invariants

Pure UI; no engine change; no new deps (hand-rolled SVG). Deterministic; never throws on malformed
input. Bounded (the engine already truncates `protocol_hierarchy` to top-k).
