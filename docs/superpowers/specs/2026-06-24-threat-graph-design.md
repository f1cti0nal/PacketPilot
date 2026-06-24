# Threat relationship graph — design

Status: design · 2026-06-24 · Feature: a dashboard panel that visualizes the finding-derived host
relationships as a node-link graph (PROJECT-SPEC §D, "conversation/flow graph").

## Problem

The dashboard is summary/table-first: KPIs, an incident *list*, a threat watchlist, an activity
heatmap, a protocol mix, and top talkers. It has **no relationship view** — nothing shows the
*topology* of an attack (which host is reaching which, and how the implicated hosts relate). A SOC
analyst triaging an incident benefits from seeing "who is doing what to whom" spatially, not just as
a list.

## Approach

A new **pure-UI** dashboard panel, `ThreatGraph`, over data already in the summary
(`findings` + `ip_threats`) — no engine change, no new dependencies:
- **Nodes** are the hosts implicated by behavioral findings (as `src_ip` or `dst_ip`). Each node's
  severity/score is the worst of its findings folded with its per-IP threat card (the authoritative
  scoring).
- **Edges** are the `src -> dst` relationships a finding establishes (deduped per pair, worst
  severity). Fan-out findings with no destination (e.g. a host sweep) contribute a node but no edge.
- **Layout** is a **deterministic radial** placement: nodes on a ring ordered by score (worst at
  top), node radius scaled by score, edges drawn as quadratic-bezier chords bowing toward the
  centre. Deterministic (no force simulation) so it is fully unit-testable and renders identically
  every time.
- Severity-colored (the app severity palette); nodes are **click/Enter-to-jump-to-flows** (reusing
  the dashboard's `onJump`). Top `maxNodes` (14) hosts shown; the remainder surfaced as "+N more".
- Hidden when fewer than two hosts are related (nothing to show).

The layout/data derivation lives in a pure `lib/threatGraph.ts` (`buildThreatGraph`) returning a
`{ nodes, edges, truncated }` model with pre-computed positions and edge paths; the component
(`cockpit/ThreatGraph.tsx`) only renders SVG from that model.

## Scope

In: finding-derived nodes/edges, deterministic radial layout, severity coloring, click/keyboard
jump, node cap + truncation note. Out: force-directed layout, edge bundling, raw-bytes conversation
edges (vs finding edges), zoom/pan, hover tooltips, a separate full-screen graph view.

## Invariants

Pure UI; no engine change; no new deps (hand-rolled SVG). Deterministic output (testable in jsdom —
structure and positions, not colors, since `severityColor` resolves CSS vars that jsdom returns
empty). Bounded node count.
