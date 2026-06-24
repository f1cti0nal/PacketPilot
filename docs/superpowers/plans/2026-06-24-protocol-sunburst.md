# Protocol hierarchy sunburst — implementation plan

Spec: [2026-06-24-protocol-sunburst-design.md](../specs/2026-06-24-protocol-sunburst-design.md)

Pure-UI, one PR. No engine change (data — `summary.protocol_hierarchy` — already populated).

## UI (`ui/src/`)

1. `lib/protocolSunburst.ts`: `buildSunburst(nodes, opts) -> { arcs, total, size, rings }`. Accumulate
   `ip.l4.l7` leaf prefixes into a tree; radial layout (centre hole + 2 equal rings; children fill
   the parent angular span by bytes; root clamped to just under 2π); `annularSector()` SVG path per
   arc + a pre-computed label point. Pure + deterministic.
2. `cockpit/ProtocolSunburst.tsx`: render the arcs (color by L4 via `l4Of` = `path.split('.')[1]`,
   depth-2 lower opacity), labels for `fraction > 0.06`, a centre `IP`/total, per-arc `<title>`, an
   L4 legend. Hidden when `arcs.length === 0`.
3. `components/Dashboard.tsx`: import + render `<ProtocolSunburst hierarchy={s.protocol_hierarchy ??
   []} />` in the protocol/charts grid (next to ProtocolMix / TopTalkers).

## Tests

4. `lib/protocolSunburst.test.ts`: tree accumulation + ring/depth assignment + determinism; single
   100% (no degenerate arc); 2-level (no-L7) paths + non-ip skipped; empty → empty model.
5. `cockpit/ProtocolSunburst.test.tsx`: renders one arc per node (scope the path query to the
   sunburst svg — the header icon has paths too) + labels + legend; empty → nothing.

## Verify

UI: `test:coverage` (80/70) · `build`. Validate the visual via `show_widget`; run an adversarial
review of the arc math. Then PR, merge on local gates. (No `build:wasm` — no engine change.)
