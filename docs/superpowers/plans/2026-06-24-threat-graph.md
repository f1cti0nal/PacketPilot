# Threat relationship graph — implementation plan

Spec: [2026-06-24-threat-graph-design.md](../specs/2026-06-24-threat-graph-design.md)

Pure-UI, one PR. No engine/wasm change.

## UI (`ui/src/`)

1. `lib/threatGraph.ts`: `buildThreatGraph(findings, threats, opts) -> { nodes, edges, truncated,
   width, height }`. Aggregate per-IP severity/score from findings, fold in `ip_threats`, rank +
   cap (`maxNodes` default 14), radial layout (ring ordered by score; node radius 7..16 by score;
   label anchor/position by angle), edges deduped per `src->dst` (worst severity) as bezier chords
   bowing toward centre. Pure + deterministic.
2. `cockpit/ThreatGraph.tsx`: renders SVG from the model — edges under nodes, severity-colored
   (`severityColor`); each node a `role="button"` `<g>` with click + Enter/Space → `onJump(ip)`;
   radial labels; a severity legend; "+N more" when truncated. Hidden when `< 2` nodes.
3. `components/Dashboard.tsx`: import + render `<ThreatGraph findings={s.findings ?? []}
   threats={s.ip_threats ?? []} onJump={toFlowsIp} />` after the threat watchlist.

## Tests

4. `lib/threatGraph.test.ts`: nodes/edges from src->dst findings + determinism; no-dst skipped +
   edge dedup (worst severity); `maxNodes` cap + truncation count; `ip_threats` severity/score fold.
5. `cockpit/ThreatGraph.test.tsx`: renders the labelled section, node click + Enter jump to flows;
   `< 2` related hosts → renders nothing.

## Verify

UI: `test:coverage` (80/70) · `build` (tsc + vite). Validate the visual design via a `show_widget`
render of the layout. Then PR, watch CI, merge on local gates. (No `build:wasm` — no engine change.)
