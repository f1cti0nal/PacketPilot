# HTTP overview panel — implementation plan

Spec: [2026-06-24-http-overview-design.md](../specs/2026-06-24-http-overview-design.md)

Engine stats rollup + a dashboard panel. One PR (direct to main). Mirrors the SNI/`port_histogram`
pattern.

## Engine (`engine/crates/ppcap-core/src/`)

1. `model/summary.rs`: `HttpHostCount { host, flows }` + `UserAgentCount { user_agent, flows }`;
   `Summary.http_hosts` / `user_agents` (`#[serde(default)]`); add to `Summary::empty()`.
2. `stats/mod.rs`: `per_http_host` / `per_http_ua: HashMap<String, u64>` (+ `new()`); fold in
   `observe_scored_flow` (next to the SNI rollup) via a `bump_string_capped` helper; build the two
   rollups in `finish` (desc flows, top-15). `enrich/reputation.rs`: add the fields to its `Summary`
   literal.
3. Tests: `stats` rollup ranked by flows + no-HTTP ignored.

## UI (`ui/src/`)

4. `types.ts`: `HttpHostCount` / `UserAgentCount` + `http_hosts` / `user_agents` on the summary type.
5. `cockpit/HttpOverviewCard.tsx`: two-column bar-list panel (top hosts | user-agents), hidden when
   empty. `components/Dashboard.tsx`: import + render in the charts grid (full-width row).
6. `cockpit/HttpOverviewCard.test.tsx`: renders ranked hosts/UAs; hidden when empty.

## Verify

Engine: full `cargo test -p ppcap-core` · `clippy`. UI: `test:coverage` · `build`. `build:wasm`
(serde carries the new summary fields — no WASM code change). Then commit direct to `main`.
