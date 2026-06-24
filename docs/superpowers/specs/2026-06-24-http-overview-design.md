# HTTP overview (top hosts + user-agents) — design

Status: design · 2026-06-24 · Feature: a dashboard panel ranking the capture's most-contacted HTTP
`Host`s and most-common client `User-Agent`s — the aggregate companion to the per-flow HTTP columns.

## Problem

The HTTP-metadata feature added per-flow `http_host` / `http_ua` (searchable in the flows table), but
there was no **aggregate** view on the dashboard — analysts couldn't see, at a glance, *which web
destinations* dominate a capture or *what client mix* (browsers vs scripts vs scanners) is present.
The TLS side already has this (`domain_threats` / the SNI rollup); HTTP did not.

## Approach

An engine stats rollup + a dashboard panel — the proven `per_domain` (SNI) / `port_histogram`
pattern, no new deps:
- `stats/mod.rs`: `per_http_host` / `per_http_ua` flow-count maps, folded in `observe_scored_flow`
  next to the SNI-domain rollup (bounded by `max_tracked_keys`, no eviction — a heavy-hitter
  histogram). At `finish`, ranked desc by flow count and truncated to top-15 into
  `summary.http_hosts` (`HttpHostCount`) and `summary.user_agents` (`UserAgentCount`).
- `cockpit/HttpOverviewCard.tsx`: a two-column panel (top hosts | user-agents) of labelled
  proportional bars. Display-only; hidden when no HTTP requests were seen. Wired into the dashboard
  charts grid.

The summary fields serialize via serde, so the UI receives them automatically (no WASM API change).

## Scope

In: top HTTP hosts + user-agents by flow count. Out: byte-ranking, per-host method breakdown,
click-to-filter (the host token → flows filter mapping is deferred, as for the other panels).

## Invariants

Engine-only stats addition; no new deps. Bounded (both maps capped by `max_tracked_keys`, output
truncated top-15). Deterministic order (desc flows, asc string). Pure-UI panel, hidden when empty.
