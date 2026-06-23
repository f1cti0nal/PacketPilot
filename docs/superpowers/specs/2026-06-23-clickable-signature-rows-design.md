# Clickable signature-match rows — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-23
**Branch:** `feat/clickable-signature-rows`

## Goal

Make the Signature matches panel (PR #31) actionable: clicking a match row jumps to that host's flows, exactly like the threat cards and top-talkers already do. Today the panel is read-only.

## Architecture

Pure UI. Add an optional `onJump` callback to `SignatureMatchesPanel`; the Dashboard wires it to the existing `toFlowsIp` (`onJumpToFlows({ ip })`). No engine/WASM/Tauri change. The Flows view's existing `initialFilter.ip → setQuery(ip)` path does the rest (the same mechanism every Dashboard pivot uses).

**Tech stack:** React 18 + TS; Vitest. No new deps.

## Global Constraints

- **Pure UI** — no engine/WASM/Tauri change. Reuse the existing `onJumpToFlows({ ip })` drilldown.
- **Backward-compatible** — when `onJump` is absent the panel renders exactly as today (read-only cards); the existing panel tests must still pass unchanged.
- **No nested interactives** — `MitreTag` is a non-interactive span, so a card-level `<button>` is valid HTML (no button-in-button).
- No new deps. Coverage gate ≥ 80/70 (vitest 1.6.1).

## Reference: the seams (verified)

```ts
// ui/src/components/Dashboard.tsx:81 const toFlowsIp = (ip:string) => onJumpToFlows?.({ ip }); :29 DashboardDrilldown { ip?; category?; severity?; proto? }
//   threat cards / top-talkers pivot via toFlowsIp (e.g. :111 onPivot={toFlowsIp})
// ui/src/views/FlowsView.tsx:128 setQuery(initialFilter.ip ?? "") — an {ip} drilldown sets the flows query to that IP (text-matches src/dst)
// ui/src/components/triage/SignatureMatchesPanel.tsx — MatchCard (the <li>); each f has src_ip:string, dst_ip:string|null
// ui/src/cockpit/primitives.tsx:77 MitreTag (renders {id} as a span — non-interactive)
// ui/src/components/triage/DomainThreatsPanel.tsx / the threat watchlist card (a full-width text-left <button> inside <li>) — the clickable-card pattern to mirror
```

## Components

### 1. `ui/src/components/triage/SignatureMatchesPanel.tsx`
- `MatchCard` gains an `onJump?: (ip: string) => void` (threaded from the panel prop).
- The **pivot IP** = `f.dst_ip ?? f.src_ip` (the matched destination — the server the signature fired on — falling back to the source when `dst_ip` is null).
- When `onJump` is provided: the card's content is wrapped in a full-width `<button type="button" className="… text-left">` with `onClick={() => onJump(f.dst_ip ?? f.src_ip)}`, `aria-label={`View flows for ${f.dst_ip ?? f.src_ip}`}`, and a hover affordance (`hover:border-[var(--color-border-strong)]` / cursor-pointer), mirroring the threat-watchlist card.
- When `onJump` is absent: the card renders as today (the static `<li>` content) — no button, no behavior change.
- `SignatureMatchesPanel` gains `onJump?: (ip: string) => void` and passes it to each `MatchCard`.

### 2. `ui/src/components/Dashboard.tsx`
Pass `onJump={toFlowsIp}` to `<SignatureMatchesPanel findings={…} onJump={toFlowsIp} />`.

## Data flow & error handling

Click a match row → `onJump(f.dst_ip ?? f.src_ip)` → `onJumpToFlows({ ip })` → the Flows view filters to that IP. `dst_ip` is `string | null`; the `?? f.src_ip` fallback guarantees a non-null pivot (`src_ip` is always present on a `Finding`). The click handler is a no-op when `onJump` is undefined (the button isn't rendered). No new data.

## Testing

- **`SignatureMatchesPanel`:** with `onJump` (a spy), clicking a `rule_match` row calls it with the match's `dst_ip`; a match whose `dst_ip` is `null` calls it with `src_ip`; the clickable row is a `<button>` with `aria-label="View flows for <ip>"`. Without `onJump`, the rows render but are NOT buttons (the existing render/empty/sid-absent tests still pass unchanged).
- **`Dashboard`:** passes `onJump` to the panel (the existing smoke tests still pass; optionally assert a click pivots via the wired `onJumpToFlows`).
- Coverage ≥ 80/70.

## Out of scope

A precise src+dst+port flow filter (the IP text-query is what every other pivot uses); separately-clickable src vs dst IPs; a per-match drill-down; pivoting from threat-card evidence sids; any engine/report change.

## File manifest

**UI — modify:** `ui/src/components/triage/SignatureMatchesPanel.tsx` (`onJump` prop + clickable card), `ui/src/components/triage/SignatureMatchesPanel.test.tsx` (new click tests), `ui/src/components/Dashboard.tsx` (wire `onJump={toFlowsIp}`).
**No engine/WASM/Tauri change, no new deps.**
