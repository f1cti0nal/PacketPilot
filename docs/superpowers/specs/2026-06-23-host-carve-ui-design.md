# Host-carve UI button — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-23
**Branch:** `feat/host-carve-ui`

## Goal

Complete the PCAP-carve feature: a "Carve host pcap" action on the IP threat cards, so an analyst can export a focused sub-pcap of all traffic touching a flagged host. The engine/WASM/Tauri/platform layers already support `CarveTarget::Host` (shipped with the carve feature) — this adds the deferred UI entry.

## Architecture

Pure UI. Thread `activeSource` (the retained capture bytes / file path the packet drill-down and flow-carve already use) from `App` → `Dashboard` → `ThreatWatchlist` → each host card. The card's carve action calls the existing `carveSubPcap({ host: ip, start_ns, end_ns }, activeSource, name)` from `lib/packets.ts`. Same retained-source gating as the flow-carve button (`packetsAvailable(activeSource)`). No engine/WASM/Tauri change.

**Tech stack:** React 18 + TS; Vitest. No new deps.

## Global Constraints

- **Pure UI** — no engine/WASM/Tauri change. The carve capability (`carve_pcap`/`carve_pcap_to`, `CarveTarget::Host`) and `carveSubPcap` already exist; this only wires a UI entry + threads `activeSource` into `Dashboard`.
- **Same gating as the flow carve** — the button is disabled (with a tooltip) when `!packetsAvailable(activeSource)` (source not retained: a Recent capture re-loaded without bytes, or not pcap-derived).
- **Whole-capture host window** — `{ host: ip, start_ns: 0, end_ns: HOST_CARVE_END_NS }` where `HOST_CARVE_END_NS = 9e18` (above any real ns-since-epoch ~1.8e18, and below `i64::MAX` 9.22e18) so every packet touching the IP is carved.
- **No-throw** — `carveSubPcap` returns `ExportResult`; surface it via a transient notice, never throw.
- **No new deps.** Coverage gate ≥ 80/70 under the locked toolchain (vitest 1.6.1). Stage specific files.

## Reference: the seams (verified)

```ts
// ui/src/lib/packets.ts  carveSubPcap(query: CarveQuery, source: ActiveSource, name: string): Promise<ExportResult>
//   ; packetsAvailable(source): boolean  (source !== null)
// ui/src/types.ts  CarveQuery { host?:string; src_ip?...; start_ns:number; end_ns:number } ; ActiveSource = {kind:"path";path}|{kind:"bytes";bytes}|null
// ui/src/components/Dashboard.tsx:32 DashboardProps { output, onJumpToFlows?, selectedIncident, onSelectIncident }  (NO activeSource)
//   :102 <ThreatWatchlist threats={s.ip_threats ?? []} onSelect={openHost} />  ; ThreatWatchlist is a local sub-component rendering compact host cards (each card has the threat.ip + an onSelect)
// ui/src/App.tsx:117 const [activeSource] = useState<ActiveSource>(null) ; :614 <Dashboard output={summary.data!} onJumpToFlows={jumpToFlows} selectedIncident=… onSelectIncident={setSelectedIncident} />
// ui/src/views/FlowsView.tsx carveFlow pattern (the flow-carve handler: build query → carveSubPcap → surface ExportResult via pktError) — mirror for host
// the flow-carve button (FlowDetail.tsx) uses a Scissors icon + canInspect gating — mirror the disabled/tooltip style
```

## Components

### 1. `App.tsx`
Pass `activeSource={activeSource}` to `<Dashboard>` (the value already exists in App state).

### 2. `Dashboard.tsx`
- `DashboardProps`: add `activeSource: ActiveSource`.
- In `Dashboard`: `const canCarve = packetsAvailable(activeSource)`; a `const [carveNotice, setCarveNotice] = useState<string | null>(null)`; a `const carveHost = useCallback(async (ip: string) => { const res = await carveSubPcap({ host: ip, start_ns: 0, end_ns: HOST_CARVE_END_NS }, activeSource, \`${ip}-carve.pcap\`); if (res.ok) setCarveNotice(res.message); else if (res.message) setCarveNotice(res.message); }, [activeSource])`.
- Pass `onCarveHost={carveHost}` + `canCarve={canCarve}` to `<ThreatWatchlist>`. Render `carveNotice` as a small transient line near the watchlist (auto-clear optional; render when non-null).
- `HOST_CARVE_END_NS = 9e18` module const.

### 3. `ThreatWatchlist` + the host card (in `Dashboard.tsx`)
- `ThreatWatchlist` props gain `onCarveHost?: (ip: string) => void` + `canCarve?: boolean`.
- Each host card renders a small icon button (`Scissors` from lucide-react) — title "Carve this host's packets (.pcap)" when `canCarve`, else "Packets only available for captures analyzed from a pcap"; `disabled={!canCarve}`; `onClick={(e) => { e.stopPropagation(); onCarveHost?.(threat.ip); }}` (stop propagation so it doesn't trigger the card's `onSelect` pivot). Cockpit styling, consistent with the card's other controls.

## Data flow & error handling

Browser: `carveSubPcap` uses the retained `activeSource` bytes → the WASM carve matches every packet with src/dst == ip across the whole capture → blob download. Desktop: re-reads the file path → Tauri writes the chosen path. Source not retained → the button is disabled (no call). Result → `carveNotice` ("Carved N packets" on desktop / "Downloaded" in the browser, or a failure message). `carveSubPcap` never throws.

## Testing

- A host card renders a carve button; it is `disabled` when `activeSource` is `null` and enabled when a `{kind:"bytes"}`/`{kind:"path"}` source is present; clicking it (enabled) calls the carve path with `{ host: <ip> }` (mock `carveSubPcap`, assert the query). `Dashboard` forwards `activeSource` to `ThreatWatchlist`. The carve click does NOT trigger the card's `onSelect` (stopPropagation). Coverage ≥ 80/70.

## Out of scope

- A host-carve entry on the incident flyout / top-talkers (the threat watchlist is the primary surface); a time-window picker (whole-capture window only); any engine/platform change (already shipped).

## File manifest

**UI — modify:** `ui/src/App.tsx` (pass `activeSource`), `ui/src/components/Dashboard.tsx` (`DashboardProps.activeSource` + `carveHost` + `ThreatWatchlist` carve button + notice) + the Dashboard test.
**No engine/WASM/Tauri change, no new deps.**
