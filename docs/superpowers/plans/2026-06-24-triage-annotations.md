# Triage annotations — implementation plan

Spec: [2026-06-24-triage-annotations-design.md](../specs/2026-06-24-triage-annotations-design.md)

Pure-UI, one PR. Mirrors the `filterProfiles.ts` localStorage pattern.

## UI (`ui/src/`)

1. `lib/annotations.ts`: `TriageStatus`, `TRIAGE_STATUSES`, `STATUS_META`, `HostAnnotation`; CRUD
   `getAnnotation` / `setAnnotation` (merge patch; remove when it collapses to `new` + empty note) /
   `clearAnnotation` / `annotationsForCapture`. Store `packetpilot.annotations.v1`; never throws; a
   `packetpilot:annotations` window event on every write.
2. `cockpit/TriageAnnotation.tsx`: `useAnnotation(captureKey, ip)` hook (event + `storage` sync);
   `TriageBadge` (read-only status pill, hidden for `new`); `TriageAnnotation` (status selector +
   note textarea).
3. `cockpit/DetailFlyout.tsx`: add a `captureKey?` prop; render `<TriageAnnotation>` under the
   narrative.
4. `components/Dashboard.tsx`: pass `captureKey={captureKey(output)}` to the DetailFlyout and the
   ThreatWatchlist; render `<TriageBadge>` next to each watchlist host IP.

## Tests

5. `lib/annotations.test.ts`: set/read (capture+host scoped), patch merge, collapse-removal,
   `clearAnnotation`, never-throw on malformed storage, change-event dispatch.
6. `cockpit/TriageAnnotation.test.tsx`: persist a status + note; badge hidden until triaged then
   reflects status live (event sync).

## Verify

UI: `test:coverage` (80/70) · `build`. Then PR, watch CI, merge on local gates. (No `build:wasm` —
no engine change.)
