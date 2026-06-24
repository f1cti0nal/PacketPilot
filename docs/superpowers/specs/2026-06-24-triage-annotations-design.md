# Triage annotations — design

Status: design · 2026-06-24 · Feature: per-host triage **status + notes**, persisted per capture, so
an analyst's triage progress survives reloads.

## Problem

PacketPilot surfaces incidents, scored hosts, and findings — but a triaging analyst has nowhere to
record *their own* state: which hosts they have looked at, which are benign, which need escalation,
and any notes. PROJECT-SPEC §D lists "saved views, tagging, bookmarks, annotations" as part of the
interaction model; this is the first piece of that triage-workflow layer.

## Approach

A **pure-UI** feature mirroring the existing localStorage CRUD modules (`filterProfiles.ts`,
`ruleSets.ts`, `recent.ts`) — no engine change, no new dependencies:
- `lib/annotations.ts`: a per-`(captureKey, ip)` `HostAnnotation { status, note, updatedAt }` stored
  under `packetpilot.annotations.v1` as `{ [captureKey]: { [ip]: HostAnnotation } }`. `status` is one
  of `new` / `investigating` / `cleared` / `escalated`. Never throws (parse/quota errors degrade to
  "no annotations"). An annotation that collapses to the default (`new` + empty note) is removed so
  the store stays clean. The capture key is the existing `captureKey(output)` (SHA-256 / path), so
  annotations are scoped to a capture and never leak across captures.
- Every write dispatches a `packetpilot:annotations` window event; a `useAnnotation(captureKey, ip)`
  hook subscribes (plus cross-tab `storage` events) so all mounted instances stay in sync.
- Surfaces: an editable `TriageAnnotation` control (a status selector + a note textarea) in the
  incident **DetailFlyout** (where the analyst drills in), and a read-only `TriageBadge` on the
  **threat watchlist** rows so triaged hosts are visible at a glance. The badge renders nothing for
  an untriaged (`new`) host.

## Scope

In: per-host status + note, per-capture persistence, the two surfaces, live cross-component sync.
Out: per-finding/per-flow annotations, tags beyond the fixed status set, server sync / sharing,
export of annotations, filtering the dashboard by status.

## Invariants

Pure UI; no engine change; no new deps. Never throws on bad/again storage. Capture-scoped. Fully
unit-testable (CRUD in jsdom localStorage; components via RTL).
